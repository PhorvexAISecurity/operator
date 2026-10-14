#!/usr/bin/env python3
"""Static Helm checks for complete M1b bindings and old/new package boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[1]
CHART=ROOT/'deploy/helm/phorvex-stack'
VALUES=CHART/'values-eks.yaml'
CM='phorvex-litellm-live-profile-64098e6f1280'
ACTIVE_VALUES={
    'litellmGatewayMetrics':{'enabled':True},
    'phorvex':{'phorvex':{'console':{'litellmLive':{
        'configMapName':CM,
        'profileSHA256':'64098e6f1280f9782edf8d5a3c6eff0e5f92199d5c009a8e571f881e657011d3',
        'sourceConfigMapName':'phorvex-litellm-admission-gateway-f550b9890b20',
    }}}},
}


def render(values=None):
    helm=os.environ.get('HELM_BIN') or shutil.which('helm')
    if not helm:raise RuntimeError('checksum-verified Helm required')
    with tempfile.NamedTemporaryFile('w',suffix='.yaml') as f:
        yaml.safe_dump(values or {},f);f.flush()
        return subprocess.run([helm,'template','phorvex',str(CHART),'-n','phorvex-system',
            '--api-versions','monitoring.coreos.com/v1/PodMonitor','--api-versions','monitoring.coreos.com/v1/ServiceMonitor',
            '-f',str(VALUES),'-f',f.name],capture_output=True,text=True)


class MetricsChartTests(unittest.TestCase):
    def test_active_source_profile_monitor_and_private_network_closure(self):
        result=render(ACTIVE_VALUES);self.assertEqual(result.returncode,0,result.stderr)
        # No Secret values are printed or written; inspect only targeted objects.
        items=[o for o in yaml.safe_load_all(result.stdout) if o]
        by={(o['kind'],o['metadata'].get('namespace'),o['metadata']['name']):o for o in items}
        profile=by['ConfigMap','phorvex-system',CM]
        raw=profile['data']['profile.json'];digest=hashlib.sha256(raw.encode()).hexdigest()
        p=json.loads(raw)
        self.assertEqual(CM,'phorvex-litellm-live-profile-'+digest[:12])
        contract=json.loads((ROOT/'build/integrations/litellm-gateway-runtime/image-contract.json').read_text())
        self.assertEqual(p['gatewayImage'],contract['imageByDigest'])
        self.assertEqual(p['sourceSHA256'],contract['gatewaySourceSHA256'])
        source=by['ConfigMap','litellm','phorvex-litellm-admission-gateway-'+p['sourceSHA256'][:12]]
        self.assertEqual(hashlib.sha256(source['data']['gateway.py'].encode()).hexdigest(),p['sourceSHA256'])
        self.assertTrue(source['immutable']);self.assertTrue(profile['immutable'])
        console=by['Deployment','phorvex-system','phorvex-phorvex-console']['spec']['template']['spec']
        env={e['name']:e for c in console['containers'] for e in c.get('env',[])}
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256']['value'],digest)
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_OUTPUT_ENABLED']['value'],'false')
        volume=next(v for v in console['volumes'] if v['name']=='litellm-live-reviewed-inputs')
        self.assertEqual(volume['projected']['sources'][0]['configMap']['name'],CM)
        monitor=by['ServiceMonitor','monitoring','phorvex-litellm-gateway-metrics']
        endpoint=monitor['spec']['endpoints'][0]
        self.assertFalse(endpoint['honorLabels'])
        self.assertEqual([r['targetLabel'] for r in endpoint['relabelings']],['namespace','pod','target'])
        self.assertEqual(endpoint['relabelings'][-1]['replacement'],'litellm')
        np=by['NetworkPolicy','litellm','phorvex-litellm-gateway-metrics']['spec']
        self.assertEqual(np['ingress'][0]['ports'],[{'port':4003,'protocol':'TCP'}])
        self.assertEqual([p['port'] for p in np['ingress'][1]['ports']],[4000,4001,4002])
        self.assertNotIn(('Deployment','litellm','litellm'),by)

    def test_disabled_emits_no_metrics_owned_objects(self):
        result=render({'litellmGatewayMetrics':{'enabled':False}});self.assertEqual(result.returncode,0,result.stderr)
        items=[o for o in yaml.safe_load_all(result.stdout) if o]
        self.assertFalse(any(o['metadata']['name']=='phorvex-litellm-gateway-metrics' for o in items))

    def test_committed_eks_stays_disabled_with_legacy_console_bindings(self):
        values=yaml.safe_load(VALUES.read_text())
        self.assertIs(values['litellmGatewayMetrics']['enabled'],False)
        legacy={
            'configMapName':'phorvex-litellm-live-profile-7ca969928785',
            'profileSHA256':'7ca969928785e68e4959b99605b34d5666e34f239ce300a031fe438b619553cc',
            'sourceConfigMapName':'phorvex-litellm-admission-gateway-4bf046ce690c',
        }
        live=values['phorvex']['phorvex']['console']['litellmLive']
        self.assertEqual({field:live[field] for field in legacy},legacy)
        result=render();self.assertEqual(result.returncode,0,result.stderr)
        items=[o for o in yaml.safe_load_all(result.stdout) if o]
        metrics_owned={CM,'phorvex-litellm-admission-gateway-f550b9890b20',
            'phorvex-litellm-gateway-metrics','phorvex-console-litellm-metrics-source'}
        self.assertFalse(any(o['metadata']['name'] in metrics_owned for o in items))
        by={(o['kind'],o['metadata'].get('namespace'),o['metadata']['name']):o for o in items}
        console=by['Deployment','phorvex-system','phorvex-phorvex-console']['spec']['template']['spec']
        env={e['name']:e for c in console['containers'] for e in c.get('env',[])}
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256']['value'],legacy['profileSHA256'])
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_OUTPUT_ENABLED']['value'],'false')
        volume=next(v for v in console['volumes'] if v['name']=='litellm-live-reviewed-inputs')
        self.assertEqual(volume['projected']['sources'][0]['configMap']['name'],legacy['configMapName'])
        self.assertNotIn(('Deployment','litellm','litellm'),by)

    def test_invalid_profile_and_source_pins_fail_closed(self):
        for field,value in [('profileSHA256','a'*64),('configMapName','unreviewed'),('sourceConfigMapName','phorvex-litellm-admission-gateway-4bf046ce690c')]:
            with self.subTest(field=field):
                values=copy.deepcopy(ACTIVE_VALUES)
                values['phorvex']['phorvex']['console']['litellmLive'][field]=value
                result=render(values)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('M1b active Console profile/source closure differs',result.stderr)

if __name__=='__main__':unittest.main()
