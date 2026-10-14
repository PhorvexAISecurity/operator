#!/usr/bin/env python3
"""Static Helm checks for authenticated Stage5 bindings and frozen legacy boundaries."""
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
CLOSURE=json.loads((ROOT/'deploy/monitoring/litellm-m5/metrics-closure.json').read_text())
CM=CLOSURE['profiles'][0]['configMapName']
ACTIVE_VALUES={
    'litellmGatewayMetrics':{'enabled':True,'protectionMode':'bearerToken','auth':{
        'secretName':CLOSURE['metricsProtection']['secretName'],'secretKey':'token'}},
    'phorvex':{'phorvex':{'console':{'litellmLive':{
        key:CLOSURE['profiles'][0][key]
        for key in ('configMapName','profileSHA256','sourceConfigMapName')
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
        self.assertEqual(endpoint['authorization'],{'type':'Bearer','credentials':{
            'name':CLOSURE['metricsProtection']['secretName'],'key':'token','optional':False}})
        self.assertIs(endpoint['followRedirects'],False)
        for field in ('bearerTokenSecret','bearerTokenFile','basicAuth','oauth2','httpHeaders'):
            self.assertNotIn(field,endpoint)
        role=by['Role','litellm','phorvex-console-litellm-metrics-source']
        self.assertEqual(role['rules'],[{'apiGroups':[''],'resources':['configmaps'],'resourceNames':[
            'phorvex-litellm-admission-gateway-4bf046ce690c',
            'phorvex-litellm-admission-gateway-f550b9890b20',CLOSURE['sourceConfigMapName']], 'verbs':['get']}])
        for obj in (profile,source,monitor,role):
            self.assertEqual(obj['metadata']['annotations']['helm.sh/resource-policy'],'keep')
            self.assertEqual(obj['metadata']['annotations']['argocd.argoproj.io/sync-options'],'Prune=false,Delete=false')
        self.assertNotIn(('Secret','litellm',CLOSURE['metricsProtection']['secretName']),by)
        self.assertNotIn(('Secret','monitoring',CLOSURE['metricsProtection']['secretName']),by)
        np=by['NetworkPolicy','litellm','phorvex-litellm-gateway-metrics']['spec']
        self.assertEqual(np['ingress'][0]['ports'],[{'port':4003,'protocol':'TCP'}])
        self.assertEqual([p['port'] for p in np['ingress'][1]['ports']],[4000,4001,4002])
        self.assertNotIn(('Deployment','litellm','litellm'),by)

    def test_disabled_emits_no_metrics_owned_objects(self):
        result=render({'litellmGatewayMetrics':{'enabled':False}});self.assertEqual(result.returncode,0,result.stderr)
        items=[o for o in yaml.safe_load_all(result.stdout) if o]
        self.assertFalse(any(o['metadata']['name']=='phorvex-litellm-gateway-metrics' for o in items))

    def test_disabled_overlay_preserves_legacy_console_bindings(self):
        legacy={
            'configMapName':'phorvex-litellm-live-profile-7ca969928785',
            'profileSHA256':'7ca969928785e68e4959b99605b34d5666e34f239ce300a031fe438b619553cc',
            'sourceConfigMapName':'phorvex-litellm-admission-gateway-4bf046ce690c',
        }
        disabled_values={
            'litellmGatewayMetrics':{'enabled':False},
            'phorvex':{'phorvex':{'console':{
                'litellmLive':{'enabled':True,**legacy},
                'litellmOutput':{'enabled':False},
            }}},
        }
        result=render(disabled_values);self.assertEqual(result.returncode,0,result.stderr)
        items=[o for o in yaml.safe_load_all(result.stdout) if o]
        metrics_owned={CM,CLOSURE['sourceConfigMapName'],'phorvex-litellm-admission-gateway-f550b9890b20',
            'phorvex-litellm-gateway-metrics','phorvex-console-litellm-metrics-source'}
        self.assertFalse(any(o['metadata']['name'] in metrics_owned for o in items))
        by={(o['kind'],o['metadata'].get('namespace'),o['metadata']['name']):o for o in items}
        console=by['Deployment','phorvex-system','phorvex-phorvex-console']['spec']['template']['spec']
        env={e['name']:e for c in console['containers'] for e in c.get('env',[])}
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256']['value'],legacy['profileSHA256'])
        self.assertEqual(env['PHORVEX_CONSOLE_LITELLM_OUTPUT_ENABLED']['value'],'false')
        volume=next(v for v in console['volumes'] if v['name']=='litellm-live-reviewed-inputs')
        self.assertEqual(volume['projected']['sources'][0]['configMap']['name'],legacy['configMapName'])
        source_role=by['Role','litellm','phorvex-phorvex-console-litellm-live-source']
        self.assertEqual(source_role['rules'][0]['resourceNames'][0],legacy['sourceConfigMapName'])
        self.assertNotIn(('Deployment','litellm','litellm'),by)

    def test_invalid_profile_and_source_pins_fail_closed(self):
        for field,value in [('profileSHA256','a'*64),('configMapName','unreviewed'),('sourceConfigMapName','phorvex-litellm-admission-gateway-4bf046ce690c')]:
            with self.subTest(field=field):
                values=copy.deepcopy(ACTIVE_VALUES)
                values['phorvex']['phorvex']['console']['litellmLive'][field]=value
                result=render(values)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Stage5 active Console profile/source closure differs',result.stderr)

    def test_missing_unknown_and_literal_auth_values_fail_closed(self):
        cases=[
            ({'protectionMode':None},'protection mode'),
            ({'protectionMode':'networkEnforced'},'protection mode'),
            ({'auth':{'secretName':''}},'Secret name'),
            ({'auth':{'secretName':'Uppercase'}},'Secret name'),
            ({'auth':{'secretName':'a'*64}},'Secret name'),
            ({'auth':{'secretName':'unreviewed-name'}},'auth reference differs'),
            ({'auth':{'secretKey':'master-key'}},'key must be token'),
            ({'auth':{'token':'synthetic-forbidden-literal'}},'Secret references only'),
            ({'bearerTokenFile':'/arbitrary/path'},'Secret reference values'),
            ({'authorization':{'credentials':'synthetic-forbidden-literal'}},'Secret reference values'),
        ]
        for change,message in cases:
            with self.subTest(change=change):
                values=copy.deepcopy(ACTIVE_VALUES)
                for key,value in change.items():
                    if key=='auth':values['litellmGatewayMetrics']['auth'].update(value)
                    else:values['litellmGatewayMetrics'][key]=value
                result=render(values)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(message,result.stderr)

    def test_frozen_m1b_source_profile_remain_available_as_historical_files(self):
        frozen=CHART/'files/litellm-m1b'
        source=json.loads((frozen/'gateway-metrics-source-configmap.json').read_text())
        self.assertEqual(hashlib.sha256(source['data']['gateway.py'].encode()).hexdigest(),
            'f550b9890b20da4b02b68fac5c102a99a0313e6f419dc41dd0c409b2bdd165c1')
        profile=json.loads((frozen/'phorvex-litellm-live-profile-64098e6f1280.json').read_text())
        self.assertEqual(hashlib.sha256(profile['data']['profile.json'].encode()).hexdigest(),
            '64098e6f1280f9782edf8d5a3c6eff0e5f92199d5c009a8e571f881e657011d3')

if __name__=='__main__':unittest.main()
