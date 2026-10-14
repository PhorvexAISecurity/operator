"""Offline fail-closed controls using synthetic nonsecret owner evidence."""
import copy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from guard_metrics_activation import check
from render import canonical


class GuardTests(unittest.TestCase):
    def fixture(self,path):
        sha='a'*64
        d={'metadata':{'uid':'deployment-fixture'},'spec':{'template':{'metadata':{'annotations':{}},'spec':{}}}}
        src='fixture-preserved-source';source_sha=hashlib.sha256(src.encode()).hexdigest()
        profile='{}';profile_sha=hashlib.sha256(profile.encode()).hexdigest()
        objects={
            'deployment.json':d,
            'gateway-source.json':{'metadata':{'uid':'source-fixture'},'immutable':True,'data':{'gateway.py':src}},
            'service.json':{'metadata':{'uid':'service-fixture'},'spec':{'ports':[{'targetPort':4001}]}},
            'profiles.json':[{'metadata':{'uid':'profile-fixture','name':'profile'},'immutable':True,'data':{'profile.json':profile}}],
            'output-policy.json':None}
        for name,obj in objects.items():(path/name).write_text(canonical(obj))
        labels={'app.kubernetes.io/name':'prometheus','prometheus':'fixture-prometheus'}
        closure={'baseline':{'deploymentUID':'deployment-fixture','sourceUID':'source-fixture','serviceUID':'service-fixture',
            'deploymentSpecSHA256':hashlib.sha256(canonical(d['spec']).encode()).hexdigest(),
            'profiles':[{'uid':'profile-fixture','name':'profile','profileSHA256':profile_sha}],'prometheusPodLabels':labels},
            'previousGatewaySourceSHA256':source_sha,'gatewayImageByDigest':'fixture@sha256:'+sha,'gatewaySourceSHA256':sha}
        runtime={'schema':'phorvex-litellm-gateway-runtime-reuse-receipt-v1','result':'pass-local-and-published-image-protocol',
                 'imageByDigest':closure['gatewayImageByDigest'],'gatewaySourceSHA256':sha,'sourceCommit':'a'*40}
        utc=datetime.now(timezone.utc).isoformat()
        config={'utc':utc,'containerArgs':[{'name':'aws-eks-nodeagent','args':['--enable-network-policy=true']}]}
        network={'utc':utc,'schema':'phorvex-litellm-network-enforcement-proof-v1','allowed':True,'denied':True,
                 'allowedPodUID':'allowed-fixture','deniedPodUID':'denied-fixture','prometheusPodLabels':labels,'evidenceSHA256':'b'*64}
        samples={'status':'success','data':{'result':[{'value':[1,'1']}]}}
        prom={'utc':utc,'queries':{name:{'result':copy.deepcopy(samples)} for name in ('vllm-up','vllm-native','vllm-ReqRate')}}
        return closure,path,runtime,config,network,prom

    def test_valid_structural_controls_and_invalid_external_gates(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp));check(*args)
            for name,mutate,message in [
                ('disabled-CNI',lambda x:x[3]['containerArgs'][0].update(args=['--enable-network-policy=false']),'enforcement disabled'),
                ('wrong-image',lambda x:x[2].update(imageByDigest='foreign:latest'),'image/source proof'),
                ('missing-denied-witness',lambda x:x[4].update(denied=False),'witness required'),
                ('down-native-source',lambda x:x[5]['queries']['vllm-up']['result']['data']['result'][0].update(value=[1,'0']),'prerequisite invalid'),
                ('absent-ReqRate',lambda x:x[5]['queries']['vllm-ReqRate']['result']['data'].update(result=[]),'prerequisite unavailable'),
            ]:
                with self.subTest(name=name):
                    current=copy.deepcopy(args);mutate(current)
                    with self.assertRaisesRegex(ValueError,message):check(*current)

    def test_owner_drift_and_active_output_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);args=self.fixture(path)
            (path/'output-policy.json').write_text(canonical({'version':2,'revision':1,'entries':[{}]}))
            with self.assertRaisesRegex(ValueError,'quiescent'):check(*args)
            (path/'output-policy.json').write_text('null')
            d=json.loads((path/'deployment.json').read_text());d['spec']['replicas']=3
            (path/'deployment.json').write_text(canonical(d))
            with self.assertRaisesRegex(ValueError,'UID/spec drift'):check(*args)

if __name__=='__main__':unittest.main()
