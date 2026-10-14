"""Offline fail-closed controls using synthetic nonsecret owner evidence."""
import copy
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import contextlib
import io
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
        closure={'schema':'phorvex-litellm-metrics-candidate-v1','baseline':{'deploymentUID':'deployment-fixture','sourceUID':'source-fixture','serviceUID':'service-fixture',
            'deploymentSpecSHA256':hashlib.sha256(canonical(d['spec']).encode()).hexdigest(),
            'profiles':[{'uid':'profile-fixture','name':'profile','profileSHA256':profile_sha}],'prometheusPodLabels':labels},
            'previousGatewaySourceSHA256':source_sha,'gatewayImageByDigest':'fixture@sha256:'+sha,'gatewaySourceSHA256':sha}
        runtime={'schema':'phorvex-litellm-gateway-runtime-reuse-receipt-v1','result':'pass-local-and-published-image-protocol',
                 'imageByDigest':closure['gatewayImageByDigest'],'gatewaySourceSHA256':sha,'sourceCommit':'a'*40}
        utc=datetime.now(timezone.utc).isoformat()
        config={'utc':utc,'containerArgs':[{'name':'aws-eks-nodeagent','args':['--enable-network-policy=true']}],
                'networkPolicyEnv':[{'name':'NETWORK_POLICY_ENFORCING_MODE','value':'strict'}]}
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
                ('standard-startup',lambda x:x[3]['networkPolicyEnv'][0].update(value='standard'),'strict CNI startup'),
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

    def test_legacy_network_freshness_and_unknown_modes_remain_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp))
            for index in (3,4,5):
                for offset in (-1801,1):
                    current=copy.deepcopy(args)
                    current[index]['utc']=(datetime.now(timezone.utc)+timedelta(seconds=offset)).isoformat()
                    with self.subTest(index=index,offset=offset),self.assertRaisesRegex(ValueError,'fresh owner evidence'):
                        check(*current)
            for mode in ('bearerToken','unknown'):
                current=copy.deepcopy(args);current[0]['metricsProtection']={'mode':mode}
                with self.assertRaisesRegex(ValueError,'legacy v1'):
                    check(*current)
            current=copy.deepcopy(args);current[0].pop('schema')
            with self.assertRaisesRegex(ValueError,'closure schema'):
                check(*current)


class AuthGuardTests(unittest.TestCase):
    def fixture(self,path):
        from prepare_metrics_activation import prepare
        from test_prepare_metrics import owned_inputs
        from test_render_metrics import AUTH, module
        from test_metrics_token_helpers import make_metadata_fixture, make_auth_fixture
        inputs=path/'inputs';values_path,values=owned_inputs(inputs)
        candidate=prepare(inputs,values_path,**AUTH)
        artifacts=path/'candidate';artifacts.mkdir()
        for name,value in candidate.items():
            (artifacts/name).write_text(canonical(value)+'\n')
        closure=candidate['metrics-closure.json']
        contract=json.loads((Path(__file__).resolve().parents[4]/'build/integrations/litellm-gateway-runtime/image-contract.json').read_text())
        runtime={'schema':'phorvex-litellm-gateway-runtime-reuse-receipt-v2',
            'result':'pass-local-and-published-image-protocol','imageByDigest':closure['gatewayImageByDigest'],
            'gatewaySourceSHA256':closure['gatewaySourceSHA256'],'sourceCommit':'a'*40,'mountedSourceCommit':'a'*40,
            'publishedImageSourceCommit':contract['publishedImageSourceCommit'],
            'publicationReceiptSHA256':contract['publishedReceiptSHA256'],
            'previousMetricsSourceSHA256':contract['previousMetricsSourceSHA256']}
        metadata=make_metadata_fixture(closure)
        proof=make_auth_fixture(closure,metadata,module.GATEWAY_SOURCE.read_text())
        utc=datetime.now(timezone.utc).isoformat();stamp=datetime.now(timezone.utc).timestamp()
        from guard_metrics_activation import NATIVE_QUERIES
        prom={'utc':utc,'queries':{name:{'query':query,'result':{'status':'success','data':{
            'resultType':'vector','result':[{'metric':{'namespace':'vllm','pod':'native-fixture'},'value':[stamp,'1']}]}}}
            for name,query in NATIVE_QUERIES.items()},
            'targets':[{'labels':{'job':'vllm','namespace':'vllm','pod':'native-fixture'},'health':'up','lastError':''}],
            'bridgeRules':[{'name':'phorvex.physics.bridge','rules':[{'name':'http_requests_total',
                'query':'sum by (namespace, pod, container, node) (vllm:request_success_total)',
                'health':'ok','lastEvaluation':utc}]}]}
        args=[closure,inputs,runtime,{'utc':utc,'containerArgs':[{'name':'aws-eks-nodeagent',
            'args':['--enable-network-policy=false']}],'networkPolicyEnv':[{'name':'NETWORK_POLICY_ENFORCING_MODE','value':'standard'}]},None,prom]
        return args,{'auth_proof':proof,'secret_metadata':metadata,'artifacts':artifacts}

    def test_disabled_cni_with_valid_auth_passes_protection_and_native_hard_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,kwargs=self.fixture(Path(tmp))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):result=check(*args,**kwargs)
            self.assertEqual(result['protectionMode'],'bearerToken')
            self.assertEqual(result['nativeDecision'],'B')
            self.assertIn('PROTECTION PASS',output.getvalue())
            args[5]['queries']['vllm-up']['result']['data']['result'][0]['value'][1]='0'
            output=io.StringIO()
            with contextlib.redirect_stdout(output),self.assertRaisesRegex(ValueError,'native vLLM.*invalid'):
                check(*args,**kwargs)
            self.assertIn('PROTECTION PASS',output.getvalue())
            args[5]['queries']['vllm-up']['result']['data']['result'][0]['value'][1]='1'
            args[5]['queries']['vllm-ReqRate']['result']['data']['result']=[]
            with self.assertRaisesRegex(ValueError,'prerequisite unavailable'):
                check(*args,**kwargs)

    def test_missing_stale_future_and_wrong_source_or_receipt_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,kwargs=self.fixture(Path(tmp))
            for name in ('auth_proof','secret_metadata'):
                for value in (None,'stale','future'):
                    current=copy.deepcopy(kwargs)
                    if value is None:current[name]=None
                    else:current[name]['utc']=(datetime.now(timezone.utc)+timedelta(seconds=-1801 if value=='stale' else 60)).isoformat()
                    with self.subTest(name=name,value=value),self.assertRaisesRegex(ValueError,'fresh'):
                        check(*args,**current)
            for mutate in (
                lambda a:a[0]['metricsProtection'].update(mode='networkEnforced'),
                lambda a:a[0]['metricsProtection'].update(tokenFile='/foreign/token'),
                lambda a:a[0]['metricsProtection'].update(secretKey='master-key'),
                lambda a:a[0].update(gatewaySourceSHA256='f550b9890b20da4b02b68fac5c102a99a0313e6f419dc41dd0c409b2bdd165c1'),
                lambda a:a[2].update(schema='phorvex-litellm-gateway-runtime-reuse-receipt-v1'),
                lambda a:a[2].update(mountedSourceCommit='b'*40),
                lambda a:a[0].update(nativeDecision='A'),
            ):
                current=copy.deepcopy(args);mutate(current)
                with self.assertRaises(ValueError):check(*current,**kwargs)

    def test_secret_generation_uid_rv_annotation_and_proof_binding_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,kwargs=self.fixture(Path(tmp))
            for mutate in (
                lambda k:k['secret_metadata']['secrets'][0].update(uid='replacement-same-name'),
                lambda k:k['secret_metadata']['secrets'][0].update(resourceVersion='drifted-version'),
                lambda k:k['secret_metadata']['secrets'][0].update(lastAppliedPresent=True),
                lambda k:k['secret_metadata']['secrets'][0].update(pairID='foreign-generation'),
                lambda k:k['auth_proof'].update(gatewaySourceSHA256='a'*64),
                lambda k:k['auth_proof'].update(candidateTemplateSHA256='a'*64),
                lambda k:k['auth_proof'].update(modelCalls=1),
            ):
                current=copy.deepcopy(kwargs);mutate(current)
                with self.assertRaises(ValueError):check(*args,**current)

    def test_rehashed_bad_projection_or_endpoint_still_fails_reviewed_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,kwargs=self.fixture(Path(tmp))
            from render_metrics import object_hash
            for name,mutate in (
                ('deployment-metrics-json-patch.json',lambda obj:obj[3]['value']['spec']['volumes'][-1]['secret'].update(optional=True)),
                ('metrics-servicemonitor.json',lambda obj:obj['spec']['endpoints'][0]['authorization']['credentials'].update(key='master-key')),
            ):
                path=kwargs['artifacts']/name;original=path.read_text();obj=json.loads(original);mutate(obj)
                path.write_text(canonical(obj)+'\n');current=copy.deepcopy(args)
                current[0]['artifactsSHA256'][name]=object_hash(obj)
                with self.assertRaisesRegex(ValueError,'candidate template/projection/endpoint'):
                    check(*current,**kwargs)
                path.write_text(original)

    def test_native_query_or_identity_or_ten_minute_health_drift_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,kwargs=self.fixture(Path(tmp))
            for mutate in (
                lambda p:p['queries']['vllm-up10m']['result']['data']['result'][0]['value'].__setitem__(1,'0'),
                lambda p:p['queries']['vllm-ReqRate'].update(query='sum(http_requests_total)'),
                lambda p:p['queries']['vllm-native']['result']['data']['result'][0]['metric'].update(pod='foreign-pod'),
                lambda p:p['targets'][0].update(health='down'),
                lambda p:p['bridgeRules'][0]['rules'][0].update(health='err'),
            ):
                current=copy.deepcopy(args);mutate(current[5])
                with self.assertRaises(ValueError):check(*current,**kwargs)


if __name__=='__main__':unittest.main()
