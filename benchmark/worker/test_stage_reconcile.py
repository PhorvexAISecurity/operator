"""Real Git/PXMS/sync/frozen replay controls; Kubernetes/ECR/Console transports scripted.
The executable derives baseline equivalence from actual fixture payloads. It is
not product-engine proof; the independently measured native stage replay is that boundary.
"""
import copy
from datetime import datetime, timezone
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE)); sys.path.insert(0,str(HERE.parents[1]))
import stage_cli
import stage_reconcile as reconcile
import stage_observer_runtime as observer
from mathlab import binary, snapshots, stage_scope
from mathlab.common import read_json,sha256_file
from benchmark.bot import testkit
from benchmark.stage import test_evidence as evidence
from benchmark.stage.evidence import Journal,Reducer
from benchmark.stage.normalize import normalize


def tree(path):
    return {str(p.relative_to(path)):sha256_file(p) for p in Path(path).rglob('*') if p.is_file()}


class Producer:
    def __init__(self,root):
        self.root=root; self.repo=root/'repo'; self.source=testkit.make_repo(self.repo)
        self.data=root/'data'; self.data.mkdir()
        self.policies={}
        for index,policy in enumerate(stage_scope.ALLOWED_POLICIES):
            name=policy.split('/')[1]; workload=stage_scope.POLICY_WORKLOADS[policy]
            self.policies[name]={'metadata':{'name':name,'uid':'policy-'+str(index),'generation':1},
                'spec':{'mode':'active' if index==0 else 'dryRun','selector':{'matchLabels':{'app':workload}}}}
        self.workloads={name:{'metadata':{'name':name,'uid':'workload-'+name,'generation':1},'spec':{'selector':{'matchLabels':{'app':name}}}}
                        for name in stage_scope.POLICY_WORKLOADS.values()}
        self.services={name:{'metadata':{'name':name,'uid':'service-'+name},'spec':{'selector':{'app':name}}} for name in self.workloads}
        self.digests={'brain':'e'*64,'manager':'f'*64}; self.cost_flags=['--math-lab-capture-cost-evidence=true']
        self.capture=list(stage_scope.ALLOWED_POLICIES); self.raw={}; self.make_records()
        self.executable=root/'native-replay'
        script=(testkit.FAKE_REPLAY % {'git_sha':self.source,'threshold':3}).replace("'overridableParameters':", "'endpointStudyMode':'PAIRED_BRAIN_REPLAY','studyCandidatesSchema':'math-lab.study-candidates.v1','overridableParameters':")
        self.executable.write_text(script); self.executable.chmod(0o755)

    def image(self,component):
        return '753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/'+component+':staging-git-'+self.source+'@sha256:'+self.digests[component]

    def make_records(self,bad=False):
        self.raw={}
        for policy in stage_scope.ALLOWED_POLICIES:
            ns,name=policy.split('/')
            for index in range(3):
                at=datetime.fromtimestamp(time.time()-10+index,timezone.utc).isoformat().replace('+00:00','Z')
                header={'schema':'math-lab.snapshot.v1','capturedAt':at,'decidedAt':at,'gitSHA':self.source,
                    'namespace':ns,'policyName':name,'policyUID':self.policies[name]['metadata']['uid'],
                    'policyGeneration':1,'brainImage':self.image('brain'),'captureIdentitySource':'recorder-process','finalized':True}
                rawhead=json.dumps(header).encode(); risk=index+3
                raw=b'PXMLSNP1'+struct.pack('>I',len(rawhead))+rawhead+json.dumps({'risk':risk,'recorded_selected':(risk>3) != bad}).encode()
                self.raw[hashlib.sha256(raw).hexdigest()]=raw

    def deployment(self,component):
        name='staging-brain' if component=='brain' else 'staging-phorvex'
        args=(['--math-lab-capture-policies='+','.join(self.capture),'--math-lab-capture-dir=/capture'] if component=='brain' else self.cost_flags)
        return {'metadata':{'name':name,'uid':component+'-uid','generation':1,'annotations':{'deployment.kubernetes.io/revision':'1'}},
            'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':component,'image':self.image(component),'args':args,
                'volumeMounts':[{'name':'capture','mountPath':'/capture'}]}],
                'volumes':[{'name':'capture','persistentVolumeClaim':{'claimName':'staging-brain-mathlab'}}]}}},
            'status':{'replicas':1,'updatedReplicas':1,'readyReplicas':1,'availableReplicas':1,'observedGeneration':1}}

    def kube(self,context,namespace,*args,**kw):
        assert context==stage_scope.STAGE_CONTEXT
        if args[0]=='get' and ',' in args[1]:
            if namespace==stage_scope.STAGE_NAMESPACE:
                items=[dict(self.deployment(c),kind='Deployment') for c in ('brain','manager')]
                for resource,kind in [('replicasets','ReplicaSet'),('pods','Pod')]:
                    items += [dict(item,kind=kind) for item in self.kube(context,namespace,'get',resource,'-o','json')['items']]
                items.append({'kind':'PersistentVolumeClaim','metadata':{'name':'staging-brain-mathlab','uid':'capture-pvc-uid'},'status':{'phase':'Bound'}})
            else:
                items=[dict(copy.deepcopy(item),kind=kind) for group,kind in [(self.policies,'PhorvexPolicy'),(self.workloads,'Deployment'),(self.services,'Service')] for item in group.values()]
            return {'kind':'List','items':items}
        if args[0]=='exec':
            component=args[3]; return {'service':component,'gitSHA':self.source}
        if args[:2]==('get','deployment'):
            name=args[2]
            if name in self.workloads:return copy.deepcopy(self.workloads[name])
            return self.deployment('brain' if name=='staging-brain' else 'manager')
        if args[:2]==('get','phorvexpolicy'):return copy.deepcopy(self.policies[args[2]])
        if args[:2]==('get','pvc'):return {'metadata':{'uid':'capture-pvc-uid'},'status':{'phase':'Bound'}}
        if args[:2]==('get','replicasets'):
            return {'items':[{'metadata':{'uid':c+'-rs','annotations':{'deployment.kubernetes.io/revision':'1'},
                'ownerReferences':[{'uid':c+'-uid','controller':True}]}} for c in ('brain','manager')]}
        if args[:2]==('get','pods'):
            return {'items':[{'metadata':{'name':c+'-pod','uid':c+'-pod-uid','ownerReferences':[{'uid':c+'-rs','controller':True}]},
                'status':{'phase':'Running','containerStatuses':[{'name':c,'ready':True,'imageID':self.image(c)}]}} for c in ('brain','manager')]}
        raise AssertionError(args)

    def ensure(self,data,image):
        path=Path(data)/'mathlab/bin'/self.digests['brain']/'brain-replay'; path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(self.executable,path)
        identity=binary.local_identity(path); identity.update(local=False,image=image['image'],image_digest=image['image_digest'])
        return identity

    def console(self,**kwargs):
        parent=self
        class Transport:
            def request(self,path):
                query=parse_qs(urlsplit(path).query); policy=query['policy'][0]
                return {'entries':[{'digest':digest,'header':snapshots.read_header(raw)} for digest,raw in parent.raw.items()
                                   if snapshots.read_header(raw)['policyName']==policy]}
            def open(self,path,**kwargs):return io.BytesIO(parent.raw[parse_qs(urlsplit(path).query)['digest'][0]])
            def close(self):pass
        return Transport()


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root=Path(temp.name); self.p=Producer(self.root)
        for patch in (mock.patch.object(stage_cli,'kube',side_effect=self.p.kube),
                      mock.patch.object(binary,'ensure_binary',side_effect=self.p.ensure),
                      mock.patch('runner.Console',side_effect=self.p.console)):
            patch.start(); self.addCleanup(patch.stop)
    def run_reconcile(self,**kw):return reconcile.reconcile(self.p.data,self.p.repo,ticks=2,timeout=30,**kw)
    def test_native_exact_replay_publication_and_readonly_probe(self):
        result=self.run_reconcile(); self.assertEqual(result['status'],'READY',result)
        pin=stage_scope.load(self.p.data); engine=stage_scope.study_engine(self.p.data,pin)
        self.assertEqual(engine['lane'],'native-stage-image'); self.assertNotIn('review_receipt',engine)
        self.assertEqual(set(pin['policies']),set(stage_scope.ALLOWED_POLICIES))
        before=tree(self.p.data),tree(self.p.repo/'.git')
        for policy in stage_scope.ALLOWED_POLICIES:
            probe=stage_cli.probe_runtime(self.p.data,self.p.repo,policy)
            self.assertEqual(probe['status'],'READY',probe)
            self.assertEqual(probe['policy']['workload_generation'],1)
        self.assertEqual(before,(tree(self.p.data),tree(self.p.repo/'.git')))
        with mock.patch.object(binary.tempfile,'TemporaryDirectory',side_effect=AssertionError('readonly version check must not create a temporary HOME')):
            stage_scope.study_engine(self.p.data,pin)
        self.assertEqual(self.run_reconcile()['status'],'READY')
        self.assertEqual(stage_scope.load(self.p.data),pin)

    def test_nonexact_payload_never_replaces_previous_pin(self):
        self.assertEqual(self.run_reconcile()['status'],'READY')
        old=(self.p.data/'mathlab/stage.json').read_bytes()
        self.p.digests['brain']='a'*64; self.p.make_records(bad=True)
        result=self.run_reconcile(); self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('BASELINE_NOT_EXACT',str(result['reasons']))
        self.assertEqual((self.p.data/'mathlab/stage.json').read_bytes(),old)
        stage_scope.study_engine(self.p.data)

    def test_manager_image_race_keeps_old_pin_and_identity(self):
        self.assertEqual(self.run_reconcile()['status'],'READY'); old=(self.p.data/'mathlab/stage.json').read_bytes()
        self.p.digests['brain']='a'*64; self.p.make_records()
        original=reconcile.run_replay
        def replay(*args):
            result=original(*args); self.p.digests['manager']='c'*64; return result
        with mock.patch.object(reconcile,'run_replay',side_effect=replay): result=self.run_reconcile()
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertIn('STAGE_CHANGED_BEFORE_PUBLICATION',str(result['reasons']))
        self.assertEqual((self.p.data/'mathlab/stage.json').read_bytes(),old)

    def test_disabled_capture_and_duplicate_cost_flag_are_actionable(self):
        self.p.capture=[]; result=self.run_reconcile()
        self.assertEqual(result['status'],'BLOCKED'); self.assertFalse((self.p.data/'mathlab/stage.json').exists())
        self.p.capture=list(stage_scope.ALLOWED_POLICIES); self.p.cost_flags += ['--math-lab-capture-cost-evidence=false']
        result=self.run_reconcile(); self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('duplicated',str(result['reasons']))

    def test_current_policy_and_workload_generations_block_old_evidence(self):
        self.assertEqual(self.run_reconcile()['status'],'READY')
        name='demo-api-defense'; self.p.policies[name]['metadata']['generation']=2
        self.p.workloads['demo-api']['metadata']['uid']='replacement'
        probe=stage_cli.probe_runtime(self.p.data,self.p.repo,stage_scope.ALLOWED_POLICIES[0])
        codes={r['code'] for r in probe['reasons']}
        self.assertIn('POLICY_GENERATION_CHANGED',codes); self.assertIn('WORKLOAD_IDENTITY_CHANGED',codes)
        result=self.run_reconcile(); self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('CAPTURE_TICKS_PENDING',str(result['reasons']))

    def test_batched_probe_uses_four_api_processes_and_rejects_service_recreation(self):
        self.assertEqual(self.run_reconcile()['status'],'READY')
        with mock.patch.object(stage_cli,'kube',side_effect=self.p.kube) as transport:
            probe=stage_cli.probe_runtime(self.p.data,self.p.repo,stage_scope.ALLOWED_POLICIES[1])
        self.assertEqual(probe['status'],'READY',probe);self.assertEqual(transport.call_count,4)
        calls=[call.args for call in transport.call_args_list]
        self.assertEqual(sum(args[2]=='exec' for args in calls),2)
        self.assertEqual(sum(',' in args[3] for args in calls if args[2]=='get'),2)
        self.p.services['stage-bench-api']['metadata']['uid']='new-service-uid'
        probe=stage_cli.probe_runtime(self.p.data,self.p.repo,stage_scope.ALLOWED_POLICIES[1])
        self.assertIn('SERVICE_IDENTITY_CHANGED',{item['code'] for item in probe['reasons']})

    def test_unpinned_allowed_active_policy_returns_true_mode_without_writes(self):
        result=reconcile.reconcile(self.p.data,self.p.repo,policies=[stage_scope.ALLOWED_POLICIES[1]],ticks=2,timeout=30)
        self.assertEqual(result['status'],'READY',result); before=tree(self.p.data)
        result=stage_cli.probe_runtime(self.p.data,self.p.repo,stage_scope.ALLOWED_POLICIES[0])
        self.assertEqual(result['policy']['mode'],'active'); self.assertIn('POLICY_NOT_PINNED',{r['code'] for r in result['reasons']})
        self.assertEqual(before,tree(self.p.data))

    def test_missing_lease_and_unapproved_policy_never_initialize_state(self):
        path=self.root/'absent'
        probe=stage_cli.probe_runtime(path,self.p.repo,stage_scope.ALLOWED_POLICIES[0])
        self.assertEqual(probe['status'],'BLOCKED'); self.assertFalse(path.exists())
        with mock.patch.object(stage_cli,'kube',side_effect=AssertionError('no API')):
            result=stage_cli.probe_runtime(path,self.p.repo,'phorvex-staging-demo/evil')
        self.assertEqual(result['reasons'][0]['code'],'POLICY_NOT_ALLOWED')

    def test_publication_failure_keeps_single_old_pointer(self):
        self.assertEqual(self.run_reconcile()['status'],'READY'); path=self.p.data/'mathlab/stage.json'; before=path.read_bytes()
        pin=stage_scope.load(self.p.data); pin['installed_at']='changed'
        replace=os.replace
        def fail(source,target):
            if Path(target)==path:raise OSError('injected atomic publication failure')
            return replace(source,target)
        with stage_scope.pin_lock(self.p.data,exclusive=True),mock.patch.object(stage_cli.os,'replace',side_effect=fail):
            with self.assertRaises(OSError):stage_cli.publish_pin(self.p.data,pin)
        self.assertEqual(path.read_bytes(),before); stage_scope.study_engine(self.p.data)
        self.assertEqual(len(list((self.p.data/'mathlab/pin-history').glob('*.json'))),1)

    def test_native_proof_survives_working_cache_prune_but_not_evidence_tamper(self):
        self.assertEqual(self.run_reconcile()['status'],'READY')
        pin=stage_scope.load(self.p.data)
        shutil.rmtree(self.p.data/'mathlab/snapshots')
        stage_scope.study_engine(self.p.data,pin)
        ref=Path(pin['native_study']['baseline_evidence'][0]['path']); receipt=read_json(ref)
        raw=next(Path(receipt['cohort_path']).glob('*.pxms')); raw.write_bytes(b'changed')
        with self.assertRaises(stage_scope.StageError):stage_scope.study_engine(self.p.data,pin)

    def test_capacity_guard_preserves_pin(self):
        self.assertEqual(self.run_reconcile()['status'],'READY'); old=(self.p.data/'mathlab/stage.json').read_bytes()
        low=shutil._ntuple_diskusage(10<<30,7<<30,3<<30)
        with mock.patch.object(reconcile.shutil,'disk_usage',return_value=low):result=self.run_reconcile()
        self.assertEqual(result['status'],'BLOCKED'); self.assertIn('DISK_RESERVE',str(result['reasons']))
        self.assertEqual((self.p.data/'mathlab/stage.json').read_bytes(),old)

    def test_native_oversized_frozen_file_is_rejected_before_unbounded_hash(self):
        self.assertEqual(self.run_reconcile()['status'],'READY');pin=stage_scope.load(self.p.data)
        receipt=read_json(pin['native_study']['baseline_evidence'][0]['path'])
        raw=next(Path(receipt['cohort_path']).glob('*.pxms'))
        with raw.open('r+b') as stream:stream.truncate(snapshots.MAX_SNAPSHOT_BYTES+1)
        with self.assertRaisesRegex(stage_scope.StageError,'oversized'):
            stage_scope.study_engine(self.p.data,pin)

    def test_missing_source_blob_and_unavailable_origin_preserve_previous_pin(self):
        self.assertEqual(self.run_reconcile()['status'],'READY')
        pin=self.p.data/'mathlab/stage.json';before=pin.read_bytes()
        blob=testkit.git(self.p.repo,'rev-parse','HEAD:phorvex/internal/decision/decision.go')
        (self.p.repo/'.git/objects'/blob[:2]/blob[2:]).unlink()
        probe=stage_cli.probe_runtime(self.p.data,self.p.repo,stage_scope.ALLOWED_POLICIES[0])
        self.assertIn('REPLAY_SOURCE_UNAVAILABLE',{reason['code'] for reason in probe['reasons']})
        original=subprocess.Popen
        def absent_origin(args,**kwargs):
            args=list(args)
            if 'fetch' in args:args[args.index('origin')]='file://'+str(self.root/'absent-origin')
            return original(args,**kwargs)
        with mock.patch.object(reconcile.subprocess,'Popen',side_effect=absent_origin):result=self.run_reconcile()
        self.assertEqual(result['status'],'BLOCKED');self.assertIn('SOURCE_FETCH_UNAVAILABLE',str(result['reasons']))
        self.assertEqual(pin.read_bytes(),before)


class LeaseAndGitTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.root=Path(tmp.name)
    def test_reader_blocks_writer_and_reentrant_nested_calls_release(self):
        failures=[]
        with stage_scope.pin_lock(self.root):
            with stage_scope.pin_lock(self.root,readonly=True):pass
            with self.assertRaisesRegex(stage_scope.StageError,'upgraded'):
                with stage_scope.pin_lock(self.root,exclusive=True):pass
            def writer():
                try:
                    with stage_scope.pin_lock(self.root,exclusive=True,timeout=.1):failures.append('acquired')
                except stage_scope.StageError:failures.append('busy')
            thread=threading.Thread(target=writer); thread.start(); thread.join()
        self.assertEqual(failures,['busy'])
        with stage_scope.pin_lock(self.root,exclusive=True):
            with stage_scope.pin_lock(self.root):pass

    def test_actual_promisor_read_does_not_fetch_or_modify_git_objects(self):
        source=self.root/'source'; first=testkit.make_repo(source)
        testkit.git(source,'config','uploadpack.allowFilter','true')
        target=self.root/'partial'
        subprocess.run(['git','clone','-q','--filter=blob:none','--no-checkout','file://'+str(source),str(target)],check=True)
        testkit.git(target,'remote','rename','origin','promisor')
        testkit.git(target,'remote','add','origin',stage_scope.REPOSITORY)
        testkit.git(source,'commit','--allow-empty','-qm','new source')
        missing=testkit.git(source,'rev-parse','HEAD')
        before=tree(target/'.git')
        self.assertEqual(stage_scope.repository(target,first),stage_scope.REPOSITORY)
        with self.assertRaises(stage_scope.StageError):stage_scope.repository(target,missing)
        self.assertEqual(before,tree(target/'.git'))
        # Deliberate retrieval remains a separate operator action.
        testkit.git(target,'fetch','promisor',missing)
        self.assertEqual(stage_scope.repository(target,missing),stage_scope.REPOSITORY)

    def test_required_promisor_trees_materialize_for_existing_offline_checkout(self):
        from benchmark.bot import replay_build
        remote=self.root/'remote';first=testkit.make_repo(remote)
        testkit.git(remote,'config','uploadpack.allowFilter','true')
        partial=self.root/'partial'
        subprocess.run(['git','clone','-q','--filter=blob:none','--no-checkout','file://'+str(remote),str(partial)],check=True)
        testkit.git(partial,'remote','set-url','origin',stage_scope.REPOSITORY)
        for number in range(270):(remote/('source-%03d.txt'%number)).write_text('required exact source blob '+str(number))
        testkit.git(remote,'add','.');testkit.git(remote,'commit','-qm','deployed source with missing blobs')
        source=testkit.git(remote,'rev-parse','HEAD')
        # Seed only the newer commit/tree graph, exactly the previously unsafe
        # blob:none lane. HEAD stays at the older tree that clone checks first.
        subprocess.run(['git','-C',str(partial),'-c','remote.origin.promisor=true','-c','remote.origin.partialclonefilter=blob:none',
                        'fetch','--no-tags','--no-write-fetch-head','--filter=blob:none','file://'+str(remote),source],check=True,capture_output=True)
        original_head=testkit.git(partial,'rev-parse','HEAD');self.assertEqual(original_head,first)
        config=(partial/'.git/config').read_bytes();before=tree(partial/'.git')
        command=['git','-C',str(partial),'archive','--format=tar',source]
        initial=subprocess.run(command,env=stage_scope.observation_git_env(),capture_output=True)
        self.assertNotEqual(initial.returncode,0);self.assertEqual(before,tree(partial/'.git'))
        with self.assertRaisesRegex(stage_scope.StageError,'unavailable offline'):
            stage_scope.repository(partial,source,complete_tree=True)
        self.assertEqual(before,tree(partial/'.git'))
        original=subprocess.Popen;fetches=[]
        def local_transport(args,**kwargs):
            args=list(args)
            if 'fetch' in args:
                self.assertIn('origin',args);fetches.append(args)
                args[args.index('origin')]='file://'+str(remote)
            return original(args,**kwargs)
        with mock.patch.object(reconcile.subprocess,'Popen',side_effect=local_transport):
            receipt=reconcile.ensure_source(partial,source,time.monotonic()+30)
        self.assertTrue(receipt['fetched']);self.assertGreaterEqual(len(fetches),2)
        self.assertEqual(config,(partial/'.git/config').read_bytes());self.assertEqual(original_head,testkit.git(partial,'rev-parse','HEAD'))
        self.assertEqual({r['source_revision'] for r in receipt['offline_checkout_trees']},{first,source})
        after=subprocess.run(command,env=stage_scope.observation_git_env(),capture_output=True)
        expected=subprocess.run(['git','-C',str(remote),'archive','--format=tar',source],capture_output=True,check=True)
        self.assertEqual(after.returncode,0);self.assertEqual(after.stdout,expected.stdout)
        self.assertEqual(stage_scope.repository(partial,source,complete_tree=True),stage_scope.REPOSITORY)
        stable=tree(partial/'.git')
        with mock.patch.dict(os.environ,{'GIT_NO_LAZY_FETCH':'1','GIT_ALLOW_PROTOCOL':'file'}):
            checkout=replay_build.checkout(partial,source,self.root/'offline-checkout')
        self.assertEqual((checkout/'source-269.txt').read_text(),'required exact source blob 269')
        self.assertEqual((checkout/'phorvex/internal/decision/decision.go').read_bytes(),(remote/'phorvex/internal/decision/decision.go').read_bytes())
        self.assertEqual(stable,tree(partial/'.git'))


class NativeImageExtractionTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.source='a'*40
        self.script=(testkit.FAKE_REPLAY % {'git_sha':self.source,'threshold':3}).replace("'overridableParameters':", "'endpointStudyMode':'PAIRED_BRAIN_REPLAY','studyCandidatesSchema':'math-lab.study-candidates.v1','overridableParameters':").encode()
    def extract(self,raw,declared_size=None):
        digest='sha256:'+hashlib.sha256(raw).hexdigest()
        manifest=json.dumps({'schemaVersion':2,'mediaType':binary.MANIFEST_TYPES[0],
                             'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':digest,'size':len(raw) if declared_size is None else declared_size}]})
        image_digest='sha256:'+hashlib.sha256(manifest.encode()).hexdigest()
        repo='753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/brain'
        image={'repository':repo,'image':repo+':staging-git-'+self.source+'@'+image_digest,'digest':image_digest}
        def ecr(args,region):
            if args[0]=='batch-get-image':return {'images':[{'imageManifest':manifest}]}
            if args[0]=='get-download-url-for-layer':return {'downloadUrl':'https://fixture.invalid/layer'}
            raise AssertionError(args)
        with mock.patch.object(binary,'_ecr',side_effect=ecr),mock.patch.object(binary.urllib.request,'urlopen',return_value=io.BytesIO(raw)):
            return binary.ensure_binary(self.root,image)
    def test_verified_archive_yields_actual_native_version(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as tar:
            item=tarfile.TarInfo('brain-replay');item.size=len(self.script);item.mode=0o755
            tar.addfile(item,io.BytesIO(self.script))
        identity=self.extract(stream.getvalue())
        self.assertEqual(identity['git_sha'],self.source)
        self.assertEqual(identity['endpoint_study_mode'],'PAIRED_BRAIN_REPLAY')
        self.assertEqual(identity['binary_sha256'],hashlib.sha256(self.script).hexdigest())
    def test_oversized_binary_and_decoded_archive_refuse_before_body_allocation(self):
        for name,size,reason in [('brain-replay',129<<20,'binary exceeds'),('padding',3<<30,'decoded archive')]:
            with self.subTest(name=name):
                item=tarfile.TarInfo(name);item.size=size
                blob=gzip.compress(item.tobuf()+b'\0'*1024)
                with self.assertRaisesRegex(binary.BinaryError,reason):self.extract(blob)
        with self.assertRaisesRegex(binary.BinaryError,'total layer download'):
            self.extract(gzip.compress(b'\0'*1024),declared_size=(512<<20)+1)


if __name__=='__main__':unittest.main()
