"""Real journal/normalizer/cached-byte controls with explicit external transports.

The replay executable below is a scripted CLI boundary, not real brain proof;
the product's real Recorder/export/paired CLI tests cover engine semantics.
No final READY flag or journal coverage result is mocked here.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))
import endpoint_refresh as refresh
from benchmark.bot import testkit
from benchmark.stage import test_evidence as observed
from benchmark.stage.normalize import atomic_json
from mathlab import snapshots, stage_scope
from mathlab.common import read_json


SCRIPT = r'''#!/usr/bin/python3
import datetime, hashlib, json, pathlib, struct, sys
SOURCE = %r
args = sys.argv[1:]
if '-version' in args:
    print(json.dumps({'gitSHA':SOURCE})); sys.exit(0)
def opt(name): return args[args.index(name)+1]
rows=[]
for path in sorted(pathlib.Path(opt('-snapshots')).glob('*.pxms')):
    raw=path.read_bytes(); n=struct.unpack('>I',raw[8:12])[0]
    header,payload=json.loads(raw[12:12+n]),json.loads(raw[12+n:])
    exact=(payload['risk']>3)==payload['recorded_selected']
    if '-export-study-candidates' in args:
        assert SOURCE==header['gitSHA'] or '-allow-cross-version' in args
        row=payload['export']; row.update(source_revision=SOURCE,snapshot_source_revision=header['gitSHA'],
            snapshot_digest=path.stem,baseline_reproduced=exact,cross_version=SOURCE!=header['gitSHA'],observational=SOURCE!=header['gitSHA'])
    else:
        assert SOURCE==header['gitSHA']
        row={'status':'OK','snapshot':{'snapshot_digest':path.stem},'baseline_check':{'reproduced':exact}}
    rows.append(row)
pathlib.Path(opt('-out')).write_text(''.join(json.dumps(row)+'\n' for row in rows))
if '-summary' in args: pathlib.Path(opt('-summary')).write_text('{}')
'''


class RefreshTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root/'data'
        self.repo = self.root/'repo'
        self.source = testkit.make_repo(self.repo)
        self.policy = 'phorvex-staging-demo/stage-bench-defense'
        self.pin = testkit.write_stage_pin(self.data, self.source, self.policy, 'policy-uid')
        self.pin['brain'].update(deployment='staging-brain', deployment_uid='brain-uid', digest=self.pin['brain']['image_digest'])
        atomic_json(self.data/'mathlab/stage.json', self.pin)
        base = Path(self.pin['replay']['path'])
        base.write_text(SCRIPT % self.source)
        self.pin['replay']['binary_sha256'] = refresh.sha256_file(base)
        atomic_json(self.data/'mathlab/bin/current.json', self.pin['replay'])
        atomic_json(self.data/'mathlab/stage.json', self.pin)
        (self.repo/'candidate').write_text('explicit candidate fixture')
        testkit.git(self.repo, 'add', 'candidate'); testkit.git(self.repo, 'commit', '-qm', 'candidate')
        self.candidate_source = testkit.git(self.repo, 'rev-parse', 'HEAD')
        candidate = self.root/'candidate-replay'
        candidate.write_text(SCRIPT % self.candidate_source); candidate.chmod(0o755)
        evidence = self.root/'review-control.txt'; evidence.write_text('explicit local test-only review fixture')
        receipt = self.root/'review.json'
        atomic_json(receipt, {'schema':'phorvex-bench.study-engine-review.v1','result':'PASS','reviewer':'test-fixture',
            'source_revision':self.candidate_source,'base_source':self.source,
            'candidate_binary_sha256':refresh.sha256_file(candidate),'base_binary_sha256':refresh.sha256_file(base),
            'evidence_sha256':[refresh.sha256_file(evidence)]})
        self.engine = refresh.stage_cli.install_study_engine(self.data, self.repo, candidate, self.candidate_source, base, [receipt,evidence])
        scope = observed.scope()
        scope.update(source_revision=self.source, image_digest=self.pin['brain']['image_digest'], context=self.pin['kube_context'])
        self.journal = observed.Journal(self.root/'journal.sqlite', scope)
        self.addCleanup(self.journal.close)
        observed.seed(self.journal); observed.rotate(self.journal); observed.seal(self.journal,1000)
        self.folder = self.data/'mathlab/snapshots'/self.policy
        self.folder.mkdir(parents=True)
        self.digests = [self.snapshot(at) for at in range(650,720)]
        self.sync = mock.patch.object(refresh.stage_cli,'sync_stage',return_value={'downloaded_digests':self.digests,'downloaded':70}).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(refresh.time,'time',return_value=1000).start()
        self.live = mock.patch.object(refresh.stage_cli,'running_image',return_value=copy.deepcopy(self.pin['brain'])).start()
        mock.patch.object(refresh.stage_cli,'kube',return_value={'metadata':{'uid':'policy-uid'}}).start()

    def snapshot(self, at, **changes):
        date = datetime.fromtimestamp(at,timezone.utc).isoformat().replace('+00:00','Z')
        header={'schema':'math-lab.snapshot.v1','capturedAt':date,'decidedAt':date,
            'namespace':self.policy.split('/')[0],'policyName':self.policy.split('/')[1],
            'policyUID':'policy-uid','gitSHA':self.source,'brainImage':self.pin['brain']['image'],
            'captureIdentitySource':'recorder-process','finalized':True}
        header.update(changes)
        encoded=json.dumps(header).encode()
        raw=b'PXMLSNP1'+struct.pack('>I',len(encoded))+encoded+json.dumps(
            {'risk':4,'recorded_selected':True,'export':observed.export(at)}).encode()
        value=hashlib.sha256(raw).hexdigest()
        (self.folder/(value+'.pxms')).write_bytes(raw)
        return value

    def run_refresh(self, **options):
        values={'target':.9,'window':600,'lookback':600,'worth_threshold':0,'ticks':64}
        values.update(options)
        return refresh.refresh(self.data,self.repo,self.policy,self.journal.path,**values)

    def pointer(self):
        return self.data/'mathlab/endpoint-traces'/(self.policy+'.manifest.json')

    def test_real_normalization_latest64_true_sourcepins_and_atomic_generation(self):
        result=self.run_refresh()
        self.assertEqual(result['state'],'READY',result)
        self.assertEqual(result['snapshot_digests'],self.digests[-64:])
        manifest=read_json(self.pointer())
        trace=read_json(self.pointer().parent/manifest['trace_file'])
        self.assertEqual(trace['source_revision'],self.candidate_source)
        self.assertEqual(manifest['snapshot_source_revision'],self.source)
        self.assertEqual(manifest['normalization']['journal_prefix'],result['observed_segment']['journal_prefix'])
        self.assertEqual(manifest['normalization']['refresh']['baseline_exact_count'],64)
        self.assertEqual(trace['ticks'][0]['ledger']['moves'][0]['intervals'][0],
            {'endpoint_uid':'service-uid:p1','start':23,'end':30})
        self.assertFalse(trace['ticks'][0]['ledger']['authoritative'])
        self.assertEqual(trace['ticks'][0]['candidates'][0]['samples'][0]['duration'],10)
        self.assertEqual(result['current_dataset']['trace_file'],manifest['trace_file'])

    def test_new_pin_or_policy_recreation_never_replaces_last_good_dataset(self):
        self.assertEqual(self.run_refresh()['state'],'READY')
        before=self.pointer().read_bytes()
        self.live.return_value['deployment_uid']='replacement'
        result=self.run_refresh()
        self.assertEqual(result['state'],'BLOCKED')
        self.assertIn('LIVE_STAGE_CHANGED',result['reason'])
        self.assertEqual(self.pointer().read_bytes(),before)

    def test_changed_installed_engine_is_revalidated_before_publication(self):
        self.assertEqual(self.run_refresh()['state'],'READY')
        before=self.pointer().read_bytes()
        original=refresh.run_replay
        def change_after_export(args,*rest):
            original(args,*rest)
            if '-export-study-candidates' in args:
                engine=read_json(self.data/'mathlab/study-engine.json'); engine['classification']='changed'
                atomic_json(self.data/'mathlab/study-engine.json',engine)
        with mock.patch.object(refresh,'run_replay',side_effect=change_after_export):
            result=self.run_refresh()
        self.assertEqual(result['state'],'BLOCKED')
        self.assertIn('STUDY_ENGINE_CHANGED',result['reason'])
        self.assertEqual(self.pointer().read_bytes(),before)

    def test_wrong_observer_source_fails_before_sync(self):
        wrong=observed.Journal(self.root/'wrong.sqlite',{**self.journal.scope,'source_revision':'f'*40})
        wrong.close()
        result=refresh.refresh(self.data,self.repo,self.policy,self.root/'wrong.sqlite',target=.9,window=600,lookback=600,worth_threshold=0)
        self.assertIn('JOURNAL_STAGE_PIN_MISMATCH',result['reason']); self.sync.assert_not_called()

    def test_insufficient_history_gap_and_unsealed_ticks_remain_unavailable(self):
        result=self.run_refresh(window=2592000,lookback=86400)
        self.assertIn('OBSERVED_HISTORY_INSUFFICIENT',result['reason'])
        self.journal.append('gap',{'reason':'disconnect'},at=1001)
        observed.seed(self.journal,at=1100,session='second'); observed.seal(self.journal,1800,session='second')
        with mock.patch.object(refresh.time,'time',return_value=1800):
            result=self.run_refresh()
        self.assertIn('ELIGIBLE_SNAPSHOTS_INSUFFICIENT',result['reason'])
        with self.journal.read_snapshot() as prefix:
            segment=refresh.segment(self.journal,prefix)
            self.assertEqual(segment['complete_from'],1100)

    def test_future_bookmark_seals_history_but_concurrent_append_cannot_change_frozen_prefix(self):
        prefix=self.journal.db.execute('SELECT max(seq) FROM events').fetchone()[0]
        original=refresh.run_replay
        appended=[]
        def append_during_replay(args,*rest):
            if not appended:
                observed.seal(self.journal,1200); appended.append(True)
            return original(args,*rest)
        with mock.patch.object(refresh,'run_replay',side_effect=append_during_replay):
            result=self.run_refresh()
        self.assertEqual(result['state'],'READY',result)
        self.assertEqual(result['observed_segment']['journal_prefix']['seq'],prefix)
        self.assertEqual(result['observed_segment']['sealed_until'],1000)
        self.assertEqual(read_json(self.pointer())['normalization']['journal_prefix']['seq'],prefix)

    def test_snapshot_header_filters_reject_manager_stamp_wrong_uid_and_future_clock(self):
        extras=[self.snapshot(800,captureIdentitySource='manager'),self.snapshot(801,policyUID='wrong'),
            self.snapshot(802,brainImage='other'),self.snapshot(803,finalized=False),self.snapshot(1100)]
        result=self.run_refresh()
        self.assertEqual(result['state'],'READY',result)
        self.assertFalse(set(extras)&set(result['snapshot_digests']))

    def test_hash_tamper_blocks_copy_and_keeps_last_good(self):
        self.assertEqual(self.run_refresh()['state'],'READY')
        before=self.pointer().read_bytes()
        self.sync.return_value={'downloaded_digests':[]}
        path=self.folder/(self.digests[-1]+'.pxms'); path.write_bytes(path.read_bytes()+b' ')
        result=self.run_refresh()
        self.assertIn('CONTENT_ADDRESS_MISMATCH',result['reason'])
        self.assertEqual(self.pointer().read_bytes(),before)

    def test_baseline_divergence_stops_export(self):
        path=self.folder/(self.digests[-1]+'.pxms')
        raw=path.read_bytes(); n=struct.unpack('>I',raw[8:12])[0]
        payload=json.loads(raw[12+n:]);payload['recorded_selected']=False
        raw=raw[:12+n]+json.dumps(payload).encode(); path.unlink()
        value=hashlib.sha256(raw).hexdigest();(self.folder/(value+'.pxms')).write_bytes(raw)
        self.sync.return_value={'downloaded_digests':[]}
        result=self.run_refresh()
        self.assertEqual(result['state'],'BLOCKED'); self.assertIn('BASELINE_NOT_EXACT',result['reason'])
        self.assertFalse(self.pointer().exists())

    def test_cache_prune_protects_current_pointer_unknown_and_other_source(self):
        self.assertEqual(self.run_refresh()['state'],'READY')
        legacy=self.snapshot(640,gitSHA='f'*40)
        unknown=self.snapshot(641)
        scope=refresh.cache_scope(self.pin,self.policy)
        record=refresh.cache_records(self.data,self.policy)
        record['snapshots'][legacy]={**scope,'source_revision':'f'*40}
        atomic_json(refresh.cache_record_path(self.data,self.policy),record)
        result=refresh.prune_cache(self.data,self.pin,self.policy,keep=1)
        self.assertEqual(result['removed'],6)
        self.assertTrue((self.folder/(legacy+'.pxms')).exists())
        self.assertTrue((self.folder/(unknown+'.pxms')).exists())
        self.assertTrue(all((self.folder/(value+'.pxms')).exists() for value in self.digests[-64:]))

    def test_cache_writer_waits_for_shared_reader_frozen_copy(self):
        namespace,name=self.policy.split('/')
        entered,finished=threading.Event(),threading.Event()
        def prune():
            entered.set()
            with snapshots.cache_lock(self.data,namespace,name,exclusive=True):
                refresh.prune_cache(self.data,self.pin,self.policy,keep=1)
                finished.set()
        with snapshots.cache_lock(self.data,namespace,name):
            thread=threading.Thread(target=prune);thread.start();entered.wait(1)
            self.assertFalse(finished.wait(.05))
            with self.journal.read_snapshot() as prefix:
                entries=refresh.select_entries(self.data,self.pin,self.policy,refresh.segment(self.journal,prefix),600,600,64)
                refresh.copy_cohort(self.data,self.policy,entries,self.root/'frozen',1 << 20)
        thread.join(3);self.assertTrue(finished.is_set())
        self.assertEqual(len(list((self.root/'frozen').glob('*.pxms'))),64)

    def test_invalid_bounds_and_runtime_or_output_failures_do_not_publish(self):
        for kwargs in ({'ticks':257},{'window':float('nan')},{'target':1},{'max_work_bytes':1}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError): self.run_refresh(**kwargs)
        with mock.patch.object(refresh,'run_replay',side_effect=refresh.RefreshBlocked('REFRESH_RUNTIME_LIMIT')):
            result=self.run_refresh()
        self.assertEqual(result['state'],'BLOCKED');self.assertEqual(result['reason'],'REFRESH_RUNTIME_LIMIT')
        self.assertFalse(self.pointer().exists())

    def test_stale_watermark_cannot_be_qualified_as_fresh(self):
        with mock.patch.object(refresh.time,'time',return_value=2000):
            result=self.run_refresh()
        self.assertEqual(result['state'],'BLOCKED')
        self.assertIn('OBSERVATION_WATERMARK_STALE_OR_FUTURE',result['reason'])
        self.assertFalse(self.pointer().exists())

    def test_real_runtime_guard_and_subprocess_output_quota(self):
        with self.assertRaisesRegex(refresh.RefreshBlocked,'RUNTIME_LIMIT'):
            with refresh.wall_limit(.01):
                time.sleep(.1)
        work=self.root/'bounded-work';work.mkdir()
        # Real isolated subprocess, no inherited credentials, real RLIMIT_FSIZE.
        script='import os; assert "AWS_SECRET_ACCESS_KEY" not in os.environ; open("large", "wb").write(b"x"*(8<<20))'
        with mock.patch.dict(refresh.os.environ,{'AWS_SECRET_ACCESS_KEY':'test-only-must-not-inherit'}):
            with self.assertRaisesRegex(refresh.RefreshBlocked,'REPLAY_EXIT'):
                refresh.run_replay(['/usr/bin/python3','-c',script],work,time.monotonic()+5,16 << 20)
        self.assertLess(refresh.bytes_in(work),16 << 20)


if __name__=='__main__':
    unittest.main()
