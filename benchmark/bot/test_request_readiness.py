"""Read actual snapshot/pin producers; fake only the remote observation boundary."""
import hashlib
import copy
import json
from pathlib import Path
import sys
import struct
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import request_readiness as readiness
import service
import test_bot as kit
import test_uploads as uploads
import testkit
from mathlab import snapshots, stage_scope
from mathlab import experiment
from benchmark.stage import test_evidence as observed
from benchmark.stage.normalize import normalize, install
import endpoint_study


class RequestReadinessTests(unittest.TestCase):
    bot = kit.BotTest.bot
    history = kit.BotTest.history
    bench_setup = kit.BotTest.bench_setup
    openai_returning = kit.BotTest.openai_returning
    upload = uploads.UploadTest.upload
    def setUp(self):
        kit.BotTest.setUp(self)
        self.repo, self.base, self.data, self.go = self.bench_setup()
        self.policy = 'phorvex-staging-demo/demo-api-defense'
        with stage_scope.pin_lock(self.data):
            pass
        with snapshots.cache_lock(self.data, *self.policy.split('/')):
            pass
        self.pin_path = self.data / 'mathlab/stage.json'
        self.now = readiness.clock('2026-10-28T00:00:10Z')
        self.probe = {'status': 'READY', 'reasons': [], 'available_policies': [self.policy, 'phorvex-staging-demo/stage-bench-defense'],
                      'policy': {'uid': 'u', 'mode': 'active'}}
        patch = mock.patch.object(readiness, 'live_probe', side_effect=lambda *args: self.probe)
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(readiness.time, 'time', return_value=self.now)
        patch.start(); self.addCleanup(patch.stop)

    def request(self, kind='bench', ticks=6, sync=False):
        return {'kind': kind, 'policy': self.policy, 'ticks': ticks, 'sync': sync, 'recorded': True}

    def inspect(self, request=None):
        return readiness.inspect(self.data, self.repo, request or self.request())

    def bytes_inventory(self):
        return {str(p.relative_to(self.data)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.data.rglob('*') if p.is_file()}

    def test_actual_source_headers_positive_and_exact_insufficient_count(self):
        before = self.bytes_inventory()
        result = self.inspect()
        self.assertEqual((result['status'], result['snapshot_count']), ('READY', 6))
        self.assertEqual(result['baseline_validation'], 'NOT_RUN')
        result = self.inspect(self.request(ticks=64))
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('SNAPSHOT_COUNT_INSUFFICIENT', [r['code'] for r in result['reasons']])
        self.assertEqual(result['requested_ticks'], 64)
        self.assertEqual(self.bytes_inventory(), before)

    def test_missing_policy_does_not_fall_back_to_fixture(self):
        pin = json.loads(self.pin_path.read_text())
        pin['policies'] = {'phorvex-staging-demo/stage-bench-defense': {'uid': 'fixture-uid', 'mode': 'dryRun'}}
        self.pin_path.write_text(json.dumps(pin))
        result = self.inspect()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['requested_policy'], self.policy)
        self.assertIn('POLICY_NOT_PINNED', [r['code'] for r in result['reasons']])
        self.assertIsNone(result['snapshot_count'])

    def test_old_image_uid_and_stale_headers_do_not_qualify(self):
        original = self.pin_path.read_text()
        for kind in ('image', 'uid', 'stale'):
            pin = json.loads(original)
            if kind == 'image':
                pin['brain']['image_digest'] = 'sha256:' + 'b' * 64
                pin['brain']['image'] = pin['brain']['image'].split('@')[0] + '@' + pin['brain']['image_digest']
            elif kind == 'uid':
                pin['policies'][self.policy]['uid'] = 'new-uid'
            self.pin_path.write_text(json.dumps(pin))
            with self.subTest(kind=kind):
                result = readiness.inspect(self.data, self.repo, self.request(), now=self.now + (1000 if kind == 'stale' else 0))
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertTrue(any(r['code'] in ('SNAPSHOT_COUNT_INSUFFICIENT', 'SNAPSHOT_FRESHNESS_UNAVAILABLE') for r in result['reasons']))
        self.pin_path.write_text(original)

    def test_live_capture_or_source_drift_blocks_despite_complete_cache(self):
        for code in ('CAPTURE_DISABLED', 'SOURCE_DRIFT', 'POLICY_UID_CHANGED'):
            self.probe = {**self.probe, 'status': 'BLOCKED', 'reasons': [{'code': code, 'message': 'Actual observed prerequisite is unavailable', 'recovery': 'Reconcile the actual stage.'}]}
            with self.subTest(code=code):
                result = self.inspect()
                self.assertEqual(result['snapshot_count'], 6)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertIn(code, [r['code'] for r in result['reasons']])

    def test_real_upload_validate_and_execution_are_separate_and_no_model_runs(self):
        bot = self.bot(BOT_REPO=str(self.repo), MATHLAB_DATA_DIR=str(self.data), BOT_GO=str(self.go))
        original = (HERE / 'testdata/endpoint-v3-10d-original.txt').read_bytes()
        before = self.bytes_inventory()
        with mock.patch.object(bot, 'sync', side_effect=AssertionError('sync:false must not download')), \
             mock.patch.object(service.planner, 'plan', side_effect=AssertionError('known missing history must stop before LLM')):
            self.upload(bot, original, caption='/validate')
            self.assertEqual(bot.queue, [])
            self.assertEqual(self.bytes_inventory(), before)
            record = json.loads(next((self.tmp / 'state/uploads').glob('*/VALIDATION.json')).read_text())
            check = record['runtime_readiness'][0]
            self.assertEqual(check['status'], 'BLOCKED')
            self.assertEqual(check['required_windows'], {'budget_seconds': 864000, 'burn_seconds': 86400})
            self.assertIn('MOVE_ATTRIBUTION_UNAVAILABLE', [r['code'] for r in check['reasons']])
            self.assertIn('ENDPOINT_DATASET_UNAVAILABLE', [r['code'] for r in check['reasons']])
            self.assertIn('ticks[].ledger.moves[].intervals[]', check['missing_fields'])
            self.upload(bot, original)
            self.assertEqual(len(bot.queue), 1)
            self.assertTrue(bot.run_next())
        rows = self.history()
        self.assertEqual([r['state'] for r in rows], ['BLOCKED', 'BLOCKED'])
        child = next(r for r in rows if r['kind'] == 'endpoint')
        root = self.tmp / 'state/jobs' / child['id'] / 'endpoint'
        result = json.loads((root / 'result.json').read_text())
        self.assertEqual(result['required_windows']['budget_seconds'], 864000)
        self.assertFalse(result['v2_executed'])
        self.assertIsNone(result['comparable_ticks'])
        self.assertIn('ticks[].ledger.moves[].intervals[]', (root/'report.html').read_text())
        self.assertEqual((root / 'original-request.md').read_bytes(), original)
        conversion = json.loads((root / 'compatibility-conversion.json').read_text())
        self.assertEqual(conversion['original_source_sha256'], hashlib.sha256(original).hexdigest())

    def test_source_change_after_validation_is_rechecked_before_model(self):
        bot = self.bot(BOT_REPO=str(self.repo), MATHLAB_DATA_DIR=str(self.data), BOT_GO=str(self.go), BOT_MAX_TICKS='6')
        bot.handle(kit.message(kit.OWNER, '/bench ticks=6 nosync explain one decision function'))
        self.assertEqual(len(bot.queue), 1)
        self.probe = {**self.probe, 'status': 'BLOCKED', 'reasons': [{'code': 'SOURCE_DRIFT', 'message': 'Stage advanced after validation', 'recovery': 'Reconcile current source.'}]}
        with mock.patch.object(service.planner, 'plan', side_effect=AssertionError('source race reached model')):
            bot.run_next()
        self.assertEqual(self.history()[-1]['state'], 'BLOCKED')

    def test_parameter_cache_shrink_before_freeze_refuses_partial_requested_cohort(self):
        self.assertEqual(self.inspect()['status'], 'READY')
        bot = self.bot(BOT_REPO=str(self.repo), MATHLAB_DATA_DIR=str(self.data), BOT_MAX_TICKS='6')
        runtime = bot.cfg.dashboard()
        source = self.data / 'mathlab/snapshots' / self.policy
        next(source.glob('*.pxms')).unlink()
        request = {'mode': 'REPLAY', 'policy': self.policy, 'parameter_id': 'P-FEA-006',
                   'cohort': {'max_snapshots': 6}, 'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                                                          {'arm_id': 'trial', 'value': 1.2}]}
        with self.assertRaisesRegex(stage_scope.StageError, 'fewer snapshots than requested'):
            runtime.preflight(request)
        self.assertEqual(runtime.requests, {})

    def test_generation_filter_excludes_old_same_uid_and_source_before_sampling(self):
        source = self.data / 'mathlab/snapshots' / self.policy
        old = testkit.make_snapshot(source, self.base, 3, False, '2026-10-28T00:00:06Z', policy_generation=8)
        new = testkit.make_snapshot(source, self.base, 4, True, '2026-10-28T00:00:07Z', policy_generation=9)
        chosen = experiment.select_cohort(self.data, {'namespace': self.policy.split('/')[0], 'policy': self.policy.split('/')[1],
            'cohort': {'git_sha': self.base, 'policy_uid': 'u', 'policy_generation': 9, 'max_snapshots': 1, 'spacing': 'even'}})
        self.assertEqual([entry['digest'] for entry in chosen], [new])
        self.assertNotEqual(old, new)

    def test_unfinished_content_addressed_snapshots_are_not_ready(self):
        source = self.data / 'mathlab/snapshots' / self.policy
        for path in list(source.glob('*.pxms')):
            raw = path.read_bytes()
            size = struct.unpack('>I', raw[len(snapshots.MAGIC):len(snapshots.MAGIC)+4])[0]
            header = json.loads(raw[len(snapshots.MAGIC)+4:len(snapshots.MAGIC)+4+size])
            header['finalized'] = False
            encoded = json.dumps(header).encode()
            changed = snapshots.MAGIC + struct.pack('>I', len(encoded)) + encoded + raw[len(snapshots.MAGIC)+4+size:]
            path.unlink()
            (source / (hashlib.sha256(changed).hexdigest() + '.pxms')).write_bytes(changed)
        result = self.inspect()
        self.assertEqual((result['status'], result['snapshot_count']), ('BLOCKED', 0))
        selected = experiment.select_cohort(self.data, {'namespace': self.policy.split('/')[0], 'policy': self.policy.split('/')[1],
                    'cohort': {'require_finalized': True, 'max_snapshots': 6}})
        self.assertEqual(selected, [])

    def test_late_identity_failure_retains_started_model_work(self):
        reply = self.openai_returning(testkit.threshold_diff(3, 5))
        control = json.loads((self.data / 'mathlab/bin/current.json').read_text())
        def model(*args, **kwargs):
            path = Path(control['path'])
            path.write_text(path.read_text() + '\n# changed after model request\n')
            return reply(*args, **kwargs)
        bot = self.bot(openai=model, BOT_REPO=str(self.repo), MATHLAB_DATA_DIR=str(self.data),
                       BOT_GO=str(self.go), BOT_MAX_TICKS='6')
        bot.handle(kit.message(kit.OWNER, '/bench ticks=6 nosync raise the rotate threshold from 3 to 5'))
        bot.run_next()
        row = self.history()[-1]
        self.assertIn(row['state'], ('BLOCKED', 'FAILED'))
        root = self.tmp / 'state/jobs' / row['id']
        activity = json.loads((root / 'ACTIVITY.json').read_text())
        self.assertTrue(activity['started']['model_started'])
        self.assertIsNone(activity['model_token_count'])
        for path in root.rglob('report.html'):
            self.assertNotIn('No model, build or replay was started', path.read_text())

    def test_broken_race_check_cannot_leave_job_running_or_relabel_internal_error(self):
        bot = self.bot(BOT_REPO=str(self.repo), MATHLAB_DATA_DIR=str(self.data))
        job = service.Job('bench', kit.OWNER, kit.OWNER, 'ticks=6 nosync explicit change')
        with mock.patch.object(bot, 'run_bench', side_effect=stage_scope.StageError('identity disappeared')), \
             mock.patch.object(bot, 'readiness_for', side_effect=ValueError('corrupt installed manifest')):
            bot.execute_job(job)
        self.assertEqual(job.state, 'FAILED')
        self.assertIn('corrupt installed manifest', (job.dir/'readiness-error.txt').read_text())
        self.assertEqual(self.history()[-1]['state'], 'FAILED')

    def install_advanced_atomic_pin(self):
        (self.repo/'next-source.txt').write_text('new actual stage source')
        testkit.git(self.repo,'add','next-source.txt');testkit.git(self.repo,'commit','-qm','next stage source')
        current=testkit.git(self.repo,'rev-parse','HEAD')
        replay=testkit.write_fake_replay(self.tmp/'next-replay',current,3)
        pin=json.loads(self.pin_path.read_text())
        pin['identity_binding']='stage-pin.replay.v1'
        pin['brain'].update(git_sha=current,image=testkit.stage_image(current))
        pin['replay']={**pin['replay'],'path':str(replay),'git_sha':current,
                       'binary_sha256':hashlib.sha256(replay.read_bytes()).hexdigest()}
        pin['policies'][self.policy]['generation']=9
        self.pin_path.write_text(json.dumps(pin))
        folder=self.data/'mathlab/snapshots'/self.policy
        for path in folder.glob('*.pxms'):path.unlink()
        for index in range(6):
            testkit.make_snapshot(folder,current,index,index>3,'2026-10-28T00:00:%02dZ'%index,policy_generation=9)
        return current

    def test_real_parameter_pipeline_uses_atomic_identity_with_stale_or_absent_legacy_file(self):
        current=self.install_advanced_atomic_pin()
        legacy=self.data/'mathlab/bin/current.json'; historical=legacy.read_bytes()
        bot=self.bot(BOT_REPO=str(self.repo),MATHLAB_DATA_DIR=str(self.data),BOT_GO=str(self.go),BOT_MAX_TICKS='6')
        bot.dashboard=bot.cfg.dashboard()
        for missing in (False,True):
            if missing:legacy.unlink()
            with self.subTest(legacy_missing=missing):
                bot.handle(kit.message(kit.OWNER,'/param P-FEA-006 1.5 ticks=6 nosync'));bot.run_next()
                self.assertEqual(self.history()[-1]['state'],'DONE',self.history()[-1])
                requests=list((self.data/'mathlab/experiments').glob('*/request.json'))
                self.assertTrue(requests)
                self.assertTrue(all(json.loads(path.read_text())['cohort']['git_sha']==current for path in requests))
                self.assertTrue(all(len(json.loads(path.read_text())['cohort']['digests'])==6 for path in requests))
                checks=[]
                service.check(bot.cfg,self.env,telegram=bot.tg,out=checks.append,model_probe=lambda _:None)
                self.assertTrue(any(line.startswith('PASS operator repository') and current[:12] in line for line in checks),checks)
                self.assertTrue(any(line.startswith('PASS go') for line in checks),checks)
                if not missing:self.assertEqual(legacy.read_bytes(),historical)
                else:self.assertFalse(legacy.exists())

    def test_endpoint_audit_uses_atomic_identity_without_legacy_current(self):
        current=self.install_advanced_atomic_pin()
        (self.data/'mathlab/bin/current.json').unlink()
        root=self.tmp/'audit';root.mkdir()
        result=endpoint_study.recorded_readiness(self.data,self.policy,6,root)
        self.assertEqual(result.get('base_commit'),current)
        self.assertEqual(result.get('snapshots_inspected'),6)
        self.assertIn('No qualified normalized endpoint trace',result['reason'])


class EndpointHistoryReadinessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='readiness-history-')
        self.addCleanup(temporary.cleanup)
        self.data = Path(temporary.name)
        scope = observed.scope()
        self.policy = scope['namespace'] + '/' + scope['policy_name']
        self.pin = testkit.write_stage_pin(self.data, scope['source_revision'], self.policy, scope['policy_uid'])
        scope['image_digest'] = self.pin['brain']['image_digest']
        journal = observed.Journal(self.data / 'observed.sqlite', scope)
        self.addCleanup(journal.close)
        observed.seed(journal)
        observed.rotate(journal)
        observed.seal(journal, 1000)
        trace, metadata = normalize(scope, journal.records, [observed.export(650)], .9, 300, 300, 0)
        self.assertEqual(metadata['state'], 'READY')
        install(trace, metadata, self.data, 'real Journal/reducer/normalizer fixture')
        self.pointer = self.data / 'mathlab/endpoint-traces' / (self.policy + '.manifest.json')
        self.original = self.pointer.read_text()
        self.request = endpoint_study.validate({'schema': endpoint_study.SCHEMA, 'title': 'Independent windows',
            'policy': self.policy, 'ticks': 1, 'dataset': 'recorded', 'sync': False,
            'study': {'window': 600, 'slo_target': .95}, 'config': {'lookback': 500}})
        self.actual = {'uid': scope['policy_uid'], 'generation': 1, 'mode': 'dryRun',
                       'workload_uid': scope['workload_uid'], 'workload_generation': 1, 'service_uid': scope['service_uid']}

    def inspect(self, request=None, actual=None, now=650):
        report = {'status': 'READY', 'reasons': []}
        readiness.endpoint_history(report, self.data, self.pin, request or self.request,
                                   actual or self.actual, {'d' * 64}, now=now)
        return report

    def test_real_history_qualifies_but_missing_engine_still_refuses_ready(self):
        result = self.inspect()
        self.assertEqual(result['endpoint_history']['available_continuous_seconds'], 640)
        self.assertEqual(result['required_windows'], {'budget_seconds': 600, 'burn_seconds': 500})
        self.assertEqual([r['code'] for r in result['reasons']], ['ENDPOINT_ENGINE_UNAVAILABLE'])
        self.assertEqual(result['status'], 'BLOCKED')

    def test_required_windows_retention_generation_and_freshness_fail_closed(self):
        cases = {'window': 'OBSERVED_HISTORY_INSUFFICIENT', 'lookback': 'OBSERVED_HISTORY_INSUFFICIENT',
                 'retention': 'RETAINED_HISTORY_UNPROVEN', 'seal': 'ENDPOINT_COVERAGE_UNAVAILABLE',
                 'policy': 'ENDPOINT_POLICY_GENERATION_UNVERIFIED', 'workload': 'ENDPOINT_WORKLOAD_GENERATION_UNVERIFIED',
                 'uid': 'ENDPOINT_WORKLOAD_UNVERIFIED', 'service': 'ENDPOINT_SERVICE_UNVERIFIED',
                 'missing-service': 'ENDPOINT_SERVICE_UNVERIFIED', 'stale': 'ENDPOINT_DATASET_STALE'}
        for case, expected in cases.items():
            meta, request, actual, now = json.loads(self.original), copy.deepcopy(self.request), dict(self.actual), 650
            if case == 'window': request['study']['window'] = 864000
            elif case == 'lookback': request['config']['lookback'] = 86400
            elif case == 'retention': meta['normalization'].pop('retention')
            elif case == 'seal': meta['normalization']['bindings'][0]['sealed_until'] = 649
            elif case == 'policy': actual['generation'] = 2
            elif case == 'workload': actual['workload_generation'] = 2
            elif case == 'uid': actual['workload_uid'] = 'recreated-uid'
            elif case == 'service': actual['service_uid'] = 'recreated-service'
            elif case == 'missing-service': actual.pop('service_uid')
            else: now = 1600
            self.pointer.write_text(json.dumps(meta))
            with self.subTest(case=case):
                result = self.inspect(request, actual, now)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertIn(expected, [r['code'] for r in result['reasons']])
                self.assertEqual(result['required_windows']['budget_seconds'], request['study']['window'])
                self.assertEqual(result['required_windows']['burn_seconds'], request['config']['lookback'])


if __name__ == '__main__':
    unittest.main()
