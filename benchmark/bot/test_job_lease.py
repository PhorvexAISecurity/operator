"""Actual pin lease and bot queue controls with scripted external transports."""
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent/'worker'), str(HERE.parents[1])]
import file_requests
import service
import test_bot as botkit
import test_uploads
import stage_cli
import stage_reconcile
import test_stage_reconcile as fixture
from mathlab import binary, stage_scope


class JobLeaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.producer = fixture.Producer(Path(temporary.name))
        for target, name, effect in ((stage_cli, 'kube', self.producer.kube),
                                     (binary, 'ensure_binary', self.producer.ensure)):
            patch = mock.patch.object(target, name, side_effect=effect)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch('runner.Console', side_effect=self.producer.console)
        patch.start(); self.addCleanup(patch.stop)
        installed = stage_reconcile.reconcile(self.producer.data, self.producer.repo, ticks=2, timeout=30)
        self.assertEqual(installed['status'], 'READY', installed)
        self.kit = botkit.BotTest()
        self.kit.setUp(); self.addCleanup(self.kit.doCleanups)
        self.bot = self.kit.bot(BOT_REPO=str(self.producer.repo), MATHLAB_DATA_DIR=str(self.producer.data),
                               BOT_POLICY=stage_scope.ALLOWED_POLICIES[0], BOT_MAX_TICKS='2')
        self.bot.dashboard = self.bot.cfg.dashboard()

    @contextmanager
    def busy_pin(self):
        path = self.producer.data/'mathlab/stage.lock'
        holder = subprocess.Popen([sys.executable, '-c',
            'import fcntl,sys; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX); '
            'print("LOCKED",flush=True); sys.stdin.read()', str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), 'LOCKED')
        def release():
            if holder.poll() is None:
                holder.stdin.close(); holder.wait(timeout=5)
        try:
            yield release
        finally:
            release(); holder.stdout.close()

    def queue_parameter(self):
        self.bot.handle(botkit.message(botkit.OWNER, '/param P-FEA-006 1.5 ticks=2 nosync'))
        self.assertEqual(len(self.bot.queue), 1)
        return self.bot.queue[0]

    def test_real_timeout_remains_blocked_after_release_and_successful_readiness(self):
        positive = self.queue_parameter()
        self.assertTrue(self.bot.run_next())
        self.assertEqual(positive.state, 'DONE')
        job = self.queue_parameter()
        actual_lock = stage_scope.pin_lock
        waits = []
        before = sorted((self.producer.data/'mathlab/experiments').glob('*'))
        with self.busy_pin() as release:
            @contextmanager
            def release_after_timeout(*args, **kwargs):
                started = time.monotonic()
                try:
                    with actual_lock(*args, **kwargs) as held:
                        yield held
                except stage_scope.StageLeaseBusy:
                    waits.append(time.monotonic()-started)
                    release()
                    raise
            with mock.patch.object(stage_scope, 'pin_lock', side_effect=release_after_timeout), \
                 mock.patch.object(self.bot, 'readiness_for', side_effect=AssertionError('known timeout must not be reprobed')):
                self.assertTrue(self.bot.run_next())
        self.assertEqual(len(waits), 1)
        self.assertGreaterEqual(waits[0], 19)
        self.assertEqual(job.state, 'BLOCKED')
        ready = self.bot.readiness_for({'kind': 'param', 'text': job.text})
        self.assertEqual(ready['status'], 'READY', ready)
        self.assertEqual(sorted((self.producer.data/'mathlab/experiments').glob('*')), before)
        result = json.loads((job.dir/'preflight/result.json').read_text())
        self.assertEqual(result['readiness']['reasons'][0]['code'], 'STAGE_PIN_LEASE_BUSY')
        self.assertGreaterEqual(result['readiness']['lease_wait_seconds'], 19)
        self.assertIsNone(result['comparable_ticks'])
        self.assertIsNone(result['readiness']['snapshot_count'])
        self.assertFalse(result['both_arms_executed'])
        self.assertFalse(any(result['activity'].values()))
        self.assertEqual(self.kit.history()[-1]['state'], 'BLOCKED')
        retry = self.queue_parameter()
        self.assertTrue(self.bot.run_next())
        self.assertEqual(retry.state, 'DONE')

    def test_original_endpoint_request_and_cancel_are_preserved_under_contention(self):
        original = (HERE/'testdata/endpoint-v3-10d-original.txt').read_bytes()
        task = file_requests.parse(original.decode())[0]
        request = json.loads(task['text'])
        test_uploads.UploadTest.upload(self.kit, self.bot, original, filename='original-10d.txt')
        self.assertEqual(len(self.bot.queue), 1)
        batch = self.bot.queue[0]
        actual_lock = stage_scope.pin_lock
        with self.busy_pin(), \
             mock.patch.object(stage_scope, 'pin_lock', side_effect=lambda data, **kw: actual_lock(data, timeout=0)), \
             mock.patch.object(self.bot, 'run_endpoint', side_effect=AssertionError('no study before lease')), \
             mock.patch.object(self.bot, 'readiness_for', side_effect=AssertionError('no live recheck')):
            self.bot.run_next()
        batch_result = json.loads((batch.dir/'BATCH.json').read_text())
        self.assertEqual(batch.state, 'BLOCKED')
        child = batch_result['results'][0]
        self.assertIn('STAGE_PIN_LEASE_BUSY', child['headline'])
        root = batch.dir.parent/child['job']/'endpoint'
        result = json.loads((root/'result.json').read_text())
        self.assertEqual(json.loads((root/'request.json').read_text()), request)
        self.assertEqual(result['required_windows'], {'budget_seconds': 864000, 'burn_seconds': 86400})
        self.assertEqual(result['requested_mode'], 'PAIRED_BRAIN_REPLAY')
        self.assertFalse(result['both_arms_executed'])
        self.assertFalse(any(result['activity'].values()))
        self.assertFalse(result['requested_sync'])
        self.assertFalse(result['preflight']['requested_sync'])
        self.assertEqual((root/'original-request.txt').read_bytes(), original)
        conversion = json.loads((root/'compatibility-conversion.json').read_text())
        self.assertEqual(conversion['original_source_sha256'], '2e0a40127b9b9b65f7d42e5fa4eb1f155d8a1819aced313b8f39435ab493a9a3')
        self.assertEqual(conversion['normalized_prompt_sha256'], task['conversion']['normalized_prompt_sha256'])
        with zipfile.ZipFile(root/'evidence.zip') as bundle:
            self.assertEqual(bundle.read('original-request.txt'), original)
            self.assertEqual(json.loads(bundle.read('compatibility-conversion.json')), conversion)
        cancelled = self.queue_parameter()
        with self.busy_pin():
            @contextmanager
            def cancel_after_actual_timeout(*args, **kwargs):
                try:
                    with actual_lock(*args, timeout=0) as held:
                        yield held
                except stage_scope.StageLeaseBusy:
                    cancelled.cancel.set()
                    raise
            with mock.patch.object(stage_scope, 'pin_lock', side_effect=cancel_after_actual_timeout):
                self.bot.run_next()
        self.assertEqual(cancelled.state, 'CANCELLED')
        self.assertFalse((cancelled.dir/'preflight/result.json').exists())

    def test_reference_study_lease_refusal_retains_reference_mode(self):
        request = json.loads((HERE/'templates/study-cost-synthetic.json').read_text())
        job = service.Job('study', botkit.OWNER, botkit.OWNER, json.dumps(request))
        actual_lock = stage_scope.pin_lock
        with self.busy_pin(), mock.patch.object(stage_scope, 'pin_lock',
                side_effect=lambda data, **kw: actual_lock(data, timeout=0)):
            self.bot.execute_job(job)
        result = json.loads((job.dir/'preflight/result.json').read_text())
        self.assertEqual(job.state, 'BLOCKED')
        self.assertEqual(result['requested_mode'], 'REFERENCE_STUDY')
        self.assertEqual(result['readiness']['requested_request'], request)
        self.assertFalse(any(result['activity'].values()))

    def test_unrelated_acquisition_and_body_errors_keep_existing_failure_handling(self):
        for error in (stage_scope.StageError('invalid stage setup'), PermissionError('denied')):
            job = self.queue_parameter()
            @contextmanager
            def fail():
                raise error
                yield
            with mock.patch.object(stage_scope, 'pin_lock', return_value=fail()):
                self.bot.run_next()
            self.assertEqual(job.state, 'FAILED')
            self.assertFalse((job.dir/'preflight/result.json').exists())
        job = self.queue_parameter()
        with mock.patch.object(self.bot, 'run_param', side_effect=stage_scope.StageLeaseBusy('body error')), \
             mock.patch.object(self.bot, 'readiness_for', side_effect=ValueError('corrupt readiness')):
            self.bot.run_next()
        self.assertEqual(job.state, 'FAILED')
        self.assertIn('corrupt readiness', (job.dir/'readiness-error.txt').read_text())
        self.assertFalse((job.dir/'preflight/result.json').exists())


if __name__ == '__main__':
    unittest.main()
