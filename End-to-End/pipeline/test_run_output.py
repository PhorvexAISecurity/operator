"""Exercise aborts through the real pipeline, detector producer and output consumers."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import e2e
from run_output import RunOutput
from transport import TransportError
from test_detector import FakeTransport as DetectorTransport, IDENTITY
import test_transport

ROOT = Path(__file__).resolve().parents[1]


class OfflineTransport(DetectorTransport):
    def describe(self):
        return 'offline fixture'

    def run(self, command, timeout=60):
        if 'get deployments.apps,replicasets.apps,pods' in command:
            return 0, json.dumps({'items': test_transport.ControllerPodsTests.workload('fixture-controller')}), ''
        if ' get pod ' in command:
            return 0, '', ''
        if ' get phorvexpolicy ' in command:
            return 0, '3|Enforce|false', ''
        return super().run(command, timeout)


class RunOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = {'invariants': {}, 'transport': {'kind': 'local'}, 'console': {},
                    'capture': {'stream_seconds': 1, 'post_attack_seconds': 1, 'settle_seconds': 0, 'max_bytes': 1000},
                    'controller_deployments': ['fixture-controller'],
                    'targets': [{'name': 'fixture', 'namespace': 'fixture-ns',
                                 'detector': {'identity': IDENTITY, 'selector': 'app=fixture'},
                                 'attack': {'path': '/unused', 'body': {}}}]}

    def attempt(self, *, mode='observe', preflight_error=None, capture_error=None,
                transport=None, baseline=None, renderer=None):
        transport = transport or OfflineTransport()
        def stream(seconds, max_bytes, on_connected=None, namespace=None):
            if on_connected:
                on_connected()
                if capture_error:
                    raise capture_error
            return [], 0
        output = RunOutput(self.root, mode, 'fixture', source_commit='a' * 40)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(e2e, 'Transport', return_value=transport))
            stack.enter_context(patch.object(e2e.Console, 'wait_preflight',
                side_effect=preflight_error, return_value=({'ok': True}, {'operator': 'test', 'console': 'test'})))
            stack.enter_context(patch.object(e2e.Console, 'stream_decisions', side_effect=stream))
            stack.enter_context(patch.object(e2e.Metrics, 'scrape', return_value={}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if renderer:
                stack.enter_context(patch.object(e2e, 'render', side_effect=renderer))
            doc, rc = e2e.run(self.cfg, mode, 'fixture' if mode == 'attack' else None,
                              self.root, baseline=baseline, output=output)
        return doc, rc, transport

    def summary(self, path, *args):
        return subprocess.run([sys.executable, str(ROOT / 'summary.py'), str(path), '--marker', *args],
                              text=True, capture_output=True, timeout=10)

    def assert_abort(self, doc, rc):
        self.assertEqual((doc['verdict'], rc), ('ABORTED', 2))
        path = self.root / f"run-{doc['runId']}.json"
        self.assertEqual(json.loads(path.read_text()), doc)
        self.assertTrue(path.with_suffix('.html').is_file())
        result = self.summary(path, '--expect-run-id', doc['runId'], '--expect-source-commit', 'a' * 40,
                              '--exit-code', '2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ABORTED', result.stdout)
        self.assertIn('<!-- phorvex-e2e-report -->', result.stdout)
        self.assertNotIn('All contracts held', result.stdout)

    def test_preflight_abort_is_current_identified_unbaselinable_and_escaped(self):
        (self.root / 'run-old.json').write_text('{"verdict":"PASS"}')
        with patch.dict(os.environ, {'FIXTURE_SECRET_TOKEN': 'do-not-publish'}):
            doc, rc, _ = self.attempt(preflight_error=TransportError('<script>do-not-publish</script>' + 'x' * 5000),
                baseline={'checks': {'HARNESS_ABORT': {'reason': 'must not waive abort'}}})
        self.assert_abort(doc, rc)
        self.assertEqual(doc['abort']['stage'], 'preflight')
        self.assertEqual(doc['tally']['pass'], 0)
        self.assertTrue(all(c['status'] == 'skip' for c in doc['checks']))
        self.assertLessEqual(len(doc['abort']['error']), 2000)
        self.assertNotIn('do-not-publish', json.dumps(doc))
        page = (self.root / f"run-{doc['runId']}.html").read_text()
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('<script>', page)

    def test_capture_failure_preserves_primary_and_real_detector_cleanup(self):
        for delete_rc in (0, 1):
            doc, rc, transport = self.attempt(mode='attack', transport=OfflineTransport(delete_rc=delete_rc),
                                            capture_error=TransportError('primary capture lost'))
            self.assert_abort(doc, rc)
            self.assertIn('primary capture lost', doc['abort']['error'])
            self.assertEqual(len(doc['abort']['cleanupErrors']), delete_rc)
            self.assertEqual(sum(' delete securityevent ' in c for c in transport.commands), 1)
            self.assertEqual(doc['injection']['name'], transport.event['metadata']['name'])
            self.assertTrue(doc['injection']['createAttempted'])
            self.assertEqual(doc['injection']['cleanup'], 'failed' if delete_rc else 'delete-request-acknowledged')
            self.assertEqual(doc['tally']['pass'], 0)

    def test_lost_create_response_still_clears_the_unique_attempt(self):
        doc, rc, transport = self.attempt(mode='attack', transport=OfflineTransport(create_rc=124))
        self.assert_abort(doc, rc)
        self.assertIn('rc=124', doc['abort']['error'])
        self.assertTrue(doc['injection']['createAttempted'])
        self.assertFalse(doc['injection']['createResponseValidated'])
        self.assertEqual(sum(' delete securityevent ' in c for c in transport.commands), 1)

    def test_cleanup_only_failure_retains_evaluated_checks_without_passing_run(self):
        doc, rc, _ = self.attempt(mode='attack', transport=OfflineTransport(delete_rc=1))
        self.assert_abort(doc, rc)
        self.assertEqual(doc['abort']['stage'], 'cleanup')
        self.assertGreater(doc['tally']['pass'], 0)  # checks actually ran before cleanup
        self.assertEqual(len(doc['abort']['cleanupErrors']), 1)

    def test_normal_run_and_baseline_rules_are_preserved(self):
        doc, rc, _ = self.attempt()
        self.assertEqual(doc['verdict'], 'FAIL')  # no decision stream, genuinely fails P03
        self.assertEqual(rc, 1)
        known = {'checks': {cid: {'reason': 'fixture'} for cid in doc['newFailures']}}
        known_doc, known_rc, _ = self.attempt(baseline=known)
        self.assertEqual(known_doc['verdict'], 'FAIL')
        self.assertEqual(known_rc, 0)
        self.assertEqual(doc['checks'], known_doc['checks'])
        self.assertNotEqual(doc['runId'], known_doc['runId'])
        self.assertEqual(self.summary(self.root / f"run-{doc['runId']}.json", '--exit-code', '1').returncode, 0)

    def test_render_failure_is_an_abort_and_disk_failure_cannot_leave_success_json(self):
        doc, rc, _ = self.attempt(renderer=RuntimeError('renderer broke'))
        self.assert_abort(doc, rc)
        self.assertEqual(doc['abort']['stage'], 'report rendering')
        original = Path.write_text
        def write(path, *args, **kwargs):
            if path.name.endswith('.html.tmp'):
                raise OSError('disk write failed')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'write_text', write):
            doc, rc, _ = self.attempt()
        self.assertEqual(rc, 2)
        path = self.root / f"run-{doc['runId']}.json"
        self.assertFalse(path.exists())
        self.assertIn('ABORTED', self.summary(path, '--exit-code', '2').stdout)

    def test_config_failure_at_cli_boundary_has_a_nonzero_report(self):
        out = self.root / 'cli'
        proc = subprocess.run([sys.executable, str(ROOT / 'pipeline/e2e.py'),
            '--config', str(self.root / 'missing.json'), '--out', str(out), '--run-id', 'cli-attempt',
            '--source-commit', 'b' * 40], text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 2)
        doc = json.loads((out / 'run-cli-attempt.json').read_text())
        self.assertEqual(doc['sourceCommit'], 'b' * 40)
        self.assertEqual(doc['verdict'], 'ABORTED')

    def test_missing_malformed_wrong_identity_and_process_failure_summaries(self):
        for raw in ('not-json', 'null', '{"schema":"phorvex.e2e/1","verdict":"PASS","checks":[null],"tally":{}}',
                    '{"schema":"phorvex.e2e/1","verdict":"ABORTED","checks":[],"tally":{},"abort":"broken"}',
                    '{"schema":"phorvex.e2e/1","verdict":"PASS","checks":[],"tally":{},"staleBaseline":[{}]}'):
            path = self.root / 'invalid.json'
            path.write_text(raw)
            result = self.summary(path)
            self.assertEqual(result.returncode, 1)
            self.assertIn('ABORTED', result.stdout)
        for field in ('counts', 'preflight'):
            path = self.root / 'nullable.json'
            path.write_text(json.dumps({'schema': 'phorvex.e2e/1', 'verdict': 'PASS',
                                        'checks': [], 'tally': {}, field: None}))
            result = self.summary(path)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('ABORTED', result.stdout)
            self.assertTrue(result.stdout.startswith('<!-- phorvex-e2e-report -->'))
        self.assertEqual(self.summary('').returncode, 1)
        doc, _, _ = self.attempt()
        path = self.root / f"run-{doc['runId']}.json"
        for args in (('--expect-run-id', 'another-attempt'), ('--expect-source-commit', 'wrong'), ('--exit-code', '2')):
            result = self.summary(path, *args)
            self.assertEqual(result.returncode, 1)
            self.assertIn('ABORTED', result.stdout)


if __name__ == '__main__':
    unittest.main()
