"""Run the actual CI report consumers offline, including publication failure."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOC = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs = self.root / 'runs/current'
        self.runs.mkdir(parents=True)
        shutil.copyfile(ROOT / 'End-to-End/summary.py', self.root / 'summary.py')
        self.env = dict(os.environ, E2E_RUN_ID='current', E2E_RUN_DIR=str(self.runs),
                        GITHUB_SHA='a' * 40, GITHUB_OUTPUT=str(self.root / 'output'),
                        GITHUB_STEP_SUMMARY=str(self.root / 'summary'),
                        PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'])

    def step(self, job, name):
        return next(s for s in DOC['jobs'][job]['steps'] if s.get('name') == name)

    def execute(self, script, replacements=None):
        values = {'steps.publish.outputs.url': '', 'steps.e2e.outputs.verdict_rc': '2',
                  'needs.deploy.outputs.version': 'fixture'}
        values.update(replacements or {})
        script = re.sub(r'\$\{\{\s*(.*?)\s*\}\}', lambda m: values.get(m[1], 'fixture'), script)
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=10)

    def report(self):
        doc = {'schema': 'phorvex.e2e/1', 'runId': 'current', 'sourceCommit': 'a' * 40,
               'verdict': 'ABORTED', 'status': 'aborted', 'checks': [], 'tally': {'skip': 0},
               'abort': {'stage': 'preflight', 'error': 'primary fixture error'}}
        (self.runs / 'run-current.json').write_text(json.dumps(doc))
        (self.runs / 'run-current.html').write_text('<h1>ABORTED fixture</h1>')

    def test_workflow_passes_exact_attempt_identity_and_preserves_exit(self):
        for job in ('e2e', 'e2e-main'):
            raw = json.dumps(DOC['jobs'][job])
            self.assertNotIn('ls -1 runs/', raw)
            self.assertNotIn('tail -1', raw)
            self.assertIn('github.run_attempt', raw)
            steps = DOC['jobs'][job]['steps']
            run = next(s['run'] for s in steps if s.get('id') == 'e2e')
            self.assertIn('--out "$E2E_RUN_DIR" --run-id "$E2E_RUN_ID" --source-commit "$GITHUB_SHA"', run)
            self.assertIn('PIPESTATUS', run)
            summary = next(s for s in steps if s.get('name') in ('Summary', 'Build the summary'))
            self.assertEqual(summary['if'], 'always()')
            self.assertIn('--expect-run-id "$E2E_RUN_ID"', summary['run'])
            self.assertIn('--expect-source-commit "$GITHUB_SHA"', summary['run'])
            self.assertIn('--exit-code', summary['run'])
            publisher = next(s['run'] for s in steps if s.get('id') == 'publish')
            self.assertIn('"$E2E_RUN_DIR"', publisher)
            self.assertTrue(publisher.endswith('"$E2E_RUN_ID"'))

    def test_missing_current_report_never_selects_stale_success_or_comment(self):
        (self.root / 'runs/run-old.json').write_text('{"verdict":"PASS"}')
        (self.root / 'comment.md').write_text('stale success')
        result = self.execute(self.step('e2e', 'Build the summary')['run'])
        self.assertEqual(result.returncode, 1, result.stderr)
        body = (self.root / 'comment-current.md').read_text()
        self.assertIn('ABORTED', body)
        self.assertIn('current', body)
        self.assertNotIn('stale success', body)
        self.assertIn('ABORTED', (self.root / 'summary').read_text())

    def test_unavailable_publisher_cannot_prevent_current_pr_summary(self):
        self.report()
        binaries = self.root / 'bin'
        binaries.mkdir()
        stub = binaries / 'sshpass'
        stub.write_text('#!/bin/sh\nexit 42\n')
        stub.chmod(0o755)
        self.env.update(PHORVEX_SSH_HOST='fixture.invalid', PHORVEX_SSH_USER='fixture',
                        PHORVEX_SSH_PASSWORD='fixture-only', PATH=str(binaries) + os.pathsep + self.env['PATH'])
        # Without a provisioned host identity the publisher refuses before any ssh (T1-E2E-AUTH):
        # the password goes only to a host whose key is pinned.
        result = subprocess.run(['bash', str(ROOT / 'End-to-End/publish-report.sh'),
            str(self.runs), 'fixture', 'current'], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotIn(result.returncode, (0, 42), result.stderr)
        self.assertIn('PHORVEX_SSH_KNOWN_HOSTS', result.stderr)
        known_hosts = self.root / 'known_hosts'
        known_hosts.write_text('[fixture.invalid]:22 ssh-ed25519 AAAAfixture\n')
        self.env['PHORVEX_SSH_KNOWN_HOSTS'] = str(known_hosts)
        result = subprocess.run(['bash', str(ROOT / 'End-to-End/publish-report.sh'),
            str(self.runs), 'fixture', 'current'], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 42)
        self.assertFalse((self.root / 'output').exists())  # no falsely published URL
        summary = self.execute(self.step('e2e', 'Build the summary')['run'])
        self.assertEqual(summary.returncode, 0, summary.stderr)
        body = (self.root / 'comment-current.md').read_text()
        self.assertIn('primary fixture error', body)
        self.assertIn('No published dashboard', body)
        self.assertNotIn('](https://', body)

    def test_publisher_rejects_missing_or_mismatched_exact_report_before_network(self):
        self.report()
        for run_id in ('missing', 'current'):
            if run_id == 'current':
                path = self.runs / 'run-current.json'
                doc = json.loads(path.read_text())
                doc['runId'] = 'old'
                path.write_text(json.dumps(doc))
            result = subprocess.run(['bash', str(ROOT / 'End-to-End/publish-report.sh'),
                str(self.runs), 'fixture', run_id], env=self.env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PHORVEX_SSH_HOST', result.stderr)  # rejected before credentials/network

    def test_actual_run_shell_keeps_python_failure_through_tee(self):
        (self.root / 'pipeline').mkdir()
        (self.root / 'pipeline/e2e.py').write_text('import sys\nprint("primary fixture error")\nsys.exit(2)\n')
        self.env['E2E_TARGET'] = 'fixture'
        for job in ('e2e', 'e2e-main'):
            step = next(s for s in DOC['jobs'][job]['steps'] if s.get('id') == 'e2e')
            result = self.execute(step['run'])
            self.assertEqual(result.returncode, 0, result.stderr)  # deferred to final gate
            self.assertIn('verdict_rc=2', (self.root / 'output').read_text())
            self.assertIn('primary fixture error', (self.runs / 'run.log').read_text())
            gate = self.step(job, 'Re-raise the End-to-End verdict')['run']
            for rc in ('2', ''):
                self.assertEqual(self.execute(gate, {'steps.e2e.outputs.verdict_rc': rc}).returncode, 2)


if __name__ == '__main__':
    unittest.main()
