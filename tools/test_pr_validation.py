"""Guard the actual all-base candidate-source workflow and its fail-closed gate."""
from pathlib import Path
import os
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / '.github/workflows/pr-validation.yml').read_text()
DOC = yaml.load(RAW, Loader=yaml.BaseLoader)


class PRValidationTests(unittest.TestCase):
    def test_all_pr_bases_and_drafts_get_unprivileged_checks(self):
        self.assertEqual(DOC['on']['pull_request'], '')
        self.assertEqual(DOC['permissions'], {'contents': 'read'})
        for forbidden in ('secrets.', 'id-token:', 'self-hosted', 'pull_request_target',
                          'aws-actions/', 'ssh ', 'kubectl ', 'pipeline/e2e.py',
                          'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, RAW)
        for name, job in DOC['jobs'].items():
            self.assertEqual(job['runs-on'], 'ubuntu-latest')
            if name != 'pr-validation':
                self.assertNotIn('if', job)
            for step in job['steps']:
                if step.get('uses', '').startswith('actions/checkout@'):
                    self.assertEqual(step['with'], {'persist-credentials': 'false'})

    def test_real_source_checks_are_wired_without_masking_failures(self):
        jobs = DOC['jobs']
        runs = {k: '\n'.join(s.get('run', '') for s in v['steps'])
                for k, v in jobs.items()}
        self.assertIn('diff -u phorvex/config/crd/bases/', runs['charts'])
        self.assertIn('bash tools/check-vendored-chart.sh', runs['charts'])
        self.assertIn('helm template phorvex deploy/helm/phorvex-stack', runs['charts'])
        self.assertIn('go -C phorvex test -mod=readonly -count=1 -timeout=15m ./...', runs['go-unit'])
        self.assertEqual(jobs['go-unit']['env']['KUBECONFIG'], '/dev/null')
        self.assertEqual(jobs['go-unit']['env']['USE_EXISTING_CLUSTER'], 'false')
        for command in ('npm ci', 'npx --no-install tsc --noEmit --incremental false', 'npm run build'):
            self.assertIn(command, runs['frontend'])

    def test_required_gate_rejects_failure_skip_and_cancellation(self):
        job = DOC['jobs']['pr-validation']
        self.assertEqual(job['name'], 'PR validation')
        self.assertEqual(job['if'], 'always()')
        self.assertEqual(set(job['needs']), {'charts', 'go-unit', 'frontend'})
        script = job['steps'][0]['run']
        good = dict(CHARTS='success', GO_UNIT='success', FRONTEND='success')
        def check(env):
            return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                                  env=dict(os.environ, **env), timeout=5).returncode
        self.assertEqual(check(good), 0)
        for key in good:
            for state in ('failure', 'skipped', 'cancelled', ''):
                with self.subTest(key=key, state=state):
                    self.assertNotEqual(check(dict(good, **{key: state})), 0)

    def test_privileged_workflow_keeps_its_main_only_pr_boundary(self):
        ci = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(ci['on']['pull_request']['branches'], ['main'])
        self.assertEqual(ci['on']['push']['branches'], ['main'])


if __name__ == '__main__':
    unittest.main()
