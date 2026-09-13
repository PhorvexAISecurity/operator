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
        self.assertTrue(any(s.get('uses') == 'azure/setup-helm@v4'
                            and s.get('with', {}).get('version') == 'v3.16.4'
                            for s in jobs['go-unit']['steps']))
        # Separate modules are executed, not merely compiled as dependencies.
        for module, minutes in (('build/metricvalidity', 5), ('build/test-harness', 15),
                                ('build/phoenix-extended', 15), ('build/falco-integrator-extended', 10),
                                ('build/prometheus-integrator-extended', 10)):
            self.assertIn(f'go -C {module} test -mod=readonly -count=1 -timeout={minutes}m ./...', runs['go-unit'])
        for command in ('npm ci', 'npx --no-install tsc --noEmit --incremental false', 'npm run build'):
            self.assertIn(command, runs['frontend'])

    def test_envtest_job_runs_the_eight_api_server_tests_on_pinned_local_binaries(self):
        job = DOC['jobs']['go-envtest']
        self.assertEqual(job['env']['KUBECONFIG'], '/dev/null')
        self.assertEqual(job['env']['USE_EXISTING_CLUSTER'], 'false')
        self.assertNotIn('KUBEBUILDER_ASSETS', job['env'])  # provisioned, never blanked
        self.assertIn('timeout-minutes', job)
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        self.assertIn('bash tools/provision-envtest.sh', runs)
        self.assertIn('echo "KUBEBUILDER_ASSETS=$assets" >> "$GITHUB_ENV"', runs)
        self.assertIn('python3 tools/envtest_gate.py run --raw-output envtest-evidence/go-test.jsonl '
                      '--summary envtest-evidence/summary.json --timeout 10m', runs)
        # The full actuator suite renders the Helm chart; without helm those tests skip and
        # the gate fails, so the job pins the same Helm as go-unit.
        self.assertTrue(any(s.get('uses') == 'azure/setup-helm@v4'
                            and s.get('with', {}).get('version') == 'v3.16.4'
                            for s in job['steps']))
        uploads = [s for s in job['steps'] if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]['if'], 'always()')
        self.assertEqual(uploads[0]['with']['path'], 'envtest-evidence/')
        self.assertEqual(uploads[0]['with']['if-no-files-found'], 'error')
        # The same Go selection as go-unit: highest module go directive, local toolchain.
        setup = [s for s in job['steps'] if s.get('uses', '').startswith('actions/setup-go@')]
        self.assertEqual(setup[0]['with']['go-version-file'], 'build/test-harness/go.mod')
        self.assertEqual(job['env']['GOTOOLCHAIN'], 'local')
        script = (ROOT / 'tools/provision-envtest.sh').read_text()
        self.assertIn('VERSION=1.34.0', script)
        self.assertIn('SHA256=9c45e40aa56971b105e596ebb3e84af6742e8709cc0523733baf8d9bb725e69c', script)
        self.assertIn('releases/download/envtest-v${VERSION}/envtest-v${VERSION}-linux-amd64.tar.gz', script)
        self.assertIn('sha256sum -c -', script)
        self.assertIn('kube_version="$("$assets/kube-apiserver" --version 2>&1)"', script)
        self.assertIn('etcd_version="$("$assets/etcd" --version 2>&1)"', script)
        self.assertNotIn('grep -q', script)
        self.assertNotIn('| head', script)
        self.assertNotIn('${ENVTEST', script)  # no environment override of version, URL or digest
        self.assertIn('set -euo pipefail', script)

    def test_required_gate_rejects_failure_skip_and_cancellation(self):
        job = DOC['jobs']['pr-validation']
        self.assertEqual(job['name'], 'PR validation')
        self.assertEqual(job['if'], 'always()')
        self.assertEqual(set(job['needs']), {'charts', 'go-unit', 'go-envtest', 'frontend'})
        script = job['steps'][0]['run']
        good = dict(CHARTS='success', GO_UNIT='success', GO_ENVTEST='success', FRONTEND='success')
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
