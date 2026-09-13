"""Keep isolated validation available without opting draft PRs into live attacks."""
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class E2EWorkflowTests(unittest.TestCase):
    def test_contract_job_covers_stacked_and_draft_prs_without_secrets(self):
        path = ROOT / '.github/workflows/e2e-contract.yml'
        raw = path.read_text()
        doc = yaml.load(raw, Loader=yaml.BaseLoader)
        self.assertIn('pull_request', doc['on'])
        self.assertFalse(doc['on']['pull_request'])  # no base/path/type filter
        self.assertEqual(doc['on']['push']['branches'], ['main'])
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        job = doc['jobs']['e2e-contract']
        self.assertEqual(job['runs-on'], 'ubuntu-latest')
        self.assertNotIn('if', job)
        self.assertNotIn('secrets.', raw)
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        self.assertIn('unittest discover -s End-to-End/pipeline', runs)
        self.assertIn('unittest discover -s tools', runs)
        self.assertNotIn('pipeline/e2e.py', runs)
        self.assertNotIn('kubectl ', runs)
        self.assertNotIn('publish-report', runs)

    def test_draft_guard_does_not_remove_live_release_validation(self):
        doc = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertIn('ready_for_review', doc['on']['pull_request']['types'])
        jobs = doc['jobs']
        condition = jobs['e2e']['if']
        self.assertIn("github.event_name == 'pull_request' && !github.event.pull_request.draft", condition)
        self.assertIn("github.event_name == 'workflow_dispatch' && !inputs.force_release", condition)
        self.assertIn('deploy', jobs['e2e-main']['needs'])
        runs = '\n'.join(s.get('run', '') for s in jobs['e2e-main']['steps'])
        self.assertIn('--mode attack', runs)
        self.assertIn('exit "$RC"', runs)
        self.assertNotIn('continue-on-error', jobs['e2e-main'])


if __name__ == '__main__':
    unittest.main()


class E2EConsoleAuthInputsTests(unittest.TestCase):
    """Every real pipeline invocation carries the authenticated console inputs and a pinned
    SSH host identity (T1-E2E-AUTH); credentials stay out of publish/report steps.

    Repository variables and secrets are not environment variables until a step maps them,
    so this asserts the mapping at each call site rather than the existence of the secret.
    """

    CONSOLE_INPUTS = {'PHORVEX_CONSOLE_BASE': 'vars.PHORVEX_CONSOLE_BASE',
                      'PHORVEX_CONSOLE_CA_FILE': 'vars.PHORVEX_CONSOLE_CA_FILE',
                      'PHORVEX_CONSOLE_TOKEN': 'secrets.PHORVEX_CONSOLE_TOKEN'}

    def jobs(self):
        doc = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        return doc['jobs']

    def test_every_pipeline_invocation_maps_the_console_inputs(self):
        call_sites = []
        for name, job in self.jobs().items():
            for step in job['steps']:
                if 'pipeline/e2e.py' in step.get('run', ''):
                    call_sites.append((name, step))
                    env = step.get('env', {})
                    for key, source in self.CONSOLE_INPUTS.items():
                        self.assertIn(source, env.get(key, ''), f'{name}: {key} not mapped from {source}')
                    self.assertIn('secrets.PHORVEX_SSH_PASSWORD', env.get('PHORVEX_SSH_PASSWORD', ''))
        self.assertEqual(sorted(j for j, _ in call_sites), ['e2e', 'e2e-main'])

    def test_each_ssh_using_job_provisions_the_host_identity_before_any_ssh(self):
        for name, job in self.jobs().items():
            steps = job['steps']
            uses_ssh = [i for i, s in enumerate(steps)
                        if 'pipeline/e2e.py' in s.get('run', '') or 'publish-report.sh' in s.get('run', '')]
            if not uses_ssh:
                continue
            provisioning = [i for i, s in enumerate(steps)
                            if 'PHORVEX_SSH_KNOWN_HOSTS=' in s.get('run', '')
                            and 'vars.PHORVEX_SSH_KNOWN_HOSTS' in str(s.get('env', {}))]
            self.assertEqual(len(provisioning), 1, f'{name}: exactly one host-identity provisioning step')
            self.assertLess(provisioning[0], min(uses_ssh), f'{name}: provisioning must precede ssh')
            run = steps[provisioning[0]]['run']
            self.assertIn('umask 077', run)
            self.assertIn('GITHUB_ENV', run)
            self.assertIn('exit 1', run)          # unprovisioned identity fails closed
            self.assertNotIn('accept-new', run)

    def test_credentials_stay_out_of_publish_and_report_steps(self):
        for name, job in self.jobs().items():
            for step in job['steps']:
                run = step.get('run', '')
                env = step.get('env', {})
                if 'pipeline/e2e.py' not in run:
                    self.assertNotIn('PHORVEX_CONSOLE_TOKEN', env,
                                     f"{name}: {step.get('name')} carries the console token")
                if 'publish-report.sh' in run or 'summary.py' in run:
                    self.assertNotIn('PHORVEX_CONSOLE', str(env), f"{name}: {step.get('name')}")

    def test_publish_script_and_pipeline_share_the_strict_host_identity(self):
        script = (ROOT / 'End-to-End/publish-report.sh').read_text()
        self.assertIn('StrictHostKeyChecking=yes', script)
        self.assertIn('PHORVEX_SSH_KNOWN_HOSTS', script)
        for forbidden in ('StrictHostKeyChecking=no', 'UserKnownHostsFile=/dev/null', 'StrictHostKeyChecking=accept-new'):
            self.assertNotIn(forbidden, script)
            self.assertNotIn(forbidden, (ROOT / 'End-to-End/pipeline/transport.py').read_text())
