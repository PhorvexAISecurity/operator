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
