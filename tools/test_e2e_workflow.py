"""Keep isolated validation available without opting draft PRs into live attacks."""
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
# An actual login: `ssh -o …`, `scp -o …` or `sshpass -e ssh -o …` — not prose or a
# `command -v sshpass` presence check.
INLINE_SSH = re.compile(r'(^|[\s;|&(])(sshpass\s+-e\s+)?(ssh|scp)\s+-')


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
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertNotIn('if', job)
        self.assertNotIn('secrets.', raw)
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        self.assertIn('unittest discover -s End-to-End/pipeline', runs)
        self.assertIn('unittest discover -s tools', runs)
        self.assertNotIn('pipeline/e2e.py', runs)
        self.assertNotIn('kubectl ', runs)
        self.assertNotIn('publish-report', runs)


class E2EPublishTransportTests(unittest.TestCase):
    """The report publisher and pipeline verify the pinned SSH host identity (T1-E2E-AUTH)."""

    def test_publish_script_and_pipeline_share_the_strict_host_identity(self):
        script = (ROOT / 'End-to-End/publish-report.sh').read_text()
        self.assertIn('StrictHostKeyChecking=yes', script)
        self.assertIn('PHORVEX_SSH_KNOWN_HOSTS', script)
        for forbidden in ('StrictHostKeyChecking=no', 'UserKnownHostsFile=/dev/null', 'StrictHostKeyChecking=accept-new'):
            self.assertNotIn(forbidden, script)
            self.assertNotIn(forbidden, (ROOT / 'End-to-End/pipeline/transport.py').read_text())


if __name__ == '__main__':
    unittest.main()
