from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import check_private_settings
from test_operations import run


class PrivateSettingsIndexTests(unittest.TestCase):
    def test_untracked_ignored_files_pass_but_force_added_paths_fail(self):
        with tempfile.TemporaryDirectory(prefix='private-settings-test-') as raw:
            repo = Path(raw)
            run(['git', 'init', '-q'], repo)
            (repo/'.gitignore').write_text('.claude/settings.json\n.claude/settings.local.json\n')
            (repo/'safe.txt').write_text('safe\n')
            local = repo/'.claude/settings.local.json'; local.parent.mkdir()
            local.write_text('harmless sentinel\n')
            run(['git', 'add', '.gitignore', 'safe.txt'], repo)
            self.assertEqual(check_private_settings.tracked(repo), [])
            run(['git', 'add', '-f', '.claude/settings.local.json'], repo)
            self.assertEqual(check_private_settings.tracked(repo), ['.claude/settings.local.json'])
            run(['git', 'reset', '-q', '--', '.claude/settings.local.json'], repo)
            self.assertEqual(check_private_settings.tracked(repo), [])
            settings = repo/'.claude/settings.json'; settings.write_text('another harmless sentinel\n')
            run(['git', 'add', '-f', '.claude/settings.json'], repo)
            run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                 'commit', '-q', '-m', 'fixture'], repo)
            self.assertEqual(check_private_settings.tracked(repo), ['.claude/settings.json'])
            self.assertTrue((repo/'safe.txt').is_file())


if __name__ == '__main__':
    unittest.main()
