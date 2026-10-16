import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-go-format.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def run(root, *args):
    subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)


class GoFormatGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        run(self.root, 'init', '-q', '-b', 'main')
        run(self.root, 'config', 'user.email', 'gate@example.invalid')
        run(self.root, 'config', 'user.name', 'gate')
        (self.root / 'old.go').write_text('package x\nfunc  untouched() {}\n')
        (self.root / 'kept.go').write_text('package x\n')
        run(self.root, 'add', '.')
        run(self.root, 'commit', '-qm', 'base')
        run(self.root, 'checkout', '-qb', 'change')
        (self.root / 'new.go').write_text('package x\n')
        (self.root / 'kept.go').write_text('package x\n\nfunc Kept() {}\n')
        (self.root / 'notes.md').write_text('not go\n')
        run(self.root, 'add', '.')
        run(self.root, 'commit', '-qm', 'change')
        # A fake gofmt that reports every file whose content contains a double space.
        self.gofmt = self.root / 'fake-gofmt'
        self.gofmt.write_text('#!/bin/sh\nshift\nfor f in "$@"; do grep -q "  " "$f" && echo "$f"; done; exit 0\n')
        self.gofmt.chmod(0o755)

    def test_only_go_files_changed_since_the_merge_base_are_checked(self):
        self.assertEqual(sorted(gate.changed_go_files('main', self.root)), ['kept.go', 'new.go'])

    def test_unformatted_changed_file_is_reported(self):
        (self.root / 'new.go').write_text('package x\nfunc  Bad() {}\n')
        run(self.root, 'commit', '-qam', 'bad')
        files = gate.changed_go_files('main', self.root)
        self.assertEqual(gate.unformatted(files, self.root, str(self.gofmt)), ['new.go'])

    def test_untouched_unformatted_file_does_not_fail_a_change(self):
        files = gate.changed_go_files('main', self.root)
        self.assertNotIn('old.go', files)
        self.assertEqual(gate.unformatted(files, self.root, str(self.gofmt)), [])

    def test_no_changed_files_needs_no_gofmt(self):
        self.assertEqual(gate.unformatted([], self.root, '/nonexistent/gofmt'), [])

    def test_missing_base_is_an_error(self):
        with self.assertRaises(subprocess.CalledProcessError):
            gate.changed_go_files('no-such-ref', self.root)
        self.assertEqual(gate.main(['check-go-format.py']), 2)


if __name__ == '__main__':
    unittest.main()
