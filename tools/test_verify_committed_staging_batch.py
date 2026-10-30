from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import verify_committed_staging_batch as VERIFY


class CleanupTests(unittest.TestCase):
    def test_every_worktree_cleanup_is_attempted_and_failure_propagates(self):
        temporary = Path(tempfile.mkdtemp(prefix="phorvex-cleanup-test-"))
        worktrees = [temporary / name for name in ("selection", "shared", "source")]
        for worktree in worktrees:
            worktree.mkdir()
        calls = []

        def fail(command, **_kwargs):
            calls.append(command)
            raise subprocess.CalledProcessError(1, command)

        try:
            with mock.patch.object(VERIFY.subprocess, "run", side_effect=fail), self.assertRaisesRegex(
                RuntimeError, "selection.*shared.*source"
            ):
                VERIFY.cleanup_worktrees(temporary, worktrees)
            self.assertEqual(len(calls), 3)
            self.assertTrue(temporary.exists())
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def test_successful_worktree_cleanup_removes_the_temporary_directory(self):
        temporary = Path(tempfile.mkdtemp(prefix="phorvex-cleanup-test-"))
        worktree = temporary / "source"
        worktree.mkdir()
        with mock.patch.object(VERIFY.subprocess, "run") as remove:
            VERIFY.cleanup_worktrees(temporary, [worktree])
        remove.assert_called_once_with(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=VERIFY.ROOT, check=True,
        )
        self.assertFalse(temporary.exists())

    def test_registered_worktree_is_removed_even_when_its_directory_is_missing(self):
        temporary = Path(tempfile.mkdtemp(prefix="phorvex-cleanup-test-"))
        missing = temporary / "deleted-source"
        with mock.patch.object(VERIFY.subprocess, "run") as remove:
            VERIFY.cleanup_worktrees(temporary, [missing])
        remove.assert_called_once_with(
            ["git", "worktree", "remove", "--force", str(missing)],
            cwd=VERIFY.ROOT, check=True,
        )
        self.assertFalse(temporary.exists())


if __name__ == "__main__":
    unittest.main()
