from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "tools/verify-git-build-identity.sh"


class ReleaseBuildIdentityTests(unittest.TestCase):
    def repository(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        (root / "source").write_text("reviewed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "source"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "reviewed"], check=True)
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        return root, sha

    def verify(self, root: Path, sha: str):
        return subprocess.run(
            [str(VERIFY), sha], cwd=root, text=True, capture_output=True, timeout=5
        )

    def test_exact_clean_head_is_the_only_admitted_source(self):
        root, sha = self.repository()
        result = self.verify(root, sha)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), sha)

    def test_wrong_or_malformed_sha_is_refused(self):
        root, sha = self.repository()
        result = self.verify(root, "f" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not equal reviewed SHA", result.stderr)
        malformed = self.verify(root, sha[:12])
        self.assertEqual(malformed.returncode, 2)

    def test_tracked_and_untracked_dirt_are_refused(self):
        root, sha = self.repository()
        (root / "source").write_text("dirty\n", encoding="utf-8")
        tracked = self.verify(root, sha)
        self.assertNotEqual(tracked.returncode, 0)
        self.assertIn("dirty checkout", tracked.stderr)

        root, sha = self.repository()
        (root / "untracked").write_text("dirty\n", encoding="utf-8")
        untracked = self.verify(root, sha)
        self.assertNotEqual(untracked.returncode, 0)
        self.assertIn("dirty checkout", untracked.stderr)


if __name__ == "__main__":
    unittest.main()
