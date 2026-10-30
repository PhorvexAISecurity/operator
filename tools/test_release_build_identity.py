from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "tools/verify-git-build-identity.sh"
IMAGE_VERIFY = ROOT / "tools/verify_service_image_identity.py"


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


class ServiceImageIdentityTests(unittest.TestCase):
    repository = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain"
    tag = "1.2.3"
    source = "a" * 40
    digest = "sha256:" + "b" * 64

    def verify(self, *, expected_digest=None, identity_source=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fake_bin = Path(temporary.name)
        docker = fake_bin / "docker"
        docker.write_text(
            """#!/usr/bin/env python3
import os
import sys
if sys.argv[1:3] == ["image", "inspect"]:
    print(os.environ["FAKE_IMAGE_INSPECT"])
elif sys.argv[1] == "run":
    print(os.environ["FAKE_BINARY_IDENTITY"])
else:
    raise SystemExit(2)
""",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        image = f"{self.repository}:{self.tag}"
        inspect = [{
            "Config": {
                "Labels": {
                    "org.opencontainers.image.revision": self.source,
                    "org.opencontainers.image.version": self.tag,
                },
                "User": "65532:65532",
            },
            "Os": "linux",
            "Architecture": "amd64",
            "RepoTags": [image],
            "RepoDigests": [f"{self.repository}@{self.digest}"],
            "Id": "sha256:" + "c" * 64,
        }]
        identity = {
            "service": "brain",
            "version": self.tag,
            "gitSHA": identity_source or self.source,
        }
        return subprocess.run(
            [
                str(IMAGE_VERIFY),
                "--image", image,
                "--service", "brain",
                "--entrypoint", "/service",
                "--git-sha", self.source,
                "--version", self.tag,
                "--expected-repository", self.repository,
                "--expected-tag", self.tag,
                "--expected-digest", expected_digest or self.digest,
            ],
            text=True,
            capture_output=True,
            timeout=5,
            env=dict(
                os.environ,
                PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                FAKE_IMAGE_INSPECT=json.dumps(inspect),
                FAKE_BINARY_IDENTITY=json.dumps(identity),
            ),
        )

    def test_pushed_repository_tag_digest_and_binary_identity_all_match(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_remote_digest_or_binary_source_is_rejected(self):
        wrong_digest = self.verify(expected_digest="sha256:" + "d" * 64)
        self.assertNotEqual(wrong_digest.returncode, 0)
        self.assertIn("does not own pushed digest", wrong_digest.stderr)
        wrong_source = self.verify(identity_source="e" * 40)
        self.assertNotEqual(wrong_source.returncode, 0)
        self.assertIn("binary identity", wrong_source.stderr)


if __name__ == "__main__":
    unittest.main()
