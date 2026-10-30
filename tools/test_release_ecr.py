"""Deterministic races and identity checks for the immutable ECR release gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_release_ecr", ROOT / "tools" / "verify_release_ecr.py")
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GATE)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
SOURCE = "1" * 40
REGISTRY = "753556437180.dkr.ecr.us-east-2.amazonaws.com"


def batch(released: bool = False) -> dict:
    contract = {
        "component": "brain",
        "identity": {"service": "brain", "command": "/service"},
        "source": SOURCE,
        "version": "1.0.0",
        "image": {"registry": REGISTRY, "repository": "phorvex/brain", "tag": "1.0.0"},
        "record": {"releaseKey": "brain"},
    }
    releases = {}
    if released:
        releases["brain"] = {"repository": f"{REGISTRY}/phorvex/brain", "digest": DIGEST_A}
    return {"schema": 2, "source": SOURCE, "components": [contract], "releases": releases}


class FakeCommands:
    def __init__(self, *, mutability="IMMUTABLE", digests=None, missing=False, identity_error=False):
        self.mutability = mutability
        self.digests = list(digests or [DIGEST_A])
        self.last_digest = self.digests[-1]
        self.missing = missing
        self.identity_error = identity_error
        self.commands = []

    def __call__(self, command, **_kwargs):
        self.commands.append(command)
        if command[:3] == ["aws", "ecr", "describe-repositories"]:
            output = (f'{{"repositories":[{{"registryId":"753556437180",'
                      f'"repositoryName":"phorvex/brain","imageTagMutability":"{self.mutability}"}}]}}')
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[:3] == ["aws", "ecr", "describe-images"]:
            if self.missing:
                return subprocess.CompletedProcess(command, 254, "", "ImageNotFoundException")
            if self.digests:
                self.last_digest = self.digests.pop(0)
            output = f'{{"imageDetails":[{{"imageDigest":"{self.last_digest}","imageTags":["1.0.0"]}}]}}'
            return subprocess.CompletedProcess(command, 0, output, "")
        if self.identity_error and any("verify_service_image_identity.py" in part for part in command):
            return subprocess.CompletedProcess(command, 1, "", "embedded identity mismatch")
        return subprocess.CompletedProcess(command, 0, "", "")


class ECRReleaseGateTests(unittest.TestCase):
    def test_mutable_repository_is_a_hard_prerequisite_failure(self):
        fake = FakeCommands(mutability="MUTABLE", missing=True)
        with self.assertRaisesRegex(RuntimeError, "must already be IMMUTABLE"):
            GATE.probe(batch(), "brain", fake)

    def test_conflicting_preexisting_tag_is_never_overwritten(self):
        fake = FakeCommands(digests=[DIGEST_B])
        with self.assertRaisesRegex(RuntimeError, "conflicting preexisting ECR tag"):
            GATE.probe(batch(), "brain", fake)

    def test_matching_persisted_tag_is_an_idempotent_retry(self):
        fake = FakeCommands(digests=[DIGEST_A])
        result = GATE.probe(batch(released=True), "brain", fake)
        self.assertEqual(result, {"component": "brain", "exists": True, "digest": DIGEST_A})
        self.assertTrue(any("verify_service_image_identity.py" in part
                            for command in fake.commands for part in command))

    def test_missing_tag_is_allowed_only_for_an_unrecorded_component(self):
        result = GATE.probe(batch(), "brain", FakeCommands(missing=True))
        self.assertEqual(result, {"component": "brain", "exists": False})
        with self.assertRaisesRegex(RuntimeError, "recorded component brain has no ECR version tag"):
            GATE.probe(batch(released=True), "brain", FakeCommands(missing=True))

    def test_retag_after_initial_verification_is_detected(self):
        fake = FakeCommands(digests=[DIGEST_A, DIGEST_B])
        self.assertEqual(GATE.verify(batch(released=True), ROOT, False, fake)[0]["digest"], DIGEST_A)
        with self.assertRaisesRegex(RuntimeError, "differs from persisted"):
            GATE.verify(batch(released=True), ROOT, False, fake)

    def test_retag_at_last_git_publication_boundary_is_detected(self):
        fake = FakeCommands(digests=[DIGEST_A, DIGEST_A, DIGEST_B])
        GATE.verify(batch(released=True), ROOT, False, fake)  # initial post-push verification
        GATE.verify(batch(released=True), ROOT, False, fake)  # immediately before commit
        with self.assertRaisesRegex(RuntimeError, "differs from persisted"):
            GATE.verify(batch(released=True), ROOT, False, fake)  # immediately before Git push

    def test_final_verification_rejects_an_unrecorded_remote_tag(self):
        with self.assertRaisesRegex(RuntimeError, "no persisted release"):
            GATE.verify(batch(), ROOT, False, FakeCommands(digests=[DIGEST_A]))

    def test_final_verification_rechecks_pending_repository_immutability(self):
        with self.assertRaisesRegex(RuntimeError, "must already be IMMUTABLE"):
            GATE.verify(batch(), ROOT, False, FakeCommands(mutability="MUTABLE", missing=True))

    def test_digest_match_does_not_waive_embedded_identity(self):
        fake = FakeCommands(digests=[DIGEST_A], identity_error=True)
        with self.assertRaisesRegex(RuntimeError, "embedded identity mismatch"):
            GATE.verify(batch(released=True), ROOT, True, fake)

    def test_batch_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.json"
            target.write_text('{"schema":2,"source":"' + SOURCE + '","components":[],"releases":{}}')
            link = root / "batch.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "symlinks are not permitted"):
                GATE.read_batch(link)

    def test_batch_file_requires_the_exact_six_component_set(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "batch.json"
            path.write_text(json.dumps(batch()))
            with self.assertRaisesRegex(SystemExit, "all six release components"):
                GATE.read_batch(path)


if __name__ == "__main__":
    unittest.main()
