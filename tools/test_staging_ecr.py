from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

import staging_release as RELEASE
import test_staging_release as FIXTURE
import verify_staging_ecr as ECR


class FakeECR:
    def __init__(self, *, mutable: set[str] | None = None, digests: dict[str, dict[str, str]] | None = None):
        self.mutable = mutable or set()
        self.digests = digests or {}
        self.commands: list[list[str]] = []
        self.target = RELEASE.expected_target()

    @staticmethod
    def option(command: list[str], name: str) -> str:
        return command[command.index(name) + 1]

    def __call__(self, command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[:3] == ["aws", "ecr", "describe-repositories"]:
            repository = self.option(command, "--repository-names")
            response = {"repositories": [{
                "registryId": self.target["accountId"],
                "repositoryName": repository,
                "repositoryArn": f"arn:aws:ecr:{self.target['region']}:{self.target['accountId']}:repository/{repository}",
                "repositoryUri": f"{self.target['registry']}/{repository}",
                "imageTagMutability": "MUTABLE" if repository in self.mutable else "IMMUTABLE",
                "imageScanningConfiguration": {"scanOnPush": True},
                "encryptionConfiguration": {"encryptionType": "AES256"},
            }]}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        if command[:3] == ["aws", "ecr", "list-tags-for-resource"]:
            tags = [{"Key": key, "Value": value} for key, value in self.target["repositoryControls"]["tags"].items()]
            return subprocess.CompletedProcess(command, 0, json.dumps({"tags": tags}), "")
        if command[:3] == ["aws", "ecr", "get-lifecycle-policy"]:
            response = {"lifecyclePolicyText": json.dumps(self.target["repositoryControls"]["lifecyclePolicy"])}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        if command[:3] == ["aws", "ecr", "get-repository-policy"]:
            return subprocess.CompletedProcess(command, 254, "", "RepositoryPolicyNotFoundException")
        if command[:3] == ["aws", "ecr", "describe-images"]:
            repository = self.option(command, "--repository-name")
            tag = self.option(command, "--image-ids").split("=", 1)[1]
            digest = self.digests.get(repository, {}).get(tag)
            if digest is None:
                return subprocess.CompletedProcess(command, 254, "", "ImageNotFoundException")
            response = {"imageDetails": [{"imageDigest": digest, "imageTags": [tag]}]}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        return subprocess.CompletedProcess(command, 0, "", "")


def batch() -> dict:
    return FIXTURE.prepared_batch()


class StagingECRTests(unittest.TestCase):
    def test_aggregate_preflight_covers_exact_eight_empty_repositories(self):
        value = batch()
        state = ECR.preflight(value, FakeECR())
        self.assertEqual([item["component"] for item in state["components"]], RELEASE.COMPONENTS)
        self.assertTrue(all(item["state"] == "absent" for item in state["components"]))

    def test_later_mutable_repository_fails_the_aggregate_before_any_push(self):
        value = batch()
        fake = FakeECR(mutable={"phorvex/staging/console"})
        with self.assertRaisesRegex(RuntimeError, "not IMMUTABLE"):
            ECR.preflight(value, fake)
        self.assertFalse(any(command[:2] == ["docker", "push"] for command in fake.commands))

    def test_tag_created_after_absent_preflight_is_a_race_failure(self):
        value = batch()
        fake = FakeECR()
        state = ECR.preflight(value, fake)
        contract = ECR.component(value, "brain")
        fake.digests[contract["image"]["repository"]] = {contract["image"]["tags"][0]: "sha256:" + "a" * 64}
        with self.assertRaisesRegex(RuntimeError, "appeared after aggregate preflight"):
            ECR.probe(value, "brain", state, fake)

    def test_interrupted_alias_creation_is_recoverable_and_exact(self):
        value = batch()
        contract = ECR.component(value, "brain")
        digest = "sha256:" + "b" * 64
        fake = FakeECR(digests={contract["image"]["repository"]: {contract["image"]["tags"][0]: digest}})
        state = ECR.preflight(value, fake)
        brain = next(item for item in state["components"] if item["component"] == "brain")
        self.assertEqual(brain["state"], "recoverable")
        self.assertEqual(brain["missingTags"], [contract["image"]["tags"][1]])
        result = ECR.probe(value, "brain", state, fake)
        self.assertEqual(result["digest"], digest)
        self.assertEqual(result["missingTags"], [contract["image"]["tags"][1]])

    def test_fixture_recovery_requires_reviewed_manifest_digest(self):
        value = batch()
        contract = ECR.component(value, "agent-sim")
        fake = FakeECR(digests={contract["image"]["repository"]: {contract["image"]["tags"][0]: "sha256:" + "c" * 64}})
        with self.assertRaisesRegex(RuntimeError, "reviewed OCI identity"):
            ECR.preflight(value, fake)


if __name__ == "__main__":
    unittest.main()
