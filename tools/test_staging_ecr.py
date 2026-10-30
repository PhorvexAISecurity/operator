from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import staging_release as RELEASE
import test_staging_release as FIXTURE
import verify_staging_ecr as ECR


class FakeECR:
    def __init__(self, *, mutable: set[str] | None = None, digests: dict[str, dict[str, str]] | None = None,
                 manifests: dict[str, tuple[str, str]] | None = None, registry_policy: bool = False):
        self.mutable = mutable or set()
        self.digests = digests or {}
        self.manifests = manifests or {}
        self.registry_policy = registry_policy
        self.commands: list[list[str]] = []
        self.target = RELEASE.expected_target()

    @staticmethod
    def option(command: list[str], name: str) -> str:
        return command[command.index(name) + 1]

    def __call__(self, command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[:3] == ["aws", "sts", "get-caller-identity"]:
            return subprocess.CompletedProcess(command, 0, json.dumps({"Account": self.target["accountId"]}), "")
        if command[:3] == ["aws", "ecr", "get-registry-policy"]:
            if self.registry_policy:
                return subprocess.CompletedProcess(command, 0, json.dumps({"policyText": "{}"}), "")
            return subprocess.CompletedProcess(command, 254, "", "RegistryPolicyNotFoundException")
        if command[:3] == ["aws", "ecr", "get-account-setting"]:
            name = self.option(command, "--name")
            values = {"REGISTRY_POLICY_SCOPE": "V2", "BASIC_SCAN_TYPE_VERSION": "AWS_NATIVE"}
            return subprocess.CompletedProcess(command, 0, json.dumps({"name": name, "value": values[name]}), "")
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
        if command[:3] == ["aws", "ecr", "batch-get-image"]:
            repository = self.option(command, "--repository-name")
            digest = self.option(command, "--image-ids").split("=", 1)[1]
            manifest, media_type = self.manifests[repository]
            response = {"images": [{"imageId": {"imageDigest": digest}, "imageManifest": manifest,
                                     "imageManifestMediaType": media_type}], "failures": []}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        if command[:3] == ["aws", "ecr", "put-image"]:
            repository = self.option(command, "--repository-name")
            tag = self.option(command, "--image-tag")
            manifest = self.option(command, "--image-manifest")
            digest = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
            self.digests.setdefault(repository, {})[tag] = digest
            response = {"image": {"imageId": {"imageDigest": digest, "imageTag": tag}}}
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
        self.assertEqual(state["registryState"]["registryPolicy"], "ABSENT")

    def test_registry_policy_and_scope_are_part_of_the_fail_closed_gate(self):
        value = batch()
        fake = FakeECR(registry_policy=True)
        with self.assertRaisesRegex(RuntimeError, "registry policy"):
            ECR.preflight(value, fake)
        self.assertFalse(any(command[:3] == ["aws", "ecr", "describe-repositories"] for command in fake.commands))

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

    def test_alias_creation_preserves_and_hashes_both_supported_manifest_formats(self):
        for media_type in sorted(ECR.IMAGE_MEDIA_TYPES):
            with self.subTest(media_type=media_type):
                value = batch()
                contract = ECR.component(value, "brain")
                manifest = json.dumps({"schemaVersion": 2, "mediaType": media_type}, separators=(",", ":"))
                digest = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
                repository = contract["image"]["repository"]
                fake = FakeECR(
                    digests={repository: {contract["image"]["tag"]: digest}},
                    manifests={repository: (manifest, media_type)},
                )
                state = ECR.preflight(value, fake)
                result = ECR.ensure_tags(value, "brain", digest, state, fake)
                self.assertEqual(result["digest"], digest)
                self.assertEqual(set(fake.digests[repository]), set(contract["image"]["tags"]))
                put = next(command for command in fake.commands if command[:3] == ["aws", "ecr", "put-image"])
                self.assertEqual(FakeECR.option(put, "--image-manifest-media-type"), media_type)

    def test_alias_creation_rejects_manifest_bytes_not_matching_the_digest(self):
        value = batch()
        contract = ECR.component(value, "brain")
        repository = contract["image"]["repository"]
        digest = "sha256:" + "d" * 64
        fake = FakeECR(
            digests={repository: {contract["image"]["tag"]: digest}},
            manifests={repository: ("{}", "application/vnd.oci.image.manifest.v1+json")},
        )
        state = ECR.preflight(value, fake)
        with self.assertRaisesRegex(RuntimeError, "manifest bytes"):
            ECR.ensure_tags(value, "brain", digest, state, fake)


if __name__ == "__main__":
    unittest.main()
