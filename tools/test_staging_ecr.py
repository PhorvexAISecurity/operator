from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import staging_release as RELEASE
import test_staging_release as FIXTURE
import test_release_ecr as SHARED_FIXTURE
import verify_release_ecr as SHARED_ECR
import verify_staging_ecr as ECR


class FakeECR:
    def __init__(self, *, mutable: set[str] | None = None, digests: dict[str, dict[str, str]] | None = None,
                 manifests: dict[str, tuple[str, str]] | None = None, registry_policy: bool = False,
                 scan_type: str = "BASIC", manifest_tags: dict[str, list[str]] | None = None):
        self.mutable = mutable or set()
        self.digests = digests or {}
        self.manifests = manifests or {}
        self.manifest_tags = manifest_tags or {}
        self.registry_policy = registry_policy
        self.scan_type = scan_type
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
        if command[:3] == ["aws", "ecr", "get-registry-scanning-configuration"]:
            response = {
                "registryId": self.target["accountId"],
                "scanningConfiguration": {"scanType": self.scan_type, "rules": []},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
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
            tags = self.manifest_tags.get(repository, [""])
            response = {"images": [
                {"imageId": {"imageDigest": digest, "imageTag": tag}, "imageManifest": manifest,
                 "imageManifestMediaType": media_type}
                for tag in tags
            ], "failures": []}
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
    def test_exact_prepared_shared_mutable_state_reaches_isolated_preflight_only(self):
        shared = SHARED_ECR.read_batch(Path(__file__).resolve().parents[1] / "release/batch.json")
        self.assertEqual(shared["status"], "prepared")
        self.assertEqual(shared["expectedComponents"], RELEASE.SERVICE_NAMES)
        shared_fake = SHARED_FIXTURE.FakeCommands(
            mutability={f"phorvex/{name}": "MUTABLE" for name in RELEASE.SERVICE_NAMES}
        )
        with self.assertRaisesRegex(RuntimeError, "must already be IMMUTABLE"):
            SHARED_ECR.preflight(shared, Path(__file__).resolve().parents[1], shared_fake)
        self.assertFalse(any(command[:2] == ["docker", "push"] or command[:3] == ["aws", "ecr", "put-image"]
                             for command in shared_fake.commands))

        isolated = batch()
        self.assertEqual(isolated["authority"]["shared"]["pendingComponents"], RELEASE.SERVICE_NAMES)
        state = ECR.preflight(isolated, FakeECR())
        self.assertEqual([item["component"] for item in state["components"]], RELEASE.COMPONENTS)
        self.assertTrue(all(item["state"] == "absent" for item in state["components"]))

    def test_service_identity_cleanup_removes_only_the_local_tag(self):
        value = batch()
        contract = ECR.component(value, "brain")
        digest = "sha256:" + "a" * 64
        commands = []

        def runner(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        ECR.verify_remote_identity(contract, digest, runner)
        repository = f"{contract['image']['registry']}/{contract['image']['repository']}"
        self.assertIn(
            ["docker", "image", "rm", f"{repository}:{contract['image']['tag']}"], commands
        )
        self.assertNotIn(
            ["docker", "image", "rm", f"{repository}:{contract['image']['tag']}", f"{repository}@{digest}"],
            commands,
        )

    def test_service_identity_cleanup_distinguishes_absence_from_daemon_failure(self):
        value = batch()
        contract = ECR.component(value, "brain")
        digest = "sha256:" + "a" * 64

        def runner(inspect_result, identity_ok=True):
            def run(command, **_kwargs):
                if "verify_service_image_identity.py" in " ".join(command):
                    return subprocess.CompletedProcess(command, 0 if identity_ok else 1, "", "identity failed")
                if command[:3] == ["docker", "image", "rm"]:
                    return subprocess.CompletedProcess(command, 1, "", "cleanup failed")
                if command[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(command, *inspect_result)
                return subprocess.CompletedProcess(command, 0, "", "")
            return run

        ECR.verify_remote_identity(
            contract, digest,
            runner((1, "", "Error response from daemon: No such image: missing")),
        )
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            ECR.verify_remote_identity(contract, digest, runner((0, "[]", "")))
        with self.assertRaisesRegex(RuntimeError, "Cannot connect to the Docker daemon"):
            ECR.verify_remote_identity(
                contract, digest,
                runner((1, "", "Cannot connect to the Docker daemon")),
            )
        with self.assertRaisesRegex(RuntimeError, "identity failed"):
            ECR.verify_remote_identity(
                contract, digest,
                runner((1, "", "Error response from daemon: No such object: missing"), identity_ok=False),
            )

    def test_service_kind_cannot_bypass_embedded_identity_verification(self):
        prepared = batch()
        value = RELEASE.complete(prepared, FIXTURE.publication_results(prepared))
        digests = {}
        for contract in value["components"]:
            name = contract["component"]
            digest = value["releases"][name]["digest"]
            digests[contract["image"]["repository"]] = {
                tag: digest for tag in contract["image"]["tags"]
            }
            if name in RELEASE.SERVICE_NAMES:
                contract["kind"] = "fixture"
                contract["identity"] = {"oci": {"manifest": digest}}

        fake = FakeECR(digests=digests)
        with self.assertRaisesRegex(RuntimeError, "component manager kind is not canonical service"):
            ECR.verify_complete(value, fake)
        self.assertFalse(any(command[0] == "docker" for command in fake.commands))
        self.assertFalse(any("verify_service_image_identity.py" in " ".join(command) for command in fake.commands))

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

        fake = FakeECR(scan_type="ENHANCED")
        with self.assertRaisesRegex(RuntimeError, "scanning mode"):
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

    def test_alias_creation_accepts_exact_manifest_repeated_for_historical_tags(self):
        value = batch()
        contract = ECR.component(value, "brain")
        manifest = json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
            separators=(",", ":"),
        )
        digest = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
        repository = contract["image"]["repository"]
        fake = FakeECR(
            digests={repository: {contract["image"]["tag"]: digest}},
            manifests={repository: (manifest, "application/vnd.oci.image.manifest.v1+json")},
            manifest_tags={repository: [contract["image"]["tag"], "historical-source-a", "historical-source-b"]},
        )
        state = ECR.preflight(value, fake)
        result = ECR.ensure_tags(value, "brain", digest, state, fake)
        self.assertEqual(result["digest"], digest)
        self.assertEqual(set(fake.digests[repository]), set(contract["image"]["tags"]))

    def test_alias_creation_rejects_conflicting_multi_tag_manifest_lookup(self):
        value = batch()
        contract = ECR.component(value, "brain")
        manifest = json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
            separators=(",", ":"),
        )
        digest = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
        repository = contract["image"]["repository"]
        fake = FakeECR(
            digests={repository: {contract["image"]["tag"]: digest}},
            manifests={repository: (manifest, "application/vnd.oci.image.manifest.v1+json")},
            manifest_tags={repository: ["historical-source-a", "historical-source-b"]},
        )
        original = fake.__call__

        def conflicting(command, **kwargs):
            result = original(command, **kwargs)
            if command[:3] == ["aws", "ecr", "batch-get-image"]:
                response = json.loads(result.stdout)
                response["images"][1]["imageManifest"] = "{}"
                return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
            return result

        state = ECR.preflight(value, fake)
        with self.assertRaisesRegex(RuntimeError, "conflicting identities"):
            ECR.ensure_tags(value, "brain", digest, state, conflicting)


if __name__ == "__main__":
    unittest.main()
