"""Deterministic aggregate/race/identity checks for the immutable ECR gate."""

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
COMMANDS = {
    "manager": "/manager", "brain": "/service", "sensor": "/service",
    "actuator": "/service", "console": "/app/console", "attacks": "/app/attacks",
}
CANONICAL = ["manager", "brain", "sensor", "actuator", "console", "attacks"]


def batch(names=("brain",), released=()) -> dict:
    names = list(names)
    contracts = []
    releases = {}
    for name in names:
        contracts.append({
            "component": name,
            "identity": {"service": name, "command": COMMANDS[name], "aliases": []},
            "source": SOURCE,
            "version": "1.0.0",
            "image": {"registry": REGISTRY, "repository": f"phorvex/{name}", "tag": "1.0.0"},
            "record": {"releaseKey": name, "gitTag": f"{name}-v1.0.0"},
        })
        if name in released:
            releases[name] = {"repository": f"{REGISTRY}/phorvex/{name}", "digest": DIGEST_A}
    return {
        "schema": 2,
        "status": "complete" if len(releases) == len(names) else ("partial" if releases else "prepared"),
        "environment": "staging",
        "source": SOURCE,
        "expectedComponents": names,
        "versions": {name: "1.0.0" for name in names},
        "components": contracts,
        "releases": releases,
    }


def read_fixture(value: dict) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "batch.json"
        path.write_text(json.dumps(value))
        return GATE.read_batch(path)


class FakeCommands:
    def __init__(self, *, mutability=None, digests=None, identity_errors=(), missing_repositories=(), wrong_repositories=()):
        self.mutability = dict(mutability or {})
        self.digests = {key: (list(value) if isinstance(value, list) else [value])
                        for key, value in (digests or {}).items()}
        self.last_digest = {key: values[-1] for key, values in self.digests.items() if values}
        self.identity_errors = set(identity_errors)
        self.missing_repositories = set(missing_repositories)
        self.wrong_repositories = set(wrong_repositories)
        self.commands = []

    @staticmethod
    def _value(command, option):
        return command[command.index(option) + 1]

    def __call__(self, command, **_kwargs):
        self.commands.append(command)
        if command[:3] == ["aws", "ecr", "describe-repositories"]:
            repository = self._value(command, "--repository-names")
            if repository in self.missing_repositories:
                return subprocess.CompletedProcess(command, 254, "", "RepositoryNotFoundException")
            account = self._value(command, "--registry-id")
            region = self._value(command, "--region")
            remote_repository = "phorvex/other" if repository in self.wrong_repositories else repository
            response = {"repositories": [{
                "registryId": account,
                "repositoryName": remote_repository,
                "repositoryArn": f"arn:aws:ecr:{region}:{account}:repository/{remote_repository}",
                "repositoryUri": f"{account}.dkr.ecr.{region}.amazonaws.com/{remote_repository}",
                "imageTagMutability": self.mutability.get(repository, "IMMUTABLE"),
            }]}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        if command[:3] == ["aws", "ecr", "describe-images"]:
            repository = self._value(command, "--repository-name")
            values = self.digests.get(repository, [None])
            if len(values) > 1:
                digest = values.pop(0)
            else:
                digest = values[0]
            self.last_digest[repository] = digest
            if digest is None:
                return subprocess.CompletedProcess(command, 254, "", "ImageNotFoundException")
            tag = self._value(command, "--image-ids").split("=", 1)[1]
            response = {"imageDetails": [{"imageDigest": digest, "imageTags": [tag]}]}
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")
        if any("verify_service_image_identity.py" in part for part in command):
            component = next((name for name in CANONICAL if f"phorvex/{name}:" in " ".join(command)), "")
            if component in self.identity_errors:
                return subprocess.CompletedProcess(command, 1, "", "embedded identity mismatch")
        return subprocess.CompletedProcess(command, 0, "", "")


class ECRBatchSetTests(unittest.TestCase):
    def test_valid_four_component_batch(self):
        names = ["brain", "sensor", "console", "attacks"]
        self.assertEqual(read_fixture(batch(names))["expectedComponents"], names)

    def test_valid_one_component_batch(self):
        self.assertEqual(read_fixture(batch(["console"]))["expectedComponents"], ["console"])

    def test_valid_full_six_component_batch(self):
        self.assertEqual(read_fixture(batch(CANONICAL))["expectedComponents"], CANONICAL)

    def test_empty_set_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "between 1 and 6"):
            read_fixture(batch([]))

    def test_missing_extra_duplicate_and_reordered_contracts_are_rejected(self):
        names = ["brain", "sensor", "console", "attacks"]
        mutations = {
            "missing": lambda value: value["components"].pop(),
            "extra": lambda value: value["components"].append(value["components"][0]),
            "duplicate": lambda value: value["components"].__setitem__(-1, value["components"][0]),
            "reordered": lambda value: value["components"].__setitem__(slice(0, 2), list(reversed(value["components"][:2]))),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = batch(names)
                mutate(value)
                with self.assertRaisesRegex(SystemExit, "exactly match"):
                    read_fixture(value)

    def test_expected_set_must_be_unique_known_and_canonical(self):
        for label, names in {
            "duplicate": ["brain", "brain"],
            "alias": ["operator"],
            "reordered": ["sensor", "brain"],
            "too many": CANONICAL + ["extra"],
        }.items():
            with self.subTest(label=label):
                value = batch([name for name in names if name in COMMANDS] or ["brain"])
                value["expectedComponents"] = names
                with self.assertRaises(SystemExit):
                    read_fixture(value)

    def test_cross_component_identity_repository_and_release_aliases_are_rejected(self):
        for field in ("identity", "repository", "release"):
            with self.subTest(field=field):
                value = batch(["brain"])
                if field == "identity":
                    value["components"][0]["identity"]["service"] = "sensor"
                elif field == "repository":
                    value["components"][0]["image"]["repository"] = "phorvex/sensor"
                else:
                    value["components"][0]["record"]["releaseKey"] = "sensor"
                with self.assertRaisesRegex(SystemExit, "aliased or cross-component"):
                    read_fixture(value)

    def test_retry_cannot_change_the_persisted_expected_set(self):
        original = read_fixture(batch(["brain", "sensor", "console", "attacks"]))
        state = GATE.preflight(original, ROOT, FakeCommands())
        changed = read_fixture(batch(["brain"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preflight.json"
            path.write_text(json.dumps(state))
            with self.assertRaisesRegex(RuntimeError, "does not match the exact batch"):
                GATE.read_preflight(path, changed)


class ECRAggregatePreflightTests(unittest.TestCase):
    def test_subset_and_full_six_preflight_cover_the_exact_expected_set(self):
        for names in (["brain", "sensor", "console", "attacks"], CANONICAL):
            with self.subTest(names=names):
                value = read_fixture(batch(names))
                state = GATE.preflight(value, ROOT, FakeCommands())
                self.assertEqual([entry["component"] for entry in state["components"]], names)
                self.assertTrue(all(entry["state"] == "absent" for entry in state["components"]))

    def test_later_mutable_repository_fails_before_any_mutating_command(self):
        names = ["brain", "sensor", "console", "attacks"]
        fake = FakeCommands(mutability={"phorvex/console": "MUTABLE"})
        with self.assertRaisesRegex(RuntimeError, "must already be IMMUTABLE"):
            GATE.preflight(read_fixture(batch(names)), ROOT, fake)
        self.assertFalse(any(command[:2] == ["docker", "push"] for command in fake.commands))

    def test_missing_or_wrong_registry_repository_is_rejected(self):
        value = read_fixture(batch(["brain"]))
        with self.assertRaisesRegex(RuntimeError, "RepositoryNotFoundException"):
            GATE.preflight(value, ROOT, FakeCommands(missing_repositories={"phorvex/brain"}))
        with self.assertRaisesRegex(RuntimeError, "differs from the batch registry/account/region"):
            GATE.preflight(value, ROOT, FakeCommands(wrong_repositories={"phorvex/brain"}))

    def test_conflicting_later_tag_fails_the_aggregate_preflight(self):
        names = ["brain", "sensor", "console", "attacks"]
        fake = FakeCommands(digests={"phorvex/attacks": DIGEST_B}, identity_errors={"attacks"})
        with self.assertRaisesRegex(RuntimeError, "embedded identity mismatch"):
            GATE.preflight(read_fixture(batch(names)), ROOT, fake)
        self.assertFalse(any(command[:2] == ["docker", "push"] for command in fake.commands))

    def test_repository_change_after_preflight_fails_before_its_push(self):
        names = ["brain", "sensor", "console", "attacks"]
        value = read_fixture(batch(names))
        fake = FakeCommands()
        state = GATE.preflight(value, ROOT, fake)
        fake.mutability["phorvex/attacks"] = "MUTABLE"
        with self.assertRaisesRegex(RuntimeError, "must already be IMMUTABLE"):
            GATE.probe(value, "attacks", state, fake)

    def test_preflight_state_cannot_change_target_component_or_digest(self):
        value = read_fixture(batch(["brain"]))
        state = GATE.preflight(value, ROOT, FakeCommands())
        mutations = (
            lambda candidate: candidate["components"][0].__setitem__("component", "sensor"),
            lambda candidate: candidate["components"][0].__setitem__("contractDigest", DIGEST_A),
            lambda candidate: candidate["components"][0].__setitem__("digest", DIGEST_A),
        )
        for mutate in mutations:
            candidate = json.loads(json.dumps(state))
            mutate(candidate)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "preflight.json"
                path.write_text(json.dumps(candidate))
                with self.assertRaisesRegex(RuntimeError, "preflight state"):
                    GATE.read_preflight(path, value)

    def test_concurrent_tag_creation_after_absent_preflight_fails_safely(self):
        value = read_fixture(batch(["brain"]))
        fake = FakeCommands(digests={"phorvex/brain": [None, DIGEST_B]})
        state = GATE.preflight(value, ROOT, fake)
        with self.assertRaisesRegex(RuntimeError, "appeared after aggregate preflight"):
            GATE.probe(value, "brain", state, fake)

    def test_partial_push_process_interruption_is_exactly_recoverable(self):
        names = ["brain", "sensor", "console", "attacks"]
        value = read_fixture(batch(names))
        fake = FakeCommands(digests={"phorvex/brain": DIGEST_A})
        state = GATE.preflight(value, ROOT, fake)
        self.assertEqual(state["components"][0]["state"], "recoverable")
        self.assertEqual([entry["state"] for entry in state["components"]],
                         ["recoverable", "absent", "absent", "absent"])
        result = GATE.probe(value, "brain", state, fake)
        self.assertEqual(result, {"component": "brain", "exists": True, "state": "recoverable", "digest": DIGEST_A})
        self.assertFalse(any(command[:2] == ["docker", "push"] for command in fake.commands))

    def test_recorded_matching_tag_is_an_idempotent_retry(self):
        value = read_fixture(batch(["brain"], released={"brain"}))
        fake = FakeCommands(digests={"phorvex/brain": DIGEST_A})
        state = GATE.preflight(value, ROOT, fake)
        self.assertEqual(state["components"][0]["state"], "recorded")
        result = GATE.probe(value, "brain", state, fake)
        self.assertEqual(result["digest"], DIGEST_A)
        self.assertTrue(any("verify_service_image_identity.py" in part
                            for command in fake.commands for part in command))

    def test_partial_completion_within_a_subset_is_verified_atomically(self):
        names = ["brain", "sensor", "console", "attacks"]
        value = read_fixture(batch(names, released={"brain"}))
        fake = FakeCommands(digests={"phorvex/brain": DIGEST_A})
        state = GATE.preflight(value, ROOT, fake)
        self.assertEqual([entry["state"] for entry in state["components"]],
                         ["recorded", "absent", "absent", "absent"])
        self.assertEqual(GATE.verify(value, ROOT, False, FakeCommands(digests={"phorvex/brain": DIGEST_A})),
                         [{"component": "brain", "digest": DIGEST_A}])

    def test_digest_or_embedded_identity_change_is_rejected(self):
        value = read_fixture(batch(["brain"], released={"brain"}))
        with self.assertRaisesRegex(RuntimeError, "differs from persisted"):
            GATE.preflight(value, ROOT, FakeCommands(digests={"phorvex/brain": DIGEST_B}))
        with self.assertRaisesRegex(RuntimeError, "embedded identity mismatch"):
            GATE.preflight(value, ROOT, FakeCommands(digests={"phorvex/brain": DIGEST_A}, identity_errors={"brain"}))

    def test_final_verification_rejects_an_unrecorded_remote_tag(self):
        value = read_fixture(batch(["brain"]))
        with self.assertRaisesRegex(RuntimeError, "no persisted release"):
            GATE.verify(value, ROOT, False, FakeCommands(digests={"phorvex/brain": DIGEST_A}))

    def test_batch_and_preflight_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.json"
            target.write_text(json.dumps(batch(["brain"])))
            link = root / "batch.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "symlinks are not permitted"):
                GATE.read_batch(link)


if __name__ == "__main__":
    unittest.main()
