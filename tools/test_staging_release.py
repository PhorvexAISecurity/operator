from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

import staging_release as RELEASE


ROOT = Path(__file__).resolve().parents[1]


def source_sha() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()


def service_contracts(source: str) -> list[dict]:
    historical = json.loads((ROOT / "release/batch.json").read_text(encoding="utf-8"))["components"]
    contracts = copy.deepcopy(historical)
    for item in contracts:
        name = item["component"]
        version = item["version"]
        item["source"] = source
        item["build"]["args"] = [
            f"GIT_SHA={source}" if value.startswith("GIT_SHA=") else value
            for value in item["build"]["args"]
        ]
        tag = f"{version}-git-{source}"
        item["image"] = {
            "registry": "753556437180.dkr.ecr.us-east-2.amazonaws.com",
            "repository": f"phorvex/staging/{name}",
            "tag": tag,
            "tags": [tag, f"git-{source}"],
        }
        item["deploy"]["application"] = "deploy/argocd/services/applicationset.yaml"
        item["deploy"]["releaseName"] = "staging"
        item["deploy"]["namespace"] = "phorvex-staging"
        for consumer in item["deploy"]["consumers"]:
            consumer["expectedRepository"] = f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/{name}"
    return contracts


def prepared_batch() -> dict:
    source = source_sha()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "services.json"
        path.write_text(json.dumps(service_contracts(source)), encoding="utf-8")
        return RELEASE.prepare(source, path)


class StagingTargetTests(unittest.TestCase):
    def test_target_is_exact_staging_only_inventory(self):
        target = RELEASE.expected_target()
        self.assertEqual(target["repositories"], RELEASE.EXPECTED_REPOSITORIES)
        self.assertTrue(all(value.startswith("phorvex/staging/") for value in target["repositories"].values()))
        self.assertEqual(target["repositoryControls"]["imageTagMutability"], "IMMUTABLE")
        self.assertTrue(target["repositoryControls"]["scanOnPush"])
        self.assertEqual(target["repositoryControls"]["resourcePolicy"], "IAM_ONLY")

    def test_prepared_contract_covers_six_services_and_two_fixtures(self):
        value = prepared_batch()
        self.assertEqual(value["status"], "prepared")
        self.assertEqual(value["expectedComponents"], RELEASE.COMPONENTS)
        self.assertEqual([item["kind"] for item in value["components"]], ["service"] * 6 + ["fixture"] * 2)
        for item in value["components"]:
            self.assertEqual(item["source"], value["source"])
            self.assertTrue(item["image"]["repository"].startswith("phorvex/staging/"))
            self.assertEqual(item["image"]["tag"], item["image"]["tags"][0])
            self.assertEqual(item["image"]["tags"][1], "git-" + value["source"])

    def test_shared_or_arbitrary_repository_is_rejected(self):
        value = prepared_batch()
        value["components"][0]["image"]["repository"] = "phorvex/manager"
        with self.assertRaisesRegex(ValueError, "not canonical staging-only"):
            RELEASE.validate_batch(value)

    def test_complete_requires_exact_ordered_eight_component_results(self):
        value = prepared_batch()
        results = {
            name: {
                "repository": f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/{name}",
                "digest": "sha256:" + format(index + 1, "064x"),
            }
            for index, name in enumerate(RELEASE.COMPONENTS)
        }
        complete = RELEASE.complete(value, results)
        self.assertEqual(complete["status"], "complete")
        missing = dict(results)
        missing.pop("attacks")
        with self.assertRaisesRegex(ValueError, "canonical eight"):
            RELEASE.complete(value, missing)

    def test_fixture_pin_replaces_only_the_exact_existing_scalar(self):
        raw = "phorvex:\n  console:\n    attackCatalog:\n      agentAction:\n        enabled: false\n        image: \"\"\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.yaml"
            path.write_text(raw, encoding="utf-8")
            keys = ["phorvex", "console", "attackCatalog", "agentAction", "image"]
            value = "registry.test/phorvex/staging/agent-sim@sha256:" + "a" * 64
            RELEASE.replace_yaml_scalar(path, keys, value)
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(RELEASE.nested(parsed, keys), value)
            self.assertFalse(RELEASE.nested(parsed, keys[:-1])["enabled"])

    def test_argocd_route_is_exact_staging_six_service_set(self):
        RELEASE.verify_argocd(RELEASE.expected_target())


if __name__ == "__main__":
    unittest.main()
