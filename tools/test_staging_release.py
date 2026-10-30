from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

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


def publication_results(value: dict) -> dict:
    results = {}
    for index, item in enumerate(value["components"]):
        digest = "sha256:" + format(index + 1, "064x")
        if item["kind"] == "fixture":
            digest = item["identity"]["oci"]["manifest"]
        results[item["component"]] = {
            "repository": f"{item['image']['registry']}/{item['image']['repository']}",
            "digest": digest,
        }
    return results


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
        results = publication_results(value)
        complete = RELEASE.complete(value, results)
        self.assertEqual(complete["status"], "complete")
        missing = dict(results)
        missing.pop("attacks")
        with self.assertRaisesRegex(ValueError, "canonical eight"):
            RELEASE.complete(value, missing)

    def test_complete_rejects_a_fixture_digest_other_than_the_reviewed_manifest(self):
        value = prepared_batch()
        results = publication_results(value)
        results["agent-sim"]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "reviewed OCI manifest"):
            RELEASE.complete(value, results)

    def test_batch_binds_git_tree_and_exact_source_derived_service_contracts(self):
        value = prepared_batch()
        canonical = service_contracts(value["source"])
        RELEASE.validate_batch(value, canonical_services=canonical)
        changed = copy.deepcopy(value)
        changed["sourceTree"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source-tree identity"):
            RELEASE.validate_batch(changed, canonical_services=canonical)
        changed = copy.deepcopy(value)
        changed["components"][0]["build"]["dockerfile"] = "deploy/docker/service.Dockerfile"
        with self.assertRaisesRegex(ValueError, "exact source-derived"):
            RELEASE.validate_batch(changed, canonical_services=canonical)

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

    def test_argocd_rejects_template_generator_and_source_overrides(self):
        target = RELEASE.expected_target()
        source = yaml.safe_load((ROOT / target["deployment"]["applicationManifest"]).read_text())
        mutations = []
        patched = copy.deepcopy(source)
        patched["spec"]["templatePatch"] = "spec:\n  destination:\n    namespace: production\n"
        mutations.append(patched)
        patched = copy.deepcopy(source)
        patched["spec"]["generators"][0]["matrix"]["generators"][0]["template"] = {"spec": {"destination": {"namespace": "production"}}}
        mutations.append(patched)
        patched = copy.deepcopy(source)
        patched["spec"]["template"]["spec"]["sources"][1]["repoURL"] = "https://github.com/example/production.git"
        mutations.append(patched)
        for index, manifest in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / target["deployment"]["applicationManifest"]
                path.parent.mkdir(parents=True)
                path.write_text(yaml.safe_dump(manifest, sort_keys=False))
                with mock.patch.object(RELEASE, "ROOT", root), self.assertRaisesRegex(ValueError, "override|route|bound"):
                    RELEASE.verify_argocd(target)

    def test_final_rendered_service_consumer_must_select_the_exact_staging_digest(self):
        value = prepared_batch()
        complete = RELEASE.complete(value, publication_results(value))
        item = next(component for component in complete["components"] if component["component"] == "brain")
        published = complete["releases"]["brain"]
        consumer = item["deploy"]["consumers"][0]
        expected = f"{published['repository']}:{item['image']['tag']}@{published['digest']}"
        deployment = {
            "apiVersion": consumer["apiVersion"],
            "kind": consumer["kind"],
            "metadata": {"name": consumer["name"], "namespace": consumer["namespace"]},
            "spec": {"template": {"spec": {"containers": [{"image": expected}]}}},
        }
        RELEASE.verify_service_documents(item, published, [deployment])

        # A later values file can otherwise override a valid authoritative scalar.
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain:shared"
        )
        with self.assertRaisesRegex(ValueError, "rendered consumer selects"):
            RELEASE.verify_service_documents(item, published, [deployment])

    def test_both_fixture_destinations_exist_and_are_preflighted_before_any_write(self):
        values = yaml.safe_load((ROOT / "deploy/environments/staging/catalogue-family.yaml").read_text())
        for name in RELEASE.FIXTURE_NAMES:
            self.assertIsInstance(RELEASE.nested(values, RELEASE.FIXTURE_SPECS[name]["deploy"]["path"]), str)

        value = RELEASE.complete(prepared_batch(), publication_results(prepared_batch()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = root / "deploy/environments/staging/catalogue-family.yaml"
            overlay.parent.mkdir(parents=True)
            overlay.write_text("phorvex:\n  console:\n    attackCatalog:\n      agentAction:\n        image: \"unchanged\"\n")
            with mock.patch.object(RELEASE, "ROOT", root), mock.patch.object(RELEASE, "validate_batch", return_value=value):
                with self.assertRaisesRegex(ValueError, "missing deployment value"):
                    RELEASE.pin_fixtures(value)
            self.assertIn('image: "unchanged"', overlay.read_text())


if __name__ == "__main__":
    unittest.main()
