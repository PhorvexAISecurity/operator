from __future__ import annotations

import copy
import hashlib
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


def git_object(source: str, path: str) -> str:
    return subprocess.run(
        ["git", "rev-parse", f"{source}:{path}"], cwd=ROOT, check=True,
        text=True, capture_output=True,
    ).stdout.strip()


def staging_authority(source: str) -> dict:
    shared_path = ROOT / "release/batch.json"
    shared_raw = shared_path.read_bytes()
    shared = json.loads(shared_raw)
    pending = [name for name in shared["expectedComponents"] if name not in shared["releases"]]
    return {
        "schema": 1,
        "target": "staging-isolated",
        "source": {
            "commit": source,
            "tree": subprocess.run(
                ["git", "rev-parse", f"{source}^{{tree}}"], cwd=ROOT, check=True,
                text=True, capture_output=True,
            ).stdout.strip(),
            "dispatchRef": "refs/heads/main",
            "serviceHelperTree": git_object(source, "phorvex/tools/servicerelease"),
            "files": {path: git_object(source, path) for path in RELEASE.SOURCE_AUTHORITY_FILES},
        },
        "shared": {
            "batchPath": "release/batch.json",
            "batchDigest": "sha256:" + hashlib.sha256(shared_raw).hexdigest(),
            "schema": shared["schema"],
            "status": shared["status"],
            "source": shared["source"],
            "expectedComponents": shared["expectedComponents"],
            "pendingComponents": pending,
            "repositories": [item["image"]["repository"] for item in shared["components"]],
        },
        "isolated": {
            "batchPath": "release/staging-batch.json",
            "repositories": [RELEASE.EXPECTED_REPOSITORIES[name] for name in RELEASE.COMPONENTS],
            "proposalPaths": RELEASE.PROPOSAL_PATHS,
        },
    }


def service_contracts(source: str) -> list[dict]:
    specs = {
        "manager": ("operator", "/manager", "deploy/docker/operator.Dockerfile", "", "phorvex/charts/phorvex", "manager", ["phorvex", "image"], "releaseDigest", "releaseSourceSHA", "staging-phorvex"),
        "brain": ("brain", "/service", "deploy/docker/service.Dockerfile", "", "deploy/charts/phorvex-brain", "brain", ["image"], "digest", "", "staging-brain"),
        "sensor": ("sensor", "/service", "deploy/docker/service.Dockerfile", "", "deploy/charts/phorvex-sensor", "sensor", ["image"], "digest", "", "staging-sensor"),
        "actuator": ("actuator", "/service", "deploy/docker/service.Dockerfile", "", "deploy/charts/phorvex-actuator", "actuator", ["image"], "digest", "", "staging-actuator"),
        "console": ("console", "/app/console", "deploy/docker/console.Dockerfile", "", "deploy/charts/phorvex-console", "console", ["phorvex", "console", "image"], "releaseDigest", "releaseSourceSHA", "staging-phorvex-console"),
        "attacks": ("attacks", "/app/attacks", "deploy/docker/console.Dockerfile", "attacks", "deploy/charts/phorvex-attacks", "attacks", ["image"], "digest", "", "staging-attacks"),
    }
    contracts = []
    for name in RELEASE.SERVICE_NAMES:
        image_name, command, dockerfile, target, chart, values_name, path, digest_key, source_key, workload = specs[name]
        version = "1.0.0"
        args = [f"GIT_SHA={source}", f"RELEASE_VERSION={version}"]
        if name in {"brain", "sensor", "actuator"}:
            args.append(f"SERVICE={name}")
        if name in {"console", "attacks"}:
            args.append(f"CONSOLE_VERSION={version}")
        tag = f"staging-{version}-git-{source}"
        values_file = f"deploy/environments/staging/{values_name}.yaml"
        contracts.append({
            "component": name, "source": source, "version": version,
            "build": {"dockerfile": dockerfile, "context": ".", "target": target, "args": args},
            "image": {
                "registry": "753556437180.dkr.ecr.us-east-2.amazonaws.com",
                "repository": f"phorvex/staging/{name}", "tag": tag,
                "tags": [tag, f"staging-git-{source}"],
            },
            "identity": {"service": name, "command": command, "validationImage": image_name, "aliases": []},
            "deploy": {
                "application": "deploy/argocd/services/applicationset.yaml", "chart": chart,
                "releaseName": "staging", "namespace": "phorvex-staging",
                "valuesFiles": ["deploy/environments/staging/phorvex.yaml", values_file,
                                "deploy/environments/staging/catalogue-family.yaml"],
                "valuesFile": values_file, "path": path, "repositoryKey": "repository",
                "tagKey": "tag", "digestKey": digest_key, "sourceKey": source_key,
                "consumers": [{
                    "apiVersion": "apps/v1", "kind": "Deployment", "namespace": "phorvex-staging",
                    "name": workload, "container": name,
                    "fieldPath": "/spec/template/spec/containers/0/image", "component": name,
                    "expectedRepository": f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/{name}",
                }],
            },
        })
    return contracts


def prepared_batch() -> dict:
    source = source_sha()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "services.json"
        authority = Path(directory) / "authority.json"
        path.write_text(json.dumps(service_contracts(source)), encoding="utf-8")
        authority.write_text(json.dumps(staging_authority(source)), encoding="utf-8")
        return RELEASE.prepare(source, path, authority)


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


def shared_batch(value: dict, names: list[str]) -> dict:
    source = "f" * 40
    components = []
    releases = {}
    versions = {}
    for isolated in value["components"][: len(RELEASE.SERVICE_NAMES)]:
        name = isolated["component"]
        if name not in names:
            continue
        item = copy.deepcopy(isolated)
        item.pop("kind")
        item["source"] = source
        item["version"] = "2.0.0"
        item["image"] = {
            "registry": "753556437180.dkr.ecr.us-east-2.amazonaws.com",
            "repository": f"phorvex/{name}", "tag": "2.0.0",
        }
        for consumer in item["deploy"]["consumers"]:
            consumer["expectedRepository"] = (
                f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/{name}"
            )
        components.append(item)
        versions[name] = "2.0.0"
        releases[name] = {
            "repository": f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/{name}",
            "digest": "sha256:" + format(len(components), "064x"),
        }
    return {
        "schema": 2, "status": "complete", "source": source, "environment": "staging",
        "expectedComponents": names, "versions": versions, "components": components,
        "releases": releases,
    }


class StagingTargetTests(unittest.TestCase):
    def test_target_is_exact_staging_only_inventory(self):
        target = RELEASE.expected_target()
        self.assertEqual(target["repositories"], RELEASE.EXPECTED_REPOSITORIES)
        self.assertTrue(all(value.startswith("phorvex/staging/") for value in target["repositories"].values()))
        self.assertEqual(target["repositoryControls"]["imageTagMutability"], "IMMUTABLE")
        self.assertTrue(target["repositoryControls"]["scanOnPush"])
        self.assertEqual(target["repositoryControls"]["registryScanType"], "BASIC")
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
            self.assertTrue(item["image"]["tag"].startswith("staging-"))
            self.assertEqual(item["image"]["tags"][1], "staging-git-" + value["source"])
            self.assertNotEqual(item["image"]["tag"], item["version"])
        self.assertEqual(value["authority"]["shared"]["status"], "prepared")
        self.assertEqual(value["authority"]["shared"]["pendingComponents"], RELEASE.SERVICE_NAMES)
        self.assertEqual(value["authority"]["isolated"]["proposalPaths"], RELEASE.PROPOSAL_PATHS)

    def test_authority_tampering_and_overlap_fail_closed(self):
        value = prepared_batch()
        mutations = {
            "helper": lambda candidate: candidate["authority"]["source"].__setitem__(
                "serviceHelperTree", "0" * 40
            ),
            "shared digest": lambda candidate: candidate["authority"]["shared"].__setitem__(
                "batchDigest", "sha256:" + "0" * 64
            ),
            "pending": lambda candidate: candidate["authority"]["shared"].__setitem__(
                "pendingComponents", []
            ),
            "repository overlap": lambda candidate: candidate["authority"]["isolated"][
                "repositories"
            ].__setitem__(0, "phorvex/manager"),
            "proposal escape": lambda candidate: candidate["authority"]["isolated"][
                "proposalPaths"
            ].append("release/batch.json"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(value)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    RELEASE.validate_batch(candidate)

    def test_shared_or_arbitrary_repository_is_rejected(self):
        value = prepared_batch()
        value["components"][0]["image"]["repository"] = "phorvex/manager"
        with self.assertRaisesRegex(ValueError, "not canonical staging-only"):
            RELEASE.validate_batch(value)

        value = prepared_batch()
        value["components"][0]["kind"] = "fixture"
        with self.assertRaisesRegex(ValueError, "service component kind"):
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

    def test_subset_shared_release_supersedes_only_its_exact_components(self):
        value = prepared_batch()
        complete = RELEASE.complete(value, publication_results(value))
        shared = shared_batch(complete, ["console"])
        relation = subprocess.CompletedProcess([], 0)
        with mock.patch.object(RELEASE.subprocess, "run", return_value=relation):
            selected = RELEASE.superseding_shared_services(shared, complete["source"])
        self.assertEqual(set(selected), {"console"})

        shared["components"][0]["image"]["repository"] = "phorvex/staging/console"
        with mock.patch.object(RELEASE.subprocess, "run", return_value=relation), self.assertRaisesRegex(
            ValueError, "identity is malformed"
        ):
            RELEASE.superseding_shared_services(shared, complete["source"])

    def test_subset_shared_release_keeps_unselected_isolated_pins_enforced(self):
        value = prepared_batch()
        complete = RELEASE.complete(value, publication_results(value))
        shared = shared_batch(complete, ["console"])
        selected = {"console": (shared["components"][0], shared["releases"]["console"])}

        def current_values(item):
            if item["component"] == "brain":
                raise ValueError("retained isolated brain pin drift")
            release = complete["releases"][item["component"]]
            result = {
                "repository": release["repository"], "tag": item["image"]["tag"],
                "digest": release["digest"],
            }
            if item["deploy"].get("sourceKey"):
                result["source"] = complete["source"]
            return result

        with (
            mock.patch.object(RELEASE, "validate_batch"),
            mock.patch.object(RELEASE, "expected_target", return_value={}),
            mock.patch.object(RELEASE, "verify_argocd"),
            mock.patch.object(RELEASE, "superseding_shared_services", return_value=selected),
            mock.patch.object(RELEASE, "active_catalogue_fixture_consumers", return_value={}),
            mock.patch.object(RELEASE, "image_values", side_effect=current_values),
            mock.patch.object(RELEASE, "verify_rendered_service"),
            self.assertRaisesRegex(ValueError, "retained isolated brain pin drift"),
        ):
            RELEASE.verify_deployment(complete, None, service_contracts(complete["source"]), shared)

    def test_subset_shared_release_renders_selected_shared_consumers(self):
        value = prepared_batch()
        complete = RELEASE.complete(value, publication_results(value))
        shared = shared_batch(complete, ["manager"])
        selected = {"manager": (shared["components"][0], shared["releases"]["manager"])}

        with (
            mock.patch.object(RELEASE, "validate_batch"),
            mock.patch.object(RELEASE, "expected_target", return_value={}),
            mock.patch.object(RELEASE, "verify_argocd"),
            mock.patch.object(RELEASE, "superseding_shared_services", return_value=selected),
            mock.patch.object(RELEASE, "active_catalogue_fixture_consumers", return_value={}),
            mock.patch.object(
                RELEASE, "verify_rendered_service", side_effect=ValueError("selected shared image volume")
            ) as rendered,
            self.assertRaisesRegex(ValueError, "selected shared image volume"),
        ):
            RELEASE.verify_deployment(complete, None, service_contracts(complete["source"]), shared)
        rendered.assert_called_once_with(shared["components"][0], shared["releases"]["manager"])

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

    def test_active_catalogue_window_accepts_exact_source_pinned_fixture_profiles(self):
        prepared = prepared_batch()
        complete = RELEASE.complete(prepared, publication_results(prepared))
        profiles = (
            ("agent-action", "agent-sim", "--agent-image"),
            ("identity-sa-rotate", "catalogue-workload", "--workload-image"),
        )
        for profile, component, image_flag in profiles:
            with self.subTest(profile=profile):
                release = complete["releases"][component]
                image = f"{release['repository']}@{release['digest']}"
                agent_release = complete["releases"]["agent-sim"]
                agent_image = f"{agent_release['repository']}@{agent_release['digest']}"
                command = [
                    "python3", str(ROOT / "tools/render_catalogue_staging_values.py"),
                    "--profile", profile, "--agent-image", agent_image,
                ]
                if component == "catalogue-workload":
                    command.extend((image_flag, image))
                generated = subprocess.run(
                    command, cwd=ROOT, check=True, text=True, capture_output=True,
                ).stdout
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    overlay = root / "deploy/environments/staging/catalogue-family.yaml"
                    overlay.parent.mkdir(parents=True)
                    overlay.write_text(generated, encoding="utf-8")
                    completed = mock.Mock(stdout=generated)
                    with (
                        mock.patch.object(RELEASE, "ROOT", root),
                        mock.patch.object(RELEASE.subprocess, "run", return_value=completed) as render,
                    ):
                        consumers = RELEASE.active_catalogue_fixture_consumers(complete)
                expected = {
                    RELEASE.consumer_key(consumer): image
                    for item in complete["components"] if item["component"] == component
                    for consumer in item["deploy"]["consumers"] if consumer["profile"] == profile
                }
                self.assertEqual(consumers, expected)
                rendered_command = render.call_args.args[0]
                self.assertIn(["--agent-image", agent_image], [rendered_command[i:i + 2] for i in range(len(rendered_command) - 1)])
                if component == "catalogue-workload":
                    self.assertIn([image_flag, image], [rendered_command[i:i + 2] for i in range(len(rendered_command) - 1)])

    def test_active_catalogue_window_rejects_wrong_identity_fixture_pin(self):
        prepared = prepared_batch()
        complete = RELEASE.complete(prepared, publication_results(prepared))
        release = complete["releases"]["catalogue-workload"]
        image = f"{release['repository']}@{release['digest']}"
        agent_release = complete["releases"]["agent-sim"]
        agent_image = f"{agent_release['repository']}@{agent_release['digest']}"
        generated = subprocess.run([
            "python3", str(ROOT / "tools/render_catalogue_staging_values.py"),
            "--profile", "identity-sa-rotate", "--agent-image", agent_image,
            "--workload-image", image,
        ], cwd=ROOT, check=True, text=True, capture_output=True).stdout
        values = yaml.safe_load(generated)
        values["phorvex"]["console"]["attackCatalog"]["familyFixtures"]["images"]["workload"] = (
            "registry.invalid.test/catalogue-workload@sha256:" + "0" * 64
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = root / "deploy/environments/staging/catalogue-family.yaml"
            overlay.parent.mkdir(parents=True)
            overlay.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
            with (
                mock.patch.object(RELEASE, "ROOT", root),
                mock.patch.object(RELEASE.subprocess, "run", return_value=mock.Mock(stdout=generated)),
                self.assertRaisesRegex(ValueError, "differs from the exact generated overlay"),
            ):
                RELEASE.active_catalogue_fixture_consumers(complete)

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
            "spec": {"template": {"spec": {"containers": [{
                "name": consumer["container"], "image": expected,
            }]}}},
        }
        RELEASE.verify_service_documents(item, published, [deployment])

        fixture_key = (
            "apps/v1", "Deployment", "p6-demo", "agent-sim",
            "/spec/template/spec/containers/0/image", "agent-sim",
        )
        fixture_image = (
            "753556437180.dkr.ecr.us-east-2.amazonaws.com/"
            "phorvex/staging/agent-sim@sha256:" + "b" * 64
        )
        fixture = {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-sim", "namespace": "p6-demo"},
            "spec": {"template": {"spec": {"containers": [{
                "name": "agent-sim", "image": fixture_image,
            }]}}},
        }
        RELEASE.verify_service_documents(
            item, published, [deployment, fixture], {fixture_key: fixture_image}
        )
        fixture["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/agent-sim:mutable"
        )
        with self.assertRaisesRegex(ValueError, "additional rendered consumer.*selects"):
            RELEASE.verify_service_documents(
                item, published, [deployment, fixture], {fixture_key: fixture_image}
            )

        # A later values file can otherwise override a valid authoritative scalar.
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain:shared"
        )
        with self.assertRaisesRegex(ValueError, "rendered consumer selects"):
            RELEASE.verify_service_documents(item, published, [deployment])

        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = expected
        pod = {"containers": [{
            "name": "gpu",
            "image": "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain@sha256:" + "a" * 64,
        }]}
        extras = [
            {
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "unexpected-pod", "namespace": "phorvex-system"},
                "spec": pod,
            },
            {
                "apiVersion": "batch/v1", "kind": "CronJob",
                "metadata": {"name": "unexpected-cron", "namespace": "phorvex-system"},
                "spec": {"jobTemplate": {"spec": {"template": {"spec": pod}}}},
            },
            {
                "apiVersion": "apps/v1", "kind": "DaemonSet",
                "metadata": {"name": "unexpected-daemon", "namespace": "phorvex-system"},
                "spec": {"template": {"spec": pod}},
            },
            {
                "apiVersion": "jobset.x-k8s.io/v1alpha2", "kind": "JobSet",
                "metadata": {"name": "unexpected-jobset", "namespace": "phorvex-system"},
                "spec": {"replicatedJobs": [{"name": "worker", "template": {"spec": {
                    "template": {"spec": pod},
                }}}]},
            },
        ]
        for extra in extras:
            with self.subTest(kind=extra["kind"]), self.assertRaisesRegex(
                ValueError, "unexpected rendered image consumers"
            ):
                RELEASE.verify_service_documents(item, published, [deployment, extra])

        custom = copy.deepcopy(extras[-1])
        custom_pod = custom["spec"]["replicatedJobs"][0]["template"]["spec"]["template"]["spec"]
        custom_pod["containers"][0]["image"] = expected
        custom_item = copy.deepcopy(item)
        custom_consumer = copy.deepcopy(consumer)
        custom_consumer.update({
            "apiVersion": custom["apiVersion"],
            "kind": custom["kind"],
            "namespace": custom["metadata"]["namespace"],
            "name": custom["metadata"]["name"],
            "fieldPath": "/spec/replicatedJobs/0/template/spec/template/spec/containers/0/image",
            "container": "gpu",
        })
        custom_item["deploy"]["consumers"].append(custom_consumer)
        RELEASE.verify_service_documents(custom_item, published, [deployment, custom])

        # Kubernetes image volumes are OCI consumers too. They are intentionally
        # unsupported until the release contract has a first-class volume schema.
        image_volume = copy.deepcopy(deployment)
        image_volume["spec"]["template"]["spec"]["volumes"] = [{
            "name": "rogue",
            "image": {
                "reference": "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain:shared",
                "pullPolicy": "IfNotPresent",
            },
        }]
        with self.assertRaisesRegex(ValueError, "image volume.*unsupported"):
            RELEASE.verify_service_documents(item, published, [image_volume])

        volume_only = {
            "apiVersion": "example.io/v1", "kind": "ImageVolumeWorkload",
            "metadata": {"name": "volume-only", "namespace": "phorvex-staging"},
            "spec": {"template": {"spec": {"volumes": [{
                "name": "rogue", "image": {"reference": "phorvex/brain:shared"},
            }]}}},
        }
        with self.assertRaisesRegex(ValueError, "image volume.*unsupported"):
            RELEASE.verify_service_documents(item, published, [deployment, volume_only])

    def test_fixture_render_rejects_every_uncontracted_image_consumer(self):
        prepared = prepared_batch()
        complete = RELEASE.complete(prepared, publication_results(prepared))
        fixture = next(item for item in complete["components"] if item["component"] == "catalogue-workload")
        fixture_consumer = next(
            consumer for consumer in fixture["deploy"]["consumers"]
            if consumer["profile"] == "quarantine"
        )
        attacks = next(item for item in complete["components"] if item["component"] == "attacks")
        self.assertEqual(len(attacks["deploy"]["consumers"]), 1)
        attacks_consumer = attacks["deploy"]["consumers"][0]
        fixture_image = (
            f"{complete['releases']['catalogue-workload']['repository']}@"
            f"{complete['releases']['catalogue-workload']['digest']}"
        )
        attacks_image = (
            f"{complete['releases']['attacks']['repository']}:{attacks['image']['tag']}@"
            f"{complete['releases']['attacks']['digest']}"
        )

        def deployment(consumer, image):
            self.assertEqual(consumer["fieldPath"], "/spec/template/spec/containers/0/image")
            return {
                "apiVersion": consumer["apiVersion"], "kind": consumer["kind"],
                "metadata": {"name": consumer["name"], "namespace": consumer["namespace"]},
                "spec": {"template": {"spec": {"containers": [{
                    "name": consumer["container"], "image": image,
                }]}}},
            }

        documents = [
            deployment(fixture_consumer, fixture_image),
            deployment(attacks_consumer, attacks_image),
        ]
        RELEASE.verify_fixture_documents(complete, "catalogue-workload", "quarantine", documents)
        documents.append({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "uncontracted", "namespace": "phorvex-staging"},
            "spec": {"containers": [{
                "name": "rogue",
                "image": "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/brain:shared",
            }]},
        })
        with self.assertRaisesRegex(ValueError, "unexpected rendered image consumers"):
            RELEASE.verify_fixture_documents(complete, "catalogue-workload", "quarantine", documents)

        profiles = {consumer["profile"] for consumer in fixture["deploy"]["consumers"]}
        self.assertEqual(profiles, {
            "controller-stop", "credential", "identity-sa-rotate", "image",
            "network-edge", "node-recycle", "pod-rotate", "quarantine",
        })

    def test_exact_pin_values_reject_other_changes_in_an_allowed_staging_file(self):
        prepared = prepared_batch()
        complete = RELEASE.complete(prepared, publication_results(prepared))
        base_values = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for item in complete["components"][: len(RELEASE.SERVICE_NAMES)]:
                relative = item["deploy"]["valuesFile"]
                before = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
                base_values[relative] = before
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    yaml.safe_dump(RELEASE.expected_service_values(before, item, complete), sort_keys=False)
                )
            fixture_outputs = {}
            fixture_files = {
                item["deploy"]["valuesFile"]
                for item in complete["components"][len(RELEASE.SERVICE_NAMES):]
            }
            for fixture_path in fixture_files:
                fixture_before = yaml.safe_load((ROOT / fixture_path).read_text(encoding="utf-8"))
                base_values[fixture_path] = fixture_before
                fixture_output = root / fixture_path
                fixture_output.parent.mkdir(parents=True, exist_ok=True)
                fixture_output.write_text(
                    yaml.safe_dump(
                        RELEASE.expected_fixture_values(fixture_before, complete, fixture_path),
                        sort_keys=False,
                    )
                )
                fixture_outputs[fixture_path] = fixture_output

            def loader(_revision, path):
                return copy.deepcopy(base_values[path])

            with mock.patch.object(RELEASE, "ROOT", root), mock.patch.object(
                RELEASE, "git_yaml_at_revision", side_effect=loader
            ):
                RELEASE.verify_exact_pin_diffs(complete, complete["source"])
                fixture_output = fixture_outputs["deploy/environments/staging/catalogue-family.yaml"]
                changed = yaml.safe_load(fixture_output.read_text(encoding="utf-8"))
                changed["unexpectedWorkload"] = {"namespace": "phorvex-system"}
                fixture_output.write_text(yaml.safe_dump(changed, sort_keys=False))
                with self.assertRaisesRegex(ValueError, "outside its exact staging fixture pin"):
                    RELEASE.verify_exact_pin_diffs(complete, complete["source"])

    def test_both_fixture_destinations_exist_and_are_preflighted_before_any_write(self):
        for name in RELEASE.FIXTURE_NAMES:
            spec = RELEASE.FIXTURE_SPECS[name]
            values = yaml.safe_load((ROOT / spec["deploy"]["valuesFile"]).read_text())
            self.assertIsInstance(RELEASE.nested(values, RELEASE.FIXTURE_SPECS[name]["deploy"]["path"]), str)

        value = RELEASE.complete(prepared_batch(), publication_results(prepared_batch()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = root / "deploy/environments/staging/catalogue-family.yaml"
            overlay.parent.mkdir(parents=True)
            overlay.write_text("phorvex:\n  console:\n    attackCatalog:\n      agentAction:\n        image: \"unchanged\"\n")
            base = root / "deploy/environments/staging/phorvex.yaml"
            base.write_text("phorvex:\n  console:\n    attackCatalog:\n      familyFixtures:\n        images: {}\n")
            with mock.patch.object(RELEASE, "ROOT", root), mock.patch.object(RELEASE, "validate_batch", return_value=value):
                with self.assertRaisesRegex(ValueError, "missing deployment value"):
                    RELEASE.pin_fixtures(value)
            self.assertIn('image: "unchanged"', overlay.read_text())


if __name__ == "__main__":
    unittest.main()
