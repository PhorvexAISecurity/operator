from __future__ import annotations

import copy
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

from tools import render_catalogue_staging_values


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/charts/phorvex-attacks"
STAGING = ROOT / "deploy/environments/staging/phorvex.yaml"
FAMILY_VALUES = ROOT / "deploy/environments/staging/catalogue-family.yaml"
ATTACKS = ROOT / "deploy/environments/staging/attacks.yaml"
CATALOGUE = ROOT / "phorvex/internal/attackcatalog/catalog.json"
PROFILES = CHART / "files/catalogue-family-profiles.yaml"
HELM = os.environ.get("HELM_BIN") or shutil.which("helm")
SERVICE_CHARTS = {
    "manager": ROOT / "phorvex/charts/phorvex",
    "sensor": ROOT / "deploy/charts/phorvex-sensor",
    "actuator": ROOT / "deploy/charts/phorvex-actuator",
    "attacks": CHART,
    "console": ROOT / "deploy/charts/phorvex-console",
}
DIGEST = "sha256:" + "a" * 64
QUARANTINE_NAMESPACE_UID = "45e2ab1b-5a45-42ab-8afe-87218f2c758d"
IMAGES = {
    "workload": "registry.example.test/phorvex/catalogue-workload@" + DIGEST,
    "phorvex": "registry.example.test/phorvex/phorvex@" + DIGEST,
    "guardrail": "registry.example.test/phorvex/guardrail@" + DIGEST,
    "python": "registry.example.test/library/python@" + DIGEST,
    "kwok": "registry.example.test/kubernetes/kwok@" + DIGEST,
}

DESTINATIONS = {
    "agent-action": (["p6-demo"], ["p6"]),
    "controller-stop": (["p4-demo"], ["p4"]),
    "credential": (["p4-demo"], ["p4"]),
    "datastore": (["p2-demo"], ["p2"]),
    "identity-sa-rotate": (["console-identity-shared"], ["p6"]),
    "image": (["p2-demo", "p3-demo"], ["p2", "p3"]),
    "network-edge": (["p2-demo"], ["p2"]),
    "node-recycle": (["p3-demo"], ["p3"]),
    "pod-rotate": (["p2-demo"], ["p2"]),
    "quarantine": (["p1-demo"], ["p1"]),
    "sensitive-output": (["p6-demo"], ["p6"]),
    "serving-kv": (["p6-demo"], ["p6"]),
    "serving-rate": (["p5-demo"], ["p5"]),
}


def configured_values(family: str) -> dict:
    destinations, lanes = DESTINATIONS[family]
    values = copy.deepcopy(yaml.safe_load(STAGING.read_text(encoding="utf-8")))
    root = values["phorvex"]
    for key in ("policyNamespaces", "actuatorNamespaces"):
        root[key] = list(dict.fromkeys(root[key] + destinations))
    root["console"]["attackNamespaces"] = list(
        dict.fromkeys(root["console"]["attackNamespaces"] + destinations)
    )
    root["trustedDetectors"] = ["phorvex-staging/staging-attacks"] + [
        f"{lane}/{lane}-attacks" for lane in lanes
    ]
    catalog = root["console"]["attackCatalog"]
    catalog.update({
        "enabled": True,
        "authorizationTenant": destinations[0],
        "familyFixtures": {
            "enabled": True,
            "profile": family,
            "namespaceUID": QUARANTINE_NAMESPACE_UID if family == "quarantine" else "",
            "cleanupPolicy": "Delete",
            "images": copy.deepcopy(IMAGES),
        },
        "prometheusEvidence": {"enabled": True},
    })
    if family == "identity-sa-rotate":
        catalog["familyFixtures"]["images"]["workload"] = ""
    if family == "agent-action":
        catalog["agentAction"] = {
            "enabled": True,
            "namespace": "p6-demo",
            "image": "registry.example.test/phorvex/agentsim@" + DIGEST,
        }
        root["agentActionDeny"] = {"enabled": True, "namespaces": ["p6-demo"]}
    if family == "sensitive-output":
        root["outputPolicy"] = {
            "enabled": True,
            "targetNamespace": "p6-demo",
            "configMapName": "",
            "configMapNames": [
                "phorvex-output-policy-gfx-t0069",
                "phorvex-output-policy-gfx-t0069-001",
                "phorvex-output-policy-gfx-t0069-002",
            ],
        }
    if family == "serving-kv":
        root.setdefault("servingSecurity", {})["mode"] = "legacy-plaintext"
    if family == "serving-rate":
        root["trustedDetectors"].append("p5-demo/rate-detector")
    return values


def objects(rendered: str) -> list[dict]:
    return [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]


@unittest.skipUnless(HELM, "helm is not installed")
class CatalogueFixtureRenderTests(unittest.TestCase):
    @classmethod
    def render(cls, family: str, values: dict | None = None, check: bool = True):
        values = values or configured_values(family)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
            yaml.safe_dump(values, override, sort_keys=False)
            override.flush()
            return subprocess.run(
                [HELM, "template", "staging", str(CHART), "--namespace", "phorvex-staging",
                 "-f", str(ATTACKS), "-f", override.name],
                check=check, text=True, capture_output=True,
            )

    def test_every_family_fully_configured_render_is_bounded(self):
        for family, (destinations, lanes) in DESTINATIONS.items():
            with self.subTest(family=family):
                docs = objects(self.render(family).stdout)
                selected = next(
                    item for item in docs
                    if item.get("kind") == "ConfigMap"
                    and item.get("metadata", {}).get("name") == "staging-catalogue-family-profile"
                )
                self.assertEqual(selected["data"]["selected-family"], family)
                fixture_docs = [item for item in docs if item.get("metadata", {}).get("labels", {}).get(
                    "phorvex.ai/catalogue-fixture-profile") == family]
                self.assertTrue(fixture_docs)
                for item in fixture_docs:
                    self.assertEqual(item["metadata"]["labels"].get("phorvex.ai/cleanup-policy"), "Delete")
                rendered_namespaces = {
                    item["metadata"]["name"] for item in docs if item.get("kind") == "Namespace"
                }
                self.assertTrue(set(lanes).issubset(rendered_namespaces))
                self.assertTrue(set(destinations).difference({"console-identity-shared"}).issubset(rendered_namespaces))
                bounded_namespaces = set(lanes) | set(destinations).difference({"console-identity-shared"})
                for kind in ("ResourceQuota", "LimitRange"):
                    self.assertEqual(
                        {item["metadata"]["namespace"] for item in docs if item.get("kind") == kind
                         and item.get("metadata", {}).get("labels", {}).get(
                             "phorvex.ai/catalogue-fixture-profile") == family},
                        bounded_namespaces,
                    )
                for role in (item for item in docs if item.get("kind") in {"Role", "ClusterRole"}
                             and item.get("metadata", {}).get("labels", {}).get(
                                 "phorvex.ai/catalogue-fixture-profile") == family):
                    for rule in role["rules"]:
                        self.assertNotIn("*", rule.get("apiGroups", []), role["metadata"]["name"])
                        self.assertNotIn("*", rule.get("resources", []), role["metadata"]["name"])
                        self.assertNotIn("*", rule.get("verbs", []), role["metadata"]["name"])
                policies = [item for item in docs if item.get("kind") == "PhorvexPolicy"
                            and item.get("metadata", {}).get("namespace") in destinations]
                expected_policy_namespaces = set() if family == "identity-sa-rotate" else set(destinations)
                self.assertEqual({item["metadata"]["namespace"] for item in policies}, expected_policy_namespaces)
                for item in docs:
                    pod_spec = None
                    if item.get("kind") in {"Deployment", "Job"}:
                        pod_spec = item["spec"]["template"]["spec"]
                    elif item.get("kind") == "Pod":
                        pod_spec = item["spec"]
                    if not pod_spec or item.get("metadata", {}).get("labels", {}).get(
                        "phorvex.ai/catalogue-fixture-profile") != family:
                        continue
                    for container in pod_spec.get("containers", []):
                        self.assertIn("@sha256:", container["image"])
                        self.assertIn("requests", container["resources"])
                        self.assertIn("limits", container["resources"])

    def test_every_family_overlay_renders_for_all_affected_services(self):
        for family in DESTINATIONS:
            values = configured_values(family)
            with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
                yaml.safe_dump(values, override, sort_keys=False)
                override.flush()
                for service, chart in SERVICE_CHARTS.items():
                    with self.subTest(family=family, service=service):
                        subprocess.run(
                            [HELM, "template", "staging", str(chart), "--namespace", "phorvex-staging",
                             "--skip-crds", "--api-versions", "monitoring.coreos.com/v1/PodMonitor",
                             "--api-versions", "monitoring.coreos.com/v1/PrometheusRule", "-f", str(STAGING),
                             "-f", str(ROOT / f"deploy/environments/staging/{service}.yaml"),
                             "-f", override.name],
                            check=True, text=True, capture_output=True,
                        )

    def test_quarantine_requires_api_assigned_namespace_uid_pin(self):
        values = configured_values("quarantine")
        values["phorvex"]["console"]["attackCatalog"]["familyFixtures"]["namespaceUID"] = ""
        result = self.render("quarantine", values, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("namespaceUID", result.stderr)

    def test_family_specific_exact_contracts(self):
        identity = objects(self.render("identity-sa-rotate").stdout)
        self.assertFalse([
            item for item in identity
            if item.get("metadata", {}).get("namespace") == "console-identity-shared"
            and item.get("kind") in {"ServiceAccount", "Deployment", "PhorvexPolicy"}
        ], "identity profile must not claim the externally owned shared fixture")
        quarantine_values = configured_values("quarantine")
        quarantine = objects(self.render("quarantine", quarantine_values).stdout)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
            yaml.safe_dump(quarantine_values, override, sort_keys=False)
            override.flush()
            quarantine_rbac = objects(subprocess.run(
                [HELM, "template", "staging", str(SERVICE_CHARTS["console"]),
                 "--namespace", "phorvex-staging", "-f", str(STAGING),
                 "-f", str(ROOT / "deploy/environments/staging/console.yaml"),
                 "-f", override.name],
                check=True, text=True, capture_output=True,
            ).stdout)
        q_policy = next(item for item in quarantine if item.get("kind") == "PhorvexPolicy"
                        and item["metadata"]["namespace"] == "p1-demo")
        self.assertEqual(q_policy["spec"]["actions"]["enabled"], ["rotate", "quarantine"])
        self.assertEqual(q_policy["spec"]["selector"]["matchLabels"], {"app.kubernetes.io/name": "demo-api"})
        attacks = next(
            item for item in quarantine if item.get("kind") == "Deployment"
            and any(
                entry.get("name") == "PHORVEX_CONSOLE_ATTACK_CATALOG_OPERATOR_NAMESPACE"
                for container in item["spec"]["template"]["spec"].get("containers", [])
                for entry in container.get("env", [])
            )
        )
        container = attacks["spec"]["template"]["spec"]["containers"][0]
        env = {entry["name"]: entry.get("value") for entry in container.get("env", [])}
        self.assertEqual(env["PHORVEX_CONSOLE_ATTACK_CATALOG_OPERATOR_NAMESPACE"], "phorvex-staging")
        operator_roles = {
            item["metadata"]["name"]: item for item in quarantine_rbac
            if item.get("kind") == "Role" and item["metadata"].get("namespace") == "phorvex-staging"
            and item["metadata"]["name"].endswith(("-attacks-ledger-read", "-attacks-cleanup-ledger"))
        }
        self.assertEqual(len(operator_roles), 2)
        verbs = {
            name.rsplit("-attacks-", 1)[1]: role["rules"][0]["verbs"]
            for name, role in operator_roles.items()
        }
        self.assertEqual(verbs, {"ledger-read": ["get"], "cleanup-ledger": ["update"]})
        expected_ledgers = {
            "phorvex-shared-capacity",
            "phorvex-quarantine-capacity-" + hashlib.sha256(
                QUARANTINE_NAMESPACE_UID.encode("ascii")
            ).hexdigest()[:40],
        }
        for role in operator_roles.values():
            self.assertEqual(set(role["rules"][0]["resourceNames"]), expected_ledgers)
        lane_cleanup = next(
            item for item in quarantine_rbac if item.get("kind") == "Role"
            and item["metadata"].get("namespace") == "p1-demo"
            and item["metadata"]["name"].endswith("-attacks-cleanup")
        )
        self.assertFalse(any("configmaps" in rule.get("resources", []) for rule in lane_cleanup["rules"]))
        controller = objects(self.render("controller-stop").stdout)
        c_policy = next(item for item in controller if item.get("kind") == "PhorvexPolicy"
                        and item["metadata"]["namespace"] == "p4-demo")
        self.assertEqual(c_policy["spec"]["actions"]["enabled"], ["rotate"])
        self.assertEqual(c_policy["spec"]["slo"]["costCeiling"], "1.7")
        self.assertEqual(c_policy["spec"]["slo"]["minAvailableReplicas"], 2)
        self.assertTrue(c_policy["spec"]["triggers"]["reactiveOnly"])
        pod_rotate = objects(self.render("pod-rotate").stdout)
        pod_rotate_policy = next(
            item for item in pod_rotate if item.get("kind") == "PhorvexPolicy"
            and item["metadata"]["namespace"] == "p2-demo"
        )
        # A missing-load rotate has an audited CHi of 1.60. Keep G9 active
        # while allowing that reviewed envelope with a bounded 0.10 margin.
        self.assertEqual(pod_rotate_policy["spec"]["slo"]["costCeiling"], "1.7")
        self.assertEqual(pod_rotate_policy["spec"]["slo"]["minAvailableReplicas"], 2)
        self.assertTrue(pod_rotate_policy["spec"]["triggers"]["reactiveOnly"])
        self.assertEqual(q_policy["spec"]["slo"]["costCeiling"], "1.2")
        network_edge = objects(self.render("network-edge").stdout)
        edge_role = [item for item in network_edge if item.get("kind") == "Role"
                        and item["metadata"]["name"].endswith("-network-edge-fixture")]
        self.assertEqual(len(edge_role), 1)
        self.assertEqual(edge_role[0]["metadata"]["namespace"], "p2-demo")
        self.assertEqual(edge_role[0]["rules"], [
            {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["get", "delete"]},
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "update"]},
        ])
        self.assertFalse([item for item in pod_rotate if item.get("kind") == "Role"
                          and item["metadata"]["name"].endswith("-network-edge-fixture")])
        datastore = objects(self.render("datastore").stdout)
        trusted = next(item for item in datastore if item.get("kind") == "ConfigMap"
                       and item["metadata"]["name"] == "datastore-trusted-snapshot")
        self.assertEqual(set(trusted["data"]), {"store.json", "store.sha256"})
        self.assertTrue(any(item.get("kind") == "Service" and item["metadata"]["name"] == "rag-store"
                            for item in datastore))
        sensitive = objects(self.render("sensitive-output").stdout)
        self.assertEqual(
            {item["metadata"]["name"] for item in sensitive if item.get("kind") == "Pod"
             and item["metadata"].get("namespace") == "p6-demo"},
            {"gfx-t0069", "gfx-t0069-001", "gfx-t0069-002"},
        )
        kv = objects(self.render("serving-kv").stdout)
        serving = next(item for item in kv if item.get("kind") == "Deployment"
                       and item["metadata"]["name"] == "kv-serving")
        self.assertEqual(serving["spec"]["replicas"], 2)
        self.assertEqual(serving["spec"]["template"]["metadata"]["annotations"]["phorvex.ai/serving-port"], "8000")
        kv_policy = next(item for item in kv if item.get("kind") == "PhorvexPolicy"
                         and item["metadata"]["name"] == "kv-serving-defense")
        self.assertEqual(kv_policy["spec"]["actions"]["enabled"], ["rotate", "kv-reset"])
        node = objects(self.render("node-recycle").stdout)
        self.assertEqual({item["metadata"]["name"] for item in node if item.get("kind") == "Node"},
                         {"p3-node-a", "p3-node-b"})
        rate = objects(self.render("serving-rate").stdout)
        self.assertTrue({"phorvex-serving-rate-budget", "phorvex-serving-rate-status"}.issubset(
            {item["metadata"]["name"] for item in rate if item.get("kind") == "ConfigMap"}
        ))
        services = {item["metadata"]["name"]: item for item in rate if item.get("kind") == "Service"
                    and item["metadata"].get("namespace") == "p5-demo"}
        self.assertEqual(services["rate-target"]["spec"]["selector"], {"app": "rate-admission"})
        self.assertEqual(services["rate-target-backend"]["spec"]["selector"], {"app": "rate-target"})

    @classmethod
    def render_chart(cls, chart: Path, family: str, values: dict | None = None, check: bool = True):
        values = values or configured_values(family)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
            yaml.safe_dump(values, override, sort_keys=False)
            override.flush()
            return subprocess.run(
                [HELM, "template", "staging", str(chart), "--namespace", "phorvex-staging",
                 "-f", str(ATTACKS), "-f", override.name],
                check=check, text=True, capture_output=True,
            )

    def test_sensitive_output_fixture_source_is_populated_and_wired(self):
        docs = objects(self.render("sensitive-output").stdout)
        source = next(item for item in docs if item.get("kind") == "ConfigMap"
                      and item["metadata"]["name"] == "sensitive-output-fixture-source")
        self.assertEqual(set(source["data"]), {"proxy.py", "support.py", "bootstrap.py"})
        for name, body in source["data"].items():
            self.assertTrue(body.strip(), f"{name} rendered empty")
        # The proxy must carry the exact two-sided oracle surface, not a stub.
        self.assertIn("phorvex.support-case-response.v1", source["data"]["proxy.py"])
        self.assertIn("[REDACTED-BY-OUTPUT-POLICY]", source["data"]["proxy.py"])
        self.assertIn("internalAuditMarker", source["data"]["proxy.py"])
        self.assertIn("activation.json", source["data"]["bootstrap.py"])
        self.assertIn("ownerReferences", source["data"]["bootstrap.py"])

        pods = {item["metadata"]["name"]: item for item in docs if item.get("kind") == "Pod"
                and item["metadata"].get("namespace") == "p6-demo"}
        self.assertEqual(set(pods), {"gfx-t0069", "gfx-t0069-001", "gfx-t0069-002"})
        for name, pod in pods.items():
            self.assertEqual(pod["metadata"]["labels"]["app"], "guardrail-fixture")
            volumes = {volume["name"]: volume for volume in pod["spec"]["volumes"]}
            # Optional policy volume lets the Pod start before bootstrap provisions
            # the ConfigMap; readiness then gates on the mounted activation.
            self.assertTrue(volumes["policy"]["configMap"]["optional"])
            self.assertEqual(volumes["policy"]["configMap"]["name"], "phorvex-output-policy-" + name)
            proxy = next(c for c in pod["spec"]["containers"] if c["name"] == "guardrail-proxy")
            self.assertEqual(proxy["command"], ["python3", "-I", "/fixture/proxy.py"])
            self.assertEqual(proxy["readinessProbe"]["httpGet"]["path"], "/healthz")

        job = next(item for item in docs if item.get("kind") == "Job"
                   and item["metadata"]["name"] == "sensitive-output-bootstrap")
        env = {entry["name"]: entry.get("value")
               for entry in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["POD_NAMESPACE"], "p6-demo")
        self.assertEqual(env["FIXTURE_PODS"], "gfx-t0069,gfx-t0069-001,gfx-t0069-002")
        for key, filename in (("PROXY_SOURCE_SHA256", "proxy.py"), ("SUPPORT_SOURCE_SHA256", "support.py")):
            digest = env[key]
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            expected = hashlib.sha256(
                (CHART / "files/sensitive-output" / filename).read_bytes()).hexdigest()
            self.assertEqual(digest, expected, f"{key} must digest the rendered {filename}")

    def test_sensitive_output_empty_or_missing_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory) / "phorvex-attacks"
            shutil.copytree(CHART, chart)
            # Control: the faithful copy still renders.
            self.assertEqual(self.render_chart(chart, "sensitive-output").returncode, 0)
            sources = chart / "files/sensitive-output"
            mutations = [
                ("blank proxy.py", lambda: (sources / "proxy.py").write_text("")),
                ("blank support.py", lambda: (sources / "support.py").write_text("")),
                ("blank bootstrap.py", lambda: (sources / "bootstrap.py").write_text("")),
                ("missing proxy.py", lambda: (sources / "proxy.py").unlink()),
            ]
            originals = {path.name: path.read_text() for path in sources.glob("*.py")}
            for label, mutate in mutations:
                with self.subTest(mutation=label):
                    mutate()
                    result = self.render_chart(chart, "sensitive-output", check=False)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("sensitive-output fixture requires a non-empty", result.stderr)
                    for name, body in originals.items():
                        (sources / name).write_text(body)

    def test_agent_action_is_immutable_scoped_and_has_no_command_surface(self):
        docs = objects(self.render("agent-action").stdout)
        deployment = next(item for item in docs if item.get("kind") == "Deployment"
                          and item["metadata"]["name"] == "agent-sim")
        pod = deployment["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(deployment["metadata"]["namespace"], "p6-demo")
        self.assertNotIn("nodeName", pod)
        self.assertNotIn("nodeSelector", pod)
        self.assertNotIn("affinity", pod)
        self.assertNotIn("command", container)
        self.assertNotIn("args", container)
        self.assertRegex(container["image"], r"@sha256:[0-9a-f]{64}$")
        role = next(item for item in docs if item.get("kind") == "Role"
                    and item["metadata"]["name"] == "staging-attacks-agent-action-catalog")
        resources = {resource for rule in role["rules"] for resource in rule["resources"]}
        self.assertNotIn("pods/exec", resources)
        self.assertNotIn("secrets", resources)

    def test_partial_or_unscoped_states_fail_closed(self):
        cases = []
        missing_image = configured_values("quarantine")
        missing_image["phorvex"]["console"]["attackCatalog"]["familyFixtures"]["images"]["workload"] = ""
        cases.append(missing_image)
        mutable_agent = configured_values("agent-action")
        mutable_agent["phorvex"]["console"]["attackCatalog"]["agentAction"]["image"] = "example.test/agentsim:latest"
        cases.append(mutable_agent)
        unscoped = configured_values("datastore")
        unscoped["phorvex"]["actuatorNamespaces"].remove("p2-demo")
        cases.append(unscoped)
        wrong_output = configured_values("sensitive-output")
        wrong_output["phorvex"]["outputPolicy"]["configMapNames"].pop()
        cases.append(wrong_output)
        for values in cases:
            with self.subTest(profile=values["phorvex"]["console"]["attackCatalog"]["familyFixtures"]["profile"]):
                result = self.render("quarantine", values, check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)


class CatalogueFixtureSourceTests(unittest.TestCase):
    def test_overlay_generator_emits_no_yaml_aliases(self):
        args = argparse.Namespace(
            profile="agent-action", workload_image="", phorvex_image="",
            agent_image="registry.example.test/phorvex/agentsim@" + DIGEST,
            python_image=IMAGES["python"], kwok_image=IMAGES["kwok"],
        )
        rendered = yaml.safe_dump(
            render_catalogue_staging_values.overlay(args), sort_keys=False, width=120,
        )
        self.assertFalse(any(
            isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None)
            for event in yaml.parse(rendered)
        ))

    def test_generated_profiles_cover_exact_catalogue_once(self):
        catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
        profiles = yaml.safe_load(PROFILES.read_text(encoding="utf-8"))
        self.assertEqual(catalogue["count"], 192)
        self.assertEqual(len(profiles["profiles"]), 13)
        source = {(item["family"], item["id"], item["expectedAction"]) for item in catalogue["entries"]}
        packaged = {
            (profile["family"], identifier, profile["expectedAction"])
            for profile in profiles["profiles"] for identifier in profile["ids"]
        }
        self.assertEqual(packaged, source)

    def test_staging_base_or_exact_reviewed_window_is_fail_closed(self):
        root = yaml.safe_load(STAGING.read_text(encoding="utf-8"))["phorvex"]
        catalog = root["console"]["attackCatalog"]
        self.assertFalse(catalog["enabled"])
        self.assertFalse(catalog["familyFixtures"]["enabled"])
        self.assertFalse(catalog["agentAction"]["enabled"])
        self.assertEqual(root["agentActionDeny"]["namespaces"], [])
        self.assertFalse(root["outputPolicy"]["enabled"])
        for values in (root["policyNamespaces"], root["actuatorNamespaces"], root["console"]["attackNamespaces"]):
            self.assertFalse(set(values).intersection({f"p{i}" for i in range(1, 7)}))
            self.assertFalse(set(values).intersection({f"p{i}-demo" for i in range(1, 7)}))
        family = yaml.safe_load(FAMILY_VALUES.read_text(encoding="utf-8"))["phorvex"]
        family_catalog = family["console"]["attackCatalog"]
        if not family_catalog["enabled"]:
            self.assertFalse(family["agentActionDeny"]["enabled"])
            self.assertFalse(family["outputPolicy"]["enabled"])
            self.assertFalse(family_catalog["familyFixtures"]["enabled"])
            return
        fixture = family_catalog["familyFixtures"]
        profile = fixture["profile"]
        self.assertIn(profile, DESTINATIONS)
        args = argparse.Namespace(
            profile=profile,
            namespace_uid=fixture.get("namespaceUID", ""),
            workload_image=fixture["images"]["workload"],
            phorvex_image=fixture["images"]["phorvex"],
            agent_image=family_catalog["agentAction"]["image"],
            python_image=fixture["images"]["python"],
            kwok_image=fixture["images"]["kwok"],
        )
        self.assertEqual(
            family,
            render_catalogue_staging_values.overlay(args)["phorvex"],
        )

    def test_overlay_generator_packages_every_profile_and_exact_grant_scope(self):
        for family, (destinations, _) in DESTINATIONS.items():
            with self.subTest(family=family):
                args = argparse.Namespace(
                    profile=family,
                    namespace_uid=QUARANTINE_NAMESPACE_UID if family == "quarantine" else "",
                    workload_image="" if family == "identity-sa-rotate" else IMAGES["workload"],
                    phorvex_image=IMAGES["phorvex"],
                    agent_image="registry.example.test/phorvex/agentsim@" + DIGEST,
                    python_image=IMAGES["python"],
                    kwok_image=IMAGES["kwok"],
                )
                root = render_catalogue_staging_values.overlay(args)["phorvex"]
                self.assertTrue(set(destinations).issubset(root["policyNamespaces"]))
                self.assertEqual(root["policyNamespaces"], root["actuatorNamespaces"])
                self.assertEqual(root["policyNamespaces"], root["console"]["attackNamespaces"])
                fixture = root["console"]["attackCatalog"]["familyFixtures"]
                self.assertEqual(fixture["profile"], family)
                self.assertEqual(fixture["cleanupPolicy"], "Delete")
                grants = json.loads(root["console"]["auth"]["grants"]["data"])
                self.assertTrue(all(subject["tenants"] == [destinations[0]] for subject in grants["subjects"]))

    def test_chart_schema_and_build_inputs_are_immutable(self):
        schema = json.loads((CHART / "values.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft-07/schema#")
        for dockerfile in (ROOT / "farm-fixtures/agentsim/Dockerfile",
                           ROOT / "farm-fixtures/catalogue-workload/Dockerfile"):
            from_lines = [line for line in dockerfile.read_text().splitlines() if line.startswith("FROM ")]
            self.assertTrue(from_lines)
            self.assertTrue(all("@sha256:" in line for line in from_lines))


if __name__ == "__main__":
    unittest.main()
