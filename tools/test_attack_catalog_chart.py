from pathlib import Path
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "deploy/charts/phorvex-common"
CHARTS = [
    ROOT / "deploy/charts/phorvex-actuator",
    ROOT / "deploy/charts/phorvex-attacks",
    ROOT / "deploy/charts/phorvex-brain",
    ROOT / "deploy/charts/phorvex-console",
    ROOT / "deploy/charts/phorvex-sensor",
    ROOT / "phorvex/charts/phorvex",
]
HELM = os.environ.get("HELM_BIN") or shutil.which("helm")


class AttackCatalogChartTests(unittest.TestCase):
    def test_defaults_are_off_and_staging_uses_the_fixed_fixture(self):
        defaults = [
            ROOT / "phorvex/charts/phorvex/values.yaml",
            ROOT / "deploy/charts/phorvex-console/values.yaml",
            ROOT / "deploy/charts/phorvex-attacks/values.yaml",
        ]
        for path in defaults:
            with self.subTest(path=path):
                values = yaml.safe_load(path.read_text())["phorvex"]
                catalog = values["console"]["attackCatalog"]
                self.assertFalse(catalog["enabled"])
                self.assertEqual(catalog["authorizationTenant"], "")
                self.assertFalse(catalog["familyFixtures"]["enabled"])
                self.assertEqual(catalog["familyFixtures"]["profile"], "")
                self.assertFalse(catalog["agentAction"]["enabled"])
                self.assertEqual(catalog["agentAction"]["namespace"], "p6-demo")
                self.assertFalse(catalog["prometheusEvidence"]["enabled"])

        staging = yaml.safe_load((ROOT / "deploy/environments/staging/phorvex.yaml").read_text())["phorvex"]
        catalog = staging["console"]["attackCatalog"]
        self.assertFalse(catalog["enabled"])
        self.assertFalse(catalog["familyFixtures"]["enabled"])
        self.assertFalse(catalog["agentAction"]["enabled"])
        self.assertFalse(catalog["prometheusEvidence"]["enabled"])
        self.assertTrue(staging["identityRotate"]["enabled"])
        self.assertEqual(staging["identityRotate"]["targetNamespace"], "console-identity-shared")
        self.assertEqual(staging["identityRotate"]["serviceAccountName"], "console-id-fixture")
        grants = yaml.safe_load(staging["console"]["auth"]["grants"]["data"])
        for subject in grants["subjects"]:
            self.assertEqual(subject["tenants"], ["phorvex-staging-demo"])

    def test_server_path_mount_and_permissions_are_fixed_in_source(self):
        deployment = (COMMON / "templates/_console.tpl").read_text()
        for exact in (
            "PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_ENABLED",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_IMAGE",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_MANAGER_PRINCIPAL",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_SENSOR_PRINCIPAL",
            "PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTUATOR_PRINCIPAL",
            "PHORVEX_CONSOLE_RUN_PROMETHEUS_EVIDENCE_ENABLED",
            "PHORVEX_CONSOLE_RUN_PROMETHEUS_ENVIRONMENT",
            "/etc/phorvex-attack-catalog/identity-profile.json",
            "attack-catalog-identity-fixture",
        ):
            self.assertIn(exact, deployment)
        rbac = (COMMON / "templates/_console-rbac.tpl").read_text()
        for exact in ("tokenreviews", "serviceaccounts/token", "configmaps", "attacks-identity-catalog",
                      "selfsubjectaccessreviews", "subjectaccessreviews",
                      'not (and $agentActionCatalog (eq . "p6-demo"))'):
            self.assertIn(exact, rbac)
        self.assertNotIn('resources: ["secrets"]\n  verbs: ["get"]', rbac)

        config_map = (ROOT / "deploy/charts/phorvex-attacks/templates/attack-catalog-identity-configmap.yaml").read_text()
        self.assertIn('dig "console" "attackCatalog" "enabled" false', config_map)
        self.assertIn("identityRotate.profile", config_map)

        agent_fixture = (ROOT / "deploy/charts/phorvex-attacks/templates/attack-catalog-agent-action-fixture.yaml").read_text()
        for exact in ("@sha256:[0-9a-f]{64}", "replicas: 2", "cpu: 10m", "memory: 32Mi",
                      'resourceNames: ["agent-deny-guard"]', 'verbs: ["get", "update"]',
                      "automountServiceAccountToken: false", "readOnlyRootFilesystem: true"):
            self.assertIn(exact, agent_fixture)
        self.assertNotIn("nodeName:", agent_fixture)
        self.assertNotIn("nodeSelector:", agent_fixture)
        self.assertNotIn("affinity:", agent_fixture)
        self.assertNotIn('resources: ["pods/exec"]', agent_fixture)

        dockerfile = (ROOT / "farm-fixtures/agentsim/Dockerfile").read_text()
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        self.assertEqual(len(from_lines), 2)
        self.assertTrue(all("@sha256:" in line for line in from_lines))

    @staticmethod
    def _agent_values(image):
        return {
            "phorvex": {
                "agentActionDeny": {"enabled": True, "namespaces": ["p6-demo"]},
                "policyNamespaces": ["phorvex-staging-demo", "console-identity-shared", "p6-demo"],
                "actuatorNamespaces": ["phorvex-staging-demo", "console-identity-shared", "p6-demo"],
                "trustedDetectors": ["p6/p6-attacks"],
                "console": {
                    "attackNamespaces": ["phorvex-staging-demo", "console-identity-shared", "p6-demo"],
                    "attackCatalog": {
                        "enabled": True,
                        "authorizationTenant": "phorvex-staging-demo",
                        "familyFixtures": {
                            "enabled": True,
                            "profile": "agent-action",
                            "cleanupPolicy": "Delete",
                        },
                        "agentAction": {"enabled": True, "namespace": "p6-demo", "image": image},
                        "prometheusEvidence": {"enabled": False},
                    },
                },
            },
        }

    def _render_agent(self, values, check=True):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
            yaml.safe_dump(values, override)
            override.flush()
            return subprocess.run([
                HELM, "template", "p6", str(ROOT / "deploy/charts/phorvex-attacks"),
                "--namespace", "p6",
                "-f", str(ROOT / "deploy/environments/staging/phorvex.yaml"),
                "-f", str(ROOT / "deploy/environments/staging/attacks.yaml"),
                "-f", override.name,
            ], check=check, text=True, capture_output=True)

    def _render_agent_console_rbac(self, values):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as override:
            yaml.safe_dump(values, override)
            override.flush()
            return subprocess.run([
                HELM, "template", "p6", str(ROOT / "deploy/charts/phorvex-console"),
                "--namespace", "p6",
                "-f", str(ROOT / "deploy/environments/staging/phorvex.yaml"),
                "-f", str(ROOT / "deploy/environments/staging/console.yaml"),
                "-f", override.name,
            ], check=True, text=True, capture_output=True).stdout

    @unittest.skipUnless(HELM, "helm is not installed")
    def test_agent_fixture_is_digest_pinned_unpinned_to_nodes_and_least_privilege(self):
        image = "registry.example.test/phorvex/agent-sim@sha256:" + "a" * 64
        rendered = self._render_agent(self._agent_values(image)).stdout
        docs = [doc for doc in yaml.safe_load_all(rendered) if doc]
        fixture = [doc for doc in docs if doc.get("metadata", {}).get("namespace") == "p6-demo"]
        namespace = next(doc for doc in docs if doc["kind"] == "Namespace" and doc["metadata"]["name"] == "p6-demo")
        self.assertEqual(namespace["metadata"]["labels"]["phorvex.ai/attack-catalog-agent-action"], "true")
        deployment = next(doc for doc in fixture if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "agent-sim")
        pod = deployment["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(deployment["spec"]["replicas"], 2)
        self.assertEqual(container["image"], image)
        self.assertNotIn("nodeName", pod)
        self.assertNotIn("nodeSelector", pod)
        self.assertNotIn("affinity", pod)
        self.assertNotIn("command", container)
        self.assertNotIn("args", container)
        self.assertEqual(container["resources"], {
            "requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"cpu": "100m", "memory": "32Mi"},
        })
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        role = next(doc for doc in fixture if doc["kind"] == "Role" and doc["metadata"]["name"] == "p6-attacks-agent-action-catalog")
        flattened = {(tuple(rule["apiGroups"]), tuple(rule["resources"]), tuple(rule["verbs"]),
                      tuple(rule.get("resourceNames", []))) for rule in role["rules"]}
        self.assertIn((("",), ("configmaps",), ("get", "update"), ("agent-deny-guard",)), flattened)
        self.assertNotIn("create", {verb for rule in role["rules"] for verb in rule["verbs"]})
        self.assertNotIn("delete", {verb for rule in role["rules"] for verb in rule["verbs"]})
        self.assertNotIn("pods/exec", {resource for rule in role["rules"] for resource in rule["resources"]})
        self.assertNotIn("secrets", {resource for rule in role["rules"] for resource in rule["resources"]})
        self.assertIn("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_ENABLED", rendered)
        self.assertIn("system:serviceaccount:p6:p6-phorvex-manager", rendered)
        self.assertNotIn("image: registry.example.test/phorvex/agent-sim:latest", rendered)

        rbac_docs = [doc for doc in yaml.safe_load_all(self._render_agent_console_rbac(self._agent_values(image))) if doc]
        p6_roles = [doc for doc in rbac_docs if doc["kind"] == "Role" and doc["metadata"].get("namespace") == "p6-demo"]
        self.assertNotIn("p6-phorvex-attacks-target", {doc["metadata"]["name"] for doc in p6_roles})
        attacks_cluster_role = next(doc for doc in rbac_docs if doc["kind"] == "ClusterRole"
                                    and doc["metadata"]["name"] == "p6-phorvex-attacks-role")
        authz = next(rule for rule in attacks_cluster_role["rules"] if rule["apiGroups"] == ["authorization.k8s.io"])
        self.assertEqual(authz["resources"], ["selfsubjectaccessreviews", "subjectaccessreviews"])
        self.assertEqual(authz["verbs"], ["create"])

    @unittest.skipUnless(HELM, "helm is not installed")
    def test_agent_fixture_rejects_mutable_or_unscoped_packaging(self):
        valid = "registry.example.test/phorvex/agent-sim@sha256:" + "a" * 64
        cases = {
            "mutable tag": self._agent_values("registry.example.test/phorvex/agent-sim:latest"),
            "wrong namespace": self._agent_values(valid),
            "missing action": self._agent_values(valid),
            "general target role": self._agent_values(valid),
        }
        cases["wrong namespace"]["phorvex"]["console"]["attackCatalog"]["agentAction"]["namespace"] = "other"
        cases["missing action"]["phorvex"]["agentActionDeny"]["enabled"] = False
        cases["general target role"]["phorvex"]["console"]["attackNamespaces"].remove("p6-demo")
        for name, values in cases.items():
            with self.subTest(name=name):
                result = self._render_agent(values, check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_every_dependent_chart_vendors_current_common_library(self):
        source_chart = yaml.safe_load((COMMON / "Chart.yaml").read_text())
        expected = {
            f"phorvex-common/{path.relative_to(COMMON)}": path.read_bytes()
            for path in COMMON.rglob("*")
            if path.is_file() and path.name != "Chart.yaml"
        }
        for chart in CHARTS:
            with self.subTest(chart=chart):
                dependency = next(
                    dep for dep in yaml.safe_load((chart / "Chart.yaml").read_text())["dependencies"]
                    if dep["name"] == "phorvex-common"
                )
                self.assertEqual(dependency["version"], source_chart["version"])
                package = chart / "charts" / f"phorvex-common-{source_chart['version']}.tgz"
                with tarfile.open(package) as archive:
                    actual = {
                        member.name: archive.extractfile(member).read()
                        for member in archive.getmembers()
                        if member.isfile()
                    }
                self.assertEqual(yaml.safe_load(actual.pop("phorvex-common/Chart.yaml")), source_chart)
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
