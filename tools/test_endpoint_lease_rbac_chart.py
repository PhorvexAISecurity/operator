"""Render the default-off endpoint lease authority and its named RBAC grants."""

import os
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
CHART = ROOT / "phorvex/charts/phorvex"
SOURCE = "a" * 64
PROXY = "example.test/proxy@sha256:" + "b" * 64
ENGINE = "example.test/engine@sha256:3534dec6b97c1b6e4042b3cb2987c6cf8c4d4e4167a833320e2f1b7f4135d050"
OPT_IN = (
    "--set", "phorvex.endpointLease.enabled=true",
    "--set", "phorvex.endpointLease.approvedSourceSHA256=" + SOURCE,
    "--set", "phorvex.endpointLease.approvedProxyImage=" + PROXY,
    "--set", "phorvex.endpointLease.approvedEngineImage=" + ENGINE,
)


def render(*args):
    return subprocess.run(
        [HELM, "template", "phorvex", str(CHART), "-n", "phorvex-system", *args],
        capture_output=True, text=True, timeout=30, check=False,
    )


def documents(result):
    if result.returncode:
        raise AssertionError(result.stderr)
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def named(docs, kind, name):
    rows = [item for item in docs if item.get("kind") == kind and
            item["metadata"]["name"] == name]
    if len(rows) != 1:
        raise AssertionError((kind, name, len(rows)))
    return rows[0]


class EndpointLeaseRBACChart(unittest.TestCase):
    def test_default_off_has_no_lease_pins_or_named_grants(self):
        docs = documents(render())
        self.assertFalse(any("endpoint-lease" in item["metadata"]["name"]
                             for item in docs))
        deployment = named(docs, "Deployment", "phorvex-phorvex")
        env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertFalse(any(item["name"].startswith("PHORVEX_ENDPOINT_LEASE_APPROVED_")
                             for item in env))

    def test_enabled_has_only_named_policy_and_journal_write_grants(self):
        docs = documents(render("--set", "phorvex.actuator=native", *OPT_IN))
        policy = named(docs, "Role", "phorvex-phorvex-endpoint-lease")
        journal = named(docs, "Role", "phorvex-phorvex-endpoint-lease-journal")
        self.assertEqual(policy["metadata"]["namespace"], "vllm")
        self.assertEqual(journal["metadata"]["namespace"], "phorvex-system")
        self.assertEqual(policy["rules"][0], {
            "apiGroups": [""], "resources": ["configmaps"],
            "resourceNames": ["phorvex-endpoint-lease-policy"],
            "verbs": ["get", "update"],
        })
        self.assertEqual(journal["rules"], [{
            "apiGroups": [""], "resources": ["configmaps"],
            "resourceNames": ["phorvex-endpoint-lease-journal"],
            "verbs": ["get", "update"],
        }])
        self.assertFalse(any("secrets" in rule["resources"] for rule in policy["rules"] + journal["rules"]))
        self.assertEqual(policy["rules"][1]["resourceNames"], ["guardrail-proxy"])
        self.assertEqual(policy["rules"][2]["resourceNames"], ["vllm"])
        self.assertEqual(policy["rules"][3]["resourceNames"], ["vllm"])
        self.assertEqual(policy["rules"][4]["verbs"], ["get"])
        for suffix, namespace in (("endpoint-lease", "vllm"),
                                  ("endpoint-lease-journal", "phorvex-system")):
            binding = named(docs, "RoleBinding", "phorvex-phorvex-" + suffix)
            self.assertEqual(binding["metadata"]["namespace"], namespace)
            self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount",
                                                    "name": "phorvex-phorvex-manager",
                                                    "namespace": "phorvex-system"}])
        deployment = named(docs, "Deployment", "phorvex-phorvex")
        env = {item["name"]: item.get("value") for item in
               deployment["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_ENDPOINT_LEASE_APPROVED_SOURCE_SHA256"], SOURCE)
        self.assertEqual(env["PHORVEX_ENDPOINT_LEASE_APPROVED_PROXY_IMAGE"], PROXY)
        self.assertEqual(env["PHORVEX_ENDPOINT_LEASE_APPROVED_ENGINE_IMAGE"], ENGINE)

    def test_enabled_rejects_phoenix_or_incomplete_engine_authority(self):
        phoenix = render(*OPT_IN)
        self.assertNotEqual(phoenix.returncode, 0)
        self.assertIn("requires native or hybrid actuator", phoenix.stderr)
        missing = render("--set", "phorvex.actuator=native", *OPT_IN[:-2])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("approvedEngineImage requires", missing.stderr)


if __name__ == "__main__":
    unittest.main()
