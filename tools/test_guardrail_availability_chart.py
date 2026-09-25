"""Offline rendered authority checks for the guardrail recovery profile."""

import os
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
CHART = ROOT / "phorvex/charts/phorvex"
BASE = [HELM, "template", "phorvex", str(CHART), "-n", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example"]
PREFIX = "phorvex.console.guardrailAvailability."
VALID = ["--set", "phorvex.console.catalogueV1.enabled=true",
         "--set", "phorvex.console.catalogueV1.scopedToken.existingSecret=reviewed-token",
         "--set", "phorvex.console.auditTransport.serverDNSName=phorvex-phorvex-audit-source.phorvex-system.svc",
         "--set", PREFIX + "enabled=true",
         "--set", PREFIX + "configMapName=reviewed-availability",
         "--set-string", PREFIX + "profileSHA256=" + "a" * 64,
         "--set", PREFIX + "guardrailJournalName=reviewed-journal"]


def render(*args):
    return subprocess.run([*BASE, *args], capture_output=True, text=True, timeout=30)


def objects(result):
    assert result.returncode == 0, result.stderr
    return [x for x in yaml.safe_load_all(result.stdout) if x]


def named(docs, kind, name, namespace=None):
    found = [x for x in docs if x.get("kind") == kind and x["metadata"]["name"] == name and
             (namespace is None or x["metadata"].get("namespace") == namespace)]
    assert len(found) == 1, (kind, name, namespace, len(found))
    return found[0]


class GuardrailAvailabilityChart(unittest.TestCase):
    def test_default_off_has_no_mount_hash_or_authority(self):
        docs = objects(render())
        dep = named(docs, "Deployment", "phorvex-phorvex-console", "phorvex-system")
        spec = dep["spec"]["template"]["spec"]
        container = next(x for x in spec["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256", env)
        self.assertNotIn("PHORVEX_CONSOLE_POD_NAME", env)
        self.assertNotIn("PHORVEX_CONSOLE_POD_UID", env)
        self.assertNotIn("guardrail-availability-reviewed-profile", {x["name"] for x in spec["volumes"]})
        self.assertFalse(any("guardrail-availability" in x["metadata"]["name"] for x in docs))

    def test_enabled_exact_mount_hash_and_read_grants(self):
        docs = objects(render(*VALID))
        dep = named(docs, "Deployment", "phorvex-phorvex-console", "phorvex-system")
        spec = dep["spec"]["template"]["spec"]
        container = next(x for x in spec["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256"], "a" * 64)
        for name, path in (("PHORVEX_CONSOLE_POD_NAME", "metadata.name"),
                           ("PHORVEX_CONSOLE_POD_UID", "metadata.uid")):
            self.assertEqual(next(x for x in container["env"] if x["name"] == name),
                             {"name": name, "valueFrom": {"fieldRef": {"fieldPath": path}}})
        self.assertEqual(next(x for x in spec["volumes"] if x["name"] == "guardrail-availability-reviewed-profile")["configMap"],
                         {"name": "reviewed-availability", "defaultMode": 0o440,
                          "items": [{"key": "config.guardrail-availability-recovery.yaml",
                                     "path": "config.guardrail-availability-recovery.yaml"}]})
        self.assertEqual(next(x for x in container["volumeMounts"] if x["name"] == "guardrail-availability-reviewed-profile"),
                         {"name": "guardrail-availability-reviewed-profile",
                          "mountPath": "/data/build/test-harness/config.guardrail-availability-recovery.yaml",
                          "subPath": "config.guardrail-availability-recovery.yaml", "readOnly": True})
        for suffix, namespace, rules in (
            ("source", "vllm", [{"apiGroups": [""], "resources": ["configmaps"],
                                  "resourceNames": ["guardrail-proxy"], "verbs": ["get"]},
                                 {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"],
                                  "verbs": ["list"]}]),
            ("journal", "phorvex-system", [{"apiGroups": [""], "resources": ["configmaps"],
                                             "resourceNames": ["reviewed-journal"], "verbs": ["get"]}])):
            name = "phorvex-phorvex-console-guardrail-availability-" + suffix
            self.assertEqual(named(docs, "Role", name, namespace)["rules"], rules)
            binding = named(docs, "RoleBinding", name, namespace)
            self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": "phorvex-phorvex-console",
                                                     "namespace": "phorvex-system"}])

    def test_umbrella_eks_example_remains_disabled(self):
        chart = ROOT / "deploy/helm/phorvex-stack"
        result = subprocess.run([HELM, "template", "phorvex-stack", str(chart), "-n", "phorvex-system",
                                 "-f", str(chart / "values-eks.yaml")], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        dep = named(docs, "Deployment", "phorvex-stack-phorvex-console", "phorvex-system")
        spec = dep["spec"]["template"]["spec"]
        container = next(x for x in spec["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256", env)
        self.assertNotIn("PHORVEX_CONSOLE_POD_NAME", env)
        self.assertNotIn("PHORVEX_CONSOLE_POD_UID", env)
        self.assertFalse(any("guardrail-availability" in x["metadata"]["name"] for x in docs))

    def test_missing_or_malformed_authority_refuses(self):
        cases = [
            (["--set", PREFIX + "enabled=true"], "requires catalogueV1.enabled"),
            (["--set", "phorvex.console.catalogueV1.enabled=true", "--set", PREFIX + "enabled=true"],
             "requires catalogueV1.scopedToken.existingSecret"),
            (VALID[:8], "configMapName is required"),
            ([*VALID[:10], *VALID[12:]], "profileSHA256 is required"),
            ([*VALID[:-2], "--set", PREFIX + "sourceConfigMap=other", *VALID[-2:]],
             "sourceConfigMap must be guardrail-proxy"),
            ([*VALID, "--set", "phorvex.console.catalogueV1.scopedToken.key=other"],
             "requires scopedToken key token"),
            ([*VALID, "--set", "phorvex.console.auditTransport.serverDNSName=other.phorvex-system.svc"],
             "requires the release audit source DNS"),
        ]
        for args, expected in cases:
            with self.subTest(expected=expected):
                result = render(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
