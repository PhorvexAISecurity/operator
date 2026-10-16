#!/usr/bin/env python3
"""Render the default-off Chroma and LiteLLM catalogue authorities."""
import os
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
BASE = [os.environ.get("HELM", "helm"), "template", "stack-check",
        str(ROOT / "phorvex/charts/phorvex"), "--namespace", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example",
        "--set", "phorvex.console.catalogueV1.enabled=true"]


def render(*extra):
    result = subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def one(docs, kind, suffix):
    rows = [doc for doc in docs if doc.get("kind") == kind and
            doc.get("metadata", {}).get("name", "").endswith(suffix)]
    if len(rows) != 1:
        raise AssertionError((kind, suffix, len(rows)))
    return rows[0]


def environment(docs):
    deployment = one(docs, "Deployment", "-phorvex-console")
    return {item["name"]: item.get("value") for item in
            deployment["spec"]["template"]["spec"]["containers"][0]["env"]}


class StackCatalogueChart(unittest.TestCase):
    def test_default_has_no_roles_or_source_authority(self):
        docs = render()
        names = {doc.get("metadata", {}).get("name", "") for doc in docs}
        self.assertFalse({name for name in names if "console-chroma-control" in name or
                          "console-litellm-control" in name})
        env = environment(docs)
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_CHROMA_ENABLED"], "false")
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_LITELLM_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_CHROMA_IMAGE_ID", env)
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256", env)

    def test_opt_in_roles_only_read_and_exact_pod_exec(self):
        docs = render("--set", "phorvex.console.catalogueV1.chroma.enabled=true",
                      "--set", "phorvex.console.catalogueV1.litellm.enabled=true")
        for suffix, namespace, service in [
            ("-console-chroma-control", "document-store", "chroma"),
            ("-console-litellm-control", "litellm", "litellm")]:
            role = one(docs, "Role", suffix)
            binding = one(docs, "RoleBinding", suffix)
            self.assertEqual(role["metadata"]["namespace"], namespace)
            self.assertEqual(binding["metadata"]["namespace"], namespace)
            self.assertEqual(binding["roleRef"]["name"], role["metadata"]["name"])
            rules = role["rules"]
            self.assertIn({"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}, rules)
            self.assertIn({"apiGroups": [""], "resources": ["services"],
                           "resourceNames": [service], "verbs": ["get"]}, rules)
            self.assertFalse([rule for rule in rules if "pods/proxy" in rule.get("resources", [])])
            self.assertFalse([rule for rule in rules if "delete" in rule.get("verbs", []) or
                              "update" in rule.get("verbs", []) or "patch" in rule.get("verbs", [])])
        env = environment(docs)
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_CHROMA_NAMESPACE"], "document-store")
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_LITELLM_NAMESPACE"], "litellm")
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256"],
                         "14ebebce3b18a492a7aadb5c011bfcd71d8d16d8e8745e305b4f2336664daafb")


if __name__ == "__main__":
    unittest.main()
