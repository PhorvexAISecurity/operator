#!/usr/bin/env python3
"""Rendered default-off authority for the fixed Mongo synthetic-document control."""
import os
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
HELM = os.environ.get("HELM", "/opt/phorvex-tools/helm")
BASE = [HELM, "template", "mongo-exposure-check", str(ROOT / "phorvex/charts/phorvex"),
        "--namespace", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example"]
SUFFIX = "-console-mongo-exposure"


def render(*extra):
    proc = subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc]


def owned(rows):
    return [row for row in rows if row.get("metadata", {}).get("name", "").endswith(SUFFIX)]


def console_env(rows):
    pods = [row for row in rows if row.get("kind") == "Deployment" and
            row.get("metadata", {}).get("name", "").endswith("-phorvex-console")]
    if len(pods) != 1:
        raise AssertionError("expected exactly one console Deployment")
    return {row["name"]: row.get("value") for row in pods[0]["spec"]["template"]["spec"]["containers"][0]["env"]}


class MongoExposureChart(unittest.TestCase):
    def test_default_disabled_adds_no_namespace_authority(self):
        docs = render()
        self.assertEqual(owned(docs), [])
        self.assertEqual(console_env(docs)["PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED"], "false")

    def test_enabled_is_exact_namespace_role_and_console_binding(self):
        docs = render("--set", "phorvex.console.mongoExposure.enabled=true")
        rows = owned(docs)
        self.assertEqual([row["kind"] for row in rows], ["Role", "RoleBinding"])
        rbac_kinds = {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
        self.assertEqual([row for row in docs if row["kind"] in rbac_kinds and row not in rows],
                         [row for row in render() if row["kind"] in rbac_kinds])
        role, binding = rows
        self.assertEqual(console_env(docs)["PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED"], "true")
        self.assertEqual(role["metadata"]["namespace"], "document-store")
        self.assertEqual(binding["metadata"]["namespace"], "document-store")
        self.assertEqual(binding["roleRef"], {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role["metadata"]["name"]})
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": "mongo-exposure-check-phorvex-console", "namespace": "phorvex-system"}])
        self.assertEqual(role["rules"], [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "create", "delete"]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["pods/portforward"], "verbs": ["create"]},
            {"apiGroups": [""], "resources": ["services"], "resourceNames": ["mongo"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["persistentvolumeclaims"], "resourceNames": ["mongo-data"], "verbs": ["get"]},
            {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get", "list"]},
        ])
        self.assertFalse([doc for doc in docs if doc["kind"] == "Namespace" and doc["metadata"]["name"] == "document-store"])

    def test_enabled_without_console_is_rejected(self):
        proc = subprocess.run([*BASE, "--set", "phorvex.console.enabled=false", "--set", "phorvex.console.mongoExposure.enabled=true"],
                              capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("mongoExposure.enabled requires console.enabled", proc.stderr)


if __name__ == "__main__":
    unittest.main()
