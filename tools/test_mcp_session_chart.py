#!/usr/bin/env python3
"""Rendered opt-in MCP baseline authority and disabled defaults."""
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
HELM = "/opt/phorvex-tools/helm"
BASE = [HELM, "template", "mcp-check", str(ROOT / "phorvex/charts/phorvex"),
        "--namespace", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example",
        "--set", "phorvex.console.catalogueV1.enabled=true"]
PIN = ["--set", "phorvex.console.catalogueV1.mcpSession.imageID=docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
       "--set", "phorvex.console.catalogueV1.mcpSession.sourceSHA256=483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5"]


def render(*extra):
    result = subprocess.run([*BASE, *extra], text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [x for x in yaml.safe_load_all(result.stdout) if x]


def one(rows, kind, suffix):
    matches = [x for x in rows if x.get("kind") == kind and
               x.get("metadata", {}).get("name", "").endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError((kind, suffix, len(matches)))
    return matches[0]


class MCPSessionChart(unittest.TestCase):
    def test_disabled_has_no_mcp_authority(self):
        docs = render()
        self.assertFalse([d for d in docs if d.get("metadata", {}).get("name", "").endswith("-console-mcp-session")])
        deployment = one(docs, "Deployment", "-phorvex-console")
        env = {x["name"]: x["value"] for x in deployment["spec"]["template"]["spec"]["containers"][0]["env"] if "value" in x}
        self.assertEqual(env.get("PHORVEX_CONSOLE_CATALOGUE_MCP_ENABLED"), "false")
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_MCP_IMAGE_ID", env)

    def test_enabled_is_only_scoped_read_proxy_and_exec(self):
        docs = render("--set", "phorvex.console.catalogueV1.mcpSession.enabled=true", *PIN)
        role = one(docs, "Role", "-console-mcp-session")
        binding = one(docs, "RoleBinding", "-console-mcp-session")
        self.assertEqual(role["metadata"]["namespace"], "mcp")
        self.assertEqual(binding["metadata"]["namespace"], "mcp")
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": "mcp-check-phorvex-console", "namespace": "phorvex-system"}])
        self.assertEqual(role["rules"], [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
            {"apiGroups": ["apps"], "resources": ["deployments", "replicasets"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["services"], "resourceNames": ["mcp-server"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["mcp-code"], "verbs": ["get"]},
            {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
            {"apiGroups": [""], "resources": ["pods/proxy"], "verbs": ["create", "delete"]},
        ])
        deployment = one(docs, "Deployment", "-phorvex-console")
        env = {x["name"]: x["value"] for x in deployment["spec"]["template"]["spec"]["containers"][0]["env"] if "value" in x}
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_MCP_NAMESPACE"], "mcp")
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_SHA256"], "483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5")

    def test_enabled_requires_reviewed_image_and_source(self):
        for pins in ([], PIN[:2]):
            result = subprocess.run([*BASE, "--set", "phorvex.console.catalogueV1.mcpSession.enabled=true", *pins],
                                    text=True, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mcpSession.", result.stderr)


if __name__ == "__main__":
    unittest.main()
