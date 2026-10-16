#!/usr/bin/env python3
"""Rendered, disabled-by-default calibration authority contract."""
import os
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
HELM = os.environ.get("HELM", "helm")
BASE = [HELM, "template", "calibration-check", str(ROOT / "phorvex/charts/phorvex"),
        "--namespace", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example",
        "--set", "phorvex.console.catalogueV1.enabled=true"]
SOURCE_SHA = "fba39e68dea763043125b29416b832418387a6780e8cce067cbe0121104d09ce"

def render(*args):
    result = subprocess.run([*BASE, *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [x for x in yaml.safe_load_all(result.stdout) if x]

def one(docs, kind, suffix):
    rows = [x for x in docs if x.get("kind") == kind and x.get("metadata", {}).get("name", "").endswith(suffix)]
    if len(rows) != 1:
        raise AssertionError((kind, suffix, len(rows)))
    return rows[0]

class GuardrailCalibrationChart(unittest.TestCase):
    def test_disabled_has_no_calibration_role_or_active_env(self):
        docs = render()
        self.assertFalse([d for d in docs if "console-guardrail-calibration" in d.get("metadata", {}).get("name", "")])
        deployment = one(docs, "Deployment", "-phorvex-console")
        env = {x["name"]: x["value"] for x in deployment["spec"]["template"]["spec"]["containers"][0]["env"] if "value" in x}
        self.assertEqual(env.get("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_CALIBRATION_ENABLED"), "false")
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_SHA256", env)

    def test_enabled_is_only_namespace_role_and_fixed_source_env(self):
        docs = render("--set", "phorvex.console.catalogueV1.guardrailCalibration.enabled=true",
                      "--set", f"phorvex.console.catalogueV1.guardrailCalibration.sourceSHA256={SOURCE_SHA}")
        role = one(docs, "Role", "-console-guardrail-calibration-v1")
        binding = one(docs, "RoleBinding", "-console-guardrail-calibration-v1")
        self.assertEqual(role["metadata"]["namespace"], "vllm")
        self.assertEqual(binding["metadata"]["namespace"], "vllm")
        self.assertEqual(binding["roleRef"]["name"], role["metadata"]["name"])
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": "calibration-check-phorvex-console", "namespace": "phorvex-system"}])
        self.assertEqual(role["rules"], [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["services"], "resourceNames": ["vllm"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["guardrail-proxy"], "verbs": ["get"]},
            {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list"]},
            {"apiGroups": [""], "resources": ["pods/proxy"], "verbs": ["get", "create"]},
        ])
        deployment = one(docs, "Deployment", "-phorvex-console")
        env = {x["name"]: x["value"] for x in deployment["spec"]["template"]["spec"]["containers"][0]["env"] if "value" in x}
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_SHA256"], SOURCE_SHA)
        self.assertEqual(env["PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SERVICE"], "vllm")

    def test_enabled_without_source_pin_refuses_to_render(self):
        result = subprocess.run([*BASE, "--set", "phorvex.console.catalogueV1.guardrailCalibration.enabled=true"], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guardrailCalibration.sourceSHA256 is required", result.stderr)

if __name__ == "__main__":
    unittest.main()
