#!/usr/bin/env python3
"""Fixed guardrail comparison chart authority remains opt-in and read-only."""
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parent.parent
BASE = ["/opt/phorvex-tools/helm", "template", "guardrail-static-check", str(ROOT / "phorvex/charts/phorvex"),
        "--namespace", "phorvex-system", "--set", "phorvex.console.enabled=true",
        "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example"]

def render(*args):
    result = subprocess.run([*BASE, *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [row for row in yaml.safe_load_all(result.stdout) if row]

class GuardrailStaticChart(unittest.TestCase):
    def test_disabled_has_no_extra_authority(self):
        docs = render()
        self.assertFalse([d for d in docs if "console-guardrail-static" in d.get("metadata", {}).get("name", "")])

    def test_enabled_adds_only_exact_configmap_reads(self):
        docs = render("--set", "phorvex.console.guardrailStatic.enabled=true",
                      "--set", "phorvex.console.guardrailStatic.guardrailJournalName=reviewed-gj",
                      "--set", "phorvex.console.guardrailStatic.kvJournalName=reviewed-kj")
        roles = [d for d in docs if d.get("kind") == "Role" and "console-guardrail-static" in d.get("metadata", {}).get("name", "")]
        self.assertEqual(len(roles), 2)
        config_rules = [rule for role in roles for rule in role["rules"] if rule["resources"] == ["configmaps"]]
        self.assertEqual(len(config_rules), 2)
        self.assertEqual({name for rule in config_rules for name in rule["resourceNames"]}, {"guardrail-proxy", "reviewed-gj", "reviewed-kj"})
        self.assertTrue(all(rule["verbs"] == ["get"] for rule in config_rules))

if __name__ == "__main__":
    unittest.main()
