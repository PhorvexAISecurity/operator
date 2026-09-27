"""Real Helm render for the default-off, digest-pinned request-drain arm."""

import os
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
BASE = [HELM, "template", "phorvex", str(ROOT / "phorvex/charts/phorvex"), "-n", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=phorvex-phorvex-audit-source.phorvex-system.svc"]
P = "phorvex.console.drainLive."
VALID = ["--set", "phorvex.console.catalogueV1.enabled=true",
         "--set", "phorvex.console.catalogueV1.scopedToken.existingSecret=reviewed-token",
         "--set", P + "enabled=true",
         "--set", P + "configMapName=phorvex-catalogue-drain-live-" + "a" * 12,
         "--set-string", P + "profileSHA256=" + "a" * 64,
         "--set", P + "journalName=phorvex-operation-" + "b" * 40]


def render(*args):
    return subprocess.run([*BASE, *args], capture_output=True, text=True, timeout=30)


class DrainLiveChart(unittest.TestCase):
    def test_default_off(self):
        result = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        dep = next(x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == "phorvex-phorvex-console")
        spec = dep["spec"]["template"]["spec"]
        env = {x["name"]: x.get("value") for x in spec["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_DRAIN_LIVE_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256", env)
        self.assertNotIn("drain-live-reviewed-profile", {x["name"] for x in spec["volumes"]})

    def test_enabled_mount_and_exact_journal_read(self):
        result = render(*VALID)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        dep = next(x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == "phorvex-phorvex-console")
        spec = dep["spec"]["template"]["spec"]
        env = {x["name"]: x.get("value") for x in spec["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_DRAIN_LIVE_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256"], "a" * 64)
        volume = next(x for x in spec["volumes"] if x["name"] == "drain-live-reviewed-profile")
        self.assertEqual(volume["configMap"]["name"], "phorvex-catalogue-drain-live-" + "a" * 12)
        role = next(x for x in docs if x.get("kind") == "Role" and x["metadata"]["name"] == "phorvex-phorvex-console-drain-live-journal")
        self.assertEqual(role["rules"][0]["resourceNames"], ["phorvex-operation-" + "b" * 40])

    def test_digest_or_journal_drift_refused(self):
        bad_hash = VALID.copy()
        bad_hash[bad_hash.index(P + "configMapName=phorvex-catalogue-drain-live-" + "a" * 12)] = P + "configMapName=phorvex-catalogue-drain-live-" + "c" * 12
        self.assertNotEqual(render(*bad_hash).returncode, 0)
        bad_journal = VALID.copy()
        bad_journal[bad_journal.index(P + "journalName=phorvex-operation-" + "b" * 40)] = P + "journalName=other"
        self.assertNotEqual(render(*bad_journal).returncode, 0)


if __name__ == "__main__":
    unittest.main()
