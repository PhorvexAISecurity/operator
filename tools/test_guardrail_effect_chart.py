"""Fixed existing guardrail-effect action remains default-off and exactly scoped."""

import os
import base64
import hashlib
import subprocess
import unittest
from pathlib import Path

import yaml
from inherited_drift import inherited_drift


ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
BASE = [HELM, "template", "phorvex", str(ROOT / "phorvex/charts/phorvex"), "-n", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=phorvex-phorvex-audit-source.phorvex-system.svc"]
P = "phorvex.console.guardrailEffect."
VALID = ["--set", "phorvex.console.catalogueV1.enabled=true",
         "--set", "phorvex.console.catalogueV1.scopedToken.existingSecret=reviewed-token",
         "--set", P + "enabled=true", "--set", P + "configMapName=reviewed-effect",
         "--set-string", P + "profileSHA256=" + "a" * 64,
         "--set", P + "guardrailJournalName=reviewed-journal"]


def render(*args):
    return subprocess.run([*BASE, *args], capture_output=True, text=True, timeout=30)


class GuardrailEffectChart(unittest.TestCase):
    def test_default_off(self):
        result = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        dep = next(x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == "phorvex-phorvex-console")
        spec = dep["spec"]["template"]["spec"]
        env = {x["name"]: x.get("value") for x in spec["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256", env)
        self.assertFalse(any("guardrail-effect" in x["metadata"]["name"] for x in docs))
        self.assertNotIn("guardrail-effect-reviewed-profile", {x["name"] for x in spec["volumes"]})

    def test_enabled_exact_profile_and_grants(self):
        result = render(*VALID)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        dep = next(x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == "phorvex-phorvex-console")
        spec = dep["spec"]["template"]["spec"]
        container = next(x for x in spec["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256"], "a" * 64)
        self.assertEqual(spec["volumes"][[x["name"] for x in spec["volumes"]].index("guardrail-effect-reviewed-profile")]["configMap"],
                         {"name": "reviewed-effect", "defaultMode": 0o440,
                          "items": [{"key": "config.guardrail-effect.yaml", "path": "config.guardrail-effect.yaml"}]})
        self.assertEqual(next(x for x in container["volumeMounts"] if x["name"] == "guardrail-effect-reviewed-profile"),
                         {"name": "guardrail-effect-reviewed-profile", "mountPath": "/etc/phorvex-guardrail-effect/config.guardrail-effect.yaml",
                          "subPath": "config.guardrail-effect.yaml", "readOnly": True})
        for suffix, namespace, names in (("source", "vllm", ["guardrail-proxy"]),
                                         ("journal", "phorvex-system", ["reviewed-journal"])):
            name = "phorvex-phorvex-console-guardrail-effect-" + suffix
            role = next(x for x in docs if x.get("kind") == "Role" and x["metadata"]["name"] == name)
            self.assertEqual(role["metadata"]["namespace"], namespace)
            self.assertEqual([r["resourceNames"] for r in role["rules"] if r["resources"] == ["configmaps"]], [names])

    def test_incomplete_authority_refuses(self):
        for args, expected in ((["--set", P + "enabled=true"], "requires catalogueV1.enabled"),
                               (VALID[:6], "configMapName is required"),
                               ([*VALID, "--set", P + "sourceConfigMap=other"], "sourceConfigMap must be guardrail-proxy"),
                               ([*VALID[:8], "--set-string", P + "profileSHA256=wrong", *VALID[10:]], "profileSHA256 must be 64 lowercase")):
            with self.subTest(expected=expected):
                result = render(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    @inherited_drift("console.guardrailEffect.configMapName no longer matches catalogueProfiles")
    def test_umbrella_optional_immutable_source(self):
        raw = b"reviewed example bytes\n"
        sha = hashlib.sha256(raw).hexdigest()
        name = "phorvex-catalogue-guardrail-effect-" + sha[:12]
        args = [HELM, "template", "phorvex", str(ROOT / "deploy/helm/phorvex-stack"),
                "-n", "phorvex-system", "-f", str(ROOT / "deploy/helm/phorvex-stack/values-eks.yaml"),
                "--set", "phorvex.phorvex.console.podBoundTokenCPU.enabled=false",
                "--set", "catalogueProfiles.guardrailEffect.enabled=true",
                "--set", "catalogueProfiles.guardrailEffect.configMapName=" + name,
                "--set-string", "catalogueProfiles.guardrailEffect.profileBase64=" + base64.b64encode(raw).decode()]
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        cm = next(x for x in docs if x.get("kind") == "ConfigMap" and x["metadata"]["name"] == name)
        self.assertTrue(cm["immutable"])
        self.assertEqual(base64.b64decode(cm["binaryData"]["config.guardrail-effect.yaml"]), raw)
        dep = next(x for x in docs if x.get("kind") == "Deployment" and x["metadata"]["name"] == "phorvex-phorvex-console")
        env = {x["name"]: x.get("value") for x in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED"], "false")
        bad = subprocess.run([*args, "--set", "catalogueProfiles.guardrailEffect.configMapName=wrong"],
                             capture_output=True, text=True, timeout=30)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
