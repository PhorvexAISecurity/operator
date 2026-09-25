"""Offline Helm controls for the separate LiteLLM inference opt-in."""

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
PREFIX = "phorvex.console.catalogueV1.litellm."


def render(*extra):
    return subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)


def env(result):
    assert result.returncode == 0, result.stderr
    docs = [x for x in yaml.safe_load_all(result.stdout) if x]
    deployment = next(x for x in docs if x.get("kind") == "Deployment" and
                      x["metadata"]["name"] == "phorvex-phorvex-console")
    container = next(x for x in deployment["spec"]["template"]["spec"]["containers"]
                     if x["name"] == "console")
    return {x["name"]: x["value"] for x in container["env"]}


class LiteLLMInferenceChart(unittest.TestCase):
    def test_default_off_and_no_alias(self):
        current = env(render("--set", "phorvex.console.catalogueV1.enabled=true"))
        self.assertEqual(current["PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS", current)

    def test_enabled_requires_base_and_reviewed_alias(self):
        args = ("--set", "phorvex.console.catalogueV1.enabled=true",
                "--set", PREFIX + "enabled=true",
                "--set", PREFIX + "inferenceEnabled=true")
        missing = render(*args)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("modelAlias is required", missing.stderr)
        disabled = render("--set", PREFIX + "inferenceEnabled=true",
                          "--set", PREFIX + "modelAlias=reviewed-model")
        self.assertNotEqual(disabled.returncode, 0)
        self.assertIn("requires catalogueV1 and litellm enabled", disabled.stderr)
        invalid = render(*args, "--set-string", PREFIX + "modelAlias=__SET_MODEL__")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("must be a reviewed model alias", invalid.stderr)
        accepted = env(render(*args, "--set-string", PREFIX + "modelAlias=reviewed-model"))
        self.assertEqual(accepted["PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED"], "true")
        self.assertEqual(accepted["PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS"], "reviewed-model")

    def test_inference_without_console_refuses(self):
        result = subprocess.run([HELM, "template", "phorvex", str(CHART), "-n", "phorvex-system",
                                 "--set", PREFIX + "inferenceEnabled=true"],
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires console.enabled", result.stderr)

    def test_umbrella_eks_example_keeps_inference_off(self):
        chart = ROOT / "deploy/helm/phorvex-stack"
        values = chart / "values-eks.yaml"
        result = subprocess.run([HELM, "template", "phorvex-stack", str(chart), "-n", "phorvex-system",
                                 "-f", str(values)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [x for x in yaml.safe_load_all(result.stdout) if x]
        deployment = next(x for x in docs if x.get("kind") == "Deployment" and
                          x["metadata"]["name"] == "phorvex-stack-phorvex-console")
        container = next(x for x in deployment["spec"]["template"]["spec"]["containers"]
                         if x["name"] == "console")
        values = {x["name"]: x["value"] for x in container["env"]}
        self.assertEqual(values["PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS", values)


if __name__ == "__main__":
    unittest.main()
