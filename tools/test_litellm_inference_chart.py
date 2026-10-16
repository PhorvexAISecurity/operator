"""Offline Helm controls for the separate LiteLLM inference opt-in."""

import os
import json
import subprocess
import unittest
from pathlib import Path

import yaml
from inherited_drift import inherited_drift


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

    @inherited_drift("values-eks.yaml enables mcpVoiceModel, which needs the inference this test disables")
    def test_umbrella_eks_activates_only_reviewed_inference_alias(self):
        chart = ROOT / "deploy/helm/phorvex-stack"
        values = chart / "values-eks.yaml"
        command = [HELM, "template", "phorvex", str(chart), "-n", "phorvex-system",
                   "--api-versions", "monitoring.coreos.com/v1/PodMonitor", "-f", str(values)]
        active = subprocess.run(command, capture_output=True, text=True, timeout=30)
        disabled = subprocess.run([*command,
                                   "--set", "phorvex.phorvex.console.catalogueV1.litellm.inferenceEnabled=false",
                                   "--set-string", "phorvex.phorvex.console.catalogueV1.litellm.modelAlias="],
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(active.returncode, 0, active.stderr)
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        live_docs = [x for x in yaml.safe_load_all(active.stdout) if x]
        base_docs = [x for x in yaml.safe_load_all(disabled.stdout) if x]

        def console(docs):
            deployment = next(x for x in docs if x.get("kind") == "Deployment" and
                              x["metadata"]["name"] == "phorvex-phorvex-console")
            container = next(x for x in deployment["spec"]["template"]["spec"]["containers"]
                             if x["name"] == "console")
            return deployment, container, {x["name"]: x.get("value") for x in container["env"]}

        active_deployment, active_container, env_active = console(live_docs)
        disabled_deployment, disabled_container, env_disabled = console(base_docs)
        flag = "PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED"
        alias = "PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS"
        self.assertEqual(env_active[flag], "true")
        self.assertEqual(env_active[alias], "gpt-4o-mini")
        self.assertEqual(env_disabled[flag], "false")
        self.assertNotIn(alias, env_disabled)
        self.assertEqual(env_active["PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256"],
                         "14ebebce3b18a492a7aadb5c011bfcd71d8d16d8e8745e305b4f2336664daafb")
        self.assertEqual(env_active["PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256"],
                         env_disabled["PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256"])
        grants = next(x for x in live_docs if x.get("kind") == "ConfigMap" and
                      x["metadata"]["name"] == "phorvex-phorvex-console-grants")
        subjects = json.loads(grants["data"]["grants.json"])["subjects"]
        caller = [x for x in subjects if x.get("subject") ==
                  "system:serviceaccount:phorvex-system:phorvex-phorvex-console-e2e"]
        self.assertEqual(len(caller), 1)
        self.assertIn("litellm", caller[0]["tenants"])
        self.assertIn("default", caller[0]["targets"])

        # Helm also renders generated credentials, so compare the stable
        # deployment and grant fields that this opt-in is allowed to affect.
        self.assertEqual({k: v for k, v in env_active.items() if k not in (flag, alias)},
                         {k: v for k, v in env_disabled.items() if k not in (flag, alias)})
        self.assertEqual(active_container["image"], disabled_container["image"])
        self.assertEqual(active_container["volumeMounts"], disabled_container["volumeMounts"])
        self.assertEqual(active_deployment["spec"]["template"]["spec"]["volumes"],
                         disabled_deployment["spec"]["template"]["spec"]["volumes"])
        disabled_grants = next(x for x in base_docs if x.get("kind") == "ConfigMap" and
                               x["metadata"]["name"] == "phorvex-phorvex-console-grants")
        self.assertEqual(grants["data"]["grants.json"], disabled_grants["data"]["grants.json"])
        self.assertEqual(grants["metadata"].get("annotations"),
                         disabled_grants["metadata"].get("annotations"))


if __name__ == "__main__":
    unittest.main()
