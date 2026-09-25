#!/usr/bin/env python3
"""Real Helm render controls for the default-off model observation."""
import copy
import pathlib
import subprocess
import shutil
import tempfile
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
HELM = shutil.which("helm") or "/opt/phorvex-tools/helm"
CHART = ROOT / "phorvex/charts/phorvex"
OVERLAY = ROOT / "deploy/helm/phorvex-stack/values-eks.yaml"

class ChartTest(unittest.TestCase):
    def render(self, values):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "values.yaml"
            path.write_text(yaml.safe_dump({"phorvex": values}))
            return subprocess.run([HELM,"template","model",str(CHART),"-f",str(path),"--show-only","templates/console-deployment.yaml"],text=True,capture_output=True)
    def test_default_and_explicit_opt_in(self):
        generic = yaml.safe_load((ROOT / "phorvex/charts/phorvex/values.yaml").read_text())["phorvex"]
        self.assertIs(generic["console"]["catalogueV1"]["mcpVoiceModel"]["enabled"], False)
        values = yaml.safe_load(OVERLAY.read_text())["phorvex"]["phorvex"]
        default=self.render(values)
        self.assertEqual(default.returncode,0,default.stderr)
        self.assertIn("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_ENABLED\n          value: \"false\"",default.stdout)
        self.assertNotIn("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_VOICE_SOURCE_SHA256",default.stdout)
        enabled=copy.deepcopy(values)
        enabled["console"]["catalogueV1"]["mcpVoiceModel"]={"enabled":True,"voiceSourceSHA256":"23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf"}
        enabled["console"]["catalogueV1"]["litellm"].update(inferenceEnabled=True,modelAlias="gpt-4o-mini")
        positive=self.render(enabled)
        self.assertEqual(positive.returncode,0,positive.stderr)
        self.assertIn("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_ENABLED\n          value: \"true\"",positive.stdout)
        self.assertIn("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_VOICE_SOURCE_SHA256",positive.stdout)
        for mutate in (lambda v:v["console"]["catalogueV1"]["mcpVoiceModel"].update(voiceSourceSHA256=""),
                       lambda v:v["console"]["catalogueV1"]["litellm"].update(modelAlias="other"),
                       lambda v:v["console"]["catalogueV1"]["mcpSession"].update(enabled=False)):
            bad=copy.deepcopy(enabled);mutate(bad)
            failed=self.render(bad)
            self.assertNotEqual(failed.returncode,0,failed.stdout)

if __name__ == "__main__": unittest.main()
