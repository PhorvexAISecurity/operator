"""Render the opt-in E2E trust boundary, including release-specific identity."""
from pathlib import Path
import subprocess
import unittest

import yaml


CHART = Path(__file__).resolve().parents[1] / "phorvex/charts/phorvex"


class DetectorChartTests(unittest.TestCase):
    def render(self, *args):
        return subprocess.run(["helm", "template", "test", str(CHART), "-n", "test-system", *args],
                              capture_output=True, text=True, check=True).stdout

    def test_disabled_by_default(self):
        text = self.render()
        self.assertNotIn("test-phorvex-e2e-detector", text)
        self.assertNotIn("ValidatingAdmissionPolicy", text)

    def test_enabled_requires_explicit_namespace(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.render("--set", "phorvex.e2eDetector.enabled=true")

    def test_enabled_is_bounded_and_trusts_only_dedicated_identity(self):
        docs = list(yaml.safe_load_all(self.render("--set", "phorvex.e2eDetector.enabled=true",
                                                "--set", "phorvex.e2eDetector.targetNamespace=voice")))
        name = "test-phorvex-e2e-detector"
        objects = {d["kind"]: d for d in docs if d and d["metadata"]["name"] == name}
        self.assertFalse(objects["ServiceAccount"]["automountServiceAccountToken"])
        self.assertEqual(objects["ClusterRole"]["rules"], [{"apiGroups": ["amtd.r6security.com"],
            "resources": ["securityevents"], "verbs": ["create", "get", "delete"]}])
        policy = objects["ValidatingAdmissionPolicy"]["spec"]
        self.assertEqual(policy["failurePolicy"], "Fail")
        self.assertIn("system:serviceaccount:test-system:" + name, policy["matchConditions"][0]["expression"])
        expressions = " ".join(v["expression"] for v in policy["validations"])
        self.assertIn("startsWith('voice/')", expressions)
        self.assertIn("startsWith('phorvex-e2e-')", expressions)
        self.assertIn("PhorvexE2EDetector", expressions)
        self.assertEqual(objects["ValidatingAdmissionPolicyBinding"]["spec"]["validationActions"], ["Deny"])
        deployment = next(d for d in docs if d and d["kind"] == "Deployment")
        args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
        trust = next(a for a in args if a.startswith("--trusted-detectors="))
        self.assertIn("test-system/" + name, trust)
        self.assertNotIn("test-system/test-phorvex-manager", trust)


if __name__ == "__main__":
    unittest.main()
