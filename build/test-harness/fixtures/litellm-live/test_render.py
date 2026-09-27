import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("litellm_live_render", Path(__file__).with_name("render.py"))
render_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_module)


def originals():
    deployment = {"kind": "Deployment", "metadata": {"name": "litellm", "namespace": "litellm"},
                  "spec": {"template": {"metadata": {"annotations": {"existing": "true"},
                                                   "labels": {"app": "litellm"}},
                                        "spec": {"containers": [{"name": "litellm", "env": [
                                            {"name": "LITELLM_MASTER_KEY", "value": "sk-private-source-only"}]}],
                                                 "volumes": [{"name": "cfg"}]}}}}
    service = {"kind": "Service", "metadata": {"name": "litellm", "namespace": "litellm",
                                               "uid": "service-uid"},
               "spec": {"selector": {"app": "litellm"},
                        "ports": [{"port": 4000, "targetPort": 4000}]}}
    return deployment, service


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.attacker = hashlib.sha256(b"sk-owned-attacker").hexdigest()
        self.control = hashlib.sha256(b"sk-owned-control").hexdigest()
        self.image = "ghcr.io/berriai/litellm@sha256:" + "a" * 64

    def test_two_phase_render_preserves_secret_and_policy_projection(self):
        phase1, source_sha = render_module.render(self.attacker, self.control, self.image,
                                                   "gpt-4o-mini")
        self.assertEqual(len(phase1), 4)
        self.assertEqual(source_sha, hashlib.sha256(Path(render_module.GATEWAY_SOURCE).read_bytes()).hexdigest())
        policy = phase1["phorvex-policy.json"]
        self.assertEqual(policy["spec"]["selector"]["matchLabels"],
                         {"phorvex.ai/litellm-live": "true"})
        self.assertEqual(policy["spec"]["actions"]["enabled"],
                         ["rotate", "quarantine", "litellm-client-revoke"])
        self.assertTrue(policy["spec"]["triggers"]["reactiveOnly"])
        d, s = originals()
        objects, _ = render_module.render(self.attacker, self.control, self.image,
                                          "gpt-4o-mini", d, s, "policy-uid")
        self.assertEqual(len(objects), 6)
        self.assertEqual(objects["client-policy-configmap.json"]["data"]["state.json"],
                         '{"active":false,"clientSHA256":"' + self.attacker +
                         '","operationId":"","revision":0,"version":1}')
        patch = objects["deployment-json-patch.json"]
        encoded = json.dumps(patch)
        self.assertNotIn("sk-private-source-only", encoded)
        self.assertIn("phorvex-litellm-master-key", encoded)
        sidecar = patch[-1]["value"]
        self.assertEqual(sidecar["name"], "litellm-admission-gateway")
        self.assertEqual(sidecar["image"], self.image)
        self.assertIn(self.image, [op.get("value") for op in patch if op.get("path", "").endswith("litellm-gateway-image")])
        self.assertIn("/etc/phorvex-litellm-policy", [v["mountPath"] for v in sidecar["volumeMounts"]])
        self.assertEqual(objects["service-json-patch.json"][-1]["value"], 4001)

    def test_refuses_incomplete_or_changed_route(self):
        d, s = originals()
        with self.assertRaisesRegex(ValueError, "phase-two"):
            render_module.render(self.attacker, self.control, self.image, "gpt-4o-mini", d, None, "policy-uid")
        s["spec"]["ports"][0]["targetPort"] = 4001
        with self.assertRaisesRegex(ValueError, "differs"):
            render_module.render(self.attacker, self.control, self.image, "gpt-4o-mini", d, s, "policy-uid")
        with self.assertRaisesRegex(ValueError, "authority"):
            render_module.render(self.attacker, self.attacker, self.image, "gpt-4o-mini")


if __name__ == "__main__":
    unittest.main()
