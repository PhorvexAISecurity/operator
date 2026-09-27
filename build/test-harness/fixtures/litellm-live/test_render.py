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
                                                   "labels": {"app": "litellm", "r6th.io/rotation-target": "true"}},
                                        "spec": {"containers": [{"name": "litellm", "env": [
                                            {"name": "LITELLM_MASTER_KEY", "value": "sk-private-source-only"}]}],
                                                 "volumes": [{"name": "cfg"}]}}}}
    service = {"kind": "Service", "metadata": {"name": "litellm", "namespace": "litellm",
                                               "uid": "service-uid"},
               "spec": {"selector": {"app": "litellm"},
                        "ports": [{"port": 4000, "targetPort": 4000}]}}
    policy = {"kind": "PhorvexPolicy", "metadata": {"name": "litellm-defense",
              "namespace": "litellm", "uid": "select-uid", "generation": 30},
              "spec": {"tenant": "litellm", "mode": "active",
                       "selector": {"matchLabels": {"r6th.io/rotation-target": "true"}},
                       "triggers": {"eventDriven": True, "reactiveOnly": True},
                       "actions": {"enabled": ["rotate", "route-rotate"]}}}
    return deployment, service, policy


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.seed_sha = hashlib.sha256(b"private-run-owned-seed-at-least-32-bytes").hexdigest()
        self.image = "docker.io/library/python@sha256:" + "a" * 64

    def test_two_phase_render_preserves_secret_and_policy_projection(self):
        phase1, source_sha = render_module.render(self.seed_sha, self.image, "gpt-4o-mini")
        self.assertEqual(len(phase1), 4)
        self.assertEqual(source_sha, hashlib.sha256(Path(render_module.GATEWAY_SOURCE).read_bytes()).hexdigest())
        self.assertNotIn("phorvex-policy.json", phase1)
        journal = phase1["protected-journal-configmap.json"]
        self.assertEqual(journal["metadata"]["namespace"], "phorvex-system")
        self.assertEqual(journal["data"]["receipts.json"], '{"receipts":[],"version":2}')
        d, s, p = originals()
        objects, _ = render_module.render(self.seed_sha, self.image,
                                          "gpt-4o-mini", d, s, p, "policy-uid")
        self.assertEqual(len(objects), 7)
        self.assertEqual(objects["client-policy-configmap.json"]["data"]["state.json"],
                         '{"entries":[],"revision":0,"version":2}')
        self.assertEqual(json.loads(objects["owned-clients-configmap.json"]["data"]["clients.json"]),
                         {"version": 2, "modelAlias": "gpt-4o-mini", "seedSHA256": self.seed_sha})
        patch = objects["deployment-json-patch.json"]
        encoded = json.dumps(patch)
        self.assertNotIn("sk-private-source-only", encoded)
        self.assertIn("phorvex-litellm-master-key", encoded)
        sidecar = patch[-1]["value"]
        self.assertEqual(sidecar["name"], "litellm-admission-gateway")
        self.assertEqual(sidecar["image"], self.image)
        self.assertIn(self.image, [op.get("value") for op in patch if op.get("path", "").endswith("litellm-gateway-image")])
        self.assertIn("/etc/phorvex-litellm-policy", [v["mountPath"] for v in sidecar["volumeMounts"]])
        self.assertIn("/etc/phorvex-litellm-seed", [v["mountPath"] for v in sidecar["volumeMounts"]])
        self.assertEqual(objects["service-json-patch.json"][-1]["value"], 4001)
        policy_patch = objects["existing-policy-json-patch.json"]
        self.assertEqual(policy_patch[-1], {"op": "add", "path": "/spec/actions/enabled/-",
                                            "value": "litellm-client-revoke"})
        self.assertEqual(policy_patch[-2]["value"], ["rotate", "route-rotate"])
        self.assertNotIn("/spec/tenant", [op["path"] for op in policy_patch])

    def test_refuses_incomplete_or_changed_route(self):
        d, s, p = originals()
        with self.assertRaisesRegex(ValueError, "phase-two"):
            render_module.render(self.seed_sha, self.image, "gpt-4o-mini", d, None, p, "policy-uid")
        s["spec"]["ports"][0]["targetPort"] = 4001
        with self.assertRaisesRegex(ValueError, "differs"):
            render_module.render(self.seed_sha, self.image, "gpt-4o-mini", d, s, p, "policy-uid")
        s["spec"]["ports"][0]["targetPort"] = 4000
        p["metadata"]["name"] = "parallel-policy"
        with self.assertRaisesRegex(ValueError, "owner policy"):
            render_module.render(self.seed_sha, self.image, "gpt-4o-mini", d, s, p, "policy-uid")
        with self.assertRaisesRegex(ValueError, "authority"):
            render_module.render("not-a-sha", self.image, "gpt-4o-mini")


if __name__ == "__main__":
    unittest.main()
