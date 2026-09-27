import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from test_render import originals

spec = importlib.util.spec_from_file_location("litellm_render_output", HERE / "render_output.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OutputRenderTests(unittest.TestCase):
    def test_private_phase_one_owner_and_phase_two_exact_patches(self):
        deployment, service, policy = originals()
        deployment["metadata"]["uid"] = "reviewed-deployment-uid"
        document = b"document-source-seed-32-bytes-0000001"
        prompt = b"prompt-source-seed-32-bytes-000000001"
        first = module.output_phase_one(deployment, document, prompt)
        self.assertEqual(first["output-policy-configmap.json"]["data"]["policy.json"],
                         '{"entries":[],"revision":0,"version":2}')
        for name in ("output-document-secret.json", "output-prompt-secret.json"):
            obj = first[name]
            self.assertTrue(obj["immutable"])
            self.assertEqual(obj["metadata"]["ownerReferences"][0]["uid"],
                             "reviewed-deployment-uid")
            self.assertEqual(set(obj["data"]), {"seed"})
        objects, _ = module.output_phase_two(deployment, service, policy,
            "client-policy-uid", "output-policy-uid", "doc-secret-uid", "prompt-secret-uid",
            "a" * 64, "docker.io/library/python@sha256:" + "b" * 64)
        patch = objects["deployment-json-patch.json"]
        sidecar = patch[-1]["value"]
        env = {x["name"]: x.get("value") for x in sidecar["env"]}
        self.assertEqual(env["PHORVEX_LITELLM_OUTPUT_POLICY_CONFIGMAP_UID"], "output-policy-uid")
        self.assertEqual(env["PHORVEX_LITELLM_OUTPUT_D_SECRET_UID"], "doc-secret-uid")
        self.assertEqual(env["PHORVEX_LITELLM_OUTPUT_P_SECRET_UID"], "prompt-secret-uid")
        self.assertIn("/etc/phorvex-litellm-output", [x["mountPath"] for x in sidecar["volumeMounts"]])
        self.assertEqual([x["value"] for x in objects["existing-policy-json-patch.json"]
                          if x["path"] == "/spec/actions/enabled/-"],
                         ["litellm-client-revoke", "sensitive-output-policy-activate"])
        self.assertNotIn(document.decode(), str(patch))
        self.assertNotIn(prompt.decode(), str(patch))

    def test_rejects_same_seed_or_unowned_deployment(self):
        deployment, _, _ = originals()
        with self.assertRaisesRegex(ValueError, "owner"):
            module.output_phase_one(deployment, b"a" * 32, b"b" * 32)
        deployment["metadata"]["uid"] = "uid"
        with self.assertRaisesRegex(ValueError, "distinct"):
            module.output_phase_one(deployment, b"a" * 32, b"a" * 32)


if __name__ == "__main__":
    unittest.main()
