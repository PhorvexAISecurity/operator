import importlib.util
import copy
import json
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
    def test_installed_first_batch_migrates_immutable_source_without_resetting_client_state(self):
        deployment, service, policy = originals()
        deployment["metadata"]["uid"] = "reviewed-deployment-uid"
        deployment["metadata"]["resourceVersion"] = "12345"
        service["spec"]["ports"][0]["targetPort"] = 4001
        policy["spec"]["actions"]["enabled"].append("litellm-client-revoke")
        template = deployment["spec"]["template"]
        template["metadata"].setdefault("labels", {})["r6th.io/rotation-target"] = "true"
        template["metadata"]["annotations"] = {
            "phorvex.ai/litellm-gateway-source-sha256": module.LEGACY_SOURCE_SHA,
            "phorvex.ai/litellm-live-service-uid": service["metadata"]["uid"],
            "phorvex.ai/litellm-client-policy-configmap-uid": "client-policy-uid"}
        template["spec"]["volumes"] = [{"name": "litellm-live-gateway-source",
                                          "configMap": {"name": "phorvex-litellm-admission-gateway"}}]
        image = "docker.io/library/python@sha256:" + "b" * 64
        template["spec"]["containers"].append({"name": "litellm-admission-gateway", "image": image,
            "command": ["python3", "-B", "/opt/phorvex/gateway.py"],
            "env": [{"name": "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256",
                     "value": module.LEGACY_SOURCE_SHA},
                    {"name": "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", "value": "client-policy-uid"},
                    {"name": "PHORVEX_LITELLM_TRIAL_SEED_FILE", "value": "/etc/phorvex-litellm-seed/seed"}],
            "volumeMounts": [{"name": "litellm-live-gateway-source",
                              "mountPath": "/opt/phorvex", "readOnly": True}]})
        live = {"version": 2, "sourceSHA256": module.LEGACY_SOURCE_SHA,
                "gatewayImage": image, "clientsSHA256": "c" * 64,
                "seedSHA256": "a" * 64, "policyName": "litellm-defense",
                "modelAlias": "gpt-4o-mini", "eventCreator": "console-identity",
                "auditSourceIdentity": "audit-identity", "maxRunSeconds": 900}
        objects, source_sha = module.output_phase_two(deployment, service, policy,
            "client-policy-uid", "output-policy-uid", "document-uid", "prompt-uid",
            "a" * 64, image, live_profile=live)
        self.assertEqual(objects["gateway-output-source-configmap.json"]["metadata"]["name"],
                         "phorvex-litellm-admission-gateway-" + source_sha[:12])
        self.assertNotIn("client-policy-configmap.json", objects)
        self.assertNotIn("protected-journal-configmap.json", objects)
        patch = objects["deployment-json-patch.json"]
        self.assertIn({"op": "test", "path": "/metadata/resourceVersion", "value": "12345"}, patch)
        self.assertIn({"op": "replace", "path": "/spec/template/spec/volumes/0/configMap/name",
                       "value": "phorvex-litellm-admission-gateway-" + source_sha[:12]}, patch)
        migrated = objects["console-live-profile-configmap.json"]["data"]["profile.json"]
        self.assertEqual(json.loads(migrated)["sourceSHA256"], source_sha)
        template["metadata"]["annotations"]["phorvex.ai/litellm-gateway-source-sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "annotation authority"):
            module.output_phase_two(deployment, service, policy,
                "client-policy-uid", "output-policy-uid", "document-uid", "prompt-uid",
                "a" * 64, image, live_profile=live)

    def test_installed_gateway_patch_refuses_stale_deployment_snapshot(self):
        deployment, service, policy = originals()
        deployment["metadata"].update(uid="reviewed-deployment-uid", resourceVersion="12345")
        service["spec"]["ports"][0]["targetPort"] = 4001
        policy["spec"]["actions"]["enabled"].append("litellm-client-revoke")
        template = deployment["spec"]["template"]
        template["metadata"].setdefault("labels", {})["r6th.io/rotation-target"] = "true"
        template["metadata"]["annotations"] = {
            "phorvex.ai/litellm-gateway-source-sha256": module.LEGACY_SOURCE_SHA,
            "phorvex.ai/litellm-live-service-uid": service["metadata"]["uid"],
            "phorvex.ai/litellm-client-policy-configmap-uid": "client-policy-uid"}
        template["spec"]["volumes"] = [{"name": "litellm-live-gateway-source",
                                          "configMap": {"name": "phorvex-litellm-admission-gateway"}}]
        image = "docker.io/library/python@sha256:" + "b" * 64
        template["spec"]["containers"].append({"name": "litellm-admission-gateway", "image": image,
            "command": ["python3", "-B", "/opt/phorvex/gateway.py"],
            "env": [{"name": "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", "value": module.LEGACY_SOURCE_SHA},
                    {"name": "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", "value": "client-policy-uid"},
                    {"name": "PHORVEX_LITELLM_TRIAL_SEED_FILE", "value": "/etc/phorvex-litellm-seed/seed"}],
            "volumeMounts": [{"name": "litellm-live-gateway-source", "mountPath": "/opt/phorvex",
                              "readOnly": True}]})
        live = {"version": 2, "sourceSHA256": module.LEGACY_SOURCE_SHA,
                "gatewayImage": image, "clientsSHA256": "c" * 64, "seedSHA256": "a" * 64,
                "policyName": "litellm-defense", "modelAlias": "gpt-4o-mini",
                "eventCreator": "console-identity", "auditSourceIdentity": "audit-identity",
                "maxRunSeconds": 900}
        with self.assertRaisesRegex(ValueError, "owner graph"):
            missing = copy.deepcopy(deployment)
            del missing["metadata"]["resourceVersion"]
            module.output_phase_two(missing, service, policy, "client-policy-uid", "output-policy-uid",
                                    "document-uid", "prompt-uid", "a" * 64, image, live_profile=live)
        objects, _ = module.output_phase_two(deployment, service, policy, "client-policy-uid",
                                              "output-policy-uid", "document-uid", "prompt-uid",
                                              "a" * 64, image, live_profile=live)
        guard = next(op for op in objects["deployment-json-patch.json"]
                     if op["path"] == "/metadata/resourceVersion")
        self.assertEqual(guard, {"op": "test", "path": "/metadata/resourceVersion",
                                 "value": "12345"})
        changed = copy.deepcopy(deployment)
        changed["metadata"]["resourceVersion"] = "12346"
        # A JSON Patch test must fail before any replace/add against a changed snapshot.
        def check_preconditions(current):
            for op in objects["deployment-json-patch.json"]:
                if op["op"] != "test":
                    continue
                value = current
                for segment in op["path"].split("/")[1:]:
                    value = value[segment.replace("~1", "/").replace("~0", "~")]
                if value != op["value"]:
                    raise ValueError("stale deployment snapshot")
        check_preconditions(deployment)
        with self.assertRaisesRegex(ValueError, "stale deployment snapshot"):
            check_preconditions(changed)

    def test_private_phase_one_owner_and_phase_two_exact_patches(self):
        deployment, service, policy = originals()
        deployment["metadata"]["uid"] = "reviewed-deployment-uid"
        document = b"document-source-seed-32-bytes-0000001"
        prompt = b"prompt-source-seed-32-bytes-000000001"
        first = module.output_phase_one(deployment, document, prompt)
        self.assertEqual(first["output-policy-configmap.json"]["data"]["policy.json"],
                         '{"entries":[],"revision":0,"version":2}')
        self.assertEqual(first["protected-output-journal-configmap.json"]["data"]["receipts.json"],
                         '{"receipts":[],"version":2}')
        slots = [first[f"litellm-output-rule-{index:02d}.json"] for index in range(32)]
        self.assertEqual(len(slots), 32)
        self.assertEqual([slot["metadata"]["name"] for slot in slots],
                         [f"litellm-output-rule-{index:02d}" for index in range(32)])
        self.assertTrue(all(slot["data"] == {"rule.json": ""} and
                            slot["metadata"]["ownerReferences"][0]["uid"] ==
                            "reviewed-deployment-uid" and not slot.get("immutable") for slot in slots))
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
