import copy
import json
import unittest

from render_activation import SOURCE_CONFIGMAP, SOURCE_SHA, render


DEPLOYMENT_UID = "11111111-1111-4111-8111-111111111111"
POLICY_UID = "22222222-2222-4222-8222-222222222222"
IMAGE = "registry.example/voice:reviewed"
APPROVED_IMAGE = "registry.example/voice@sha256:" + "a" * 64
IMAGE_IDS = [APPROVED_IMAGE] * 3
CREATOR = "system:serviceaccount:phorvex:console"


def deployment():
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "voice-bot", "namespace": "voice", "uid": DEPLOYMENT_UID, "resourceVersion": "71"},
            "spec": {"replicas": 3, "template": {"metadata": {"annotations": {"existing": "keep"}},
                                  "spec": {"containers": [{"name": "bot", "image": IMAGE,
                                                           "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                                                           "env": [{"name": "MONGO_URI", "valueFrom": {"secretKeyRef": {"name": "voice-secrets", "key": "mongo"}}}]}]}}}}


def policy():
    return {"kind": "PhorvexPolicy", "metadata": {"name": "voice-defense", "namespace": "voice",
            "uid": POLICY_UID, "resourceVersion": "93"},
            "spec": {"mode": "active", "actions": {"enabled": ["voice-memory-note-revoke", "voice-refund-pair-deny", "rotate"]}}}


def apply_patch(value, operations):
    result = copy.deepcopy(value)
    for operation in operations:
        parts = [part.replace("~1", "/").replace("~0", "~") for part in operation["path"].split("/")[1:]]
        parent = result
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        leaf = parts[-1]
        if operation["op"] == "test":
            actual = parent[int(leaf)] if isinstance(parent, list) else parent[leaf]
            if actual != operation["value"]:
                raise ValueError("stale resource precondition")
        elif leaf == "-":
            parent.append(operation["value"])
        elif isinstance(parent, list):
            parent.insert(int(leaf), operation["value"])
        else:
            parent[leaf] = operation["value"]
    return result


class RenderVoiceMemoryActivationTest(unittest.TestCase):
    def test_preserves_voice_container_and_wires_required_policy(self):
        before = deployment()
        objects = render(before, policy(), b"s" * 48, DEPLOYMENT_UID, POLICY_UID,
                         IMAGE, APPROVED_IMAGE, IMAGE_IDS, 10001, CREATOR)
        self.assertEqual(set(objects), {"source-configmap.json", "policy-configmap.json", "refund-policy-configmap.json",
                                        "state-token-secret.json", "deployment-patch.json"})
        source = objects["source-configmap.json"]
        self.assertTrue(source["immutable"])
        self.assertEqual(source["metadata"]["name"], SOURCE_CONFIGMAP)
        self.assertEqual(set(source["data"]), {"bot.py", "voice_memory_policy.py"})
        rule = json.loads(objects["policy-configmap.json"]["data"]["rule.json"])
        self.assertEqual((rule["deploymentUID"], rule["policyUID"], rule["sourceSHA256"]),
                         (DEPLOYMENT_UID, POLICY_UID, SOURCE_SHA))
        self.assertEqual((rule["revision"], rule["entries"]), (0, []))
        self.assertEqual(json.loads(objects["refund-policy-configmap.json"]["data"]["rule.json"]), rule)

        updated = apply_patch(before, objects["deployment-patch.json"])
        self.assertEqual(updated["spec"]["template"]["metadata"]["annotations"]["existing"], "keep")
        bot = updated["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(bot["image"], APPROVED_IMAGE)
        self.assertEqual(bot["env"][0], before["spec"]["template"]["spec"]["containers"][0]["env"][0])
        self.assertEqual(bot["readinessProbe"], before["spec"]["template"]["spec"]["containers"][0]["readinessProbe"])
        self.assertIn({"name": "VOICE_MEMORY_POLICY_REQUIRED", "value": "true"}, bot["env"])
        self.assertIn({"name": "VOICE_REFUND_POLICY_REQUIRED", "value": "true"}, bot["env"])
        self.assertIn({"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}, bot["env"])
        mounts = {m["mountPath"]: m for m in bot["volumeMounts"]}
        self.assertEqual(mounts["/etc/phorvex/voice-memory-policy"]["readOnly"], True)
        self.assertNotIn("subPath", mounts["/etc/phorvex/voice-memory-policy"])
        self.assertNotIn("subPath", mounts["/etc/phorvex/voice-refund-policy"])
        self.assertEqual(mounts["/etc/phorvex/voice-refund-policy"]["readOnly"], True)
        self.assertEqual(mounts["/app/bot.py"]["subPath"], "bot.py")
        state = updated["spec"]["template"]["spec"]
        self.assertEqual(state["initContainers"][0]["name"], "voice-memory-state-owner")
        self.assertEqual(state["initContainers"][0]["securityContext"]["runAsUser"], 0)
        self.assertEqual(state["volumes"][1]["configMap"]["optional"], True)
        stale = copy.deepcopy(before)
        stale["metadata"]["resourceVersion"] = "72"
        with self.assertRaises(ValueError):
            apply_patch(stale, objects["deployment-patch.json"])

    def test_refuses_wrong_owner_or_existing_mount(self):
        with self.assertRaises(ValueError):
            render(deployment(), policy(), b"s" * 48, "33333333-3333-4333-8333-333333333333",
                   POLICY_UID, IMAGE, APPROVED_IMAGE, IMAGE_IDS, 10001, CREATOR)
        prior = deployment()
        prior["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = [
            {"name": "old", "mountPath": "/etc/phorvex/voice-memory-policy"}]
        with self.assertRaises(ValueError):
            render(prior, policy(), b"s" * 48, DEPLOYMENT_UID, POLICY_UID,
                   IMAGE, APPROVED_IMAGE, IMAGE_IDS, 10001, CREATOR)
        with self.assertRaises(ValueError):
            render(deployment(), policy(), b"s" * 48, DEPLOYMENT_UID, POLICY_UID,
                   IMAGE, APPROVED_IMAGE, IMAGE_IDS[:2] + ["other@sha256:" + "b" * 64], 10001, CREATOR)

    def test_stable_agency_mode_does_not_pin_one_run_to_deployment(self):
        objects = render(deployment(), policy(), b"s" * 48, DEPLOYMENT_UID, POLICY_UID,
                         IMAGE, APPROVED_IMAGE, IMAGE_IDS, 10001, CREATOR, True)
        updated = apply_patch(deployment(), objects["deployment-patch.json"])
        env = updated["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertIn({"name": "VOICE_AGENCY_TEST_ENABLED", "value": "true"}, env)
        self.assertFalse(any(item["name"] == "VOICE_AGENCY_TEST_RUN_ID" for item in env))


if __name__ == "__main__":
    unittest.main()
