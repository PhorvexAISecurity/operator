import copy
from pathlib import Path
import unittest

from policy import LEGACY_FILES, PolicyUnavailable, canonical, digest
from render_activation import prepare, new_policy, deployment_patch, LEGACY_PATHS
from test_runtime import fixture


class ActivationTest(unittest.TestCase):
    def setUp(self):
        pins, self.profile, _ = fixture()
        uid = pins.deployment_uid
        self.owner = [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "voice-bot", "uid": uid, "controller": True}]
        self.dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "voice-bot", "namespace": "voice",
            "uid": uid, "resourceVersion": "10"}, "spec": {"template": {"metadata": {"annotations": {"legacy": "unchanged"}},
            "spec": {"containers": [{"name": "bot", "command": ["python3", "-B", "/app/bot.py"], "image": "legacy-digest",
                "envFrom": [{"secretRef": {"name": "voice-secrets"}}], "env": [
                    {"name": "PUBLIC_HOST", "value": "voicebot.phorvex.ai"},
                    {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                    {"name": "VOICE_MEMORY_POLICY_REQUIRED", "value": "true"}],
                "volumeMounts": [{"name": "old-source", "mountPath": "/app/bot.py", "subPath": "bot.py", "readOnly": True}]}],
                "volumes": [{"name": "old-source", "configMap": {"name": "old-exact-source"}}]}}}}
        data = {name: (Path(__file__).parent.parent / "voice-memory" / name).read_text() for name in LEGACY_FILES}
        sha = digest(b"\0".join(data[name].encode() for name in LEGACY_FILES))
        self.legacy = {"kind": "ConfigMap", "metadata": {"namespace": "voice", "name": "voice-memory-source-" + sha[:12],
            "uid": pins.wrapper_cm_uid, "resourceVersion": "11", "ownerReferences": self.owner}, "immutable": True, "data": data}
        self.security = {"kind": "PhorvexPolicy", "metadata": {"namespace": "voice", "name": "voice-defense", "uid": pins.security_policy_uid}}
        self.ingress = {"kind": "Ingress", "metadata": {"namespace": "voice", "name": "voice-bot-public"}, "spec": {"rules": [
            {"host": "voicebot.phorvex.ai", "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {
                "service": {"name": "voice-bot", "port": {"number": 8080}}}}]}}]}}

    def prepared(self):
        return prepare(self.dep, self.legacy, self.security, self.ingress, canonical(self.profile))

    def test_phased_patch_preserves_legacy_and_scopes_get_only_runtime_authority(self):
        cm, state, rbac = self.prepared()
        self.assertEqual(set(cm["data"]), {"entry.py", "policy.py", "auth-profile.json"})
        self.assertEqual(rbac[1]["rules"], [{"apiGroups": [""], "resources": ["configmaps"],
                                          "resourceNames": ["voice-session-admission-policy"], "verbs": ["get"]}])
        wrapper = copy.deepcopy(cm)
        wrapper["metadata"].update(uid="00000000-0000-4000-8000-000000000006", resourceVersion="12")
        desired = new_policy(self.dep, wrapper, cm, state)
        policy = copy.deepcopy(desired)
        policy["metadata"].update(uid="00000000-0000-4000-8000-000000000007", resourceVersion="13")
        before = copy.deepcopy(self.dep["spec"]["template"])
        patch = deployment_patch(self.dep, wrapper, policy, desired, state,
                                 "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + "c" * 64,
                                 "system:serviceaccount:phorvex-system:reviewed-console")
        self.assertEqual([p["op"] for p in patch], ["test", "test", "test", "replace"])
        self.assertEqual(patch[2]["value"], before)
        after = patch[3]["value"]
        old_bot, new_bot = before["spec"]["containers"][0], after["spec"]["containers"][0]
        self.assertEqual(new_bot["env"][:len(old_bot["env"])], old_bot["env"])
        self.assertEqual(new_bot["envFrom"], old_bot["envFrom"])
        self.assertEqual(new_bot["volumeMounts"][:len(old_bot["volumeMounts"])], old_bot["volumeMounts"])
        self.assertEqual(after["metadata"]["annotations"]["legacy"], "unchanged")
        self.assertEqual(self.dep["spec"]["template"], before)
        self.assertEqual(new_bot["command"], ["python3", "-B", "/opt/voice-admission/entry.py"])
        for name, value in LEGACY_PATHS.items():
            self.assertEqual([e for e in new_bot["env"] if e["name"] == name], [{"name": name, "value": value}])

    def test_explicit_legacy_path_drift_duplicates_and_indirection_refuse(self):
        cm, state, _ = self.prepared()
        wrapper = copy.deepcopy(cm)
        wrapper["metadata"].update(uid="00000000-0000-4000-8000-000000000006", resourceVersion="12")
        desired = new_policy(self.dep, wrapper, cm, state)
        policy = copy.deepcopy(desired)
        policy["metadata"].update(uid="00000000-0000-4000-8000-000000000007", resourceVersion="13")
        for name, value in LEGACY_PATHS.items():
            for entries in ([{"name": name, "value": "/wrong"}],
                            [{"name": name, "valueFrom": {"secretKeyRef": {"name": "voice-secrets", "key": name}}}],
                            [{"name": name, "value": value}] * 2):
                dep = copy.deepcopy(self.dep)
                dep["spec"]["template"]["spec"]["containers"][0]["env"].extend(entries)
                with self.assertRaises(PolicyUnavailable):
                    deployment_patch(dep, wrapper, policy, desired, state,
                                     "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + "c" * 64,
                                     "system:serviceaccount:phorvex-system:reviewed-console")

    def test_source_url_owner_or_existing_activation_drift_is_rejected(self):
        for change in ("source", "owner", "ingress", "existing", "token-override"):
            dep, legacy, ingress = copy.deepcopy(self.dep), copy.deepcopy(self.legacy), copy.deepcopy(self.ingress)
            if change == "source":
                legacy["data"]["bot.py"] += "\n# changed"
            elif change == "owner":
                legacy["metadata"]["ownerReferences"][0]["uid"] = "unreviewed"
            elif change == "ingress":
                ingress["spec"]["rules"][0]["host"] = "wrong.example"
            elif change == "existing":
                dep["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "VOICE_ADMISSION_SOURCE_SHA256", "value": "self-selected"})
            else:
                dep["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "TWILIO_AUTH_TOKEN", "value": "override"})
            with self.assertRaises(PolicyUnavailable, msg=change):
                prepare(dep, legacy, self.security, ingress, canonical(self.profile))
