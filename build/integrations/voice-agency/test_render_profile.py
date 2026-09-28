"""Installation preflight rejects source and identity substitution."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from render_profile import ROOT, SOURCE_SHA, CREATOR, CLIPS, canonical, render, sha


def fixture():
    dep_uid = "11111111-1111-1111-1111-111111111111"
    policy_uid = "22222222-2222-2222-2222-222222222222"
    rs_uid = "33333333-3333-3333-3333-333333333333"
    def obj(kind, ns, name, uid="44444444-4444-4444-4444-444444444444"):
        return {"kind": kind, "metadata": {"namespace": ns, "name": name, "uid": uid, "resourceVersion": "1"}}
    def owner(kind, name, uid):
        return [{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}]
    source = obj("ConfigMap", "voice", "voice-memory-source-reviewed")
    source["metadata"]["ownerReferences"] = owner("Deployment", "voice-bot", dep_uid)
    source.update(immutable=True, data={name: (ROOT / "build/integrations/voice-memory" / name).read_text()
                                        for name in ("bot.py", "voice_memory_policy.py")})
    mounts = [{"name": "source", "mountPath": "/app/" + name, "readOnly": True, "subPath": name}
              for name in ("bot.py", "voice_memory_policy.py")]
    mounts.append({"name": "rule", "mountPath": "/etc/phorvex/voice-refund-policy", "readOnly": True})
    spec = {"containers": [{"name": "bot", "image": "reviewed@sha256:" + "a" * 64,
                            "command": ["python3", "-B", "/app/bot.py"], "volumeMounts": mounts,
                            "env": [{"name": n, "value": "true"} for n in
                                    ("VOICE_REFUND_POLICY_REQUIRED", "VOICE_AGENCY_TEST_ENABLED")]}],
            "volumes": [{"name": "source", "configMap": {"name": source["metadata"]["name"]}},
                        {"name": "rule", "configMap": {"name": "voice-refund-policy"}}]}
    annotations = {"phorvex.ai/voice-refund-source-sha256": SOURCE_SHA,
                   "phorvex.ai/voice-refund-policy-configmap": "voice-refund-policy",
                   "phorvex.ai/voice-refund-event-creator": CREATOR}
    dep = obj("Deployment", "voice", "voice-bot", dep_uid)
    dep["spec"] = {"replicas": 1, "selector": {"matchLabels": {"app": "bot"}},
                   "template": {"metadata": {"annotations": annotations}, "spec": spec}}
    policy = obj("PhorvexPolicy", "voice", "voice-defense", policy_uid)
    policy["spec"] = {"mode": "active", "actions": {"enabled": ["voice-refund-pair-deny", "noop"]}}
    rule = obj("ConfigMap", "voice", "voice-refund-policy")
    rule["metadata"]["ownerReferences"] = owner("Deployment", "voice-bot", dep_uid)
    rule["data"] = {"rule.json": canonical({"version": 1, "deploymentUID": dep_uid, "policyUID": policy_uid,
                                           "sourceSHA256": SOURCE_SHA, "revision": 0,
                                           "operationId": "", "entries": []}).decode()}
    pod = obj("Pod", "voice", "voice-bot-reviewed")
    pod["metadata"].update(labels={"app": "bot"}, annotations=deepcopy(annotations),
                           ownerReferences=owner("ReplicaSet", "voice-bot-rs", rs_uid))
    pod["spec"] = deepcopy(spec)
    pod["status"] = {"phase": "Running", "podIP": "10.0.0.1", "conditions": [{"type": "Ready", "status": "True"}],
                     "containerStatuses": [{"name": "bot", "ready": True, "containerID": "containerd://reviewed",
                                            "imageID": "reviewed@sha256:" + "a" * 64}]}
    rs = obj("ReplicaSet", "voice", "voice-bot-rs", rs_uid)
    rs["metadata"]["ownerReferences"] = owner("Deployment", "voice-bot", dep_uid)
    console = obj("Deployment", "phorvex-system", "phorvex-phorvex-console")
    console["spec"] = {"template": {"spec": {"serviceAccountName": "phorvex-phorvex-console", "containers": [{
        "name": "console", "args": ["-audit-source-url=https://audit.example:8445",
                                     "-audit-source-server-dns=audit.example"]}]}}}
    return [dep, policy, source, rule, {"items": [pod]}, {"items": [rs]}, console]


class RefundProfileTest(unittest.TestCase):
    def test_spoken_fixture_copies_and_all_fixed_pins_agree(self):
        for phase, digest in CLIPS.items():
            with self.subTest(phase=phase):
                integration_name = phase.replace("_", "-")
                integration = (ROOT / "build/integrations/voice-agency/audio" /
                               (integration_name + ".ulaw")).read_bytes()
                embedded = (ROOT / "phorvex/internal/console" /
                            ("voice_agency_" + phase + ".ulaw")).read_bytes()
                self.assertEqual(integration, embedded)
                self.assertEqual(sha(integration), digest)
                self.assertLessEqual(len(integration), 65536)

    def test_exact_profile_and_journal_owner_pin(self):
        objects = fixture()
        raw, cm, digest, values = render(*objects)
        profile = json.loads(raw)
        self.assertEqual(set(profile), {"version", "sourceSHA256", "probeSHA256", "attackClipSHA256",
                                       "benignClipSHA256", "policyName", "eventCreator",
                                       "auditSourceIdentity", "maxRunSeconds"})
        self.assertEqual(digest, sha(raw))
        self.assertEqual(raw, canonical(profile))
        self.assertEqual(cm["data"]["profile.json"], raw.decode())
        self.assertTrue(cm["immutable"])
        self.assertEqual(profile["auditSourceIdentity"], "https://audit.example:8445|audit.example")
        self.assertEqual(profile["probeSHA256"], sha((ROOT / "phorvex/internal/console/voice_agency_probe.py").read_bytes()))
        self.assertIn(objects[0]["metadata"]["uid"].encode(), values)

    def test_substituted_source_owner_scope_and_audit_refuse(self):
        mutations = [
            lambda a: a[2]["data"].update({"bot.py": a[2]["data"]["bot.py"] + "\n# substituted"}),
            lambda a: a[2]["metadata"]["ownerReferences"][0].update(uid=a[1]["metadata"]["uid"]),
            lambda a: a[3]["metadata"]["ownerReferences"][0].update(uid=a[1]["metadata"]["uid"]),
            lambda a: a[4]["items"][0]["metadata"]["annotations"].update({"phorvex.ai/voice-refund-event-creator": "wrong"}),
            lambda a: a[4]["items"][0]["spec"]["containers"][0]["env"][1].update(value="false"),
            lambda a: a[4]["items"][0]["spec"]["volumes"][0]["configMap"].update(name="wrong-source"),
            lambda a: a[5]["items"][0]["metadata"]["ownerReferences"][0].update(uid=a[1]["metadata"]["uid"]),
            lambda a: a[0]["spec"].update(replicas=2),
            lambda a: a[6]["spec"]["template"]["spec"].update(serviceAccountName="other-console"),
            lambda a: a[6]["spec"]["template"]["spec"]["containers"][0]["args"].append("-audit-source-url=https://other:8445"),
            lambda a: a[6]["spec"]["template"]["spec"]["containers"][0]["args"].__setitem__(1, "-audit-source-server-dns=other.example"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                objects = fixture()
                mutate(objects)
                with self.assertRaises(ValueError):
                    render(*objects)

    def test_reviewed_source_and_all_five_clips(self):
        paths = ["build/integrations/voice-memory/" + name for name in ("bot.py", "voice_memory_policy.py")]
        paths += ["phorvex/internal/console/voice_agency_" + name for name in
                  ("probe.py", "attack.ulaw", "benign.ulaw", "own_control.ulaw",
                   "confirm_other.ulaw", "confirm_own.ulaw")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for rel in paths:
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, target)
            for rel in paths[:2] + paths[3:]:
                with self.subTest(path=rel):
                    target = root / rel
                    original = target.read_bytes()
                    target.write_bytes(original + b"x")
                    with self.assertRaises(ValueError):
                        render(*fixture(), root=root)
                    target.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
