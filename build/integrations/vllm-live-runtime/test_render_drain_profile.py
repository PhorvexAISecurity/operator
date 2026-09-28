"""The opt-in profile can be rendered before its own console Pod rolls."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from render_drain_profile import COMPLETION_SHA, ENGINE_SHA, main, render as render_current

def render(*args, **kwargs):
    return render_current(*args, **kwargs, legacy_v1=True)
from test_render_guardrail_profile import lease_fixture


UID = "11111111-1111-4111-8111-111111111111"
IMAGE = "repo.invalid/image@sha256:" + "a" * 64


def pod(name, namespace, containers):
    return {"metadata": {"name": name, "namespace": namespace, "uid": UID,
                         "labels": {"app": "vllm", "phorvex.ai/serving": "true"},
                         "annotations": {"phorvex.ai/drain-proxy-source": "b" * 64,
                                         "phorvex.ai/drain-engine-source": "c" * 64}},
            "status": {"containerStatuses": [{"name": item, "ready": True, "restartCount": 0,
                                               "imageID": IMAGE, "containerID": "containerd://" + "d" * 64}
                                              for item in containers]}}


def inputs():
    return {"cluster": {"metadata": {"name": "kube-system", "uid": UID}},
            "pod": pod("vllm-0", "vllm", ["vllm", "guardrail"]),
            "service": {"metadata": {"name": "vllm", "namespace": "vllm", "uid": UID},
                        "spec": {"selector": {"app": "vllm"}, "ports": [{"port": 8000, "protocol": "TCP", "targetPort": 8000}]}},
            "policy": {"metadata": {"name": "vllm-defense", "namespace": "vllm", "uid": UID, "generation": 4},
                       "spec": {"mode": "active", "selector": {"matchLabels": {"app": "vllm"}},
                                "actions": {"enabled": ["request-drain"]}}},
            "manager": pod("manager-0", "phorvex-system", ["manager"]),
            "console": pod("console-old", "phorvex-system", ["console"]),
            "console_deployment": {"kind": "Deployment", "metadata": {"name": "phorvex-phorvex-console",
                                                                "namespace": "phorvex-system", "uid": UID}},
            "sources": {"serving_completion.py": COMPLETION_SHA, "serving_engine.py": ENGINE_SHA}}


def leased_inputs():
    objects, retained = lease_fixture()
    objects["pod"]["metadata"]["labels"]["phorvex.ai/serving"] = "true"
    objects["pod"]["metadata"]["annotations"].update({
        "phorvex.ai/drain-proxy-source": "b" * 64,
        "phorvex.ai/drain-engine-source": "c" * 64})
    objects["policy"]["spec"]["actions"]["enabled"].append("request-drain")
    objects["sources"] = {"serving_completion.py": COMPLETION_SHA,
                          "serving_engine.py": ENGINE_SHA}
    return objects, retained


class DrainProfileRender(unittest.TestCase):
    def test_historical_restart_requires_current_container_identity(self):
        objects = inputs()
        guard = next(row for row in objects["pod"]["status"]["containerStatuses"]
                     if row["name"] == "guardrail")
        guard["restartCount"] = 1
        raw, _ = render(objects, "dev-test", "https://audit.invalid|audit.invalid")
        self.assertEqual(json.loads(raw)["proxyContainerID"], guard["containerID"])
        for invalid in (-1, True, None, "1"):
            with self.subTest(restart_count=invalid):
                guard["restartCount"] = invalid
                with self.assertRaises(ValueError):
                    render(objects, "dev-test", "reviewed-audit")
        guard["restartCount"] = 1
        guard["containerID"] = ""
        with self.assertRaises(ValueError):
            render(objects, "dev-test", "reviewed-audit")

    def test_self_rollout_has_no_future_pod_pin(self):
        raw, values = render(inputs(), "dev-test", "https://audit.invalid|audit.invalid")
        profile = json.loads(raw)
        self.assertNotIn("consolePodUID", profile)
        self.assertNotIn("consoleContainerID", profile)
        self.assertEqual(profile["consoleDeploymentUID"], UID)
        self.assertFalse(values["phorvex"]["phorvex"]["console"]["drainLive"]["enabled"])

    def test_route_or_source_drift_refused(self):
        bad = inputs()
        bad["service"]["spec"]["selector"] = {"missing": "label"}
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")
        bad = inputs()
        bad["service"]["spec"]["ports"][0]["targetPort"] = 8001
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")
        bad = inputs()
        bad["sources"]["serving_engine.py"] = "e" * 64
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")

    def test_leased_target_requires_exact_retained_authority(self):
        objects, retained = leased_inputs()
        audit = json.loads(retained)["auditSourceIdentity"]
        raw, _ = render(objects, "dev-test", audit, retained)
        self.assertEqual(json.loads(raw)["retainedCallerLeaseProfileSHA256"],
                         hashlib.sha256(retained).hexdigest())
        self.assertNotIn("clientBSHA256", json.loads(raw))
        with self.assertRaises(ValueError): render(objects, "dev-test", audit)
        with self.assertRaises(ValueError): render(objects, "dev-test", "different-audit", retained)
        absent = copy.deepcopy(objects)
        del absent["source"]
        with self.assertRaises(ValueError): render(absent, "dev-test", audit, retained)

    def test_nonleased_target_rejects_retained_authority(self):
        objects = inputs()
        with self.assertRaises(ValueError): render(objects, "dev-test", "reviewed-audit", b"{}")
        objects["pod"]["metadata"]["annotations"]["phorvex.ai/endpoint-lease-source-sha256"] = ""
        with self.assertRaises(ValueError): render(objects, "dev-test", "reviewed-audit")

    def test_retained_profile_identity_and_installed_projection_mismatch(self):
        objects, retained = leased_inputs()
        audit = json.loads(retained)["auditSourceIdentity"]
        wrong_uid = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        for field, value in (("serviceUID", wrong_uid), ("sourceConfigMapUID", wrong_uid),
                             ("policyUID", wrong_uid), ("proxyImage", "different-image"),
                             ("policyGeneration", 999)):
            with self.subTest(field=field):
                altered = json.loads(retained)
                altered[field] = value
                changed = json.dumps(altered, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaises(ValueError): render(objects, "dev-test", audit, changed)
        changed = copy.deepcopy(objects)
        changed["pod"]["metadata"]["annotations"]["phorvex.ai/endpoint-lease-source-sha256"] = "f" * 64
        with self.assertRaises(ValueError): render(changed, "dev-test", audit, retained)
        changed = copy.deepcopy(objects)
        console_spec = changed["console"]["spec"]["containers"][0]
        next(row for row in console_spec["env"] if row["name"] == "PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256")["value"] = "f" * 64
        with self.assertRaises(ValueError): render(changed, "dev-test", audit, retained)

    def test_cli_requires_exact_retained_profile_bytes(self):
        objects, retained = leased_inputs()
        audit = json.loads(retained)["auditSourceIdentity"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = ["render_drain_profile.py", "--legacy-v1"]
            for key, value in objects.items():
                path = root / (key + ".json")
                path.write_text(json.dumps(value))
                arguments.extend(("--" + key.replace("_", "-"), str(path)))
            profile_path = root / "retained.json"
            profile_path.write_bytes(retained)
            arguments.extend(("--context", "dev-test", "--audit-source-identity", audit,
                              "--retained-caller-lease-profile", str(profile_path),
                              "--retained-caller-lease-profile-sha256", "0" * 64,
                              "--out", str(root / "output")))
            with patch.object(sys, "argv", arguments), self.assertRaisesRegex(ValueError, "byte/hash drift"):
                main()
            arguments[-3] = hashlib.sha256(retained).hexdigest()
            with patch.object(sys, "argv", arguments):
                main()
            rendered = json.loads((root / "output" / "profile.json").read_bytes())
            self.assertEqual(rendered["retainedCallerLeaseProfileSHA256"], arguments[-3])


class DrainProfileV2(unittest.TestCase):
    def objects(self):
        value = inputs()
        value["manager"]["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "manager-rs", "uid": UID, "controller": True}]
        value["manager_replicaset"] = {"kind": "ReplicaSet", "metadata": {"name": "manager-rs", "uid": UID, "namespace": "phorvex-system", "ownerReferences": [{"kind": "Deployment", "name": "phorvex-phorvex", "uid": UID, "controller": True}]}}
        value["manager_deployment"] = {"kind": "Deployment", "metadata": {"name": "phorvex-phorvex", "uid": UID, "namespace": "phorvex-system", "generation": 1}, "spec": {"replicas": 1}, "status": {"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
        return value

    def test_component_releases_leave_target_profile_bytes_unchanged(self):
        objects = self.objects()
        before, _ = render_current(objects, "dev-test", "reviewed-audit")
        objects["manager"]["metadata"]["uid"] = "22222222-2222-4222-8222-222222222222"
        objects["manager"]["metadata"]["name"] = "replacement-manager"
        for component in ("manager", "console"):
            objects[component]["status"]["containerStatuses"][0]["imageID"] = "repo.invalid/next@sha256:" + "e" * 64
            objects[component]["status"]["containerStatuses"][0]["containerID"] = "containerd://replacement"
        after, _ = render_current(objects, "dev-test", "reviewed-audit")
        self.assertEqual(before, after)
        profile = json.loads(after)
        self.assertEqual(profile["schema"], "live-request-drain-v2")
        self.assertEqual(profile["managerDeploymentUID"], UID)
        for name in ("managerPodUID", "managerContainerID", "managerImageID", "consoleImageID"):
            self.assertNotIn(name, profile)
        self.assertEqual(profile["podUID"], UID)
        self.assertEqual(profile["drainEngineSourceSHA256"], "c" * 64)

    def test_unsettled_wrong_owner_or_missing_originals_refuse(self):
        for change in (lambda o: o.pop("manager_deployment"),
                       lambda o: o["manager_deployment"]["status"].update(observedGeneration=0),
                       lambda o: o["manager_replicaset"]["metadata"]["ownerReferences"][0].update(uid="foreign")):
            objects = self.objects()
            change(objects)
            with self.assertRaises((ValueError, KeyError)):
                render_current(objects, "dev-test", "reviewed-audit")


if __name__ == "__main__":
    unittest.main()
