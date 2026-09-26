"""Offline synthetic tests for the owned CPU fixture package."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import provision
import render


class FixturePackageTest(unittest.TestCase):
    def plan(self):
        return {
            "namespace": "vllm", "context": "reviewed-dev-context",
            "clusterUID": "11111111-1111-4111-8111-111111111111",
            "proxyImage": "example.invalid/proxy@sha256:" + "a" * 64,
            "supportImage": "example.invalid/support@sha256:" + "b" * 64,
            "modelServiceName": "vllm",
            "modelServiceUID": "22222222-2222-4222-8222-222222222222",
            "modelTargetPodName": "vllm-reviewed",
            "modelTargetPodUID": "33333333-3333-4333-8333-333333333333",
            "modelTargetImageID": "containerd://sha256:" + "c" * 64,
            "modelID": "Qwen/Qwen2.5-7B-Instruct-AWQ",
            "modelAPIKeySecretName": "model-client-secret",
            "modelAPIKeySecretKey": "api-key",
            "eventCreator": "system:serviceaccount:phorvex-system:console-reviewed",
        }

    def package(self, root):
        plan_path = root / "plan-input.json"
        plan_path.write_text(json.dumps(self.plan()))
        marker_path = root / "marker-input"
        marker = "ownedSyntheticMarker_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        marker_path.write_text(marker)
        marker_path.chmod(0o600)
        out = root / "package"
        summary = render.render(plan_path, out, marker_path)
        return out, summary, marker

    def test_render_has_exact_owned_objects_and_private_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            out, summary, marker = self.package(Path(directory))
            plan, checked = provision.load_package(out)
            self.assertEqual(checked["sourceSHA256"], summary["sourceSHA256"])
            self.assertEqual(plan["modelServiceName"], "vllm")
            source = json.loads((out / "source-configmap.json").read_bytes())
            pod = json.loads((out / "fixture-pod.json").read_bytes())
            service = json.loads((out / "fixture-service.json").read_bytes())
            policy = json.loads((out / "fixture-policy.json").read_bytes())
            self.assertTrue(source["immutable"])
            self.assertEqual(set(source["data"]), set(render.SOURCE_FILES))
            self.assertEqual({c["name"] for c in pod["spec"]["containers"]},
                             {"guardrail-proxy", "support-app"})
            proxy_container = next(c for c in pod["spec"]["containers"]
                                   if c["name"] == "guardrail-proxy")
            self.assertEqual(proxy_container["workingDir"], "/src")
            self.assertEqual(next(e["value"] for e in proxy_container["env"]
                                  if e["name"] == "PYTHONPATH"), "/src")
            self.assertGreaterEqual(proxy_container["readinessProbe"]["timeoutSeconds"], 3)
            self.assertEqual(pod["spec"]["automountServiceAccountToken"], False)
            self.assertNotIn("app=vllm", json.dumps(pod))
            self.assertEqual(service["spec"]["selector"][render.LABEL], "true")
            volumes = {v["name"]: v for v in pod["spec"]["volumes"]}
            self.assertTrue(volumes["output-policy"]["configMap"]["optional"])
            self.assertEqual(volumes["output-policy"]["configMap"]["name"],
                             render.POLICY_CM_NAME)
            support = next(c for c in pod["spec"]["containers"] if c["name"] == "support-app")
            self.assertEqual(support["command"][-1], "/src/support_fixture.py")
            self.assertIn("127.0.0.1:8002/v1/support/state",
                          support["readinessProbe"]["exec"]["command"][-1])
            self.assertIn("127.0.0.1",
                          support["livenessProbe"]["exec"]["command"][-1])
            self.assertGreaterEqual(support["readinessProbe"]["timeoutSeconds"], 3)
            self.assertNotIn("httpGet", support["readinessProbe"])
            self.assertNotIn("tcpSocket", support["livenessProbe"])
            env = {e["name"]: e for e in support["env"]}
            self.assertEqual(env["SUPPORT_FIXTURE_MODEL_URL"]["value"],
                             "http://vllm.vllm.svc:8000")
            self.assertEqual(env["SUPPORT_FIXTURE_MARKER_FILE"]["value"],
                             render.PRIVATE_MARKER_PATH)
            self.assertEqual(policy["spec"]["selector"]["matchLabels"],
                             {render.LABEL: "true"})
            self.assertEqual(policy["spec"]["mode"], "active")
            self.assertIn("sensitive-output-policy-activate", policy["spec"]["actions"]["enabled"])
            self.assertGreater(len(policy["spec"]["actions"]["enabled"]), 1)
            for name in summary["files"]:
                self.assertEqual((out / name).stat().st_mode & 0o077, 0)
                if name != "marker-secret.json":
                    self.assertNotIn(marker, (out / name).read_text())

    def test_default_provision_mode_performs_no_api_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            out, _, _ = self.package(Path(directory))
            with mock.patch.object(sys, "argv", ["provision.py", "--package", str(out)]), \
                    mock.patch.object(provision.subprocess, "run",
                                      side_effect=AssertionError("kubectl called")), \
                    contextlib.redirect_stdout(io.StringIO()) as captured:
                provision.main()
            self.assertEqual(json.loads(captured.getvalue())["status"], "validated-no-api-calls")

    def test_tampered_source_or_unpinned_image_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out, _, _ = self.package(root)
            pod_path = out / "fixture-pod.json"
            pod = json.loads(pod_path.read_bytes())
            pod["spec"]["containers"][0]["image"] = "python:latest"
            pod_path.write_bytes(render.canonical(pod))
            with self.assertRaises(ValueError):
                provision.load_package(out)
            plan = self.plan()
            plan["proxyImage"] = "python:latest"
            with self.assertRaises(ValueError):
                render.validate_plan(plan)

    def test_two_phase_provisioning_binds_pod_and_configmap_uids(self):
        class FakeKubectl:
            last = None
            def __init__(self, _kubeconfig, _context):
                type(self).last = self
                self.objects = {}
                self.created = []
                self.patches = []
                self.next_uid = 1

            def _key(self, kind, name):
                return (kind.lower(), name)

            def absent(self, kind, name, namespace="vllm"):
                assert self._key(kind, name) not in self.objects

            def _create(self, value):
                item = copy.deepcopy(value)
                kind = item["kind"].lower()
                name = item["metadata"]["name"]
                key = self._key(kind, name)
                assert key not in self.objects
                item["metadata"]["uid"] = f"{self.next_uid:08x}-1111-4111-8111-111111111111"
                item["metadata"]["resourceVersion"] = "1"
                if kind == "phorvexpolicy":
                    item["metadata"]["generation"] = 1
                if kind == "pod":
                    item["status"] = {"containerStatuses": [
                        {"name": "guardrail-proxy", "ready": True,
                         "imageID": "containerd://sha256:" + "a" * 64},
                        {"name": "support-app", "ready": True,
                         "imageID": "containerd://sha256:" + "b" * 64},
                    ]}
                self.next_uid += 1
                self.objects[key] = item
                self.created.append(key)

            def create_file(self, path):
                self._create(json.loads(Path(path).read_bytes()))

            def create_object(self, value):
                self._create(value)

            def get(self, kind, name, namespace="vllm"):
                return copy.deepcopy(self.objects[self._key(kind, name)])

            def patch(self, kind, name, uid, resource_version, operations):
                item = self.objects[self._key(kind, name)]
                assert item["metadata"]["uid"] == uid
                assert item["metadata"]["resourceVersion"] == resource_version
                for operation in operations:
                    keys = [part.replace("~1", "/").replace("~0", "~")
                            for part in operation["path"].split("/")[1:]]
                    parent = item
                    for key in keys[:-1]:
                        parent = parent[key]
                    if operation["op"] == "test":
                        assert parent[keys[-1]] == operation["value"]
                    else:
                        parent[keys[-1]] = operation["value"]
                item["metadata"]["resourceVersion"] = str(int(resource_version) + 1)
                self.patches.append((kind, name, operations))

            def call(self, *args, **_kwargs):
                assert args[2:4] == ("wait", "--for=condition=Ready")
                return ""

        with tempfile.TemporaryDirectory() as directory:
            out, _, marker = self.package(Path(directory))
            with mock.patch.object(provision, "Kubectl", FakeKubectl), \
                    mock.patch.object(provision, "_model_preflight"), \
                    contextlib.redirect_stdout(io.StringIO()) as captured:
                provision.provision(out, Path("/fake/kubeconfig"), self.plan()["context"],
                                    self.plan()["clusterUID"])
            fake = FakeKubectl.last
            self.assertEqual(fake.created, [
                ("configmap", render.SOURCE_NAME), ("secret", render.MARKER_SECRET_NAME),
                ("pod", render.POD_NAME), ("configmap", render.POLICY_CM_NAME),
                ("service", render.SERVICE_NAME), ("phorvexpolicy", render.POD_NAME)])
            pod = fake.get("pod", render.POD_NAME)
            cm = fake.get("configmap", render.POLICY_CM_NAME)
            self.assertEqual(cm["metadata"]["ownerReferences"][0]["uid"], pod["metadata"]["uid"])
            activation = json.loads(cm["data"]["activation.json"])
            self.assertEqual(activation, {"version": 1,
                "ruleId": "support-internal-audit-marker-v1", "configMapUID": cm["metadata"]["uid"],
                "active": False, "revision": 0, "operationId": ""})
            self.assertIn("phorvex.ai/output-policy-rule-sha256", pod["metadata"]["annotations"])
            self.assertNotIn(marker, captured.getvalue())
            pins = json.loads((out / "runtime-pins.json").read_bytes())
            self.assertEqual(pins["podUID"], pod["metadata"]["uid"])
            self.assertEqual(pins["outputPolicyConfigMapUID"], cm["metadata"]["uid"])


if __name__ == "__main__":
    unittest.main()
