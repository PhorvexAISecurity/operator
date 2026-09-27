"""Exact offline guards for the existing guardrail-effect profile renderer."""

import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("render_guardrail_profile", HERE / "render_guardrail_profile.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


def uid(n):
    return f"{n:08x}-0000-4000-8000-000000000000"


def obj(kind, name, namespace, n, **more):
    return {"apiVersion": "v1", "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "uid": uid(n), **more}}


def fixture():
    cluster = obj("Namespace", "kube-system", None, 1)
    pod = obj("Pod", "vllm-abc", "vllm", 2,
              labels={"app": "vllm", "phorvex.ai/role": "leader", "phorvex.ai/guardrail-tier": "true"},
              annotations={"phorvex.ai/guardrail-variant": "pgv1",
                           "phorvex.ai/guardrail-variants": "pgv1,pgv2"})
    vllm = {"name": "vllm", "image": "example/vllm@sha256:" + "1" * 64,
            "args": ["--model", renderer.MODEL, "--port", "8001", "--host", "127.0.0.1"],
            "env": [{"name": "VLLM_API_KEY", "valueFrom": {"secretKeyRef": {"name": "vllm-control", "key": "api-key"}}}]}
    guard = {"name": "guardrail", "image": "example/guard@sha256:" + "2" * 64,
             "command": ["sh", "-c", "exec python /src/dual_server.py"],
             "env": [{"name": name, "valueFrom": {"secretKeyRef": {"name": "vllm-control", "key": key}}}
                     for name, key in (("VLLM_API_KEY", "api-key"), ("PHORVEX_GUARDRAIL_ADMIN_KEY", "admin-bearer"))],
             "volumeMounts": [{"name": "source", "mountPath": "/src"}]}
    pod["spec"] = {"containers": [vllm, guard], "volumes": [{"name": "source", "configMap": {"name": "guardrail-proxy"}}]}
    pod["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                     "containerStatuses": [{"name": c["name"], "image": c["image"],
                                            "imageID": c["image"], "containerID": "containerd://" + c["name"],
                                            "restartCount": 0, "ready": True} for c in pod["spec"]["containers"]]}
    service = obj("Service", "vllm", "vllm", 3)
    service["spec"] = {"selector": {"phorvex.ai/role": "leader"},
                       "ports": [{"port": 8000, "protocol": "TCP", "targetPort": 8000}]}
    slices = {"kind": "List", "metadata": {}, "items": [{"kind": "EndpointSlice",
        "metadata": {"name": "vllm-abc", "namespace": "vllm", "uid": uid(4),
                     "labels": {"kubernetes.io/service-name": "vllm"},
                     "ownerReferences": [{"controller": True, "kind": "Service", "name": "vllm", "uid": service["metadata"]["uid"]}]},
        "ports": [{"name": "", "port": 8000, "protocol": "TCP"}],
        "endpoints": [{"targetRef": {"kind": "Pod", "name": "vllm-abc", "uid": pod["metadata"]["uid"]},
                       "conditions": {"ready": True, "serving": True, "terminating": False}}]}]}
    source = obj("ConfigMap", "guardrail-proxy", "vllm", 5)
    source["data"] = {"guardrail_proxy.py": renderer.PROXY.read_text(),
                      "dual_server.py": renderer.DUAL.read_text()}
    for key in renderer.DRAIN_SOURCE_SHA256:
        source["data"][key] = (renderer.PROXY.parent / key).read_text() if (renderer.PROXY.parent / key).exists() else "fixture-" + key
    policy = obj("PhorvexPolicy", "vllm-defense", "vllm", 6, generation=12)
    policy["spec"] = {"mode": "active", "actions": {"enabled": ["rotate", "guardrail-rotate"]},
                      "triggers": {"eventDriven": True}, "selector": {"matchLabels": {"app": "vllm"}}}
    policy["status"] = {"observedGeneration": 12}
    manager = obj("Pod", "phorvex-phorvex-abc", "phorvex-system", 7,
                  labels={"app.kubernetes.io/component": "manager", "app.kubernetes.io/name": "phorvex",
                          "app.kubernetes.io/instance": "phorvex"},
                  ownerReferences=[{"controller": True, "kind": "ReplicaSet", "name": "phorvex-phorvex-rs", "uid": uid(11)}])
    manager["spec"] = {"serviceAccountName": "phorvex-phorvex-manager", "containers": [
        {"name": "manager", "image": renderer.PHORVEX_IMAGE_REPO + "@sha256:" + "3" * 64}]}
    manager["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                         "containerStatuses": [{"name": "manager", "image": "sha256:" + "5" * 64,
                                                "imageID": renderer.PHORVEX_IMAGE_REPO + "@sha256:" + "3" * 64,
                                                "containerID": "containerd://manager", "ready": True, "restartCount": 0}]}
    audit_args = ["-audit-source-url=https://phorvex-phorvex-audit-source.phorvex-system.svc:8445",
                  "-audit-source-server-dns=phorvex-phorvex-audit-source.phorvex-system.svc",
                  "-audit-source-client-cert=/etc/audit-client/tls.crt",
                  "-audit-source-client-key=/etc/audit-client/tls.key",
                  "-audit-source-ca=/etc/audit-client/ca.crt"]
    console_c = {"name": "console", "image": "example/console:v1", "args": audit_args,
                 "volumeMounts": [{"name": "audit", "mountPath": "/etc/audit-client", "readOnly": True},
                                  {"name": "token", "mountPath": "/etc/phorvex-catalogue-v1", "readOnly": True}]}
    console = obj("Pod", "console-abc", "phorvex-system", 8,
                  labels={"app.kubernetes.io/component": "console"},
                  ownerReferences=[{"controller": True, "kind": "ReplicaSet", "name": "console-rs", "uid": uid(9)}])
    console["spec"] = {"serviceAccountName": "phorvex-console", "containers": [console_c],
                       "volumes": [{"name": "audit", "secret": {"secretName": "audit-client"}},
                                   {"name": "token", "secret": {"secretName": "scoped-token"}}]}
    console["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                         "containerStatuses": [{"name": "console", "image": "example/console:v1",
                                                "imageID": "example/console@sha256:" + "4" * 64,
                                                "containerID": "containerd://console", "ready": True, "restartCount": 0}]}
    rs = obj("ReplicaSet", "console-rs", "phorvex-system", 9,
             ownerReferences=[{"controller": True, "kind": "Deployment", "name": "console", "uid": uid(10)}])
    rs["spec"] = {"template": {"spec": {"serviceAccountName": "phorvex-console", "containers": [copy.deepcopy(console_c)]}}}
    deployment = obj("Deployment", "console", "phorvex-system", 10, generation=3)
    deployment["spec"] = {"selector": {"matchLabels": {"app.kubernetes.io/component": "console"}},
                          "template": {"spec": {"serviceAccountName": "phorvex-console", "containers": [copy.deepcopy(console_c)]}}}
    deployment["status"] = {"observedGeneration": 3, "availableReplicas": 1}
    return dict(zip(renderer.ROLES, (cluster, pod, service, slices, source, policy, manager, console, rs, deployment)))


class RenderGuardrailProfileTest(unittest.TestCase):
    def setUp(self):
        self.reviewed_drain_hashes = renderer.DRAIN_SOURCE_SHA256
        renderer.DRAIN_SOURCE_SHA256 = {
            key: renderer.digest(((renderer.PROXY.parent / key).read_bytes() if (renderer.PROXY.parent / key).exists()
                                  else ("fixture-" + key).encode()))
            for key in self.reviewed_drain_hashes}

    def tearDown(self):
        renderer.DRAIN_SOURCE_SHA256 = self.reviewed_drain_hashes

    def test_exact_profile_and_native_journal(self):
        raw, cm, values = renderer.render(fixture(), "arn:aws:eks:us-east-2:123456789012:cluster/test")
        profile = json.loads(raw)
        f = profile["guardrailAvailabilityFixture"]
        self.assertTrue(f["captureCurrentJournal"])
        self.assertEqual((f["guardrailJournalUID"], f["activeVariant"]), ("", ""))
        self.assertEqual(f["sourceSHA256"], hashlib.sha256(renderer.PROXY.read_bytes()).hexdigest())
        self.assertEqual(f["boundarySourceSHA256"], hashlib.sha256(renderer.DUAL.read_bytes()).hexdigest())
        self.assertEqual(cm["binaryData"]["config.guardrail-effect.yaml"], renderer.base64.b64encode(raw).decode())
        self.assertEqual(values["phorvex"]["phorvex"]["console"]["guardrailEffect"]["guardrailJournalName"],
                         f["guardrailJournalName"])
        self.assertEqual(renderer.journal_name("fdb92f85-c98d-40c8-83db-7881041b1f8b"),
                         "phorvex-serving-effect-a63da83e4ffcd99478d7dc594d61a12cf1753f26")

    def test_current_stock_runtime_and_authority_drift_refuse(self):
        changes = (
            lambda x: x["source"]["data"].pop("dual_server.py"),
            lambda x: x["source"]["data"].pop("drain_v11.py"),
            lambda x: x["source"]["data"].update({"drain_v11_init.py": "tampered"}),
            lambda x: x["pod"]["spec"]["containers"][1]["env"].clear(),
            lambda x: x["pod"]["spec"]["containers"][1].update(command=["sh", "-c", "exec python /src/guardrail_proxy.py"]),
            lambda x: x["pod"]["status"]["containerStatuses"][0].update(ready=False),
            lambda x: x["service"]["spec"]["selector"].update({"phorvex.ai/route-key": "old"}),
            lambda x: x["endpointslices"]["items"][0]["endpoints"][0]["targetRef"].update(uid=uid(99)),
            lambda x: x["console"]["metadata"]["ownerReferences"][0].update(uid=uid(98)),
            lambda x: x["manager"]["metadata"]["labels"].update({"app.kubernetes.io/name": "phoenix"}),
            lambda x: x["manager"]["spec"].update(serviceAccountName="operator-controller-manager"),
            lambda x: x["policy"]["status"].update(observedGeneration=11),
            lambda x: x["source"]["data"].update({"dual_server.py": "unreviewed"}),
        )
        for change in changes:
            with self.subTest(change=change.__code__.co_firstlineno):
                inputs = fixture()
                change(inputs)
                with self.assertRaises(ValueError):
                    renderer.render(inputs, "arn:aws:eks:us-east-2:123456789012:cluster/test")

    def test_manifest_requires_exact_fresh_single_get_hashes(self):
        inputs = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"schema": "guardrail-effect-inputs-v1", "inputs": {}}
            for role, obj in inputs.items():
                receipt = {"args": ["get", role, "-o", "json"], "rc": 0, "dispatch_count": 1,
                           "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "stdout": json.dumps(obj)}
                raw = json.dumps(receipt).encode()
                (root / (role + ".json")).write_bytes(raw)
                manifest["inputs"][role] = {"path": role + ".json", "sha256": renderer.digest(raw)}
            raw = json.dumps(manifest).encode()
            path = root / "manifest.json"
            path.write_bytes(raw)
            loaded, hashes = renderer.read_manifest(path, renderer.digest(raw))
            self.assertEqual(loaded["pod"]["metadata"]["uid"], inputs["pod"]["metadata"]["uid"])
            self.assertEqual(hashes["source"], manifest["inputs"]["source"]["sha256"])
            (root / "source.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "hash drift"):
                renderer.read_manifest(path, renderer.digest(raw))
            with self.assertRaisesRegex(ValueError, "manifest byte/hash drift"):
                renderer.read_manifest(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
