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
             "command": renderer.LEGACY_COMMAND.copy(),
             "env": [{"name": name, "valueFrom": {"secretKeyRef": {"name": "vllm-control", "key": key}}}
                     for name, key in (("VLLM_API_KEY", "api-key"), ("PHORVEX_GUARDRAIL_ADMIN_KEY", "admin-bearer"))],
             "volumeMounts": [{"name": "source", "mountPath": "/src"},
                              {"name": "admin-tls", "mountPath": "/etc/phorvex/admin-tls", "readOnly": True}]}
    guard["env"].extend(({"name": "PHORVEX_ADMIN_TLS_CERT_FILE", "value": "/etc/phorvex/admin-tls/tls.crt"},
                         {"name": "PHORVEX_ADMIN_TLS_KEY_FILE", "value": "/etc/phorvex/admin-tls/tls.key"}))
    pod["spec"] = {"containers": [vllm, guard], "volumes": [
        {"name": "source", "configMap": {"name": "guardrail-proxy"}},
        {"name": "admin-tls", "secret": {"secretName": "vllm-control", "items": [
            {"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}}]}
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
    console["spec"] = {"serviceAccountName": "phorvex-phorvex-console", "containers": [console_c],
                       "volumes": [{"name": "audit", "secret": {"secretName": "audit-client"}},
                                   {"name": "token", "secret": {"secretName": "scoped-token"}}]}
    console["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                         "containerStatuses": [{"name": "console", "image": "example/console:v1",
                                                "imageID": "example/console@sha256:" + "4" * 64,
                                                "containerID": "containerd://console", "ready": True, "restartCount": 0}]}
    rs = obj("ReplicaSet", "console-rs", "phorvex-system", 9,
             ownerReferences=[{"controller": True, "kind": "Deployment", "name": "console", "uid": uid(10)}])
    rs["spec"] = {"template": {"spec": {"serviceAccountName": "phorvex-phorvex-console", "containers": [copy.deepcopy(console_c)]}}}
    deployment = obj("Deployment", "console", "phorvex-system", 10, generation=3)
    deployment["spec"] = {"selector": {"matchLabels": {"app.kubernetes.io/component": "console"}},
                          "template": {"spec": {"serviceAccountName": "phorvex-phorvex-console", "containers": [copy.deepcopy(console_c)]}}}
    deployment["status"] = {"observedGeneration": 3, "availableReplicas": 1}
    return dict(zip(renderer.ROLES, (cluster, pod, service, slices, source, policy, manager, console, rs, deployment)))


def lease_fixture():
    objects = fixture()
    pod, source, service, policy = (objects[k] for k in ("pod", "source", "service", "policy"))
    guard = pod["spec"]["containers"][1]
    source["immutable"] = True
    source["data"]["endpoint_lease.py"] = renderer.LEASE.read_text()
    guard["command"] = ["python3", "-B", "/src/dual_server.py"]
    guard["volumeMounts"] = [{"name": "admin-tls", "mountPath": "/etc/phorvex/admin-tls", "readOnly": True}]
    guard["volumeMounts"].extend({"name": "source", "mountPath": "/src/" + name,
                                  "subPath": name, "readOnly": True} for name in renderer.LEASE_SOURCE_FILES)
    guard["volumeMounts"].append({"name": "lease-keys", "mountPath": "/etc/phorvex/endpoint-lease-keys",
                                  "readOnly": True})
    pod["spec"]["volumes"].append({"name": "lease-keys", "secret": {"secretName": "phorvex-endpoint-lease-keys"}})
    composite = renderer.digest(b"\0".join(source["data"][name].encode() for name in renderer.LEASE_SOURCE_FILES))
    policy_uid, secret_uid = uid(21), uid(22)
    pod["metadata"]["annotations"].update({
        "phorvex.ai/endpoint-lease-source-configmap": "guardrail-proxy",
        "phorvex.ai/endpoint-lease-source-sha256": composite,
        "phorvex.ai/endpoint-lease-policy-configmap-uid": policy_uid})
    for name, value in (("PHORVEX_ENDPOINT_LEASE_REQUIRED", "true"),
                        ("PHORVEX_ENDPOINT_LEASE_SECRET_DIR", "/etc/phorvex/endpoint-lease-keys"),
                        ("PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", policy_uid),
                        ("PHORVEX_ENDPOINT_LEASE_SECRET_UID", secret_uid),
                        ("PHORVEX_ENDPOINT_LEASE_SERVICE_UID", service["metadata"]["uid"]),
                        ("PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", composite)):
        guard["env"].append({"name": name, "value": value})
    guard["env"].append({"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}})
    state = {"version": 1, "revision": 0, "serviceUID": service["metadata"]["uid"],
             "proxySourceSHA256": composite, "secretUID": secret_uid, "seedSHA256": "a" * 64,
             "allowedClientHMACs": ["b" * 64, "c" * 64], "revokedClientHMACs": [],
             "lastOperationID": ""}
    lease_policy = obj("ConfigMap", "phorvex-endpoint-lease-policy", "vllm", 21,
                       resourceVersion="7")
    lease_policy["data"] = {"state.json": json.dumps(state, sort_keys=True, separators=(",", ":"))}
    objects["lease_policy"] = lease_policy
    audit = objects["console"]["spec"]["containers"][0]["args"][0].split("=", 1)[1]
    profile = {"version": 1, "serviceName": "vllm", "serviceUID": service["metadata"]["uid"],
               "policyName": "vllm-defense", "policyUID": policy["metadata"]["uid"],
               "policyGeneration": policy["metadata"]["generation"], "policyConfigMapUID": policy_uid,
               "journalUID": uid(23), "tenantSecretUID": secret_uid, "consoleSecretUID": uid(24),
               "sourceConfigMapName": "guardrail-proxy", "sourceConfigMapUID": source["metadata"]["uid"],
               "proxySourceSHA256": composite, "proxyImage": guard["image"],
               "approvedEngineImage": pod["spec"]["containers"][0]["image"],
               "seedSHA256": "a" * 64, "clientASHA256": "d" * 64, "clientBSHA256": "e" * 64,
               "clientAHMAC": "b" * 64, "clientBHMAC": "c" * 64,
               "eventCreator": "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
               "auditSourceIdentity": audit + "|phorvex-phorvex-audit-source.phorvex-system.svc",
               "modelId": renderer.MODEL, "maxRunSeconds": 900}
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    profile_name = "phorvex-catalogue-endpoint-lease-" + renderer.digest(raw)[:12]
    for item in (objects["console"], objects["console_replicaset"]["spec"]["template"],
                 objects["console_deployment"]["spec"]["template"]):
        spec = item["spec"]
        c = next(x for x in spec["containers"] if x["name"] == "console")
        c.setdefault("env", []).extend((
            {"name": "PHORVEX_CONSOLE_ENDPOINT_LEASE_ENABLED", "value": "true"},
            {"name": "PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256", "value": renderer.digest(raw)}))
        c["volumeMounts"].extend((
            {"name": "lease-profile", "mountPath": "/etc/phorvex-endpoint-lease/profile.json",
             "subPath": "profile.json", "readOnly": True},
            {"name": "lease-callers", "mountPath": "/etc/phorvex-endpoint-lease-callers", "readOnly": True}))
        spec.setdefault("volumes", []).extend((
            {"name": "lease-profile", "configMap": {"name": profile_name}},
            {"name": "lease-callers", "secret": {"secretName": "vllm-endpoint-lease-callers"}}))
    return objects, raw


class RenderGuardrailProfileTest(unittest.TestCase):
    def setUp(self):
        self.reviewed_drain_hashes = renderer.DRAIN_SOURCE_SHA256
        self.reviewed_legacy_hashes = renderer.LEGACY_SOURCE_SHA256
        renderer.LEGACY_SOURCE_SHA256 = {
            "guardrail_proxy.py": renderer.digest(renderer.PROXY.read_bytes()),
            "dual_server.py": renderer.digest(renderer.DUAL.read_bytes())}
        renderer.DRAIN_SOURCE_SHA256 = {
            key: renderer.digest(((renderer.PROXY.parent / key).read_bytes() if (renderer.PROXY.parent / key).exists()
                                  else ("fixture-" + key).encode()))
            for key in self.reviewed_drain_hashes}

    def tearDown(self):
        renderer.DRAIN_SOURCE_SHA256 = self.reviewed_drain_hashes
        renderer.LEGACY_SOURCE_SHA256 = self.reviewed_legacy_hashes

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

    def test_historical_restart_accepts_current_pinned_container_only(self):
        objects = fixture()
        statuses = objects["pod"]["status"]["containerStatuses"]
        guard = next(row for row in statuses if row["name"] == "guardrail")
        guard["restartCount"] = 1
        raw, _, _ = renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")
        self.assertEqual(json.loads(raw)["guardrailAvailabilityFixture"]["podUID"],
                         objects["pod"]["metadata"]["uid"])
        for invalid in (-1, True, None, "1"):
            with self.subTest(restart_count=invalid):
                guard["restartCount"] = invalid
                with self.assertRaises(ValueError):
                    renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")
        guard["restartCount"] = 1
        guard["containerID"] = ""
        with self.assertRaises(ValueError):
            renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")

    def test_exact_docker_hub_library_projection_from_current_cri(self):
        pod = fixture()["pod"]
        spec = next(row for row in pod["spec"]["containers"] if row["name"] == "guardrail")
        status = next(row for row in pod["status"]["containerStatuses"] if row["name"] == "guardrail")
        spec["image"] = "python:3.11-slim"
        status.update(image="docker.io/library/python:3.11-slim",
                      imageID="docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
                      containerID="containerd://3293a4eb83094300ece30db88920ad428c390b789650f4a02714e8bb6ba8b596",
                      restartCount=1)
        selected_spec, selected_status = renderer.container(pod, "guardrail")
        self.assertEqual((selected_spec["image"], selected_status["containerID"]),
                         (spec["image"], status["containerID"]))
        for altered in ("docker.io/library/python:3.12-slim",
                        "docker.io/library/node:3.11-slim",
                        "ghcr.io/library/python:3.11-slim",
                        "docker.io/other/python:3.11-slim"):
            with self.subTest(status_image=altered):
                status["image"] = altered
                with self.assertRaises(ValueError):
                    renderer.container(pod, "guardrail")
        status["image"] = "docker.io/library/python:3.11-slim"
        status["containerID"] = ""
        with self.assertRaises(ValueError):
            renderer.container(pod, "guardrail")

    def test_historical_and_startup_repaired_source_closures_do_not_mix(self):
        context = "arn:aws:eks:us-east-2:123456789012:cluster/test"
        objects = fixture()
        current_proxy = renderer.digest(renderer.PROXY.read_bytes())
        current_dual = objects["source"]["data"]["dual_server.py"]
        current_drain = objects["source"]["data"]["drain_v11.py"]
        old_dual = current_dual + "\n# synthetic historical listener"
        old_drain = current_drain + "\n# synthetic historical drain"
        repaired = renderer.STARTUP_REPAIRED_LEGACY_SOURCE_SHA256
        historical = renderer.LEGACY_SOURCE_SHA256
        historical_drain = renderer.DRAIN_SOURCE_SHA256
        try:
            # Synthetic bytes test the closure join without requiring git
            # history in a shallow checkout. Production pins remain literal.
            renderer.LEGACY_SOURCE_SHA256 = {
                "guardrail_proxy.py": current_proxy,
                "dual_server.py": renderer.digest(old_dual.encode()),
            }
            renderer.DRAIN_SOURCE_SHA256 = {
                "drain_v11.py": renderer.digest(old_drain.encode()),
                "drain_v11_init.py": self.reviewed_drain_hashes["drain_v11_init.py"],
            }
            renderer.STARTUP_REPAIRED_LEGACY_SOURCE_SHA256 = {
                "guardrail_proxy.py": current_proxy,
                "dual_server.py": renderer.digest(renderer.DUAL.read_bytes()),
            }
            renderer.render(objects, context)
            objects["source"]["data"]["dual_server.py"] = old_dual
            with self.assertRaises(ValueError):
                renderer.render(objects, context)
            objects["source"]["data"]["dual_server.py"] = current_dual
            objects["source"]["data"]["drain_v11.py"] = old_drain
            with self.assertRaises(ValueError):
                renderer.render(objects, context)
            objects["source"]["data"]["dual_server.py"] = old_dual
            renderer.render(objects, context)
        finally:
            renderer.STARTUP_REPAIRED_LEGACY_SOURCE_SHA256 = repaired
            renderer.LEGACY_SOURCE_SHA256 = historical
            renderer.DRAIN_SOURCE_SHA256 = historical_drain

    def test_exact_five_file_lease_closure_requires_retained_b_authority(self):
        objects, retained = lease_fixture()
        raw, _, _ = renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test", retained)
        fixture_data = json.loads(raw)["guardrailAvailabilityFixture"]
        self.assertEqual(fixture_data["retainedCallerLeaseProfileSHA256"], renderer.digest(retained))
        self.assertEqual(fixture_data["sourceSHA256"], renderer.digest(renderer.PROXY.read_bytes()))
        with self.assertRaises(ValueError):
            renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")
        after, retained_after = lease_fixture()
        state = json.loads(after["lease_policy"]["data"]["state.json"])
        state.update(revision=1, allowedClientHMACs=["c" * 64],
                     revokedClientHMACs=["b" * 64], lastOperationID="d" * 32)
        after["lease_policy"]["data"]["state.json"] = json.dumps(state, sort_keys=True, separators=(",", ":"))
        renderer.render(after, "arn:aws:eks:us-east-2:123456789012:cluster/test", retained_after)
        for change in (
            lambda o, p: o["source"]["data"].pop("endpoint_lease.py"),
            lambda o, p: o["source"]["data"].update({"endpoint_lease.py": "wrong"}),
            lambda o, p: o["source"].update(immutable=False),
            lambda o, p: o["pod"]["status"]["containerStatuses"][1].update(imageID="example/guard@sha256:" + "9" * 64),
            lambda o, p: o["pod"]["spec"]["containers"][1].update(command=["sh", "-c", "exec python /src/dual_server.py"]),
            lambda o, p: o["pod"]["spec"]["containers"][1]["volumeMounts"][1].update(readOnly=False),
            lambda o, p: o["pod"]["spec"]["containers"][1]["env"].append({"name": "PYTHONPATH", "value": "/tmp"}),
            lambda o, p: o["pod"]["metadata"]["annotations"].update({"phorvex.ai/endpoint-lease-source-sha256": "0" * 64}),
            lambda o, p: o["lease_policy"]["data"].update({"state.json": o["lease_policy"]["data"]["state.json"] + " "}),
            lambda o, p: o["lease_policy"]["metadata"].update(uid=uid(99)),
            lambda o, p: p.update({"clientBHMAC": "f" * 64}),
            lambda o, p: p.update({"consoleSecretUID": ""}),
            lambda o, p: p.update({"auditSourceIdentity": "untrusted"}),
            lambda o, p: o["console"]["spec"]["containers"][0]["env"][0].update(value="false"),
            lambda o, p: o["console_deployment"]["spec"]["template"]["spec"]["volumes"][1]["secret"].update(secretName="other"),
        ):
            with self.subTest(change=change.__code__.co_firstlineno):
                changed, profile = lease_fixture()
                decoded = json.loads(profile)
                change(changed, decoded)
                with self.assertRaises(ValueError):
                    renderer.render(changed, "arn:aws:eks:us-east-2:123456789012:cluster/test",
                                    json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode())

    def test_four_file_closure_rejects_lease_requirement_or_extra_policy(self):
        objects = fixture()
        objects["pod"]["spec"]["containers"][1]["env"].append(
            {"name": "PHORVEX_ENDPOINT_LEASE_REQUIRED", "value": "true"})
        with self.assertRaises(ValueError):
            renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")
        objects = fixture()
        objects["lease_policy"] = lease_fixture()[0]["lease_policy"]
        with self.assertRaises(ValueError):
            renderer.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")

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

    def test_eleven_get_manifest_adds_only_lease_policy_configmap(self):
        inputs, retained = lease_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"schema": "guardrail-effect-inputs-v1", "inputs": {}}
            for role, value in inputs.items():
                receipt = {"args": ["get", role, "-o", "json"], "rc": 0, "dispatch_count": 1,
                           "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "stdout": json.dumps(value)}
                raw = json.dumps(receipt).encode()
                (root / (role + ".json")).write_bytes(raw)
                manifest["inputs"][role] = {"path": role + ".json", "sha256": renderer.digest(raw)}
            raw = json.dumps(manifest).encode()
            path = root / "manifest.json"
            path.write_bytes(raw)
            loaded, hashes = renderer.read_manifest(path, renderer.digest(raw))
            self.assertIn("lease_policy", hashes)
            profile, _, _ = renderer.render(loaded, "arn:aws:eks:us-east-2:123456789012:cluster/test", retained)
            self.assertEqual(json.loads(profile)["guardrailAvailabilityFixture"]["retainedCallerLeaseProfileSHA256"],
                             renderer.digest(retained))
            manifest["inputs"]["secret"] = manifest["inputs"]["lease_policy"]
            raw = json.dumps(manifest).encode()
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "manifest role set"):
                renderer.read_manifest(path, renderer.digest(raw))


if __name__ == "__main__":
    unittest.main()
