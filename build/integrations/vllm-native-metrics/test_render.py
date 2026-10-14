"""Offline original-capture, drift, token-boundary and guarded rollback controls."""
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import render
from test_metrics_token_helpers import make_metadata_fixture

SOURCE = b'# synthetic renderer source; listener is never imported or run\n'


def obj(kind, name, n, namespace="vllm", **fields):
    return {"apiVersion": "apps/v1" if kind in ("Deployment", "ReplicaSet") else "v1", "kind": kind,
            "metadata": {"namespace": namespace, "name": name, "uid": "uid-" + str(n),
                         "resourceVersion": str(n), "generation": 2}, **fields}


def listing(kind, items):
    return {"apiVersion": "v1", "kind": kind + "List", "metadata": {"resourceVersion": "100"}, "items": items}


def fixture():
    source = obj("ConfigMap", "guardrail-proxy", 5, immutable=True,
                 data={name: "# original " + name + "\n" for name in render.LEASE_SOURCE_FILES})
    digest = render.sha(b"\0".join(source["data"][n].encode() for n in render.LEASE_SOURCE_FILES))
    policy = obj("ConfigMap", "phorvex-endpoint-lease-policy", 6,
        data={"state.json": json.dumps({"version": 1, "revision": 2, "serviceUID": "uid-4",
            "proxySourceSHA256": digest, "secretUID": "untouched-tenant-secret",
            "seedSHA256": "b" * 64, "allowedClientHMACs": ["c" * 64], "revokedClientHMACs": ["d" * 64],
            "lastOperationID": "e" * 32}, sort_keys=True, separators=(",", ":"))})
    env = [{"name": k, "value": v} for k, v in (
        ("PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", digest),
        ("PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", "uid-6"),
        ("PHORVEX_ENDPOINT_LEASE_SERVICE_UID", "uid-4"),
        ("PHORVEX_ENDPOINT_LEASE_SECRET_UID", "untouched-tenant-secret"),
        ("PHORVEX_ENDPOINT_LEASE_REQUIRED", "true"))]
    template = {"metadata": {"labels": {"app": "vllm", "phorvex.ai/serving": "true", "route": "original"},
        "annotations": {"phorvex.ai/endpoint-lease-source-configmap": "guardrail-proxy",
                        "phorvex.ai/endpoint-lease-source-sha256": digest,
                        "phorvex.ai/endpoint-lease-policy-configmap-uid": "uid-6",
                        "other/annotation": "preserve-me"}}, "spec": {
        "automountServiceAccountToken": False, "serviceAccountName": "original-serving-account",
        "securityContext": {"fsGroup": 10001, "fsGroupChangePolicy": "OnRootMismatch"},
        "terminationGracePeriodSeconds": 37, "nodeSelector": {"node-type": "gpu"},
        "containers": [
            {"name": "vllm", "image": "original/engine@sha256:" + "1" * 64,
             "args": ["--model", "pinned/model", "--revision", "pinned-revision", "--host", "127.0.0.1", "--port", "8001"],
             "resources": {"requests": {"nvidia.com/gpu": "1", "memory": "6Gi"}},
             "readinessProbe": {"httpGet": {"port": 8000, "path": "/health"}},
             "livenessProbe": {"httpGet": {"port": 8000, "path": "/health"}}},
            {"name": "guardrail", "image": "original/guardrail@sha256:" + "2" * 64,
             "command": ["python3", "-B", "/src/dual_server.py"], "env": env,
             "securityContext": {"runAsUser": 10001},
             "ports": [{"name": "serving", "containerPort": 8000, "protocol": "TCP"}],
             "volumeMounts": [{"name": "original-source", "mountPath": "/src/" + n,
                               "subPath": n, "readOnly": True} for n in render.LEASE_SOURCE_FILES]}],
        "initContainers": [{"name": "phorvex-drain-ledger-init", "image": "original/guardrail@sha256:" + "2" * 64,
                            "command": ["python3", "-B", "/src/drain_v11_init.py"],
                            "volumeMounts": [{"name": "ledger", "mountPath": "/var/lib/phorvex-drain"}]}],
        "volumes": [{"name": "original-source", "configMap": {"name": "guardrail-proxy", "defaultMode": 420}},
                    {"name": "ledger", "emptyDir": {}}, {"name": "tls", "secret": {"secretName": "existing-admin"}}]}}
    deployment = obj("Deployment", "vllm", 1, spec={"replicas": 1, "minReadySeconds": 8,
        "progressDeadlineSeconds": 901, "revisionHistoryLimit": 7,
        "selector": {"matchLabels": {"app": "vllm"}},
        "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}},
        "template": copy.deepcopy(template)}, status={"observedGeneration": 2, "replicas": 1,
            "updatedReplicas": 1, "availableReplicas": 1, "readyReplicas": 1})
    rs = obj("ReplicaSet", "vllm-rs", 2, spec={"replicas": 1, "template": copy.deepcopy(template)})
    rs["metadata"]["ownerReferences"] = [{"controller": True, "kind": "Deployment", "name": "vllm", "uid": "uid-1"}]
    rs["spec"]["template"]["metadata"]["labels"]["pod-template-hash"] = "rs"
    pod = obj("Pod", "vllm-rs-pod", 3, spec=copy.deepcopy(template["spec"]))
    pod["metadata"].update(copy.deepcopy(template["metadata"]))
    pod["metadata"]["ownerReferences"] = [{"controller": True, "kind": "ReplicaSet", "name": "vllm-rs", "uid": "uid-2"}]
    pod["metadata"]["labels"]["pod-template-hash"] = "rs"
    pod["spec"]["nodeName"] = "original-gpu-node"
    pod["status"] = {"phase": "Running", "podIP": "10.0.0.3", "conditions": [{"type": "Ready", "status": "True"}],
        "containerStatuses": [{"name": name, "ready": True, "imageID": "original/" + name + "@sha256:" + str(n) * 64,
                               "containerID": "containerd://original-" + name, "restartCount": 0}
                              for name, n in (("vllm", 1), ("guardrail", 2))]}
    service = obj("Service", "vllm", 4, spec={"type": "ClusterIP", "selector": {"route": "original", "phorvex.ai/serving": "true"},
                    "ports": [{"port": 8000, "targetPort": 8000, "protocol": "TCP"}]})
    endpoint = obj("EndpointSlice", "vllm-endpoint", 8,
        ports=[{"port": 8000, "protocol": "TCP"}], endpoints=[{"addresses": ["10.0.0.3"],
            "conditions": {"ready": True, "terminating": False},
            "targetRef": {"kind": "Pod", "name": "vllm-rs-pod", "uid": "uid-3"}}])
    endpoint["metadata"].update(labels={"kubernetes.io/service-name": "vllm"},
        ownerReferences=[{"controller": True, "kind": "Service", "name": "vllm", "uid": "uid-4"}])
    journal = obj("ConfigMap", "phorvex-endpoint-lease-journal", 7, namespace="phorvex-system",
        data={"receipts.json": '{"version":1,"receipts":[{"phase":"terminal-full","operationID":"original-op"}]}'})
    drain = obj("ConfigMap", "phorvex-operation-old", 9, namespace="phorvex-system", data={"receipt": json.dumps({
        "kind": "request-drain", "policyNamespace": "vllm", "serviceUID": "uid-4", "targetUID": "old-pod-uid",
        "phase": "drain-dispatching-v11"})})
    inputs = {"deployment.json": deployment, "pod.json": pod, "replicaset.json": rs, "service.json": service,
        "endpointslices.json": listing("EndpointSlice", [endpoint]), "source.json": source, "policy.json": policy,
        "journal.json": journal, "drain-journals.json": listing("ConfigMap", [drain]),
        "inventory.json": {"configMaps": listing("ConfigMap", [copy.deepcopy(source), copy.deepcopy(policy)]),
                           "services": listing("Service", [copy.deepcopy(service)]),
                           "serviceMonitors": listing("ServiceMonitor", [])},
        "token-metadata.json": make_metadata_fixture({"metricsProtection": render.metrics_protection()})}
    capture = {"manifestSHA256": "f" * 64, "capturedAt": render.token.utc(),
               "sha256": {name: render.sha(render.canonical(value)) for name, value in inputs.items()}}
    return inputs, capture


def patched(original, operations):
    result = copy.deepcopy(original)
    for operation in operations:
        keys = operation["path"].split("/")[1:]
        parent = result
        for key in keys[:-1]:
            parent = parent[key]
        if operation["op"] == "test":
            if parent[keys[-1]] != operation["value"]:
                raise ValueError("JSON patch precondition failed")
        else:
            if operation["op"] != "replace":
                raise ValueError("unexpected operation")
            parent[keys[-1]] = copy.deepcopy(operation["value"])
    return result


def write_inputs(directory, inputs):
    digests = {}
    for name, obj_value in inputs.items():
        # Use pretty-printed, noncanonical file bytes to exercise exact file SHA.
        raw = json.dumps(obj_value, indent=2).encode()
        (directory / name).write_bytes(raw)
        digests[name] = render.sha(raw)
    (directory / "captures.json").write_bytes(render.canonical({"schema": render.CAPTURE_SCHEMA,
        "capturedAt": render.token.utc(), "sha256": digests}))


class Renderer(unittest.TestCase):
    def setUp(self):
        self.inputs, self.capture = fixture()

    def rendered(self, inputs=None, **kwargs):
        return render.render(inputs or self.inputs, self.capture, SOURCE, **kwargs)

    def test_forward_preserves_every_original_setting_and_source_policy_journals(self):
        before = copy.deepcopy(self.inputs)
        artifacts = self.rendered()
        candidate = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        restored = copy.deepcopy(candidate["spec"])
        template = restored["template"]
        template["metadata"]["labels"].pop(render.OPT_IN)
        template["metadata"]["annotations"].pop(render.SOURCE_ANNOTATION)
        template["spec"]["initContainers"].pop()
        del template["spec"]["volumes"][-2:]
        self.assertEqual(restored, before["deployment.json"]["spec"])
        self.assertEqual(self.inputs, before)
        closure = artifacts["metrics-closure.json"]
        self.assertEqual(closure["baseline"]["leasePolicyRevision"], 2)
        self.assertEqual(closure["baseline"]["historicalDrainJournals"][0]["phase"], "drain-dispatching-v11")
        self.assertEqual(closure["baseline"]["protectedJournalSHA256"], render.sha(before["journal.json"]["data"]["receipts.json"].encode()))
        self.assertEqual(closure["metricsProtection"]["workloadNamespace"], "vllm")
        self.assertNotIn("gatewayNamespace", json.dumps(closure))
        for name, digest in closure["artifactsSHA256"].items():
            self.assertEqual(digest, render.sha(render.canonical(artifacts[name]) + b"\n"))

    def test_native_sidecar_only_two_mounts_and_exact_security_resources(self):
        candidate = self.rendered()["deployment-candidate-spec.json"]["template"]["spec"]
        self.assertEqual([c["name"] for c in candidate["containers"]], ["vllm", "guardrail"])
        self.assertEqual([c["name"] for c in candidate["initContainers"]], ["phorvex-drain-ledger-init", render.SIDECAR])
        sidecar = candidate["initContainers"][-1]
        self.assertEqual(sidecar["restartPolicy"], "Always")
        self.assertEqual(sidecar["command"], ["python3", "-B", "/opt/phorvex/metrics.py"])
        self.assertEqual(sidecar["image"], render.token.IMAGE)
        self.assertEqual(sidecar["volumeMounts"], [
            {"name": render.SOURCE_VOLUME, "mountPath": "/opt/phorvex/metrics.py", "subPath": "metrics.py", "readOnly": True},
            {"name": render.TOKEN_VOLUME, "mountPath": "/etc/phorvex-vllm-metrics", "readOnly": True}])
        self.assertEqual(sidecar["securityContext"], {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}})
        self.assertEqual(sidecar["resources"], {"requests": {"cpu": "10m", "memory": "16Mi"},
                                              "limits": {"cpu": "100m", "memory": "64Mi"}})
        for field in ("env", "envFrom", "livenessProbe", "readinessProbe", "startupProbe", "volumeDevices"):
            self.assertNotIn(field, sidecar)
        credential = candidate["volumes"][-1]["secret"]
        self.assertEqual(credential, {"secretName": render.token.NAME, "optional": False, "defaultMode": 0o440,
                                     "items": [{"key": "token", "path": "token", "mode": 0o440}]})
        self.assertEqual(candidate["securityContext"]["fsGroup"], 10001)
        self.assertFalse(candidate["automountServiceAccountToken"])
        self.assertFalse(candidate["volumes"][-2]["configMap"]["optional"])

    def test_content_named_immutable_source_and_exact_monitor_authorization_relabelings(self):
        artifacts = self.rendered()
        cm, service, monitor = [artifacts[name] for name in
            ("metrics-source-configmap.json", "metrics-service.json", "metrics-servicemonitor.json")]
        self.assertEqual(cm["metadata"]["name"], render.NAME + "-" + render.sha(SOURCE)[:12])
        self.assertTrue(cm["immutable"])
        self.assertEqual(cm["data"], {"metrics.py": SOURCE.decode()})
        self.assertEqual(service["spec"]["selector"], {"app": "vllm", render.OPT_IN: "enabled"})
        self.assertNotIn("phorvex.ai/serving", service["spec"]["selector"])
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"], [{"name": "engine-metrics", "port": 9102, "targetPort": 9102, "protocol": "TCP"}])
        self.assertEqual(monitor["metadata"]["namespace"], "monitoring")
        self.assertEqual(monitor["metadata"]["labels"]["release"], "kube-prom-stack")
        self.assertEqual(monitor["spec"]["namespaceSelector"], {"matchNames": ["vllm"]})
        self.assertEqual(monitor["spec"]["selector"]["matchLabels"], service["metadata"]["labels"])
        self.assertEqual(monitor["spec"]["jobLabel"], "phorvex.ai/metrics-job")
        endpoint = monitor["spec"]["endpoints"][0]
        self.assertEqual(endpoint["authorization"], {"type": "Bearer", "credentials": {
            "name": "phorvex-vllm-native-metrics-token-v1", "key": "token", "optional": False}})
        self.assertEqual(endpoint["relabelings"], [
            {"action": "replace", "sourceLabels": ["__meta_kubernetes_namespace"], "targetLabel": "namespace"},
            {"action": "replace", "sourceLabels": ["__meta_kubernetes_pod_name"], "targetLabel": "pod"},
            {"action": "replace", "sourceLabels": ["__meta_kubernetes_pod_node_name"], "targetLabel": "node"},
            {"action": "replace", "targetLabel": "container", "replacement": "vllm"}])
        self.assertEqual((endpoint["interval"], endpoint["scrapeTimeout"], endpoint["honorLabels"], endpoint["followRedirects"]),
                         ("30s", "5s", False, False))
        self.assertNotIn("metricRelabelings", endpoint)

    def test_forward_guards_uid_resource_version_and_entire_spec(self):
        operations = self.rendered()["deployment-metrics-json-patch.json"]
        self.assertEqual([o["path"] for o in operations[:3]], ["/metadata/uid", "/metadata/resourceVersion", "/spec"])
        for mutate in (lambda d: d["metadata"].update(uid="recreated"),
                       lambda d: d["metadata"].update(resourceVersion="new"),
                       lambda d: d["spec"].update(replicas=2),
                       lambda d: d["spec"]["template"]["spec"]["containers"][0].update(image="unreviewed"),
                       lambda d: d["spec"].update(progressDeadlineSeconds=1000)):
            current = copy.deepcopy(self.inputs["deployment.json"])
            mutate(current)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                patched(current, operations)

    def test_inverse_requires_current_rv_and_restores_exact_original_template(self):
        artifacts = self.rendered()
        current = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        current["metadata"]["resourceVersion"] = "post-rollout-rv"
        with self.assertRaises(ValueError):
            patched(current, artifacts["deployment-metrics-rollback-json-patch.json"])
        rebound = self.rendered(rollback=current, rollback_sha=render.sha(render.canonical(current)))
        operations = rebound["deployment-metrics-rollback-json-patch.json"]
        self.assertEqual([o["path"] for o in operations[:3]], ["/metadata/uid", "/metadata/resourceVersion", "/spec"])
        self.assertEqual(operations[1]["value"], "post-rollout-rv")
        restored = patched(current, operations)
        self.assertEqual(restored["spec"], self.inputs["deployment.json"]["spec"])
        self.assertEqual(restored["metadata"]["uid"], "uid-1")
        self.assertFalse(rebound["metrics-closure.json"]["rollback"]["requiresCurrentDeploymentCapture"])
        for mutate in (lambda d: d["metadata"].update(uid="replacement"),
                       lambda d: d["spec"].update(replicas=2),
                       lambda d: d["spec"]["template"]["spec"]["initContainers"][-1]["volumeMounts"].append(
                           {"name": "tls", "mountPath": "/etc/admin"})):
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(rollback=changed, rollback_sha=render.sha(render.canonical(changed)))

    def test_graph_source_endpoint_policy_and_security_drift_fail(self):
        mutations = [
            lambda x: x["pod.json"]["metadata"]["ownerReferences"][0].update(uid="recreated-rs"),
            lambda x: x["replicaset.json"]["metadata"]["ownerReferences"][0].update(uid="recreated-deployment"),
            lambda x: x["replicaset.json"]["spec"]["template"]["spec"].update(serviceAccountName="changed"),
            lambda x: x["pod.json"]["spec"]["containers"][0].update(args=["--host", "0.0.0.0"]),
            lambda x: x["pod.json"]["status"]["containerStatuses"][0].update(ready=False),
            lambda x: x["deployment.json"]["spec"]["template"]["spec"].update(automountServiceAccountToken=True),
            lambda x: x["deployment.json"]["spec"]["template"]["spec"]["securityContext"].update(fsGroup=0),
            lambda x: x["deployment.json"]["spec"]["template"]["spec"]["containers"].append({"name": "third"}),
            lambda x: x["deployment.json"]["spec"]["strategy"]["rollingUpdate"].update(maxSurge=1),
            lambda x: x["endpointslices.json"]["items"][0]["endpoints"][0]["targetRef"].update(uid="wrong-pod"),
            lambda x: x["endpointslices.json"]["items"][0]["endpoints"][0].update(addresses=["10.0.0.99"]),
            lambda x: x["endpointslices.json"]["items"][0]["endpoints"].append(copy.deepcopy(x["endpointslices.json"]["items"][0]["endpoints"][0])),
            lambda x: x["source.json"].update(immutable=False),
            lambda x: x["source.json"]["data"].update({"dual_server.py": "changed"}),
            lambda x: x["policy.json"]["metadata"].update(uid="replacement-policy"),
            lambda x: x["journal.json"]["data"].update({"receipts.json": '{"version":1,"receipts":[{"phase":"dispatching"}]}'}),
            lambda x: x["drain-journals.json"]["items"][0]["data"].update({"receipt": json.dumps({"kind": "request-drain",
                "policyNamespace": "vllm", "serviceUID": "uid-4", "targetUID": "uid-3", "phase": "drain-dispatching-v11"})})]
        for mutate in mutations:
            changed = copy.deepcopy(self.inputs)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(changed)

    def test_any_new_object_collision_and_baseline_inventory_drift_fail(self):
        for key, index in (("configMaps", 0), ("services", 1), ("serviceMonitors", 2)):
            changed = copy.deepcopy(self.inputs)
            collision = copy.deepcopy(render.monitoring_objects(SOURCE)[index])
            collision["metadata"].update(uid="collision-uid", resourceVersion="200")
            changed["inventory.json"][key]["items"].append(collision)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.rendered(changed)
        changed = copy.deepcopy(self.inputs)
        changed["inventory.json"]["services"]["items"][0]["metadata"]["resourceVersion"] = "new-rv"
        with self.assertRaises(ValueError):
            self.rendered(changed)

    def test_pod_admission_default_tolerations_are_bounded_and_originals_preserved(self):
        changed = copy.deepcopy(self.inputs)
        original = {"key": "nvidia.com/gpu", "effect": "NoSchedule", "operator": "Exists"}
        for template in (changed["deployment.json"]["spec"]["template"],
                         changed["replicaset.json"]["spec"]["template"]):
            template["spec"]["tolerations"] = [original]
        changed["pod.json"]["spec"]["tolerations"] = [original] + [
            {"key": "node.kubernetes.io/" + key, "effect": "NoExecute", "operator": "Exists", "tolerationSeconds": 300}
            for key in ("not-ready", "unreachable")]
        self.rendered(changed)
        # kubectl's generic List wrapper has no list RV; each full object has one.
        changed["endpointslices.json"]["kind"] = "List"
        changed["endpointslices.json"]["metadata"]["resourceVersion"] = ""
        self.rendered(changed)
        for mutate in (lambda s: s["tolerations"][1].update(tolerationSeconds=3600),
                       lambda s: s["tolerations"].pop(0),
                       lambda s: s["tolerations"].append({"operator": "Exists"}),
                       lambda s: s.update(ephemeralContainers=[{"name": "debug", "image": "unreviewed"}])):
            bad = copy.deepcopy(changed)
            mutate(bad["pod.json"]["spec"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(bad)

    def test_token_uid_rv_provenance_pair_freshness_and_full_secret_rejection(self):
        for mutate in (
            lambda m: m["secrets"][0].update(resourceVersion="drift"),
            lambda m: m["secrets"][0].update(uid="recreated"),
            lambda m: m["secrets"][0].update(provenance="stage5-v1"),
            lambda m: m["secrets"][0].update(pairID="2" * 32),
            lambda m: m["secrets"][0].update(ready=False),
            lambda m: m["generator"].update(sourceSHA256="f" * 64),
            lambda m: m["generator"]["records"][0].update(immutable=False),
            lambda m: m["secrets"].pop(),
            lambda m: m.update(utc="2099-01-01T00:00:00Z"),
            lambda m: m["secrets"][0].update(data={"token": "forbidden"})):
            changed = copy.deepcopy(self.inputs)
            mutate(changed["token-metadata.json"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(changed)

    def test_exact_file_sha_manifest_missing_capture_links_and_secret_data_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_inputs(directory, self.inputs)
            inputs, closure_capture = render.load_inputs(directory)
            self.assertEqual(inputs, self.inputs)
            self.assertEqual(closure_capture["sha256"]["pod.json"], render.sha((directory / "pod.json").read_bytes()))
            path = directory / "pod.json"
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(ValueError): render.load_inputs(directory)
            path.write_bytes(original)
            path.unlink()
            path.symlink_to(directory / "deployment.json")
            with self.assertRaises(OSError): render.load_inputs(directory)
            path.unlink()
            with self.assertRaises(OSError): render.load_inputs(directory)
            bad = copy.deepcopy(self.inputs)
            bad["inventory.json"]["extra"] = {"kind": "Secret", "data": {"token": "forbidden"}}
            write_inputs(directory, bad)
            with self.assertRaises(ValueError): render.load_inputs(directory)
            (directory / "captures.json").write_text('{"schema":"duplicate","schema":"duplicate"}')
            with self.assertRaises(ValueError): render.load_inputs(directory)

    def test_stale_manifest_missing_input_and_output_reuse_fail(self):
        capture = copy.deepcopy(self.capture)
        capture["capturedAt"] = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()
        with self.assertRaises(ValueError): render.render(self.inputs, capture, SOURCE)
        incomplete = copy.deepcopy(self.inputs)
        incomplete.pop("token-metadata.json")
        with self.assertRaises(ValueError): self.rendered(incomplete)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "rendered"
            artifacts = self.rendered()
            render.write_artifacts(output, artifacts, SOURCE)
            with self.assertRaises(FileExistsError): render.write_artifacts(output, artifacts, SOURCE)
            for name, digest in artifacts["metrics-closure.json"]["artifactsSHA256"].items():
                self.assertEqual(render.sha((output / name).read_bytes()), digest)
            self.assertEqual((output / "vllm-native-metrics.yaml").read_bytes(), render.source_manifest(SOURCE))

    def test_checked_manifest_tracks_final_source_and_obsolete_job_only_removed(self):
        root = render.ROOT.parents[2]
        self.assertEqual((root / "deploy/monitoring/vllm-native-metrics.yaml").read_bytes(),
                         render.source_manifest((render.ROOT / "metrics.py").read_bytes()))
        # SHA256 of retained job bytes from the checked pre-Stage6 source. These
        # assertions remain valid after committing the removal and in shallow CI.
        path = "deploy/monitoring/additional-scrape-configs.yaml"
        checked = (root / path).read_text()
        def jobs(text):
            import re
            return {chunk.splitlines()[0]: chunk for chunk in re.split(r"(?m)^- job_name: ", text)[1:]}
        after = jobs(checked)
        self.assertNotIn("vllm", after)
        self.assertEqual({k: render.sha(v.encode()) for k, v in after.items()}, {
            "dcgm": "4d4d15792cabed3a242c52bbc428a7c8d9db63befe03295450e7bc6733838e7f",
            "cadvisor-standalone": "5c62dc06c8edc7ce47ba06400facd5974057c8d7473231d9822de1063ba4f6f0"})

    def test_offline_cli_emits_complete_hash_closure_and_refuses_incomplete_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "inputs"
            directory.mkdir()
            write_inputs(directory, self.inputs)
            output = Path(temp) / "review"
            argv = ["render.py", "--inputs", str(directory), "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()), \
                    patch.object(render.provision, "ProxyAPI", side_effect=AssertionError("renderer must stay offline")):
                self.assertEqual(render.main(), 0)
            closure = json.loads((output / "metrics-closure.json").read_bytes())
            self.assertEqual(closure["sourceManifestSHA256"], render.sha((output / "vllm-native-metrics.yaml").read_bytes()))
            self.assertEqual(closure["capture"]["sha256"]["pod.json"], render.sha((directory / "pod.json").read_bytes()))
            (directory / "token-metadata.json").unlink()
            absent = Path(temp) / "refused"
            argv[-1] = str(absent)
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(render.main(), 1)
            self.assertFalse(absent.exists())

    def test_cli_source_race_and_rollback_file_hash_mismatch_emit_no_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "inputs"
            directory.mkdir()
            write_inputs(directory, self.inputs)
            output = Path(temp) / "review"
            argv = ["render.py", "--inputs", str(directory), "--output", str(output)]
            reader = render.read_bounded
            reads = []
            def source_race(path, *args):
                raw = reader(path, *args)
                if path == render.ROOT / "metrics.py":
                    reads.append(path)
                    if len(reads) > 1:
                        return raw + b"# changed during rendering\n"
                return raw
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()), \
                    patch.object(render, "read_bounded", side_effect=source_race):
                self.assertEqual(render.main(), 1)
            self.assertFalse(output.exists())
            current = patched(self.inputs["deployment.json"], self.rendered()["deployment-metrics-json-patch.json"])
            rollback = Path(temp) / "rollback.json"
            rollback.write_bytes(render.canonical(current))
            argv += ["--rollback-deployment", str(rollback), "--rollback-sha256", "0" * 64]
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(render.main(), 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
