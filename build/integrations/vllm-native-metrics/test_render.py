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


def write_inputs(directory, inputs, captured_at=None):
    digests = {}
    for name, obj_value in inputs.items():
        # Use pretty-printed, noncanonical file bytes to exercise exact file SHA.
        raw = json.dumps(obj_value, indent=2).encode()
        (directory / name).write_bytes(raw)
        digests[name] = render.sha(raw)
    (directory / "captures.json").write_bytes(render.canonical({"schema": render.CAPTURE_SCHEMA,
        "capturedAt": captured_at or render.token.utc(), "sha256": digests}))


class Renderer(unittest.TestCase):
    def setUp(self):
        self.inputs, self.capture = fixture()

    def rendered(self, inputs=None, **kwargs):
        return render.render(inputs or self.inputs, self.capture, SOURCE, **kwargs)

    def rollback_args(self, artifacts, current):
        raw = render.canonical(artifacts["metrics-closure.json"]) + b"\n"
        return {"rollback": current, "rollback_sha": render.sha(render.canonical(current)),
                "rollback_closure": raw, "rollback_closure_sha": render.sha(raw),
                "rollback_captured_at": render.token.utc()}

    def frozen_originals(self):
        captured = datetime.now(timezone.utc) - timedelta(hours=2)
        self.capture["capturedAt"] = captured.isoformat()
        self.inputs["token-metadata.json"]["utc"] = (captured - timedelta(minutes=5)).isoformat()
        self.capture["sha256"]["token-metadata.json"] = render.sha(render.canonical(self.inputs["token-metadata.json"]))
        return captured

    def frozen_forward(self):
        captured = self.frozen_originals()
        with patch.object(render.provision, "datetime") as clock:
            clock.now.return_value = captured + timedelta(seconds=1)
            clock.fromisoformat.side_effect = datetime.fromisoformat
            return self.rendered()

    def prepare_rollback_cli(self, directory):
        captured = self.frozen_originals()
        inputs = directory / "inputs"
        inputs.mkdir()
        write_inputs(inputs, self.inputs, self.capture["capturedAt"])
        forward = directory / "forward"
        argv = ["render.py", "--inputs", str(inputs), "--output", str(forward)]
        with patch.object(render.provision, "datetime") as clock, \
                patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
            clock.now.return_value = captured + timedelta(seconds=1)
            clock.fromisoformat.side_effect = datetime.fromisoformat
            self.assertEqual(render.main(), 0)
        closure = forward / "metrics-closure.json"
        operations = json.loads((forward / "deployment-metrics-json-patch.json").read_bytes())
        current = patched(self.inputs["deployment.json"], operations)
        current["metadata"]["resourceVersion"] = "post-rollout-rv"
        candidate = directory / "candidate.json"
        candidate.write_bytes(json.dumps(current, indent=2).encode() + b"\n")
        output = directory / "rollback"
        argv[4] = str(output)
        argv += ["--rollback-deployment", str(candidate),
                 "--rollback-sha256", render.sha(candidate.read_bytes()),
                 "--rollback-captured-at", render.token.utc(),
                 "--rollback-closure", str(closure),
                 "--rollback-closure-sha256", render.sha(closure.read_bytes())]
        return argv, current

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
        rebound = self.rendered(**self.rollback_args(artifacts, current))
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
                self.rendered(**self.rollback_args(artifacts, changed))

    def test_rollback_frozen_originals_and_token_evidence_do_not_expire(self):
        artifacts = self.frozen_forward()
        original = copy.deepcopy(self.inputs)
        current = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        current["metadata"]["resourceVersion"] = "post-rollout-rv"
        args = self.rollback_args(artifacts, current)
        with patch.object(render.provision, "validate_metadata", side_effect=AssertionError("frozen UTC must stay frozen")), \
                patch.object(render.provision, "recent", wraps=render.provision.recent) as recent, \
                patch.object(render.token, "validate_record", wraps=render.token.validate_record) as records:
            rebound = self.rendered(**args)
        recent.assert_called_once_with(args["rollback_captured_at"])
        self.assertEqual(records.call_count, 4)
        self.assertEqual(self.inputs, original)
        self.assertEqual(patched(current, rebound["deployment-metrics-rollback-json-patch.json"])["spec"],
                         original["deployment.json"]["spec"])
        self.assertEqual(rebound["metrics-closure.json"]["rollback"]["forwardClosureSHA256"], args["rollback_closure_sha"])
        self.assertEqual(rebound["metrics-closure.json"]["rollback"]["capturedAt"], args["rollback_captured_at"])
        operations = rebound["deployment-metrics-rollback-json-patch.json"]
        for mutate in (lambda d: d["metadata"].update(uid="replacement"),
                       lambda d: d["metadata"].update(resourceVersion="later-status-update"),
                       lambda d: d["spec"].update(progressDeadlineSeconds=902)):
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                patched(changed, operations)
        with self.assertRaises(ValueError):
            self.rendered()

    def test_rollback_candidate_timestamp_is_required_bounded_fresh_and_utc(self):
        artifacts = self.frozen_forward()
        current = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        for value in (None, "", "x" * 65, "not-a-date", datetime.now().isoformat(),
                      (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat(),
                      (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
                      "2026-10-14T12:00:00+01:00"):
            args = self.rollback_args(artifacts, current)
            args["rollback_captured_at"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.rendered(**args)
        instant = datetime.now(timezone.utc)
        args = self.rollback_args(artifacts, current)
        args["rollback_captured_at"] = (instant - timedelta(minutes=30)).isoformat()
        with patch.object(render.provision, "datetime") as clock:
            clock.now.return_value = instant
            clock.fromisoformat.side_effect = datetime.fromisoformat
            self.rendered(**args)
            args["rollback_captured_at"] = (instant - timedelta(seconds=1800, microseconds=1)).isoformat()
            with self.assertRaises(ValueError):
                self.rendered(**args)

    def test_rollback_rejects_missing_closure_wrong_file_sha_and_modified_closure_bindings(self):
        artifacts = self.frozen_forward()
        current = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        args = self.rollback_args(artifacts, current)
        for key in args:
            missing = dict(args)
            missing[key] = None
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.rendered(**missing)
        for raw, digest in ((args["rollback_closure"], "0" * 64),
                            (args["rollback_closure"] + b"\n", args["rollback_closure_sha"]),
                            (b"{}", render.sha(b"{}"))):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.rendered(**(args | {"rollback_closure": raw, "rollback_closure_sha": digest}))
        mutations = [
            lambda c: c.update(schema="different-schema"),
            lambda c: c["capture"].update(manifestSHA256="0" * 64),
            lambda c: c["capture"]["sha256"].update({"pod.json": "0" * 64}),
            lambda c: c["inputsCanonicalSHA256"].update({"token-metadata.json": "0" * 64}),
            lambda c: c.update(metricsSourceSHA256="0" * 64),
            lambda c: c.update(sourceManifestSHA256="0" * 64),
            lambda c: c.update(originalSpecSHA256="0" * 64),
            lambda c: c.update(candidateSpecSHA256="0" * 64),
            lambda c: c.update(originalTemplateSHA256="0" * 64),
            lambda c: c.update(candidateTemplateSHA256="0" * 64),
            lambda c: c.update(tokenMetadataSHA256="0" * 64),
            lambda c: c["secretPair"]["secrets"][0].update(uid="recreated"),
            lambda c: c["tokenHelperProvenance"]["generate_metrics_token.py"].update(sourceSHA256="0" * 64),
            lambda c: c["artifactsSHA256"].update({"deployment-metrics-rollback-json-patch.json": "0" * 64}),
            lambda c: c["rollback"].update(requiresCurrentDeploymentCapture=False)]
        for mutate in mutations:
            changed = copy.deepcopy(artifacts["metrics-closure.json"])
            mutate(changed)
            raw = render.canonical(changed) + b"\n"
            # Even a matching file SHA cannot authorize an inconsistent closure.
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(**(args | {"rollback_closure": raw, "rollback_closure_sha": render.sha(raw)}))

    def test_rollback_rejects_frozen_capture_token_source_and_spec_tampering(self):
        artifacts = self.frozen_forward()
        current = patched(self.inputs["deployment.json"], artifacts["deployment-metrics-json-patch.json"])
        args = self.rollback_args(artifacts, current)
        for mutate in (lambda x: x["pod.json"]["metadata"].update(resourceVersion="later"),
                       lambda x: x["source.json"]["data"].update({"dual_server.py": "changed"}),
                       lambda x: x["token-metadata.json"].update(utc=render.token.utc()),
                       lambda x: x["token-metadata.json"]["secrets"][0].update(uid="recreated"),
                       lambda x: x["token-metadata.json"]["generator"].update(pairID="2" * 32)):
            changed = copy.deepcopy(self.inputs)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.rendered(changed, **args)
        for key in ("manifestSHA256", "capturedAt", "sha256"):
            changed = copy.deepcopy(self.capture)
            changed[key] = ({**changed[key], "token-metadata.json": "0" * 64} if key == "sha256"
                            else render.token.utc() if key == "capturedAt" else "0" * 64)
            with self.subTest(capture=key), self.assertRaises(ValueError):
                render.render(self.inputs, changed, SOURCE, **args)
        with self.assertRaises(ValueError):
            render.render(self.inputs, self.capture, SOURCE + b"# source drift\n", **args)
        for mutate in (lambda d: d["metadata"].update(uid="recreated"),
                       lambda d: d["spec"].update(replicas=2),
                       lambda d: d["spec"].update(progressDeadlineSeconds=902),
                       lambda d: d["spec"]["template"]["spec"]["initContainers"][-1].update(image="unreviewed")):
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.subTest(candidate=mutate), self.assertRaises(ValueError):
                self.rendered(**(args | {"rollback": changed, "rollback_sha": render.sha(render.canonical(changed))}))

    def test_frozen_token_whitelist_generator_provenance_and_identity_checks_remain_enforced(self):
        artifacts = self.frozen_forward()
        closure = artifacts["metrics-closure.json"]
        evidence = self.inputs["token-metadata.json"]
        for mutate in (
            lambda m: m.update(schema="stage5-schema"),
            lambda m: m["secrets"][0].update(data={"token": "forbidden"}),
            lambda m: m["secrets"][0].update(uid="recreated"),
            lambda m: m["secrets"][0].update(resourceVersion="drift"),
            lambda m: m["secrets"][0].update(provenance="stage5-v1"),
            lambda m: m["secrets"][0].update(ready=False),
            lambda m: m["secrets"][0].update(lastAppliedPresent=True),
            lambda m: m["generator"].update(sourceSHA256="0" * 64),
            lambda m: m["generator"].update(imageByDigest="unreviewed"),
            lambda m: m["generator"].update(jobUID=""),
            lambda m: m["generator"]["records"][0].update(immutable=False),
            lambda m: m["generator"]["records"][1].update(namespace="vllm"),
            lambda m: m["secrets"].pop()):
            changed = copy.deepcopy(evidence)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                render.frozen_token_records(changed, closure, closure["metricsProtection"])

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

    def test_cli_source_race_emits_no_artifacts(self):
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

    def test_cli_rollback_after_originals_and_tokens_expire_restores_exact_original(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            argv, current = self.prepare_rollback_cli(directory)
            forward = directory / "forward" / "metrics-closure.json"
            frozen_bytes = forward.read_bytes()
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()), \
                    patch.object(render.provision, "ProxyAPI", side_effect=AssertionError("renderer must stay offline")):
                self.assertEqual(render.main(), 0)
            output = directory / "rollback"
            operations = json.loads((output / "deployment-metrics-rollback-json-patch.json").read_bytes())
            self.assertEqual(patched(current, operations)["spec"], self.inputs["deployment.json"]["spec"])
            self.assertEqual(operations[1]["value"], "post-rollout-rv")
            closure = json.loads((output / "metrics-closure.json").read_bytes())
            self.assertEqual(closure["capture"], json.loads(frozen_bytes)["capture"])
            self.assertEqual(closure["rollback"]["forwardClosureSHA256"], render.sha(frozen_bytes))
            self.assertEqual(closure["rollback"]["captureSHA256"], render.sha((directory / "candidate.json").read_bytes()))
            self.assertEqual(closure["rollback"]["capturedAt"], argv[argv.index("--rollback-captured-at") + 1])
            for name, digest in closure["artifactsSHA256"].items():
                self.assertEqual(render.sha((output / name).read_bytes()), digest)
            self.assertEqual(forward.read_bytes(), frozen_bytes)
            with self.assertRaises(ValueError):
                render.load_inputs(directory / "inputs")
            # A rebound closure cannot replace the explicit original forward closure.
            argv[4] = str(directory / "second-rollback")
            argv[argv.index("--rollback-closure") + 1] = str(output / "metrics-closure.json")
            argv[argv.index("--rollback-closure-sha256") + 1] = render.sha((output / "metrics-closure.json").read_bytes())
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(render.main(), 1)
            self.assertFalse((directory / "second-rollback").exists())

    def test_cli_rollback_incomplete_flags_stale_candidate_and_wrong_file_hashes_emit_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            argv, _ = self.prepare_rollback_cli(Path(temp))
            flags = ("--rollback-deployment", "--rollback-sha256", "--rollback-captured-at",
                     "--rollback-closure", "--rollback-closure-sha256")
            refused = []
            for flag in flags:
                index = argv.index(flag)
                refused.append(argv[:index] + argv[index + 2:])
            for flag, value in (
                ("--rollback-sha256", "0" * 64), ("--rollback-closure-sha256", "0" * 64),
                ("--rollback-sha256", "a" * 65), ("--rollback-closure-sha256", "A" * 64),
                ("--rollback-captured-at", "x" * 65),
                ("--rollback-captured-at", (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()),
                ("--rollback-captured-at", (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat())):
                changed = list(argv)
                changed[changed.index(flag) + 1] = value
                refused.append(changed)
            for changed in refused:
                with self.subTest(argv=changed), patch.object(sys, "argv", changed), \
                        patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(render.main(), 1)
                self.assertFalse(Path(argv[4]).exists())

    def test_cli_rollback_frozen_capture_and_token_file_tampering_cannot_be_rehashed_away(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            argv, _ = self.prepare_rollback_cli(directory)
            inputs = directory / "inputs"
            originals = {name: (inputs / name).read_bytes() for name in (*render.INPUT_FILES, "captures.json")}
            for filename in ("captures.json", "deployment.json", "pod.json", "source.json", "token-metadata.json"):
                for repair_manifest in (False, True):
                    for name, raw in originals.items():
                        (inputs / name).write_bytes(raw)
                    (inputs / filename).write_bytes(originals[filename] + b"\n")
                    if repair_manifest and filename != "captures.json":
                        manifest = json.loads(originals["captures.json"])
                        manifest["sha256"][filename] = render.sha((inputs / filename).read_bytes())
                        (inputs / "captures.json").write_bytes(render.canonical(manifest))
                    with self.subTest(filename=filename, repair=repair_manifest), \
                            patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                        self.assertEqual(render.main(), 1)
                    self.assertFalse(Path(argv[4]).exists())
            # Refreshing UTC and repinning the manifest cannot change frozen token evidence.
            for name, raw in originals.items():
                (inputs / name).write_bytes(raw)
            evidence = json.loads(originals["token-metadata.json"])
            evidence["utc"] = render.token.utc()
            (inputs / "token-metadata.json").write_bytes(render.canonical(evidence))
            manifest = json.loads(originals["captures.json"])
            manifest["sha256"]["token-metadata.json"] = render.sha((inputs / "token-metadata.json").read_bytes())
            (inputs / "captures.json").write_bytes(render.canonical(manifest))
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(render.main(), 1)
            self.assertFalse(Path(argv[4]).exists())

    def test_cli_rollback_candidate_and_closure_are_exact_bounded_regular_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            argv, current = self.prepare_rollback_cli(directory)
            candidate = directory / "candidate.json"
            closure = directory / "forward" / "metrics-closure.json"
            for path, limit in ((candidate, render.MAX_CAPTURE), (closure, render.MAX_CLOSURE)):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(render.main(), 1)
                self.assertFalse(Path(argv[4]).exists())
                path.unlink()
                path.symlink_to(directory / "inputs" / "deployment.json")
                with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(render.main(), 1)
                path.unlink()
                with path.open("wb") as stream:
                    stream.truncate(limit + 1)
                with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(render.main(), 1)
                self.assertFalse(Path(argv[4]).exists())
                path.write_bytes(original)
            current["spec"]["progressDeadlineSeconds"] += 1
            candidate.write_bytes(render.canonical(current))
            argv[argv.index("--rollback-sha256") + 1] = render.sha(candidate.read_bytes())
            with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(render.main(), 1)
            self.assertFalse(Path(argv[4]).exists())

    def test_forward_cli_stale_original_capture_and_stale_token_metadata_still_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inputs = directory / "inputs"
            inputs.mkdir()
            stale = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()
            write_inputs(inputs, self.inputs, stale)
            with self.assertRaises(ValueError):
                render.load_inputs(inputs)
            for phase in ("capture", "token"):
                if phase == "token":
                    self.inputs["token-metadata.json"]["utc"] = stale
                    write_inputs(inputs, self.inputs)
                    render.load_inputs(inputs)  # Fresh manifest; stale token must still fail rendering.
                output = directory / phase
                argv = ["render.py", "--inputs", str(inputs), "--output", str(output)]
                with patch.object(sys, "argv", argv), patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(render.main(), 1)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
