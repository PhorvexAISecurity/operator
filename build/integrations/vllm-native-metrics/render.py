"""Offline Stage6 renderer with fresh forward and closure-bound rollback evidence.

Nothing here contacts Kubernetes. JSON output is also valid YAML. The initial
inverse is review-only. Rebind it with all five --rollback-* arguments: a fresh
candidate Deployment file/SHA/UTC and the frozen forward closure file/SHA.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import generate_metrics_token as token
import provision_metrics_token as provision

ROOT = Path(__file__).resolve().parent
NAME = "phorvex-vllm-native-metrics"
SIDECAR = "phorvex-vllm-metrics"
OPT_IN = "phorvex.ai/vllm-native-metrics"
SOURCE_ANNOTATION = "phorvex.ai/vllm-native-metrics-source-sha256"
SOURCE_VOLUME = "phorvex-vllm-metrics-source"
TOKEN_VOLUME = "phorvex-vllm-metrics-token"
TOKEN_FILE = "/etc/phorvex-vllm-metrics/token"
CAPTURE_SCHEMA = "phorvex-vllm-native-metrics-captures-v1"
CLOSURE_SCHEMA = "phorvex-vllm-native-metrics-closure-v1"
INPUT_FILES = ("deployment.json", "pod.json", "replicaset.json", "service.json",
               "endpointslices.json", "source.json", "policy.json", "journal.json",
               "drain-journals.json", "inventory.json", "token-metadata.json")
LEASE_SOURCE_FILES = ("guardrail_proxy.py", "dual_server.py", "endpoint_lease.py",
                      "drain_v11.py", "drain_v11_init.py")
MAX_CAPTURE = 32 << 20
MAX_CLOSURE = 1 << 20
MAX_TIMESTAMP = 64
SHA = re.compile(r"[0-9a-f]{64}\Z")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def json_bytes(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "nonfinite JSON value"))


def read_bounded(path, limit=MAX_CAPTURE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                "bounded regular capture required")
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "capture exceeds bound")
    return raw


def identity(obj, kind, name=None, namespace="vllm"):
    require(isinstance(obj, dict) and obj.get("kind") == kind and obj.get("apiVersion"),
            "full object kind/version required")
    meta = obj.get("metadata", {})
    require(meta.get("namespace") == namespace and (name is None or meta.get("name") == name) and
            all(isinstance(meta.get(key), str) and meta[key] for key in ("name", "uid", "resourceVersion")) and
            not meta.get("deletionTimestamp"), "object name/namespace/UID/RV differs")
    return {key: meta[key] for key in ("namespace", "name", "uid", "resourceVersion")}


def full_list(value, kind, namespace):
    require(isinstance(value, dict) and value.get("kind") in ("List", kind + "List") and
            value.get("apiVersion") and isinstance(value.get("metadata"), dict) and
            isinstance(value.get("items"), list), "full API List capture required")
    identities = [identity(obj, kind, namespace=namespace) for obj in value["items"]]
    require(len({x["name"] for x in identities}) == len(identities) and
            len({x["uid"] for x in identities}) == len(identities), "duplicate inventory object")
    return value["items"]


def no_secret_objects(value):
    if isinstance(value, dict):
        require(value.get("kind") != "Secret" and "stringData" not in value,
                "credential data forbidden in captures")
        for item in value.values():
            no_secret_objects(item)
    elif isinstance(value, list):
        for item in value:
            no_secret_objects(item)


def forward_closure(raw, digest):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_CLOSURE and
            isinstance(digest, str) and SHA.fullmatch(digest) and sha(raw) == digest,
            "forward closure file SHA256 drift or byte bound")
    closure = json_bytes(raw)
    no_secret_objects(closure)
    require(isinstance(closure, dict) and closure.get("schema") == CLOSURE_SCHEMA and
            closure.get("activation") == "review-only" and
            closure.get("rollback", {}).get("requiresCurrentDeploymentCapture") is True and
            closure["rollback"].get("captureSHA256") is None,
            "original forward closure required")
    return closure


def fresh_rollback_timestamp(value):
    require(isinstance(value, str) and 0 < len(value) <= MAX_TIMESTAMP,
            "bounded rollback capture UTC required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0,
            "rollback capture timestamp must be UTC")
    provision.recent(value)


def load_inputs(directory, rollback_closure=None, rollback_closure_sha=None):
    require((rollback_closure is None) == (rollback_closure_sha is None), "forward closure pair required")
    frozen = None if rollback_closure is None else forward_closure(rollback_closure, rollback_closure_sha)
    manifest_raw = read_bounded(directory / "captures.json", 16384)
    manifest = json_bytes(manifest_raw)
    require(set(manifest) == {"schema", "capturedAt", "sha256"} and
            manifest["schema"] == CAPTURE_SCHEMA and isinstance(manifest["sha256"], dict) and
            set(manifest["sha256"]) == set(INPUT_FILES), "exact capture manifest required")
    if frozen is None:
        provision.recent(manifest["capturedAt"])
    inputs, hashes = {}, {}
    total = 0
    for filename in INPUT_FILES:
        expected = manifest["sha256"][filename]
        require(isinstance(expected, str) and SHA.fullmatch(expected), "invalid input SHA256")
        raw = read_bounded(directory / filename)
        total += len(raw)
        require(total <= 64 << 20 and sha(raw) == expected, "capture SHA256 drift or total byte bound")
        inputs[filename] = json_bytes(raw)
        hashes[filename] = sha(raw)
        no_secret_objects(inputs[filename])
    capture = {"manifestSHA256": sha(manifest_raw), "capturedAt": manifest["capturedAt"], "sha256": hashes}
    if frozen is not None:
        require(capture == frozen.get("capture"), "frozen capture versus forward closure drift")
    return inputs, capture


def controller(obj, kind, parent):
    owners = [x for x in obj["metadata"].get("ownerReferences", []) if x.get("controller") is True]
    require(len(owners) == 1 and owners[0].get("kind") == kind and
            owners[0].get("name") == parent["metadata"]["name"] and
            owners[0].get("uid") == parent["metadata"]["uid"], "controller UID/name drift")


def matches(current, expected):
    # Pod admission may add fields; it cannot change any captured template field.
    if isinstance(expected, dict):
        return isinstance(current, dict) and all(key in current and matches(current[key], value)
                                                 for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(current, list) and len(current) == len(expected) and all(
            matches(a, b) for a, b in zip(current, expected))
    return type(current) is type(expected) and current == expected


def without_template_hash(template):
    result = copy.deepcopy(template)
    result.get("metadata", {}).get("labels", {}).pop("pod-template-hash", None)
    return result


def pod_matches_template(current, expected):
    # DefaultTolerationSeconds admission appends these two to live Pods only.
    # Compare every original toleration and allow only these exact additions.
    actual = copy.deepcopy(current)
    original = expected.get("tolerations", [])
    extras = copy.deepcopy(actual.get("tolerations", []))
    for toleration in original:
        if toleration not in extras:
            return False
        extras.remove(toleration)
    defaults = [{"key": "node.kubernetes.io/" + key, "operator": "Exists",
                 "effect": "NoExecute", "tolerationSeconds": 300}
                for key in ("not-ready", "unreachable")]
    if len(extras) > 2 or any(extras.count(t) != 1 or t not in defaults for t in extras):
        return False
    actual["tolerations"] = original
    if actual.get("ephemeralContainers"):
        return False
    return matches(actual, expected)


def literal_env(container, name, expected):
    rows = [x for x in container.get("env", []) if x.get("name") == name]
    require(len(rows) == 1 and rows[0].get("value") == expected and "valueFrom" not in rows[0],
            "captured serving environment binding differs")


def option(args, name, expected):
    require(isinstance(args, list) and args.count(name) == 1, "engine argument binding differs")
    pos = args.index(name)
    require(pos + 1 < len(args) and args[pos + 1] == expected, "engine argument binding differs")


def validate_baseline(inputs):
    dep, pod, rs, service, source, policy, journal = [inputs[n + ".json"] for n in
        ("deployment", "pod", "replicaset", "service", "source", "policy", "journal")]
    identities = {name: identity(obj, kind, expected, ns) for name, obj, kind, expected, ns in (
        ("deployment", dep, "Deployment", "vllm", "vllm"),
        ("pod", pod, "Pod", None, "vllm"), ("replicaset", rs, "ReplicaSet", None, "vllm"),
        ("service", service, "Service", "vllm", "vllm"),
        ("source", source, "ConfigMap", "guardrail-proxy", "vllm"),
        ("policy", policy, "ConfigMap", "phorvex-endpoint-lease-policy", "vllm"),
        ("journal", journal, "ConfigMap", "phorvex-endpoint-lease-journal", "phorvex-system"))}
    spec = dep.get("spec", {})
    require(spec.get("replicas") == 1 and spec.get("strategy") == {
        "type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}},
        "singleton rollout strategy differs")
    require(dep.get("status", {}).get("observedGeneration") == dep["metadata"].get("generation") and
            all(dep.get("status", {}).get(key) == 1 for key in
                ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")),
            "settled singleton Deployment required")
    template = spec["template"]
    ps = template["spec"]
    require(ps.get("automountServiceAccountToken") is False and
            ps.get("securityContext", {}).get("fsGroup") == 10001 and
            all(ps.get(key, False) is False and pod["spec"].get(key, False) is False
                for key in ("hostNetwork", "hostPID", "hostIPC")), "Pod credential or namespace isolation differs")
    containers, init = ps.get("containers", []), ps.get("initContainers", [])
    require(len(containers) == 2 and {c.get("name") for c in containers} == {"vllm", "guardrail"} and
            len(init) == 1 and init[0].get("name") == "phorvex-drain-ledger-init" and
            "restartPolicy" not in init[0], "original serving/ledger container contract differs")
    require(template.get("metadata", {}).get("labels", {}).get("app") == "vllm" and
            matches(template["metadata"]["labels"], spec.get("selector", {}).get("matchLabels", {})) and
            not spec.get("selector", {}).get("matchExpressions"), "workload selector differs")
    controller(pod, "ReplicaSet", rs)
    controller(rs, "Deployment", dep)
    require(without_template_hash(rs["spec"]["template"]) == template and
            pod_matches_template(pod["spec"], ps) and matches(pod["metadata"].get("labels", {}), template["metadata"]["labels"]) and
            matches(pod["metadata"].get("annotations", {}), template["metadata"].get("annotations", {})),
            "Deployment/ReplicaSet/Pod template drift")
    status = pod.get("status", {})
    require(status.get("phase") == "Running" and status.get("podIP") and pod["spec"].get("nodeName") and
            any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])),
            "one Ready scheduled Pod required")
    statuses = status.get("containerStatuses", [])
    require(len(statuses) == 2 and {s.get("name") for s in statuses} == {"vllm", "guardrail"} and
            all(s.get("ready") is True and s.get("containerID") and
                re.search(r"sha256:[0-9a-f]{64}$", s.get("imageID", "")) for s in statuses),
            "original serving runtime identities required")
    engine = next(c for c in containers if c["name"] == "vllm")
    guard = next(c for c in containers if c["name"] == "guardrail")
    option(engine.get("args"), "--host", "127.0.0.1")
    option(engine.get("args"), "--port", "8001")
    for container in containers + init:
        require(container.get("name") != SIDECAR and
                all(p.get("containerPort") != 9102 and p.get("name") != "engine-metrics"
                    for p in container.get("ports", [])), "sidecar name/port collision")
    volumes = ps.get("volumes", [])
    require(len({v.get("name") for v in volumes}) == len(volumes) and
            not {SOURCE_VOLUME, TOKEN_VOLUME} & {v.get("name") for v in volumes} and
            OPT_IN not in template["metadata"].get("labels", {}) and
            SOURCE_ANNOTATION not in template["metadata"].get("annotations", {}) and
            not provision.credential_reference(template), "metrics label/source/volume/credential collision")
    require(source.get("immutable") is True and not source.get("binaryData") and
            set(source.get("data", {})) == set(LEASE_SOURCE_FILES) and
            all(isinstance(v, str) and 0 < len(v.encode()) <= 1 << 20 for v in source["data"].values()),
            "original immutable five-file source required")
    source_sha = sha(b"\0".join(source["data"][name].encode() for name in LEASE_SOURCE_FILES))
    annotations = template["metadata"].get("annotations", {})
    require(annotations.get("phorvex.ai/endpoint-lease-source-configmap") == "guardrail-proxy" and
            annotations.get("phorvex.ai/endpoint-lease-source-sha256") == source_sha and
            annotations.get("phorvex.ai/endpoint-lease-policy-configmap-uid") == identities["policy"]["uid"],
            "source/policy annotation closure differs")
    require(set(policy.get("data", {})) == {"state.json"} and not policy.get("binaryData"),
            "full lease policy required")
    state = json_bytes(policy["data"]["state.json"].encode())
    require(state.get("version") == 1 and type(state.get("revision")) is int and state["revision"] >= 0 and
            state.get("serviceUID") == identities["service"]["uid"] and state.get("proxySourceSHA256") == source_sha and
            isinstance(state.get("secretUID"), str) and state["secretUID"], "lease source/service state differs")
    for key, expected in (("PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", source_sha),
            ("PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", identities["policy"]["uid"]),
            ("PHORVEX_ENDPOINT_LEASE_SERVICE_UID", identities["service"]["uid"]),
            ("PHORVEX_ENDPOINT_LEASE_SECRET_UID", state["secretUID"]),
            ("PHORVEX_ENDPOINT_LEASE_REQUIRED", "true")):
        literal_env(guard, key, expected)
    source_volumes = [v for v in volumes if v.get("configMap", {}).get("name") == "guardrail-proxy"]
    require(len(source_volumes) == 1 and source_volumes[0]["configMap"].get("optional") is not True,
            "original serving source projection differs")
    source_name = source_volumes[0]["name"]
    for filename in LEASE_SOURCE_FILES:
        require(any(m.get("name") == source_name and m.get("mountPath") == "/src/" + filename and
                    m.get("subPath") == filename and m.get("readOnly") is True for m in guard.get("volumeMounts", [])),
                "original serving source mount differs")
    require(service.get("spec", {}).get("type", "ClusterIP") == "ClusterIP" and
            service["spec"].get("selector") and
            matches(pod["metadata"]["labels"], service["spec"]["selector"]) and
            any(p.get("port") == 8000 and p.get("targetPort") == 8000 and p.get("protocol", "TCP") == "TCP"
                for p in service["spec"].get("ports", [])), "serving Service route differs")
    slices = full_list(inputs["endpointslices.json"], "EndpointSlice", "vllm")
    ready = []
    for item in slices:
        require(item["metadata"].get("labels", {}).get("kubernetes.io/service-name") == "vllm",
                "EndpointSlice Service label differs")
        controller(item, "Service", service)
        require(any(p.get("port") == 8000 and p.get("protocol", "TCP") == "TCP" for p in item.get("ports", [])),
                "serving EndpointSlice port differs")
        ready.extend(e for e in item.get("endpoints", []) if e.get("conditions", {}).get("ready") is True)
    require(len(ready) == 1 and ready[0].get("addresses") == [status["podIP"]] and
            ready[0].get("targetRef", {}).get("kind") == "Pod" and
            ready[0]["targetRef"].get("name") == identities["pod"]["name"] and
            ready[0]["targetRef"].get("uid") == identities["pod"]["uid"] and
            ready[0].get("conditions", {}).get("terminating", False) is False,
            "sole Ready endpoint Pod/IP drift")
    require(set(journal.get("data", {})) == {"receipts.json"} and not journal.get("binaryData"),
            "full protected lease journal required")
    receipts = json_bytes(journal["data"]["receipts.json"].encode())
    require(receipts.get("version") == 1 and isinstance(receipts.get("receipts"), list) and
            all(r.get("phase") == "terminal-full" for r in receipts["receipts"]),
            "unresolved protected lease operation")
    drain = full_list(inputs["drain-journals.json"], "ConfigMap", "phorvex-system")
    historical = []
    for obj in drain:
        require(set(obj.get("data", {})) == {"receipt"} and not obj.get("binaryData"), "full drain journal required")
        receipt = json_bytes(obj["data"]["receipt"].encode())
        require(receipt.get("kind") == "request-drain" and receipt.get("policyNamespace") == "vllm" and
                receipt.get("serviceUID") == identities["service"]["uid"], "drain journal domain differs")
        require(receipt.get("targetUID") and receipt["targetUID"] != identities["pod"]["uid"],
                "current-Pod drain operation requires lead reconciliation")
        historical.append({**identity(obj, "ConfigMap", namespace="phorvex-system"),
                           "targetUID": receipt["targetUID"], "phase": receipt.get("phase"),
                           "receiptSHA256": sha(obj["data"]["receipt"].encode())})
    return {"identities": identities, "servingRuntime": statuses,
            "servingSourceSHA256": source_sha, "leasePolicyRevision": state["revision"],
            "leasePolicyStateSHA256": sha(policy["data"]["state.json"].encode()),
            "protectedJournalSHA256": sha(journal["data"]["receipts.json"].encode()),
            "historicalDrainJournals": historical}


def metrics_protection():
    return {"mode": "bearerToken", "secretName": token.NAME, "secretKey": "token",
            "workloadNamespace": "vllm", "monitorNamespace": "monitoring", "tokenFile": TOKEN_FILE}


def monitoring_objects(source):
    require(isinstance(source, bytes) and 0 < len(source) <= 1 << 20, "bounded final metrics source required")
    source.decode("utf-8")
    digest = sha(source)
    labels = {"app.kubernetes.io/name": NAME, "phorvex.ai/metrics-job": "vllm"}
    configmap = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": NAME + "-" + digest[:12], "namespace": "vllm",
        "labels": {"app.kubernetes.io/name": NAME}, "annotations": {SOURCE_ANNOTATION: digest}},
        "immutable": True, "data": {"metrics.py": source.decode("utf-8")}}
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {
        "name": NAME, "namespace": "vllm", "labels": labels}, "spec": {"type": "ClusterIP",
        "selector": {"app": "vllm", OPT_IN: "enabled"},
        "ports": [{"name": "engine-metrics", "port": 9102, "targetPort": 9102, "protocol": "TCP"}]}}
    monitor = {"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor", "metadata": {
        "name": NAME, "namespace": "monitoring", "labels": {"release": "kube-prom-stack",
        "app.kubernetes.io/name": NAME}}, "spec": {"jobLabel": "phorvex.ai/metrics-job",
        "namespaceSelector": {"matchNames": ["vllm"]}, "selector": {"matchLabels": labels},
        "endpoints": [{"port": "engine-metrics", "path": "/metrics", "scheme": "http",
        "interval": "30s", "scrapeTimeout": "5s", "honorLabels": False, "followRedirects": False,
        "authorization": {"type": "Bearer", "credentials": {"name": token.NAME, "key": "token", "optional": False}},
        "relabelings": [{"action": "replace", "sourceLabels": ["__meta_kubernetes_namespace"], "targetLabel": "namespace"},
                         {"action": "replace", "sourceLabels": ["__meta_kubernetes_pod_name"], "targetLabel": "pod"},
                         {"action": "replace", "sourceLabels": ["__meta_kubernetes_pod_node_name"], "targetLabel": "node"},
                         {"action": "replace", "targetLabel": "container", "replacement": "vllm"}]}]}}
    return [configmap, service, monitor]


def source_manifest(source):
    return ("# Generated by build/integrations/vllm-native-metrics/render.py from final metrics.py bytes.\n"
            "# Apply source before rollout; after serving proof create Service, run auth proof, then activate ServiceMonitor.\n" +
            "\n---\n".join(json.dumps(obj, indent=2, ensure_ascii=True) for obj in monitoring_objects(source)) + "\n").encode()


def sidecar(source_name):
    return {"name": SIDECAR, "image": token.IMAGE, "imagePullPolicy": "IfNotPresent",
        "restartPolicy": "Always", "command": ["python3", "-B", "/opt/phorvex/metrics.py"],
        "ports": [{"name": "engine-metrics", "containerPort": 9102, "protocol": "TCP"}],
        "securityContext": provision.security(),
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}},
        "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File",
        "volumeMounts": [{"name": SOURCE_VOLUME, "mountPath": "/opt/phorvex/metrics.py", "subPath": "metrics.py", "readOnly": True},
                         {"name": TOKEN_VOLUME, "mountPath": "/etc/phorvex-vllm-metrics", "readOnly": True}]}


def candidate_spec(dep, objects):
    result = copy.deepcopy(dep["spec"])
    template = result["template"]
    template["metadata"].setdefault("labels", {})[OPT_IN] = "enabled"
    template["metadata"].setdefault("annotations", {})[SOURCE_ANNOTATION] = objects[0]["metadata"]["annotations"][SOURCE_ANNOTATION]
    ps = template["spec"]
    ps["initContainers"].append(sidecar(objects[0]["metadata"]["name"]))
    ps["volumes"].extend([
        {"name": SOURCE_VOLUME, "configMap": {"name": objects[0]["metadata"]["name"], "optional": False,
                                              "defaultMode": 0o444, "items": [{"key": "metrics.py", "path": "metrics.py"}]}},
        {"name": TOKEN_VOLUME, "secret": {"secretName": token.NAME, "optional": False,
                                          "defaultMode": 0o440, "items": [{"key": "token", "path": "token", "mode": 0o440}]}}])
    return result


def reject_collisions(inventory, objects, inputs):
    require(isinstance(inventory, dict) and set(inventory) == {"configMaps", "services", "serviceMonitors"},
            "fresh bounded object inventory required")
    by_kind = {}
    for key, kind, ns in (("configMaps", "ConfigMap", "vllm"), ("services", "Service", "vllm"),
                          ("serviceMonitors", "ServiceMonitor", "monitoring")):
        by_kind[kind] = full_list(inventory[key], kind, ns)
    for obj in objects:
        require(not any(item["metadata"]["name"] == obj["metadata"]["name"] for item in by_kind[obj["kind"]]),
                "new source/Service/ServiceMonitor name collision")
    # Prevent a valid-looking original from disagreeing with the fresh list read.
    for filename, kind in (("source.json", "ConfigMap"), ("policy.json", "ConfigMap"), ("service.json", "Service")):
        original = inputs[filename]
        found = [obj for obj in by_kind[kind] if obj["metadata"]["name"] == original["metadata"]["name"]]
        require(len(found) == 1 and found[0] == original, "baseline versus inventory capture drift")


def guarded_patch(dep, expected_spec, template):
    return [{"op": "test", "path": "/metadata/uid", "value": dep["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": dep["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": copy.deepcopy(expected_spec)},
            {"op": "replace", "path": "/spec/template", "value": copy.deepcopy(template)}]


def frozen_token_records(evidence, closure, protection):
    # The forward closure binds the original metadata bytes and their UTC. Validate
    # their whitelist/identities without refreshing UTC or changing helper behavior.
    require(isinstance(evidence, dict) and set(evidence) == {"schema", "utc", "generator", "secrets"} and
            evidence["schema"] == provision.SCHEMA and closure.get("metricsProtection") == protection,
            "frozen credential schema or protection differs")
    generator = evidence["generator"]
    require(isinstance(generator, dict) and
            set(generator) == {"jobUID", "sourceSHA256", "imageByDigest", "pairID", "records"} and
            isinstance(generator["jobUID"], str) and generator["jobUID"] and
            generator["imageByDigest"] == token.IMAGE and
            generator["sourceSHA256"] == sha(read_bounded(ROOT / "generate_metrics_token.py", 1 << 20)) and
            isinstance(generator["records"], list) and len(generator["records"]) == 2 and
            isinstance(evidence["secrets"], list) and len(evidence["secrets"]) == 2,
            "complete frozen generator provenance required")
    pair_id = generator["pairID"]
    post = {}
    for record in generator["records"]:
        token.validate_record(record, pair_id, filled=True)
        require(record["namespace"] not in post, "duplicate frozen generator namespace")
        post[record["namespace"]] = record
    observed = {}
    for record in evidence["secrets"]:
        require(isinstance(record, dict) and set(record) == token.SAFE_KEYS and record.get("ready") is True,
                "frozen metadata-only readback required")
        full = dict(record, immutable=True)
        token.validate_record(full, pair_id, filled=True)
        namespace = record["namespace"]
        require(namespace not in observed and full == post.get(namespace),
                "frozen credential UID or resourceVersion drift")
        observed[namespace] = record
    require(set(post) == set(observed) == set(token.NAMESPACES), "complete frozen credential pair required")
    records = [observed[namespace] for namespace in token.NAMESPACES]
    require(closure.get("secretPair") == {"pairID": pair_id, "secrets": records},
            "frozen credential pair versus forward closure drift")
    return records


def render(inputs, capture, source, rollback=None, rollback_sha=None,
           rollback_closure=None, rollback_closure_sha=None, rollback_captured_at=None):
    rollback_args = (rollback, rollback_sha, rollback_closure, rollback_closure_sha, rollback_captured_at)
    require(all(x is None for x in rollback_args) or all(x is not None for x in rollback_args),
            "all five rollback inputs required")
    require(set(inputs) == set(INPUT_FILES) and set(capture) == {"manifestSHA256", "capturedAt", "sha256"} and
            set(capture["sha256"]) == set(INPUT_FILES) and
            all(isinstance(value, str) and SHA.fullmatch(value) for value in
                [capture["manifestSHA256"], *capture["sha256"].values()]), "full SHA-bound capture set required")
    input_hashes = {name: sha(canonical(value)) for name, value in inputs.items()}
    frozen = None
    if rollback is None:
        provision.recent(capture["capturedAt"])
    else:
        frozen = forward_closure(rollback_closure, rollback_closure_sha)
        require(capture == frozen.get("capture") and input_hashes == frozen.get("inputsCanonicalSHA256"),
                "frozen originals versus forward closure drift")
        require(isinstance(rollback_sha, str) and SHA.fullmatch(rollback_sha), "rollback capture SHA256 required")
        fresh_rollback_timestamp(rollback_captured_at)
        no_secret_objects(rollback)
    baseline = validate_baseline(inputs)
    objects = monitoring_objects(source)
    reject_collisions(inputs["inventory.json"], objects, inputs)
    protection = metrics_protection() | {"authenticatedSourceSHA256": sha(source)}
    records = (provision.validate_metadata(inputs["token-metadata.json"], {"metricsProtection": protection})
               if frozen is None else frozen_token_records(inputs["token-metadata.json"], frozen, protection))
    dep = inputs["deployment.json"]
    candidate = candidate_spec(dep, objects)
    if rollback is not None:
        identity(rollback, "Deployment", "vllm")
        require(rollback["metadata"]["uid"] == dep["metadata"]["uid"] and rollback.get("spec") == candidate,
                "rollback stable UID or full candidate spec drift")
    artifacts = {
        "metrics-source-configmap.json": objects[0], "metrics-service.json": objects[1], "metrics-servicemonitor.json": objects[2],
        "deployment-metrics-json-patch.json": guarded_patch(dep, dep["spec"], candidate["template"]),
        "deployment-metrics-rollback-json-patch.json": guarded_patch(dep, candidate, dep["spec"]["template"]),
        "deployment-original-template.json": dep["spec"]["template"], "deployment-candidate-spec.json": candidate}
    closure = {"schema": CLOSURE_SCHEMA, "activation": "review-only",
        "capture": capture, "inputsCanonicalSHA256": input_hashes, "baseline": baseline, "metricsSourceSHA256": sha(source),
        "metricsImageByDigest": token.IMAGE, "sourceConfigMapName": objects[0]["metadata"]["name"],
        "sourceManifestSHA256": sha(source_manifest(source)),
        "originalSpecSHA256": sha(canonical(dep["spec"])), "candidateSpecSHA256": sha(canonical(candidate)),
        "originalTemplateSHA256": sha(canonical(dep["spec"]["template"])),
        "candidateTemplateSHA256": sha(canonical(candidate["template"])),
        "metricsProtection": protection, "tokenMetadataSHA256": capture["sha256"]["token-metadata.json"],
        "secretPair": {"pairID": inputs["token-metadata.json"]["generator"]["pairID"], "secrets": records},
        "tokenHelperProvenance": {name: {"parent": module.PARENT_PROVENANCE,
            "sourceSHA256": sha(read_bounded(ROOT / name, 1 << 20))} for name, module in (
                ("generate_metrics_token.py", token), ("provision_metrics_token.py", provision))},
        "monitoringSpecsSHA256": {o["kind"]: sha(canonical(o.get("spec", o))) for o in objects},
        "rollback": {"resourceVersion": dep["metadata"]["resourceVersion"],
            "requiresCurrentDeploymentCapture": True, "captureSHA256": None},
        "artifactsSHA256": {name: sha(canonical(value) + b"\n") for name, value in artifacts.items()}}
    if frozen is not None:
        # Compare the entire regenerated forward closure before rebinding its
        # inverse. This includes file/manifest/source/spec/token/helper hashes.
        require(canonical(closure) == canonical(frozen), "regenerated forward closure drift")
        name = "deployment-metrics-rollback-json-patch.json"
        artifacts[name] = guarded_patch(rollback, candidate, dep["spec"]["template"])
        closure["artifactsSHA256"][name] = sha(canonical(artifacts[name]) + b"\n")
        closure["rollback"] = {"resourceVersion": rollback["metadata"]["resourceVersion"],
            "requiresCurrentDeploymentCapture": False, "captureSHA256": rollback_sha,
            "capturedAt": rollback_captured_at, "forwardClosureSHA256": rollback_closure_sha}
    require(len(canonical(closure) + b"\n") <= MAX_CLOSURE, "closure exceeds byte bound")
    artifacts["metrics-closure.json"] = closure
    return artifacts


def write_artifacts(output, artifacts, source):
    # An existing output directory is never overwritten or partially refreshed.
    output.mkdir(mode=0o700)
    for name, value in artifacts.items():
        with (output / name).open("xb") as stream:
            stream.write(canonical(value) + b"\n")
    with (output / "vllm-native-metrics.yaml").open("xb") as stream:
        stream.write(source_manifest(source))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rollback-deployment", type=Path, help="full current candidate Deployment, at most 32MiB")
    parser.add_argument("--rollback-sha256", help="64 lowercase hex digits: exact candidate file SHA256")
    parser.add_argument("--rollback-captured-at", help="candidate capture UTC, at most 64 characters, age 0..1800s")
    parser.add_argument("--rollback-closure", type=Path, help="frozen forward metrics-closure.json, at most 1MiB")
    parser.add_argument("--rollback-closure-sha256", help="64 lowercase hex digits: exact forward closure file SHA256")
    args = parser.parse_args()
    try:
        rollback_args = (args.rollback_deployment, args.rollback_sha256, args.rollback_captured_at,
                         args.rollback_closure, args.rollback_closure_sha256)
        require(all(x is None for x in rollback_args) or all(x is not None for x in rollback_args),
                "all five rollback flags required")
        closure_raw = None
        if args.rollback_deployment is not None:
            require(isinstance(args.rollback_sha256, str) and SHA.fullmatch(args.rollback_sha256),
                    "rollback capture SHA256 required")
            fresh_rollback_timestamp(args.rollback_captured_at)
            closure_raw = read_bounded(args.rollback_closure, MAX_CLOSURE)
        inputs, capture = load_inputs(args.inputs, closure_raw, args.rollback_closure_sha256)
        source = read_bounded(ROOT / "metrics.py", 1 << 20)
        rollback = None
        if args.rollback_deployment is not None:
            raw = read_bounded(args.rollback_deployment)
            require(sha(raw) == args.rollback_sha256, "rollback capture SHA256 drift")
            rollback = json_bytes(raw)
            no_secret_objects(rollback)
        artifacts = render(inputs, capture, source, rollback, args.rollback_sha256,
                           closure_raw, args.rollback_closure_sha256, args.rollback_captured_at)
        # Do not publish a closure if another worker changed the mounted program.
        require(read_bounded(ROOT / "metrics.py", 1 << 20) == source, "metrics source changed during rendering")
        write_artifacts(args.output, artifacts, source)
        print(json.dumps({"result": "rendered-review-only", "metricsSourceSHA256": sha(source),
                          "inverseNeedsFreshDeployment": rollback is None}))
        return 0
    except Exception:
        # Never echo capture contents, API paths, environment values or tokens.
        print("native metrics render refused: captures/source/token metadata must be complete, fresh and consistent")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
