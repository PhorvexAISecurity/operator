"""Bounded bootstrap/evidence/cleanup through an authorized loopback API proxy.

No outside-cluster Secret GET can negotiate a full object. Empty slots are created
exclusively; only the in-cluster generator fills them. All failures are fixed safe
categories. There is no adopt, overwrite, replacement, or rotation mode.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from generate_metrics_token import (IMAGE, NAME, NAMESPACES, PARTIAL_ACCEPT, SAFE_KEYS,
    NoRedirect, SafeFailure, canonical, labels, runtime_image_matches, safe_record, secret_path, utc, validate_record)

SCHEMA = "phorvex-litellm-metrics-secret-metadata-v1"
ROOT = Path(__file__).resolve().parent


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def recent(value):
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(value.replace("Z", "+00:00"))).total_seconds()
    except Exception:
        raise SafeFailure("invalid evidence timestamp") from None
    if not 0 <= age <= 1800:
        raise SafeFailure("fresh credential evidence required")


def validate_metadata(evidence, closure=None):
    if set(evidence) != {"schema", "utc", "generator", "secrets"} or evidence["schema"] != SCHEMA:
        raise SafeFailure("invalid credential evidence schema")
    recent(evidence["utc"])
    generator = evidence["generator"]
    if (set(generator) != {"jobUID", "sourceSHA256", "imageByDigest", "pairID", "records"} or
            not generator.get("jobUID") or generator["imageByDigest"] != IMAGE or
            generator.get("sourceSHA256") != hashlib.sha256((ROOT / "generate_metrics_token.py").read_bytes()).hexdigest() or
            len(generator["records"]) != 2 or len(evidence["secrets"]) != 2):
        raise SafeFailure("complete generator provenance required")
    pair_id = generator["pairID"]
    post = {r["namespace"]: validate_record(r, pair_id, filled=True) for r in generator["records"]}
    if set(post) != set(NAMESPACES):
        raise SafeFailure("complete generated credential pair required")
    observed = {}
    for record in evidence["secrets"]:
        if (not isinstance(record, dict) or set(record) != SAFE_KEYS or record.get("ready") is not True):
            raise SafeFailure("invalid metadata-only readback")
        full = dict(record, immutable=True)
        validate_record(full, pair_id, filled=True)
        namespace = record["namespace"]
        if namespace in observed or full != post[namespace]:
            raise SafeFailure("credential UID or resourceVersion drift")
        observed[namespace] = record
    if set(observed) != set(NAMESPACES):
        raise SafeFailure("complete metadata-only pair required")
    if closure is not None:
        protection = closure.get("metricsProtection", {})
        if (protection.get("mode") != "bearerToken" or protection.get("secretName") != NAME or
                protection.get("secretKey") != "token" or protection.get("gatewayNamespace") != "litellm" or
                protection.get("monitorNamespace") != "monitoring"):
            raise SafeFailure("credential protection tuple differs")
    return [observed[namespace] for namespace in NAMESPACES]


class ProxyAPI:
    """Existing kubectl proxy authentication; no kubeconfig/credentials are copied."""
    def __init__(self, port=18081):
        if not 1024 <= port <= 65535:
            raise SafeFailure("loopback proxy port required")
        self.base = f"http://127.0.0.1:{port}"
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, accept="application/json", missing=False):
        if not path.startswith("/") or "?" in path:
            raise SafeFailure("invalid API path")
        # This check applies centrally even if a future caller forgets metadata().
        if method == "GET" and "/secrets" in path and accept != PARTIAL_ACCEPT:
            raise SafeFailure("full credential retrieval forbidden")
        headers = {"Accept": accept}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.base + path, data=None if body is None else canonical(body).encode(),
                          method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise SafeFailure("API response exceeds bound")
                result = json.loads(raw)
                if method == "GET" and "/secrets" in path and (
                        result.get("kind") != "PartialObjectMetadata" or result.get("apiVersion") != "meta.k8s.io/v1" or
                        set(result) - {"apiVersion", "kind", "metadata"}):
                    raise SafeFailure("metadata-only response required")
                return result
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise SafeFailure("bounded API request refused") from None
        except Exception:
            raise SafeFailure("bounded API request failed") from None

    def get(self, path, missing=False):
        return self.request("GET", path, missing=missing)

    def metadata(self, namespace, pair_id, filled, missing=False):
        obj = self.request("GET", secret_path(namespace), accept=PARTIAL_ACCEPT, missing=missing)
        return None if obj is None else safe_record(obj, namespace, pair_id, partial=True, immutable=filled)

    def create(self, path, obj):
        # Exclusive POST, never apply/update. Slot creation only carries empty data.
        return self.request("POST", path, obj)

    def delete(self, path, uid, version, secret=False):
        body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions":
                {"uid": uid, "resourceVersion": version}, "propagationPolicy": "Foreground"}
        result = self.request("DELETE", path, body, accept=PARTIAL_ACCEPT if secret else "application/json")
        if result.get("status") == "Failure":
            raise SafeFailure("guarded deletion refused")
        if secret and result.get("kind") not in ("Status", "PartialObjectMetadata"):
            raise SafeFailure("metadata-only deletion response required")

    def logs(self, namespace, pod):
        # Only these reviewed bounded helpers' nonsecret logs are allowed.
        request = Request(self.base + f"/api/v1/namespaces/{namespace}/pods/{pod}/log?limitBytes=65536",
                          headers={"Accept": "text/plain"})
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise SafeFailure("helper output exceeds bound")
            return raw.decode("ascii")
        except Exception:
            raise SafeFailure("bounded helper output unavailable") from None


def credential_reference(value):
    if isinstance(value, list):
        return any(credential_reference(item) for item in value)
    if not isinstance(value, dict):
        return False
    if value.get("secretName") == NAME:
        return True
    for key in ("secretKeyRef", "secretRef", "credentials", "bearerTokenSecret", "secret"):
        if isinstance(value.get(key), dict) and value[key].get("name") == NAME:
            return True
    return any(credential_reference(item) for item in value.values())


def no_consumers(api):
    """Fresh workload/monitor inventory; no Secret list/get or generated config reads."""
    deployment = api.get("/apis/apps/v1/namespaces/litellm/deployments/litellm")
    template = deployment["spec"]["template"]
    gateway = next((c for c in template["spec"]["containers"] if c["name"] == "litellm-admission-gateway"), None)
    if gateway is None:
        raise SafeFailure("observed gateway container required")
    enabled = [e for e in gateway.get("env", []) if e.get("name") == "PHORVEX_LITELLM_METRICS_ENABLED"]
    if (len(enabled) > 1 or any(e.get("value") != "0" or "valueFrom" in e for e in enabled) or
            gateway.get("envFrom") or any(p.get("containerPort") == 4003 for p in gateway.get("ports", [])) or
            template.get("metadata", {}).get("labels", {}).get("phorvex.ai/litellm-gateway-metrics") == "enabled"):
        raise SafeFailure("metrics must be disabled before credential mutation")
    for namespace in NAMESPACES:
        paths = [f"/api/v1/namespaces/{namespace}/pods"]
        paths += [f"/apis/apps/v1/namespaces/{namespace}/{kind}" for kind in
                  ("deployments", "replicasets", "statefulsets", "daemonsets")]
        paths += [f"/apis/batch/v1/namespaces/{namespace}/{kind}" for kind in ("jobs", "cronjobs")]
        paths += [f"/apis/monitoring.coreos.com/v1/namespaces/{namespace}/servicemonitors"]
        for path in paths:
            obj = api.get(path)
            if not isinstance(obj.get("items"), list) or credential_reference(obj["items"]):
                raise SafeFailure("credential consumers still present or inventory invalid")


def security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


def resource_path(obj):
    metadata = obj["metadata"]
    namespace, name = metadata["namespace"], metadata["name"]
    kinds = {"ServiceAccount": ("/api/v1", "serviceaccounts"), "ConfigMap": ("/api/v1", "configmaps"),
             "Pod": ("/api/v1", "pods"), "Job": ("/apis/batch/v1", "jobs"),
             "Role": ("/apis/rbac.authorization.k8s.io/v1", "roles"),
             "RoleBinding": ("/apis/rbac.authorization.k8s.io/v1", "rolebindings")}
    base, plural = kinds[obj["kind"]]
    return f"{base}/namespaces/{namespace}/{plural}/{name}"


def record_object(obj):
    return {"path": resource_path(obj), "uid": obj["metadata"]["uid"],
            "kind": obj["kind"], "bodySHA256": sha(owned_body(obj))}


def owned_body(obj):
    # Status/defaults may evolve, but every explicitly created spec/metadata field
    # is compared recursively at cleanup. The receipt retains the reviewed body.
    return {key: value for key, value in obj.items() if key not in ("status", "metadata")} | {
        "metadata": {key: value for key, value in obj["metadata"].items() if key not in
        ("uid", "resourceVersion", "creationTimestamp", "managedFields", "generation")}}


def matches_subset(current, reviewed):
    if isinstance(reviewed, dict):
        return isinstance(current, dict) and all(
            (key not in current and key in ("hostNetwork", "hostPID", "hostIPC") and value is False) or
            (key in current and matches_subset(current[key], value)) for key, value in reviewed.items())
    if isinstance(reviewed, list):
        return isinstance(current, list) and len(current) == len(reviewed) and all(
            matches_subset(a, b) for a, b in zip(current, reviewed))
    return current == reviewed


def create_recorded(api, body, state, save):
    path = resource_path(body)
    result = api.create(path.rsplit("/", 1)[0], body)
    if not matches_subset(result, body) or not result["metadata"].get("uid"):
        raise SafeFailure("created helper differs from reviewed body")
    state["objects"].append({"path": path, "uid": result["metadata"]["uid"], "body": body})
    save(state)
    return result


def cleanup_objects(api, state, save):
    for record in list(reversed(state["objects"])):
        current = api.get(record["path"], missing=True)
        if current is not None:
            if current["metadata"]["uid"] != record["uid"] or not matches_subset(current, record["body"]):
                raise SafeFailure("helper UID or reviewed body drift")
            api.delete(record["path"], record["uid"], current["metadata"]["resourceVersion"])
        state["objects"].remove(record)
        save(state)


def bootstrap_objects(pair_id, slots):
    name = "phorvex-metrics-token-" + pair_id[:12]
    meta = lambda namespace: {"name": name, "namespace": namespace, "labels": labels(pair_id)}
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("litellm"),
          "automountServiceAccountToken": False}
    objects = [sa]
    for namespace in NAMESPACES:
        objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": meta(namespace), "rules": [{"apiGroups": [""], "resources": ["secrets"],
            "resourceNames": [NAME], "verbs": ["patch"]}]})
        objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": meta(namespace), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
            "subjects": [{"kind": "ServiceAccount", "namespace": "litellm", "name": name}]})
    source = (ROOT / "generate_metrics_token.py").read_text()
    inputs = {"schema": "phorvex-litellm-metrics-token-inputs-v1", "pairID": pair_id, "slots": slots}
    objects.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("litellm"),
                    "immutable": True, "data": {"generate_metrics_token.py": source, "slots.json": canonical(inputs)}})
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta("litellm"), "spec": {
        "backoffLimit": 0, "activeDeadlineSeconds": 120, "template": {"metadata": {"labels": labels(pair_id)}, "spec": {
        "restartPolicy": "Never", "serviceAccountName": name, "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001},
        "containers": [{"name": "generate", "image": IMAGE, "imagePullPolicy": "Always",
            "command": ["python3", "-B", "/opt/phorvex-token/generate_metrics_token.py"],
            "securityContext": security(), "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                "limits": {"cpu": "100m", "memory": "64Mi"}},
            "volumeMounts": [{"name": "helper", "mountPath": "/opt/phorvex-token", "readOnly": True},
                {"name": "api", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}]}],
        "volumes": [{"name": "helper", "configMap": {"name": name, "defaultMode": 292}},
            {"name": "api", "projected": {"defaultMode": 292, "sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}]}}]}}]}}}}
    objects.append(job)
    return objects


def validate_report(report, pair_id):
    allowed = {"schema", "utc", "pairID", "result", "records", "error"}
    if (set(report) - allowed or report.get("schema") != "phorvex-litellm-metrics-token-generation-v1" or
            report.get("pairID") != pair_id or report.get("result") not in ("partial", "complete") or
            not isinstance(report.get("records"), list) or len(report["records"]) > 2 or
            ("error" in report and report["error"] != "credential generation incomplete")):
        raise SafeFailure("invalid sanitized generator output")
    namespaces = set()
    for record in report["records"]:
        validate_record(record, pair_id, filled=True)
        if record["namespace"] in namespaces:
            raise SafeFailure("duplicate generator record")
        namespaces.add(record["namespace"])
    if report["result"] == "complete" and namespaces != set(NAMESPACES):
        raise SafeFailure("complete generator pair required")
    return report


def generator_pod(api, job, complete=False):
    pods = api.get("/api/v1/namespaces/litellm/pods")["items"]
    owned = [pod for pod in pods if any(owner.get("uid") == job["metadata"]["uid"] and owner.get("kind") == "Job"
                                      for owner in pod["metadata"].get("ownerReferences", []))]
    if len(owned) != 1:
        raise SafeFailure("one actual generator Pod required")
    pod = owned[0]
    template = job["spec"]["template"]["spec"]
    if not matches_subset(pod["spec"], template):
        raise SafeFailure("actual generator Pod differs")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if (len(statuses) != 1 or not runtime_image_matches(statuses[0].get("imageID", "")) or
            (complete and pod.get("status", {}).get("phase") != "Succeeded")):
        raise SafeFailure("actual generator runtime proof required")
    return pod


def collect_metadata(api, state):
    report = validate_report(state["report"], state["pairID"])
    if report["result"] != "complete":
        raise SafeFailure("partial generation cannot authorize activation")
    evidence = {"schema": SCHEMA, "utc": utc(), "generator": {"jobUID": state["jobUID"],
        "sourceSHA256": state["sourceSHA256"], "imageByDigest": IMAGE,
        "pairID": state["pairID"], "records": report["records"]}, "secrets": [
        api.metadata(namespace, state["pairID"], True) for namespace in NAMESPACES]}
    validate_metadata(evidence)
    return evidence


def provision(api, state, save, wait_seconds=120):
    if state["slots"] or state["objects"] or state.get("report"):
        raise SafeFailure("bootstrap rerun forbidden")
    no_consumers(api)
    # Inspect both names before either creation. A collision is never adopted.
    for namespace in NAMESPACES:
        if api.request("GET", secret_path(namespace), accept=PARTIAL_ACCEPT, missing=True) is not None:
            raise SafeFailure("credential name collision")
    for namespace in NAMESPACES:
        body = {"apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": namespace,
                "name": NAME, "labels": labels(state["pairID"])}, "type": "Opaque", "data": {}}
        created = api.create(secret_path(namespace).rsplit("/", 1)[0], body)
        if created.get("data") or created.get("stringData") or created.get("immutable") or created.get("type") != "Opaque":
            raise SafeFailure("created credential slot was not empty")
        anchor = safe_record(created, namespace, state["pairID"])
        state["slots"].append(anchor)
        save(state)
        slot = api.metadata(namespace, state["pairID"], False)
        if slot != anchor:
            raise SafeFailure("new empty credential slot identity drift")
    objects = bootstrap_objects(state["pairID"], state["slots"])
    state["sourceSHA256"] = hashlib.sha256(objects[-2]["data"]["generate_metrics_token.py"].encode()).hexdigest()
    try:
        for body in objects:
            actual = create_recorded(api, body, state, save)
        state["jobUID"] = actual["metadata"]["uid"]
        save(state)
        deadline = time.monotonic() + min(max(wait_seconds, 1), 120)
        while time.monotonic() < deadline:
            job = api.get(resource_path(actual))
            if job.get("status", {}).get("succeeded") == 1 or job.get("status", {}).get("failed"):
                pod = generator_pod(api, job, complete=job.get("status", {}).get("succeeded") == 1)
                report = validate_report(json.loads(api.logs("litellm", pod["metadata"]["name"])), state["pairID"])
                if any(next((slot["uid"] for slot in state["slots"] if slot["namespace"] == record["namespace"]), None)
                       != record["uid"] for record in report["records"]):
                    raise SafeFailure("generator slot UID differs")
                state["report"] = report
                save(state)
                if report["result"] != "complete" or job.get("status", {}).get("succeeded") != 1:
                    raise SafeFailure("partial credential provisioning requires guarded cleanup")
                evidence = collect_metadata(api, state)
                state["evidence"] = evidence
                save(state)
                return evidence
            time.sleep(2)
        raise SafeFailure("generator deadline exceeded")
    finally:
        # Privileges are removed first even if Pod evidence/deletion subsequently fails.
        privileged = [r for r in state["objects"] if r["body"]["kind"] in ("RoleBinding", "Role")]
        for record in reversed(privileged):
            current = api.get(record["path"], missing=True)
            if current is not None:
                if current["metadata"]["uid"] != record["uid"] or not matches_subset(current, record["body"]):
                    raise SafeFailure("bootstrap privilege drift")
                api.delete(record["path"], record["uid"], current["metadata"]["resourceVersion"])
            state["objects"].remove(record)
            save(state)
        cleanup_objects(api, state, save)


def cleanup_slots(api, state, save, consumer_absence=None):
    cleanup_objects(api, state, save)
    no_consumers(api)
    filled = {r["namespace"]: r for r in state.get("report", {}).get("records", [])}
    if state.get("report", {}).get("result") == "complete":
        # Filled credentials may have existed in consumers after provisioning;
        # Operator/Prometheus reconciliation and target absence must be recorded.
        if (not consumer_absence or set(consumer_absence) != {"utc", "prometheusReconciled", "targetAbsent", "evidenceSHA256"} or
                consumer_absence.get("prometheusReconciled") is not True or consumer_absence.get("targetAbsent") is not True or
                not re.fullmatch(r"[0-9a-f]{64}", consumer_absence.get("evidenceSHA256", ""))):
            raise SafeFailure("reconciled consumer absence proof required")
        recent(consumer_absence["utc"])
    for slot in list(state["slots"]):
        anchor = filled.get(slot["namespace"], slot)
        observed = api.metadata(slot["namespace"], state["pairID"], slot["namespace"] in filled, missing=True)
        if observed is not None:
            expected = {key: value for key, value in anchor.items() if key != "immutable"}
            if observed != expected:
                raise SafeFailure("credential cleanup UID or resourceVersion drift")
            api.delete(secret_path(slot["namespace"]), anchor["uid"], anchor["resourceVersion"], secret=True)
        state["slots"].remove(slot)
        save(state)


def write_new(path, obj):
    with path.open("x") as handle:
        handle.write(canonical(obj) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "run", "collect", "cleanup"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--consumer-absence", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            state = {"schema": "phorvex-litellm-metrics-token-bootstrap-v1", "pairID": uuid.uuid4().hex,
                     "utc": utc(), "slots": [], "objects": []}
            write_new(args.state, state)
        else:
            state = json.loads(args.state.read_text())
            if state.get("schema") != "phorvex-litellm-metrics-token-bootstrap-v1":
                raise SafeFailure("invalid bootstrap state")
            labels(state["pairID"])
            api = ProxyAPI(args.port)
            save = lambda value: args.state.write_text(canonical(value) + "\n")
            if args.action == "run":
                evidence = provision(api, state, save)
                if args.output:
                    write_new(args.output, evidence)
            elif args.action == "collect":
                if not args.output:
                    raise SafeFailure("exclusive evidence output required")
                write_new(args.output, collect_metadata(api, state))
            else:
                absence = json.loads(args.consumer_absence.read_text()) if args.consumer_absence else None
                cleanup_slots(api, state, save, absence)
        print("metrics credential " + args.action + " complete")
        return 0
    except Exception:
        print("metrics credential operation refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
