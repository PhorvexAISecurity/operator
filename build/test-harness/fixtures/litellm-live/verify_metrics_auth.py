"""Prepare/run/collect/cleanup an actual-source, tokenless-API auth witness.

Only the in-cluster probe reads the monitoring token. The witness imports the
reviewed gateway bytes, its actual loader and MetricsHandler; it never creates
Gateway, a serving/status listener, or an upstream. Live probe plans use the same
bounded controls against exactly two recorded replica IPs and their ClusterIP.
"""
import argparse
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid
from generate_metrics_token import IMAGE, NAME, SafeFailure, canonical, runtime_image_matches, utc
from provision_metrics_token import (ProxyAPI, ROOT, cleanup_objects, collect_metadata,
    create_recorded, matches_subset, recent, resource_path, security, sha, validate_metadata, write_new)

TOKEN_FILE = "/etc/phorvex-litellm-metrics/token"
CHECK_STATUS = {
    "no-token": 401, "wrong-token": 401, "valid-token": 200,
    "duplicate-auth": 401, "joined-auth": 401, "basic-auth": 401,
    "malformed-auth": 401, "trailing-auth": 401, "internal-auth": 401,
    "oversized-auth": 401, "non-metrics": 404, "status-path": 404,
    "model-path": 404, "absolute-target": 404, "query-target": 404,
    "encoded-target": 404, "post-method": 501, "head-method": 501,
    "request-body": 400, "transfer-encoding": 400,
}
HELPERS = ("generate_metrics_token.py", "provision_metrics_token.py", "verify_metrics_auth.py")


def auth_closure_hash(closure):
    return sha({key: closure[key] for key in ("metricsProtection", "candidateTemplateSHA256",
                "gatewaySourceSHA256", "gatewayImageByDigest", "monitoringSpecsSHA256")})


def validate_closure(closure, source):
    expected = {"mode": "bearerToken", "authenticatedSourceSHA256": hashlib.sha256(source.encode()).hexdigest(),
                "secretName": NAME, "secretKey": "token", "gatewayNamespace": "litellm",
                "monitorNamespace": "monitoring", "tokenFile": TOKEN_FILE}
    if (closure.get("schema") != "phorvex-litellm-metrics-candidate-v2" or
            closure.get("metricsProtection") != expected or
            closure.get("gatewaySourceSHA256") != expected["authenticatedSourceSHA256"] or
            expected["authenticatedSourceSHA256"] != hashlib.sha256((ROOT / "gateway_metrics.py").read_bytes()).hexdigest() or
            closure.get("gatewayImageByDigest") != IMAGE or
            not re.fullmatch(r"[0-9a-f]{64}", closure.get("candidateTemplateSHA256", ""))):
        raise SafeFailure("reviewed authenticated candidate required")
    auth_closure_hash(closure)


def helper_data():
    return {name: (ROOT / name).read_text() for name in HELPERS}


def pod_spec(name, namespace, helper, source=None, targets=None):
    env = [{"name": "PHORVEX_LITELLM_METRICS_TOKEN_FILE", "value": TOKEN_FILE}]
    mounts = [{"name": "helper", "mountPath": "/opt/phorvex-proof", "readOnly": True},
              {"name": "credential", "mountPath": str(Path(TOKEN_FILE).parent), "readOnly": True}]
    volumes = [{"name": "helper", "configMap": {"name": helper, "defaultMode": 292}},
               {"name": "credential", "secret": {"secretName": NAME, "optional": False,
                "defaultMode": 288, "items": [{"key": "token", "path": "token", "mode": 288}]}}]
    mode = "probe" if targets is not None else "witness"
    container = {"name": mode, "image": IMAGE, "imagePullPolicy": "Always",
        "command": ["python3", "-B", "/opt/phorvex-proof/verify_metrics_auth.py", mode],
        "securityContext": security(), "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
        "limits": {"cpu": "100m", "memory": "64Mi"}}, "env": env, "volumeMounts": mounts}
    if targets is None:
        env += [{"name": "PHORVEX_LITELLM_METRICS_ENABLED", "value": "1"},
                {"name": "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", "value": source["sha"]},
                {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}},
                {"name": "POD_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}}]
        mounts.append({"name": "source", "mountPath": "/opt/phorvex-source", "readOnly": True})
        volumes.append({"name": "source", "configMap": {"name": source["name"], "defaultMode": 292,
            "items": [{"key": "gateway.py", "path": "gateway.py"}]}})
        container["ports"] = [{"name": "metrics", "containerPort": 4003, "protocol": "TCP"}]
        container["readinessProbe"] = {"tcpSocket": {"port": 4003}, "periodSeconds": 2,
                                       "timeoutSeconds": 1, "failureThreshold": 5}
    else:
        env.append({"name": "PHORVEX_METRICS_PROBE_TARGETS", "value": canonical(targets)})
    return {"restartPolicy": "Never", "automountServiceAccountToken": False,
        "hostNetwork": False, "hostPID": False, "hostIPC": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                            "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": volumes}


def prepare(closure, metadata, source, run_id=None):
    validate_closure(closure, source)
    validate_metadata(metadata, closure)
    run_id = run_id or uuid.uuid4().hex
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise SafeFailure("invalid witness identity")
    name = "phorvex-metrics-proof-" + run_id[:12]
    meta = lambda namespace, suffix: {"namespace": namespace, "name": name + suffix,
            "labels": {"phorvex.ai/metrics-auth-proof": run_id}}
    source_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("litellm", "-source"),
                 "immutable": True, "data": {"gateway.py": source}}
    helpers = [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(namespace, "-helper"),
                "immutable": True, "data": helper_data()} for namespace in ("litellm", "monitoring")]
    witness = {"apiVersion": "v1", "kind": "Pod", "metadata": meta("litellm", "-witness"),
        "spec": pod_spec(name + "-witness", "litellm", name + "-helper",
                         {"name": name + "-source", "sha": closure["gatewaySourceSHA256"]})}
    witness["spec"]["activeDeadlineSeconds"] = 300
    return {"schema": "phorvex-litellm-metrics-auth-witness-plan-v1", "utc": utc(), "runID": run_id,
            "scope": "preactivation-metrics-only", "closure": closure, "metadata": metadata,
            "sourceConfigMap": source_cm, "helperConfigMaps": helpers, "witnessPod": witness, "objects": []}


def probe_job(plan, targets):
    name = plan["witnessPod"]["metadata"]["name"].removesuffix("-witness")
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"namespace": "monitoring",
            "name": name + "-probe", "labels": {"phorvex.ai/metrics-auth-proof": plan["runID"]}},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "template": {
                "metadata": {"labels": {"phorvex.ai/metrics-auth-proof": plan["runID"]}},
                "spec": pod_spec(name + "-probe", "monitoring", name + "-helper", targets=targets)}}}


def actual_image(pod):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or not runtime_image_matches(statuses[0].get("imageID", "")):
        raise SafeFailure("actual published runtime identity required")
    return statuses[0]["imageID"]


def ready(pod):
    return pod.get("status", {}).get("phase") == "Running" and any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in pod.get("status", {}).get("conditions", []))


def check_pod(pod, expected, succeeded=False):
    spec = pod.get("spec", {})
    if (not pod.get("metadata", {}).get("uid") or not spec.get("nodeName") or
            not matches_subset(spec, expected) or spec.get("initContainers") or spec.get("ephemeralContainers") or
            len(spec.get("volumes", [])) != len(expected["volumes"]) or
            any(container.get("envFrom") for container in spec.get("containers", [])) or
            "phorvex.ai/litellm-gateway-metrics" in pod.get("metadata", {}).get("labels", {}) or
            spec.get("automountServiceAccountToken") is not False or
            any(spec.get(key, False) is not False for key in ("hostNetwork", "hostPID", "hostIPC")) or
            (succeeded and pod.get("status", {}).get("phase") != "Succeeded") or
            (not succeeded and not ready(pod))):
        raise SafeFailure("actual metrics proof Pod differs or is not ready")
    actual_image(pod)


def validate_checks(checks):
    if not isinstance(checks, list) or len(checks) != len(CHECK_STATUS):
        raise SafeFailure("complete bounded auth controls required")
    found = set()
    for item in checks:
        if (not isinstance(item, dict) or set(item) != {"name", "status", "bodyLength", "verdict"} or
                item.get("name") not in CHECK_STATUS or item["name"] in found or
                item.get("status") != CHECK_STATUS[item["name"]] or item.get("verdict") != "pass" or
                type(item.get("bodyLength")) is not int or not 0 <= item["bodyLength"] <= 65536 or
                (item["name"] == "valid-token" and item["bodyLength"] == 0) or
                (item["name"] != "valid-token" and item["bodyLength"] != 0)):
            raise SafeFailure("auth control failed or unsafe receipt")
        found.add(item["name"])
    return checks


def validate_probe_report(report, targets):
    if (not isinstance(report, dict) or set(report) != {"schema", "utc", "targets", "modelCalls", "upstreamConfigured"} or
            report.get("schema") != "phorvex-litellm-metrics-probe-report-v1" or
            report.get("modelCalls") != 0 or type(report["modelCalls"]) is not int or
            report.get("upstreamConfigured") is not False or len(report.get("targets", [])) != len(targets)):
        raise SafeFailure("sanitized probe report required")
    recent(report["utc"])
    for observed, target in zip(report["targets"], targets):
        if set(observed) != {"target", "checks"} or observed["target"] != target:
            raise SafeFailure("probe endpoint identity differs")
        validate_checks(observed["checks"])
    return report


def sanitize_evidence_object(obj):
    """Discard raw annotations, managed fields and container termination messages."""
    kind = obj["kind"]
    meta = obj["metadata"]
    keep = {"apiVersion": obj["apiVersion"], "kind": kind, "metadata": {key: meta[key] for key in
            ("name", "namespace", "uid", "resourceVersion", "labels", "ownerReferences") if key in meta}}
    if kind == "ConfigMap":
        keep.update(immutable=obj.get("immutable"), data=obj.get("data", {}))
    else:
        keep["spec"] = obj["spec"]
        status = obj.get("status", {})
        if kind == "Job":
            keep["status"] = {key: status[key] for key in ("succeeded", "failed") if key in status}
        else:
            keep["status"] = {key: status[key] for key in ("phase", "podIP") if key in status}
            keep["status"]["conditions"] = [{"type": c["type"], "status": c["status"]}
                for c in status.get("conditions", []) if c.get("type") == "Ready"]
            keep["status"]["containerStatuses"] = [{key: c[key] for key in ("name", "imageID") if key in c}
                for c in status.get("containerStatuses", [])]
    return keep


def proof_from_evidence(plan, evidence, metadata):
    closure = plan["closure"]
    witness, probe = evidence["witnessPod"], evidence["probePod"]
    secret_records = validate_metadata(metadata, closure)
    identities = [{key: record[key] for key in ("namespace", "name", "uid", "resourceVersion")} for record in secret_records]
    return {"schema": "phorvex-litellm-metrics-auth-proof-v1", "utc": utc(),
        "scope": "preactivation-metrics-only", "metricsProtection": closure["metricsProtection"],
        "candidateTemplateSHA256": closure["candidateTemplateSHA256"], "closureSHA256": auth_closure_hash(closure),
        "gatewaySourceSHA256": closure["gatewaySourceSHA256"], "imageByDigest": IMAGE,
        "secretPair": {"pairID": metadata["generator"]["pairID"], "secrets": identities},
        "witness": {"podUID": witness["metadata"]["uid"], "nodeName": witness["spec"]["nodeName"],
            "sourceConfigMapUID": evidence["sourceConfigMap"]["metadata"]["uid"], "imageID": actual_image(witness),
            "specSHA256": sha(witness["spec"]), "ready": ready(witness)},
        "probe": {"podUID": probe["metadata"]["uid"], "nodeName": probe["spec"]["nodeName"],
            "imageID": actual_image(probe), "specSHA256": sha(probe["spec"]), "phase": probe["status"]["phase"]},
        "modelCalls": 0, "upstreamConfigured": False,
        "checks": evidence["probeReport"]["targets"][0]["checks"],
        "evidence": evidence, "evidenceSHA256": sha(evidence)}


def validate_auth_proof(value, closure, metadata):
    keys = {"schema", "utc", "scope", "metricsProtection", "candidateTemplateSHA256", "closureSHA256",
            "gatewaySourceSHA256", "imageByDigest", "secretPair", "witness", "probe", "modelCalls",
            "upstreamConfigured", "checks", "evidence", "evidenceSHA256"}
    if not isinstance(value, dict) or set(value) != keys:
        raise SafeFailure("strict auth proof schema required")
    recent(value["utc"])
    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {
            "sourceConfigMap", "helperConfigMaps", "witnessPod", "probeJob", "probePod", "probeReport"}:
        raise SafeFailure("complete actual auth evidence required")
    source_cm = evidence["sourceConfigMap"]
    source = source_cm.get("data", {}).get("gateway.py", "")
    validate_closure(closure, source)
    if (source_cm.get("immutable") is not True or set(source_cm.get("data", {})) != {"gateway.py"} or
            source_cm.get("binaryData") or not source_cm.get("metadata", {}).get("uid")):
        raise SafeFailure("immutable actual witness source required")
    run_id = evidence["witnessPod"].get("metadata", {}).get("labels", {}).get("phorvex.ai/metrics-auth-proof", "")
    plan = prepare(closure, metadata, source, run_id)
    if not matches_subset(source_cm, plan["sourceConfigMap"]):
        raise SafeFailure("witness source CM identity differs")
    if len(evidence["helperConfigMaps"]) != 2:
        raise SafeFailure("reviewed helper CMs required")
    for current, expected in zip(evidence["helperConfigMaps"], plan["helperConfigMaps"]):
        if (not matches_subset(current, expected) or current.get("data") != helper_data() or
                current.get("binaryData") or not current.get("metadata", {}).get("uid")):
            raise SafeFailure("actual reviewed helper source differs")
    witness = evidence["witnessPod"]
    if not matches_subset(witness["metadata"], plan["witnessPod"]["metadata"]):
        raise SafeFailure("witness Pod identity differs")
    check_pod(witness, plan["witnessPod"]["spec"])
    ip = witness.get("status", {}).get("podIP", "")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise SafeFailure("actual witness IP required") from None
    targets = [{"name": "witness", "host": ip, "port": 4003, "podUID": witness["metadata"]["uid"]}]
    expected_job = probe_job(plan, targets)
    job = evidence["probeJob"]
    if (not matches_subset(job, expected_job) or not job["metadata"].get("uid") or
            job.get("status", {}).get("succeeded") != 1):
        raise SafeFailure("actual completed probe Job required")
    probe = evidence["probePod"]
    check_pod(probe, expected_job["spec"]["template"]["spec"], succeeded=True)
    if not any(owner.get("kind") == "Job" and owner.get("uid") == job["metadata"]["uid"]
               for owner in probe["metadata"].get("ownerReferences", [])):
        raise SafeFailure("probe Job/Pod identity differs")
    validate_probe_report(evidence["probeReport"], targets)
    expected = proof_from_evidence(plan, evidence, metadata)
    expected["utc"] = value["utc"]
    if value != expected:
        raise SafeFailure("auth proof candidate or evidence binding differs")
    return value


def run(api, plan, save):
    if plan["objects"] or plan.get("probeJob"):
        raise SafeFailure("witness plan rerun forbidden")
    validate_closure(plan["closure"], plan["sourceConfigMap"]["data"]["gateway.py"])
    validate_metadata(plan["metadata"], plan["closure"])
    for body in [plan["sourceConfigMap"], *plan["helperConfigMaps"], plan["witnessPod"]]:
        create_recorded(api, body, plan, save)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        witness = api.get(resource_path(plan["witnessPod"]))
        if witness.get("status", {}).get("phase") in ("Failed", "Succeeded"):
            raise SafeFailure("witness did not remain running")
        if ready(witness):
            check_pod(witness, plan["witnessPod"]["spec"])
            ip = str(ipaddress.ip_address(witness["status"]["podIP"]))
            targets = [{"name": "witness", "host": ip, "port": 4003, "podUID": witness["metadata"]["uid"]}]
            plan["probeJob"] = probe_job(plan, targets)
            create_recorded(api, plan["probeJob"], plan, save)
            save(plan)
            return
        time.sleep(2)
    raise SafeFailure("witness readiness deadline exceeded")


def collect(api, plan):
    job = api.get(resource_path(plan["probeJob"]))
    deadline = time.monotonic() + 120
    while not job.get("status", {}).get("succeeded") and time.monotonic() < deadline:
        if job.get("status", {}).get("failed"):
            raise SafeFailure("auth probe failed")
        time.sleep(2)
        job = api.get(resource_path(plan["probeJob"]))
    if job.get("status", {}).get("succeeded") != 1:
        raise SafeFailure("probe completion deadline exceeded")
    pods = api.get("/api/v1/namespaces/monitoring/pods")["items"]
    pods = [pod for pod in pods if any(owner.get("uid") == job["metadata"]["uid"]
                                     for owner in pod["metadata"].get("ownerReferences", []))]
    if len(pods) != 1:
        raise SafeFailure("one actual probe Pod required")
    evidence = {"sourceConfigMap": api.get(resource_path(plan["sourceConfigMap"])),
        "helperConfigMaps": [api.get(resource_path(body)) for body in plan["helperConfigMaps"]],
        "witnessPod": api.get(resource_path(plan["witnessPod"])), "probeJob": job, "probePod": pods[0],
        "probeReport": json.loads(api.logs("monitoring", pods[0]["metadata"]["name"]))}
    # Bind every readback to this exclusive run's recorded object UIDs.
    for obj in [evidence["sourceConfigMap"], *evidence["helperConfigMaps"], evidence["witnessPod"], job]:
        record = next((item for item in plan["objects"] if item["path"] == resource_path(obj)), None)
        if record is None or obj["metadata"]["uid"] != record["uid"]:
            raise SafeFailure("proof object recreated or unrecorded")
    metadata = dict(plan["metadata"], utc=utc(), secrets=[
        api.metadata(namespace, plan["metadata"]["generator"]["pairID"], True) for namespace in ("litellm", "monitoring")])
    proof = proof_from_evidence(plan, evidence, metadata)
    validate_auth_proof(proof, plan["closure"], metadata)
    evidence = {key: ([sanitize_evidence_object(obj) for obj in value] if key == "helperConfigMaps" else
                     value if key == "probeReport" else sanitize_evidence_object(value))
                for key, value in evidence.items()}
    proof = proof_from_evidence(plan, evidence, metadata)
    validate_auth_proof(proof, plan["closure"], metadata)
    return {"authProof": proof, "secretMetadata": metadata}


def witness_main():
    try:
        source_path = Path("/opt/phorvex-source/gateway.py")
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != os.environ["PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256"]:
            raise SafeFailure("witness source differs")
        spec = importlib.util.spec_from_file_location("reviewed_metrics_gateway", source_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        token = module.configured_metrics_token(os.environ)
        if token is None:
            raise SafeFailure("witness credential unavailable")
        registry = module.configured_metrics(os.environ)
        registry.observe("GET", "/v1/models", 200, "completed", .01)
        handler = type("ReviewedWitnessHandler", (module.MetricsHandler,), {"metrics": registry, "metrics_token": token})
        # The actual source server suppresses request-bearing exception traces.
        module.MetricsHTTPServer(("0.0.0.0", 4003), handler).serve_forever()
    except Exception:
        print("metrics witness failed", flush=True)
        return 1
    return 0


def controls(token):
    valid = [("Authorization", "Bearer " + token)]
    wrong = ("0" if token[0] != "0" else "1") + token[1:]
    yield "no-token", "GET", "/metrics", [], None
    yield "wrong-token", "GET", "/metrics", [("Authorization", "Bearer " + wrong)], None
    yield "valid-token", "GET", "/metrics", valid, None
    variants = {"duplicate-auth": valid + valid, "joined-auth": [("Authorization", "Bearer " + token + ", Bearer " + token)],
        "basic-auth": [("Authorization", "Basic " + token)], "malformed-auth": [("Authorization", "Bearer malformed")],
        "trailing-auth": [("Authorization", "Bearer " + token + " ")],
        "internal-auth": [("Authorization", "Bearer  " + token)],
        "oversized-auth": [("Authorization", "Bearer " + token + "0")]}
    for name, headers in variants.items():
        yield name, "GET", "/metrics", headers, None
    for name, path in (("non-metrics", "/"), ("status-path", "/v1/admission/state"), ("model-path", "/v1/models"),
                       ("absolute-target", "http://example.invalid/metrics"), ("query-target", "/metrics?x=1"), ("encoded-target", "/%6detrics")):
        yield name, "GET", path, valid, None
    yield "post-method", "POST", "/metrics", valid, None
    yield "head-method", "HEAD", "/metrics", valid, None
    yield "request-body", "GET", "/metrics", valid + [("Content-Length", "1")], b"x"
    yield "transfer-encoding", "GET", "/metrics", valid + [("Transfer-Encoding", "chunked")], b"0\r\n\r\n"


def probe_target(target, token, deadline=None):
    if (set(target) != {"name", "host", "port", "podUID"} or target["port"] != 4003 or
            not re.fullmatch(r"[a-z0-9-]{1,40}", target["name"]) or not isinstance(target["podUID"], str)):
        raise SafeFailure("invalid probe endpoint")
    # Concrete IP targets only: no redirect, proxy, URL credentials or arbitrary DNS.
    ipaddress.ip_address(target["host"])
    results = []
    for name, method, path, headers, body in controls(token):
        if deadline is not None and time.monotonic() >= deadline:
            raise SafeFailure("metrics auth probe deadline exceeded")
        connection = http.client.HTTPConnection(target["host"], 4003, timeout=5)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            for key, value in headers:
                connection.putheader(key, value)
            connection.putheader("Connection", "close")
            connection.endheaders(body)
            response = connection.getresponse()
            data = response.read(65537)
            passed = (response.status == CHECK_STATUS[name] and len(data) <= 65536 and
                      response.getheader("Connection", "").lower() == "close" and
                      (len(data) > 0 if name == "valid-token" else len(data) == 0) and
                      token.encode() not in data and (name != "valid-token" or (
                      response.getheader("Content-Type", "").startswith("text/plain; version=0.0.4") and
                      response.getheader("Cache-Control") == "no-store" and
                      b"# TYPE http_requests_total counter" in data and
                      b"# TYPE http_request_duration_seconds histogram" in data)))
            results.append({"name": name, "status": response.status, "bodyLength": len(data),
                            "verdict": "pass" if passed else "fail"})
            if not passed:
                raise SafeFailure("metrics auth control failed")
        finally:
            connection.close()
    validate_checks(results)
    return {"target": target, "checks": results}


def probe_main():
    try:
        with Path(TOKEN_FILE).open("rb") as handle:
            raw = handle.read(65)
        if not re.fullmatch(b"[0-9a-f]{64}", raw):
            raise SafeFailure("probe credential unavailable")
        token = raw.decode("ascii")
        targets = json.loads(os.environ["PHORVEX_METRICS_PROBE_TARGETS"])
        if not isinstance(targets, list) or len(targets) not in (1, 3):
            raise SafeFailure("bounded probe targets required")
        deadline = time.monotonic() + 90
        observations = []
        for target in targets:
            if time.monotonic() >= deadline:
                raise SafeFailure("metrics auth probe deadline exceeded")
            observations.append(probe_target(target, token, deadline))
        report = {"schema": "phorvex-litellm-metrics-probe-report-v1", "utc": utc(),
                  "targets": observations,
                  "modelCalls": 0, "upstreamConfigured": False}
        print(canonical(report), flush=True)
        return 0
    except Exception:
        print('{"error":"metrics auth probe failed"}', flush=True)
        return 1


def prepare_live(plan, pods, service):
    """Three exact targets, for immediate production proof after the reviewed rollout.

    This creates only a monitoring probe Job; it never mutates the Deployment,
    Service/ServiceMonitor or credential generation. Live proof has a distinct
    schema and cannot satisfy the preactivation witness guard.
    """
    validate_metadata(plan["metadata"], plan["closure"])
    if (len(pods) != 2 or len({pod["metadata"]["uid"] for pod in pods}) != 2 or
            service["metadata"].get("namespace") != "litellm" or
            service["metadata"].get("name") != "phorvex-litellm-gateway-metrics" or
            service["spec"].get("type", "ClusterIP") != "ClusterIP" or
            service["spec"].get("ports") != [{"name": "gateway-metrics", "port": 4003, "targetPort": "gateway-metrics", "protocol": "TCP"}]):
        raise SafeFailure("exact production replicas and metrics ClusterIP required")
    targets = []
    for index, pod in enumerate(pods):
        if not ready(pod) or pod["metadata"].get("namespace") != "litellm":
            raise SafeFailure("actual Ready production replicas required")
        spec = pod["spec"]
        gateway = next((c for c in spec["containers"] if c["name"] == "litellm-admission-gateway"), None)
        if gateway is None or gateway.get("image") != IMAGE:
            raise SafeFailure("production gateway image differs")
        source_env = next((e.get("value") for e in gateway.get("env", []) if e.get("name") == "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256"), None)
        if source_env != plan["closure"]["gatewaySourceSHA256"]:
            raise SafeFailure("production gateway source differs")
        targets.append({"name": "replica-" + str(index + 1), "host": str(ipaddress.ip_address(pod["status"]["podIP"])),
                        "port": 4003, "podUID": pod["metadata"]["uid"]})
    targets.append({"name": "clusterip", "host": str(ipaddress.ip_address(service["spec"]["clusterIP"])),
                    "port": 4003, "podUID": ""})
    live = {"schema": "phorvex-litellm-metrics-live-probe-plan-v1", "utc": utc(), "runID": plan["runID"],
            "closure": plan["closure"], "metadata": plan["metadata"], "pods": pods, "service": service,
            "targets": targets, "helperConfigMaps": [plan["helperConfigMaps"][1]], "objects": []}
    live["probeJob"] = probe_job(plan, targets)
    return live


def live_inputs_current(api, plan):
    for prior in plan["pods"]:
        current = api.get(f"/api/v1/namespaces/litellm/pods/{prior['metadata']['name']}")
        if (current["metadata"]["uid"] != prior["metadata"]["uid"] or current["spec"] != prior["spec"] or
                current["status"].get("podIP") != prior["status"].get("podIP") or not ready(current)):
            raise SafeFailure("production replica UID spec IP or readiness drift")
    prior = plan["service"]
    current = api.get("/api/v1/namespaces/litellm/services/phorvex-litellm-gateway-metrics")
    if current["metadata"]["uid"] != prior["metadata"]["uid"] or current["spec"] != prior["spec"]:
        raise SafeFailure("production metrics Service UID or spec drift")


def collect_live(api, plan):
    live_inputs_current(api, plan)
    job = api.get(resource_path(plan["probeJob"]))
    deadline = time.monotonic() + 120
    while not job.get("status", {}).get("succeeded") and time.monotonic() < deadline:
        if job.get("status", {}).get("failed"):
            raise SafeFailure("production auth probe failed")
        time.sleep(2)
        job = api.get(resource_path(plan["probeJob"]))
    if job.get("status", {}).get("succeeded") != 1:
        raise SafeFailure("production auth probe deadline exceeded")
    record = next((item for item in plan["objects"] if item["path"] == resource_path(job)), None)
    if record is None or record["uid"] != job["metadata"]["uid"] or not matches_subset(job, plan["probeJob"]):
        raise SafeFailure("production probe Job identity drift")
    pods = api.get("/api/v1/namespaces/monitoring/pods")["items"]
    pods = [pod for pod in pods if any(owner.get("uid") == job["metadata"]["uid"]
                                     for owner in pod["metadata"].get("ownerReferences", []))]
    if len(pods) != 1:
        raise SafeFailure("one actual production probe Pod required")
    pod = pods[0]
    check_pod(pod, plan["probeJob"]["spec"]["template"]["spec"], succeeded=True)
    report = validate_probe_report(json.loads(api.logs("monitoring", pod["metadata"]["name"])), plan["targets"])
    metadata = dict(plan["metadata"], utc=utc(), secrets=[
        api.metadata(namespace, plan["metadata"]["generator"]["pairID"], True) for namespace in ("litellm", "monitoring")])
    validate_metadata(metadata, plan["closure"])
    helpers = [api.get(resource_path(body)) for body in plan["helperConfigMaps"]]
    for current, expected in zip(helpers, plan["helperConfigMaps"]):
        record = next((item for item in plan["objects"] if item["path"] == resource_path(current)), None)
        if record is None or record["uid"] != current["metadata"]["uid"] or not matches_subset(current, expected):
            raise SafeFailure("production probe helper identity drift")
    evidence = {"replicas": plan["pods"], "service": plan["service"], "probeJob": job,
                "probePod": pod, "helperConfigMaps": helpers, "probeReport": report}
    return {"schema": "phorvex-litellm-metrics-live-auth-proof-v1", "utc": utc(),
            "scope": "live-two-replica-clusterip", "closureSHA256": auth_closure_hash(plan["closure"]),
            "secretMetadata": metadata, "targets": report["targets"], "modelCalls": 0,
            "modelCallsScope": "metrics-listener-only; independent serving fixture required",
            "evidence": evidence, "evidenceSHA256": sha(evidence)}


def main():
    # Cluster commands have no token/source values in argv; source identity is a
    # nonsecret env field and tokens are read solely from mounted Secret files.
    if len(os.sys.argv) == 2 and os.sys.argv[1] == "witness":
        return witness_main()
    if len(os.sys.argv) == 2 and os.sys.argv[1] == "probe":
        return probe_main()
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "run", "collect", "cleanup", "prepare-live", "run-live", "collect-live"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--closure", type=Path)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--pods", type=Path)
    parser.add_argument("--service", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            if not args.closure or not args.metadata or not args.source:
                raise SafeFailure("complete witness preparation inputs required")
            write_new(args.state, prepare(json.loads(args.closure.read_text()), json.loads(args.metadata.read_text()), args.source.read_text()))
        else:
            plan = json.loads(args.state.read_text())
            api = ProxyAPI(args.port)
            save = lambda value: args.state.write_text(canonical(value) + "\n")
            if args.action == "run":
                try:
                    run(api, plan, save)
                except Exception:
                    cleanup_objects(api, plan, save)
                    raise
            elif args.action == "collect":
                if not args.output:
                    raise SafeFailure("exclusive auth proof output required")
                try:
                    write_new(args.output, collect(api, plan))
                finally:
                    cleanup_objects(api, plan, save)
            elif args.action == "prepare-live":
                if not args.output or not args.pods or not args.service:
                    raise SafeFailure("complete production proof inputs required")
                write_new(args.output, prepare_live(plan, json.loads(args.pods.read_text()), json.loads(args.service.read_text())))
            elif args.action == "run-live":
                if plan["objects"]:
                    raise SafeFailure("production proof rerun forbidden")
                try:
                    validate_metadata(plan["metadata"], plan["closure"])
                    live_inputs_current(api, plan)
                    for body in [*plan["helperConfigMaps"], plan["probeJob"]]:
                        create_recorded(api, body, plan, save)
                except Exception:
                    cleanup_objects(api, plan, save)
                    raise
            elif args.action == "collect-live":
                if not args.output:
                    raise SafeFailure("exclusive production proof output required")
                try:
                    write_new(args.output, collect_live(api, plan))
                finally:
                    cleanup_objects(api, plan, save)
            else:
                cleanup_objects(api, plan, save)
        print("metrics auth " + args.action + " complete")
        return 0
    except Exception:
        print("metrics auth operation refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
