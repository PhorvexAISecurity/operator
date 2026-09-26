"""Render the owned CPU guardrail-output fixture; this command makes no API calls."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat


POD_NAME = "guardrail-output-fixture"
SERVICE_NAME = POD_NAME
SOURCE_NAME = POD_NAME
MARKER_SECRET_NAME = "guardrail-output-fixture-marker"
POLICY_CM_NAME = "phorvex-output-policy-" + POD_NAME
LABEL = "phorvex.ai/guardrail-output-fixture"
PRIVATE_MARKER_PATH = "/etc/phorvex-support/marker"
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
DNS = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")
CREATOR = re.compile(r"system:serviceaccount:phorvex-system:[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")
MARKER = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
PLAN_KEYS = {"namespace", "context", "clusterUID", "proxyImage", "supportImage",
             "modelServiceName", "modelServiceUID", "modelTargetPodName",
             "modelTargetPodUID", "modelTargetImageID", "modelID",
             "modelAPIKeySecretName", "modelAPIKeySecretKey", "eventCreator"}
SOURCE_FILES = ("guardrail_proxy.py", "output_policy.py", "support_fixture.py")
SOURCE_DIR = Path(__file__).resolve().parents[2] / "guardrail"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def validate_plan(value):
    if type(value) is not dict or set(value) != PLAN_KEYS:
        raise ValueError("fixture plan has missing or unknown fields")
    if value["namespace"] != "vllm":
        raise ValueError("fixture namespace must be vllm")
    if type(value["context"]) is not str or not value["context"] or value["context"] == "in-cluster":
        raise ValueError("reviewed external kubeconfig context required")
    for key in ("clusterUID", "modelServiceUID", "modelTargetPodUID"):
        if type(value[key]) is not str or not UID.fullmatch(value[key]):
            raise ValueError(f"{key} must be a pinned Kubernetes UID")
    if (type(value["modelTargetImageID"]) is not str
            or "sha256:" not in value["modelTargetImageID"]
            or len(value["modelTargetImageID"]) > 256):
        raise ValueError("modelTargetImageID must be a pinned runtime image ID")
    for key in ("proxyImage", "supportImage"):
        if type(value[key]) is not str or not IMAGE.fullmatch(value[key]):
            raise ValueError(f"{key} must be an image digest reference")
    for key in ("modelServiceName", "modelTargetPodName", "modelAPIKeySecretName",
                "modelAPIKeySecretKey"):
        if type(value[key]) is not str or not DNS.fullmatch(value[key]) or len(value[key]) > 63:
            raise ValueError(f"{key} must be a DNS label")
    if value["modelServiceName"] == SERVICE_NAME:
        raise ValueError("model Service cannot be the fixture Service")
    if value["modelID"] != "Qwen/Qwen2.5-7B-Instruct-AWQ":
        raise ValueError("model ID must match the reviewed guarded model")
    if type(value["eventCreator"]) is not str or not CREATOR.fullmatch(value["eventCreator"]):
        raise ValueError("event creator must be the reviewed console service account")
    return value


def _env(name, value):
    return {"name": name, "value": value}


def _secret_env(name, secret, key):
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}


def _mount(name, path, *, read_only=True):
    return {"name": name, "mountPath": path, "readOnly": read_only}


def documents(plan, marker, source):
    proxy_hash = hashlib.sha256(source["guardrail_proxy.py"].encode() + b"\x00"
                                + source["output_policy.py"].encode()).hexdigest()
    support_hash = hashlib.sha256(source["support_fixture.py"].encode()).hexdigest()
    namespace = plan["namespace"]
    common_meta = {"namespace": namespace}
    source_cm = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {**common_meta, "name": SOURCE_NAME},
        "immutable": True, "data": source,
    }
    marker_secret = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {**common_meta, "name": MARKER_SECRET_NAME},
        "immutable": True, "type": "Opaque",
        "data": {"marker": base64.b64encode(marker.encode()).decode()},
    }
    source_mount = _mount("source", "/src")
    tmp_mount = _mount("tmp", "/tmp", read_only=False)
    security = {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    init_code = (
        "import os,pathlib; src=pathlib.Path('/run/marker-source/marker'); "
        "dst='/run/marker-private/marker'; raw=src.read_bytes(); "
        "assert 32<=len(raw)<=128 and raw.decode('ascii').strip()==raw.decode('ascii'); "
        "fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); "
        "os.write(fd,raw); os.fsync(fd); os.close(fd)"
    )
    proxy_code = (
        "import guardrail_proxy,uvicorn; "
        "uvicorn.run(guardrail_proxy.create_app(load_models=False), "
        "host='0.0.0.0',port=8000,log_level='info')"
    )
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {**common_meta, "name": POD_NAME,
                     "labels": {"app": POD_NAME, LABEL: "true", "data-class": "internal"},
                     "annotations": {
                         "phorvex.ai/serving-port": "8000",
                         "phorvex.ai/output-policy-configmap": POLICY_CM_NAME,
                         "phorvex.ai/output-proxy-source-sha256": proxy_hash,
                         "phorvex.ai/output-support-source-sha256": support_hash,
                         "phorvex.ai/output-event-creator": plan["eventCreator"],
                     }},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always", "terminationGracePeriodSeconds": 30,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "runAsGroup": 10001, "fsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [{
                "name": "marker-copy", "image": plan["supportImage"],
                "imagePullPolicy": "IfNotPresent",
                "command": ["python3", "-B", "-c", init_code],
                "securityContext": security,
                "volumeMounts": [_mount("marker-source", "/run/marker-source"),
                                 _mount("marker-private", "/run/marker-private", read_only=False),
                                 tmp_mount],
                "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                              "limits": {"cpu": "100m", "memory": "128Mi"}},
            }],
            "containers": [{
                "name": "guardrail-proxy", "image": plan["proxyImage"],
                "imagePullPolicy": "IfNotPresent",
                "workingDir": "/src",
                "command": ["python3", "-B", "-c", proxy_code],
                "env": [_env("PYTHONDONTWRITEBYTECODE", "1"),
                        _env("PYTHONPATH", "/src"),
                        _env("PHORVEX_SUPPORT_FIXTURE_ENABLED", "1"),
                        _env("PHORVEX_SENSITIVE_OUTPUT_POLICY_DIR", "/etc/phorvex/output-policy"),
                        _env("PHORVEX_SENSITIVE_OUTPUT_STATE_DIR", "/var/lib/phorvex-output-policy"),
                        {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}],
                "ports": [{"name": "guarded", "containerPort": 8000}],
                "readinessProbe": {"httpGet": {"path": "/v1/output-policy/state", "port": 8000},
                                   "periodSeconds": 5, "timeoutSeconds": 4,
                                   "failureThreshold": 3},
                "livenessProbe": {"tcpSocket": {"port": 8000},
                                  "periodSeconds": 10, "timeoutSeconds": 2,
                                  "failureThreshold": 3},
                "securityContext": security,
                "volumeMounts": [source_mount,
                                 _mount("output-policy", "/etc/phorvex/output-policy"),
                                 _mount("output-state", "/var/lib/phorvex-output-policy", read_only=False),
                                 tmp_mount],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                              "limits": {"cpu": "500m", "memory": "512Mi"}},
            }, {
                "name": "support-app", "image": plan["supportImage"],
                "imagePullPolicy": "IfNotPresent",
                "command": ["python3", "-B", "/src/support_fixture.py"],
                "env": [_env("PYTHONDONTWRITEBYTECODE", "1"),
                        _env("SUPPORT_FIXTURE_MODEL_URL",
                             f"http://{plan['modelServiceName']}.{namespace}.svc:8000"),
                        _env("SUPPORT_FIXTURE_MODEL", plan["modelID"]),
                        _env("SUPPORT_FIXTURE_MARKER_FILE", PRIVATE_MARKER_PATH),
                        _secret_env("VLLM_API_KEY", plan["modelAPIKeySecretName"],
                                    plan["modelAPIKeySecretKey"])],
                "ports": [{"name": "support", "containerPort": 8002}],
                "readinessProbe": {"exec": {"command": ["python3", "-B", "-c",
                    "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8002/v1/support/state',timeout=2); assert r.status==200 and len(r.read(1025))<=1024"]},
                                   "periodSeconds": 5, "timeoutSeconds": 4,
                                   "failureThreshold": 3},
                "livenessProbe": {"exec": {"command": ["python3", "-B", "-c",
                    "import socket; s=socket.create_connection(('127.0.0.1',8002),2); s.close()"]},
                                  "periodSeconds": 10, "timeoutSeconds": 3,
                                  "failureThreshold": 3},
                "securityContext": security,
                "volumeMounts": [source_mount,
                                 _mount("marker-private", "/etc/phorvex-support"),
                                 tmp_mount],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                              "limits": {"cpu": "500m", "memory": "512Mi"}},
            }],
            "volumes": [
                {"name": "source", "configMap": {"name": SOURCE_NAME, "defaultMode": 0o444}},
                {"name": "marker-source", "secret": {"secretName": MARKER_SECRET_NAME,
                                                      "defaultMode": 0o440}},
                {"name": "marker-private", "emptyDir": {}},
                {"name": "output-policy", "configMap": {"name": POLICY_CM_NAME,
                                                        "optional": True, "defaultMode": 0o444}},
                {"name": "output-state", "emptyDir": {}},
                {"name": "tmp", "emptyDir": {}},
            ],
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {**common_meta, "name": SERVICE_NAME},
        "spec": {"type": "ClusterIP", "selector": {"app": POD_NAME, LABEL: "true"},
                 "ports": [{"name": "http", "port": 8000, "targetPort": 8000,
                            "protocol": "TCP"}]},
    }
    phorvex_policy = {
        "apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
        "metadata": {**common_meta, "name": POD_NAME},
        "spec": {
            "tenant": namespace,
            "selector": {"matchLabels": {LABEL: "true"}},
            "objective": {"lambda": "0.4",
                          "costWeights": {"normSparsity": "0.4", "flowDisruption": "0.6"}},
            "budget": {"maxMovesPerTick": 1, "tickInterval": "10s",
                       "antiOverRotationWindow": "90s", "proactiveFloor": "15m"},
            "slo": {"minAvailableReplicas": 1},
            "assetValue": {"fromLabels": {"data-class": {"internal": "0.4"}},
                           "weightSecrets": "0.8", "blastRadiusFromGraph": True},
            "triggers": {"eventDriven": True, "reactiveOnly": True},
            "actions": {"enabled": ["rotate", "quarantine",
                                    "sensitive-output-policy-activate"]},
            "mode": "active",
        },
    }
    return {"source-configmap.json": source_cm, "marker-secret.json": marker_secret,
            "fixture-pod.json": pod, "fixture-service.json": service,
            "fixture-policy.json": phorvex_policy,
            "sourceSHA256": proxy_hash, "supportSourceSHA256": support_hash}


def render(plan_path: Path, out_dir: Path, marker_file: Path | None = None):
    plan = validate_plan(json.loads(plan_path.read_text()))
    if out_dir.exists():
        raise FileExistsError("render output directory must be new")
    source = {name: (SOURCE_DIR / name).read_text(encoding="utf-8") for name in SOURCE_FILES}
    if marker_file:
        fd = os.open(marker_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 256 or info.st_mode & 0o007:
                raise ValueError("marker input must be private regular file")
            marker = os.read(fd, 257).decode("ascii").strip()
        finally:
            os.close(fd)
    else:
        marker = secrets.token_urlsafe(48)
    if not MARKER.fullmatch(marker):
        raise ValueError("private marker shape invalid")
    docs = documents(plan, marker, source)
    out_dir.mkdir(mode=0o700, parents=True)
    os.chmod(out_dir, 0o700)
    for name in ("source-configmap.json", "marker-secret.json", "fixture-pod.json",
                 "fixture-service.json", "fixture-policy.json"):
        fd = os.open(out_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, canonical(docs[name]))
            os.fsync(fd)
        finally:
            os.close(fd)
    plan_fd = os.open(out_dir / "plan.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(plan_fd, canonical(plan))
        os.fsync(plan_fd)
    finally:
        os.close(plan_fd)
    summary = {"schema": "phorvex.guardrail-output-fixture-package.v1",
               "podName": POD_NAME, "serviceName": SERVICE_NAME,
               "context": plan["context"], "clusterUID": plan["clusterUID"],
               "modelServiceName": plan["modelServiceName"],
               "modelServiceUID": plan["modelServiceUID"],
               "modelTargetPodName": plan["modelTargetPodName"],
               "modelTargetPodUID": plan["modelTargetPodUID"],
               "modelTargetImageID": plan["modelTargetImageID"],
               "modelID": plan["modelID"],
               "sourceConfigMapName": SOURCE_NAME,
               "policyConfigMapName": POLICY_CM_NAME,
               "sourceSHA256": docs["sourceSHA256"],
               "supportSourceSHA256": docs["supportSourceSHA256"],
               "files": ["plan.json", "source-configmap.json", "marker-secret.json", "fixture-pod.json",
                         "fixture-service.json", "fixture-policy.json"]}
    summary_fd = os.open(out_dir / "summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(summary_fd, canonical(summary))
        os.fsync(summary_fd)
    finally:
        os.close(summary_fd)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--marker-file", type=Path)
    args = parser.parse_args()
    summary = render(args.plan, args.out_dir, args.marker_file)
    print(json.dumps(summary, sort_keys=True))  # never print marker or Secret content


if __name__ == "__main__":
    main()
