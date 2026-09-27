"""Render a review-only vLLM/guardrail control rollout from exact live originals.

No Secret is read, created, or emitted. The output is a private candidate for the
normal workload owner and Helm pipeline; this program never calls Kubernetes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
PROXY = HERE.parents[1] / "test-harness" / "guardrail" / "guardrail_proxy.py"
DUAL = HERE / "dual_server.py"
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
IMAGE = re.compile(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ORIGINAL_PROXY_SHA256 = "fba39e68dea763043125b29416b832418387a6780e8cce067cbe0121104d09ce"
# The legacy four-file guardrail profile accepts these PR365 source bytes.
# Later five-file lease work changed both checked-in modules; never emit a
# hybrid four-file candidate by reading those newer bytes opportunistically.
LEGACY_SOURCE_COMMIT = "440da58d6e965d7f885cd35e44faa510d383cfc8"
LEGACY_PROXY_SHA256 = "7659d44ef8e637fd74db754e393f65c3e58289cc3be347c716e10e83127076f2"
LEGACY_DUAL_SHA256 = "c89135124108e7f613f029a0b4bde5c9a6201f73b1b0f0041d2d4379140d2dfd"
LIVE_BASE_IMAGE = "vllm/vllm-openai:v0.7.3"
PUBLISHED_IMAGE = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:af3e5ce57d156c09533dde6bb7feab8f252ef3dbc3277b77c2baef4bd781897f"
SECRET_KEYS = ("api-key", "admin-bearer", "tls.crt", "tls.key")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_exact(path: Path, expected: str) -> dict:
    if not HEX.fullmatch(expected):
        raise ValueError("source hash must be exact SHA-256")
    raw = path.read_bytes()
    if len(raw) > 4_000_000 or sha(raw) != expected:
        raise ValueError("source original size/hash drift")
    return json.loads(raw)


def put_env(container: dict, name: str, secret: str, key: str):
    rows = container.setdefault("env", [])
    if sum(e.get("name") == name for e in rows) > 1:
        raise ValueError("duplicate environment authority")
    rows[:] = [e for e in rows if e.get("name") != name]
    rows.append({"name": name, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}})


def local_health(probe: dict):
    get = probe.get("httpGet")
    if not isinstance(get, dict) or get.get("path") != "/health" or get.get("port") != 8001:
        raise ValueError("vLLM health probe differs from reviewed endpoint")
    probe.pop("httpGet")
    probe["exec"] = {"command": ["python3", "-c",
        "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=4); raise SystemExit(0 if r.status == 200 else 1)"]}


def render(deployment: dict, configmap: dict, policy: dict, image: str,
           workload_secret: str, operator_secret: str, server_name: str) -> dict[str, bytes]:
    if image != PUBLISHED_IMAGE or not IMAGE.fullmatch(image) or any(not DNS.fullmatch(v) for v in
            (workload_secret, operator_secret, server_name.replace(".", "-"))):
        raise ValueError("immutable image or Secret/server identity invalid")
    if deployment.get("kind") != "Deployment" or deployment.get("metadata", {}).get("namespace") != "vllm" or deployment["metadata"].get("name") != "vllm":
        raise ValueError("wrong exact workload")
    if configmap.get("kind") != "ConfigMap" or configmap.get("metadata", {}).get("namespace") != "vllm" or configmap["metadata"].get("name") != "guardrail-proxy":
        raise ValueError("wrong exact proxy source ConfigMap")
    if policy.get("metadata", {}).get("namespace") != "vllm" or policy["metadata"].get("name") != "vllm-defense" or not policy["metadata"].get("uid"):
        raise ValueError("exact policy identity unavailable")
    data = configmap.get("data", {})
    if set(data) != {"guardrail_proxy.py"} or sha(data["guardrail_proxy.py"].encode()) != ORIGINAL_PROXY_SHA256:
        raise ValueError("installed proxy source differs from reviewed original")
    new_proxy = PROXY.read_bytes()
    dual = DUAL.read_bytes()
    if len(new_proxy) > 100_000 or len(dual) > 25_000:
        raise ValueError("source outside review bound")
    if sha(new_proxy) != LEGACY_PROXY_SHA256 or sha(dual) != LEGACY_DUAL_SHA256:
        raise ValueError("legacy four-file source differs from PR365; use reviewed checkout " + LEGACY_SOURCE_COMMIT)
    dep = copy.deepcopy(deployment)
    cm = copy.deepcopy(configmap)
    for obj in (dep, cm):
        for field in ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"):
            obj["metadata"].pop(field, None)
        obj.pop("status", None)
    spec = dep["spec"]["template"]["spec"]
    containers = {c["name"]: c for c in spec["containers"]}
    if set(containers) != {"vllm", "guardrail"} or spec.get("serviceAccountName", "default") != "default":
        raise ValueError("container or ServiceAccount set changed")
    engine, guard = containers["vllm"], containers["guardrail"]
    if engine.get("image") != LIVE_BASE_IMAGE or engine.get("args", []).count("--port") != 1:
        raise ValueError("vLLM image or serving args changed")
    args = engine["args"]
    if args[args.index("--port") + 1] != "8001" or "--host" in args:
        raise ValueError("vLLM port/host drift")
    if "--enable-lora" not in args or not any(e.get("name") == "VLLM_ALLOW_RUNTIME_LORA_UPDATING" and e.get("value") == "1" for e in engine.get("env", [])):
        raise ValueError("runtime LoRA capability is not evidenced")
    if not any(e.get("name") == "VLLM_SERVER_DEV_MODE" and e.get("value") == "1" for e in engine.get("env", [])):
        raise ValueError("reviewed dev-mode reset route unavailable")
    engine["image"] = image
    engine["args"] = args + ["--host", "127.0.0.1"]
    put_env(engine, "VLLM_API_KEY", workload_secret, "api-key")
    for name in ("startupProbe", "readinessProbe", "livenessProbe"):
        local_health(engine[name])
    command = guard.get("command", [])
    if len(command) != 3 or command[:2] != ["sh", "-c"] or not command[2].endswith("exec python /src/guardrail_proxy.py"):
        raise ValueError("guardrail launch command changed")
    if any(e.get("name") in ("PHORVEX_DRAIN_V11", "PHORVEX_SUPPORT_FIXTURE_ENABLED") and e.get("value") == "1" for e in guard.get("env", [])):
        raise ValueError("unreviewed proxy runtime mode enabled")
    guard["command"][2] = command[2][:-len("exec python /src/guardrail_proxy.py")] + "exec python /src/dual_server.py"
    put_env(guard, "VLLM_API_KEY", workload_secret, "api-key")
    put_env(guard, "PHORVEX_GUARDRAIL_ADMIN_KEY", workload_secret, "admin-bearer")
    for name, key in (("PHORVEX_ADMIN_TLS_CERT_FILE", "tls.crt"), ("PHORVEX_ADMIN_TLS_KEY_FILE", "tls.key")):
        rows = guard.setdefault("env", [])
        rows[:] = [e for e in rows if e.get("name") != name]
        rows.append({"name": name, "value": "/etc/phorvex/admin-tls/" + key})
    if any(p.get("containerPort") == 8443 for p in guard.get("ports", [])):
        raise ValueError("admin port already occupied")
    guard.setdefault("ports", []).append({"name": "admin-tls", "containerPort": 8443, "protocol": "TCP"})
    guard.setdefault("volumeMounts", []).append({"name": "vllm-admin-tls", "mountPath": "/etc/phorvex/admin-tls", "readOnly": True})
    if any(v.get("name") == "vllm-admin-tls" for v in spec.get("volumes", [])):
        raise ValueError("admin TLS volume already exists")
    spec.setdefault("volumes", []).append({"name": "vllm-admin-tls", "secret": {"secretName": workload_secret,
        "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}})
    labels = dep["spec"]["template"]["metadata"].setdefault("labels", {})
    labels["phorvex.ai/lora-enabled"] = "true"
    ann = dep["spec"]["template"]["metadata"].setdefault("annotations", {})
    ann["phorvex.ai/serving-port"] = "8443"
    ann["phorvex.ai/kv-reset-path"] = "/reset_prefix_cache"
    cm["data"] = {"guardrail_proxy.py": new_proxy.decode(), "dual_server.py": dual.decode()}
    binding = {"namespace": "vllm", "policyName": "vllm-defense", "policyUID": policy["metadata"]["uid"],
               "serviceAccount": "default", "profileID": "vllm-reset-ack-v1", "secretName": operator_secret,
               "bearerKey": "bearer", "caKey": "ca.crt", "serverName": server_name}
    # phorvex-stack is an umbrella chart: its dependency values live under
    # phorvex.phorvex, not the dependency's internal phorvex root alone.
    values = {"phorvex": {"phorvex": {"servingSecurity": {"mode": "secure-required", "bindings": [binding]}}}}
    # JSON is valid YAML and preserves exact key/string spelling for Helm overlays.
    return {"deployment.candidate.json": json.dumps(dep, sort_keys=True, separators=(",", ":")).encode(),
            "configmap.candidate.json": json.dumps(cm, sort_keys=True, separators=(",", ":")).encode(),
            "values.overlay.yaml": json.dumps(values, indent=2, sort_keys=True).encode() + b"\n",
            "secret-contract.json": json.dumps({"workloadNamespace": "vllm", "workloadSecret": workload_secret,
               "workloadKeys": SECRET_KEYS, "operatorNamespace": "phorvex-system", "operatorSecret": operator_secret,
               "operatorKeys": ("bearer", "ca.crt"), "bearerMustEqual": "workload admin-bearer",
               "certificateSAN": server_name, "credentialBytesIncluded": False}, sort_keys=True, indent=2).encode() + b"\n"}


def main():
    p = argparse.ArgumentParser()
    for name in ("deployment", "deployment-sha256", "configmap", "configmap-sha256",
                 "policy", "policy-sha256", "image", "workload-secret", "operator-secret", "server-name", "out"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    result = render(read_exact(Path(a.deployment), a.deployment_sha256),
                    read_exact(Path(a.configmap), a.configmap_sha256),
                    read_exact(Path(a.policy), a.policy_sha256), a.image,
                    a.workload_secret, a.operator_secret, a.server_name)
    output = Path(a.out)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, 0o700)
    hashes = {}
    for name, raw in result.items():
        path = output / name
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = sha(raw)
    print(json.dumps({"status": "REVIEW_ONLY", "filesSHA256": hashes, "secretBytesStored": False}, sort_keys=True))


if __name__ == "__main__":
    main()
