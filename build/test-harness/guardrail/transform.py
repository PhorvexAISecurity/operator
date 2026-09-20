import json
import math
import os
import sys


def configured_threshold(name):
    raw = os.environ.get(name, "0.5")
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a finite number in [0,1], got {raw!r}") from exc
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise SystemExit(f"{name} must be a finite number in [0,1], got {raw!r}")
    return raw


initial_variant = os.environ.get("GUARDRAIL_INITIAL_VARIANT", "pgv2").strip()
if initial_variant not in ("pgv1", "pgv2"):
    raise SystemExit(f"GUARDRAIL_INITIAL_VARIANT must be pgv1 or pgv2, got {initial_variant!r}")
guardrail_mode = os.environ.get("GUARDRAIL_MODE", "enforce").strip().lower()
if guardrail_mode not in ("enforce", "observe"):
    raise SystemExit(f"GUARDRAIL_MODE must be enforce or observe, got {guardrail_mode!r}")
threshold_pgv1 = configured_threshold("GUARDRAIL_THRESHOLD_PGV1")
threshold_pgv2 = configured_threshold("GUARDRAIL_THRESHOLD_PGV2")

if sys.argv[1:] == ["--validate-config"]:
    print(json.dumps({
        "initial_variant": initial_variant,
        "mode": guardrail_mode,
        "thresholds": {"pgv1": threshold_pgv1, "pgv2": threshold_pgv2},
    }, sort_keys=True))
    raise SystemExit(0)

d = json.load(open(sys.argv[1]))
api_key_secret_name = os.environ.get("VLLM_API_KEY_SECRET_NAME", "").strip()
api_key_secret_key = os.environ.get("VLLM_API_KEY_SECRET_KEY", "api-key").strip()
if not api_key_secret_name or not api_key_secret_key:
    raise SystemExit("VLLM_API_KEY_SECRET_NAME and a nonempty VLLM_API_KEY_SECRET_KEY are required")
api_key_env = {
    "name": "VLLM_API_KEY",
    "valueFrom": {"secretKeyRef": {"name": api_key_secret_name, "key": api_key_secret_key}},
}
for k in ("resourceVersion", "uid", "creationTimestamp", "generation", "managedFields"):
    d["metadata"].pop(k, None)
d.pop("status", None)
t = d["spec"]["template"]
t["metadata"].setdefault("labels", {})["phorvex.ai/guardrail-tier"] = "true"
ann = t["metadata"].setdefault("annotations", {})
ann["phorvex.ai/guardrail-variant"] = initial_variant
ann["phorvex.ai/guardrail-variants"] = "pgv2,pgv1"
ann["phorvex.ai/guardrail-path"] = "/v1/guardrail/reload"
spec = t["spec"]
for c in spec["containers"]:
    if c["name"] == "vllm":
        c["args"] = ["8001" if a == "8000" and i > 0 and c["args"][i - 1] == "--port" else a
                     for i, a in enumerate(c["args"])]
        for p in ("readinessProbe", "livenessProbe", "startupProbe"):
            if p in c and "httpGet" in c[p] and c[p]["httpGet"].get("port") == 8000:
                c[p]["httpGet"]["port"] = 8001
        c["env"] = [item for item in c.get("env", []) if item.get("name") != "VLLM_API_KEY"] + [api_key_env]
sidecar = {
    "name": "guardrail",
    "image": "python:3.11-slim",
    "command": ["sh", "-c", "pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && pip install --no-cache-dir fastapi 'uvicorn[standard]' httpx transformers && exec python /src/guardrail_proxy.py"],
    "env": [
        {"name": "GUARDRAIL_INITIAL_VARIANT", "value": initial_variant},
        {"name": "GUARDRAIL_MODE", "value": guardrail_mode},
        {"name": "GUARDRAIL_THRESHOLD_PGV1", "value": threshold_pgv1},
        {"name": "GUARDRAIL_THRESHOLD_PGV2", "value": threshold_pgv2},
        api_key_env,
        {"name": "HF_HOME", "value": "/tmp/hf"},
        {"name": "TOKENIZERS_PARALLELISM", "value": "false"},
    ],
    "ports": [{"containerPort": 8000}],
    "resources": {"requests": {"cpu": "500m", "memory": "2Gi"}, "limits": {"cpu": "1500m", "memory": "3500Mi"}},
    "startupProbe": {"httpGet": {"path": "/v1/guardrail/state", "port": 8000}, "periodSeconds": 10, "failureThreshold": 120},
    "readinessProbe": {"httpGet": {"path": "/v1/guardrail/state", "port": 8000}, "periodSeconds": 10, "failureThreshold": 3},
    "volumeMounts": [{"name": "guardrail-src", "mountPath": "/src"}],
}
spec["containers"] = [c for c in spec["containers"] if c["name"] != "guardrail"] + [sidecar]
vs = [v for v in spec.get("volumes", []) if v.get("name") != "guardrail-src"]
vs.append({"name": "guardrail-src", "configMap": {"name": "guardrail-proxy"}})
spec["volumes"] = vs
json.dump(d, open(sys.argv[2], "w"))
args = d["spec"]["template"]["spec"]["containers"][0]["args"]
print("containers:", [c["name"] for c in spec["containers"]])
print("vllm --port ->", args[args.index("--port") + 1])
print("vllm readiness port ->", d["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["port"])
print("guardrail config ->", {
    "initial_variant": initial_variant,
    "mode": guardrail_mode,
    "thresholds": {"pgv1": threshold_pgv1, "pgv2": threshold_pgv2},
})
