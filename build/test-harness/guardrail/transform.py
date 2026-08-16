import json
import sys

d = json.load(open(sys.argv[1]))
for k in ("resourceVersion", "uid", "creationTimestamp", "generation", "managedFields"):
    d["metadata"].pop(k, None)
d.pop("status", None)
t = d["spec"]["template"]
t["metadata"].setdefault("labels", {})["phorvex.ai/guardrail-tier"] = "true"
ann = t["metadata"].setdefault("annotations", {})
ann["phorvex.ai/guardrail-variant"] = "pgv2"
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
sidecar = {
    "name": "guardrail",
    "image": "python:3.11-slim",
    "command": ["sh", "-c", "pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && pip install --no-cache-dir fastapi 'uvicorn[standard]' httpx transformers && exec python /src/guardrail_proxy.py"],
    "env": [
        {"name": "GUARDRAIL_INITIAL_VARIANT", "value": "pgv2"},
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
