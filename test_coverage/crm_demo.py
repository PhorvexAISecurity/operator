#!/usr/bin/env python3
"""On the jump host: live CRM cross-record refund attack + deny-guard defense, per Pod.
Prints one JSON result object. Restores the guard to OFF at the end."""
import json
import subprocess
import time

NS = "crm"
MARK = "phorvex-crm-drill-%d" % int(time.time())


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)


def pods():
    out = sh("kubectl", "-n", NS, "get", "pods", "-l", "app=crm",
             "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase} {.status.containerStatuses[0].ready}\n{end}").stdout
    return [l.split()[0] for l in out.strip().splitlines() if l.strip().lower().endswith("true") and "Running" in l]


def call(pod, method, path, body=None):
    """Hit this exact Pod's own localhost:8080 via exec, so it proves per-Pod state."""
    py = ("import urllib.request,json,sys\n"
          "d=%s\n"
          "req=urllib.request.Request('http://127.0.0.1:8080%s',data=(json.dumps(d).encode() if d is not None else None),"
          "method='%s',headers={'Content-Type':'application/json'})\n"
          "try:\n"
          " r=urllib.request.urlopen(req,timeout=5); print(r.status); print(r.read().decode())\n"
          "except urllib.error.HTTPError as e:\n"
          " print(e.code); print(e.read().decode())\n") % (repr(body) if body is not None else "None", path, method)
    r = sh("kubectl", "-n", NS, "exec", pod, "--", "python3", "-c", py)
    lines = (r.stdout or "").splitlines()
    code = int(lines[0]) if lines and lines[0].isdigit() else -1
    return code, ("\n".join(lines[1:]) if len(lines) > 1 else r.stderr[:200])


def set_guard(denied):
    body = json.dumps({"denied_order_ids": denied})
    sh("kubectl", "-n", NS, "create", "configmap", "crm-refund-guard",
       "--from-literal=denied.json=" + body, "--dry-run=client", "-o", "yaml")
    p = subprocess.run(["kubectl", "-n", NS, "create", "configmap", "crm-refund-guard",
                        "--from-literal=denied.json=" + body, "--dry-run=client", "-o", "yaml"],
                       capture_output=True, text=True)
    subprocess.run(["kubectl", "apply", "-f", "-"], input=p.stdout, capture_output=True, text=True)


result = {"marker": MARK, "pods": pods(), "stages": []}
P = result["pods"]

# 1. Attack via each Pod while guard is OFF: cross-record refund of Bob's OR-5002 lands.
set_guard([])
time.sleep(2)
result["attack_guard_off"] = {p: call(p, "POST", "/refunds", {"order_id": "OR-5002", "amount": 499.0, "reason": MARK + "-attack"})[0] for p in P}

# 2. Activate the guard: revoke OR-5002.
set_guard(["OR-5002"])

# 3. Poll until every Pod enforces (ConfigMap mount propagation), up to 120s.
deadline = time.time() + 120
enforced = {}
while time.time() < deadline:
    enforced = {p: call(p, "POST", "/refunds", {"order_id": "OR-5002", "amount": 1.0, "reason": MARK + "-replay"})[0] for p in P}
    if all(c == 403 for c in enforced.values()):
        break
    time.sleep(10)
result["replay_denied_per_pod"] = enforced
result["propagation_seconds"] = round(120 - (deadline - time.time()))

# 4. Legit unrelated order (OR-5001) still refunds on every Pod while OR-5002 is revoked.
result["legit_still_works_per_pod"] = {p: call(p, "POST", "/refunds", {"order_id": "OR-5001", "amount": 10.0, "reason": MARK + "-legit"})[0] for p in P}

# 5. Restore guard OFF and confirm OR-5002 refunds again on every Pod.
set_guard([])
deadline = time.time() + 120
restored = {}
while time.time() < deadline:
    restored = {p: call(p, "POST", "/refunds", {"order_id": "OR-5002", "amount": 1.0, "reason": MARK + "-restored"})[0] for p in P}
    if all(c == 200 for c in restored.values()):
        break
    time.sleep(10)
result["restored_per_pod"] = restored

# 6. Oracle: count this drill's refunds in /audit by marker (via any Pod).
code, body = call(P[0], "GET", "/audit")
try:
    aud = json.loads(body)["refunds"]
    result["audit_marker_refunds"] = [(x.get("order_id"), x.get("reason")) for x in aud if MARK in str(x.get("reason", ""))]
except Exception:
    result["audit_marker_refunds"] = "parse-error"

result["verdict"] = ("DEFENDED cross-pod"
                     if all(c == 403 for c in result["replay_denied_per_pod"].values())
                     and all(c == 200 for c in result["legit_still_works_per_pod"].values())
                     and all(c == 200 for c in result["restored_per_pod"].values())
                     else "INCOMPLETE")
print(json.dumps(result, indent=2))
