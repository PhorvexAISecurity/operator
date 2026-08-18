#!/usr/bin/env bash
# batchm3.sh — M1/M2/M3 final: redirect-following MCP client, pod-delete cycles (no RS churn).
set -uo pipefail
NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchm3; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }

cat > /tmp/mcp_client.py <<'PY'
import json, sys, urllib.request, urllib.error
def rpc(payload, sess=None):
    body = json.dumps(payload).encode()
    url = "http://127.0.0.1:28502/mcp/"
    for _ in range(3):
        req = urllib.request.Request(url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                     **({"mcp-session-id": sess} if sess else {})})
        try:
            r = urllib.request.urlopen(req, timeout=15)
            text = r.read().decode()
            sess_out = r.headers.get("mcp-session-id", sess)
            break
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 307, 308) and e.headers.get("Location"):
                url = e.headers["Location"]; continue
            raise
    if "data: " in text: text = text.split("data: ", 1)[1].split("\n", 1)[0]
    return json.loads(text), sess_out
init, sess = rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":
    {"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"redteam","version":"0"}}})
rpc({"jsonrpc":"2.0","method":"notifications/initialized"}, sess)
tools, _ = rpc({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}, sess)
for t in tools["result"]["tools"]:
    print(f"TOOL {t['name']}: {t['description'][:280]}")
res, _ = rpc({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_promotions","arguments":{}}}, sess)
print("CALL check_promotions ->", json.dumps(res["result"])[:380])
PY

say "1) baseline benign probe"
POD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n mcp pod/$POD 28502:8000 >/tmp/pf-m3.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" /tmp/pf-m3.log || { echo BIND-FAILED; cat /tmp/pf-m3.log; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/benign.txt"

say "2) poison CM + restart pod (delete, not rollout)"
jq -n --arg c "$(cat /tmp/server_poisoned.py)" '{data:{"server.py":$c}}' | kubectl patch configmap -n mcp mcp-code --type merge -p "$(cat)"
kubectl delete pod -n mcp $POD --wait=false
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=420s
POD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "serving from: $POD"

say "3) M1/M2 evidence: poisoned tools/list + poisoned call"
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$POD 28502:8000 >/tmp/pf-m3.log 2>&1 &
PF=$!; sleep 4; grep -q "Forwarding from" /tmp/pf-m3.log || { echo BIND-FAILED; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/m1-m2.txt"

say "4) Phorvex reaction while poisoned (unwatched -> silence)"
kubectl logs -n $NSX deploy/$CTRL --since=3m 2>/dev/null | grep -i "mcp/" | tail -4 | tee "$OUT/reaction-unwatched.txt"
echo "(empty = blind — no policy covered ns mcp until now)"

say "5) M3b: enroll + foothold event -> expect rotate"
kubectl apply -f - <<'EOF'
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: mcp-defense
  namespace: mcp
spec:
  tenant: mcp
  selector:
    matchLabels:
      app: mcp-server
  actions:
    enabled: ["rotate"]
  assetValue:
    blastRadiusFromGraph: true
    fromLabels:
      data-class:
        internal: "0.4"
        public: "0.1"
        restricted: "1.0"
    weightSecrets: "0.8"
  objective:
    costWeights:
      flowDisruption: "0.6"
      normSparsity: "0.4"
    lambda: "0.4"
  budget:
    antiOverRotationWindow: 10s
    maxMovesPerTick: 1
    proactiveFloor: 15m
    tickInterval: 5s
  mode: active
  triggers:
    eventDriven: true
    reactiveOnly: true
  slo:
    minAvailableReplicas: 1
EOF
sleep 8
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: m3-mcp-foothold2
spec:
  rule:
    type: Panic
    threatLevel: critical
    source: redteam
  targets:
    - mcp/$POD
  description: "M3b: foothold on the (poisoned) mcp pod — watched now, expect rotate"
  anomalyScore: "0.95"
EOF
for i in $(seq 1 15); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "mcp/" | grep -iE "rotate" | tail -1)
  [ -n "$D" ] && { echo "$D" | head -c 320; echo; break; }
  echo "  ...waiting ($i)"
done
kubectl delete securityevent m3-mcp-foothold2 --ignore-not-found

say "6) M3a: poison survives the rotate? (config-at-rest)"
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=420s
POD3=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "post-rotate pod: $POD3 (was $POD)"
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$POD3 28502:8000 >/tmp/pf-m3.log 2>&1 &
PF=$!; sleep 4; grep -q "Forwarding from" /tmp/pf-m3.log || { echo BIND-FAILED; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/m3a-survives.txt"

say "7) cleanup: benign CM + restart + drop policy + verify clean"
jq -n --arg c "$(kubectl get -o jsonpath='{.data.server\.py}' configmap -n mcp mcp-code > /dev/null; cat /tmp/server_orig.py)" '{data:{"server.py":$c}}' | kubectl patch configmap -n mcp mcp-code --type merge -p "$(cat)"
kubectl delete pod -n mcp $POD3 --wait=false
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=420s
kubectl delete phorvexpolicy -n mcp mcp-defense --ignore-not-found
FINALPOD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$FINALPOD 28502:8000 >/tmp/pf-m3.log 2>&1 &
PF=$!; sleep 4
python3 /tmp/mcp_client.py | tee "$OUT/final-clean.txt"
kubectl get pods -n mcp | tee "$OUT/pods-after.txt"
kill $PF 2>/dev/null
echo done
