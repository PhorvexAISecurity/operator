#!/usr/bin/env bash
# batchm5.sh — continue from the live poisoned state: M1/M2 evidence, M3b rotate, M3a survival, cleanup.
set -uo pipefail
NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchm5; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }

POD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
say "1) M1/M2 evidence from poisoned pod $POD"
kubectl port-forward -n mcp pod/$POD 28502:8000 >/tmp/pf-m5.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" /tmp/pf-m5.log || { echo BIND-FAILED; cat /tmp/pf-m5.log; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/m1-m2.txt"

say "2) Phorvex while poisoned (unwatched -> silence)"
kubectl logs -n $NSX deploy/$CTRL --since=5m 2>/dev/null | grep -i "mcp/" | tail -3 | tee "$OUT/reaction-unwatched.txt"
echo "(empty = blind)"

say "3) M3b: enroll + foothold event -> expect rotate"
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
  name: m3-mcp-foothold4
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
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "mcp/" | grep -iE "rotate|decision" | tail -1)
  [ -n "$D" ] && { echo "$D" | head -c 320; echo; break; }
  echo "  ...waiting ($i)"
done
kubectl delete securityevent m3-mcp-foothold4 --ignore-not-found

say "4) M3a: poison survives the rotate?"
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=420s
POD3=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "post-rotate pod: $POD3 (was $POD)"
[ "$POD3" = "$POD" ] && echo "=> no rotation happened" || echo "=> POD ROTATED"
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$POD3 28502:8000 >/tmp/pf-m5.log 2>&1 &
PF=$!; sleep 4; grep -q "Forwarding from" /tmp/pf-m5.log || { echo BIND-FAILED; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/m3a-survives.txt"

say "5) cleanup: benign CM + restart + drop policy + verify clean"
jq -n --arg c "$(cat /tmp/server_orig.py)" '{data:{"server.py":$c}}' | kubectl patch configmap -n mcp mcp-code --type merge -p "$(cat)"
kubectl delete pod -n mcp $POD3 --wait=false
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=420s
kubectl delete phorvexpolicy -n mcp mcp-defense --ignore-not-found
kubectl get configmap -n mcp mcp-code -o jsonpath='{.data.server\.py}' | grep -c "INTERNAL NOTE FOR THE ASSISTANT" || echo "clean: 0 poison markers"
FINALPOD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$FINALPOD 28502:8000 >/tmp/pf-m5.log 2>&1 &
PF=$!; sleep 4
python3 /tmp/mcp_client.py | tee "$OUT/final-clean.txt"
kill $PF 2>/dev/null
kubectl get pods -n mcp | tee "$OUT/pods-after.txt"
echo done
