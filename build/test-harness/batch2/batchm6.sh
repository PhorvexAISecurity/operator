#!/usr/bin/env bash
# batchm6.sh — the tight one. Verify every state transition out loud.
set -uo pipefail
NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchm6; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
marks(){ kubectl get configmap -n mcp mcp-code -o jsonpath='{.data.server\.py}' | grep -c "INTERNAL NOTE"; }

say "1) poison + VERIFY the CM actually changed"
jq -n --arg c "$(cat /tmp/server_min_poison.py)" '{data:{"server.py":$c}}' | kubectl patch configmap -n mcp mcp-code --type merge -p "$(cat)"
echo "CM poison markers now: $(marks) (must be 1)"

say "2) restart pod + VERIFY the poison is mounted in the new pod"
OLD=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl delete pod -n mcp $OLD --wait=false
for i in $(seq 1 40); do
  sleep 10
  NEW=$(kubectl get pods -n mcp -l app=mcp-server --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
  PHASE=$(kubectl get pod -n mcp $NEW -o jsonpath='{.status.phase}' 2>/dev/null || echo "?")
  READY=$(kubectl get pod -n mcp $NEW -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo "?")
  echo "  [$i] pod=$NEW phase=$PHASE ready=$READY"
  [ "$READY" = "true" ] && break
done
echo "mounted-file markers in $NEW: $(kubectl exec -n mcp $NEW -- grep -c 'INTERNAL NOTE' /app/server.py 2>/dev/null || kubectl exec -n mcp $NEW -- sh -c 'grep -rc INTERNAL NOTE $(find / -name server.py -maxdepth 4 2>/dev/null | head -1)' 2>/dev/null || echo '?')"

say "3) probe: M1 (description) + M2 (response)"
kubectl port-forward -n mcp pod/$NEW 28502:8000 >/tmp/pf-m6.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" /tmp/pf-m6.log || { echo BIND-FAILED; cat /tmp/pf-m6.log; exit 1; }
python3 /tmp/mcp_client.py | tee "$OUT/m1-m2.txt"

say "4) Phorvex while poisoned (unwatched -> silence expected)"
kubectl logs -n $NSX deploy/$CTRL --since=5m 2>/dev/null | grep -i "mcp/" | tail -3 | tee "$OUT/reaction.txt"; echo "(empty = blind)"

say "5) M3b: policy + foothold event -> watch 90s for rotate"
kubectl delete phorvexpolicy -n mcp mcp-defense --ignore-not-found >/dev/null 2>&1
kubectl apply -f - <<'EOF'
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: mcp-defense
  namespace: mcp
spec:
  tenant: mcp
  selector: {matchLabels: {app: mcp-server}}
  actions: {enabled: ["rotate"]}
  assetValue:
    blastRadiusFromGraph: true
    fromLabels: {data-class: {internal: "0.4", public: "0.1", restricted: "1.0"}}
    weightSecrets: "0.8"
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, lambda: "0.4"}
  budget: {antiOverRotationWindow: 10s, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  mode: active
  triggers: {eventDriven: true, reactiveOnly: true}
  slo: {minAvailableReplicas: 1}
EOF
sleep 10
echo "pod age check: $(kubectl get pod -n mcp $NEW -o jsonpath='{.metadata.creationTimestamp}') (window 10s — any pod older is attackable)"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: m3-mcp-final
spec:
  rule: {type: Panic, threatLevel: critical, source: redteam}
  targets: ["mcp/$NEW"]
  description: "M3b final: foothold on poisoned mcp pod, watched -> rotate expected"
  anomalyScore: "0.95"
EOF
for i in $(seq 1 18); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "mcp/" | tail -2)
  [ -n "$D" ] && { echo "$D" | head -c 400; echo; break; }
  echo "  ...waiting ($i)"
done
kubectl delete securityevent m3-mcp-final --ignore-not-found >/dev/null

say "6) M3a: poison after rotate"
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=300s 2>/dev/null
CUR=$(kubectl get pods -n mcp --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "pod now: $CUR (was $NEW)"; [ "$CUR" = "$NEW" ] && echo "=> NO rotation" || echo "=> ROTATED"
kill $PF 2>/dev/null; sleep 2
kubectl port-forward -n mcp pod/$CUR 28502:8000 >/tmp/pf-m6.log 2>&1 &
PF=$!; sleep 4
python3 /tmp/mcp_client.py | tee "$OUT/m3a.txt"

say "7) cleanup + verify"
kill $PF 2>/dev/null
jq -n --arg c "$(cat /tmp/server_orig.py)" '{data:{"server.py":$c}}' | kubectl patch configmap -n mcp mcp-code --type merge -p "$(cat)"
kubectl delete pod -n mcp $CUR --wait=false
kubectl wait -n mcp --for=condition=Ready pod -l app=mcp-server --timeout=300s
kubectl delete phorvexpolicy -n mcp mcp-defense --ignore-not-found
echo "CM poison markers at end: $(marks) (must be 0)"
kubectl get pods -n mcp | tee "$OUT/pods-after.txt"
echo done
