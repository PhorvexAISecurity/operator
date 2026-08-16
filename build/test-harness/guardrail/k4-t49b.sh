#!/usr/bin/env bash
# k4-t49b.sh — T49 evidence re-do (T49-b). Selection already proven twice; this pass captures
# the measurable LOCAL effect correctly: metrics via pod :8001 (vLLM plain text — the sidecar
# drops content-encoding on gzip, so svc /metrics is unusable), plus the sidecar's own log line
# as the enactment receipt, plus the epoch annotation. No roll needed; pod already past F17.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-t49b; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "leader: $VPOD | controller: $OP" | tee "$OUT/target.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid} age-born={.metadata.creationTimestamp} peers={.metadata.annotations.phorvex\.ai/disagg-kv-peers}{"\n"}' | tee "$OUT/uid-before.txt"
date -Is | tee "$OUT/start.txt"

kubectl port-forward -n $NSV svc/vllm 24157:8000 >$OUT/pf-svc.log 2>&1 &
PF1=$!; kubectl port-forward -n $NSV pod/$VPOD 24158:8001 >$OUT/pf-direct.log 2>&1 &
PF2=$!; trap 'kill $PF1 $PF2 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf-svc.log && grep -q "Forwarding from" $OUT/pf-direct.log || { echo "PF FAILED"; exit 1; }

say "0) plant crafted prefix TWICE via svc (1st MISS, 2nd HIT); gauge from :8001"
PREFIX="ZQX-K4B-$(date +%s) The following is a stable system context block for the disaggregated serving rig. $(python3 -c "print(' '.join(['cachewarm']*220))")"
CHAT() { curl -s --max-time 120 http://127.0.0.1:24157/v1/chat/completions -H "Content-Type: application/json" \
  -d "{\"model\":\"Qwen/Qwen2.5-7B-Instruct-AWQ\",\"messages\":[{\"role\":\"user\",\"content\":\"$PREFIX --- Question: reply with the single word OK.\"}],\"max_tokens\":4,\"temperature\":0}"; }
CHAT -o /dev/null; echo "first send (cold MISS)"
sleep 1; CHAT | head -c 120 > "$OUT/plant-hit.txt"; echo; echo "second send (expect HIT)"
RATE_BEFORE=$(curl -s http://127.0.0.1:24158/metrics | grep "gpu_prefix_cache_hit_rate" | head -1)
echo "$RATE_BEFORE" | tee "$OUT/metrics-before.txt"

say "1) scope policy + fire KVPoisoning"
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","kv-migrate-invalidate"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
sleep 6
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
EV=redteam-k4b-$(date +%s)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $EV}
spec:
  rule: {type: KVPoisoning, threatLevel: critical, source: redteam}
  targets: ["$NSV/$VPOD"]
  description: "K4: poisoned KV migrated from a prefill worker (disaggregated serving)"
  anomalyScore: "0.9"
EOF

say "2) watch for kv-migrate-invalidate selection (up to 150s)"
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep '"action": "kv-migrate-invalidate"' | tail -1)
  if [ -n "$L" ]; then FOUND=yes; echo "$L" | tee "$OUT/decision.txt"; break; fi
done
[ -z "$FOUND" ] && { echo "no selection in 150s" | tee "$OUT/decision.txt"; exit 1; }

say "3) effect evidence A: sidecar enactment receipt (the handler POSTed /v1/kv/invalidate)"
sleep 3
kubectl logs -n $NSV $VPOD -c guardrail --since=5m | grep "kv invalidate" | tail -2 | tee "$OUT/sidecar-receipt.txt"
echo "--- and NO actuate-failed in operator log:" | tee -a "$OUT/sidecar-receipt.txt"
kubectl logs -n $NSX $OP --since=5m | grep -c "actuate failed" | tee -a "$OUT/sidecar-receipt.txt"

say "4) effect evidence B: repeat the SAME planted request; hit-rate gauge 0.50 -> 0.00"
sleep 2
CHAT | head -c 120 > "$OUT/repeat-after.txt"
curl -s http://127.0.0.1:24158/metrics | grep "gpu_prefix_cache_hit_rate" | head -1 | tee "$OUT/metrics-after.txt"
echo "epoch on pod:"; kubectl get pod -n $NSV $VPOD -o jsonpath='{.metadata.annotations.phorvex\.ai/kv-migrate-epoch}{"\n"}' | tee "$OUT/epoch.txt"

say "5) pod unchanged + policy/event restored as-found"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid} phase={.status.phase}{"\n"}' | tee "$OUT/uid-after.txt"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-restored.txt"
kubectl delete securityevent $EV --wait=false 2>/dev/null
kill $PF1 $PF2 2>/dev/null
date -Is | tee "$OUT/end.txt"
