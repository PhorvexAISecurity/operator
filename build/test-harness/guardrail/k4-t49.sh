#!/usr/bin/env bash
# k4-t49.sh — T49: K4 re-run (disaggregated-KV poison -> kv-migrate-invalidate), now with the
# /v1/kv/invalidate route live on the leader (sidecar v3). T21 proved selection; stack 404'd.
# Oracles: (a) selection; (b) LOCAL invalidate REAL + MEASURABLE — plant a crafted prefix
# (repeat request = cache HIT), fire, repeat again = MISS, and the prefix-cache counters move;
# (c) handler note records the cross-worker deferred sentinel (peers declared via annotation);
# (d) pod UID unchanged. Honesty: "evicts planted cache state", NOT "cures the injection" —
# and MigrateRemote is code-deferred (never POSTs to peers) — the note says so, by design.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-t49; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "leader: $VPOD | controller: $OP" | tee "$OUT/target.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid} peers={.metadata.annotations.phorvex\.ai/disagg-kv-peers}{"\n"}' | tee "$OUT/uid-before.txt"
date -Is | tee "$OUT/start.txt"

say "0) F17 guard: leader pod age must clear antiOverRotationWindow (15m + 30s)"
while :; do
  BORN=$(kubectl get pod -n $NSV $VPOD -o jsonpath='{.metadata.creationTimestamp}')
  AGE=$(( $(date -u +%s) - $(date -u -d "$BORN" +%s) ))
  echo "leader age: ${AGE}s"
  [ $AGE -gt 930 ] && break
  sleep 20
done

kubectl port-forward -n $NSV svc/vllm 24151:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }

say "1) plant a crafted prefix: distinctive long prefix, sent TWICE (1st = MISS, 2nd = HIT)"
PREFIX="ZQX-K4-$(date +%s) The following is a stable system context block for the disaggregated serving rig. $(python3 -c "print(' '.join(['cachewarm']*220))")"
CHAT() { curl -s --max-time 120 http://127.0.0.1:24151/v1/chat/completions -H "Content-Type: application/json" \
  -d "{\"model\":\"Qwen/Qwen2.5-7B-Instruct-AWQ\",\"messages\":[{\"role\":\"user\",\"content\":\"$PREFIX --- Question: reply with the single word OK.\"}],\"max_tokens\":4,\"temperature\":0}"; }
CHAT -o /dev/null; echo "first send done (cold MISS)"
sleep 1
CHAT | head -c 150 > "$OUT/plant-hit.txt"; echo "second send done (expect HIT)" 
curl -s http://127.0.0.1:24151/metrics 2>/dev/null | grep -E "prefix_cache_(hits|queries) " | tee "$OUT/metrics-before.txt"

say "2) scope policy + fire KVPoisoning"
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","kv-migrate-invalidate"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
sleep 6
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
EV=redteam-k4-$(date +%s)
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

say "3) watch for kv-migrate-invalidate selection (up to 150s)"
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep "kv-migrate-invalidate" | tail -3)
  if [ -n "$L" ]; then FOUND=yes; echo "$L" | tee "$OUT/decision.txt"; break; fi
done
[ -z "$FOUND" ] && { echo "no kv-migrate-invalidate in 150s; tick tail:" | tee "$OUT/decision.txt"; kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV" | tail -5 | tee -a "$OUT/decision.txt"; }

say "4) effect oracle A: handler note (local invalidate + cross-worker deferred sentinel)"
kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep -i "kv-migrate-invalidate:" | tail -2 | tee "$OUT/note.txt"

say "5) effect oracle B: repeat the SAME planted request — HIT->MISS?"
sleep 2
CHAT | head -c 150 > "$OUT/repeat-after.txt"
curl -s http://127.0.0.1:24151/metrics 2>/dev/null | grep -E "prefix_cache_(hits|queries) " | tee "$OUT/metrics-after.txt"
echo "--- delta (expect: queries +1, hits UNCHANGED => the planted prefix was evicted) ---" | tee "$OUT/delta.txt"
paste "$OUT/metrics-before.txt" "$OUT/metrics-after.txt" | tee -a "$OUT/delta.txt"

say "6) pod unchanged + policy/event restored as-found"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid} phase={.status.phase} epoch={.metadata.annotations.phorvex\.ai/kv-migrate-epoch}{"\n"}' | tee "$OUT/uid-after.txt"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-restored.txt"
kubectl delete securityevent $EV --wait=false 2>/dev/null
kill $PF 2>/dev/null
date -Is | tee "$OUT/end.txt"
