#!/usr/bin/env bash
# warmpool-t46.sh — T46: B5 GPU co-tenant eviction -> warm-swap, FULL E2E with a real warm pool.
# Proves: (a) warm-swap selected; (b) shadow promoted with ZERO cold-load on the serving path;
# (c) old leader's in-flight REALLY aborted by /v1/drain (sidecar v2); (d) old leader retired;
# (e) serving CONTINUES via the stand-in (degraded model id) while the 7B rewarms off-path.
# Honest notes: stand-in is a smaller model (T4 can't hold two 7Bs); handler's rewarm-to-N clone
# is a 7B spec that the card can't hold -> documented + cleaned. Policy/svc restored as-found.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-t46; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
SHADOW=$(kubectl get pods -n $NSV -l app=vllm-standin --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "leader: $VPOD | shadow: $SHADOW | controller: $OP" | tee "$OUT/target.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid}{"\n"}' | tee "$OUT/uid-before.txt"
date -Is | tee "$OUT/start.txt"

say "0) F17 wait: leader pod age must clear antiOverRotationWindow (15m + 30s)"
while :; do
  BORN=$(kubectl get pod -n $NSV $VPOD -o jsonpath='{.metadata.creationTimestamp}')
  AGE=$(( $(date -u +%s) - $(date -u -d "$BORN" +%s) ))
  echo "leader age: ${AGE}s"
  [ $AGE -gt 930 ] && break
  sleep 20
done

kubectl port-forward -n $NSV svc/vllm 24131:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }

say "1) baseline: chat via svc (7B), endpoints = leader only"
curl -s --max-time 60 http://127.0.0.1:24131/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 250 | tee "$OUT/baseline.txt"; echo
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' | tee -a "$OUT/baseline.txt"

say "2) start a LONG in-flight generation (background), then fire GPUEviction mid-stream"
( curl -s --max-time 240 -w '\nCURL_EXIT=%{http_code}/%{exitcode}\n' http://127.0.0.1:24131/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Count from 1 to 200, one number per line, no commentary."}],"max_tokens":600,"temperature":0}' > "$OUT/inflight.txt" 2>&1 ) &
INFLIGHT_PID=$!
sleep 4
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","warm-swap"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
sleep 6
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0 (in-flight started ~4s earlier)" | tee "$OUT/event.txt"
EV=redteam-b5-$(date +%s)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $EV}
spec:
  rule: {type: GPUEviction, threatLevel: critical, source: redteam}
  targets: ["$NSV/$VPOD"]
  description: "B5: hostile co-tenant pressure on the shared GPU — evict without cold-load"
  anomalyScore: "0.9"
EOF

say "3) watch for warm-swap selection + enactment (up to 150s)"
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep "warm-swap" | tail -3)
  if [ -n "$L" ]; then FOUND=yes; echo "$L" | tee "$OUT/decision.txt"; break; fi
done
[ -z "$FOUND" ] && { echo "no warm-swap in 150s; tick tail:" | tee "$OUT/decision.txt"; kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV" | tail -5 | tee -a "$OUT/decision.txt"; }

say "4) verify the cutover"
sleep 3
echo "--- roles ---" | tee "$OUT/cutover.txt"
kubectl get pods -n $NSV -L phorvex.ai/role -l phorvex.ai/swap-group=vllm-main 2>/dev/null | tee -a "$OUT/cutover.txt"
echo "--- old leader $VPOD (expect NotFound) ---" | tee -a "$OUT/cutover.txt"
kubectl get pod -n $NSV $VPOD 2>&1 | tee -a "$OUT/cutover.txt"
echo "--- endpoints now (expect shadow IP) ---" | tee -a "$OUT/cutover.txt"
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' | tee -a "$OUT/cutover.txt"

say "5) in-flight evidence (expect aborted: curl error / partial stream)"
wait $INFLIGHT_PID 2>/dev/null
tail -c 400 "$OUT/inflight.txt" | tee "$OUT/inflight-evidence.txt"; echo
wc -c "$OUT/inflight.txt" | tee -a "$OUT/inflight-evidence.txt"

say "6) serving CONTINUES via the stand-in (zero cold-start; degraded model id is the honest trade)"
curl -s --max-time 90 http://127.0.0.1:24131/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 300 | tee "$OUT/standin-serves.txt"; echo

say "7) restore: deployment recreates the 7B (role=leader) -> stand-in back to warm-shadow -> clean rewarm clone"
echo "--- rewarm clone (7B spec; expected to OOM on the full card — documented rig limit) ---" | tee "$OUT/restore.txt"
kubectl get pods -n $NSV -l app=vllm,phorvex.ai/role=warm-shadow 2>/dev/null | tee -a "$OUT/restore.txt"
echo "waiting for the recreated 7B leader (up to 8 min)..."
for i in $(seq 1 48); do
  NEW7B=$(kubectl get pods -n $NSV -l app=vllm,phorvex.ai/role=leader --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$NEW7B" ] && [ "$NEW7B" != "$VPOD" ] && kubectl get pod -n $NSV $NEW7B -o jsonpath='{.status.containerStatuses[*].ready}' | grep -q "true true" && { echo "new 7B Ready: $NEW7B" | tee -a "$OUT/restore.txt"; break; }
  sleep 10
done
kubectl label pod -n $NSV $SHADOW phorvex.ai/role=warm-shadow --overwrite | tee -a "$OUT/restore.txt"
kubectl delete pod -n $NSV -l app=vllm,phorvex.ai/role=warm-shadow --wait=false 2>/dev/null | tee -a "$OUT/restore.txt"
sleep 5
echo "--- endpoints after restore (expect new 7B only) ---" | tee -a "$OUT/restore.txt"
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' | tee -a "$OUT/restore.txt"
curl -s --max-time 90 http://127.0.0.1:24131/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 250 | tee -a "$OUT/restore.txt"; echo

say "8) restore policy as-found + delete event"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-restored.txt"
kubectl delete securityevent $EV --wait=false 2>/dev/null
kubectl get pods -n $NSV -L phorvex.ai/role | tee "$OUT/final-pods.txt"
kill $PF 2>/dev/null
date -Is | tee "$OUT/end.txt"
