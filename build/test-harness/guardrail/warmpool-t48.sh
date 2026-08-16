#!/usr/bin/env bash
# warmpool-t48.sh — T48: B4 re-run (model tamper/extraction -> model-shard-replace), now with a
# shard shadow: the stand-in carries phorvex.ai/model-shard=main (live-pod labels; no restart).
# Leader has NO parallel-group label -> single-pod warmCutover path (same mechanics as T46).
# Oracles: (a) model-shard-replace selected; (b) stand-in promoted zero cold-load; (c) old
# leader drained (real /v1/drain) + retired; (d) svc keeps answering via stand-in.
# F18-aware restore: relabel stand-in to warm-shadow PROMPTLY after the flip (do NOT wait for
# the Deployment's recreate to be Ready first — the reconciler would reap it), then wait.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-t48; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
SHADOW=$(kubectl get pods -n $NSV -l app=vllm-standin --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "leader: $VPOD | shadow: $SHADOW | controller: $OP" | tee "$OUT/target.txt"
date -Is | tee "$OUT/start.txt"

say "0) F17 guard on the leader"
while :; do
  BORN=$(kubectl get pod -n $NSV $VPOD -o jsonpath='{.metadata.creationTimestamp}')
  AGE=$(( $(date -u +%s) - $(date -u -d "$BORN" +%s) ))
  echo "leader age: ${AGE}s"
  [ $AGE -gt 930 ] && break
  sleep 20
done

say "1) wire the shard group on LIVE pods (no restart): model-shard=main on leader + shadow"
kubectl label pod -n $NSV $VPOD phorvex.ai/model-shard=main --overwrite | tee "$OUT/labels.txt"
kubectl label pod -n $NSV $SHADOW phorvex.ai/model-shard=main --overwrite | tee -a "$OUT/labels.txt"
kubectl get pods -n $NSV -L phorvex.ai/model-shard,phorvex.ai/role | tee -a "$OUT/labels.txt"

kubectl port-forward -n $NSV svc/vllm 24141:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }

say "2) baseline chat (7B) + in-flight long request (drain evidence), then fire ModelTampering"
curl -s --max-time 60 http://127.0.0.1:24141/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 200 | tee "$OUT/baseline.txt"; echo
( curl -s --max-time 240 -w '\nCURL_EXIT=%{http_code}/%{exitcode}\n' http://127.0.0.1:24141/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Count from 1 to 200, one number per line."}],"max_tokens":600,"temperature":0}' > "$OUT/inflight.txt" 2>&1 ) &
INFLIGHT_PID=$!
sleep 4
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","model-shard-replace"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
sleep 6
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
EV=redteam-b4-$(date +%s)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $EV}
spec:
  rule: {type: ModelTampering, threatLevel: critical, source: redteam}
  targets: ["$NSV/$VPOD"]
  description: "B4/G2: served-model weight tamper indicated by fingerprint drift — replace the shard cleanly"
  anomalyScore: "0.9"
EOF

say "3) watch for model-shard-replace selection (up to 150s)"
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep "model-shard-replace" | tail -3)
  if [ -n "$L" ]; then FOUND=yes; echo "$L" | tee "$OUT/decision.txt"; break; fi
done
[ -z "$FOUND" ] && { echo "no model-shard-replace in 150s; tick tail:" | tee "$OUT/decision.txt"; kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV" | tail -5 | tee -a "$OUT/decision.txt"; }

say "4) verify the cutover"
sleep 3
kubectl get pods -n $NSV -L phorvex.ai/role -l phorvex.ai/model-shard=main 2>/dev/null | tee "$OUT/cutover.txt"
echo "--- old leader $VPOD (expect NotFound) ---" | tee -a "$OUT/cutover.txt"
kubectl get pod -n $NSV $VPOD 2>&1 | tee -a "$OUT/cutover.txt"

say "5) in-flight drain evidence"
wait $INFLIGHT_PID 2>/dev/null
tail -c 300 "$OUT/inflight.txt" | tee "$OUT/inflight-evidence.txt"; echo

say "6) F18-aware restore: shadow back to warm-shadow NOW (end the double-leader before the Deployment's recreate gets reaped)"
kubectl label pod -n $NSV $SHADOW phorvex.ai/role=warm-shadow --overwrite | tee "$OUT/restore.txt"
kubectl delete pod -n $NSV -l app=vllm,phorvex.ai/role=warm-shadow --wait=false 2>/dev/null | tee -a "$OUT/restore.txt"
echo "waiting for the recreated 7B leader (single leader now — no fight; up to 8 min)..."
for i in $(seq 1 48); do
  NEW7B=$(kubectl get pods -n $NSV -l app=vllm,phorvex.ai/role=leader --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$NEW7B" ] && [ "$NEW7B" != "$VPOD" ] && [ "$(kubectl get pod -n $NSV $NEW7B -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null)" = "true true" ] && { echo "new 7B Ready: $NEW7B" | tee -a "$OUT/restore.txt"; break; }
  sleep 10
done
sleep 3
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' 2>/dev/null | tee -a "$OUT/restore.txt"
curl -s --max-time 90 http://127.0.0.1:24141/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 200 | tee -a "$OUT/restore.txt"; echo

say "7) persist the shard labels in BOTH templates (maintenance roll; svc is briefly empty while the 7B boots — bridging would re-trigger the F18 fight, so we accept the quiet-hours gap)"
kubectl patch deploy -n $NSV vllm --type strategic -p '{"spec":{"template":{"metadata":{"labels":{"phorvex.ai/model-shard":"main"}}}}}'
kubectl rollout status deploy -n $NSV vllm --timeout=600s
kubectl patch deploy -n $NSV vllm-standin --type strategic -p '{"spec":{"template":{"metadata":{"labels":{"phorvex.ai/model-shard":"main"}}}}}'
kubectl rollout status deploy -n $NSV vllm-standin --timeout=300s
sleep 3
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' 2>/dev/null | tee -a "$OUT/restore.txt"
kubectl get pods -n $NSV -L phorvex.ai/role,phorvex.ai/model-shard | tee "$OUT/final-pods.txt"

say "8) restore policy as-found + delete event"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-restored.txt"
kubectl delete securityevent $EV --wait=false 2>/dev/null
kill $PF 2>/dev/null
date -Is | tee "$OUT/end.txt"
