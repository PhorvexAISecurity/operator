#!/usr/bin/env bash
# warmpool-t47.sh — T47: B2 re-run (denial-of-wallet flood -> request-drain), now with a REAL
# /v1/drain on the leader (sidecar v2). T14 proved selection; stock vLLM 404'd the drain.
# Oracles: (a) request-drain selected; (b) serving label flips to "drained"; (c) in-flight
# flood requests REALLY aborted (clients cut mid-stream); (d) pod UID unchanged (no restart).
# Honest: the serving label is the stop-admit CONTRACT — no svc on this rig selects it, so
# stop-admit is label-only; the stack abort is the real effect. Label + policy restored after.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-t47; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "leader: $VPOD | controller: $OP" | tee "$OUT/target.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid}{"\n"}' | tee "$OUT/uid-before.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='serving-label-before="{.metadata.labels.phorvex\.ai/serving}"{"\n"}' | tee -a "$OUT/target.txt"
date -Is | tee "$OUT/start.txt"

say "0) F17 guard: leader pod age must clear antiOverRotationWindow (15m + 30s)"
while :; do
  BORN=$(kubectl get pod -n $NSV $VPOD -o jsonpath='{.metadata.creationTimestamp}')
  AGE=$(( $(date -u +%s) - $(date -u -d "$BORN" +%s) ))
  echo "leader age: ${AGE}s"
  [ $AGE -gt 930 ] && break
  sleep 20
done

kubectl port-forward -n $NSV svc/vllm 24140:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }

say "1) baseline chat + start the flood (12 concurrent long requests, evidence per request)"
curl -s --max-time 60 http://127.0.0.1:24140/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 200 | tee "$OUT/baseline.txt"; echo
CURLPIDS=""
for i in $(seq 1 12); do
  ( curl -s --max-time 240 -w 'CURL_EXIT=%{http_code}/%{exitcode} t=%{time_total}s\n' -X POST http://127.0.0.1:24140/v1/completions -H 'Content-Type: application/json' \
    -d "{\"model\":\"Qwen/Qwen2.5-7B-Instruct-AWQ\",\"prompt\":\"Write a very long detailed essay about the history of computing, part $i.\",\"max_tokens\":512}" > "$OUT/flood-$i.txt" 2>&1 ) &
  CURLPIDS="$CURLPIDS $!"
done
echo "flood running (12 concurrent)..." | tee "$OUT/flood-start.txt"

say "2) scope policy + fire DenialOfWallet (flood is mid-flight)"
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","request-drain"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
sleep 6
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
EV=redteam-b2-$(date +%s)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $EV}
spec:
  rule: {type: DenialOfWallet, threatLevel: critical, source: redteam}
  targets: ["$NSV/$VPOD"]
  description: "B2: expensive-turn flood saturating the vLLM pod (denial-of-wallet)"
  anomalyScore: "0.9"
EOF

say "3) watch for request-drain selection (up to 150s)"
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep "request-drain" | tail -3)
  if [ -n "$L" ]; then FOUND=yes; echo "$L" | tee "$OUT/decision.txt"; break; fi
done
[ -z "$FOUND" ] && { echo "no request-drain in 150s; tick tail:" | tee "$OUT/decision.txt"; kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV" | tail -5 | tee -a "$OUT/decision.txt"; }

say "4) after: serving label (expect drained — success path KEEPS it; rollback re-admits), pod alive"
sleep 2
kubectl get pod -n $NSV $VPOD -o jsonpath='serving-label-after="{.metadata.labels.phorvex\.ai/serving}" uid={.metadata.uid} phase={.status.phase}{"\n"}' | tee "$OUT/after.txt"

say "5) flood evidence: how many requests were aborted mid-flight"
wait $CURLPIDS 2>/dev/null
ABORTED=0; DONE=0
for i in $(seq 1 12); do
  R=$(tail -1 "$OUT/flood-$i.txt" 2>/dev/null)
  echo "flood-$i: $R" | tee -a "$OUT/flood-results.txt"
  echo "$R" | grep -q "CURL_EXIT=200/0" && DONE=$((DONE+1)) || ABORTED=$((ABORTED+1))
done
echo "completed=$DONE aborted=$ABORTED" | tee -a "$OUT/flood-results.txt"
echo "--- sample aborted response ---" | tee -a "$OUT/flood-results.txt"
for i in $(seq 1 12); do grep -Lq "CURL_EXIT=200/0" "$OUT/flood-$i.txt" 2>/dev/null && { head -c 200 "$OUT/flood-$i.txt" | tee -a "$OUT/flood-results.txt"; break; }; done; echo

say "6) verify serving still works after the drain (re-entry not blocked — per design)"
curl -s --max-time 60 http://127.0.0.1:24140/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 200 | tee "$OUT/post-drain.txt"; echo

say "7) cleanup: serving label back to absent, policy as-found, event gone"
kubectl label pod -n $NSV $VPOD phorvex.ai/serving- 2>&1 | tee "$OUT/cleanup.txt"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee -a "$OUT/cleanup.txt"
kubectl delete securityevent $EV --wait=false 2>/dev/null
kill $PF 2>/dev/null
date -Is | tee "$OUT/end.txt"
