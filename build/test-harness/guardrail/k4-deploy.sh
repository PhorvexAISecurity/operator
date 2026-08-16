#!/usr/bin/env bash
# k4-deploy.sh — the K4 fixture: sidecar v3 (/v1/kv/invalidate -> real prefix-cache reset) +
# the disagg-kv-peers annotation on the leader template. ONE rollout does both (ConfigMap code
# is read at sidecar boot). MigrateRemote stays code-deferred [PENDING] — the note records it.
set -uo pipefail
NSV=vllm
OUT=/tmp/px-k4deploy; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
date -Is | tee "$OUT/start.txt"

say "0) backup deployment"
kubectl get deploy -n $NSV vllm -o yaml > "$OUT/vllm-deploy.backup3.yaml"
wc -l "$OUT/vllm-deploy.backup3.yaml"

say "1) sidecar v3 into the ConfigMap"
kubectl -n $NSV create configmap guardrail-proxy --from-file=guardrail_proxy.py=/tmp/guardrail_proxy.py --dry-run=client -o yaml | kubectl apply -f -

say "2) leader template += disagg-kv-peers annotation (stand-in IP as the declared P/D peer) — rolls the 7B once"
SHADOWIP=$(kubectl get pod -n $NSV -l app=vllm-standin -o jsonpath='{.items[0].status.podIP}')
echo "peer to declare: $SHADOWIP:8000" | tee "$OUT/peer.txt"
kubectl patch deploy -n $NSV vllm --type strategic -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"phorvex.ai/disagg-kv-peers\":\"$SHADOWIP:8000\"}}}}}"
kubectl rollout status deploy -n $NSV vllm --timeout=600s
NEWPOD=$(kubectl get pods -n $NSV -l app=vllm --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
echo "new leader: $NEWPOD"
kubectl get pod -n $NSV $NEWPOD -o jsonpath='peers={.metadata.annotations.phorvex\.ai/disagg-kv-peers} born={.metadata.creationTimestamp}{"\n"}' | tee -a "$OUT/peer.txt"

say "3) smoke: /v1/kv/invalidate via svc (expect {\"invalidated\":true}) + chat still fine"
kubectl port-forward -n $NSV svc/vllm 24150:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }
curl -s --max-time 15 -X POST http://127.0.0.1:24150/v1/kv/invalidate -H "Content-Type: application/json" -d '{"local":true}' | tee "$OUT/smoke.txt"; echo
curl -s --max-time 90 http://127.0.0.1:24150/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 200 | tee -a "$OUT/smoke.txt"; echo
kill $PF 2>/dev/null
date -Is | tee "$OUT/end.txt"
