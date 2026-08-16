#!/usr/bin/env bash
# warmpool-deploy.sh — build the warm pool for warm-swap (B5) + upgrade the sidecar with /v1/drain.
# 1) sidecar v2 (drain) into the ConfigMap (7B picks it up on the template-label rollout below)
# 2) Ollama stand-in (qwen2.5:0.5b, CPU node, :8000) as the warm shadow — the honest degraded
#    failover tier (the T4 can't hold two 7Bs; zero GPU risk)
# 3) vllm deployment template += swap-group/role=leader labels (rolls the 7B, ~2.5 min)
# 4) svc/vllm selector -> phorvex.ai/role=leader (AFTER the new pod is Ready with the label)
set -uo pipefail
NSV=vllm
OUT=/tmp/px-warmpool; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
date -Is | tee "$OUT/start.txt"

say "0) backup deployment + service"
kubectl get deploy -n $NSV vllm -o yaml > "$OUT/vllm-deploy.backup2.yaml"
kubectl get svc -n $NSV vllm -o yaml > "$OUT/vllm-svc.backup.yaml"
wc -l "$OUT/vllm-deploy.backup2.yaml" "$OUT/vllm-svc.backup.yaml"

say "1) sidecar v2 (with /v1/drain) into the ConfigMap"
kubectl -n $NSV create configmap guardrail-proxy --from-file=guardrail_proxy.py=/tmp/guardrail_proxy.py --dry-run=client -o yaml | kubectl apply -f -

say "2) deploy the warm shadow (Ollama qwen2.5:0.5b, CPU, :8000)"
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-standin
  namespace: vllm
spec:
  replicas: 1
  selector:
    matchLabels: {app: vllm-standin}
  template:
    metadata:
      labels:
        app: vllm-standin
        phorvex.ai/swap-group: vllm-main
        phorvex.ai/role: warm-shadow
        phorvex.ai/model-loaded: "true"
      annotations:
        phorvex.ai/serving-port: "8000"
        phorvex.ai/health-path: "/"
        phorvex.ai/model-id: "qwen2.5:0.5b"
    spec:
      tolerations: [{operator: Exists}]  # all 5 nodes are tainted on this cluster
      containers:
      - name: ollama
        image: ollama/ollama:latest
        env: [{name: OLLAMA_HOST, value: "0.0.0.0:8000"}]
        command: [sh, -c]
        args:
        - |
          ollama serve &
          sleep 3
          ollama pull qwen2.5:0.5b
          wait
        ports: [{containerPort: 8000}]
        resources:
          requests: {cpu: 500m, memory: 1Gi}
          limits: {cpu: 2, memory: 2Gi}
        startupProbe:
          httpGet: {path: "/", port: 8000}
          periodSeconds: 10
          failureThreshold: 60
        readinessProbe:
          exec:
            command: [sh, -c, "ollama list | grep -q 'qwen2.5:0.5b'"]
          periodSeconds: 10
          failureThreshold: 3
EOF
echo "waiting for shadow Ready (image pull + model pull, up to 8 min)..."
kubectl wait --for=condition=ready pod -n $NSV -l app=vllm-standin --timeout=480s && echo SHADOW READY || { echo "SHADOW NOT READY — diagnose:"; kubectl describe pod -n $NSV -l app=vllm-standin | tail -20; exit 1; }

say "3) leader template += swap-group/role=leader (rolls the 7B — also picks up sidecar v2)"
kubectl patch deploy -n $NSV vllm --type strategic -p '{"spec":{"template":{"metadata":{"labels":{"phorvex.ai/swap-group":"vllm-main","phorvex.ai/role":"leader"}}}}}'
kubectl rollout status deploy -n $NSV vllm --timeout=600s
NEWPOD=$(kubectl get pods -n $NSV -l app=vllm --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
echo "new leader pod: $NEWPOD"
kubectl get pod -n $NSV $NEWPOD -o jsonpath='labels: role={.metadata.labels.phorvex\.ai/role} swap-group={.metadata.labels.phorvex\.ai/swap-group}{"\n"}'
kubectl get pod -n $NSV $NEWPOD -o jsonpath='{.metadata.creationTimestamp}{"\n"}' | tee "$OUT/leader-born.txt"

say "4) svc/vllm selector -> phorvex.ai/role=leader (verify endpoints stay non-empty)"
kubectl patch svc -n $NSV vllm --type merge -p '{"spec":{"selector":{"phorvex.ai/role":"leader"}}}'
sleep 3
kubectl get endpoints -n $NSV vllm -o jsonpath='{.subsets[*].addresses[*].ip}{"\n"}' | tee "$OUT/endpoints.txt"
grep -q "172\." "$OUT/endpoints.txt" || { echo "ENDPOINTS EMPTY — rolling svc back"; kubectl replace -f "$OUT/vllm-svc.backup.yaml"; exit 1; }

say "5) smoke: chat via svc (7B), drain route exists, shadow answers directly"
kubectl port-forward -n $NSV svc/vllm 24130:8000 >$OUT/pf.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4; grep -q "Forwarding from" $OUT/pf.log || { echo "PF FAILED"; exit 1; }
echo "--- chat via svc (expect 7B) ---" | tee "$OUT/smoke.txt"
curl -s --max-time 60 http://127.0.0.1:24130/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen2.5-7B-Instruct-AWQ","messages":[{"role":"user","content":"Say the word PARIS and nothing else."}],"max_tokens":8}' | head -c 300 | tee -a "$OUT/smoke.txt"; echo
echo "--- drain route on the leader (expect {\"aborted\":0}) ---" | tee -a "$OUT/smoke.txt"
curl -s --max-time 10 -X POST http://127.0.0.1:24130/v1/drain -H "Content-Type: application/json" -d '{"abort_inflight":true}' | tee -a "$OUT/smoke.txt"; echo
kill $PF 2>/dev/null
SHADOWIP=$(kubectl get pod -n $NSV -l app=vllm-standin -o jsonpath='{.items[0].status.podIP}')
echo "--- shadow direct /v1/models (expect qwen2.5:0.5b) ---" | tee -a "$OUT/smoke.txt"
kubectl run curl-standin-$RANDOM -n $NSV --rm -i --restart=Never --image=curlimages/curl:8.10.1 --timeout=120s --quiet \
  -- curl -s --max-time 20 http://$SHADOWIP:8000/v1/models 2>/dev/null | head -c 300 | tee -a "$OUT/smoke.txt"; echo
date -Is | tee "$OUT/end.txt"
