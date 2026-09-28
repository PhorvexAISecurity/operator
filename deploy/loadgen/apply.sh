#!/usr/bin/env bash
# Deploy (or update) phorvex-loadgen.
#
# The generator source is mounted from a ConfigMap built here from loadgen.py, so loadgen.py
# stays the single source of truth — no image build, matching how crm and mcp-server ship.
# The pod is rolled by stamping a hash of the code onto the pod template, so an edit to
# loadgen.py actually takes effect instead of sitting in a stale ConfigMap mount.
#
# Usage:
#   ./apply.sh                 apply namespace, code, workload, and the ServiceMonitor
#   ./apply.sh --no-monitor    skip the ServiceMonitor (clusters without the Prometheus CRDs)
set -euo pipefail

cd "$(dirname "$0")"
NS=phorvex-loadgen
WITH_MONITOR=1
[[ "${1:-}" == "--no-monitor" ]] && WITH_MONITOR=0

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }

echo "==> namespace + workload"
kubectl apply -f loadgen.yaml

# vLLM enforces an API key. Mirror ONLY the client credential (`api-key`) into this namespace;
# `admin-bearer` and the TLS private key in that Secret stay where they are. Without this the
# generator gets a 401 on every vLLM request and produces pure error traffic.
echo "==> vLLM client credential"
if kubectl get secret vllm-control -n vllm >/dev/null 2>&1; then
  VLLM_API_KEY=$(kubectl get secret vllm-control -n vllm -o jsonpath='{.data.api-key}' | base64 -d)
  kubectl create secret generic loadgen-vllm -n "$NS" \
    --from-literal=api-key="$VLLM_API_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
else
  echo "    WARN: vllm/vllm-control not found; vLLM traffic will be unauthenticated (401s)"
fi

echo "==> code ConfigMap from loadgen.py"
kubectl create configmap loadgen-code -n "$NS" \
  --from-file=loadgen.py=loadgen.py \
  --dry-run=client -o yaml | kubectl apply -f -

CODE_HASH=$(sha256sum loadgen.py | cut -c1-16)
echo "==> rolling pod for code hash $CODE_HASH"
kubectl patch deployment loadgen -n "$NS" --type=merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"phorvex.ai/code-hash\":\"$CODE_HASH\"}}}}}"

if [[ "$WITH_MONITOR" == 1 ]]; then
  if kubectl get crd servicemonitors.monitoring.coreos.com >/dev/null 2>&1; then
    echo "==> ServiceMonitor"
    kubectl apply -f servicemonitor.yaml
  else
    echo "==> ServiceMonitor skipped (monitoring.coreos.com CRDs not installed)"
  fi
fi

echo "==> waiting for rollout"
kubectl rollout status deployment/loadgen -n "$NS" --timeout=300s

echo
kubectl get pods -n "$NS" -o wide
echo
echo "logs:    kubectl logs -n $NS deploy/loadgen -f"
echo "metrics: kubectl exec -n $NS deploy/loadgen -- python -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:9090/metrics').read().decode())\""
echo "pause:   kubectl scale deployment/loadgen -n $NS --replicas=0"
