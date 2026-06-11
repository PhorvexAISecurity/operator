#!/usr/bin/env bash
# Step 3 — deploy the stack with Helm (Phoenix CRDs+operator -> Phorvex CRD+operator
# -> dashboard, in dependency order; Helm installs CRDs before workloads).
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
_resolve_registry

CHART="$REPO_ROOT/deploy/helm/phorvex-stack"

echo "==> Vendoring subcharts (phoenix + phorvex)"
helm dependency build "$CHART"

# Point Phoenix at ECR only if we built it there; otherwise keep upstream ghcr image.
PHOENIX_ARGS=()
if [ "$BUILD_PHOENIX" = "true" ]; then
  PHOENIX_ARGS=(--set "phoenix.amtd.image.repository=$REGISTRY/$ECR_PHOENIX"
                --set "phoenix.amtd.image.tag=$PHOENIX_TAG")
fi

echo "==> helm upgrade --install $HELM_RELEASE -> ns/$K8S_NAMESPACE"
helm upgrade --install "$HELM_RELEASE" "$CHART" \
  --namespace "$K8S_NAMESPACE" --create-namespace \
  --set "global.registry=$REGISTRY" \
  --set "phorvex.phorvex.image.repository=$REGISTRY/$ECR_PHORVEX" \
  --set "phorvex.phorvex.image.tag=$PHORVEX_TAG" \
  --set "dashboard.image.repository=$REGISTRY/$ECR_CONSOLE" \
  --set "dashboard.image.tag=$CONSOLE_TAG" \
  "${PHOENIX_ARGS[@]}" \
  --wait --timeout 5m \
  "$@"   # pass-through extra --set flags (e.g. --set dashboard.service.type=LoadBalancer)

echo "==> Rollout status"
kubectl -n "$K8S_NAMESPACE" get pods,svc
echo
echo "==> CRDs:"
kubectl get crd | grep -E 'phorvex.ai|amtd.r6security.com' || true
echo
echo "==> Reach the dashboard:"
echo "    kubectl -n $K8S_NAMESPACE port-forward svc/${HELM_RELEASE}-console 8090:80"
echo "    open http://localhost:8090"
echo "==> Done. (Optional: ./04-integrators.sh for Falco/Prometheus signal sources.)"
