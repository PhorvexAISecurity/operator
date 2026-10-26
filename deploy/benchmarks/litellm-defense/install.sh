#!/usr/bin/env bash
# Stand up the LiteLLM-defense benchmark on a single GPU VM:
#   1. K3s (single node), the NVIDIA device plugin, Helm and kube-prometheus-stack
#   2. operator-refactored (manager + in-process sensor/brain/actuator + console),
#      native backend, defending the `litellm` namespace with rotate
#   3. a LiteLLM proxy in front of a GPU-backed vLLM model, with steady request load
#
# It is idempotent: re-running reconciles. It installs nothing offensive — the attack in
# this benchmark is the product's own catalogue foothold signal, fired by benchmark.sh
# through the console API. See README.md.
#
# Run it ON the GPU VM (it needs the NVIDIA driver + Container Toolkit already present),
# from a checkout of operator-refactored:
#   sudo deploy/benchmarks/litellm-defense/install.sh
#
# Override with environment variables (defaults shown):
#   OPNS=phorvex-system RELEASE=bench MODEL=Qwen/Qwen2.5-0.5B-Instruct
#   ECR=753556437180.dkr.ecr.us-east-2.amazonaws.com AWS_REGION=us-east-2
#   MANAGER_TAG=0.11.1 CONSOLE_TAG=0.10.0
set -euo pipefail

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
MODEL="${MODEL:-Qwen/Qwen2.5-0.5B-Instruct}"
ECR="${ECR:-753556437180.dkr.ecr.us-east-2.amazonaws.com}"
AWS_REGION="${AWS_REGION:-us-east-2}"
MANAGER_TAG="${MANAGER_TAG:-0.11.1}"
CONSOLE_TAG="${CONSOLE_TAG:-0.10.0}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

say() { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

need curl
need aws

# ── 1. K3s ───────────────────────────────────────────────────────────────────
if ! command -v k3s >/dev/null 2>&1; then
  say "installing K3s (traefik disabled; local-path storage default)"
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -s -
fi
until k3s kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done
KUBECTL=(k3s kubectl)
"${KUBECTL[@]}" get nodes

# ── 2. GPU: RuntimeClass + device plugin ─────────────────────────────────────
say "NVIDIA runtime + device plugin"
if ! nvidia-smi >/dev/null 2>&1; then
  echo "WARN: nvidia-smi failed on this host; the vLLM pod will not schedule until a GPU driver is present." >&2
fi
"${KUBECTL[@]}" apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: nvidia}
handler: nvidia
YAML
"${KUBECTL[@]}" apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.17.0/deployments/static/nvidia-device-plugin.yml
# K3s auto-detects /usr/bin/nvidia-container-runtime and adds a `nvidia` containerd
# runtime; the device plugin must run under it to enumerate the GPU.
"${KUBECTL[@]}" -n kube-system patch daemonset nvidia-device-plugin-daemonset --type merge \
  -p '{"spec":{"template":{"spec":{"runtimeClassName":"nvidia"}}}}'
"${KUBECTL[@]}" -n kube-system rollout status ds/nvidia-device-plugin-daemonset --timeout=180s || true

# ── 3. Helm + kube-prometheus-stack ──────────────────────────────────────────
if ! command -v helm >/dev/null 2>&1; then
  say "installing Helm"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi
say "kube-prometheus-stack (Prometheus + the PodMonitor/PrometheusRule CRDs)"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update >/dev/null
helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --wait --timeout 10m

# ── 4. Namespaces + ECR pull secret ──────────────────────────────────────────
say "namespaces + ECR pull secret"
for ns in "$OPNS" litellm; do "${KUBECTL[@]}" create namespace "$ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -; done
ECR_PW="$(aws ecr get-login-password --region "$AWS_REGION")"
for ns in "$OPNS" litellm; do
  "${KUBECTL[@]}" -n "$ns" create secret docker-registry ecr \
    --docker-server="$ECR" --docker-username=AWS --docker-password="$ECR_PW" \
    --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -
done

# ── 5. operator image digests (pull by digest, like a release) ────────────────
digest() { aws ecr describe-images --region "$AWS_REGION" --repository-name "phorvex/$1" \
  --image-ids imageTag="$2" --query 'imageDetails[0].imageDigest' --output text; }
say "resolving ECR digests for manager:$MANAGER_TAG console:$CONSOLE_TAG"
MANAGER_DIGEST="$(digest manager "$MANAGER_TAG")"
CONSOLE_DIGEST="$(digest console "$CONSOLE_TAG")"
echo "    manager $MANAGER_DIGEST"
echo "    console $CONSOLE_DIGEST"

# ── 6. audit transport mTLS Secrets ──────────────────────────────────────────
say "audit mTLS Secrets"
NAMESPACE="$OPNS" SERVER_SECRET="${RELEASE}-audit-server" CLIENT_SECRET="${RELEASE}-audit-client" \
  SERVER_DNS="${RELEASE}-phorvex-audit-source.${OPNS}.svc" CLIENT_DNS="${RELEASE}-phorvex-console.${OPNS}.svc" \
  KUBECONFIG="$KUBECONFIG" bash "$REPO_ROOT/deploy/eks/provision-audit-mtls.sh"

# ── 7. the K3s OIDC issuer, for the console's bearer identity ─────────────────
ISSUER="$("${KUBECTL[@]}" get --raw /.well-known/openid-configuration | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')"
[ -n "$ISSUER" ] || { echo "could not read the K3s OIDC issuer" >&2; exit 1; }
# The console verifies tokens in-cluster against the API server's JWKS.
JWKS="https://kubernetes.default.svc/openid/v1/jwks"
say "console bearer identity verified against $ISSUER"
VALUES="$(mktemp)"; trap 'rm -f "$VALUES"' EXIT
sed "s#__K3S_ISSUER__#${ISSUER}#g" "$HERE/values/operator.yaml" > "$VALUES"

# ── 8. operator-refactored ────────────────────────────────────────────────────
say "operator-refactored (native, console on) into $OPNS"
helm upgrade --install "$RELEASE" "$CHART" --namespace "$OPNS" -f "$VALUES" \
  --set phorvex.image.repository="$ECR/phorvex/manager" \
  --set phorvex.image.tag="$MANAGER_TAG" \
  --set phorvex.image.releaseDigest="$MANAGER_DIGEST" \
  --set phorvex.console.image.repository="$ECR/phorvex/console" \
  --set phorvex.console.image.tag="$CONSOLE_TAG" \
  --set phorvex.console.image.releaseDigest="$CONSOLE_DIGEST" \
  --set-string phorvex.console.auth.oidc.issuer="$ISSUER" \
  --set-string phorvex.console.auth.oidc.jwksUrl="$JWKS" \
  --set 'imagePullSecrets[0].name=ecr' \
  --timeout 8m || true
# The manager chart renders no imagePullSecret; bind the ECR secret to the operator
# ServiceAccounts so their pods can pull the private images, then roll them.
for sa in "${RELEASE}-phorvex-manager" "${RELEASE}-phorvex-console"; do
  "${KUBECTL[@]}" -n "$OPNS" patch serviceaccount "$sa" -p '{"imagePullSecrets":[{"name":"ecr"}]}' || true
done
"${KUBECTL[@]}" -n "$OPNS" rollout restart deploy/"${RELEASE}-phorvex" deploy/"${RELEASE}-phorvex-console" || true
"${KUBECTL[@]}" -n "$OPNS" rollout status deploy/"${RELEASE}-phorvex" --timeout=5m || true
"${KUBECTL[@]}" -n "$OPNS" rollout status deploy/"${RELEASE}-phorvex-console" --timeout=5m || true

# ── 9. the LiteLLM target + policy ───────────────────────────────────────────
say "LiteLLM (model $MODEL) + policy into litellm"
sed "s#__MODEL__#${MODEL}#g" "$HERE/manifests/litellm.yaml" | "${KUBECTL[@]}" apply -f -
"${KUBECTL[@]}" apply -f "$HERE/manifests/policy.yaml"

say "waiting for LiteLLM (vLLM pulls the model on first start; this is slow)"
"${KUBECTL[@]}" -n litellm rollout status deploy/vllm --timeout=20m || true
"${KUBECTL[@]}" -n litellm rollout status deploy/litellm --timeout=5m || true

cat <<DONE

Installed. Check the policy is ticking and the fleet is measured:
  k3s kubectl -n $OPNS logs deploy/${RELEASE}-phorvex -c manager | grep '"msg":"tick"' | tail -3
Then run the benchmark:
  deploy/benchmarks/litellm-defense/benchmark.sh
DONE
