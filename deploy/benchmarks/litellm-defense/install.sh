#!/usr/bin/env bash
# Stand up the LiteLLM-defense benchmark on a single GPU VPS, portably:
#   1. preflight: distro deps, the AWS CLI + credentials, the NVIDIA driver, and the
#      NVIDIA Container Toolkit (installed if missing) so K3s/containerd can see the GPU
#   2. K3s (single node), the NVIDIA device plugin, Helm and kube-prometheus-stack
#   3. operator-refactored (manager + in-process sensor/brain/actuator + console),
#      native backend, defending the `litellm` namespace with rotate
#   4. a LiteLLM proxy in front of a GPU-backed vLLM model (tensor-parallel across the
#      VM's GPUs), with steady request load
#
# It installs nothing offensive — the attack in this benchmark is the product's own
# catalogue foothold signal, fired by benchmark.sh through the console API. See README.md.
#
# Run it ON the GPU VM, as root or via sudo, from a checkout of operator-refactored:
#   sudo deploy/benchmarks/litellm-defense/install.sh
#
# Prerequisites it does NOT install (they need a reboot / are host-specific):
#   - a working NVIDIA driver (`nvidia-smi` succeeds)
# It DOES install, if missing: curl/tar/unzip/gpg, the AWS CLI v2, the NVIDIA Container
# Toolkit, K3s, Helm.
#
# Override with environment variables (defaults shown):
#   OPNS=phorvex-system RELEASE=bench
#   GPUS=1 TENSOR_PARALLEL=$GPUS MODEL=Qwen/Qwen2.5-0.5B-Instruct
#   VLLM_IMAGE=vllm/vllm-openai:v0.6.3.post1 MODEL_MAX_LEN=4096 GPU_MEM_UTIL=0.6 DTYPE=half
#   ECR=753556437180.dkr.ecr.us-east-2.amazonaws.com AWS_REGION=us-east-2
#   MANAGER_TAG=0.11.1 CONSOLE_TAG=0.10.0 HF_TOKEN=            (for gated models)
#
# Example, two A100s serving a 7B model tensor-parallel:
#   sudo GPUS=2 MODEL=Qwen/Qwen2.5-7B-Instruct GPU_MEM_UTIL=0.9 \
#     deploy/benchmarks/litellm-defense/install.sh
set -euo pipefail
export PATH="/usr/local/bin:/usr/local/sbin:$PATH"

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
GPUS="${GPUS:-1}"
TENSOR_PARALLEL="${TENSOR_PARALLEL:-$GPUS}"
MODEL="${MODEL:-Qwen/Qwen2.5-0.5B-Instruct}"
VLLM_IMAGE="${VLLM_IMAGE:-vllm/vllm-openai:v0.6.3.post1}"
MODEL_MAX_LEN="${MODEL_MAX_LEN:-4096}"
GPU_MEM_UTIL="${GPU_MEM_UTIL:-0.6}"
DTYPE="${DTYPE:-half}"   # float16 works on T4 (compute 7.5) and A100; use auto/bfloat16 on A100 if preferred
ECR="${ECR:-753556437180.dkr.ecr.us-east-2.amazonaws.com}"
AWS_REGION="${AWS_REGION:-us-east-2}"
MANAGER_TAG="${MANAGER_TAG:-0.11.1}"
CONSOLE_TAG="${CONSOLE_TAG:-0.10.0}"
HF_TOKEN="${HF_TOKEN:-}"
ECR_PASSWORD="${ECR_PASSWORD:-}"       # set with the two digests below => no AWS CLI/creds on this host
MANAGER_DIGEST="${MANAGER_DIGEST:-}"   # sha256:...  (resolve off-host to keep AWS creds off the VM)
CONSOLE_DIGEST="${CONSOLE_DIGEST:-}"   # sha256:...

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
say() { printf '\n==> %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── 0. preflight: distro, base tools, AWS, GPU driver, container toolkit ──────
say "preflight"
. /etc/os-release 2>/dev/null || true
if command -v apt-get >/dev/null 2>&1; then PKG=apt; elif command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum; else die "no supported package manager (apt/dnf/yum)"; fi
pkg_install() { case "$PKG" in apt) $SUDO apt-get update -qq && $SUDO apt-get install -y "$@";; *) $SUDO "$PKG" install -y "$@";; esac; }

for b in curl tar gzip; do command -v "$b" >/dev/null 2>&1 || pkg_install "$b"; done
command -v gpg >/dev/null 2>&1 || pkg_install gnupg || true
command -v python3 >/dev/null 2>&1 || pkg_install python3 || die "python3 is required for the reports"

# ECR access: either this host has AWS credentials, or the caller pre-supplies the ECR login
# password AND both image digests (ECR_PASSWORD/MANAGER_DIGEST/CONSOLE_DIGEST) — resolved on a
# host that does have credentials — in which case no AWS credentials are needed here at all.
if [ -n "$ECR_PASSWORD" ] && [ -n "$MANAGER_DIGEST" ] && [ -n "$CONSOLE_DIGEST" ]; then
  say "using pre-supplied ECR credentials and image digests (no AWS CLI needed on this host)"
else
  if ! command -v aws >/dev/null 2>&1; then
    say "installing the AWS CLI v2"
    command -v unzip >/dev/null 2>&1 || pkg_install unzip
    tmpz="$(mktemp -d)"; curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "$tmpz/aws.zip"
    unzip -q -o "$tmpz/aws.zip" -d "$tmpz"; $SUDO "$tmpz/aws/install" --update; rm -rf "$tmpz"
  fi
  aws sts get-caller-identity >/dev/null 2>&1 || die "the AWS CLI cannot authenticate; configure credentials able to pull from $ECR (env AWS_ACCESS_KEY_ID/SECRET, ~/.aws, an instance profile), or pass ECR_PASSWORD + MANAGER_DIGEST + CONSOLE_DIGEST resolved off-host"
fi

nvidia-smi >/dev/null 2>&1 || die "nvidia-smi failed — install the NVIDIA GPU driver for this host first (distro-specific, needs a reboot), then re-run"
DRIVER="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)"
GPU_NAME="$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
DETECTED_GPUS="$(nvidia-smi --query-gpu=name --format=csv,noheader | grep -c .)"
say "GPU: $GPU_NAME x$DETECTED_GPUS, driver $DRIVER (requesting GPUS=$GPUS, tensor-parallel=$TENSOR_PARALLEL)"
[ "$DETECTED_GPUS" -ge "$GPUS" ] || die "asked for $GPUS GPU(s) but only $DETECTED_GPUS present"
[ "${DRIVER%%.*}" -ge 525 ] 2>/dev/null || echo "WARN: driver $DRIVER may be too old for $VLLM_IMAGE (needs a recent CUDA driver); override VLLM_IMAGE if vLLM fails to start." >&2

# NVIDIA Container Toolkit: K3s auto-detects /usr/bin/nvidia-container-runtime, so install
# the toolkit BEFORE K3s starts.
if ! command -v nvidia-container-runtime >/dev/null 2>&1; then
  say "installing the NVIDIA Container Toolkit"
  if [ "$PKG" = apt ]; then
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | $SUDO gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      | $SUDO tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null
    $SUDO apt-get update -qq && $SUDO apt-get install -y nvidia-container-toolkit
  else
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | $SUDO tee /etc/yum.repos.d/nvidia-container-toolkit.repo >/dev/null
    $SUDO "$PKG" install -y nvidia-container-toolkit
  fi
fi
command -v nvidia-container-runtime >/dev/null 2>&1 || die "NVIDIA Container Toolkit install did not provide nvidia-container-runtime"

# ── 1. K3s ───────────────────────────────────────────────────────────────────
if ! command -v k3s >/dev/null 2>&1; then
  say "installing K3s (traefik disabled; local-path storage default)"
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -s -
else
  $SUDO systemctl restart k3s   # pick up the toolkit if K3s predates it
fi
until $SUDO k3s kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done
KUBECTL=($SUDO k3s kubectl)
"${KUBECTL[@]}" get nodes
# K3s writes the nvidia runtime into its containerd config when the binary is present.
CONTAINERD_CFG=/var/lib/rancher/k3s/agent/etc/containerd/config.toml
$SUDO grep -q 'runtimes.nvidia' "$CONTAINERD_CFG" 2>/dev/null \
  || echo "WARN: K3s did not auto-add the nvidia containerd runtime; the device plugin may not advertise the GPU." >&2

# ── 2. GPU: RuntimeClass + device plugin (under the nvidia runtime) ───────────
say "NVIDIA RuntimeClass + device plugin"
"${KUBECTL[@]}" apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: nvidia}
handler: nvidia
YAML
"${KUBECTL[@]}" apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.17.0/deployments/static/nvidia-device-plugin.yml
# The plugin must run under the nvidia runtime to enumerate the GPU.
"${KUBECTL[@]}" -n kube-system patch daemonset nvidia-device-plugin-daemonset --type merge \
  -p '{"spec":{"template":{"spec":{"runtimeClassName":"nvidia"}}}}'
"${KUBECTL[@]}" -n kube-system rollout status ds/nvidia-device-plugin-daemonset --timeout=180s || true
for _ in $(seq 1 24); do
  [ -n "$("${KUBECTL[@]}" get node -o jsonpath='{.items[0].status.allocatable.nvidia\.com/gpu}')" ] && break; sleep 5
done
ADV="$("${KUBECTL[@]}" get node -o jsonpath='{.items[0].status.allocatable.nvidia\.com/gpu}')"
say "node advertises nvidia.com/gpu = ${ADV:-<none>}"
[ -n "$ADV" ] || die "no GPU advertised; check the driver and the NVIDIA Container Toolkit"

# ── 3. Helm + kube-prometheus-stack ──────────────────────────────────────────
if ! command -v helm >/dev/null 2>&1; then
  say "installing Helm"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | $SUDO bash
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

# ── 4. Namespaces + ECR pull secret + HF token ───────────────────────────────
say "namespaces + ECR pull secret"
for ns in "$OPNS" litellm; do "${KUBECTL[@]}" create namespace "$ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -; done
ECR_PW="${ECR_PASSWORD:-$(aws ecr get-login-password --region "$AWS_REGION")}"
for ns in "$OPNS" litellm; do
  "${KUBECTL[@]}" -n "$ns" create secret docker-registry ecr \
    --docker-server="$ECR" --docker-username=AWS --docker-password="$ECR_PW" \
    --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -
done
"${KUBECTL[@]}" -n litellm create secret generic hf-token --from-literal=token="$HF_TOKEN" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -

# ── 4b. AMTD CRDs + the benchmark's red-team identity ─────────────────────────
# The operator watches SecurityEvents (and the rest of the AMTD API) and the chart's
# creator-identity ValidatingAdmissionPolicy binds to the SecurityEvent resource, but the
# chart does not ship these CRDs — install them before the operator starts. redteam-rbac
# creates the bench-redteam ServiceAccount that benchmark.sh fires the foothold as.
say "AMTD CRDs + red-team identity"
# Server-side apply, one file at a time: these CRD schemas are large and the client-side
# last-applied annotation would exceed the 256KB metadata limit (warminferencesets). The
# glob also matches only the real manifests, not any stray editor/archive sidecar files.
for crd in "$REPO_ROOT"/build/phoenix-extended/config/crd/bases/amtd.r6security.com_*.yaml; do
  "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$crd"
done
"${KUBECTL[@]}" apply -f "$HERE/manifests/redteam-rbac.yaml"

# ── 5. operator image digests (pull by digest, like a release) ────────────────
digest() { aws ecr describe-images --region "$AWS_REGION" --repository-name "phorvex/$1" \
  --image-ids imageTag="$2" --query 'imageDetails[0].imageDigest' --output text; }
say "resolving ECR digests for manager:$MANAGER_TAG console:$CONSOLE_TAG"
MANAGER_DIGEST="${MANAGER_DIGEST:-$(digest manager "$MANAGER_TAG")}"
CONSOLE_DIGEST="${CONSOLE_DIGEST:-$(digest console "$CONSOLE_TAG")}"
echo "    manager $MANAGER_DIGEST"
echo "    console $CONSOLE_DIGEST"

# ── 6. audit transport mTLS Secrets ──────────────────────────────────────────
say "audit mTLS Secrets"
NAMESPACE="$OPNS" SERVER_SECRET="${RELEASE}-audit-server" CLIENT_SECRET="${RELEASE}-audit-client" \
  SERVER_DNS="${RELEASE}-phorvex-audit-source.${OPNS}.svc" CLIENT_DNS="${RELEASE}-phorvex-console.${OPNS}.svc" \
  KUBECONFIG="$KUBECONFIG" ${SUDO:+$SUDO -E} bash "$REPO_ROOT/deploy/eks/provision-audit-mtls.sh"

# ── 7. the K3s OIDC issuer, for the console's bearer identity ─────────────────
ISSUER="$("${KUBECTL[@]}" get --raw /.well-known/openid-configuration | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')"
[ -n "$ISSUER" ] || die "could not read the K3s OIDC issuer"
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
say "LiteLLM (model $MODEL, $GPUS GPU(s), TP=$TENSOR_PARALLEL) + policy into litellm"
sed -e "s#__MODEL__#${MODEL}#g" -e "s#__VLLM_IMAGE__#${VLLM_IMAGE}#g" \
    -e "s#__GPUS__#${GPUS}#g" -e "s#__TP__#${TENSOR_PARALLEL}#g" \
    -e "s#__MAX_LEN__#${MODEL_MAX_LEN}#g" -e "s#__GPU_MEM_UTIL__#${GPU_MEM_UTIL}#g" -e "s#__DTYPE__#${DTYPE}#g" \
    "$HERE/manifests/litellm.yaml" | "${KUBECTL[@]}" apply -f -
"${KUBECTL[@]}" apply -f "$HERE/manifests/policy.yaml"

say "waiting for LiteLLM (vLLM pulls the model on first start; this is slow)"
"${KUBECTL[@]}" -n litellm rollout status deploy/vllm --timeout=30m || true
"${KUBECTL[@]}" -n litellm rollout status deploy/litellm --timeout=5m || true

cat <<DONE

Installed. Check the policy is ticking and the fleet is measured:
  ${SUDO:+sudo }k3s kubectl -n $OPNS logs deploy/${RELEASE}-phorvex -c manager | grep '"msg":"tick"' | tail -3
Then run the benchmark:
  deploy/benchmarks/litellm-defense/benchmark.sh
DONE
