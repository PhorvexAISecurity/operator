#!/usr/bin/env bash
# Step 2 — build the images and push them to ECR.
#
# Builds (always): phorvex (operator), phorvex-console (dashboard).
# Builds (only if BUILD_PHOENIX=true): phoenix-amtd-operator from build/phoenix-extended.
#
# All builds use the REPO ROOT as context (the operator/console need the multi-module
# layout: phorvex/ + build/phoenix-extended/). Uses `docker buildx` for linux/amd64 so
# images run on standard EKS nodes even when you build on an Apple-silicon Mac.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
_resolve_registry

PLATFORM="${PLATFORM:-linux/amd64}"   # set linux/arm64 for Graviton nodegroups
echo "==> Registry=$REGISTRY  Platform=$PLATFORM"

ensure_repo() {
  local name="$1"
  aws ecr describe-repositories --repository-names "$name" --region "$AWS_REGION" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "$name" --region "$AWS_REGION" \
         --image-scanning-configuration scanOnPush=true >/dev/null
  echo "    ecr repo ready: $name"
}

echo "==> Ensuring ECR repositories"
ensure_repo "$ECR_PHORVEX"
ensure_repo "$ECR_CONSOLE"
[ "$BUILD_PHOENIX" = "true" ] && ensure_repo "$ECR_PHOENIX" || true

echo "==> Logging Docker into ECR"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# buildx builder (created once, reused).
docker buildx inspect phorvex-builder >/dev/null 2>&1 || docker buildx create --name phorvex-builder --use
docker buildx use phorvex-builder

build_push() {
  local dockerfile="$1" tag="$2"
  echo "==> Building + pushing $tag"
  docker buildx build \
    --platform "$PLATFORM" \
    -f "$REPO_ROOT/deploy/docker/$dockerfile" \
    -t "$tag" \
    --push \
    "$REPO_ROOT"
}

build_push operator.Dockerfile "$REGISTRY/$ECR_PHORVEX:$PHORVEX_TAG"
build_push console.Dockerfile  "$REGISTRY/$ECR_CONSOLE:$CONSOLE_TAG"

if [ "$BUILD_PHOENIX" = "true" ]; then
  echo "==> Building + pushing extended Phoenix operator"
  docker buildx build --platform "$PLATFORM" \
    -f "$REPO_ROOT/build/phoenix-extended/Dockerfile" \
    -t "$REGISTRY/$ECR_PHOENIX:$PHOENIX_TAG" \
    --push \
    "$REPO_ROOT/build/phoenix-extended"
fi

echo "==> Pushed:"
echo "    $REGISTRY/$ECR_PHORVEX:$PHORVEX_TAG"
echo "    $REGISTRY/$ECR_CONSOLE:$CONSOLE_TAG"
[ "$BUILD_PHOENIX" = "true" ] && echo "    $REGISTRY/$ECR_PHOENIX:$PHOENIX_TAG" || true
echo "==> Done. Next: ./03-deploy.sh"
