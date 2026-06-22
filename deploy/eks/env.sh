#!/usr/bin/env bash
# Shared configuration for the Phorvex EKS deploy scripts. Override any value by
# exporting it before sourcing, e.g.  AWS_REGION=us-west-2 ./01-create-cluster.sh
set -euo pipefail

# ── Cluster / region ─────────────────────────────────────────────────────────
export AWS_REGION="${AWS_REGION:-us-east-2}"
export CLUSTER_NAME="${CLUSTER_NAME:-phorvex}"
export K8S_NAMESPACE="${K8S_NAMESPACE:-phorvex-system}"
export HELM_RELEASE="${HELM_RELEASE:-phorvex}"

# ── Image tags ───────────────────────────────────────────────────────────────
export PHORVEX_TAG="${PHORVEX_TAG:-0.1.0}"
export CONSOLE_TAG="${CONSOLE_TAG:-0.1.0}"
export PHOENIX_TAG="${PHOENIX_TAG:-v0.2.3}"

# ── ECR repository names ─────────────────────────────────────────────────────
export ECR_PHORVEX="${ECR_PHORVEX:-phorvex}"
export ECR_CONSOLE="${ECR_CONSOLE:-phorvex-console}"
export ECR_PHOENIX="${ECR_PHOENIX:-phoenix-amtd-operator}"

# Build the extended Phoenix operator into ECR too? Default false => use upstream
# public ghcr.io/r6security/phoenix/amtd-operator (Phoenix is unmodified anyway).
export BUILD_PHOENIX="${BUILD_PHOENIX:-false}"

# ── Derived (account id + registry host) ─────────────────────────────────────
# Requires `aws` configured. Resolved lazily so `source env.sh` is cheap to re-run.
_resolve_registry() {
  : "${AWS_ACCOUNT_ID:=$(aws sts get-caller-identity --query Account --output text)}"
  export AWS_ACCOUNT_ID
  export REGISTRY="${REGISTRY:-${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com}"
}

# Repo root (this file lives in deploy/eks/).
export REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
