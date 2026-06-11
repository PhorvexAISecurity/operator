#!/usr/bin/env bash
# Step 1 — create (or reuse) the EKS cluster and point kubectl at it.
# Idempotent: skips creation if the cluster already exists.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

echo "==> Region=$AWS_REGION  Cluster=$CLUSTER_NAME"

if eksctl get cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "==> Cluster '$CLUSTER_NAME' already exists — reusing."
else
  echo "==> Creating cluster (this takes ~15-20 min)..."
  # Substitute placeholders in cluster.yaml and feed to eksctl.
  CLUSTER_NAME="$CLUSTER_NAME" AWS_REGION="$AWS_REGION" \
    envsubst < cluster.yaml | eksctl create cluster -f -
fi

echo "==> Updating kubeconfig"
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"

echo "==> Current context:"
kubectl config current-context
kubectl get nodes
echo "==> Done. Next: ./02-ecr-build-push.sh"
