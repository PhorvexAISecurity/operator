#!/usr/bin/env bash
# One-time setup: create the GitHub OIDC provider + IAM role for CI.
# Run this once from any machine with admin AWS credentials.
# After running, copy the printed role ARN into GitHub → Settings → Secrets → AWS_ROLE_ARN.
set -euo pipefail

ACCOUNT_ID="753556437180"
REGION="us-east-2"
ROLE_NAME="github-actions-phorvex"
POLICY_NAME="github-actions-phorvex-ecr"
OIDC_PROVIDER="token.actions.githubusercontent.com"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Creating GitHub OIDC identity provider (idempotent)"
aws iam create-open-id-connect-provider \
  --url "https://${OIDC_PROVIDER}" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" \
  --region "$REGION" 2>/dev/null \
  || echo "    OIDC provider already exists — skipping"

echo "==> Creating IAM role: ${ROLE_NAME}"
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document "file://${DIR}/iam-oidc-trust.json" \
  --description "Assumed by GitHub Actions CI for ECR push (PhorvexSecurity/operator)" \
  2>/dev/null || echo "    Role already exists — skipping"

echo "==> Attaching inline ECR policy"
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$POLICY_NAME" \
  --policy-document "file://${DIR}/iam-ecr-policy.json"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "==> Done. Add this as the AWS_ROLE_ARN secret in GitHub:"
echo "    ${ROLE_ARN}"
echo ""
echo "    GitHub → Settings → Secrets and variables → Actions → New repository secret"
echo "    Name:  AWS_ROLE_ARN"
echo "    Value: ${ROLE_ARN}"
