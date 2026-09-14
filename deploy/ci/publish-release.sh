#!/usr/bin/env bash
set -euo pipefail

: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${V:?V is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

VALUES_FILE="deploy/helm/phorvex-stack/values-eks.yaml"

if ! [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]]; then
  echo "::error::SOURCE_SHA is not a full Git object id"
  exit 1
fi
if ! [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::V is not a semantic release version"
  exit 1
fi
if [ "$(git rev-parse HEAD)" != "$SOURCE_SHA" ]; then
  echo "::error::The release checkout moved away from workflow source $SOURCE_SHA before publication."
  exit 1
fi

echo "released=false" >> "$GITHUB_OUTPUT"

git config user.name "phorvex-ci[bot]"
git config user.email "ci@phorvex.ai"
git add "$VALUES_FILE"
if git diff --cached --quiet -- "$VALUES_FILE"; then
  echo "::error::$VALUES_FILE has no staged release change."
  exit 1
fi

# [skip ci] stops the version commit from recursively versioning itself.
git commit -m "release: v$V [skip ci]" \
  -m "Deployed by ArgoCD from deploy/helm/phorvex-stack/values-eks.yaml."
git tag -a "v$V" -m "v$V"

# The commit and tag must land together. If another run moved main after the freshness
# check, this push fails safely. That is a superseded run, not a broken deployment.
if git push --atomic origin HEAD:main "v$V"; then
  echo "released=true" >> "$GITHUB_OUTPUT"
  exit 0
else
  PUSH_STATUS=$?
fi

# Never leave the rejected tag in a persistent self-hosted checkout. The next job also
# prunes tags before computing a version, providing a second boundary against residue.
git tag -d "v$V" >/dev/null 2>&1 || true

if ! git fetch --quiet --force --no-tags origin \
  '+refs/heads/main:refs/remotes/origin/main'; then
  echo "::error::The release push failed, and main could not be refreshed to determine whether this run was superseded."
  exit "$PUSH_STATUS"
fi
REMOTE_SHA="$(git rev-parse refs/remotes/origin/main)"
if [ "$REMOTE_SHA" != "$SOURCE_SHA" ]; then
  echo "::notice::Release v$V was superseded because main advanced from $SOURCE_SHA to $REMOTE_SHA. Rollout and E2E are skipped."
  exit 0
fi

echo "::error::Atomic release push failed while main still points to $SOURCE_SHA."
exit "$PUSH_STATUS"
