#!/usr/bin/env bash
set -euo pipefail

: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

if ! [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]]; then
  echo "::error::SOURCE_SHA is not a full Git object id"
  exit 1
fi

CHECKED_OUT_SHA="$(git rev-parse HEAD)"
if [ "$CHECKED_OUT_SHA" != "$SOURCE_SHA" ]; then
  echo "::error::The release checkout ($CHECKED_OUT_SHA) does not match the workflow source ($SOURCE_SHA)."
  exit 1
fi

# A self-hosted runner keeps its Git repository between jobs. Prune remote-deleted tags
# explicitly so a tag made by a failed atomic push cannot become the next run's version
# baseline. Fetch the branch and tags together before any AWS or ECR side effect.
git fetch --quiet --force --prune --prune-tags origin \
  '+refs/heads/main:refs/remotes/origin/main' \
  '+refs/tags/*:refs/tags/*'

REMOTE_SHA="$(git rev-parse refs/remotes/origin/main)"
echo "remote_sha=$REMOTE_SHA" >> "$GITHUB_OUTPUT"

if [ "$REMOTE_SHA" = "$SOURCE_SHA" ]; then
  echo "current=true" >> "$GITHUB_OUTPUT"
  echo "Release source is current at $SOURCE_SHA."
else
  echo "current=false" >> "$GITHUB_OUTPUT"
  echo "::notice::This deploy is superseded: main is $REMOTE_SHA, but the run built $SOURCE_SHA. No release will be published."
fi
