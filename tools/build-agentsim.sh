#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == *@* ]]; then
  echo "usage: $0 LOCAL_IMAGE_TAG" >&2
  exit 2
fi
tag=$1

root=$(git rev-parse --show-toplevel)
docker buildx build \
  --file "$root/farm-fixtures/agentsim/Dockerfile" \
  --platform linux/amd64 \
  --network none \
  --provenance=false \
  --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --load \
  --tag "$tag" \
  "$root"
docker image inspect --format '{{.Id}}' "$tag"
