#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == *@* ]]; then
  echo "usage: $0 LOCAL_IMAGE_TAG" >&2
  exit 2
fi
tag=$1
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
  exit 2
fi

root=$(git rev-parse --show-toplevel)
docker buildx build \
  --file "$root/farm-fixtures/catalogue-workload/Dockerfile" \
  --platform linux/amd64 \
  --network none \
  --provenance=false \
  --sbom=false \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --load \
  --tag "$tag" \
  "$root"
docker image inspect --format '{{.Id}}' "$tag"
