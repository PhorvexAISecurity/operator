#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 EXPECTED_40_CHARACTER_LOWERCASE_GIT_SHA" >&2
  exit 2
fi
expected=$1
root=$(git rev-parse --show-toplevel)
cd "$root"

head_sha=$(git rev-parse --verify HEAD)
if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ || "$head_sha" != "$expected" ]]; then
  echo "build checkout HEAD $head_sha does not equal reviewed SHA $expected" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  echo "refusing to build release images from a dirty checkout" >&2
  git status --short --untracked-files=normal >&2
  exit 1
fi
printf '%s\n' "$head_sha"
