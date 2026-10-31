#!/usr/bin/env bash
set -euo pipefail

mode="${1:---offline}"
case "$mode" in
  --offline)
    echo "Replace with deterministic build, test, invariant and fixture checks."
    exit 2
    ;;
  --live)
    echo "Live verification is not implemented. It must default to read-only and name its approval gate." >&2
    exit 2
    ;;
  *)
    echo "usage: $0 [--offline|--live]" >&2
    exit 2
    ;;
esac
