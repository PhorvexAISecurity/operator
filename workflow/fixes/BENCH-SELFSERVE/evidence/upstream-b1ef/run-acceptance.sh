#!/usr/bin/env bash
set -euo pipefail
cd /workspace/operator-benchmark-selfserve
export PATH=/workspace/.phorvex-tools/tar135/bin:/workspace/.phorvex-tools:$PATH
export HELM_BIN=/workspace/.phorvex-tools/helm
export PYTHON_BIN=/workspace/.phorvex-tools/python312/python/bin/python3.12
export TMPDIR=/workspace/.phorvex-test-tmp
exec bash workflow/fixes/BENCH-SELFSERVE/evidence/upstream-b1ef/verify-upstream.sh --offline
