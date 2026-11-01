#!/usr/bin/env bash
set -euo pipefail
cd /workspace/operator-benchmark-selfserve
export PATH=/workspace/.phorvex-go/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.linux-amd64/bin:/workspace/.phorvex-tools/tar135/bin:/workspace/.phorvex-tools:/workspace/.phorvex-tools/python312/python/bin:$PATH
export GO_BIN=/workspace/.phorvex-go/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.linux-amd64/bin/go
export GOTOOLCHAIN=local
export HELM_BIN=/workspace/.phorvex-tools/helm
export PREFLIGHT_PYTHON_3_11=/workspace/.phorvex-tools/python311/python/bin/python3.11
export PREFLIGHT_PYTHON_3_12=/workspace/.phorvex-tools/python312/python/bin/python3.12
export TMPDIR=/workspace/.phorvex-test-tmp
export GOCACHE=/workspace/.phorvex-go/capture-cache
export GOPATH=/workspace/.phorvex-go/gopath
export GOMAXPROCS=2
export KUBECONFIG=/dev/null
export KUBEBUILDER_ASSETS=
export USE_EXISTING_CLUSTER=false
exec /workspace/.phorvex-tools/python311/python/bin/python3.11 workflow/tools/workflow.py preflight BENCH-SELFSERVE --run --python /workspace/.phorvex-tools/python311/python/bin/python3.11 --helm /workspace/.phorvex-tools/helm --timeout 3600 --output evidence/upstream-be676/preflight/receipt.json
