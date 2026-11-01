#!/usr/bin/env bash
set -euo pipefail
cd /workspace/operator-benchmark-stage
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
bash workflow/fixes/BENCH-STAGE/verify.sh --invariants > workflow/fixes/BENCH-STAGE/evidence/final-source/l1.txt 2>&1
bash workflow/fixes/BENCH-STAGE/verify.sh --integration > workflow/fixes/BENCH-STAGE/evidence/final-source/l2.txt 2>&1
