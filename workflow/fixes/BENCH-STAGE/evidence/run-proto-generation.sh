#!/usr/bin/env bash
set -euo pipefail
cd /workspace/operator-benchmark-stage
export PATH=/workspace/.phorvex-go/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.linux-amd64/bin:$PATH
export GOTOOLCHAIN=local GOPATH=/workspace/.phorvex-go/gopath GOCACHE=/workspace/.phorvex-go/capture-cache TMPDIR=/workspace/.phorvex-test-tmp GOMAXPROCS=2
exec bash tools/generate-proto.sh
