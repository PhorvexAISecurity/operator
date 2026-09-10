#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../phorvex"
output_dir=${1:-config/rbac/generated-native}
mkdir -p "$output_dir"
GOMAXPROCS=${GOMAXPROCS:-2} go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 \
  rbac:roleName=phorvex-native-marker-contract paths=./internal/actuator \
  output:rbac:artifacts:config="$output_dir"
