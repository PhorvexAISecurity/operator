#!/usr/bin/env bash
set -euo pipefail

mode="${1:---offline}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo"
go_bin="${GO_BIN:-go}"

invariants() {
  "$go_bin" -C phorvex test -mod=readonly -count=1 -timeout=15m -v \
    ./internal/actionset ./internal/decision \
    -run 'TestPreparation|TestStudyPreparation|TestStudyRealContainment|TestStudyNegativePricedGain|TestStudyPreservesRealResource'
}

integration() {
  "$go_bin" -C phorvex test -mod=readonly -count=1 -timeout=15m -v \
    ./internal/mathlab ./internal/brainclient ./cmd/brain-replay \
    -run 'TestEndpointStudy|TestRecorderProcessIdentity|TestRecorderRejectsUnproven|TestOptionalCostCapture|TestBaselineReplayReproduces|TestRemoteSnapshotRelay|TestSnapshotRelay|TestSnapshotClient|TestEndpointCLI|TestStudyJSON|TestReplayIdentity'
}

case "$mode" in
  --offline)
    invariants
    integration
    ;;
  --invariants) invariants ;;
  --integration) integration ;;
  --live)
    echo "Live checks belong to the independent lead under AUTHORIZATION.md; use the source-bound deployment and campaign evidence. This script performs no cluster action." >&2
    exit 2
    ;;
  *)
    echo "usage: $0 [--offline|--invariants|--integration|--live]" >&2
    exit 2
    ;;
esac
