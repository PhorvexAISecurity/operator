#!/usr/bin/env bash
set -euo pipefail
# Run from this worktree. Keep baseline source isolated from the implementation.
: "${GO_BIN:?set GO_BIN to the Go executable}"
: "${TMPDIR:?set TMPDIR to an executable writable temporary directory}"
baseline=1c23931621d47218ded424b58e4db127344fb33b
baseline_dir="$(mktemp -d "$TMPDIR/bench-v3-baseline.XXXXXX")"
git archive "$baseline" | tar -x -C "$baseline_dir"
cp phorvex/internal/ingest/workload_spec_producer_test.go "$baseline_dir/phorvex/internal/ingest/"
"$GO_BIN" test -C "$baseline_dir/phorvex" ./internal/ingest -run '^TestWorkloadSpecRealProducerCounterexample$' -count=1 -v
