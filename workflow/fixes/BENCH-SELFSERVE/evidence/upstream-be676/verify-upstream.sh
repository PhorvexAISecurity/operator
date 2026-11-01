#!/usr/bin/env bash
set -euo pipefail

mode="${1:---offline}"
case "$mode" in
  --offline)
    repo="$(git rev-parse --show-toplevel)"
    cd "$repo"
    evidence_dir="$repo/workflow/fixes/BENCH-SELFSERVE/evidence/upstream-be676"
    mkdir -p "$evidence_dir"
    python_bin="${PYTHON_BIN:?Set PYTHON_BIN to the exact current chart CI Python}"
    "$python_bin" -c 'import sys; assert sys.version_info[:3] == (3,12,15), sys.version'
    export PYTHONDONTWRITEBYTECODE=1
    run_suite() {
      "$python_bin" -c 'import sys,unittest; s=unittest.defaultTestLoader.discover(sys.argv[1],pattern=sys.argv[2]); r=unittest.TextTestRunner(verbosity=2).run(s); sys.exit(0 if r.wasSuccessful() and r.testsRun and not r.skipped else 1)' "$1" "$2"
    }
    {
      git rev-parse HEAD
      "$python_bin" --version
      run_suite tools test_stage_benchmark_capture.py
      run_suite benchmark/bot test_selfserve_requests.py
    } > "$evidence_dir/l1.txt" 2>&1
    {
      git rev-parse HEAD
      "$python_bin" --version
      run_suite benchmark/bot test_request_readiness.py
      run_suite benchmark/worker test_stage_reconcile.py
      run_suite benchmark/worker test_stage_observer_runtime.py
      run_suite benchmark/worker test_endpoint_refresh.py
      run_suite benchmark/bot test_job_lease.py
    } > "$evidence_dir/l2.txt" 2>&1
    echo 'PASS: deterministic capture/render invariants and real parser/PXMS/normalizer/reconciliation producer controls. Independent stage acceptance is separate.'
    ;;
  --live)
    echo 'Live verification belongs to bench-v3-lead under AUTHORIZATION.md; this worker script never mutates a cluster or sends Telegram messages.' >&2
    exit 2
    ;;
  *)
    echo "usage: $0 [--offline|--live]" >&2
    exit 2
    ;;
esac
