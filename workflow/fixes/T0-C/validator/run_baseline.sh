#!/usr/bin/env bash
# Runs the validator on the two 0.4.74 baseline records and writes
# report-baseline-0.4.74.md (+ .json) next to this script.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXES="$(cd "$HERE/../.." && pwd)"
RECORDS=(
  "$FIXES/T1-A/evidence/live/02-vllm-decision-record-0.4.74.json"
  "$FIXES/T0-C/evidence/live-baseline/01-selected-record-rotate-voice-0.4.73.json"
)
python3 "$HERE/audit_trace_validator.py" "${RECORDS[@]}" \
  --report "$HERE/report-baseline-0.4.74.md" \
  --json "$HERE/report-baseline-0.4.74.json" "$@"
