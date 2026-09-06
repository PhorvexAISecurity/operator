#!/usr/bin/env bash
# T1-A verifier — one command re-runs this fix's verification (FIX_LOOP §9). Offline always; live is K3's half.
# Exit non-zero on any failed assertion.
set -euo pipefail
cd "$(dirname "$0")/../../phorvex"
export GOTOOLCHAIN=local GOFLAGS=-mod=mod
echo "== code base: $(git rev-parse --short HEAD)  (fix authored against 016361c / v0.4.72)"
echo "== L0: build + the fix's own tests (lock a/c/d/e, record, trace) =="
go build ./...
go test ./internal/killchain/ -run 'TestLeakageGate|TestLeakageRecord|TestAIStageClassification' -v 2>&1 | grep -E '^(--- |ok|FAIL)'
go test ./internal/decision/ -run 'TestDecisionTraceRecordsLeakageWithHonestAbsence' -v 2>&1 | grep -E '^(--- |ok|FAIL)'
echo "== L1: the whole offline invariant suite, never scoped (FIX_LOOP §4 L1) =="
go test ./internal/killchain/ ./internal/decision/ ./internal/actionset/ ./internal/feasibility/ ./internal/platform/ ./internal/audit/ ./internal/model/
echo "== L3 (post-deploy, K3): see 05-evidence.md — not executed here =="
