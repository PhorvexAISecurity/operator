# PHORVEXSEC-58 — ThreatPosture targeting decision report

Date: 2026-08-12  
Branch: `fix/phvx-58-threat-posture-claim`

## Decision

**Option B: keep `ctxprov.ThreatPosture` audit-only in the default P1 engine and
correct the targeting claims.**

The ticket's conclusion that event severity does not reach P1 targeting was too
broad. The derived `ThreatPosture` scalar is copied only into the decision record,
but the raw `SecurityEvent` severity already enters `killchain.Assess` as
`eventAlpha`. That changes P(hold), stage urgency, recon-fact weights, and greedy
selection. Wiring the derived scalar into P1 gain would count the same event twice
and would add an uncalibrated coefficient to the consequence-weighted coverage
objective.

## Implemented

- Added `P-THREAT-POSTURE-DECISION.md` to record Option B and the precise boundary.
- Corrected the default provider comments: five signals are recorded, but not all
  five are independent P1 targeting multipliers.
- Corrected `sensed.go`, `README.md`, `P0-REPORT.md`, and
  `P-CONTEXT-DECISION.md`; none now claims the derived posture scalar boosts P1
  targeting.
- Preserved `ThreatPosture` in decision/audit output for operator explanation.

## Proof

`TestEventSeverityDrivesP1WithoutThreatPostureScalar` puts a low-severity asset
first and a critical-severity asset second under a one-move budget while forcing
both posture scalars to zero. The critical asset wins through the kill-chain path.

`TestThreatPostureScalarIsAuditOnlyInP1` changes only the derived scalar and proves
that it does not independently reweight P1 selection.

```text
go build ./...                                                        PASS
go test -count=1 ./internal/decision -run 'Test(EventSeverityDrivesP1WithoutThreatPostureScalar|ThreatPostureScalarIsAuditOnlyInP1)' PASS
go test -count=1 -skip TestScenariosExport ./internal/...             PASS
```

The unfiltered internal suite still invokes `TestScenariosExport`, a benchmark
artifact generator that defaults to writing
`internal/decision/bin/scenarios-instances.jsonl`; that directory is absent on
main. Its failure is pre-existing and unrelated to this change.

## Result

Raw event severity drives P1 exactly once through the kill-chain assessment. The
derived posture scalar remains visible for audit without silently changing the
optimizer's calibrated objective.
