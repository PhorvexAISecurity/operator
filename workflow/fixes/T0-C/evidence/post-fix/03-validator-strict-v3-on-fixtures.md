# Phorvex audit decision-record validation

- records: **9**  pass: **9**  fail: **0**  undecidable: **0**
- laws derived from `internal/model/decision_trace.go`, `internal/decision/coverage.go`, `internal/model/types.go` (see README.md)

## Per-record

| decisionID | tenant/pod | trace | brainImage tag | selectedAction | status | checks failed/undecidable |
|---|---|---|---|---|---|---|
| `dc9b5f317d5a` | t/v3-status | v3 | sha-test | quarantine | PASS | - |
| `45fd938b19a7` | t/v3-round-a | v3 | sha-test | quarantine | PASS | - |
| `d542d8f93af1` | t/v3-round-b | v3 | sha-test | quarantine | PASS | - |
| `53bcef602a86` | t/v3-round-c | v3 | sha-test | noop | PASS | - |
| `30e40bce571c` | t/v3-gpu | v3 | sha-test | quarantine | PASS | - |
| `7ab23562f1e8` | t/v3-nan | v3 | sha-test | noop | PASS | - |
| `91d21621b212` | t/v3-reactive | v3 | sha-test | noop | PASS | - |
| `6fc605c56e44` | t/v3-slo | v3 | sha-test | noop | PASS | - |
| `60c0ac9587ce` | t/v3-b0 | v3 | sha-test | noop | PASS | - |

## Check matrix

| decisionID | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `dc9b5f317d5a` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `45fd938b19a7` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `d542d8f93af1` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `53bcef602a86` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `30e40bce571c` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `7ab23562f1e8` | PASS | PASS | PASS | PASS | SKIPPED | SKIPPED | PASS | PASS | PASS | PASS | PASS | PASS |
| `91d21621b212` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `6fc605c56e44` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `60c0ac9587ce` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

## All check messages

### `dc9b5f317d5a390b5e41f9447c823776` — t/v3-status

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (43 present, 41 absent)
- 4. selection-reference: **PASS** — selectedAction='quarantine', key='ns/v3-status|quarantine'
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 4 identity(ies) reconstruct
- 7. selection-reconstruction: **PASS** — argmax 'ns/v3-status|quarantine' netGain=3.5784999397374144 (unique); budget=1, movesSpent=1 -> 'quarantine' as recorded
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='exact_binding_no_update'
- 11. redaction: **PASS** — 591 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `45fd938b19a7e47aaa7f92549a02699a` — t/v3-round-a

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (43 present, 41 absent)
- 4. selection-reference: **PASS** — selectedAction='quarantine', key='ns/v3-round-a|quarantine'
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 4 identity(ies) reconstruct
- 7. selection-reconstruction: **PASS** — argmax 'ns/v3-round-a|quarantine' netGain=3.5784999397374144 (unique); budget=2, movesSpent=2 -> 'quarantine' as recorded
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='binding_positive_update'
- 11. redaction: **PASS** — 591 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `d542d8f93af13efcf2c526b64fbebe6a` — t/v3-round-b

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (43 present, 41 absent)
- 4. selection-reference: **PASS** — selectedAction='quarantine', key='ns/v3-round-b|quarantine'
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 4 identity(ies) reconstruct
- 7. selection-reconstruction: **PASS** — argmax 'ns/v3-round-b|quarantine' netGain=3.5784999397374144 (unique); budget=2, movesSpent=2 -> 'quarantine' as recorded
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='binding_positive_update'
- 11. redaction: **PASS** — 591 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `53bcef602a86d6638871d9c23d8b60da` — t/v3-round-c

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (39 present, 45 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 4 identity(ies) reconstruct
- 7. selection-reconstruction: **PASS** — argmax 'ns/v3-round-c|quarantine' netGain=3.5784999397374144 (unique); budget=2, movesSpent=2 -> 'noop' as recorded
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='binding_positive_update'
- 11. redaction: **PASS** — 591 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `30e40bce571cb50e4bf919f9d07dbbc8` — t/v3-gpu

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (44 present, 40 absent)
- 4. selection-reference: **PASS** — selectedAction='quarantine', key='ns/v3-gpu|quarantine'
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 4 identity(ies) reconstruct
- 7. selection-reconstruction: **PASS** — argmax 'ns/v3-gpu|quarantine' netGain=3.571416606404081 (unique); budget=1, movesSpent=1 -> 'quarantine' as recorded
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='exact_binding_no_update'
- 11. redaction: **PASS** — 592 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `7ab23562f1e868b14bbf86c1a0c03188` — t/v3-nan

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (19 present, 65 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **SKIPPED** — no candidate has cNorm, cFlow and expectedCost all present: decisionTrace.candidates[0]: absent cNorm, cFlow, expectedCost; decisionTrace.candidates[1]: absent cNorm, cFlow, expectedCost
- 6. netgain-law: **SKIPPED** — no candidate carries the terms: decisionTrace.candidates[0]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[1]: absent marginalCoverage, lambdaContribution, netGain
- 7. selection-reconstruction: **PASS** — no feasible candidate generated (2 generator exclusion(s)) -> noop; noopReason='unactionable due to NaN: telemetry.connCount'
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='nonbinding_decay'
- 11. redaction: **PASS** — 583 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `91d21621b2121cd36e2b9dd652fee662` — t/v3-reactive

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (35 present, 49 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 2 identity(ies) reconstruct; netGain skipped on 2: decisionTrace.candidates[0]: absent marginalCoverage, netGain; decisionTrace.candidates[1]: absent marginalCoverage, netGain
- 7. selection-reconstruction: **PASS** — reactive-only gate: 2 generated candidate(s) skipped before scoring -> noop; noopReason consistent
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='nonbinding_decay'
- 11. redaction: **PASS** — 577 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `6fc605c56e4431abd3f6440c0f147b5f` — t/v3-slo

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (35 present, 49 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 2 identity(ies) reconstruct; netGain skipped on 2: decisionTrace.candidates[0]: absent marginalCoverage, netGain; decisionTrace.candidates[1]: absent marginalCoverage, netGain
- 7. selection-reconstruction: **PASS** — no feasible candidate generated (2 generator exclusion(s)) -> noop; noopReason='conformal-slo: worst-case cost 0.92 > ceiling 0.00'
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='nonbinding_decay'
- 11. redaction: **PASS** — 583 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

### `60c0ac9587cea067cc9f7aab23108816` — t/v3-b0

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v3
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 84 optionals well-formed (35 present, 49 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **PASS** — 2 candidate(s) reconstruct
- 6. netgain-law: **PASS** — 2 identity(ies) reconstruct; netGain skipped on 2: decisionTrace.candidates[0]: absent marginalCoverage, netGain; decisionTrace.candidates[1]: absent marginalCoverage, netGain
- 7. selection-reconstruction: **PASS** — budget=0 <= 0: greedy never ran, noop forced (selectionReasons ['move_budget_exhausted'])
- 8. ordering: **PASS** — 5 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 5 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='budget_nonpositive_no_update'
- 11. redaction: **PASS** — 591 strings scanned, no secret-shaped content
- 12. v3-hooks: **PASS** — actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold

## Field presence census

| field | present | absent | records lacking key |
|---|---:|---:|---:|
| `decisionTrace.candidates[].cFlow` | 16 | 2 | - |
| `decisionTrace.candidates[].cNorm` | 16 | 2 | - |
| `decisionTrace.candidates[].conformalCalibrated` | 8 | 10 | - |
| `decisionTrace.candidates[].conformalQuantile` | 8 | 10 | - |
| `decisionTrace.candidates[].costHigh` | 16 | 2 | - |
| `decisionTrace.candidates[].expectedCost` | 16 | 2 | - |
| `decisionTrace.candidates[].feasible` | 18 | 0 | - |
| `decisionTrace.candidates[].gpuEnvelopeApplied` | 16 | 2 | - |
| `decisionTrace.candidates[].gpuEnvelopeSlack` | 1 | 17 | - |
| `decisionTrace.candidates[].grossFullValue` | 18 | 0 | - |
| `decisionTrace.candidates[].lambdaContribution` | 16 | 2 | - |
| `decisionTrace.candidates[].marginalCoverage` | 10 | 8 | - |
| `decisionTrace.candidates[].netGain` | 10 | 8 | - |
| `decisionTrace.candidates[].provenance` | 18 | 0 | - |
| `decisionTrace.candidates[].selectionRound` | 4 | 14 | - |
| `decisionTrace.candidates[].sloGateResult` | 16 | 2 | - |
| `decisionTrace.facts[].assetValue` | 45 | 0 | - |
| `decisionTrace.facts[].coveredRound` | 8 | 37 | - |
| `decisionTrace.facts[].dispersionContribution` | 0 | 45 | - |
| `decisionTrace.facts[].pHoldContribution` | 0 | 45 | - |
| `decisionTrace.facts[].relativeWeight` | 0 | 45 | - |
| `decisionTrace.facts[].urgencyContribution` | 0 | 45 | - |
| `decisionTrace.inputs.betaMean` | 9 | 0 | 0 |
| `decisionTrace.inputs.coResidency` | 0 | 9 | 0 |
| `decisionTrace.inputs.connectionCount` | 0 | 9 | 0 |
| `decisionTrace.inputs.cvss` | 0 | 9 | 0 |
| `decisionTrace.inputs.dispersionCap` | 0 | 9 | 0 |
| `decisionTrace.inputs.dispersionMult` | 0 | 9 | 0 |
| `decisionTrace.inputs.epss` | 0 | 9 | 0 |
| `decisionTrace.inputs.exposureSeconds` | 9 | 0 | 0 |
| `decisionTrace.inputs.gpuUtilization` | 0 | 9 | 0 |
| `decisionTrace.inputs.imageRarity` | 0 | 9 | 0 |
| `decisionTrace.inputs.leakage` | 0 | 9 | 0 |
| `decisionTrace.inputs.modelRarity` | 0 | 9 | 0 |
| `decisionTrace.inputs.pHold` | 9 | 0 | 0 |
| `decisionTrace.inputs.projectedNextStageSec` | 9 | 0 | 0 |
| `decisionTrace.inputs.requestRate` | 0 | 9 | 0 |
| `decisionTrace.inputs.sloHeadroom` | 9 | 0 | 0 |
| `decisionTrace.inputs.smOccupancy` | 0 | 9 | 0 |
| `decisionTrace.inputs.stageHazard` | 9 | 0 | 0 |
| `decisionTrace.inputs.stageUrgency` | 9 | 0 | 0 |
| `decisionTrace.inputs.threatPosture` | 9 | 0 | 0 |
| `decisionTrace.inputs.vramFraction` | 0 | 9 | 0 |
| `decisionTrace.selectionRound` | 4 | 5 | 0 |
