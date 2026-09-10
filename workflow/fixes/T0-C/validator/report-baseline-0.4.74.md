# Phorvex audit decision-record validation

- records: **2**  pass: **2**  fail: **0**  undecidable: **0**
- laws derived from `internal/model/decision_trace.go`, `internal/decision/coverage.go`, `internal/model/types.go` (see README.md)

## Per-record

| decisionID | tenant/pod | trace | brainImage tag | selectedAction | status | checks failed/undecidable |
|---|---|---|---|---|---|---|
| `253c43da2ddd` | vllm/vllm-77997646c9-nhzv4 | v2 | 0.4.74 | noop | PASS | - |
| `a69f5a97617a` | voice/voice-bot-79d7f9464d-hdwlg | v2 | 0.4.73 | rotate | PASS | - |

## Check matrix

| decisionID | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `253c43da2ddd` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `a69f5a97617a` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |

## All check messages

### `253c43da2dddc93e618eed25fa23878b` — vllm/vllm-77997646c9-nhzv4

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v2
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 650 optionals well-formed (146 present, 504 absent)
- 4. selection-reference: **PASS** — selectedAction='noop', no selected candidate
- 5. ecost-law: **PASS** — 1 candidate(s) reconstruct; skipped 1: decisionTrace.candidates[0]: absent cNorm, cFlow, expectedCost
- 6. netgain-law: **PASS** — 1 identity(ies) reconstruct; netGain skipped on 2: decisionTrace.candidates[0]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[1]: absent marginalCoverage, netGain
- 7. selection-reconstruction: **PASS** — reactive-only gate: 1 generated candidate(s) skipped before scoring -> noop; noopReason consistent
- 8. ordering: **PASS** — 122 facts sorted; 2 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 4 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='min_clamp'
- 11. redaction: **PASS** — 3075 strings scanned, no secret-shaped content
- 12. v3-hooks: **SKIPPED** — trace is v2; v3 laws (actionStatus/costHigh/coveredBefore/dispatch) not applicable

### `a69f5a97617ae66f97e0fc1c94221ef7` — voice/voice-bot-79d7f9464d-hdwlg

- 1. schema: **PASS** — envelope phorvex.audit.v2; trace phorvex.decision-trace.v2
- 2. identity: **PASS** — all six identity fields non-empty
- 3. presence-flags: **PASS** — 669 optionals well-formed (149 present, 520 absent)
- 4. selection-reference: **PASS** — selectedAction='rotate', key='voice/voice-bot-79d7f9464d-hdwlg|rotate'
- 5. ecost-law: **PASS** — 1 candidate(s) reconstruct; skipped 5: decisionTrace.candidates[1]: absent cNorm, cFlow, expectedCost; decisionTrace.candidates[2]: absent cNorm, cFlow, expectedCost; decisionTrace.candidates[3]: absent cNorm, cFlow, expectedCost; decisionTrace.candidates[4]: absent cNorm, cFlow, expectedCost; decisionTrace.candidates[5]: absent cNorm, cFlow, expectedCost
- 6. netgain-law: **PASS** — 2 identity(ies) reconstruct; netGain skipped on 5: decisionTrace.candidates[1]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[2]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[3]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[4]: absent marginalCoverage, lambdaContribution, netGain; decisionTrace.candidates[5]: absent marginalCoverage, lambdaContribution, netGain
- 7. selection-reconstruction: **PASS** — argmax 'voice/voice-bot-79d7f9464d-hdwlg|rotate' netGain=11.946470871982712 (unique); budget=1, movesSpent=1 -> 'rotate' as recorded
- 8. ordering: **PASS** — 118 facts sorted; 6 candidates in canonical order; coverKeys sorted
- 9. cover-keys-resolve: **PASS** — 3 cover key(s) all resolve to facts[].factKey
- 10. dual-update: **PASS** — demand/spent/budget/rawExcess/lambdaBefore agree; updateReason='exact_binding_no_update'
- 11. redaction: **PASS** — 3164 strings scanned, no secret-shaped content
- 12. v3-hooks: **SKIPPED** — trace is v2; v3 laws (actionStatus/costHigh/coveredBefore/dispatch) not applicable

## Field presence census

| field | present | absent | records lacking key |
|---|---:|---:|---:|
| `decisionTrace.candidates[].cFlow` | 2 | 6 | - |
| `decisionTrace.candidates[].cNorm` | 2 | 6 | - |
| `decisionTrace.candidates[].costHigh` | 2 | 6 | - |
| `decisionTrace.candidates[].expectedCost` | 2 | 6 | - |
| `decisionTrace.candidates[].feasible` | 3 | 5 | - |
| `decisionTrace.candidates[].grossFullValue` | 8 | 0 | - |
| `decisionTrace.candidates[].lambdaContribution` | 2 | 6 | - |
| `decisionTrace.candidates[].marginalCoverage` | 1 | 7 | - |
| `decisionTrace.candidates[].netGain` | 1 | 7 | - |
| `decisionTrace.candidates[].provenance` | 8 | 0 | - |
| `decisionTrace.facts[].assetValue` | 240 | 0 | - |
| `decisionTrace.facts[].dispersionContribution` | 0 | 240 | - |
| `decisionTrace.facts[].pHoldContribution` | 0 | 240 | - |
| `decisionTrace.facts[].relativeWeight` | 0 | 240 | - |
| `decisionTrace.facts[].urgencyContribution` | 0 | 240 | - |
| `decisionTrace.inputs.betaMean` | 2 | 0 | 0 |
| `decisionTrace.inputs.coResidency` | 2 | 0 | 0 |
| `decisionTrace.inputs.connectionCount` | 2 | 0 | 0 |
| `decisionTrace.inputs.cvss` | 0 | 2 | 0 |
| `decisionTrace.inputs.dispersionCap` | 0 | 2 | 0 |
| `decisionTrace.inputs.dispersionMult` | 2 | 0 | 0 |
| `decisionTrace.inputs.epss` | 0 | 2 | 0 |
| `decisionTrace.inputs.exposureSeconds` | 2 | 0 | 0 |
| `decisionTrace.inputs.gpuUtilization` | 1 | 1 | 0 |
| `decisionTrace.inputs.imageRarity` | 2 | 0 | 0 |
| `decisionTrace.inputs.leakage` | 0 | 1 | 1 |
| `decisionTrace.inputs.modelRarity` | 1 | 1 | 0 |
| `decisionTrace.inputs.pHold` | 2 | 0 | 0 |
| `decisionTrace.inputs.requestRate` | 1 | 1 | 0 |
| `decisionTrace.inputs.smOccupancy` | 0 | 2 | 0 |
| `decisionTrace.inputs.stageHazard` | 2 | 0 | 0 |
| `decisionTrace.inputs.stageUrgency` | 2 | 0 | 0 |
| `decisionTrace.inputs.threatPosture` | 2 | 0 | 0 |
| `decisionTrace.inputs.vramFraction` | 0 | 2 | 0 |
| `decisionTrace.selectionRound` | 1 | 1 | 0 |
