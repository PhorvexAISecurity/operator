# Phorvex audit decision-record validator

Independent, read-only, stdlib-only Python 3.10+ checker for `phorvex.audit.v2`
records carrying a `decisionTrace` (`phorvex.decision-trace.v2`; v3 hooks reserved).
It re-derives the decision from the record and refuses to treat an absent
`{present:false}` optional as zero.

## Run

```
python3 audit_trace_validator.py <record.json|records.jsonl>... \
    [--report report.md] [--json results.json] [--strict-v3]
./run_baseline.sh            # the two 0.4.74 records -> report-baseline-0.4.74.md/.json
```

* `.json` = one record; `.jsonl` = one record per line, lines whose
  `kind != "phorvex.decision"` or that lack `decisionTrace` are skipped.
* Exit `0` iff every record is PASS (no check FAIL and no check UNDECIDABLE);
  `1` otherwise. UNDECIDABLE is a finding, not a crash: it means the record does
  not carry enough scored fields to replay the selection.
* `--strict-v3`: a v2 record FAILS check 12 instead of SKIPPED.

Record status: FAIL if any check FAILs; else UNDECIDABLE if any check is
UNDECIDABLE; else PASS. SKIPPED checks (law not applicable / terms absent) never
count against a record and always say why.

## Source of every law

Paths are relative to `operator/phorvex/`. Line numbers are as of the
`calm-tilt-live` checkout on 2026-09-03; look for the named symbol if they drift.

| Go source | What it fixes |
|---|---|
| `internal/model/decision_trace.go:17-30` | schema constant `phorvex.decision-trace.v2`, `weighted_dimensionless_v1`, `confirmed_dimensionless_disruption_loss`, `strict_gain_positive` |
| `internal/model/decision_trace.go:32-48` | `OptionalFloat/Int/Bool` = `{present, value}`; absent means unavailable, never 0 |
| `internal/model/decision_trace.go:50-186` | every json tag used here (inputs, facts, candidates, dualUpdate, trace) |
| `internal/model/decision_trace.go:189-192` | the four redaction regexes (`authorization`, `bearer`, secret k=v, `://user:pass@`) |
| `internal/model/decision_trace.go:216-318` (`Canonical()`) | facts sorted by `factKey`; candidates sorted by asset key (prefix before last `\|`) then `canonicalActionRank` then `candidateKey`; `coverKeys` sorted |
| `internal/model/decision_trace.go:337-431` (`Validate()`) | finite floats; brainImage/gitSHA/decisionID/tickID/policyUID/assetUID mandatory; unique fact & candidate keys; `netGain = marginalCoverage*provenance - lambdaContribution` (1e-9); `expectedCost = normWeight*cNorm + flowWeight*cFlow` (1e-9, only when `costRepresentationVersion != ""`); representation constants; `lambdaConfiguredPolicy==lambdaConfiguredSeed`, `lambdaRuntimeLegacy==lambdaRuntime`; dualUpdate demand/spent/budget/rawExcess/lambdaBefore/updateReason; noop <=> zero selected & no key & noopReason; else exactly one selected == selectedCandidateKey |
| `internal/model/types.go:105-114` (`MutatingActions`) | the canonical 15-action order hard-coded as `MUTATING_ACTIONS` |
| `internal/decision/coverage.go:171-177` | `strictPositiveGain(g) = g > 0` (no epsilon, equality fails); `legacyMixedGain = marginal*prov - lambda*ECost` |
| `internal/decision/coverage.go:343-380` | greedy: skip `!attackBackedKey` assets BEFORE scoring (reactive-only); marginal = sum of uncovered coverKeys weights; strict `>` so the first candidate in generation order wins ties (lower `tieBreakRank`); loop runs `budget` rounds; break when best gain not > 0 |
| `internal/decision/coverage.go:604-800` (`buildDecisionTrace`) | `candidateKey = ns/pod\|action`; `tieBreakRank` = generation ordinal, `-1` for generator exclusions; `marginalCoverage`/`netGain` present iff the greedy evaluated the candidate; `lambdaContribution = lambda*ECost`; `selectionReason` vocabulary (`selected_strict_positive_gain`, `reactive_only_no_direct_foothold`, `partition_other_action_selected`, `move_budget_exhausted`, `not_evaluated_by_current_greedy`, `strict_gain_not_positive`, `not_selected_by_current_greedy_ranking`, `existing_generator_exclusion`); excluded rows carry cost terms only if `CostEvaluated`, cNorm/cFlow only if actionable; `noopReason` switch: `reactive-only: no direct foothold` / `no candidate generated` / infeasibleWhy / `priced-out: no net-positive feasible move` / `budget-exhausted` / `not selected by current greedy round`; `selectionRound` present only when selected; `tieBreakReason` text |

Observed wire quirk: excluded candidates whose generator produced no cover set
are marshalled with `"coverKeys": null` (Go nil slice). The validator treats
null as an empty list.

## The checks

| # | name | asserts |
|---|---|---|
| 1 | schema | envelope `schemaVersion == phorvex.audit.v2`; `decisionTrace.schemaVersion` in {v2, v3}; records which |
| 2 | identity | brainImage, gitSHA, decisionID, tickID, policyUID, assetUID non-empty strings |
| 3 | presence-flags | every `{present,value}` object has boolean `present`; present numeric values finite; top-level lambda/weights finite; builds the presence census (`inputs.*`, `facts[].*`, `candidates[].*`, `selectionRound`) |
| 4 | selection-reference | noop => no `selected:true`, no `selectedCandidateKey`, non-empty `noopReason`; else exactly one selected candidate whose key/action equal `selectedCandidateKey`/`selectedAction` with reason `selected_strict_positive_gain`; envelope `action`/`selected` agree with the trace |
| 5 | ecost-law | per candidate with cNorm, cFlow, expectedCost present: `expectedCost ~= normWeight*cNorm + flowWeight*cFlow` (abs or rel 1e-9); SKIPPED per candidate with the absent terms named |
| 6 | netgain-law | `netGain ~= marginalCoverage*provenance - lambdaContribution` and `lambdaContribution ~= lambdaRuntime*expectedCost` where the terms are present; absences named |
| 7 | selection-reconstruction (P-C1) | replays the greedy: (a) any generated candidate with `reactive_only_no_direct_foothold` => all must be, none scored, record noop with `reactive-only` reason; (b) nothing generated => noop, `no candidate generated` iff candidates empty; (c) scored candidates: argmax netGain, ties to lower tieBreakRank; expected = that candidate iff `netGain > 0 and budget > 0 and movesSpent < budget` (with `movesSpent == budget` the slot may be this asset's own move or another asset's -> noop must read `budget-exhausted`); noop with all netGain <= 0 must read `priced-out...` and losers `strict_gain_not_positive`; a selected trace needs `selectionRound` in 1..budget and other scored candidates `partition_other_action_selected`; generated but unscored candidates with budget > 0 => UNDECIDABLE naming the absent `netGain` paths |
| 8 | ordering (P-C7) | facts ascending by factKey (unique, non-empty); candidates by asset key, then `MUTATING_ACTIONS` rank, then candidateKey (unique, action known); each `coverKeys` sorted; `candidateKey == assetNamespace/assetName\|action` |
| 9 | cover-keys-resolve | every candidate coverKey is a `facts[].factKey` |
| 10 | dual-update | when `costRepresentationVersion` non-empty: representation/unit/selector constants, lambda aliases, `dualUpdate.{demand,spent,budget,lambdaBefore}` equal `candidateDemand,movesSpent,budget,lambdaRuntimeLegacy`, `rawExcess == candidateDemand - budget`, `updateReason` non-empty; SKIPPED (pre-T0-B record) when empty |
| 11 | redaction | every string in the WHOLE record (envelope + trace, keys included) against `(?i)bearer\s+\S+`, `(?i)authorization\s*[:=]`, `://[^/@\s]+:[^/@\s]+@`, `(?i)(api[_-]?key\|password\|token\|credential)\s*[:=]\s*\S+`, plus the Go `secretKVPattern`; any hit FAILs naming the path |
| 12 | v3-hooks | only for `phorvex.decision-trace.v3` (else SKIPPED, or FAIL under `--strict-v3`): (a) `actionStatus` = 15 unique rows in canonical order, `status`/`exclusionKind` vocabularies, `status==selected <=> exclusionKind==none`, `cost-nan => infeasible`; (b) `costHigh ~= expectedCost + (rotate ? max(conformalQuantile, gpuEnvelopeApplied ? gpuEnvelopeSlack : 0) : 0)` skipping cost-nan rows; (c) `coveredBeforeDecision == (coveredRound.present and coveredRound.value < evaluationRound)` and `marginalCoverage ~= sum finalWeight of coverKeys whose fact is not covered-before`; (d) `dispatchOutcome` in {not-attempted, emitted, emitted-false, dispatch-error}. Field names are the exact camelCase names above; the laws come from the T0-C spec, not yet from Go |

## Report layout

Header counts (records / pass / fail / undecidable); per-record table
(decisionID prefix, tenant/pod, trace version, brainImage tag, selectedAction,
status, failed checks); a 12-column PASS/FAIL/SKIPPED/UNDECIDABLE matrix; a
section per failing/undecidable record with each message verbatim; every check
message for every record; and the field-presence census (present / absent counts
per optional field path across all records).

## Positive controls

Mutated copies of the two baseline records were run before trusting the PASS:
netGain off by 1e-6, swapped candidate order, injected `Bearer` token, netGain
removed from the selected candidate (UNDECIDABLE), expectedCost changed, wrong
noopReason, unresolved coverKey + wrong dualUpdate.spent, selected trace flipped
to noop, non-boolean `present` + empty gitSHA, and a mixed `.jsonl`. Each was
caught by the intended check; see `run_baseline.sh` for the clean run.
