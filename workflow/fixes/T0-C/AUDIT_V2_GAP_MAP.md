# AUDIT_V2_GAP_MAP — T0-C Task 1 (Proposer, 2026-09-03)

Gap map of the CURRENT decision record against the ticket's 12 required-implementation sections.
The current record = envelope `phorvex.audit.v2` (`internal/audit/log.go:24-90`) + nested
`phorvex.decision-trace.v2` (`internal/model/decision_trace.go`, T0-D `c53258d`, live at 0.4.74).
The ticket quoted the anatomy at `fb52e6c`, which predates T0-D — this map is against the live
record, per the Skeptic's pointer. Ground truth: code at `515c56a` (v0.4.74) + live records
`evidence/live-baseline/01` (selected, voice/rotate) and
`fixes/T1-A/evidence/live/02` (noop, vllm).

Legend: **P** present · **D** present-but-dishonest (the field exists; its value misleads) ·
**M** missing · **N** present under a different name/semantics.

## §1 — Schema version (v3 or versioned companion; v2 readable)

| requirement | status | evidence |
|---|---|
| versioned companion | **P** | `decisionTrace` is already a versioned companion inside audit v2: `DecisionTraceSchemaV2` (decision_trace.go:18); envelope contract untouched |
| historical stays readable | **P** | `Validate()` reads pre-T0-B records via empty-`costRepresentationVersion` branch (decision_trace.go:404-419) + rollback aliases; test `TestDecisionTraceV2ReadsAndRestoresPreT0BRollbackRecord` |

Increment: bump to `decision-trace.v3`; keep the v2 read path. No new envelope version needed.

## §2 — Identity (13 fields)

**P — all 13 present** in the trace (decision_trace.go:144-157): schemaVersion, decisionID,
tickID, timestamp, brainImage, gitSHA, decisionEngine, policyNamespace, policyName, policyUID,
tenantName, assetNamespace, assetName, assetUID. Verified live in both sample records.
Empty strings surface as `"notAvailable"` (coverage.go:567-571), never silently empty.

## §3 — Control (6 fields)

| ticket field | status | evidence |
|---|---|---|
| maxMovesPerTick | **N** | recorded as `budget` = `pol.MaxMovesPerTick` (coverage.go:644) |
| candidateDemand | **P** | `candidateDemand` (coverage.go:645); live: 1 |
| movesSelected | **M** | no field; derivable per-record as `selected?1:0`, but the per-tick total is nowhere |
| movesSpent | **P** | `movesSpent` (coverage.go:646) |
| dryRun | **P** | `dryRun` (coverage.go:647) |
| killSwitchState | **P** | `killSwitchEngaged`, stamped post-build by the runner (manager.go:920); plain bool, explicit false |

## §4 — λ / cost state (4 fields)

| ticket field | status | evidence |
|---|---|---|
| lambdaConfiguredSeed | **P** | `lambdaConfiguredSeed` = pol.Lambda (coverage.go:648); live: 0.4 (voice), 0.5 (vllm) |
| lambdaRuntime | **P** | `lambdaRuntime` (coverage.go:649); live: **0 everywhere** — demand ≤ budget on every tenant, dual update never fires (M-19/M-22 trap; see facts §1a) |
| rlsPrimed | **N** | `inputs.primed` (coverage.go:683); live: true in 22% of records |
| costModelVersion | **D** | `costRepresentationVersion` = "weighted_dimensionless_v1" names the *objective score* representation, not the cost model. The cost model's identity (`rls-dual-conformal`, p1cost.go:299) is **not recorded** — a record cannot distinguish which cost model produced ECost/CHi |

## §5 — Per-candidate cost (7 named quantities)

| ticket field | status | evidence |
|---|---|---|
| CNorm | **P** | `cNorm` OptionalFloat (coverage.go:767); live: 1 on selected rotate |
| CFlow | **P** | `cFlow` (coverage.go:768); live: 0.0727 |
| ECost | **P** | `expectedCost` (coverage.go:769); reconstructs: 0.4·1+0.6·0.0727=0.4436 ✓ |
| CHi | **P** | `costHigh` (coverage.go:770); live: 0.5213 |
| conformalQuantile-or-residual | **M** | the conformal window's quantile (conformal.go:85) is never recorded; CHi−ECost only recovers the slack on the additive branch — the GPU-envelope branch (p1cost.go:208-209) breaks that arithmetic. CHi is not independently reconstructable |
| costCeiling | **M** | `EffectiveCostCeiling(pol)` (p1cost.go:33-38; policy slo.costCeiling=1.2 or default 1.2) is consumed at generator.go:229 and never recorded |
| SLOGateResult | **M** | the hard gate's outcome exists only as the *rejection* string `conformal-slo: worst-case cost X > ceiling Y` (generator.go:230) — 0 occurrences in the retained corpus; the pass side leaves no trace |
| (adjacent) UnactionableCategory | **N** | recorded only inside `existingExclusionReason` when it fires at generation (generator.go:217-222); on excluded rows the builder re-derives it to *omit* CNorm/CFlow (coverage.go:803-807) but drops the string; 0 live occurrences |

## §6 — Physics (R-9 six + 7 telemetry, all with presence)

| field | status | evidence |
|---|---|---|
| imageRarity, coResidency, epss, modelRarity, dispersionMult | **P** | inputs, all OptionalFloat (coverage.go:675-682); the R-9 six complete incl. `physicsScanned` (:680) |
| SMOccupancy | **P** | `smOccupancy` + honest-absence keyed on SMSource (coverage.go:672); live: absent (T4, no DCP) |
| leakage | **P** | T1-A addition (coverage.go:674); live: absent |
| VRAMFraction | **D** | `vramFraction` present but its flag is **always false** — `stampGPU` drops `VRAMPresent` (adapters.go:19-29), **M-152**; the gate consumes the float the record calls absent |
| GPUUtilization, phase, requestRate, connectionCount | **P** | coverage.go:669-671, 668 |
| SLOHeadroom | **D** | envelope `sloHeadroom` is a bare float64 (log.go:55) — no presence state; not in trace inputs at all |

## §7 — Belief (11 fields)

| field | status | evidence |
|---|---|---|
| betaMean, pHold, stage, stageHazard, stageUrgency, threatPosture, exposureVariable, exposureSeconds, proactiveFloor, antiOverRotationWindow | **P** | inputs (coverage.go:684-694) |
| nextStage | **N** | envelope-only (`nextStage`, log.go:68 with omitempty — M-146 class: zero/empty erased); not in trace inputs. `projectedNextStageSec` same (log.go:84) |

## §8 — Facts (5 + decomposition)

| ticket field | status | evidence |
|---|---|---|
| factKey, factType, finalWeight | **P** | coverage.go:705-708; live: 118 facts on the selected record |
| alreadyCovered | **D** | `coveredBeforeDecision` is **hardcoded `false`** (coverage.go:709) — asserts "not covered" without evaluating coverage |
| coveringActions | **M** | no field; cover relation visible only per-candidate via `coverKeys`. `ActionSet` does not carry `CoverByAction`, so the builder cannot reconstruct it today without plumbing |
| assetValue | **P** | `assetValue` OptionalFloat present:true (coverage.go:711) |
| pHoldFactor, urgencyFactor, dispersionFactor, relativeWeight | **N** | all four `present:false` always (coverage.go:713-718) — honest absence ("recon exposes only the final weight"), but the ticket's named `decompositionAvailable:false` flag does not exist; absence is per-field implicit |
| (extra) sourceComponent | **P** | recon name (coverage.go:710) |

## §9 — One status per canonical action (10-value enum)

**M — the taxonomy does not exist.** Rows exist only for actions that reach the generator loop,
which iterates `enabledActions(pol)` (generator.go:106, 188): not-enabled actions leave **no
row**. Live measurement (facts §bonus): vllm has rows for 2 of 15 canonical actions; three
actions (adapter-rotate, request-drain, guardrail-rotate) have zero rows fleet-wide. From the
record alone, "not-enabled" is indistinguishable from "enabled but never generated" — the R-2
hole. `notClassifiedByCurrentModel` is `true` on every row (coverage.go:776, 798) — the marker
that this classification is unimplemented, currently vacuous rather than informative. The
selection-side vocabulary (`selectionReason`, 6 values) and generator-side vocabulary
(`existingExclusionReason`: recon-cover / availability / anti-over-rotation / conformal-slo /
NaN-category) exist but are two separate enums with no unified status.

## §10 — Candidate economics (14 fields)

**P — 13 of 14** per candidate: action, candidateKey, coverKeys, marginalCoverage, provenance,
grossValue (`grossFullValue`), ECost, CHi, lambdaContribution, netGain, feasible (OptionalBool),
selected, tieBreakRank (coverage.go:759-777). **selectionRound: N** — trace-level
`selectionRound` OptionalInt (coverage.go:815), not per-candidate. Reconstruction contracts
already enforced by `Validate()`: netGain = marginalCoverage·provenance − λContribution
(decision_trace.go:390-395), ECost = wN·CNorm + wF·CFlow (:396-401).

## §11 — Dispatch outcome (4 states)

**M as an enum; D in what exists.** Envelope `actuated` bool (log.go:44, no omitempty — explicit
false ✓) collapses `not-attempted` and `emitted-false` into one value, and `dispatch-error`
lands nowhere structured. Actuation forensics (handler, objectsTouched, rollbackRef,
mutationKind — log.go:76-79) appear only on emit. And `actuated=true` means "the handler
returned Emitted" — M-35 class: endpoint-rotate reports Emitted even when the restitch fails,
so the field overstates effect. No `confirmed`/`attack-mitigated` anywhere (ticket's exclusion
already satisfied).

## §12 — Deterministic ordering

| requirement | status | evidence |
|---|---|---|
| facts by factKey | **P** | Canonical() (decision_trace.go:275) |
| coverKeys lexical | **P** | decision_trace.go:289 |
| candidates by assetUID then canonical action | **D** | sort key is the **namespace/name** prefix of candidateKey, not assetUID (decision_trace.go:300-315); canonical action rank ✓ (:311). Moot inside a per-asset record, spec-mismatched in key choice |
| cost components fixed | **P** | struct field order |
| redaction | **P** | Canonical() redacts (decision_trace.go:189-204) + test |
| non-interference | **P** | builder runs post-selection, reads the completed ActionSet (coverage.go:601-603); Canonical never mutates (:217, test :153) |

## Envelope-level note (out of the trace's scope, in the ticket's spirit)

M-146 lives at the envelope: `threatRisk`, `lambda`, `stageHazard`, `preemptMargin`,
`projectedNextStageSec`, `perDollar`, `coveredWeight`, `nextStage`… all carry `omitempty`
(log.go:46-84) — measured zeros erased. The trace is the honest layer; T0-C should not
re-encode these into v3, but the gap map records that the envelope still violates
"present:false ≠ value:0" (ticket trap 4) outside the trace.

## The increment (what T0-C must add), ranked by ticket property

1. **P-C2 complete action accounting (§9)** — per-asset status for all 15 canonical actions:
   `not-enabled` derivable from `pol` in the builder (ActionEnabled, types.go:120) · `no-cover`
   from len(coverKeys)==0 · `infeasible` / `conformal-slo` / NaN from the existing exclusion
   rows · `candidate`/`selected`/`priced-out`/`budget-exhausted` from the selection pass ·
   `not-evaluated-by-current-model` for everything else (ticket trap 3).
2. **P-C3 cost reconstruction (§5)** — add `conformalQuantile` (or residual), `costCeiling`,
   `sloGateResult` per candidate; record the cost-model identity (`costModelVersion` =
   p1cost Name()).
3. **P-C1 reconstructability (§8)** — fix `coveredBeforeDecision` hardcode; add
   `coveringActions` (requires carrying CoverByAction in ActionSet or an honest
   decompositionAvailable-style absence); add the named `decompositionAvailable` flag.
4. **§3/§4/§7 field completions** — movesSelected, sloHeadroom (with presence) into inputs,
   nextStage/projectedNextStageSec into inputs with presence.
5. **§11 dispatch enum** — not-attempted | emitted | emitted-false | dispatch-error, from the
   runner's dispatch result; do NOT add confirmed/mitigated (ticket).
6. **§12 key correction** — candidate sort by assetUID.
7. **Schema** — `phorvex.decision-trace.v3`; v2 reader preserved.
