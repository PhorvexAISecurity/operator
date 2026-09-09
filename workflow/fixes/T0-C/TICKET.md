# T0-C — verbatim ticket (boss, 2026-09-03, relayed by Mehrdad)

**Named fix:** `B-5/R-2/R-9` · **Tier:** T0 — Instrument and unblock
**Subsystem:** `RECORD` · **Owner:** Mehrdad
**We need to include this in CI to run every time and generate reports in the end to end system. Please talk to hami in this regard.**
**Code:** `internal/audit`, `internal/metrics`, with data supplied from `internal/decision`, `internal/actionset`, `internal/recon`, `internal/cost`, and `internal/runner`
**Closes:** no numbered Master Issue · **Implements:** B-5, R-2, R-9 · **Depends on:** nothing
**Blocks:** final verification of T0-B and every later brain-side mathematical, sensing, belief, cost, or selection change
**Branch:** `t0/record-complete-decision-path`

Tier exit criterion: a decision record carries the candidate set, the per-candidate cost decomposition, lambda as a field, and the exclusion reason for every action not considered — and lambda is observed non-zero on a tenant whose budget does not bind.

## What is wrong
Record captures the chosen action's outcome, not the inputs / candidate set. Cannot reconstruct: actions considered; excluded; why; facts+weights; complete cost decomposition; runtime λ structured; RLS primed; which physics multipliers changed ordering.

## Traps
1. Do not record only the winner. 2. Do not invent future inputs (no new clocks/belief/cost formulas/effect confirmation/capability logic; uncomputed ⇒ unavailable). 3. Never claim `no-rbac`/`no-handler`/`runtime-capability-missing` if never evaluated ⇒ `not-evaluated-by-current-model`. 4. `present:false` ≠ `present:true,value:0`. 5. No secrets (tokens, Secret values, credentials, prompts, sensitive control-plane URLs). 6. No unbounded Prometheus cardinality — arrays go in audit records, not labels.

## Recommendation
B-5: candidate list (action, cover keys, coverage value, ECost, CHi, exclusion reason). R-2: unselectability reason — `no-cover`, `not-installable`, `infeasible`, `priced-out` are different. R-9: six dispersion inputs `imageRarity, coResidency, epss, modelRarity, dispersionMult, physicsScanned`.

## Required implementation
1. Next audit schema version (v3 or versioned companion); historical v2 stays readable.
2. Identity: schemaVersion decisionID tickID timestamp brainImage gitSHA decisionEngine policyNamespace policyName policyUID tenantName assetNamespace assetName assetUID.
3. Control: maxMovesPerTick candidateDemand movesSelected movesSpent dryRun killSwitchState.
4. λ/cost state: lambdaConfiguredSeed lambdaRuntime rlsPrimed costModelVersion (T0-B worth fields later, not invented here).
5. Per-candidate cost: CNorm CFlow ECost conformalQuantile-or-residual CHi costCeiling SLOGateResult — exact source names; recorded components must reproduce ECost and CHi.
6. Physics: the R-9 six + SMOccupancy VRAMFraction GPUUtilization phase requestRate connectionCount SLOHeadroom; every telemetry quantity with presence state.
7. Belief: betaMean pHold stage nextStage stageHazard stageUrgency threatPosture exposureVariable exposureSeconds proactiveFloor antiOverRotationWindow (no Tier-1 clocks).
8. Facts: factKey factType finalWeight alreadyCovered coveringActions; where available assetValue pHoldFactor urgencyFactor dispersionFactor relativeWeight; else decompositionAvailable:false.
9. One status per canonical action: not-enabled | not-installable | no-cover | candidate | infeasible | conformal-slo | priced-out | budget-exhausted | selected | not-evaluated-by-current-model.
10. Candidate economics: action candidateKey coverKeys marginalCoverage provenance grossValue ECost CHi lambdaContribution netGain feasible selected selectionRound.
11. Dispatch outcome (current states only): not-attempted | emitted | emitted-false | dispatch-error. No `confirmed`/`attack-mitigated`.
12. Deterministic ordering: facts by factKey; actions canonical; candidates by assetUID then canonical action; coverKeys lexical; cost components fixed.

## Tasks
1 DEV gap map `AUDIT_V2_GAP_MAP.md` · 2 DEV schema v3/companion · 3–7 DEV schema+tests (identity; λ/RLS/cost; facts/weights/physics/R-9; per-action status; ordering/compat/redaction) · 8 DEV reviewer · 9 AI ENGINEER independent validator (recompute components, ordering, selected/noop) + report · 10 AI ENGINEER reviewer (hidden inputs still required).

## Properties
P-C1 reconstructability · P-C2 complete action accounting · P-C3 cost reconstruction (ECost, CHi) · P-C4 score reconstruction · P-C5 non-interference · P-C6 explicit absence · P-C7 deterministic ordering · P-C8 confidentiality · P-C9 backward compatibility.

## Definition of done (abridged, all items)
v3/companion exists · image+gitSHA · policy/asset UID · λ numeric · rlsPrimed · every cost component · ECost/CHi reconstruct · R-9 six · belief/exposure · facts/weights/coverKeys · status+reason for every canonical action · unknown capability honest · every generated candidate present · selected references exactly one candidate · noop structured reason · dispatch state · no Tier-2 state · ordering tests · trace-on/off equivalence 100% · redaction tests · no unbounded labels · DEV review · validator reconstructs 100% of Tier-0 corpus or fails each record with exact missing field · predicted-output range recorded before merge.

## Predicted-output range (ticket's)
Before: only chosen action's economics visible; no candidate set; unselectability causes indistinguishable; dispersion inputs unauditable.
After: selection unchanged; every canonical action has a status; every candidate reconstructable; runtime λ a field; physics/dispersion visible; unknown capability honestly unknown.
