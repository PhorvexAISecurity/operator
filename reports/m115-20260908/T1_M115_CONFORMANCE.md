# PHORVEXSEC-198 — current-correction conformance evidence

Date: 2026-09-08. Contract: **M115-MEASUREMENT-v1**, dated 2026-09-07, sections 6, 11.1, G01–G03/G18 and 13.
Baseline: `ea5d5cad4990365f55e61eddb3da2c6bfc2009a1`, v0.4.96. This baseline includes merged PR 124 (`a13b83af3b2d1a43f1365d90dc59b06fbf176459`). The exact replacement review SHA is supplied in the card's submission manifest and PR.

## What this delivers

The current absent/disabled correction is supplemented with exact regression evidence, consumer inventory, serialized records, and checked-arithmetic fixes found during conformance. It does not implement or certify a measurement adapter. vllm and every other unapproved class remain absent. The shipped activation list stays empty, and the queue contribution remains disabled unconditionally.

**New defect reproduced:** L=1.6e308 and E=8e307 are finite. Their sum overflows, and the merged code returned present residual 0 instead of 1/3. `TestM115LargeFiniteAndScale` fails on the baseline (M115_OVERFLOW_BEFORE.log). The fix evaluates the contract's scaled equivalent when the sum overflows. Ordinary inputs retain the original calculation. Invalid/overflowing products remain absent with a reason. A positive product that underflows to zero is also explicitly absent (`underflow-expected`), rather than reported as measured zero. Redundant clipping is removed; finite nonnegative operands already bound the ruled result.

## Acceptance matrix

| Requirement | Evidence / assertion |
|---|---|
| M01–M06 | TestFlowResidualMatchesRulingVector: 0, 0.5, -0.5, 1, -1, 0 with tolerance 1e-9 |
| M07–M08 | Same test: missing mean and percentile-only latency are absent |
| Units | TestFlowResidualUnitInvariance and TestResidualFlowTermIsUnitInvariantEndToEnd |
| Antisymmetry, range, agreement, saturation, monotonicity | TestFlowResidualProperties |
| Scale invariance, large finite arithmetic | TestM115LargeFiniteAndScale (scales 1, 1e-200, 1e200, 8e307) |
| Negative/NaN/Inf/stale in every input | TestM115InvalidInputsSerializeAsAbsent, with finite JSON serialization and product-overflow/underflow absence |
| Aggregation examples | TestAggregatePresentOnly and TestM115MeasuredZeroAggregate: present-only denominator, opposite signs do not cancel, {0,absent} remains measured zero, empty set absent |
| G01 unapproved class | TestUnactivatedClassIsAbsentWithReason, TestUnactivatedFlowLeavesTheAggregateHonest, TestM115HistoricalUnapprovedClass |
| G02 queue disabled | TestQueueTermStaysDisabledEvenWithBothInputsPresent and TestM115HistoricalQueueUnitDependence |
| G03/G18 absence through consumers | TestM115RecordPresenceRoundTrip exercises flowRecord → audit.ToRecord → actual audit MarshalJSON/UnmarshalJSON. Absent, measured zero and present nonzero remain distinguishable in both residual and aggregate. See M115_RECORDS.json |
| Decision/fact path | TestM115InactiveInputsDoNotChangeDecisions compares the complete serialized CoverageEngine output with missing versus valid high-discrepancy unactivated Little inputs. Outputs are byte-identical |

Present-zero/nonzero record examples activate **only the test fixture namespace** and restore the previous list. They are not evidence of production activation or adapter certification.

## Negative controls and baseline identity

- Historical pre-M115 `5fe1c8e` (parent of a52a3a5): the same TestM115HistoricalPresentOnlyDenominator returns 0.775 rather than 1. TestM115HistoricalQueueUnitDependence gives 0.2980769230769231 with a per-second rate and 0 with the equivalent per-minute rate. Both fail as expected. See M115_HISTORICAL_BEFORE.log.
- Pre-activation `a52a3a5`: unchanged TestM115HistoricalUnapprovedClass finds an unapproved component present with magnitude 0.5. See M115_ACTIVATION_BEFORE.log.
- Current merged baseline: finite-sum overflow test returns 0 rather than 1/3. See M115_OVERFLOW_BEFORE.log.
- Controlled asymmetric-denominator mutation `(L-E)/E`: TestFlowResidualProperties fails antisymmetry. See M115_ASYMMETRY_CONTROL.log. This is explicitly a mutation control, not a claim that this exact equation was the historical pre-M115 implementation (which did not expose this pure residual function).
- All baseline-compatible tests pass on the replacement implementation. Mutations were restored before final verification.

## Consumer and fact-path inventory

At the pinned current baseline plus this patch:

1. `physics.FlowResidual` is the pure calculation. `FlowResidualFor` applies the class gate. `Components` uses the gated result, and `Aggregate` preserves presence independently of its numeric placeholder.
2. The **active production consumer is the decision trace**: `decision.flowRecord` calls those functions and builds OptionalFloat fields, including aggregate presence. `coverage.go` places this in Inputs.Flow.
3. `audit.ToRecord` retains the trace. The v2 audit serialization round-trip preserves its presence bits. Unavailable numeric fields may physically carry 0 but explicitly remain present=false, as allowed by G18. This is not a measured zero.
4. The legacy PhysicsProfile.Residual API discards aggregate presence and returns a float. A source scan finds **no production call to that method** at this SHA. It must not be reintroduced as a decision input without a presence-preserving contract. The report does not infer this from an unmerged PR.
5. No current recon fact, belief, optimizer or feasibility path consumes Inputs.Flow or the pure Little residual. The concrete inventory is in M115_CONSUMER_INVENTORY.txt. The complete-output regression additionally verifies the unactivated flow-input path does not alter current facts, scores or selection in its fixture.
6. Byte-flow remains an existing separate diagnostic component. This patch does not grant it attack semantics or change its formula, thresholds or weights.

## Configuration, checks and scope

Full `go test ./...`, `go vet ./...`, and pendingcheck pass. The focused suite was rerun after adding the final audit serialization checks. Logs are attached. This patch changes only the pure arithmetic branch, tests and documentation. Chart, deployment configuration, thresholds, weights, activation configuration and ingest queries have no diff.

The startup `flow-residual-classes` option / PHORVEX_FLOW_RESIDUAL_CLASSES override already exists and is unchanged. Default and shipped chart settings activate no classes. We do not treat a manual allowlist override as mathematical authorization.

PR 124's recorded GitHub checks show changes/chart-sync/builds passed, E2E failed, deploy skipped, and no formal review objects. See m115-pr124-status.json. Merge is not substituted for independent code-review evidence. The new PR's CI status is recorded separately on submission, without implying that pending or failed E2E passed.

## Replay and review boundary

This correction does not activate a production component. Deterministic before/after input replay, actual audit serialization, exact math vectors and historical negative controls cover its changed paths. No deployed adapter, live occupancy validation, or production replay is claimed. The attached records are reproducible test records, not customer telemetry.

**Remaining sign-offs:** independent DEV review and MATH's exact-SHA conformance decision. The evidence package is ready for those reviews, not a self-issued approval. No deployment/merge is requested by this document.

## Separate future implementation

Contract sections 2–5, 7–9, 11.2 and the remaining G vectors require a linked future measurement implementation: independent occupancy event accumulator, aligned populations/windows, boundary terms, certified error/rate budgets, versioned adapter certificate, low/driven-load fixtures and compatibility checks. None are prerequisites for closing the current absent/disabled correction once its own reviews pass (contract sections 1 and 13). No adapter activation is performed here.
