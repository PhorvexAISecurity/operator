# Constants registry

PHVX-24 item 1. Reviewed on 2026-08-20 against an integration of PRs #52–#59, not just the
older base of PR #57. The `file:line` references below therefore match that combined tree.

## Scope and evidence labels

This is the risk registry requested by PHVX-24: every constant named by the ticket, plus the
adjacent cost-path constants found while tracing those values to their production consumers. It
is not presented as an inventory of every numeric literal in the repository.

Evidence is labelled rather than blended:

- **assertion-backed** — a test proves a formula, invariant, or wiring property;
- **repository artifact** — raw or summarized measurements are committed;
- **reported aggregate** — a task note records results, but the raw live snapshot is unavailable
  in this repository;
- **reconstructed fixture** — generated from a declared fixture and not live-cluster evidence;
- **unvalidated** — no cited derivation or applicable evidence was found.

The ticket's portability screen is useful but only one-way: a value with units, or a cap or
denominator, is cluster-scale-sensitive. A dimensionless value is not automatically portable or
validated; priors, blend weights, and hazard shapes can still be fleet-dependent.

## Scale-sensitive constants

| Constant | Value | Location | Meaning | Tune or fixed? | Validation status |
|---|---:|---|---|---|---|
| `CoResidencyCap` | `4.0` | `internal/platform/platform.go` | Compatibility denominator in `1 + clamp01((running namespaces on node-1)/cap)` | Production default fixed; PR #58 computes shadow candidates only | **Namespace-dispersion proxy, not tenant or GPU-sharing evidence.** System DaemonSets and ordinary namespaces participate. The value remains for declared dispersion consumers and is traced with basis `running-namespace-count-on-node`; it cannot activate model-theft or GPU-side-channel classification. |
| `MaxDispersionMult` | `4.0` | `internal/recon/ucw.go:53` | Cap on the compounded UCW scarcity multiplier | Production default fixed; PR #58 evaluates a shadow cap only | **Reported aggregate, not raw live evidence.** The task note reports products `2.03–8.00` and 19/71 pods at the cap. No raw live snapshot is committed. |
| `ReadyDelayReference` | `400s` | `internal/cost/p1cost.go:127` | Normalizer for replacement PodReady delay, capped at `2×` | Production fixed; PR #58 runs a shadow Kaplan–Meier estimator | **Pipeline assertion-backed; value not live-validated here.** Censoring, frozen deadlines, export, and fallback are tested, but the committed reconstructed ready-delay artifact has no live outcomes. |
| Kill-chain sojourn defaults | `1800/600/3600/1200/600s`; AI `300/180/900/3600s` | `api/v1alpha1/defaults.go:15-18`; consumed at `internal/killchain/hazard.go:290-301` | Weibull characteristic dwell by stage | Policy default; overrideable through `spec.brain.killChain.sojournScaleSeconds` | **Wiring assertion-backed, magnitudes unvalidated.** PR #58 wires and tests overrides; it does not fit these defaults. |
| `exactWorkBudget` | `300_000` | `internal/decision/optimality.go:72` | Work ceiling for the exact verification arm | Fixed tractability guard | **Repository artifact + tests.** PR #55 derives it from the 500ms ruling, records the exact status matrix, and reports the worst admitted calibration-host run at about 375ms. This is not a physics portability scale. |
| Request-rate normalizer | `200 req/s` | P1: `internal/cost/action_flow.go:110`; RLS: `internal/cost/rls.go:42`; legacy P0: `internal/cost/switching.go:97` | Saturates load pressure before it enters flow-cost features | Fixed and duplicated in three paths | **Unvalidated.** A 2000 req/s service is permanently saturated while a 5 req/s service barely moves. Not covered by PHVX-74. |
| Connection-count normalizer | `100 connections` | P1: `internal/cost/action_flow.go:86,111`; legacy P0: `internal/cost/switching.go:66` | Saturates connection pressure | Fixed and duplicated | **Unvalidated.** Carries service-scale units and is not covered by PHVX-74. |

## Dimensionless priors, caps, and formulas

| Constant | Value | Location | Meaning | Tune or fixed? | Validation status |
|---|---:|---|---|---|---|
| `provFloor` | `0.34` | `internal/decision/coverage.go:165` | Discount for a fresh candidate with no evidence | Fixed | **Assertion-backed behavior; no cited empirical fit.** |
| Weibull shape default | `2.0` | `api/v1alpha1/defaults.go:13`; consumed at `internal/killchain/hazard.go:297-301` | Increasing stage-transition hazard | Policy default via `spec.brain.killChain.shape` | **Override wiring tested; magnitude unvalidated.** |
| RLS θ prior | `[0.15,0.85,0.55,0,0.45,0.20]` | `internal/cost/rls.go:47-50` | Initial phase/GPU/load flow weights | Learned away online unless calibration is frozen | **Construction-validated only:** chosen to reproduce the prior behavior, not fitted to data. |
| `maxThetaStep` | `0.25` | `internal/cost/rls.go:53-63` | Maximum one-observation change to an RLS coefficient | Fixed safety rate limit | **Reasoned bound, not empirical fit.** It is documented as one quarter of the largest prior weight. |
| `rarity()` | `1 + clamp01(log2(N/count)/log2(N))` | `internal/platform/platform.go:173-180` | Population-relative surprisal in `[1,2]` | Fixed formula | **Assertion-backed.** `TestRarityIsPopulationRelative` and companion tests pin the intended population semantics. This is a formula validation, not a live measurement. |
| `DefaultCostCeiling` | `1.2` | `internal/model/types.go`; CRD `spec.slo.costCeiling` | Independent hard ceiling for the dimensionless conformal switching-cost bound; never derived from objective weights | Per-service policy override | **`[ESTIMATE-UNVALIDATED]`.** One logical pod replacement plus the provisional structural margin from PHVX-9a/9b. |
| P1 unmeasured action-flow priors | cutover `0.10+0.15·load`; serving state `0.05+0.10·load`; lightweight `0.02`; unknown `2.0`; quarantine `0.25+0.15·conn` | `internal/cost/action_flow.go:17-39,82-99` | Action-specific disruption-loss priors | Fixed until action-specific measurements exist | **Mixed.** The kv-reset fraction in the same file is backed by committed raw samples; the values listed here are explicitly `[ESTIMATE-UNVALIDATED]`. |
| Legacy P0 `flowCost` priors and blend | phase `0.5/1/0.7/0.15/0.2`; GPU `0.6` or `0.4+0.5·util`; load `0.2`; blend `0.55/0.35` | `internal/cost/switching.go:59-100` | Legacy switching-cost model | Fixed legacy path | **Unvalidated.** Its pre-clamp maximum is `1.065`, so a band is flattened at `1.0`; this does **not** describe the current P1 action-specific path. |

## GPU envelope

| Constant | Value | Location | Meaning | Tune or fixed? | Validation status |
|---|---:|---|---|---|---|
| `DefaultGPUEnvelopeMax` | `1.0` | `internal/cost/conformal.go:22` | Conservative fallback without hardware evidence | Runtime flag/config | **Deliberate fail-safe**, not a fit. |
| `MeasuredT4GPUEnvelopeMax` | `117/400 = 0.2925` | `internal/cost/conformal.go:27` | T4 replacement envelope | Runtime flag/config | **Reported measurement with assertion-backed arithmetic.** The code and test preserve `117/400`; the underlying live event is not a raw artifact in this PR. |

## Operational dials

| Dial | Default | Default/consumer | Policy field | Status |
|---|---:|---|---|---|
| λ configured runtime seed | `0.6` | `internal/cost/dual.go`; `internal/decision/coverage.go` | `spec.objective.lambda` | **Wired in PR #57.** It seeds each tenant's legacy runtime controller once; subsequent reconciles do not erase learned state. The controller is not certified as an exact move-budget dual. |
| `MaxMovesPerTick` (B) | `3` | `api/v1alpha1/defaults.go:28,77-87` | `spec.budget.maxMovesPerTick` | Externalized and consumed. |
| Tick interval (Δ) | `20s` | `api/v1alpha1/defaults.go:30,97-103` | `spec.budget.tickInterval` | Externalized and consumed. |
| `ProactiveFloor` | `1h` | `api/v1alpha1/defaults.go:32,113-119` | `spec.budget.proactiveFloor` | Externalized and consumed. |
| Flow-disruption weight | `0.6` | `api/v1alpha1/defaults.go:26,67-70` | `spec.objective.costWeights.flowDisruption` | Externalized and consumed. |

λ is an **initial condition**, not a fixed production price. The legacy controller adapts it to realized
budget pressure. The policy value is consumed only when a tenant bucket is first created so a
routine policy reconcile cannot wipe learned state.

## Corrections to the original ticket table

| Ticket says | Combined-tree reality |
|---|---|
| `CoResidencyCap` at `ucw.go:35` | `internal/platform/platform.go:46` |
| `MaxDispersionMult` at `ucw.go:35` | `internal/recon/ucw.go:53` |
| `provFloor` at `coverage.go:179` | `internal/decision/coverage.go:165` |
| `exactBruteForceAssetCap = 18` | Removed; PR #55 uses `exactWorkBudget = 300_000` at `optimality.go:72` |
| `rarity()` at `platform.go:169-176` | `internal/platform/platform.go:173-180` |
| One unnamed `0.2` describes the cost path | The action-set ceiling has its own `+0.2`; P1 action-flow priors, request/connection normalizers, and the legacy P0 blend are separate surfaces |
| Sojourn defaults are “overridable in principle” but never overridden | PR #58 wires `spec.brain.killChain` into the hazard consumer and tests it; the defaults remain uncalibrated |
| All scales are covered by PHVX-74 | Request-rate and connection-count normalization are not |

## Remaining work

- PHVX-24 item 2 still needs the math-owned joint re-fit and an activation decision. PR #58 remains
  shadow-only and its committed evidence is reconstructed, not live.
- Item 3 is PHORVEXSEC-104 / PR #59.
- Item 4's formula, tests, and comment are complete in PR #56; the requested deployment annotation
  remains unresolved because `mock-rag-chatbot` was retired and no honest replacement target has
  been selected.
- Item 6 remains math-owned and gated by its prerequisites.
- The request/connection normalizers need a separately scoped calibration owner; silently folding
  them into PHVX-74 would misstate that ticket's delivered scope.
