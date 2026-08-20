# PHORVEXSEC-115 (PHVX-24) — items 1, 4 and 5 report

Updated: 2026-08-20

Primary branches:

- PR #57 — `docs/phvx-24-constants-registry`
- PR #56 — `feat/phvx-24-rarity-population`

Related work verified in the combined review: PR #55 (`exactWorkBudget`), PR #58 (shadow scale
calibration and kill-chain policy overrides), and PR #59 (PHORVEXSEC-104 EPSS feed).

## Correct status

| Item | Status | Evidence / blocker |
|---|---|---|
| 1 — constants registry | **Complete for the PHVX-24 scope** | `phorvex/CONSTANTS-REGISTRY.md`, rechecked against the combined PR #52–#59 tree |
| 2 — re-fit clamp/caps | **Open, math-owned** | PR #58 is shadow-only; committed calibration evidence is reconstructed, not live |
| 3 — EPSS coverage | **Separate task in review** | PHORVEXSEC-104 / PR #59 |
| 4 — ModelRarity | **Partially complete** | Formula tests and source comment are complete in PR #56; requested deployment annotation remains unresolved because its target was retired |
| 5 — operational dials | **Complete after a P1 wiring fix in PR #57** | B, Δ, ProactiveFloor, and weights were already consumed; λ existed in policy but P1 ignored it until this review |
| 6 — offline sweep | **Open, math-owned** | Must retain the task's prerequisite ordering |

PHORVEXSEC-115 as a whole must therefore remain **In Progress**. The earlier report's statement that
items 1, 4, and 5 were all complete was wrong.

## 1. Item 1 — corrected constants registry

The registry records value, current combined-tree location, meaning, whether the value is fixed or
configurable, and a typed evidence status. It no longer treats assertion-backed formulas,
task-reported aggregates, reconstructed fixtures, and raw live measurements as interchangeable.

### Evidence boundary

The task's 2026-08-19 note reports these cluster aggregates:

- 71 pods and five nodes;
- namespaces/node `[2,4,5,8,9]`;
- 56/71 pods at the co-residency ceiling;
- uncapped products `2.03–8.00`, with 19/71 pods at the dispersion cap.

Those are useful **reported aggregates**, but the raw live snapshot is not committed in this
repository. PR #58's committed evidence manifest correctly labels its inputs
`reconstructed_fixture_not_live`. This report does not promote either source into a raw live claim.

### Scale-sensitive constants outside PHVX-74

The current P1 path normalizes request rate by `200 req/s` and connection count by `100` in
`internal/cost/action_flow.go`; the RLS feature path repeats the request normalizer, and the legacy
P0 switching model repeats both. These are unit-carrying service scales with no cited derivation.
They are not covered by PHVX-74.

The action-set generator also has its own fixed `+0.2` cost-ceiling margin. This is separate from
the old `flowCost` blend. The previous report incorrectly described the ten constants in
`internal/cost/switching.go` as if they were the current P1 rotate path; they belong to the legacy
P0 switching model. P1 uses the action-specific priors in `internal/cost/action_flow.go`.

### What PR #58 changed — and did not change

PR #58 wires startup/5-minute sampling/30-minute refresh/7-day lookback shadow calibration,
censoring-aware ready-delay records, raw exports, metrics, and read-only production-vs-shadow
comparisons. Production scoring still uses the shipped co-residency, dispersion, and ready-delay
constants.

PR #58 also wires `spec.brain.killChain.shape` and per-stage
`sojournScaleSeconds` into the hazard consumer. The registry's old statement that those values were
only “overridable in principle” is stale. The override path is tested; the default magnitudes are
still unmeasured.

## 2. Item 4 — formula complete, deployment subtask open

PR #56 keeps `rarity()` unchanged and adds:

- `TestRarityIsPopulationRelative` for all five ticket cases;
- a test proving ImageRarity and ModelRarity use the same function with different populations;
- a monotonicity test guarding the occupancy/rarity direction;
- the corrected ModelRarity source comment.

This establishes the intended formula semantics. It is not described as a live measurement.

The task's later cluster note reports two distinct model IDs on two model-serving pods, which would
make each 1-of-2 and therefore score `2.0`. The raw live snapshot is unavailable here, so this is
kept as a reported aggregate rather than independent verification.

### Why the annotation was not invented

The task asks for:

`phorvex.ai/model-id: sentence-transformers/all-MiniLM-L6-v2`

on the `mock-rag-chatbot` Deployment. That Deployment no longer exists; it was retired together
with `litellm` and `phorvex-live-demo` when ArgoCD took that capacity.

The nearby workloads are not honest substitutes:

- `document-store/chroma` embeds through ONNX and has no `device: cuda` model-serving identity;
- `voice/voice-bot` calls a remote model through LiteLLM rather than serving that model in the pod.

Annotating either would fabricate the population that `rarity()` is supposed to measure. The
subtask remains open until the owner selects a real model-serving deployment or explicitly removes
the retired-target requirement.

## 3. Item 5 — the policy field existed, but λ was not wired to P1

The following fields were already externalized and consumed:

| Dial | Default | Policy field |
|---|---:|---|
| `MaxMovesPerTick` (B) | `3` | `spec.budget.maxMovesPerTick` |
| Tick interval (Δ) | `20s` | `spec.budget.tickInterval` |
| `ProactiveFloor` | `1h` | `spec.budget.proactiveFloor` |
| flow-disruption weight | `0.6` | `spec.objective.costWeights.flowDisruption` |

λ was different. `buildPolicy` copied `spec.objective.lambda`, but `CoverageEngine` ignored
`model.Policy.Lambda` and always constructed every tenant's dual solver at hardcoded `0.6`.
Therefore item 5 was not complete despite the CRD field existing.

PR #57 now:

- exposes the shipped `DefaultLambdaSeed = 0.6`;
- constructs each tenant's isolated P1 cost bucket from that tenant policy's λ;
- accepts `0` as a valid seed, falls back defensively for negative/NaN/Inf values, and clamps values
  above the solver range;
- consumes the seed only when the tenant bucket is created, so a routine policy reconcile cannot
  erase adaptive dual state;
- tests two tenants with distinct λ values and the no-reset behavior.

λ remains an adaptive budget shadow price. The policy controls its initial condition, not every
future value.

## 4. Other corrections retained in PR #57

- The demo overlay no longer says EPSS has “no hardcoded inputs; it's all discovered.” Before PR #59,
  EPSS came from a small maintained cache; after PR #59, the feed can refresh that cache, but absent
  coverage still remains honest-absent.
- The stale `exactBruteForceAssetCap` comment now names `exactWorkBudget` and `ExactSkipped`.
- The old clean-checkout failure claim for `scenarios_export_test.go` was removed. The test now skips
  when `SCEN_OUT` is unset and creates its output directory when explicitly requested.
- The registry uses `exactWorkBudget = 300_000` from PR #55, not the old `200_000` value.

## Verification

Completed directly on PR #57 after the λ fix:

- `go test ./internal/cost ./internal/decision`
- `git diff --check`

The report and line references were also reviewed against the combined PR #52–#59 integration.
Full combined build/vet/test/race, dashboard, Helm, CRD synchronization, and workflow-scope checks
are the final release gate before this report is attached to Plane.

## Conclusion

PR #57 closes the registry and operational-dial work honestly. PR #56 closes the formula and
comment portion of item 4. It does **not** close PHORVEXSEC-115: items 2 and 6 remain math-owned,
item 3 remains PHORVEXSEC-104, and item 4 still needs an owner decision on the retired deployment
target.
