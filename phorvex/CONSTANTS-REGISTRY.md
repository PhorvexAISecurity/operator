# Constants registry

PHVX-24 item 1. One row per shipped constant: what it is, where it lives, what it means, whether it
is meant to be tuned, and **whether it has ever been validated against anything**.

The last column is the point of the document. "Unvalidated, no cited derivation" is not an
accusation — it is where the risk concentrates, and it cannot be seen by reading any single file.

**The portability rule.** A constant is portable iff it is *dimensionless*. Anything carrying units,
or acting as a cap or a denominator, is a **scale** — and a scale fitted to one cluster is wrong on
another. Scales are the rows to worry about; dimensionless ratios are not.

Every `file:line` below was re-checked against `main` on 2026-08-19. The line numbers in the PHVX-24
ticket body had drifted; see [Corrections](#corrections-to-the-ticket-table).

---

## Scales — carry units or act as a cap/denominator

These are the rows the portability rule flags. All are being addressed by PHVX-74 (PHORVEXSEC-130).

| Constant | Value | Location | Meaning | Class | Validated? |
|---|---|---|---|---|---|
| `CoResidencyCap` | `4.0` | `internal/platform/platform.go:46` | Denominator of the co-residency multiplier: `1 + clamp01((tenants-1)/cap)`, so a node with `cap+1` distinct tenants saturates at +1.0 | Scale | **No derivation.** Measured 2026-08-19: namespaces/node = `[2,4,5,8,9]`, so 3 of 5 nodes saturate and **56 of 71 pods** sit at the 2.0 ceiling |
| `MaxDispersionMult` | `4.0` | `internal/recon/ucw.go:53` | Ceiling on the compounded in-pod UCW multiplier | Scale | **No derivation.** Measured 2026-08-19: uncapped products span **2.03–8.00**; **19 of 71 pods (26.8%)** are pinned at the cap |
| `ReadyDelayReference` | `400s` | `internal/cost/p1cost.go:121` | Normalizer for pod-ready latency: `min(L/ref, 2)` | Scale (seconds) | **No derivation.** A 70B model's warm-up and a busybox pod share one reference |
| `SojournScale` | `1800/600/3600/1200/600`s; AI `300/180/900/3600`s | `internal/killchain/hazard.go:164` | Characteristic dwell per kill-chain stage, feeding the Weibull hazard | Scale (seconds) | **`[SP-0-PENDING]` — unmeasured.** Struct field with a default, overridable in principle; nothing overrides it, so every deployment runs these values |
| `exactWorkBudget` | `200_000` | `internal/decision/optimality.go:46` | Work ceiling above which the exact-optimality arm is skipped | Tractability limit | **Partially.** Replaced the old flat 18-asset cap (PHVX-23). PR #55 re-derives it from the 500 ms ruling and measures the worst admitted run at 375 ms |
| Request-rate normalizer | `200.0` | `internal/cost/switching.go:97` | Divides observed `ReqRate` before saturating: `0.2 * sat(ReqRate/200.0)` | **Scale (req/s)** | **No derivation.** Carries units, so the portability rule flags it: a service whose normal load is 2000 req/s saturates this term permanently, and a 5 req/s service never moves it. **Not listed in the PHVX-24 ticket** |

## Dimensionless — portable by the rule

| Constant | Value | Location | Meaning | Class | Validated? |
|---|---|---|---|---|---|
| `provFloor` | `0.34` | `internal/decision/coverage.go:160` | Discount applied to a fresh, evidence-less candidate so a manufactured decoy cannot crowd out a real foothold | Fixed | **No cited derivation** |
| `Shape` (Weibull *k*) | `2.0` | `internal/killchain/hazard.go:176` | `k>1` makes the hazard increase with dwell | Fixed | **No cited derivation.** `k=2` is the conventional linearly-increasing choice, but nothing here cites a fit |
| RLS θ prior | `[0.15, 0.85, 0.55, 0, 0.45, 0.20]` | `internal/cost/rls.go:50` | Prior flow weights: bias/idle floor, +cold, +warm, idle, +gpu, +load | Prior (learned from) | **Reproduces P0 behaviour by construction** — chosen so nil-data equals the previous hand-coded phase logic. Not fitted to data |
| `rarity()` | `1 + clamp01(log2(N/count)/log2(N))` | `internal/platform/platform.go:170` | Population-relative surprisal in `[1,2]` | Formula | ✅ **Verified correct — do not change.** Pinned by `TestRarityIsPopulationRelative` (PHVX-24 item 4) |

## Flow-disruption cost weights — `internal/cost/switching.go:71-99`

The ticket records this as one row ("the `0.2` has no name, no comment, no derivation"). It is
**ten** numbers in a single function, all unnamed and none derived. They set the entire rotate-cost
prior, so they decide *which* pod gets rotated as much as any weight in the objective does.

| Term | Value | Line | Meaning |
|---|---|---|---|
| phase prior — default | `0.5` | `:71` | Fallback when phase is unknown |
| phase prior — cold-starting | `1.0` | `:74` | Rotating a still-warming pod: worst case |
| phase prior — warm | `0.7` | `:76` | |
| phase prior — idle | `0.15` | `:78` | "the moment to strike" |
| phase prior — draining | `0.2` | `:80` | |
| GPU tax — no telemetry | `0.6` | `:87` | Flat warm-load tax for a GPU pod |
| GPU tax — with telemetry | `0.4 + 0.5·sat(util)` | `:89` | Busier GPU ⇒ costlier to drop |
| load term coefficient | `0.2` | `:97` | Weight on dropped-connection cost |
| blend — phase weight | `0.55` | `:99` | |
| blend — GPU weight | `0.35` | `:99` | Note `0.55 + 0.35 = 0.90`; the remaining 0.10 is carried by `loadHit`, which is **not** bounded to 0.10 — it can reach 0.2, so the sum can exceed 1.0 before `clamp01c` |

⚠️ The last row is worth a second look: the blend reads as a convex combination but is not one.
`sat()` bounds its argument to `[0,1]`, so the GPU term peaks at `0.4 + 0.5 = 0.9`, and the pre-clamp
total peaks at `0.55·1.0 + 0.35·0.9 + 0.2 = 1.065`. `clamp01c` silently absorbs the overflow, which
means the worst-case rotate cost is **flat at 1.0 across a band of genuinely different situations** —
the same saturation complaint PHVX-24 makes about the UCW clamp, in a second place nobody has
measured. Whether it is intended or a leftover is not recorded anywhere.

## GPU envelope

| Constant | Value | Location | Meaning | Class | Validated? |
|---|---|---|---|---|---|
| `DefaultGPUEnvelopeMax` | `1.0` | `internal/cost/conformal.go:22` | Fail-safe when a deployment has no hardware evidence | Fail-safe | ✅ **Deliberately conservative** — the honest-absent value, not a fit |
| `MeasuredT4GPUEnvelopeMax` | `117.0/400.0 = 0.2925` | `internal/cost/conformal.go:27` | Worst observed vLLM replacement on T4 | Measured | ✅ **Measured** — the one scale in this document derived from a recorded observation. Deployed via `--gpu-envelope-max=0.2925` |

## Operational dials — externalised to policy

The PHVX-24 ticket lists these under item 5 ("externalise the operational dials"). **Already done** —
each is a `PhorvexPolicy` field with a code default, so the shipped number is a default, not a
constant.

| Dial | Default | Default declared at | Policy field |
|---|---|---|---|
| λ (objective cost weight) | `0.6` | `api/v1alpha1/defaults.go:16` | `spec.objective.lambda` |
| `MaxMovesPerTick` (B) | `3` | `api/v1alpha1/defaults.go:20` | `spec.budget.maxMovesPerTick` |
| `TickInterval` (Δ) | `20s` | `api/v1alpha1/defaults.go:22` | `spec.budget.tickInterval` |
| `ProactiveFloor` | `1h` | `api/v1alpha1/defaults.go:24` | `spec.budget.proactiveFloor` |
| `FlowDisruption` | `0.6` | `api/v1alpha1/defaults.go:18` | `spec.objective.flowDisruption` |

⚠️ **The λ seed is not a tuning target.** `NewDualSolver` starts at `0.6` with step `0.05`
(`internal/cost/dual.go:26`) and then *self-calibrates* against realized spend — the recorded trace
drives λ from 0.6 to 3.6 in 12 ticks. The seed sets where the search starts, not where it lands.

⚠️ **`MaxMovesPerTick` default `3` vs live `1`.** Every tenant policy on the cluster sets `1`. A new
policy that omits the field gets `3`, which puts the exact-optimality arm in a materially more
expensive regime (PHVX-23).

---

## Corrections to the ticket table

Verified against `main` on 2026-08-19. The ticket's own table has drifted:

| Ticket says | Actual |
|---|---|
| `CoResidencyCap` at `ucw.go:35` | `platform.go:46` — different **file**, not just line |
| `MaxDispersionMult` at `ucw.go:35` | `ucw.go:53` |
| `provFloor` at `coverage.go:179` | `coverage.go:160` |
| `exactBruteForceAssetCap = 18` at `optimality.go:30` | **No longer exists.** Removed by PHVX-23 and replaced with `exactWorkBudget`. Only a stale comment remains at `localsearch.go:216` |
| `rarity()` at `platform.go:169-176` | `platform.go:170-176` |
| Cost ceiling `βnorm + βflow + 0.2`, "the `0.2` has no name, no comment, no derivation" | **Understated.** The flow-disruption path is `internal/cost/switching.go:71-99`, and it holds ~10 unnamed constants, not one — see the row added below |
| `minAvailableReplicas = 2 (nats)` | Operator-set in the tenant policy, not a shipped constant — correctly out of scope for this registry |

## What "validated" means here

Only **two** rows in this document are backed by a recorded measurement:
`MeasuredT4GPUEnvelopeMax` (worst observed T4 replacement) and `rarity()` (verified formula, now
pinned by test). `exactWorkBudget` becomes a third once PR #55 merges.

Everything in the **Scales** table — the rows the portability rule says are the dangerous ones — is
unvalidated. That is the finding, and it is the whole reason PHVX-74 exists.
