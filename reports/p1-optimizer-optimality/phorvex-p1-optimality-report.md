# Phorvex P1 Optimizer — Optimality Report

**Is the greedy move-selector optimal — and if not, can we close the gap?** Two answers, both measured:
(1) on the facts the engine actually ships, the greedy is **provably optimal**; (2) on the one
shared-fact case where a plain greedy slips, a **greedy-then-swaps** optimizer **closes the gap to the
exact optimum**. This answers the Optimization Scientist's note end-to-end — the counterexample, the
boundary, and the regression target it set.

| | |
|---|---|
| Engine | `internal/decision/coverage.go` submodular-greedy (`gain = marginal·prov − λ·ECost`) |
| Verdict (shipped facts) | **greedy = brute-force optimal · ratio 1.000 · gap 0** |
| Boundary (shared facts) | plain greedy drops to **0.845** — reproduced deterministically |
| Gap closed | **greedy-then-swaps → 1.000** (verified live + unit-tested, no regression) |
| Status | 4 tests passing · full decision suite green · live in the bench (`console bench-swaps`) |

---

## 1. TL;DR

- Phorvex selects moves with a **submodular greedy** (`marginal·prov − λ·ECost`). Greedy is **provably
  optimal** when the objective is **modular** — when no two pods can cover the same recon "fact".
- The shipped `standard-recon` profile keys **every** fact by its owning pod (`facts.go` `Key() = Asset
  + "|" + Kind[…]`). Covers are **asset-disjoint** ⇒ modular ⇒ **greedy == exact**. The engine measures
  this on every ablation (`OptimalityOut`). **Live:** all three bench scenarios report **ratio 1.000,
  gap 0**.
- A gap needs a **shared** fact (submodular). The note's hub-spoke instance does exactly that; we
  reproduced it **exactly**: greedy 23.616 vs optimum 27.952 → **0.845**.
- **We closed it.** A deterministic **greedy-then-swaps** local search (`localsearch.go`) reaches the
  exact optimum on the hub-spoke (**0.845 → 1.000**), stays **1.000** on the disjoint control, and over a
  720-cell submodular sweep **never underperforms greedy and never exceeds the exact optimum**.

---

## 2. Why greedy is exact on the shipped facts

The greedy accumulates `marginal·prov − λ·ECost` per pick. If every candidate's cover keys are owned by a
single asset (disjoint universes), the set value is the **sum** of the picks' standalone values — a
**modular** function — and greedy over a modular function under a partition/budget constraint is optimal.

`recon.Fact.Key()` guarantees disjointness (`"<ns>/<pod>|<kind>"`), so pod A's facts never collide with
pod B's. The engine's `coversDisjoint()` self-check confirms it; `computeOptimality()` brute-forces the
exact optimum over the identical objective.

**Live measurement (`POST /api/benchmark-sim`, B=2, proactive):**

| Scenario | greedy ratio | gap | greedy+swaps | asset-disjoint |
|---|---:|---:|---:|:---:|
| NATS brokers (stateful) | **1.0000** | 0.0000 | 1.0000 | ✓ |
| Mixed fleet | **1.0000** | 0.0000 | 1.0000 | ✓ |
| AI / GPU | **1.0000** | 0.0000 | 1.0000 | ✓ |

---

## 3. The boundary — where a plain greedy slips

A gap needs a **shared** fact. The hand-specified hub-spoke instance: three `pool` facts (weight 5) each
shared between a `hub` and one `spoke`; each spoke a private fact (weight 9). `B=2`, `λ=0.3`, `prov=1`.

**The load-bearing inequality:** `pool (5) < private (9) < 2·pool (10)` — two spokes (28) beat hub+spoke
(24), yet the hub standalone (15) outscores each spoke (14), so greedy grabs the hub first and is locked
out of the better two-spoke pair.

| | Selected | Coverage | Objective |
|---|---|---:|---:|
| **Greedy** | hub, spoke-0 | 24.0 | **23.616** |
| **Optimum** (B=2) | spoke-0, spoke-1 | 28.0 | **27.952** |

```
TestScenarioNonOptimal_HubSpokeClean
  greedy picks [ns/hub ns/spoke-0] -> objective 23.616
  exact optimum                    -> objective 27.952
  OptimalityRatio=0.8449  gap=4.336
--- PASS
```

The paired **disjoint control** (pools re-keyed per pod) is exact — `ratio 1.000000` — proving the cause
is the sharing, not a bug.

---

## 4. The gap, closed — greedy-then-swaps

`internal/decision/localsearch.go` adds a deterministic **1-exchange local search** seeded from the base
greedy: while a single **add / drop / swap** (one move per asset, ≤B total) strictly improves the set
objective, apply the best one. Properties, by construction:

- **Never underperforms greedy** — it starts from greedy and only applies strictly-improving exchanges.
- **Byte-identical on modular (disjoint) facts** — no improving exchange exists ⇒ exact-on-disjoint
  guarantee preserved.
- **Escapes the hub-spoke lock-in** — from `{hub, spoke-0}` it swaps `hub → spoke-1`, reaching the
  optimal `{spoke-0, spoke-1}`.

**Measured (live probe, `optimizerProbe` in `/api/benchmark-sim`):**

| Probe | greedy | greedy+swaps | exact | picks (swaps) |
|---|---:|---:|---:|---|
| Shared (hub-spoke) | **0.8449** | **1.0000** | 27.952 | `[spoke-0, spoke-1]` |
| Disjoint (control ≈ shipped) | 1.0000 | 1.0000 | 28.616 | `[hub, spoke-0]` |

**Tests (all passing, full decision suite green):**

```
TestSwapsCloseTheGap_HubSpoke
  SHARED  greedy=23.616 (ratio 0.8449)  swaps=27.952 (ratio 1.0000) picks=[ns/spoke-0 ns/spoke-1]
  DISJOINT swaps ratio=1.000000 (no regression)
--- PASS
TestSwapsNeverUnderperformGreedy_Sweep
  sweep: 720 cells — swaps strictly improved greedy on 124, never underperformed, never exceeded exact
--- PASS
```

**Honest scope:** greedy-then-swaps is a **local** search — it closes this gap and never regresses, but it
is not a global solver for every conceivable submodular instance. A universal guarantee is the **LP / MPC**
tier the note also names; swaps is the cheapest, ship-safe first rung. It is wired as a **benchmark/opt-in
optimizer** — the shipped `Decide` is untouched (and on the disjoint facts it ships, promoting it would be
a no-op).

---

## 5. What shipped in the codebase

| File | What |
|---|---|
| `internal/decision/localsearch.go` | `greedyThenSwaps` (1-exchange local search) + `RunOptimizerProbe` (live greedy/swaps/exact on both fixtures). |
| `internal/decision/optimality.go` | `OptimalityOut` gains `SwapObjective` / `SwapRatio`; `computeOptimality` reports them. |
| `internal/decision/optimality_scenario_test.go` | 4 deterministic tests: the 0.845 gap, the 1.000 disjoint control, the swaps-close-the-gap proof, the never-underperform sweep. |
| `internal/console/benchmark_sim.go` | `/api/benchmark-sim` returns `optimizerProbe` + per-config `swapRatio`. |
| `dashboard-web/components/steps/bench.tsx` | **Greedy=Optimal** column + the **Optimizer optimality** card (greedy 0.845 → swaps 1.000, live). |

---

## 6. The note's regression target — status

> *With shared recon facts the P1 greedy covers 24.0 vs the optimum 28.0 (ratio 0.845); with the shipped
> asset-disjoint facts it is exactly optimal (1.000). This is the regression target a lazy-greedy-with-
> swaps / LP / MPC optimizer must close.*

**Closed at the greedy-with-swaps tier.** The 0.845 hub-spoke instance is now 1.000 under `greedyThenSwaps`,
proven by unit test and shown live in the bench, with no regression on disjoint facts and no change to the
shipped `Decide`. The LP/MPC tier remains available if a future recon profile ever needs a *global*
guarantee on arbitrary submodular instances — but nothing shipped requires it today.

---

## 7. Reproduce

```bash
# the gap, the control, the fix, and the sweep
go test ./internal/decision -run 'ScenarioNonOptimal|Swaps' -v

# live: greedy vs greedy+swaps vs exact
curl -s -H "X-Phorvex-Lens: operator" -H "Content-Type: application/json" \
  -X POST http://localhost:8095/api/benchmark-sim \
  -d '{"scenario":"nats-broker","configs":[{"label":"d","maxMovesPerTick":1,"reactiveOnly":true,"normSparsity":0.4,"flowDisruption":0.6,"weightSecrets":0.8,"minAvailableReplicas":2,"proactiveFloorSec":900}]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["optimizerProbe"])'
```

Or open the dashboard → **Optimizer Bench** → Run benchmark → the **Optimizer optimality** card.

---

*Phorvex — Adaptive Moving Target Defense · engine p1-coverage · console bench-swaps · generated 2026-07-08*
