# P-OPTIMIZE-RATIO — search + decision (STOP for approval before building)

**Question.** Maximize recon-per-dollar beyond the current 1.62×, AND answer rigorously: is the submodular
greedy selection actually near-optimal (1−1/e) vs an exact solve? Verify submodularity, benchmark greedy-vs-exact
on dispersed (heavy-tailed) fleets, prove any lift by ablation — measured, not asserted.

**Method.** Deep multi-agent search (11 agents: understand → analyze → adversarially verify → synthesize) over
the real optimizer (`internal/decision/coverage.go`, `ablation.go`, `internal/recon/facts.go`, `internal/cost/`).
The two load-bearing claims were independently re-verified against the code (below). **Analysis only — no brain
code changed this pass.**

---

## Headline (and it's stronger + more honest than the premise)

**The greedy is not merely near-optimal — it is EXACTLY optimal (ratio 1.000) on both shipped profiles.** The
textbook 1−1/e (cardinality) and 1/2 (partition-matroid) bounds quoted in the code comments are **loose** here:
they are valid upper bounds on the gap, not tight. So the "is greedy near-optimal vs exact?" question resolves
to **greedy = exact, gap = 0** on the real system — there is **structurally zero headroom** for any
selection-combinatorics improvement on the shipped profiles.

**Scope of this claim (PHORVEXSEC-114).** Exact optimality is **proven structurally**: with
block-ownership plus the partition constraint the objective is modular over a truncated partition
matroid, so the greedy is exact by Rado–Edmonds. That proof is **scale-free** and does not depend on
fleet size. The empirical check is separate and bounded: it is a brute-force comparison, admitted only
while the enumeration stays inside the work budget (`optimality.go`). Measured directly at
**76 assets at the live move budget of B=1: ratio 1.000000000000, gap 0** — and at 18 and 40 assets on
the way. Above the work budget the exact arm reports `ExactSkipped`; it never reports a ratio it did
not compute.

**Why (verified):** `recon.Fact.Key() = Asset|Kind[|Edge]` ([facts.go:62-68](internal/recon/facts.go#L62-L68)) —
every cover key is **prefixed by its owning asset**, and lateral edges are keyed on the **source** asset. So
distinct candidates have **provably disjoint cover-key universes**; the `!covered[k]` marginal discount
([coverage.go:184-188](internal/decision/coverage.go#L184-L188)) **never fires across the partition**. A
coverage function over disjoint sets is **modular** (the strongest case, not merely submodular). Greedy's
round-by-round top-B-by-net-value selection over a partition matroid is then **exactly the optimum**.

---

## Q1 — Submodularity verdict

| Property | Verdict | Evidence |
|---|---|---|
| Coverage term Σ w(facts covered by S) | **Modular** (not strictly submodular) on shipped profiles | asset-prefixed keys ⇒ disjoint covers (`facts.go:65`) |
| Diminishing returns (marginal non-increasing) | **Holds** (overlap only *decreases* gain) | search reproduction: 0/200000 violations, disjoint **and** adversarial-overlap |
| Monotonicity | **FAILS** (objective can decrease) | the `−λ·ECost` term + `gain≤0` early stop (`coverage.go:197`) |
| `prov(c.Key)` discount | **Preserves modularity** | per-candidate, tick-fixed, set-**independent** constant (`coverage.go:154-167` reads only exposure/urgency, never `covered`) |
| **Resulting guarantee** | **Greedy = exact, ratio 1.0** | matroid-greedy on a modular objective; brute-force 0/300000 suboptimal on disjoint fleets |

**Greedy regime:** cost-benefit greedy of `marginal·prov − λ·ECost` over a **partition matroid** (one move/asset)
under a **cardinality** budget `B = MaxMovesPerTick`, λ frozen per tick, strict-`>` first-seen tie-break. Not
knapsack; not lazy. The 1/2 and 1−1/e bounds become operative **only** under a deliberately-overlapping profile.

---

## Q2 — Greedy vs exact (the answer)

**Greedy is exact on the real engine (gap 0).** The gap appears **only** when cross-asset cover-key overlap is
artificially injected (a "cluster-wide shared fact" re-keyed off a shared neighbor/node instead of the owning
asset): brute-force then showed **46022/300000 suboptimal, worst-case ratio 0.394**, peaking when the budget is
binding (B≈N/3), overlap density ≈0.5, and value is positively correlated with cost. **No in-tree profile
produces overlap**, so on the actual system the "1.62×" headline is a property of **weight concentration**
(heavy tail) and the **λ/cost gate** — NOT of any greedy optimality margin.

**Honest correction to the premise:** the absolute **1.62× is a code-comment target** (`ablation.go:19`
"exact tie at 1.62×"), **unrun on real data** — the in-repo gate asserts only **`Ratio > 1.0`**
([ablation_test.go:49](internal/decision/ablation_test.go#L49)), and the repo's own notes say a live `--ablation`
on an arbitrary namespace can return ~0–1×. So "beat 1.62×" is, today, beating a comment, not a measured baseline.

---

## Q3 — Ratio-lift candidates (ranked; what's real vs not)

| Candidate | Kind | Gate-safe | Expected lift (honest) |
|---|---|---|---|
| **(f) fact-weight / asset-value + blast-radius sharpening** (new recon profile) | **real-ratio-lift** | ✅ | Real but **bounded + fleet-/budget-contingent**: saturates (no gain mult 1.75→2.0), **washes out** as the fleet uniformizes (1.726→1.000), **decays with budget** (2.59 @B=1 → 1.08 @B=5; ~1.49–1.73 @gate B=2, straddling 1.62). "Reliably beyond 1.62×" is **refuted**. |
| **(e) per-class λ / budget shadow price** (new policy fields) | real-ratio-lift | ✅ | Real, **moderate, capped** — λ only changes which/how-many of B fire; can only break the ratio if mis-tuned (decoy-rocket). Best win: a cheap-valuable quarantine not gated by rotate-calibrated λ. |
| (a) ratio-greedy (Δcov/Δcost) | real-ratio-lift | ❌ risky | Small/situational; as a **default-path** edit it rewrites the scoring key + tie order ⇒ breaks byte-identity + can drop the overdue pod (P3 gate). |
| (b) best-singleton ∪ greedy (knapsack trick) | no-op / speculative | ❌ | **Zero** — no knapsack constraint exists; greedy already exact. |
| (d) continuous-greedy / pipage / local search | no-op / **hazard** | ❌ | **Zero** + **determinism hazard** (pipage is randomized — violates the deterministic-brain invariant). |
| (c) lazy-greedy / CELF | **perf-only** | ✅ | **Exactly zero** ratio effect (identical selection); wall-clock only. |

---

## Recommendation

**Build NOTHING into the default decision path.** Greedy is provably exact on the shipped profiles, so every
classic submodular trick is a no-op, a determinism hazard, or perf-only. The expected **measured** ratio lift
from any brain change on the shipped profiles is **0**.

The one honest, gate-safe, **measurable** deliverable is the **greedy-vs-exact benchmark itself** — it converts
the "greedy is optimal" claim from the search agents' reproductions into an **in-tree measured fact**, and
surfaces exactly where (overlap) a gap would appear. If a recon-per-$ improvement is genuinely wanted, the lever
is **weights, not selection** — candidate (f), behind a **new** recon profile (default `standard-recon`
untouched), shipped only if the **measured** per-fleet lift is positive (never asserted to beat 1.62×).

---

## Build plan (for the NEXT, approval pass — gated, ablation-proven, default byte-identical)

- **Step 1 — measurement only (no brain change):** add `ExactValue/GreedyValue/ExactPerDollar/OptimalityRatio/
  OptimalityGap` to `AblationResult` + an `exactArm()` (Tier-B brute force over `{skip,rotate,quarantine}^N`,
  N≤~16) running on the **same** `AssembleSet` substrate and the **frozen** pre-Step λ/prov as the other arms.
  **Ablation proof:** on the existing fleets it must log `OptimalityRatio = 1.000` exactly — if not, an unseen
  shared key exists → stop and investigate. (Additive fields + a test arm; touches no decision logic ⇒
  byte-identical by construction.)
- **Step 2 — benchmark-only fleets:** a Zipf/Pareto value generator with value↔cost correlation + a
  **benchmark-only** `overlap-recon` profile (lateral edge re-keyed on the neighbor), **not** wired to any
  default path; sweep N×B×overlap×α×corr and **report** mean ± 95% CI and min ratio (`Logf`, no assert). This is
  where any nonzero gap becomes visible.
- **Step 3 — optional weight lift (only if 1/2 motivate it):** candidate (f) as a **new** recon profile,
  multipliers 1.0-neutral on uniform fleets, gated behind `engineWithProfile`; ship only if the **measured**
  per-dollar lift on the target fleet is positive. Re-run all four gates + the uniform-fleet byte-identical tie.
- **Step 4 — only if a real knapsack or genuine cover-overlap ever lands:** reconsider (a)/(b) as a **second
  Optimizer behind a flag**, re-proving determinism via a decision-hash diff.

**Gate preservation:** (1) `TestAblationP1BeatsRandomPerDollar` (Ratio>1.0) — a new profile leaves the default
arm byte-identical; (2) `TestCoverageZeroDayProactiveNoEvents` (P3) — don't raise the seed λ (0.6)/`Dual.Step`,
no ratio>λ stop; (3) `TestCoverageStatefulNeverRotated` — risk-free (exclusion is upstream in `feasibility`); (4)
determinism — any default-path edit to the greedy loop is gate-risky, so all changes go behind a profile/flag
whose zero-value = current behavior.

---

## Honest caveats (asserted vs measured)

- **Measured by the search agents (reproductions of `coverage.go:175-207`, NOT the in-tree suite):** diminishing
  returns 0/200000 violations; greedy == brute-force 0/300000 on disjoint covers; overlap restores suboptimality
  (46022/300000, worst 0.394); the (f) lift saturates / washes out / decays with budget; deterministic
  (scarcity=1.638357 across 8 runs). **These become in-tree facts only after Step 1's `exactArm`.**
- **Asserted, NOT measured here:** the absolute **1.62×** is a comment target, unrun on real data; the gate is
  `Ratio>1.0`.
- **What makes the lift zero:** on shipped profiles **no brain change can lift the ratio** (greedy already
  exact); the (f) weight lift is **zero on a uniformly-dispersed fleet** and an adversary can neutralize it by
  authoring uniform dispersion.
- **Profile dependence (the key fragility):** the entire exact/modular result holds **only** because lateral
  edges are keyed on the owning asset (`facts.go:65`). A single future profile that re-keys any fact off a
  shared neighbor/node (e.g. **co-residency keyed by node**) flips the objective to genuine submodular and drops
  the guarantee to the matroid-1/2 / non-monotone regime — at which point (a)/(d) acquire real (still bounded)
  lift. **Read `recon/ucw.go` co-residency key construction before betting (d) is strictly a no-op.**
- The test suite + a live ablation were **not executed** this pass (static + reproduction evidence only).

---

## Decision requested

The rigorous answer to the headline question is: **greedy is exact, not just near-optimal — there is no
selection-side headroom, and "1.62×" is an unrun comment, not a measured baseline.** I recommend approving
**Step 1 (the greedy-vs-exact benchmark, no brain change)** to make that an in-tree measured fact, treating
**Step 2** (overlap/dispersion sweep) as the honest stress test, and gating **Step 3** (weight-sharpening
profile) behind a measured per-fleet lift — never asserted. **No code built this pass. STOP for approval.**
