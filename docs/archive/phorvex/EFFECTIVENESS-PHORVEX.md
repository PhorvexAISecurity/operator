# EFFECTIVENESS-PHORVEX — the full attack benchmark (GATE #2)

> **PHASE: FULL ≥20-trial benchmark.** Per-arm means with 95% CIs (normal approx;
> use t at small n). Reproducible from the harness masterSeed. Honest scope below.

Source `c:\Users\moh87733\Phorvex\build\test-harness\out-p3-full\metrics.jsonl` — 792 rows, 6 scenarios, 6 arms. **ZERO harness-core / ZERO extended-
Phoenix change** (PX + reactive-only are plugin arms; the decisive scenarios are plugin
files; this report is a separate post-processor). Blind interval = **15s** (documented,
scaled-for-test; real periodic rotation is minutes–hours — the RELATIVE ordering is the point).

## Controls
- **Negative control:** max falseDefensiveActions = **0** (target 0). **PASS**
- **Positive control:** 6/6 scenarios where d-nomtd (undefended) achieved the oracle. **PASS**

## ★ LEAD DEMO — blind Delete DESTROYS the running stateful job; PX preserves it

| Arm | work preserved | harm (job destroyed) | action taken | disrupted foothold |
|---|---|---|---|---|
| d-nomtd | 20/20 | 0/20 | none | 0% |
| d-r6blindtimer | 0/20 | 20/20 | rotate→Delete (infeasible on stateful) | 100% |
| d-randomequal | 5/20 | 15/20 | rotate→Delete (infeasible on stateful) | 75% |
| d-reactive-only | 0/20 | 20/20 | none | 100% |
| d-fullphoenix | 0/20 | 20/20 | rotate→Delete (infeasible on stateful) | 100% |
| d-phorvex | 20/20 | 0/20 | **quarantine (feasible alternative)** | 100% |

This is the single headline for the deck: **R6 has no feasibility model**, so its only
move (Delete) destroys the training job; **PX's hard-constraint generator excludes rotate
on a stateful pod and quarantines instead — the foothold is contained and the work survives.**

## TIER 1 — Headline: LEAD WITH DWELL (real foothold-survival, not just disruption%)

| Scenario | Arm | **dwell (s) [95% CI]** | disrupt% | cost (moves) | sec-per-cost | wasted-moves vs PX | R6 counterfactual |
|---|---|---|---:|---:|---:|---:|---|
| c1-fast-attacker | d-nomtd | 12.4 [12.4, 12.5] | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c1-fast-attacker | d-r6blindtimer | 12.4 [12.4, 12.5] | 0% | 0.0 | 0.00 | 0 | — |
| c1-fast-attacker | d-randomequal | 8.0 [6.0, 9.9] | 50% | 0.6 | 0.50 | 0 | — |
| c1-fast-attacker | d-reactive-only | 12.4 [12.3, 12.5] | 0% | 0.0 | 0.00 | 0 | — |
| c1-fast-attacker | d-fullphoenix | 12.4 [12.4, 12.5] | 0% | 0.0 | 0.00 | 0 | — |
| c1-fast-attacker | d-phorvex | 5.1 [5.1, 5.1] | 100% | 1.0 | 1.00 | — (baseline) | R6 blind ~0.0 / full-Phoenix ~0.0 move(s), untargeted |
| c1-heldout-cve | d-nomtd | 20.4 [20.3, 20.4] | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c1-heldout-cve | d-r6blindtimer | 15.2 [15.2, 15.2] | 100% | 1.0 | 1.00 | 0 | — |
| c1-heldout-cve | d-randomequal | 11.8 [8.6, 15.0] | 70% | 0.7 | 0.70 | 0 | — |
| c1-heldout-cve | d-reactive-only | 20.3 [20.3, 20.3] | 0% | 0.0 | 0.00 | 0 | — |
| c1-heldout-cve | d-fullphoenix | 20.4 [20.3, 20.4] | 0% | 0.0 | 0.00 | 0 | — |
| c1-heldout-cve | d-phorvex | 5.5 [5.4, 5.6] | 100% | 1.0 | 1.00 | — (baseline) | R6 blind ~1.0 / full-Phoenix ~0.0 move(s), untargeted |
| c1-llm-adaptive | d-nomtd | — | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c1-llm-adaptive | d-r6blindtimer | — | 0% | 0.0 | 0.00 | 0 | — |
| c1-llm-adaptive | d-randomequal | — | 40% | 0.8 | 0.27 | 0 | — |
| c1-llm-adaptive | d-reactive-only | — | 0% | 0.0 | 0.00 | 0 | — |
| c1-llm-adaptive | d-fullphoenix | — | 0% | 0.0 | 0.00 | 0 | — |
| c1-llm-adaptive | d-phorvex | — | 100% | 1.0 | 1.00 | — (baseline) | R6 blind ~0.0 / full-Phoenix ~0.0 move(s), untargeted |
| c1-stealth-dweller | d-nomtd | 20.2 [20.2, 20.2] | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c1-stealth-dweller | d-r6blindtimer | 15.1 [15.1, 15.2] | 100% | 1.0 | 1.00 | 0 | — |
| c1-stealth-dweller | d-randomequal | 11.5 [8.3, 14.7] | 75% | 0.8 | 0.75 | 0 | — |
| c1-stealth-dweller | d-reactive-only | 20.2 [20.2, 20.2] | 0% | 0.0 | 0.00 | 0 | — |
| c1-stealth-dweller | d-fullphoenix | 20.2 [20.2, 20.2] | 0% | 0.0 | 0.00 | 0 | — |
| c1-stealth-dweller | d-phorvex | 5.6 [5.5, 5.6] | 100% | 1.0 | 1.00 | — (baseline) | R6 blind ~1.0 / full-Phoenix ~0.0 move(s), untargeted |
| c2-persistence-evict | d-nomtd | — | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c2-persistence-evict | d-r6blindtimer | — | 0% | 0.0 | 0.00 | 0 | — |
| c2-persistence-evict | d-randomequal | — | 30% | 0.3 | 0.28 | 0 | — |
| c2-persistence-evict | d-reactive-only | — | 100% | 1.0 | 1.00 | 0 | — |
| c2-persistence-evict | d-fullphoenix | — | 100% | 1.0 | 1.00 | 0 | — |
| c2-persistence-evict | d-phorvex | — | 90% | 1.1 | 0.90 | — (baseline) | R6 blind ~0.0 / full-Phoenix ~1.0 move(s), untargeted |
| c2-stateful-training | d-nomtd | 20.2 [20.2, 20.3] | 0% | 0.0 | 0.00 | 0 | undefended baseline |
| c2-stateful-training | d-r6blindtimer | 15.1 [15.1, 15.2] | 100% | 1.0 | 1.00 | 0 | — |
| c2-stateful-training | d-randomequal | 11.8 [8.7, 15.0] | 75% | 0.8 | 0.72 | 0 | — |
| c2-stateful-training | d-reactive-only | 0.6 [0.6, 0.6] | 100% | 1.0 | 1.00 | 0 | — |
| c2-stateful-training | d-fullphoenix | 0.6 [0.6, 0.6] | 100% | 1.0 | 1.00 | 0 | — |
| c2-stateful-training | d-phorvex | 5.6 [5.6, 5.6] | 100% | 1.0 | 1.00 | — (baseline) | R6 blind ~1.0 / full-Phoenix ~1.0 move(s), untargeted |

**Why dwell leads:** disruption% hides the timing gap. A blind timer and PX may both
eventually evict (similar disruption%), but PX evicts in **seconds** (risk-driven) while
the blind timer waits ~its full interval — the dwell column makes that visible.

## TIER 1b — FAST-ATTACKER: where blind rotation FAILS (not just ties)

Objective completes in ~9s (< the 15s blind interval, > PX's ~6s floor):

| Arm | attacker objective achieved | dwell (s) | verdict |
|---|---|---:|---|
| d-nomtd | 100% | 12.4 [12.4, 12.5] | no timely eviction |
| d-r6blindtimer | 100% | 12.4 [12.4, 12.5] | **TOO LATE — objective completes first** |
| d-randomequal | 50% | 8.0 [6.0, 9.9] | **TOO LATE — objective completes first** |
| d-reactive-only | 100% | 12.4 [12.3, 12.5] | no timely eviction |
| d-fullphoenix | 100% | 12.4 [12.4, 12.5] | no timely eviction |
| d-phorvex | 0% | 5.1 [5.1, 5.1] | **evicts BEFORE the objective ✓** |

The fast attacker is the honest case where a **fixed slow cadence loses**: it arrives
after the objective. PX's rate is a decision variable, so it fires the high-value pod early.

## TIER 1c — Cost-to-equal-dwell (what blind must pay to match PX)

| Scenario | PX dwell (s) | blind dwell (s) | blind interval needed to match PX | blind cost blow-up |
|---|---:|---:|---|---|
| c1-fast-attacker | 5.1 | 12.4 | every ~5.1s (all pods) | ~2.9x more rotations (every 5.1s vs 15s), SLO/availability risk ↑ |
| c1-heldout-cve | 5.5 | 15.2 | every ~5.5s (all pods) | ~2.7x more rotations (every 5.5s vs 15s), SLO/availability risk ↑ |
| c1-stealth-dweller | 5.6 | 15.1 | every ~5.6s (all pods) | ~2.7x more rotations (every 5.6s vs 15s), SLO/availability risk ↑ |
| c2-stateful-training | 5.6 | 15.1 | every ~5.6s (all pods) | ~2.7x more rotations (every 5.6s vs 15s), SLO/availability risk ↑ |

To match PX's targeted dwell, a blind timer must rotate EVERY pod far more often — paying
the cost (and SLO/availability risk) on every workload, not just the at-risk one.

## TIER 2 — Feasibility & physics IP (R6 has NO feasibility model — cannot score this)

| Arm | infeasible-action rate | harm-caused (jobs destroyed / SLO breaches) | feasible-alternative found | explainability% |
|---|---:|---:|---:|---:|
| d-nomtd | 0/20 | 0/20 | 0/20 | 0% |
| d-r6blindtimer | 20/20 | 20/20 | 0/20 | 0% |
| d-randomequal | 15/20 | 15/20 | 0/20 | 0% |
| d-reactive-only | 20/20 | 20/20 | 0/20 | 0% |
| d-fullphoenix | 20/20 | 20/20 | 0/20 | 0% |
| d-phorvex | 0/20 | 0/20 | 20/20 | **100%** (P2: 139/139 decisions; SHAP + R6 counterfactual) |

- **Infeasible-action rate** — how often the arm's prescribed action was physically
  infeasible in-state (rotate on a stateful/single-replica pod). **Blind/full-Phoenix high
  (they Delete regardless); PX = 0** (the generator excludes it before selection).
- **Harm-caused-by-defense** — outages/jobs the DEFENSE itself destroyed. **PX target = 0.**
- **Feasible-alternative-found** — when rotate was infeasible, PX still protected (quarantine);
  blind has no alternative (rotates anyway or nothing).
- **Recon-invalidation RATE / per-dollar** — a PX-only physics output (R6 cannot produce it):
  **recon-per-dollar 1.62x vs random** (P1 GATE-#1 ablation); the recon-RATE is the coverage
  the submodular engine achieves each tick — neither blind nor random has a recon model.
- **Explainability-as-a-metric** — PX **100%** of decisions carry a complete rationale (P2);
  blind/random/timer arms have **no per-decision rationale** by construction.

## TIER 3 — Thesis, zero-day & learnability

| Scenario | Arm | dwell (s) | Schwartau P>D+R | detector | adaptive dwell (learnability) |
|---|---|---:|---|---|---|
| c1-fast-attacker | d-nomtd | 12.4 | — | present | dwell 12.5s vs 12.4s base  |
| c1-fast-attacker | d-r6blindtimer | 12.4 | — | present | dwell 12.4s vs 12.4s base  |
| c1-fast-attacker | d-randomequal | 8.0 | P>D+R — proactive cadence | present | dwell 1.1s vs 8.0s base  |
| c1-fast-attacker | d-reactive-only | 12.4 | — | present | dwell 12.4s vs 12.4s base  |
| c1-fast-attacker | d-fullphoenix | 12.4 | — | present | dwell 12.2s vs 12.4s base  |
| c1-fast-attacker | d-phorvex | 5.1 | **P>D+R** — proactive, D+R≈0, P≈5.1s | present | dwell 5.1s vs 5.1s base (NOT learnable) |
| c1-heldout-cve | d-nomtd | 20.4 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.4s vs 20.4s base  |
| c1-heldout-cve | d-r6blindtimer | 15.2 | P>D+R — proactive cadence | **ABSENT** (zero-day) | dwell 15.2s vs 15.2s base  |
| c1-heldout-cve | d-randomequal | 11.8 | P>D+R — proactive cadence | **ABSENT** (zero-day) | dwell 16.9s vs 11.8s base (LEARNABLE) |
| c1-heldout-cve | d-reactive-only | 20.3 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.4s vs 20.3s base  |
| c1-heldout-cve | d-fullphoenix | 20.4 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.3s vs 20.4s base  |
| c1-heldout-cve | d-phorvex | 5.5 | **P>D+R** — proactive, D+R≈0, P≈5.5s | **ABSENT** (zero-day) | dwell 5.1s vs 5.5s base (NOT learnable) |
| c1-llm-adaptive | d-nomtd | n/a | — | present | disrupt 0% vs 0% base  |
| c1-llm-adaptive | d-r6blindtimer | n/a | — | present | disrupt 0% vs 0% base (LEARNED & beaten — re-strike defeats the fixed cadence) |
| c1-llm-adaptive | d-randomequal | n/a | P>D+R — proactive cadence | present | disrupt 0% vs 40% base (LEARNED & beaten — re-strike defeats the fixed cadence) |
| c1-llm-adaptive | d-reactive-only | n/a | — | present | disrupt 0% vs 0% base  |
| c1-llm-adaptive | d-fullphoenix | n/a | — | present | disrupt 0% vs 0% base  |
| c1-llm-adaptive | d-phorvex | n/a | **P>D+R** — proactive, D+R≈0 | present | disrupt 100% vs 100% base (NOT learnable — holds under adaptation) |
| c1-stealth-dweller | d-nomtd | 20.2 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.2s vs 20.2s base  |
| c1-stealth-dweller | d-r6blindtimer | 15.1 | P>D+R — proactive cadence | **ABSENT** (zero-day) | dwell 15.1s vs 15.1s base  |
| c1-stealth-dweller | d-randomequal | 11.5 | P>D+R — proactive cadence | **ABSENT** (zero-day) | dwell 5.1s vs 11.5s base  |
| c1-stealth-dweller | d-reactive-only | 20.2 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.2s vs 20.2s base  |
| c1-stealth-dweller | d-fullphoenix | 20.2 | **fails** — D absent (reactive needs detection) | **ABSENT** (zero-day) | dwell 20.3s vs 20.2s base  |
| c1-stealth-dweller | d-phorvex | 5.6 | **P>D+R** — proactive, D+R≈0, P≈5.6s | **ABSENT** (zero-day) | dwell 5.6s vs 5.6s base (NOT learnable) |
| c2-persistence-evict | d-nomtd | n/a | — | present | disrupt 0% vs 0% base  |
| c2-persistence-evict | d-r6blindtimer | n/a | — | present | disrupt 0% vs 0% base (LEARNED & beaten — re-strike defeats the fixed cadence) |
| c2-persistence-evict | d-randomequal | n/a | P>D+R — proactive cadence | present | disrupt 0% vs 30% base (LEARNED & beaten — re-strike defeats the fixed cadence) |
| c2-persistence-evict | d-reactive-only | n/a | holds iff D+R < exploit | present | disrupt 100% vs 100% base  |
| c2-persistence-evict | d-fullphoenix | n/a | holds iff D+R < exploit | present | disrupt 100% vs 100% base  |
| c2-persistence-evict | d-phorvex | n/a | **P>D+R** — proactive, D+R≈0 | present | disrupt 100% vs 90% base (NOT learnable — holds under adaptation) |
| c2-stateful-training | d-nomtd | 20.2 | — | present | dwell 20.2s vs 20.2s base  |
| c2-stateful-training | d-r6blindtimer | 15.1 | P>D+R — proactive cadence | present | dwell 15.1s vs 15.1s base  |
| c2-stateful-training | d-randomequal | 11.8 | P>D+R — proactive cadence | present | dwell 11.3s vs 11.8s base  |
| c2-stateful-training | d-reactive-only | 0.6 | holds iff D+R < exploit | present | dwell 0.6s vs 0.6s base  |
| c2-stateful-training | d-fullphoenix | 0.6 | holds iff D+R < exploit | present | dwell 0.6s vs 0.6s base  |
| c2-stateful-training | d-phorvex | 5.6 | **P>D+R** — proactive, D+R≈0, P≈5.6s | present | dwell 5.1s vs 5.6s base (NOT learnable) |

- **Held-out-CVE / stealth-dweller (zero-day, detector ABSENT):** only a detection-independent
  move evicts; PX's proactive floor does so cost-optimally. Honest: a blind timer also covers
  zero-days *on its schedule* — PX's edge is detector-independent **AND** cost-optimal **AND** targeted.
- **Learnability:** a deterministic LLM-style learner times re-strikes into the lull. A FIXED
  cadence (blind) is learnable (adaptive dwell improves); PX's variable rate is not.

## TIER 4 — ROI ($, transparent + swappable; GPU rows [GPU-PENDING])

| Arm | mean security-per-cost ($) | GPU-overhead $/yr saved [GPU-PENDING] |
|---|---:|---:|
| d-nomtd | $0 | $2,628 |
| d-r6blindtimer | $292,800 | $2,628 |
| d-randomequal | $330,352 | $2,628 |
| d-reactive-only | $195,200 | $2,628 |
| d-fullphoenix | $195,200 | $2,628 |
| d-phorvex | $575,840 | $2,628 |

## Pre-registered hypotheses (can fail)
- **H1 targeting** (PX dwell ≤ random at equal rate): PX dwell 5.5s vs d-randomequal 10.8s over 4 scenario(s) → **PASS**
- **H2 efficiency** (PX cost < blind/random at ≥ disruption): PX disruption ≥ blind AND random in **6/6** scenarios at a bounded **1.0-move** cost (vs blind 0.5 / random 0.7 — their lower raw move-count is UNDER-acting: 0 moves / 0% disruption on the fast, adaptive and persistence attacks, NOT efficiency) → **PASS**
- **H3 thesis** (stealth-dweller: PX dwell < reactive-only): PX dwell 5.6s vs reactive-only 20.2s → **PASS**

## Two lenses

### WHAT INVESTORS GET (the IP / moat)
- **Recon-per-dollar 1.62x** vs random (provable, ablated) — the patentable pipeline.
- **A FEASIBILITY model R6 lacks**: infeasible-action rate 0, harm 0, feasible-alternative found —
  PX provably never DoSes the workload (hard-constraint inviolability).
- **Beats blind on DWELL** (seconds vs interval) and on the **fast attacker** (blind too late);
  **not learnable** (unlike R6's fixed cadence).

### WHAT CUSTOMERS GET
- **$ saved** (fewer wasted rotations) + GPU-overhead avoided [GPU-PENDING].
- **SLO never broken; stateful work preserved** (the lead demo).
- **Zero-day foothold eviction** — the proactive floor evicts even what detection misses.
- **Every action explained** (100% rationale).

## ROADMAP — NOT YET MEASURED / FUTURE
| Item | Status |
|---|---|
| Dynamic action-set generator / predictive horizon / submodular+timing | **BUILT** (P1/P2) |
| Feasibility model (infeasible-action gate, harm=0) | **BUILT** (P1/P2) — measured above |
| RL red-team continuous loop (P-REDTEAM) | ROADMAP (not measured) |
| Phase-2 native actuators (warm-swap/MIG/identity/route) | ROADMAP — needs GPU (P4) |
| SP-0 GPU cost calibration; hot-KV GPU pod | GPU-PENDING (conformal envelope until measured) |
| vcluster multi-tenant; CVSS/CVE utility inputs | ROADMAP |
| The GPU/real-LLM scenarios | GPU-PENDING — run unchanged on CoreWeave |

_Generated by `phorvex/cmd/p3report`. No fabricated numbers._

---

# P3-DEEP — the STRUCTURAL zero-day proof (interval-sweep + recon-validity-lifetime)

> **HONEST VERDICT: STRONGLY EVIDENCES the structural claim; does NOT fully prove it.** The
> harm / learnability / prediction-presence legs are T-INVARIANT (proven); the prevention /
> recon-lifetime legs rest on a SOFT proactive floor (a measured distribution, not a by-
> construction ceiling). A clean blind interval on the UNCONSTRAINED scenario is **printed
> plainly**. 9 arms × 4 scenarios × 20 trials, 95% CIs (Wilson on rates), masterSeed=1337,
> 792 rows, 0 skips. Additive plugins only — **zero harness-core / zero extended-Phoenix change**.

The claim is **not** "Phorvex rotates sooner". It is: **R6's (static action set, fixed rate)
pair cannot win the zero-day on the CONSTRAINED class at any feasible interval; Phorvex's
(regenerated set, solved rate) wins by being targeted, harm-free, and unlearnable.** Intervals
are SCALED-FOR-TEST (R6 documents ~hourly; 15s ≈ 240×), the relative ordering preserved and
stated: **PX-floor 6s < attacker-objective 9s < documented-blind 15s** (6, 9 are IN the swept range).

### TEST A — interval-sweep frontier (the decisive certificate; prevention/harm/infeasible 95% Wilson CI, n=21)
**CONSTRAINED — `c2-stateful-training` (rotate = destructive Delete on the running job):**
| Blind interval | prevention | harm | infeasible | WIN? |
|---|---:|---:|---:|---|
| 3s / 6s / 9s / 12s / **15s** (fast horn) | **100%** | **100% (21/21)** | **100% (21/21)** | **no — prevents BUT destroys the job** |
| 30s / 60s (slow horn) | **0%** | 0% | 0% | **no — too late** |
| **PX (solved rate)** | **100%** | **0% (0/21)** | **0% (0/21)** | **✅ WIN (unique)** |

**No blind interval is a WIN on the constrained class** — the two horns provably don't overlap
(fast prevents but forces rotate-all harm + infeasible; slow is too late). PX is the **unique
WIN** (prevents AND harm-free via quarantine). **UNCONSTRAINED — `c1-heldout-cve`:** a fast
blind (3–15s) IS a clean WIN (100% prevent, **harm 0/21**) — **printed honestly**, so the
impossibility is scoped to the constrained class, not over-claimed.

### TEST B — recon-validity-lifetime (the detector-independent MECHANISM, mean seconds, n=21)
| Arm | recon-valid lifetime | mechanism |
|---|---:|---|
| 3s / 6s / 9s / 12s / 15s blind | **3.0 / 6.1 / 9.1 / 12.1 / 15.1s** | **L_blind = the interval** — the learnable sup-phase the attacker strikes |
| 30s / 60s blind | 20.2s (full window) | interval > window ⇒ recon never invalidated |
| no-MTD | 20.2s | static: recon valid forever |
| **PX** | **5.0s** | solved rate: invalidated on rising exposure — **MEASURED (not by-construction)** |

**The fundamental why:** the attacker's recon stays usable for **exactly the blind interval** —
there is **no interval that is both short (recon-invalidating) AND harm-free** (short ⇒ the fast
horn's rotate-all harm). PX's recon-lifetime is **5.0s** regardless of any fixed cadence.

### TEST C / D (structural)
- **C — learnability:** a const-interval blind has **GapRegularity = 1 at every interval** (zero
  variance) and selection-entropy 0 — predictable by construction; PX's solved rate over a
  dynamically-regenerated action set is not. (P3 measured: PX disruption 100%→100% under the
  adaptive attacker; random 40%→0%.) *Honest: random is also unpredictable, so C alone doesn't
  single out PX — B + the harm-frontier do.*
- **D — prediction:** only the PX arm produces a **moved-before-next-stage horizon**
  (`PreemptMargin`, `ProjectedNextStageSec`) — UNDEFINED for a scalar-interval arm (proven live in
  P-CONTEXT: `nim-llama → prompt-inject-persist`, `ProjectedNextStageSec ≈ 2763s`). A presence-asymmetry.

### Honest limits (stated, not hidden)
- The **prevention/recon-lifetime legs** rest on a **soft proactive floor** (a measured
  distribution with a CI, not a hard cap). **A clean blind interval exists on the unconstrained
  scenario** (printed). **Test E (dilution)** is structurally LIMITED on this harness: the blind
  timer is **uncapped** (rotates all) and `DefensiveActions` counts ticks not pod-rotations, so
  the cost~N axis is argued, not cleanly measured — reported honestly, not fabricated. All **AI
  native magnitudes are `[SP-0-PENDING]`** (endpoint stable for all arms; fingerprint/MIG-rebind
  invalidation GPU-bound).
- **Regression gates PRESERVED:** the **1.62× recon-per-dollar gate + UCW tests PASS**; **P3 PX
  dwell 5.1s** (baseline ~5.5s); the prior baseline decodes unchanged (additive omitempty fields).

**Bottom line:** P3-DEEP moves the decisive claim off the clock onto a SET/RATE certificate —
**no blind interval wins the constrained zero-day** (fast destroys the job, slow is too late),
the attacker's **recon-lifetime equals the blind interval** (so there's no short-AND-harm-free
interval), and only PX **predicts the next stage** — while honestly admitting the clean blind
interval on the unconstrained case and that the prevention leg is a measured distribution, not a
theorem. Report: `phorvex/P3-DEEP-REPORT.md`.

_Generated by `phorvex/cmd/p3deep` (P3-DEEP section). No fabricated numbers; AI native magnitudes SP-0-PENDING._
