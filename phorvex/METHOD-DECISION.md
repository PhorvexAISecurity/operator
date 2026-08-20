# Phorvex P1 — METHOD DECISION (STEP 1 search result, for approval)

**Deterministic brain, NO LLM in the decision path.** This document recommends, with
reasoning, the best method for each of the three axes — **decision / recon-invalidation**,
**context model**, **cost model** — and how they compose into one architecture that
satisfies every P1 hard requirement. **Nothing has been built yet. Approve (or amend)
before STEP 2.**

---

## How the search was run (honest provenance)

A 3-phase multi-agent search (18 agents, ~1.1M tokens): **(1) generate** 3–4 candidate
methods per axis (grounded in the PRD/MVP + P0 + the security-game / MTD / combinatorial-
optimization literature, web-searched), **(2) adversarially verify** each candidate
against the eligibility gate — a skeptic agent tried to **refute** criterion (4) *and*
(5), defaulting to "refuted" when a proof was hand-wavy — **(3) synthesize**. **12
candidates** were generated and adversarially scored.

**One honest caveat:** a key-mismatch in my orchestration script left the three
synthesis agents without the candidate list, so they fell back to a *first-principles*
take and defaulted to the PRD's Stackelberg game. I therefore synthesized the final
recommendation **myself, directly from the 12 adversarially-verified candidates** (their
scores + refutation verdicts are reproduced below). The result diverges from the PRD
default — deliberately, per your instruction to "search for the BEST, don't just
validate the PRD." Full raw output is archived in the workflow transcript.

**Eligibility gate result:** all **4 decision-axis** candidates passed **(4) AND (5)**.
The context/cost candidates were marked "ineligible" by the gate only because criteria
(4) "beats random per-dollar" and (5) "has a proactive trigger" are properties of the
**decision method**, not of a supporting context/cost component — the gate doesn't apply
to them standalone (they *enable* the decision method's 4+5). They are ranked on the six
scores.

---

## TL;DR — the recommendation

| Axis | **Winner** | One-line why |
|---|---|---|
| **Decision** | **Cost-weighted Submodular Recon-Coverage maximization** over a *dynamically-generated* feasible action set, with a **Lagrangian budget-dual (λ)** that makes per-asset rotation **rate** an emergent decision variable | Criterion (4) *is its literal objective* — facts-invalidated-per-dollar — with deterministic online greedy (no MINLP), hard-constraints-by-construction, and exactness proved only for the shipped asset-keyed profiles. |
| **Context** | **Semi-Markov kill-chain belief with explicit sojourn-time hazard** (= the predictive belief horizon) + **Beta-Bernoulli P(hold)** + **per-tenant conjugate memory**, over the **P0 reachability graph** | The stage-exit hazard `h_s(t)` *is* the forward projection (fires before the next stage), is detector-independent, deterministic, and explainable. |
| **Cost** | **RLS self-calibrating** `C = λ₁·C_norm + λ₂·C_flow` with a **dual-descent budget shadow-price** (λ *solved*, not hand-set), hardened by **conformal robust upper-bounds** for the `[SP-0-PENDING]` GPU/KV-cache terms | Learns cost from telemetry online; λ is the timing knob; the unmeasured GPU term enters as a *provable* robust envelope (never fabricated), keeping SLO feasibility provable. |

These three **unify** into a single Lagrangian: the cost model supplies `C(m)` and the
dual price `λ`; the context model supplies the fact-weights `w = value × blast × P(hold)
× stage-hazard`; the decision engine greedily maximizes `Σ w(facts covered) − λ·C` over
the live feasible set. The **same dual λ** is the budget price, the timing rate (the
Whittle-index view), and the cost weight — one knob, three jobs.

---

## Axis A — DECISION / RECON-INVALIDATION METHOD

### Candidates evaluated (adversarial scores, 1–5; all four passed the 4∧5 gate)

| Candidate | seam | kind | IP | **perDollar(4)** | **0day(5)** | SLO | eligible |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Submodular Recon-Coverage Knapsack** (+ Lagrangian timing dual) | 5 | 5 | 5 | **5** | 4 | 5 | ✅ |
| Restless-Bandit / **Whittle-Index** proactive timing (novel) | 4 | 4 | 5 | 4 | **5** | 4 | ✅ |
| Markov-**Stackelberg** game (PRD default, hardened) | 5 | 3 | 3 | 4 | 4 | 4 | ✅ |
| Receding-Horizon **MPC** over the belief horizon | 4 | 3 | 4 | 4 | **5** | 5 | ✅ |

### Winner: **Submodular Recon-Coverage maximization + Lagrangian timing dual**

**Mechanism.** Define a per-tenant **fact-universe** `F`: each *recon fact* is a
`(variable, asset)` the attacker has learned or is *about to* learn — pod IP/identity,
node placement, image digest, network/lateral edge, KV/session state — weighted by
`w = asset_value × blast_radius × P(hold) × stage-urgency`. A move `m` (rotate or
quarantine on asset *i*) **covers** (invalidates) the subset `cover(m) ⊆ F`: a rotate
wipes identity + in-memory + session facts; a quarantine invalidates reachability/
lateral-edge facts without wiping local state. The recon-invalidation value
`g(S) = w(⋃_{m∈S} cover(m))` is **monotone submodular**, but the implemented objective
`g(S) − λ·C(S)` is **non-monotone** because of the cost penalty and is constrained by a
truncated partition matroid. The classic monotone/cardinality approximation guarantee therefore
does **not** apply. The shipped asset-keyed profiles have a separate, stronger structural proof:
their covers are block-owned, making the objective modular and the deterministic greedy exact.
Any future overlapping profile requires a new proof; no generic approximation constant is claimed.

**Why it wins (the six criteria + the P1 hard requirements):**
- **(4) per-dollar recon — its literal objective.** "facts-invalidated-per-dollar" is a
  number you *log and compare* against random (which covers a uniformly-random fact
  subset → strictly dominated in expectation). This makes the **STEP-3 ablation provable
  and falsifiable**, not rhetorical — the single biggest reason it beats the Stackelberg
  default.
- **(ii) Dynamic action-set generator — structural, not bolted-on.** The feasible action
  set *is* the candidate cover set: an infeasible move contributes no coverage, so
  feasibility generation and optimization are **one pass**. New primitives (future
  image/GPU/network rotation) just register a new `cover()` set — one file, no solver change.
- **(v) Hard constraints by construction.** Feasibility (PDB, resource conservation,
  affinity/taints, stateful-warm-first) + SLO filter the candidate set *before*
  optimization, so an SLO-violating move is **literally not selectable** — inviolability
  is a structural property, not a penalty term. (Provable: the selected set ⊆ the feasible
  set by construction.)
- **(iv) Timing as a decision variable.** The Lagrangian dual of the budget constraint
  yields a shadow price `λ`; the exposure clock continuously inflates the weight of facts
  the attacker has had time to re-learn; an asset fires exactly when its
  marginal-coverage-per-dollar crosses `λ` — **proactive, detector-free**, a rate not a
  cron. (This dual *is* the Whittle index restricted to the coverage reward — see graft.)
- **(vi) Solver shape.** Discrete = which `(asset,action)` selected; continuous = per-asset
  rate `r_i` + fact-weights. Nonlinear cost is fine because the objective is the
  per-**dollar** ratio (cost enters as knapsack weight / dual price, the greedy is agnostic
  to cost nonlinearity). **Offline precompute:** dual prices, fact→cover incidence,
  lazy-greedy priority. **Online:** lazy-greedy `O(B·|F|·log)` — well under 1 s, **no
  online MINLP**.
- **Explainable.** The marginal-gain decomposition per selected move **is** the SHAP-style
  attribution (which facts, what weight, what cost) — explainability falls out for free.

**(5) zero-day, stated honestly (HONESTY GUARD):** the proactive floor is the
`λ`-crossing driven by exposure-accrual + stage-hazard — it fires **with no detector**, so
on a held-out-CVE / detector-evading attack Phorvex still shrinks dwell by invalidating
the recon the attacker relies on. The claim is **"detector-independent, cost-optimal,
consequence-targeted dwell reduction" — NOT "uniquely stops zero-days"** (R6's blind
timer also covers zero-days on a schedule; the edge is that ours is cost-optimal and
consequence-targeted *per dollar*).

**Graft from the runner-up (Whittle-Index).** Adopt the renewal-theory **hazard-accrual
curve** `h_i(age)` and the **Whittle-index reading of the dual** as the formal optimality
argument for the per-asset rate (timing was the Whittle candidate's strongest dimension,
0day=5). The two are the *same Lagrangian relaxation of the budget constraint* — we get
submodular coverage's dynamic action-set IP *and* the bandit's provable timing optimality
from one dual. (Caveat honestly: Whittle optimality is *asymptotic in #arms*; on a tiny
kind cluster we validate empirically and do **not** over-claim optimality at small N.)

**Why NOT the PRD's Markov-Stackelberg game (the runner-up the synthesis agents defaulted
to):** it scored seam5 but **kind3 / IP3** — solving the game online is expensive,
offline policy-table precompute suffers state-explosion over a combinatorial action
space, and the optimal **mixed** strategy injects randomization that sits awkwardly with
"deterministic." It's also the *obvious* approach R6 already cites (weak IP). **We keep it
as the offline attacker-model *validity check*** (does our coverage policy approximate the
game's equilibrium value?), not as the online engine. MPC is kept as the conceptual basis
for the **receding-horizon belief lookahead** (graft its forward-projection, not its
online QP).

---

## Axis B — CONTEXT MODEL

### Candidates evaluated (scores 1–5; eligibility N/A — supporting component)

| Candidate | seam | kind | IP | perDollar | 0day | SLO |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **HSMM-Hazard** (semi-Markov sojourn/dwell) | 4 | 3 | **5** | 4 | **5** | 4 |
| BAG-Belief (Bayesian attack-graph, junction-tree) | 5 | 4 | 3 | **5** | 3 | 5 |
| BetaHold (Beta-Bernoulli P(hold) + conjugate memory) | 5 | **5** | 2 | 3 | 4 | 5 |
| DS-Ignorance (Dempster-Shafer, explicit ignorance) | 3 | 3 | 4 | 3 | 4 | 4 |

### Winner: **Semi-Markov hazard belief + Beta-Bernoulli P(hold) + per-tenant conjugate memory, over the P0 graph**

**Core = HSMM-Hazard.** A semi-Markov kill-chain model (Recon→Exploit→Persist→Lateral→
Impact) with **explicit per-stage sojourn (dwell-time) distributions**. The stage-exit
**hazard `h_s(t)` is literally the predictive belief horizon (iii)**: it rises as dwell
accrues and as the projected stage approaches a high-consequence transition (e.g. an
imminent lateral pivot), so it tells the action-set generator to *pre-materialize*
"quarantine-the-edge" or "rotate-now" **before** the attacker acts — detector-independent
(best-in-axis on 0day=5, IP=5). Inference is a closed-form forward recursion (deterministic,
explainable: most-likely stage + sojourn), `O(|S|²·Dmax)` with bounded `Dmax` → ≪1 s.

**Grafts (this is a layered model, each piece one file):**
- **Beta-Bernoulli `P(hold)` + per-tenant conjugate memory** (from BetaHold, kind=5):
  cheap, deterministic, closed-form posterior arithmetic; the **conjugate memory is the
  per-tenant learned-prior / context-MEMORY layer** (a tunable). Critically it **covers
  HSMM's cold-start** — when SecurityEvents are sparse on kind, the stage belief leans on
  the conjugate prior until events accrue.
- **Forward-hop reachability belief over the P0 graph** (from BAG-Belief, seam=5,
  perDollar=5): mark which edges are *about to be traversed* into high-value nodes, so the
  generator surfaces edge-cut (quarantine) candidates on exactly those paths. Reuses the
  P0 NetworkPolicy+RBAC graph — zero new ingest.
- **Explicit-ignorance flag** (from DS-Ignorance): when stage confidence is low (a careful
  detector-evader), *say so* and lean on the hazard floor rather than a confident-but-wrong
  stage — the honest behavior on the decisive stealth-dweller scenario.

**Honesty:** the hazard **raises the rotation rate; it never relaxes a hard constraint**
(the SLO/budget guarantee lives in the optimizer, not here). The held-out-CVE benchmark
must show the **hazard-driven proactive floor** (not stage *classification*) shrinks
dwell — else criterion (5) collapses to "smarter reactive"; we test for exactly that.

---

## Axis C — COST MODEL

### Candidates evaluated (scores 1–5)

| Candidate | seam | kind | IP | perDollar | 0day | SLO |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **RC-DD** (RLS cost + dual-descent shadow-price) | 5 | **5** | 4 | **5** | 4 | 5 |
| **CDR-Cost** (conformal distributionally-robust) | 5 | 4 | **5** | 4 | 4 | 5 |
| KCF-KKT (Kalman cost filter + KKT dual) | 4 | 4 | 4 | 4 | 4 | 5 |
| EWMA-HP (pragmatic baseline) | 5 | 5 | 2 | 3 | 3 | 4 |

### Winner: **RC-DD (RLS + dual-descent λ) hardened with CDR-Cost conformal bounds**

**Core = RC-DD.** `C = λ₁·C_norm + λ₂·C_flow`. `C_flow` is nonlinear in the raw pod state
but **linear in engineered features** (phase one-hot, saturated gpu/load), so **recursive
least squares** gives a closed-form *online* fit of a nonlinear cost surface, calibrated
from observed rotations — **self-calibrating from telemetry** as required. **λ is solved,
not hand-set:** projected-subgradient **dual descent** on the budget/SLO constraint yields
λ as the **budget shadow-price**. λ **is the timing knob** — rotate when accrued exposure
risk crosses `λ·marginal-cost` — the *same* λ the decision engine uses (one knob, three
jobs). RLS update + dual step run on the telemetry-ingest cadence **offline**; online is
just `Ĉ_flow = φᵀθ` + top-B → `O(N log N)`, ≪1 s, **no MINLP**.

**Graft = CDR-Cost conformal robust bound (highest IP=5).** The `[SP-0-PENDING]` GPU/
KV-cache/warm-load terms enter as a **conformal/interval upper bound `C_hi`** computed
offline from the residual stream. **Feasibility uses `C_hi`; the objective uses `E[C]`.**
This is the clean way to keep the **SLO guarantee provable while a coefficient is literally
unmeasured**: a move whose *worst-case* disruption would breach SLO is removed from the
feasible set with a coverage guarantee — and we **never fabricate a GPU-$ number** (the
`[0, C_gpu_max]` envelope is a *declared engineering bound*, not a measurement; it tightens
to a real value only after SP-0).

**Honesty / hard-cap discipline:** dual descent gives an *asymptotic* (regret-bounded)
budget guarantee; the **hard move-budget B is still enforced as an inviolable top-B
truncation** — λ only shapes *which* B. Pre-SP-0 the GPU coefficient stays a flagged prior;
**no learned GPU-$ figure is reported before SP-0.**

---

## The unified architecture (and how it drops into the P0 registries)

```
exposure clock ─┐                          ┌─ FeasibilityConstraint registry (Layer A, HARD)
                ▼                          ▼      → DYNAMIC ACTION-SET GENERATOR (live feasible (asset,action) set)
 ContextProvider/BeliefEstimator ──► fact-weights w = value×blast×P(hold)×stageHazard(t)
                │ (semi-Markov hazard = predictive horizon; conjugate per-tenant memory)
                ▼
 CostModel (Layer B, SOFT): C(m) via RLS  +  λ via dual-descent  +  C_hi conformal (GPU [SP-0-PENDING])
                │
                ▼
 DECISION: submodular greedy  max Σ w(facts covered by S) − λ·C(S)   over the generated set, until budget B / λ-crossing
                │  (marginal-gain log = SHAP-style attribution; no generic ratio claimed; no MINLP)
                ▼
        Seam 1: emit SecurityEvent + maintain AMTD  →  Phoenix runs delete | quarantine
```

- **PhysicsProfile** → the per-tenant *perturbable variables + cost map + recon-fact map*
  (the `cover()` incidence: which facts each action invalidates).
- **FeasibilityConstraint registry** → Layer A hard gate **and** the dynamic action-set
  generator (one pass).
- **CostModel** → RC-DD + conformal `C_hi`; emits `C(m)` and the dual `λ`.
- **BeliefEstimator + ReconInvalidation** → semi-Markov hazard with the **predictive belief
  horizon**; the fact-weight accrual.
- **ContextProvider** → value/blast (P0 graph), kill-chain stage, P(hold), conjugate memory.
- **Decision engine** → submodular coverage greedy (replaces P0's `risk−λ·cost` top-B).

Every box is an existing P0 interface → P1 is a **drop-in** of new registry impls + a new
optimizer, **zero change to the P0 skeleton, the Phoenix seam, or extended Phoenix**.

### Solver-shape compliance (the hard requirement), in one place
- **Mixed discrete + continuous:** discrete = selected `(asset,action)`; continuous =
  `λ`, RLS `θ`, per-asset rate `r_i`, fact-weights.
- **Nonlinear cost:** absorbed via per-dollar ratio + RLS-on-engineered-features + conformal
  endpoint (all closed-form; no global nonlinear solve).
- **Offline precompute → fast online:** offline = dual prices/Whittle table, fact→cover
  incidence, RLS/dual updates, HSMM kernels, conformal quantiles. Online = lazy-greedy +
  table lookups, `O(B·|F|·log)` / `O(N log N)`, **< 1 s for ≤1000 assets, NO online MINLP.**
- **Inviolable hard constraints:** feasibility+SLO prune the candidate set *before*
  selection (and CDR's `C_hi` certifies the SLO prune) → a violating move is unselectable
  by construction; cost/λ are soft objective terms only.

---

## What STEP 2 would build (preview — for your approval)

Per your spec, as **modular swappable interfaces** (each = one file, zero core change):
1. **PhysicsProfile** — per-tenant perturbable variables + cost map + **recon-fact `cover()`
   map**.
2. **FeasibilityConstraint registry (Layer A)** — PDB, resource conservation, affinity/
   taints, stateful-warm-first — **doubling as the DYNAMIC ACTION-SET GENERATOR** (core IP,
   explicit + tested: the set provably changes with state).
3. **CostModel (Layer B)** — RLS self-calibration + dual-descent λ + conformal `C_hi`;
   GPU/KV terms `[SP-0-PENDING]`.
4. **BeliefEstimator + ReconInvalidation** — semi-Markov hazard with the **predictive belief
   horizon** + per-tenant conjugate **context-memory**.
5. **per-variable exposure clock → proactive engine** — rotation rate as a *solved* decision
   variable (λ-crossing), event-risk raises it, never detector-gated.
6. **Decision engine** — submodular recon-coverage greedy over the generated set; SHAP-style
   marginal-gain attribution; **provable hard-constraint inviolability** (a test that asserts
   no SLO-violating move can ever be returned).
7. **STEP-3 IP ablation on kind** — perturbing a recon variable invalidates the generated
   attacks **more per dollar** than random rotation; reported with **real numbers**; if it
   fails, we say so.

**Open risks carried honestly:** (a) the **fact-universe taxonomy** is the IP-critical
modeling step — facts must be crisply tied to measured exposure variables or the per-dollar
number is unfalsifiable; (b) **correlated facts** remove the shipped modular/exact structure —
they need careful `cover()` sets and a fresh proof; (c) **SP-0 unmeasured** → GPU/KV cost stays a conformal envelope,
no fabricated number; (d) Whittle/dual optimality is **asymptotic** — validated empirically
at small N, not over-claimed; (e) the held-out-CVE benchmark must show the **hazard floor**
(not stage classification) shrinks dwell, or (5) reduces to "smarter reactive."

---

## Decision requested

**Approve** this stack (Submodular Recon-Coverage + Lagrangian/Whittle timing · Semi-Markov
hazard + conjugate memory · RLS+dual-descent+conformal cost), or tell me which axis to
swap to its runner-up:
- Decision → Markov-Stackelberg game (PRD default) or Whittle-index-first timing.
- Context → BAG junction-tree-first, or the simpler BetaHold-only.
- Cost → CDR-conformal-first, or the pragmatic EWMA-HP baseline.

I will not write any P1 code until you approve.
