# P-CONTEXT — Step 1 decision: the both-products context model

**Date:** 2026-06-06 · **Status: DECISION FOR APPROVAL — STOP before building (Steps 2–3).**

Give CONTEXT the same discovered-and-proven treatment physics got: complete and beat the
PRD+P1 context (belief/P(hold)+memory, kill-chain stage, predictive horizon, value/blast,
spread) **for BOTH the K8s and AI/inference products (co-equal, mandatory)**, feeding the
**UNCHANGED** optimizer / proactive engine / dynamic-action-set generator / actuation /
extended Phoenix through the existing `ContextProvider`/`BeliefEstimator`/`FactContext`
seams + the engine-owned `killchain.Assess` (the one authorized belief-wall edit).
Deterministic, no LLM in the decision path.

**Method.** A 5-expert-persona search (detection/SOC & kill-chain, Bayesian/sequential
inference, AI/ML inference security, graph/blast-radius, offensive security): 4 mapped the
PRD+P1 gap; 5 contributed quantified signals; candidates were generated per spine and
**adversarially scored** (the synth re-ran the CI gates uncached and measured the key
divergence numerically). Two candidates scored cleanly (one scorer agent failed to emit
structured output and is excluded). I authored this decision from the structured result;
every load-bearing claim was code-verified against `phorvex/internal`.

---

## 1. Candidates (both eligible, both-products-first-class, all quantified)

| Candidate (spine) | Total | Verdict | Note |
|---|---:|---|---|
| **Predictive-Horizon CONTEXT** ✅ | **35/40** | preserves (improve unproven) | Coherent Weibull-**survival** kill-chain unifying P(hold)+hazard, AI stages as a parallel chain, the cleanest seam routing (belief solely through `Assess`+`conjugate.go`). |
| Survival-Spine (Bayesian-belief-first) | 34/40 | preserves | Near-identical substance + same honest live-β deferral; lost 1 pt on two attribution cracks (mis-attributed the `BeliefEstimator` seam to the P0 engine; undersold the new InfectedSet state). |

They are near-identical in substance; the winner carries one fewer crack. The decision
**adopts the winner and grafts the Survival-Spine's belief upgrades** (they're the same set).

---

## 2. THE MANDATORY CORRECTION (the preservation bug the search caught — applied before any claim)

Both candidates proposed rewriting P(hold) as a **survival function of the existing Weibull
hazard (shape=2)**. The synth ran it: the baseline just-moved damping is **shape=1**
(`1-exp(-t/30)`, `hazard.go:175`); the rewrite is shape=2. They are equal only at t=30s and
in the saturated t≥600s region — **at t=60s they diverge by +0.117 damping / +0.025 PHold on
the GENERIC path.** The CI gates pass only because the tests probe t=1 (both <0.1) and t=3600
(both 1.0), never mid-exposure — i.e. by **threshold luck, not equivalence**.

> **Correction (load-bearing):** gate the survival-form PHold rewrite behind
> `ModelID!='' || HasGPU`, exactly like every other AI term. The **generic K8s belief layer
> is left byte-identical to P1** (it is already correct); the survival sharpening fires ONLY
> for AI workloads where it is genuinely new. This restores true generic byte-identity →
> the 1.62× gate and P3 dwell are preserved **by construction**, not by luck.

This is the difference between an honest "preserves the baseline" claim and an unnoticed
generic-path regression. It is in the recommendation as a hard precondition.

---

## 3. RECOMMENDATION — build the **Predictive-Horizon CONTEXT model** (one phorvex-own edit set)

Land a single set of edits to **phorvex-own** `killchain` + `conjugate.go` (the optimizer,
dual, conformal, actuation, proactive engine, dynamic-action-set generator, **extended
Phoenix, and the harness stay untouched**; everything propagates through the existing
`factCtx` closure and the EMR weight `AssetValue·PHold·urg`):

### 3a. AI kill-chain — 4 stages (parallel chain, ordinals 5–8), values `[SP-0-PENDING]`
| Stage | Signature (sensed off EXISTING fields — never a new SecurityEvent.Type) | Consequence | Sojourn | Successor |
|---|---|---:|---:|---|
| **GPUSideChannel** | `HasGPU && CoResidency>1 && ModelRarity>1` + no exploit yet, or a DCGM util-leakage event | 0.15 | 300s | ModelTheft |
| **ModelTheft** | side-channel + high leakage (`SMOccupancy+VRAMFraction+CoResidency`) reconstructing a rare model | **0.9** | 180s | Impact |
| **LLMJacking** (B1) | `EndpointPath!=''` + compute-abuse signature (Falco crypto / GPUUtil·TokensPerSec spike) | 0.6 | 900s | Impact |
| **PromptInjectPersist** (B3) | `ModelID!='' && KVRebuildSec>0` + a Persist-class (Panic/Drift) event | 0.65 | 3600s | Lateral |

**The `killchain.Assess` edit (the single authorized belief-wall crossing)** classifies by
highest-precedence AI signature first, else falls through to the **unchanged** generic
5-stage `stageFromEvent` byte-for-byte. **Three mandatory companion edits** (or the model is
silently wrong): (a) add the 4 AI scales to `NewModel.SojournScale` (else the `scale<=0`
fallback inherits the 1800s recon dwell); (b) add the 4 AI cases to `consequence()` (else it
defaults to 0.1); (c) replace `next=stage+1` (`hazard.go:151`) with a per-stage successor map
`AINextStage` — **a parallel chain has no linear +1 successor** (the one structural defect the
baseline cannot absorb). **PromptInjectPersist overrides `RecoverScale=max(30,KVRebuildSec)`**
so P(hold) does **not** collapse to ~0 after a rotation (a persisted KV/agent implant survives
a wipe — the single place the generic 30s damping is *provably wrong*). Honest-absent:
`ModelID=='' && !HasGPU` → no AI signature → successor map = `next+1`, RecoverScale = 30s.

### 3b. Belief upgrades (in `conjugate.go` + the gated Assess PHold block)
- **survival-form P(hold)** (AI-gated per §2) — unifies the three unrelated number systems into one Weibull.
- **UCB confidence channel** from the discarded `(a+b)` evidence mass (thin-evidence tenant treated as uncertain, not point-estimated).
- **hierarchical empirical-Bayes prior** — per-tenant posterior shrinks toward a fleet base-rate instead of the hand-picked `Beta(1,4)=0.2` cold-start.
- **negative-evidence wiring** — a moved asset with no follow-on event → `Observe(tenant, <0)` so the posterior can **fall**; fixes the **monotone confirmation-bias ratchet** the search found (`coverage.go:303` only ever increments up). *The math already exists (`conjugate.go:73-74`); only the wiring is missing.*

### 3c. Predictive horizon → the new measurable "moved-before-next-stage"
Two additive `Assessment` fields, pure closed-form reads of the existing Weibull (no consumer change):
- **`PreemptMargin = 1 − weibullCDF(exposure + moveLatency, scale, shape)`** = P(the stage has NOT transitioned to its successor by the time our move lands) ∈ [0,1].
- **`ProjectedNextStageSec = SojournScale·(−ln(1−0.5))^(1/shape) − exposure`** = seconds to the median next-stage transition.
- **Run-time fleet aggregate** `(#moves where moveDwell < ProjectedNextStageSec)/(#moves)` is the falsifiable number the baseline never had — **but it needs a new harness counter, which the zero-harness-change scope forbids**, so it degrades to the per-asset decision-time form (which is fully claimable). K8s generic-stage preempt is **live on kind**; AI magnitudes are SP-0.

### 3d. Value/blast + live-β — Tier-1 resolved, full SIR deferred (honest)
- **RESOLVED NOW (no belief-wall crossing):** `InfectionFrontierMultiplier ∈ [1,1+κ]` — "this pod touches a known-infected neighbor", where `InfectedSet` is reconstructed from `TargetsPod≥Exploit` events (firstSeen/lastSeen). Rides `AssetValue/BlastRadius` via `factCtx`, **zero at empty-I** (so the 1.62× tie + ucw nil-data invariant reproduce), separately ablatable. Plus a **GPUColocationEdge** (shared Node/MIG, both GPU) blast edge for B2.
- **DEFINITIONS delivered** (values may be pending, definitions may not): `β̂` (per-contact transmission prob), `γ̂` (per-tick clearance), `R0 = β̂/γ̂·mean-degree` — reusing the ConjugateMemory negative-evidence path.
- **DEFERRED-WITH-REASON:** the full `dI/dt = βSI − γI` **value** — β is non-observable fast enough to act on and non-falsifiable without injected-infection ground truth the harness doesn't provide. Claiming a live β value would violate the falsifiability gate. *Honest cost: Tier-1 needs genuinely NEW per-tick InfectedSet state (not "zero machinery"); reconstruction under-counts → a safe lower bound.*

---

## 4. PRD-context completed-and-beaten map (code-verified)
- **Asset value / blast** [built] → + GPUColocationEdge (B2 co-location) + Tier-1 infection frontier (zero at empty-I).
- **Workload phase / SLO headroom** [built] → preserved unchanged.
- **Threat posture** [built, **AI-blind**] → 4 AI stages classified in `Assess` off Pod+Physics+Telemetry+SecurityEvent strings (no new Type).
- **Exposure** [built] → + GPUCoResidencyExposure (AI recon-accrual).
- **Kill-chain** [5 generic stages] → **4 AI stages** (parallel chain) + the successor-map fix + the KV-keyed RecoverScale fix.
- **Predictive horizon** [Weibull hazard, lead-time computed-then-discarded] → surfaced as `ProjectedNextStageSec` + `PreemptMargin`.
- **Belief / P(hold)** [Beta + noisy-OR + damping, three unrelated systems; mass discarded; monotone ratchet] → survival posterior (AI-gated) + UCB confidence + hierarchical prior + negative-evidence (posterior can fall).
- **Spread / SIR** [static only] → Tier-1 frontier now; β̂/γ̂/R0 defined; full SIR deferred-with-reason.
- **Domain priors** [P-PHYSICS, FactContext-only] → now also read in the belief layer (CoResidency/ModelRarity/KVRebuildSec gate the AI stages).

---

## 5. Honest baseline assessment — **preserves now; improves only under conditions**
- **PRESERVES (proven):** with the §2 correction applied, the generic K8s path is byte-identical; the CI gates the synth re-ran uncached all PASS — 1.62× (`TestAblationP1BeatsRandomPerDollar`), `TestUCWScarcityTiesAtUniform`/`LiftsUnderDispersion`, and the four killchain tests. NeutralPhysics sets every AI multiplier to 1.0; AI recon facts stay **audit-only**; the ucw uniform-scarcity is a constant-scale invariant. So **1.62× + P3 dwell/feasibility are preserved by construction.**
- **IMPROVES (UNPROVEN today — paper until conditions hold):** every measurable beat is conditional — the survival/confidence/hierarchical/negative-evidence upgrades only diverge from the point estimate when their trigger exists (AI fact, thin evidence, fleet base-rate gap, a measured no-follow-up outcome); the AI-stage urgency/successor/KV-RecoverScale fire only for `ModelID!=''||HasGPU`, and **all AI magnitudes (300/180/900/3600s sojourns, AIRecoverScale, leakage rates) are `[SP-0-PENDING]` uncalibrated knobs** — no AI beat is falsifiable until a real GPU fleet calibrates them.
- **Net (plain):** the demonstrable deliverables today are the **STRUCTURE** (4 AI stages, successor map, the two horizon fields, the β̂/γ̂/R0 definitions, the belief upgrades) and the **generic-equivalence guarantee**. Measurable improvement is deferred to the conditions under which the new carriers light up. **"Baseline preserved, no measurable improvement yet" is the honest verdict** — and it dominates the baseline (never worse, strictly richer structure).

---

## 6. Honest scope + extensibility
**Zero change to** the optimizer, dual, conformal, actuation, proactive engine, dynamic-action-set
generator, **extended Phoenix, and the harness.** **Phorvex-own edits** to `killchain` (`Assess`,
`stageFromEvent`, `consequence`, `NewModel.SojournScale`, the `AINextStage` map, the two
Assessment fields) + `conjugate.go` (the belief upgrades) — all additive, AI-gated or honest-absent.
**One module = one signal/stage:** each AI stage = one entry in {classifier, SojournScale,
consequence, successor map}; each belief upgrade is an independent toggle collapsing to baseline
when its condition is absent; the horizon fields are pure closed-form reads. Per-tenant
(`ConjugateMemory` keyed by tenant), per-platform (PhysicsWitness from the scanner), deterministic.

---

## 7. Open risks (carried openly)
1. **Preservation mechanism (highest)** — the survival-form rewrite MUST be AI-gated (§2) or the generic path regresses at mid-exposure; re-run the gates after gating.
2. **All AI magnitudes `[SP-0-PENDING]`** — uncalibrated knob proposals; no AI beat falsifiable until a real GPU fleet.
3. **`plannedMoveLatencySec` implicit** — defaults to 0 and overstates preemption unless sourced from the actuator's measured per-action latency (live on kind for rotate/quarantine).
4. **AI classification reads heuristic SecurityEvent strings** — sensor-dependent; the matcher MUST fail-to-generic conservatively (never false-positive an AI stage on a generic pod) to protect byte-identity.
5. **Hierarchical pool** introduces cross-tenant coupling — τ small, restart-rebuilt (NFR3); verify it doesn't regress the memory-monotonicity test.
6. **Negative-evidence window** must be tied to the stage sojourn (KV-aware for PromptInjectPersist) so a slow attacker isn't falsely scored cleared.
7. **PreemptMargin fleet-aggregate** needs a forbidden harness counter → only the per-asset decision-time form is claimable.
8. **Tier-1 InfectedSet** is genuinely new per-tick state; reconstruction is lossy (under-counts = the safe direction).

---

## 8. If approved — Step 2 build + Step 3 proof
**Step 2:** the `killchain.Assess` edit (4 AI stages + classifier + the 3 companion edits + AI-gated
survival PHold + the successor map + KV-RecoverScale); `conjugate.go` belief upgrades (UCB confidence,
hierarchical prior, negative-evidence); the two horizon Assessment fields; the Tier-1 InfectedSet +
InfectionFrontierMultiplier + GPUColocationEdge; β̂/γ̂/R0 definitions. All AI-gated / honest-absent.

**Step 3 (prove on kind, REAL numbers):** show **AI kill-chain stages classified live** (deploy a
mock NIM/GPU-labeled pod so the signatures fire), the **predictive horizon projecting next stage** +
the **decision-time moved-before-next-stage (PreemptMargin/ProjectedNextStageSec)** measured on generic
K8s stages (live), per-tenant memory falling under negative evidence; **re-run the IP ablation + P3** —
**match-or-beat** 1.62× + dwell/feasibility (the honest expectation is an **exact preserve** at nil-data,
reported as such), claiming only what is measured; **AI values honestly `[SP-0-PENDING]`.**

**PASS filters:** go build/vet/test green; AI stages built + classified live on kind; predictive horizon
+ moved-before-next-stage measured (decision-time form); belief/memory decision shown (negative-evidence
posterior fall + hierarchical prior); ablation + P3 re-run with real numbers; deterministic, no LLM in the
decision path; both products first-class; extended Phoenix + harness build unchanged; nothing fabricated.

---

## 9. Decision
**Build the Predictive-Horizon CONTEXT model** — a both-products survival-kill-chain context that
completes the 4 AI stages (via the authorized `killchain.Assess` edit), surfaces the predictive horizon
as a measurable moved-before-next-stage, sharpens belief (survival posterior AI-gated, UCB confidence,
hierarchical prior, negative-evidence fixing the confirmation-bias ratchet), and resolves live-β to a
Tier-1 infection-frontier (full SIR honestly deferred) — all through the existing seams with the
optimizer/proactive/Phoenix/harness **untouched**. With the mandatory AI-gating correction it **preserves
1.62× + P3 by construction** and improves only under measured AI/dispersion/infection conditions. The AI
half is first-class in definition, honestly `[SP-0-PENDING]` in value.

**>>> STOPPING for your approval before building Step 2/3. <<<**
Approve the Predictive-Horizon model (with the AI-gated correction, as scoped), or tell me to adjust the
spine / belief upgrades / live-β boundary first.
