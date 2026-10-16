# P3-DEEP — Step 1 decision: the structural zero-day experiment

**Date:** 2026-06-06 · **Status: DECISION FOR APPROVAL — STOP before building (Steps 2–3).**

Prove the zero-day advantage is **STRUCTURAL, not a timing race**. The claim is not "Phorvex
rotates sooner"; it is: **R6's (STATIC action set, FIXED rate) pair cannot prevent zero-days at
any feasible interval without unacceptable cost/harm, while Phorvex's (dynamically-regenerated
set, solved rate) does — by construction on the constrained class.** Built on the completed
physics (P-PHYSICS/UCW) + context (P-CONTEXT); additive harness plugins only; **zero
harness-core / zero extended-Phoenix change**; both K8s and AI products; deterministic.

**Method.** A 4-expert search (MTD theory, offensive-security/red-team, detection/SOC,
measurement/statistics): 4 seam-mappers → 4 experts → 3 experiment designs, **adversarially
scored** against an eligibility gate (ineligible if it only re-proves timing, is K8s-only, or
any metric is unquantified). The synth **verified every load-bearing claim against source and
ran the keystone divergence numerically.** I authored this decision from the structured result.

---

## 1. Candidates (all eligible, all "strong-evidence", all admit the clean interval)

| Candidate (spine) | Total | Structural verdict |
|---|---:|---|
| **Structural Zero-Day Suite** ✅ (A-frontier; B/C/D/E as why) | **33/35** | strong-evidence |
| PROBE-STRUCT (set-rate impossibility; C+D spine) | 33/35 | strong-evidence (provesStructural=5, mechanism=5; −1 harness fit) |
| RECON-LIFETIME LAW (B-spine) | 32/35 | strong-evidence (B partly re-measures dwell) |

The three are materially equivalent in rigor and honesty. The winner has the **cleanest
harm-sourcing** (reads the existing `[harm=...]` state-string marker — no new stamp) and the
best both-products + harness fit. It adopts PROBE-STRUCT's load-bearing insight: **put the
weight on the T-invariant SET/RATE/SCALE properties, not the clock.**

---

## 2. THE HONEST VERDICT — strongly evidences; does **not** fully prove (and that's the right call)

### Genuinely PROVEN (T-invariant — no interval value repairs them; code-verified)
- **A · harm/infeasible:** `rotateOnce` deletes **every** rotation-target pod with **no quarantine alternative** (`rotation.go:85-101`, verified — no per-asset targeting, no budget). On a stateful/PDB pod this **forces** harm>0 + infeasible>0 at *any* rate. A **feasibility-SET defect**.
- **C · learnability:** `GapRegularity = 1−CV = 1` at **every** interval for a zero-variance const cadence (`learner.go:87` + `d_r6blindtimer.go:41`); selection-entropy = 0 for a singleton action. Predictability is **intrinsic** to (fixed set, fixed rate).
- **E · dilution:** rotate-all is **uncapped** (cost ~ N) while PX is capped at `maxMovesPerTick=1` → a budget-conservation dichotomy (capped ⇒ protection ~ B/N; uncapped ⇒ cost ~ N). A **SCALE law**.
- **D · prediction-presence:** `PreemptMargin`/`ProjectedNextStageSec` are pure functions of a stage classifier + Weibull sojourn + successor **map** that **do not exist** in a scalar-T+label arm → the function is **undefined**, not merely worse (a capability-presence asymmetry, interval-invariant).

### Only STRONG-EVIDENCE (the keystone over-claim — verified, and corrected here)
- The **prevention** leg of A and the **recon-validity-lifetime inequality** in B over-reach. *"L_PX ≤ proactiveFloor = 6s by construction, regardless of phase"* is **not supported by the code**: the proactive floor enters `hazard.go` **only** as `exposurePressure = clamp01(exposureSec/proactiveFloorSec)`, blended via **noisy-OR** into `pHoldRaw` — a **soft belief/pressure term, NOT a hard inviolable cap**. PX evicts only when the submodular greedy actually selects the asset under budget — **probabilistic, not guaranteed**. So **`L_PX` is a MEASURED bound (report it as a distribution with a CI), not a constructive theorem.**
- **Test B is partly a re-measurement of timing** — `L_blind(learned) = T` is the inter-rotation gap (= the dwell bound) reframed. Its claim to be a *distinct* mechanism rests genuinely on **detector-independence** + the **sup(T) vs mean(T/2)** reframing — honest, but thin. **B is read JOINTLY with A, never alone.**

### The clean blind interval — it exists, and the design admits it head-on
**YES:** on the **unconstrained** `c1-heldout-cve` at **N=1**, a fast `T<9s` (below the attacker objective) **can prevent the zero-day harm-free** — the scenario's own code comment concedes the blind timer "covers it by luck/schedule." A rigged design would claim universal impossibility; **this one runs BOTH the unconstrained (c1) and constrained (c2-stateful+PDB) classes, narrows the impossibility claim to the constrained set, and PRINTS any clean blind row plainly.** That is the design's strongest integrity feature.

> **Required fix before execution (mandatory):** soften every "by construction / regardless of
> phase" on the floor to *"the floor drives the greedy to act before the objective with high
> probability under budget"*; report B's PX lifetime as a **distribution**, not a constant 6s;
> keep the **C+D-as-spine / A+B-as-consequence** framing so the suite never leans on the
> dwell-equivalent B alone.

---

## 3. RECOMMENDATION — build the Structural Zero-Day Suite (additive plugins; A decisive; B/C/D/E explain why)

**Arms:** all 6 already exist. **Test A** parameterizes the blind interval via a thin
self-registering `d_r6blindtimer_swept.go` wrapper (the shared `timerEngine.nextDelay` is a
per-instance closure — `rotation.go:35` — so a blind-at-T arm is one file, zero engine change).

**New scenario plugins** (one self-registering file each): `b_recon_lifetime.go` (500ms
UID/IP/nodeName poll on the at-risk pod), `e_dilution_fleet.go` (fleet-size sweep: N decoys + 1
at-risk), and a `c2-stateful-PDB` constrained variant (so the harm column has teeth). Reuse
`c1_fast_attacker`, `c1_heldout_cve`, `c2_stateful_training`, `ai1_model_theft`.

### Test A — INTERVAL-SWEEP (decisive)
Sweep blind over **T ∈ {3, 6, 9, 12, 15, 30, 60}s** on two classes: **constrained** (c2-stateful
+ PDB, rotate = destructive Delete) and **unconstrained** (c1-heldout-cve). Per (T, scenario),
≥20 trials: `ZeroDayPreventionRate`, `HarmRate`, `InfeasibleRotateRate`, `DefensiveMoveCost`,
`GapRegularity`. **`WIN(T)` = prevention CI-low ≥ 0.95 AND harm CI-high = 0 AND infeasible = 0
AND cost bounded AND GapRegularity < learnable-threshold — all simultaneously**, on the
constrained class. The two horns provably don't overlap: **fast (T<9s)** prevents but forces
rotate-all harm + infeasible + cost-explosion + stays predictable; **slow (T≥15s)** is too late.
**PX is the unique `WIN=TRUE`** (acts at the floor, harm=0 via quarantine, cost=1). Any clean
row (incl. a clean constrained row) is **printed**.

### Test B — RECON-VALIDITY-LIFETIME (the detector-independent mechanism)
`L` = wall-seconds the attacker's recon snapshot of the at-risk asset stays valid+usable
(K8s: UID/podIP/nodeName, polled 500ms from capture until the first identity change; emitted via
`Evidence[r6th.reconValidLifetimeSec]` → omitempty `Metric` field). Two numbers/arm with CIs:
**learned sup-phase** `L_blind = T` (the attacker strikes just after a rotation via
`Learner.PlanDelaySeconds`, reaching the supremum because CV=0) and **unlearned mean ~T/2**;
right-censoring (static arm) reported KM-style as a lower bound. **`L_PX` reported as a
MEASURED distribution with a CI-high — NOT "by construction".**

### Test C — LEARNABILITY EPISODES
Extend `adaptive.Learner` with an episodic loop (E=20 episodes per (arm,T)):
`AttackerSuccessByEpisode`, the OLS **learning slope** dSuccess/dEpisode + CI, final
`GapRegularity`, selection-entropy (bits). Control = `d-randomequal` (if random also flat, report
the PX/random tie and locate the distinction in B/E — honesty).

### Test D — PREDICTION (the capability blind lacks)
A 4-line additive bridge reads the **already-computed** `Decision.PreemptMargin` /
`ProjectedNextStageSec` (populated `coverage.go:297-298`) into the existing AMTD audit map (no new
SecurityEvent type); the harness lifts them to omitempty `Metric` fields. Report the full
`PreemptMargin` distribution + the ≥0.5 rate + `MovedBeforeNextStageRate` (**tied to A's actual
eviction so it isn't a free win**) + the presence-asymmetry (1 of 6 arms produces a horizon). Run a
stage where exposure approaches the sojourn median so `PreemptMargin` varies in (0,1), not vacuous.

### Test E — TARGETING/DILUTION
Sweep fleet **N ∈ {1,2,4,8,16,32}**: `AtRiskProtection(N)`, protection-share, the **log-log
dilution slope** vs H0=−1 (blind) / H0=0 (PX), crossover N. **The SLO/PDB move-cap is enforced and
stated** (removing it is forbidden rigging — uncapped just moves the dilution to the cost~N axis).
**Refuse a win at N=1** (PX and blind tie there); report the crossover.

**Both products:** every test carries a first-class AI row (the 4 AI stages via the `aiNextStage`
successor map); **GPU magnitudes `[SP-0-PENDING]` (`CapabilityPending=true`), definitions complete.**

---

## 4. Both-products coverage (honest)
**K8s — live on kind, magnitudes MEASURED:** A (c1/c2 generic chain), B (UID/IP/placement probe),
C (learner), D (generic stage classifier + horizon), E (co-resident fleet dilution).
**AI — first-class definitions, magnitudes `[SP-0-PENDING]`:** the 4 AI stages classify live via the
successor **map** (a naive time-since-event surrogate computes the *wrong* AI successor — so even
faking D fails on the AI chain). But honestly: the **external endpoint is STABLE for all arms incl
PX** (`ai1_model_theft.go:84`), so A-AI/B-AI **tie on the backend-pod-identity proxy** and we **say
so**; fingerprint/MIG-rebind resets are Phase-2 audit-only. **If a native GPU run shows PX cannot
invalidate the fingerprint faster than blind, the AI-B/D claims are RETRACTED, not fabricated.** This
is honestly **definition-complete / magnitude-pending**, not first-class-measured on the AI side.

---

## 5. Completes + beats the timing baseline; regression-gated
- **Completes (hard gates, void the run on drift):** the **1.62× recon-per-dollar** IP gate (UCW byte-tie at nil-data), the **P3 dwell band** (PX 5.1–5.6s vs blind 12–15s vs no-MTD 20s), **infeasible=0/harm=0** for PX, and the **792-row metrics.jsonl decodes BYTE-UNCHANGED** (every new field omitempty, every new key rides the Evidence-LIFT seam). If any prior row changes byte-for-byte, the additive discipline failed and the run is **void, not a result**.
- **Beats the timing-only framing:** the decisive output (`WIN(T)`) is a **SET/RATE certificate**, not a rotate-sooner number — it adds harm/infeasible/predictability/dilution columns **no interval T repairs**. The structural edge is **not** "PX uniquely prevents" (false at N=1) but **"blind's at-risk lifetime is longer (B), harm/cost is forced (A-constrained), it is learnable (C), and it dilutes (E) — none repairable by any T."**

---

## 6. Honest open risks (carried openly)
1. **A is decisive only on the CONSTRAINED class** — on c1-heldout-cve a fast T<objective prevents harm-free at N=1; run both, report the constrained frontier, print any clean row.
2. **Keystone over-claim (material):** the proactive floor is a soft noisy-OR term, so `L_PX` is probabilistic — report as a measured CI/distribution, not a ceiling; B partly re-measures dwell (read jointly with A).
3. **C can tie:** d-randomequal is also flat-GapRegularity yet dilutes/dwells — a flat C alone doesn't prove PX; if random ties, report it and locate the distinction in B/E; if a blind T's learning-slope CI brackets 0, concede for that T.
4. **D wins by ABSENCE** — it proves PX *has* a capability, not that it changes the outcome; tie `PreemptMargin` to A's actual moved-before-eviction; `moveLatency=0` is optimistic (real latency lowers it).
5. **E needs the move-cap enforced + stated;** N=1 is a tie by design.
6. **All AI native magnitudes `[SP-0-PENDING]`;** endpoint stable for all arms; retract on a contrary native run, never fabricate.
7. **Documented `[R6 PAPER ONLY]` jitter** would raise CV and lower GapRegularity below 1 — we test the **in-code** const (no jitter) and state that jitter would partially mask the cadence.
8. **Presence-asymmetry (D) is "gameable"** only by bolting PX's per-stage hazard brain onto the blind arm — which concedes the structural point; report the asymmetry as-defined.
9. **Stats gap:** `stats.go` is t-only; t-on-0/1 under-covers at the 0%/100% extremes where PX/blind live → an **additive Wilson helper** is needed (flagged, additive).
10. **Harm is in the state-string marker** (not the Evidence map) — the winner reads the marker (no new stamp).
11. **Interval values are SCALED-FOR-TEST** (15s ≈ 240× compression of the PRD ~hourly anchor) — only the **relative ordering** (PX-floor 6 < objective 9 < blind 15) and the qualitative shapes are claimed.

---

## 7. If approved — Step 2/3
**Build:** `d_r6blindtimer_swept.go` (swept-T blind arms), `b_recon_lifetime.go`, `e_dilution_fleet.go`,
the `c2-stateful-PDB` variant, the Test-D 4-line audit-map bridge + Evidence lift, the Wilson helper,
and the `p3report` extension (the interval-sweep frontier table + B/C/D/E tables + both lenses).
**Run** ≥20 trials/arm with **95% CIs** (Wilson on rates, t(df=19) on continuous, OLS on slopes)
across the interval-sweep × recon-lifetime × learnability-episodes × prediction × dilution, both
products, masterSeed=1337. **Prove** the structural claim *on the constrained class* (or honestly
print any clean interval), report `L` structurally shorter for PX (as a distribution), the
learning-slope asymmetry, and moved-before-next-stage — **preserving the 1.62× gate + P3
dwell/feasibility (hard-gated)**. **Report once, both investor and customer lenses, with the
"strong-evidence not proof" verdict stated plainly.**

**PASS filters:** go build/vet/test green; additive only (zero harness-core / zero extended-Phoenix);
≥20 trials + 95% CIs; the structural claim **proven on the constrained legs (A-harm/C/E/D) and
honestly qualified on the prevention/recon legs**; both products; recon-validity-lifetime +
interval-sweep + learnability + prediction measured with REAL numbers; nothing fabricated;
reproducible from masterSeed=1337; the baseline decodes byte-unchanged.

---

## 8. Decision
**Build the Structural Zero-Day Suite.** It moves the decisive claim off the clock onto four
T-invariant SET/RATE/SCALE properties (rotate-all harm, intrinsic learnability, B/N dilution,
prediction-presence) that are **genuinely proven**, while **honestly reporting** that the
prevention/recon-lifetime legs are strong evidence resting on a soft-floor probabilistic outcome
(measured as a distribution, not a theorem) and that **a clean blind interval exists on the
unconstrained scenario at N=1 (printed plainly)**. Honest headline: **it strongly evidences — does
not fully prove — that R6's static-set/fixed-rate pair cannot win the zero-day on the constrained
class at any feasible interval; Phorvex wins by a regenerated set + a solved rate that is targeted,
harm-free, unlearnable, and non-diluting.** AI rows are definition-complete, magnitude `[SP-0-PENDING]`.

**>>> STOPPING for your approval before building Step 2/3. <<<**
Approve the Structural Zero-Day Suite (with the soft-floor honesty fix + the both-class interval
sweep, as scoped), or tell me to adjust the test set / claim scope first.
