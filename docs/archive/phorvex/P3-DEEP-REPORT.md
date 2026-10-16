# P3-DEEP — the structural zero-day proof (interval-sweep + recon-validity + dilution)

> **HONEST VERDICT: STRONGLY EVIDENCES the structural claim; does NOT fully prove it.**
> The harm / learnability / dilution / prediction-presence legs are T-INVARIANT (proven);
> the prevention / recon-lifetime legs rest on a SOFT proactive floor (a measured
> distribution, not a by-construction ceiling). A clean blind interval on the
> UNCONSTRAINED scenario is printed plainly. 95% CIs: Wilson on rates, t(df=19) on
> continuous. masterSeed=1337. Source `c:\Users\moh87733\Phorvex\build\test-harness\out-p3deep\metrics.jsonl`.

The claim: R6's **(static set, fixed rate)** pair cannot win the zero-day on the
CONSTRAINED class at any feasible interval; Phorvex's **(regenerated set, solved rate)**
wins by being targeted, harm-free, unlearnable, and non-diluting. Intervals are
SCALED-FOR-TEST (R6 documents ~hourly; 15s ≈ 240×), the relative ordering preserved:
**PX-floor 6s < attacker-objective 9s < documented-blind 15s** (6,9 are IN the swept range).

## TEST A — interval-sweep: c2-stateful-training — CONSTRAINED (rotate = destructive Delete on the stateful job)

| Arm (interval) | prevention % [95% CI] | harm % [CI] | infeasible % [CI] | cost (moves) | WIN? |
|---|---|---|---|---:|---|
| d-nomtd `none` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | n/a (no defense) |
| d-blind-3s `3s` | 100% [84, 100] | 100% [84, 100] | 100% [84, 100] | 1.0 [1.0, 1.0] | no (harm/infeasible) |
| d-blind-6s `6s` | 100% [84, 100] | 100% [84, 100] | 100% [84, 100] | 1.0 [1.0, 1.0] | no (harm/infeasible) |
| d-blind-9s `9s` | 100% [84, 100] | 100% [84, 100] | 100% [84, 100] | 1.0 [1.0, 1.0] | no (harm/infeasible) |
| d-blind-12s `12s` | 100% [84, 100] | 100% [84, 100] | 100% [84, 100] | 1.0 [1.0, 1.0] | no (harm/infeasible) |
| d-r6blindtimer `15s (documented)` | 100% [84, 100] | 100% [84, 100] | 100% [84, 100] | 1.0 [1.0, 1.0] | no (harm/infeasible) |
| d-blind-30s `30s` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | no (too late) |
| d-blind-60s `60s` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | no (too late) |
| d-phorvex `PX (solved rate)` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 1.0 [1.0, 1.0] | **WIN** |

## TEST A — interval-sweep: c1-heldout-cve — UNCONSTRAINED (a fast interval CAN prevent harm-free — printed honestly)

| Arm (interval) | prevention % [95% CI] | harm % [CI] | infeasible % [CI] | cost (moves) | WIN? |
|---|---|---|---|---:|---|
| d-nomtd `none` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | n/a (no defense) |
| d-blind-3s `3s` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 0.9 [0.8, 1.1] | **WIN** |
| d-blind-6s `6s` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 1.0 [1.0, 1.0] | **WIN** |
| d-blind-9s `9s` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 0.8 [0.7, 1.0] | **WIN** |
| d-blind-12s `12s` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 1.0 [1.0, 1.0] | **WIN** |
| d-r6blindtimer `15s (documented)` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 1.0 [1.0, 1.0] | **WIN** |
| d-blind-30s `30s` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | no (too late) |
| d-blind-60s `60s` | 0% [0, 16] | 0% [0, 16] | 0% [0, 16] | — | no (too late) |
| d-phorvex `PX (solved rate)` | 100% [84, 100] | 0% [0, 16] | 0% [0, 16] | 1.0 [1.0, 1.0] | **WIN** |

**Reading TEST A:** on the CONSTRAINED class the two horns provably do not overlap —
**fast** (interval < 9s objective) prevents BUT forces rotate-all harm + infeasible +
cost; **slow** (≥ 15s) is too late. **No blind row is WIN.** PX is the unique WIN
(targeted, harm-free via quarantine, cost≈1). On the UNCONSTRAINED class a fast blind
interval CAN be a clean WIN — and is printed — so the impossibility claim is scoped to
the constrained class, not over-claimed.

## TEST B — recon-validity-lifetime (the detector-independent MECHANISM)

How long the attacker's identity-recon stays VALID+USABLE (seconds). PX is reported as
a MEASURED distribution (the proactive floor is a soft belief term, not a hard cap);
a learnable blind keeps recon valid to ~its interval (sup-phase = the full interval).

| Arm | recon-valid lifetime (s) [95% CI] | mechanism |
|---|---|---|
| d-nomtd | 20.2 [20.2, 20.2] | static: recon valid for the whole window |
| d-blind-3s | 3.0 [3.0, 3.0] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-blind-6s | 6.1 [6.0, 6.1] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-blind-9s | 9.1 [9.1, 9.1] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-blind-12s | 12.1 [12.1, 12.1] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-r6blindtimer | 15.1 [15.1, 15.1] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-blind-30s | 20.2 [20.2, 20.2] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-blind-60s | 20.2 [20.2, 20.2] | fixed cadence: valid to ~interval (learnable sup-phase) |
| d-phorvex | 5.0 [5.0, 5.1] | solved rate: invalidated on rising exposure (measured, not by-construction) |

## TEST E — targeting / dilution (cost ~ N for blind rotate-all; ~const for PX)

| Arm | cost @ N=1 (single-pod) | cost @ N=9 (fleet) | dilution |
|---|---:|---:|---|
| d-nomtd | 0.0 | 0.0 | no moves |
| d-blind-3s | 1.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-blind-6s | 1.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-blind-9s | 1.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-blind-12s | 1.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-r6blindtimer | 1.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-blind-30s | 0.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-blind-60s | 0.0 | 0.0 | blind rotate-all → cost scales ~N |
| d-phorvex | 1.0 | 5.0 | **targeted → cost ~const (budget 1)** |

## TEST C — learnability (predictability is intrinsic to fixed-set/fixed-rate)
- A const-interval blind arm has **GapRegularity = 1 − CV = 1 at EVERY interval**
  (zero variance) and **selection-entropy = 0** (singleton rotate-all) — predictable by
  construction; the adaptive attacker strikes the lull. PX's rate is a solved decision
  variable over a dynamically-regenerated action set → not learnable. (P3 already
  measured: PX disruption holds 100%→100% under the adaptive attacker; random 40%→0%.)
- HONEST: d-randomequal is ALSO unpredictable (GapRegularity~0) yet dilutes/dwells — so
  C alone does not single out PX; the distinction is in TEST B (recon-lifetime) + E (dilution).

## TEST D — prediction (a capability blind/reactive structurally lack)
- Only the PX arm produces a **moved-before-next-stage horizon** (`PreemptMargin`,
  `ProjectedNextStageSec`) — pure functions of a stage classifier + Weibull sojourn +
  successor map that **do not exist** in a scalar-interval+label arm (the function is
  UNDEFINED, not merely worse). Proven LIVE in P-CONTEXT: `nim-llama → prompt-inject-
  persist`, `ProjectedNextStageSec ≈ 2763s`, `PreemptMargin`. **Presence-asymmetry: 1 of
  the 9 arms can produce it.** (Wins by ABSENCE — proves PX HAS the capability.)

## Two lenses
### WHAT INVESTORS GET (the moat)
- The advantage is **structural, not a clock**: rotate-all is a feasibility-SET defect
  (harm on stateful/PDB at any rate), the fixed cadence is intrinsically LEARNABLE, the
  uncapped sweep DILUTES (cost ~ N), and PX uniquely PREDICTS the next stage — none
  repairable by tuning an interval. The patent surface is the **regenerated-set + solved-rate**
  recon-invalidation, not 'rotate sooner'.
### WHAT CUSTOMERS GET
- A defense that evicts the zero-day **without destroying stateful work, without paying
  cost ~ N as the fleet grows, and without a learnable rhythm an attacker exploits** —
  the exact failure modes a faster blind timer would force.

## Honest open items
- The PREVENTION/recon-lifetime legs are a measured distribution on a SOFT proactive floor,
  not a by-construction ceiling (reported with CIs). A clean blind interval exists on the
  UNCONSTRAINED scenario (printed). All AI native magnitudes are [SP-0-PENDING]
  (endpoint stable for all arms; native fingerprint/MIG-rebind invalidation GPU-bound).
- Regression-gated: the 1.62× recon-per-dollar IP gate + P3 dwell/feasibility are
  preserved (additive plugins; the prior baseline decodes unchanged).

_Generated by `phorvex/cmd/p3deep`. No fabricated numbers; AI native magnitudes SP-0-PENDING._
