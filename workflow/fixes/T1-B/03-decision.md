# 03 — Decision · T1-B (`CLOCK->BELIEF`) · converged spec after §A + addendum A1 + §B

**State:** CRITIQUED → AGREED on this memo. **Base:** `b418692` (deployed `0.4.80` @ `17082b7`).
**Inputs:** `01-proposal.md`; `02-critique.md` §A (sealed `c6bc74e8…`), addendum A1 (sealed), §B.
Every §B point is adopted or answered with the code fact; no design change, two coherence/honesty amendments.

## The convergence (both derivations agreed cold — §B.0)
One clock (`ExposureByVariable[VarPodIdentity]`, ≡ pod age until first identity change) + one knob
(`ProactiveFloor`) feed many consumers; register stale on M-143 (cap landed `5f4c3ed`) and M-27
(aging landed, τ_ev still the floor); **no stage-entry timestamp exists** (§1.2 grep == A1.3); the
one behavioural change is the Weibull dwell clock; horizons **inherit** 900s ("inherited, not chosen"
recorded — Math gate NO); clock values live at trace `inputs` level, not per-fact.

## B.1 — ADOPTED (coherence, verified in source): preempt/projNext move with the dwell
Verified at `b418692`: `hazard.go:371` `weibullCDF(exposureSec, …)`, `:432` `preempt := 1 −
weibullCDF(exposureSec, …)`, `:433` `projectedNextStageSec(…, exposureSec)` — **three independent
reads of the same accrued-dwell quantity**. Splitting `:371` onto `InStageSec` while `:432/:433`
keep pod age makes one tick say "transition unlikely" and "survival margin pinned high" at once.
**Decision:** the dwell family = `{:371 hazard, :432 preempt, :433 projNext}` all read `InStageSec`.
The move family = `{:410 pHold pressure, :425/:427 just-moved damping}` read the identity/move clock.
Inside `Assess` this is two locals: `dwellSec` (→ Weibull family) and `moveSec` (→ pressure/damping);
today both equal the single `exposureSec` param, so the equal-value initialisation is byte-identical.

## B.2 — ADOPTED (honest naming, P2): rename the move clock
`SinceConfirmedMoveSec` overclaimed. Renamed **`SinceIdentityChangeSec`** = time since pod UID change,
with the doc line: *"equals time-since-confirmed-move only for identity-changing moves; the general
per-action move-epoch clock is M-23's cycle (CLOCK->CHOICE)."* Trace key follows the honest name.
No code behaviour change.

## B.3 — CONCEDED to the Proposer: `sensed.go:152` stays untouched
K3 withdrew §A row 5. `ProactiveFloor` IS the CRD's hygiene max-exposure fraction, so normalising
`sig.Exposure` by it is the knob's own meaning. The only borrowed uses re-pointed by T1-B: T_exp
(`:410`), τ_ev ×2 (`:326`, `sensed.go:138`). `sensed.go:152` and the prov overdue gate stay.

## B.4 / U-3 — no new register entry; M-23 owns it
The pod-alive cadence gap is already **M-23**. K3 (R1 seat) adds one cross-reference line to M-23
when this 03 lands ("T1-B's clock table names this boundary; fix stays CLOCK->CHOICE"). No duplicate.

## Recorded unresolved choices (source does not determine — recorded, not invented)
- **U-1** move/damping clock: left on `SinceIdentityChangeSec`; whether "attacker hold" should be
  time-since-evidence is the noisy-OR redesign (M-143 residual / T3-D).
- **F2 (recorded, K3 P3):** dwell keys on the post-override stage, so an AI-classifier flap oscillates that pod's dwell/hazard. Latent, not live — 0.4.80 baseline has zero AI stages; if AI stages become common this couples to M-25's override-stability cycle.
- **U-2** stage-dwell across brain restart: in-memory `StageClock`; after restart `InStageSec` falls
  back to **pod-age-upper-bound (= today's value)** — conservative (over-states dwell, never
  under-states imminence). Persisted store is T3-C.
- **U-4** plateau feedback ratchet (`coverage.go:574` `Observe(0.25·betaMean)`): M-143 residual.
- **U-5** (from §B.3, retired — not a residual; `:152` is correct as-is).
- **U-6** (from A1.1): `internal/belief/reconexposure.go:43-48,59-60` (P0 legacy) decay left on
  `ProactiveFloor` **deliberately** — P0 is not the live optimiser (`manager.go:137` = P1 coverage);
  routing a dead, untested path invites regression. The new `EventAgeHorizon` field exists for a
  future P0 revival to adopt. In-scope-but-untouched, with the reason recorded (ticket allows this;
  silence would not).

## Clock origin/reset/owner table (final — the "no code before the table" gate)
| Typed value | Semantic | Origin | Reset | Owner | Consumers after T1-B | Today |
|---|---|---|---|---|---|---|
| `PodAgeSec` | lifecycle age | `Pod.Age` (`kube.go:288-292`) | never | ingest | trace only | — |
| `SinceIdentityChangeSec` | since UID change (⊇ confirmed move) | `Exposure[podIdentity]` (`clock.go:93`) | UID change / GC re-seed `StartedAt` | `exposure.Clock` | pHold pressure `:410`, damping `:425/:427` | ≡ exposureSec |
| `InStageSec` | time in the current **assessed** stage (post AI-override, F2/K3 P3 — dwell and Weibull scale agree on one stage) | new `StageClock`: first tick a stage value is seen for slot → seed `StartedAt`; changes → `now` | stage-value change; GC re-seed; **restart → pod-age-upper-bound** | new `killchain.StageClock` | **Weibull dwell `:371`, preempt `:432`, projNext `:433`** | ≡ SinceIdentityChangeSec on non-transitioning pods |
| `SinceEvidenceSec` | since newest timestamped event | `min(e.Age)` over targeting events | new event | derived/tick | trace only (no live consumer — recorded) | absent w/o events |
| `EventAgeHorizonSec` (τ_ev) | staleness horizon | new `Policy.EventAgeHorizon` = `EffectiveProactiveFloor()` | reconcile | `model.Policy` (no CRD field) | `hazard.go:326`, `sensed.go:138` | = floor (900s) |
| `ExposurePressureScaleSec` (T_exp) | pressure scale | new `Policy.ExposurePressureScale` = `EffectiveProactiveFloor()` | reconcile | `model.Policy` | `hazard.go:410` | = floor |
| `ProactiveFloor` | hygiene cadence (CRD) | unchanged | unchanged | CRD | `sensed.go:152`, prov `:308-321`, feasibility | unchanged |
| `AntiOverRotationWindow` × `exposureVarFor` | per-action cadence veto | unchanged | unchanged | CRD | `feasibility/defaults.go:81-120` — **NON-MOVER (M-23/CLOCK->CHOICE)** | unchanged |

## Behavioural delta (final)
- **D-1 (Class-A core):** with all horizons = floor and `dwellSec = moveSec = InStageSec` on
  non-transitioning pods, **event weights, posture, pHold pressure, damping** are byte-identical
  (frozen-corpus trace-on/off + golden diff = only added `inputs.clocks` keys). *(Shrunk per B.1:
  the dwell fields are no longer in the byte-identical set — they are D-2.)*
- **D-2 (the one change):** the dwell family (`hazard`, `preempt`, `projNext`, `stageUrgency`,
  `lateralUrgency`, the six AI fact weights) reads `InStageSec`. Non-transitioning pod ⇒ identical
  (dwell == pod age). On a stage transition ⇒ hazard/urgency **young again**. Measured baseline
  transition rate **≈ 7e-5/record** (recon 14,211 / exploit 1 @ `17082b7`); ceiling ≤ 1%. **The
  L3 must NOT expect a fleet-wide hazard drop** — never-transitioning pods stay at 1.000; a fleet
  drop = spurious reset = REOPEN. Positive control = fixture + the next live escalation.
- **D-3:** trace gains `inputs.clocks{podAgeSec, sinceIdentityChangeSec, sinceEvidence{p,v},
  inStageSec, eventAgeHorizonSec, exposurePressureScaleSec}` ≈ **+180–300 B/record (≤ +0.3%)**;
  negligible under M-154's cap.
- **D-4:** restart re-seeds to today's values; no persisted state.
- **D-5:** cadence, feasibility, cover, cost, λ, actuation, CRD, metrics untouched.

## Diff scope (Proposer builds; K3 reviews per P3)
`killchain/hazard.go` (two locals `dwellSec`/`moveSec`; three horizon substitutions) + new
`killchain/stage_clock.go`; `ctxprov/sensed.go` (one τ_ev arg); `model/types.go` (+2 Policy fields);
`runner/manager.go` (+2 buildPolicy lines, +1 StageClock `RetainTenant`); `decision/coverage.go`
(build `BeliefClocks`, pass tracker `now`, trace `inputs.clocks`); `model/decision_trace.go` (+1
struct, Canonical/Validate). `Assess(view,pol,exposureSec,proactiveFloorSec)` **keeps its signature**
(wrapper builds `BeliefClocks`), so 9 test files + `ablation_run.go:50` + `coverage.go:202` compile
unchanged. `internal/exposure` unchanged; `internal/belief` untouched (U-6).

## Tests (§5 + §B.6)
- `TestStageDwellRestartsOnStageTransition` — RED captured (`evidence/pre-fix/01`), GREEN post-fix
  (same binary path, `evidence/post-fix/`, per P4/B.6.2).
- Decoupling: `EventAgeHorizon ≠ floor` ⇒ evidence/posture follow horizon, hygiene `:152` follows
  floor; `ExposurePressureScale ≠ floor` ⇒ pressure follows scale; all-equal ⇒ frozen-corpus identical.
- StageClock: seed-from-StartedAt; reset on stage change; **no reset on unchanged stage incl. the
  ablation double-Assess ordering** (B.6.1); GC re-seed; UID = new slot; restart fallback.
- Coherence: on a transition, hazard/preempt/projNext move together (B.1 — no split-clock record).
- Trace: `clocks` presence + Canonical ordering + Validate; **additive under v3, no schema bump**
  (B.6.3 — state in the commit message).

## Open for Skeptic sign-off → AGREED
B.1 table+D-1/D-2 wording (done above), B.2 rename (done), U-6 wording, the two-locals implementation.
§B.7 already reads "approve with B.1/B.2 folded" — this memo folds them; STATUS → AGREED on K3's ack.
