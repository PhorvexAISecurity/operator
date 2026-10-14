Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-6 — RL / Per-Customer Overfit Hook

**Scope:** How every **proven `(attack, actuator, brain-verdict)` triple** from the adversarial
competition — with the brain's explanation **quoted exactly** and the **seven metrics** (docx §8;
WS-3 §3) attached — is appended to the **per-customer RL learning record, shadow only**, and feeds
**governed calibration** that tunes per-customer behavior **without ever structurally changing the
deterministic brain** (docx §11). The record is the memory that lets the loop overfit to a
customer's real adversary. Brain Contract: *proposal → replay → shadow, NEVER a
live write*; brain structure is untouched; only governed, calibrated parameters move, under
audit.

**Tag legend:** `[CODE-CITED]` = stated in a source comment/code (the `file:line` follows the tag);
`[DOC-CITED]` = stated in a doc, report, markdown file or paper (incl. intake reports and the
architecture docx); `[INFERRED]` = composed from cited code but not stated verbatim;
`[UNVERIFIED]` = not confirmable from the repo.

---

## 0. The two calibration surfaces (orientation)

Phorvex has **two distinct calibratable surfaces**, both isolated from `Decide`:

1. **Per-tenant online cost calibration** — the RLS `C_flow` estimator, one per tenant, that
   refines the flow-cost prior from *measured real rotations*. This is the "per-customer"
   knob. `[CODE-CITED]` `phorvex/internal/cost/rls.go:84-101`, `phorvex/internal/decision/coverage.go:41-53`.
2. **Fleet shadow scale calibration** — the `calib.Runtime` shadow collector that proposes
   co-residency scale, dispersion cap and ready-delay references from the fleet's own tenancy.
   `[CODE-CITED]` `phorvex/internal/calib/runtime.go:34`, `:113-126`.

The **redteam RL** (`internal/redteam`) is a *third* surface — the attacker/generator learner —
and holds the *only* ML in the system. It never touches `Decide`. `[CODE-CITED]`
`phorvex/cmd/redteam-rl/main.go:1-14`, `phorvex/internal/redteam/autograd.go:1-8`.

---

## (a) Data path: proven triples → proposal → replay on twin → shadow → governed promotion

### Step 1 — A proven triple becomes a *measured observation*, not a label guess
A proven `(attack, actuator, brain-verdict)` triple (a round WIN, docx §3.1 step 5) is only admitted
as calibration input **after the actuator's effect is externally, exactly confirmed on the twin**,
and the brain learns from the *measured disruption*, not from the action emission.

- The RLS recursion "is fed only after a rotation's replacement reaches `PodReady`, keeping action
  emission latency out of the learned disruption label." `[CODE-CITED]`
  `phorvex/internal/cost/rls.go:16-17`.
- Exact-completion gating of loss evidence: `ObserveOnce` "creates a SecurityEvent only after exact
  completion. Failed observations create no loss evidence." `[CODE-CITED]`
  `phorvex/internal/lossobserver/observer.go:40-41`, digest/bytes/EOF checks `:76-95`.
- Admitted triples are retained as **immutable, tamper-evident** records — the brain's verdict quoted
  exactly, the seven-metric scorecard attached (docx §11, D4) — (sha256-named files,
  canonical re-validation on read, monotonic `history-incomplete` latch). `[CODE-CITED]`
  `phorvex/internal/losshistory/store.go:1-2`, `:156-182`, `:74-102`, `:304-411`.

→ *A triple the verification loop could not validate to exact completion produces no calibration
input at all.* `[INFERRED]` from the two gates above.

### Step 2 — Proposal
The validated observation is folded into a **proposal**, never a committed value:

- Fleet scales: `CalibrateCoResidency` / `CalibrateJoint` / dispersion — "Production is unaffected:
  the returned scale is a proposal." `[CODE-CITED]` `phorvex/internal/calib/coresidency.go:95-102`,
  `phorvex/internal/calib/dispersion.go:104`.
- Per-tenant cost: `RLS.Update` folds one `(features, observedCost)` sample into `theta` via the RLS
  recursion, **rate-limited** so one observation cannot reprice a tenant (`maxThetaStep = 0.25`).
  `[CODE-CITED]` `phorvex/internal/cost/rls.go:165-224`, const `:83`, rationale `:72-82`.

### Step 3 — Replay on the twin
Proposals are evaluated by **re-running the deterministic economics as INPUTS** against the proposed
parameters — a digital twin of the brain, not the brain's live state:

- `calib.Runtime` keeps reproducible history and recomputes against it; "now is the observation
  clock, passed rather than read so a replayed history reproduces exactly." `[CODE-CITED]`
  `phorvex/internal/calib/metrics.go:192`, `phorvex/internal/calib/scale.go:47`.
- The redteam env **replays the real `cost.DualSolver`** ("Decide stays byte-deterministic; only
  λ/physics re-ground as INPUTS each tick"). `[CODE-CITED]`
  `phorvex/internal/redteam/cotrain.go:1-8`, `phorvex/internal/redteam/pomdp.go:1-16`.

### Step 4 — Shadow evaluation
A shadow decision prices the counterfactual against **existing** knowledge and advances *none* of it:

- `DecideShadowChecked` "evaluates a counterfactual … without advancing any of it (M-163). … the
  shadow folds no stage entry, seeds no owner state, moves no dual price, teaches no conjugate
  memory, stamps no caller-owned view and increments no operational counter. Its own decisions carry
  the full trace, with the dual update marked `Applied=false`." `[CODE-CITED]`
  `phorvex/internal/decision/coverage.go:746-755`.
- `ShadowViews` returns **cloned** views (`clone := *view`); "Production views are never mutated."
  `[CODE-CITED]` `phorvex/internal/calib/runtime.go:318-320`, `:340`.
- Shadow cost buckets are **transient and never registered**: "no seed is consumed, the alias stays
  unclaimed, no BucketMeta is minted and creationEvent does not move." `[CODE-CITED]`
  `phorvex/internal/decision/coverage.go:424-482`.
- Proven by test: adding shadow evaluations must leave the next production decision identical, and
  a shadow "must not have performed production's reversion on the shared calibrator." `[CODE-CITED]`
  `phorvex/internal/decision/m163_shadow_isolation_test.go:455-500`.

### Step 5 — Governed promotion
Nothing promotes itself. The observability layer makes "the proposal, its provenance and its
disagreement with production all observable BEFORE anything is switched over." `[CODE-CITED]`
`phorvex/internal/calib/metrics.go:24-26`. Promotion of a discovered path is a **human action**:
`Gate.AutoEscalate()` is hard-wired `false`; `Approve` "is the explicit HUMAN action (the only way a
proposal becomes promotable)." `[CODE-CITED]` `phorvex/internal/redteam/cotrain.go:20-52`; asserted at
`phorvex/internal/redteam/redteam_test.go:77-78`.

This is **metric-rule 3** (docx §8.3): the seven metrics reach the brain **only** through this RL
record as **shadow proposals with human approval — never directly**; no metric is wired into
`Decide`, and the brain is unchanged. `[DOC-CITED docx §8.3, §11.1]`

---

## (b) What may be calibrated vs what is structurally frozen in the brain

### Calibratable (governed parameters that move under audit)
- **Per-tenant RLS `theta`** — the `C_flow` cost weights, one bucket per tenant, isolated with
  "zero cross-feed." `[CODE-CITED]` `phorvex/internal/cost/rls.go:86-101`,
  `phorvex/internal/decision/coverage.go:41-53`, `:383-422`.
- **Fleet shadow scales** — co-residency scale, dispersion cap, ready-delay reference; proposals only,
  "Learned values never enter production scoring." `[CODE-CITED]`
  `phorvex/internal/calib/runtime.go:34`, `:318-355`.

### Structurally frozen (the brain's shape — untouched)
- **`Decide` / `DualSolver` determinism** — "Decide stays byte-deterministic"; "NO ML in
  Phorvex.Decide." `[CODE-CITED]` `phorvex/internal/redteam/cotrain.go:3-4`,
  `phorvex/cmd/redteam-rl/main.go:6-7`.
- **Feature vector shape** — `featureDim = 6`, fixed bit assignment in `Features`. `[CODE-CITED]`
  `phorvex/internal/cost/rls.go:19-50`.
- **The shipped prior** — `priorTheta` reproduces the P0 phase-based flow prior "so nil-data ==
  today's behavior"; `SetFrozen(true)` reverts to exactly this. `[CODE-CITED]`
  `phorvex/internal/cost/rls.go:51-72`, `:104-118`.
- **Output invariants** — `Predict` clamp `[0,2]` and NaN-safe conservative-max. `[CODE-CITED]`
  `phorvex/internal/cost/rls.go:132-153`.
- **Selection structure** — proactive gate (`perDollar > λ`), `B=1` top-net selection, and the
  `provFloor` fresh-candidate discount. `[CODE-CITED]` `phorvex/internal/redteam/pomdp.go:4-5`,
  `:54-57`; `phorvex/internal/decision/coverage.go:542`.
- **Structure extends by registration, not mutation** — a new constraint/profile/cost model is one
  file, zero core change. `[CODE-CITED]` `phorvex/internal/decision/modularity_test.go:1-8`.

→ *The only thing a proven triple ever moves is a numeric parameter (`theta`, a scale), inside fixed
structure, rate-limited and reversible.* `[INFERRED]` from the two lists above.

---

## (c) Reuse of redteam RL (PPO / POMDP / co-train) as the generator-learning engine — brain untouched

The redteam package **is** the generator-learning engine, and all ML lives there:

- **Recurrent-PPO** (GRU policy, GAE, clipped surrogate, BPTT, Adam, grad-norm clip). `[CODE-CITED]`
  `phorvex/internal/redteam/ppo.go:1-6`, agent `:14-41`, `Train` `:85-146`.
- **Effects-only POMDP** — the env runs the **real deterministic `cost.DualSolver`**; the attacker
  "observes ONLY effects … never λ/Decide." `[CODE-CITED]` `phorvex/internal/redteam/pomdp.go:1-16`,
  `Obs` `:86-90`.
- **Continuous co-training + PBT/QD** — population trains vs the live deterministic defender; QD
  (MAP-Elites) surfaces novel paths (it discovered the dispersion-steer). `[CODE-CITED]`
  `phorvex/internal/redteam/cotrain.go:1-8`, `:74-90`; `phorvex/internal/redteam/pbt_qd.go:1-11`.
- **Autodiff** — "contains NO Phorvex decision logic … imported only by `cmd/redteam-rl`."
  `[CODE-CITED]` `phorvex/internal/redteam/autograd.go:1-8`.

**Why the brain is untouched:** the learner's env *consumes* the deterministic economics as a fixed
oracle (λ/physics re-ground as INPUTS each tick), so learning changes the **attacker's** weights, never
Phorvex's. The defender's selection fix `steerProvDiscount` in the env **mirrors** the real
`coverage.go` `provFloor` as a constant — the brain is a frozen reference, not a learning target.
`[CODE-CITED]` `phorvex/internal/redteam/pomdp.go:54-57`, `phorvex/internal/decision/coverage.go:542`.

**Enforced import boundary:** `internal/redteam` is imported **only** by `cmd/redteam-rl/main.go`
(verified: repo-wide `grep` for importers of `internal/redteam` returns that single file). The
decision packages import neither `internal/redteam` nor `internal/calib` in production code (verified:
`grep` of `internal/decision/*.go` excluding tests returns no `calib`/`redteam` import). `[INFERRED]`
(from verification greps); the design intent is `[CODE-CITED]` at `phorvex/internal/calib/metrics.go:16-21`
("nothing on the decision path can reach it … enforced by a dependency check").

**Role in the hook:** redteam RL is the **generator-learning engine** — it learns the *attacker's*
weights, with the brain as a frozen reference oracle, never a learning target (docx §11.2). The
competition's attack fragments themselves come from the generator roster (WS-2 / docx §5) and must
pass the deterministic "attack is real" gate; proven triples from the competition are the measured
observations of §(a) Step 1. The redteam promotion gate (§(a) Step 5) feeds proposed paths to
humans, never to `Decide`. `[INFERRED]` (The docx does not specify whether redteam-RL-discovered
paths are injected into the competition's attack queue; not asserted here.)

---

## (d) Governance / audit gate on any calibration write; the never-live-write invariant

### The write gate (per-tenant online calibration — PHVX-2 off-switch)
- `RLS.SetFrozen` — freezing "REVERTS theta to the shipped prior rather than holding the last learned
  value … this is a safety control, not a pause button"; `Update` is a no-op while frozen.
  `[CODE-CITED]` `phorvex/internal/cost/rls.go:104-118`, `:165-167`. Explicitly **distinct** from the
  actuation KillSwitch. `[CODE-CITED]` `phorvex/internal/cost/rls.go:93-98`.
- `CoverageEngine.SetCostCalibrationFrozen` applies the switch "to EVERY tenant bucket, present and
  future," idempotently (re-freezing every tick must not keep reverting theta). `[CODE-CITED]`
  `phorvex/internal/decision/coverage.go:286-299`; lazy-tenant correctness tested at
  `phorvex/internal/decision/calibration_switch_test.go:12-50`.
- **Operator control plane:** the switch is re-evaluated **every tick** from the `costCalibration` key
  of a sentinel ConfigMap, "so it takes effect without a restart"; a transient read error holds the
  current state rather than discarding calibration. `[CODE-CITED]`
  `phorvex/internal/runner/manager.go:1249-1258`, `phorvex/internal/runner/killswitch.go:133-163`.

### The audit surface
- `CostCalibrationFrozen()` reports state "for audit." `[CODE-CITED]`
  `phorvex/internal/decision/coverage.go:301-302`.
- `CalibrationState()` reports, per tenant, whether the RLS left the prior (`Primed`) and how many
  real observations folded in (`Updates`). `[CODE-CITED]` `phorvex/internal/decision/coverage.go:263-284`;
  RLS `Primed()`/`Updates()` `phorvex/internal/cost/rls.go:225-230`.
- `publishRLSMetrics` runs **after** the switch is applied each tick (incl. explicit zeroes).
  `[CODE-CITED]` `phorvex/internal/runner/manager.go:1260-1263`.
- Shadow-scale metrics publish value **and** provenance (`measured | fallback_default`) and the
  disagreement with production, by design, before any switch-over. `[CODE-CITED]`
  `phorvex/internal/calib/metrics.go:24-62`.
- Human-approval gate records every proposed path with `Approved` state. `[CODE-CITED]`
  `phorvex/internal/redteam/cotrain.go:13-53`.

### The never-live-write invariant
Every proposal path terminates in shadow/replay and cannot write production state:
- Shadow decisions: `Applied=false`, no dual-price move, no owner-state seed. `[CODE-CITED]`
  `phorvex/internal/decision/coverage.go:746-755`.
- Shadow views are clones; production views never mutated. `[CODE-CITED]`
  `phorvex/internal/calib/runtime.go:318-320`.
- `calib-soak` runs the collector against **live** k8s with a `denyWritesClient` that rejects every
  Create/Update/Delete/Patch locally, forces policies to dry-run, and freezes the kill switch
  (`localWriteDeny=true actuationFrozen=true`). `[CODE-CITED]`
  `phorvex/cmd/calib-soak/main.go:5-8`, `:35-85`, `:158-176`.

The **single** path that moves a production-priced parameter is `RLS.Update`, fed only by an
exactly-validated post-`PodReady` rotation, rate-limited by `maxThetaStep`, bounded in output by the
`Predict` clamp, and instantly reversible to the shipped prior by the PHVX-2 freeze. That is *governed
calibration of a numeric parameter inside fixed structure*, not a structural change to the brain, and
it is not a live write of a decision or actuation. `[INFERRED]` from
`phorvex/internal/cost/rls.go:16-17,83,132-153,165-224` + `phorvex/internal/decision/coverage.go:286-302`.

---

## (e) Known calibration debt from intake

1. **Calibration evidence-export memory spike** —
   `workflow/intake/RPT-20260920-181636-bound-memory-during-calibration-evidence-export`.
   `calib.Export` materializes the full indented comparison JSON, full CSV rows, serialized
   score-cell strings and an extra CSV byte buffer, all at once. At a synthetic 24,300-comparison
   history: export-disabled max RSS 147,332 KiB vs export-enabled 547,684 KiB; 732,692,624 bytes
   cumulatively allocated by `Export`, producing 13 files / 189,252,291 bytes. Prescribed fix:
   **bounded streaming serialization** preserving exact schema, ordering, bytes, and atomic
   per-file replacement — *without* disabling exports, shortening the seven-day history, or
   discarding evidence. Explicitly does **not** establish live-OOM causality. Status: verified
   source finding; independent worker confirmation + output-row parity required before repair.
   `[DOC-CITED]` (intake `DEDUP.md` / `REPORT.md` / `VERIFICATION.md`).

2. **Expired comparison references retained after logical expiry (M179)** —
   `workflow/intake/RPT-20260919-122509-calibration-expired-comparison-references`.
   `Runtime.samples` in-place compaction left expired comparison/score/snapshot references reachable
   beyond `len` in the backing array (54,441,112 bytes remained after logical expiry in the 12-score
   case). **Already repaired** (DEDUP of item 1 states "M179 … already repaired"): `retainAndRelease`
   now clears discarded slots before shortening the slice. `[CODE-CITED]`
   `phorvex/internal/calib/runtime.go:209-222`, `:244`, `:261`; regression at
   `phorvex/internal/calib/m179_expiry_test.go`.

3. **Carried constraints (not yet resolved; must not be "solved" by deleting evidence)** — the
   seven-day comparison retention *budget* and the recurring 6–8h manager OOM remain **distinct,
   unproven/design-level** questions; neither is explained by items 1–2, and "do not solve memory
   pressure by silently removing scientific evidence." `[DOC-CITED]` (both intake `REPORT.md`s).

---

## Invariant summary (one line)

Proven triples (with the brain's verdict quoted exactly and the seven metrics attached) move only
**numeric parameters** (`theta`, scales) via **proposal → replay-on-twin →
shadow**, observable before any switch-over, promoted only by a human, reversible by a per-tick
operator freeze, and **never** as a live write or a change to the deterministic brain's structure.
`[INFERRED]` from all citations above.

---

*Open questions: none.*
