# 03 — Decision · T0-C (B-5/R-2/R-9) · Proposer answers, point by point

Verdict on the round: **all five blocking demands ACCEPTED** — each is code-correct at `515c56a`
and each makes the record *reconstruct* rather than merely *exist*. Corrections (B.6) accepted
with the small precisions noted. Test plan replaced per B.7. The agreed spec below is final
unless the diff review finds a contradiction with it.

## B.1 — CHi reconstruction · ACCEPTED

Verified `p1cost.go:175-184`: rotate `slack = max(Quantile() clamped ≥0, [HasGPU && !Primed] ?
FlowDisruption·GPUEnvelopeMax() : 0)`; `chi = total + slack`; non-rotate `chi = total`. The
envelope branch is the majority GPU case live (78% unprimed) — my "q absent there" left CHi
unreconstructable exactly there. Agreed fields, per candidate:

- `conformalQuantile` (OptionalFloat) — present on every row where the cost path ran
  (rotate rows); the raw `Quantile()` value pre-clamp is not observable post-hoc, so record the
  **post-clamp** value actually used in `max(...)` (the law needs that one).
- `conformalCalibrated` (bool) = `Conformal.Calibrated()` — distinguishes measured q from
  `ColdStartSlack=0.1` (Trap 4 closed).
- `gpuEnvelopeApplied` (bool), `gpuEnvelopeSlack` (OptionalFloat, present iff applied).
- Non-rotate rows: all absent + `gpuEnvelopeApplied=false` (bool, not Optional — the branch is
  knowable for every row: `action==rotate && HasGPU && !primed`).

**Pinned law** (Validate + your validator): `CHi = ECost + (action==rotate ?
max(conformalQuantile, gpuEnvelopeApplied ? gpuEnvelopeSlack : 0) : 0)`. NaN rows: all four
absent (the NaN early-return at `:166-172` never computes slack) — the law applies only where
`exclusionKind != cost-nan`.

## B.2 — coveredBeforeDecision round semantics · ACCEPTED

Verified `:364-368` (overwrite per round) and `covered` as bool. Agreed:

- Additive `coveredRound := map[string]int{}` in the selection loop, written beside
  `covered[k] = true` at `:386` as `coveredRound[k] = round+1` (1-based; zero selection effect —
  it is written, never read, by the loop).
- Per fact: `coveredRound` (OptionalInt; absent = never covered this tick).
- Per record: `evaluationRound` (int) = the round whose marginal the record carries — the
  selection round for the winner's asset, the last executed round otherwise. Coherent per
  record because `selectedAsset[c.Key]` skips the winner's *whole asset*, so all of a record's
  candidates share one last-evaluated round.
- `coveredBeforeDecision` becomes **derived**: `coveredRound.present && coveredRound <
  evaluationRound`. Recorded anyway (computed, not asserted) so readers don't re-derive.
- **Validator law**: `marginalCoverage = Σ finalWeight(k) for k ∈ coverKeys with
  ¬coveredBeforeDecision(k)`. On this fleet (B=1): false everywhere except keys shared with the
  winner — now computed.

## B.3 — NaN vs infeasible · ACCEPTED (your ruling supersedes my D-3)

`p1cost.go:24-26`'s deliberate distinction stands in the record. Every `actionStatus` row
carries all three: `status` (ticket's 10 values — NaN rows read `infeasible`), `exclusionKind`
(mandatory closed enum: `not-enabled | recon-cover | feasibility | cost-nan | slo-gate |
reactive-only | selection | none`), `reason` (verbatim string, redacted). This is R-2's
"different conditions with different fixes" made structural. `Validate` pins the enum and the
consistency rules (e.g. `status=selected ⇔ exclusionKind=none`; `cost-nan ⇒ status=infeasible`).

## B.4 — reactive-only rows · ACCEPTED

Per row `scored` (bool = candidateKey ∈ `evaluatedMarginal` — already plumbed to the builder,
no new pipeline state) and `exclusionKind=reactive-only` for the unscored-because-`!attackBackedKey`
case (`:359-361`), `reason` = the existing verbatim string. vllm today: 2 rows
`candidate, scored=false, exclusionKind=reactive-only` + 13 `not-enabled`. Honest.

## B.5 — dispatch outcomes · ACCEPTED, with one addition

Full enumeration of the pre-`Actuate` surface (`manager.go:1041-1103`):

| State | dispatchOutcome | reason |
|---|---|---|
| not selected (`:1054`) | `not-attempted` | `unselected` |
| dry-run (`:929` gate — `actuate` never runs) | `not-attempted` | `dry-run` |
| kill-switch (`:929` gate) | `not-attempted` | `kill-switch` |
| **`EnsurePolicy` error (`:1048-1050`) — whole tick suppressed** | `not-attempted` | `ensure-policy-failed` |
| inviolability guard (`:1060`) | `not-attempted` | `inviolability-guard` |
| missing tick view (`:1074-1079`) | `not-attempted` | `no-tick-view` |
| emit-boundary feasibility veto (`:1080-1085`) | `not-attempted` | `emit-boundary-infeasible` (+ verdict.Reason in detail) |
| `Actuate` err (`:1100-1103`) | `dispatch-error` | `failed` \| `deadline-expired` |
| `res.Emitted=false` | `emitted-false` | actuator's reason string |
| `res.Emitted=true` | `emitted` | — |

The `ensure-policy-failed` row is my addition to your enumeration — a fourth guard, tick-level,
found while verifying your three. Write ordering is safe: `actuate()` runs at `:933`, stamps
land on `decisions[i].Trace` inside the loop, `m.Audit.Record` is `:937` — the outcome is known
before the write. Stamp only when `Trace != nil` (trace-off path untouched).

## B.6 — corrections · all accepted

1. **`movesSelected` dropped.** Verified `:532-533`: the `movesSpent` parameter *is*
   `len(selectedAsset)`. No duplicate field, no alias — 04 documents `movesSpent ≡ movesSelected`
   in the schema comment instead (an alias without a Validate equality is a second name for drift).
2. **§12 comparator untouched.** One asset per record (`:723`,`:781`); the assetUID sort is
   vacuous. §12 satisfied by a `Validate` rule: every candidate key's asset prefix == the
   record's asset. Stated in 04.
3. **`costModelVersion`:** `Name()` is on `p1CostModel` (`p1cost.go:297-299`). The builder holds
   `*cost.P1Cost` — I will add a side-effect-free accessor on `P1Cost` returning the wrapped
   model's `Name()` constant (no hard-coded string in the builder).
4. **Canonical vocabulary = `model.MutatingActions` (15).** `noop` is the no-mutation sentinel a
   *selected* record uses to say "nothing worth doing"; `disable` is a policy-level switch —
   neither is a move the generator can propose. `Validate` pins: `len(actionStatus) == 15`,
   canonical order, unique. (Your §A said 16 in two places; B.6/B.9 converge on 15 — noted as
   resolved, not a disagreement.)
5. **`coveringActions` over ALL actions** — from recon's `CoverByAction` (`generator.go:166-168`
   scans every declared cover, disabled included). A fact's cover set is a property of the fact;
   enablement is what `actionStatus` records. Stated.
6. **`sloGateResult` presence:** present/true for generated candidates (passed `:229`),
   present/false for `conformal-slo` rows, absent for rows excluded upstream of the gate.
   `costCeiling` = the generator's effective `d.CostCeiling`, not `pol.CostCeiling`.
7. **`Validate()` has no non-test caller** — stated here and in 04: every reconstructability
   invariant in `Validate` runs in tests only; the production check is your Task-9 validator.
   Wiring `Validate` into the writer is a separate decision, not this ticket.

## B.7 — test plan · replaced

Struck: "replay live records through the builder" (impossible — records are outputs). L2 =
constructed fixtures in `decision_trace_test.go` style (`covView`, `fixedTraceEngine`):

1. B=2 two-asset tick — B.2 `coveredRound`/`evaluationRound` semantics + the validator law.
2. GPU-unprimed rotate — B.1 envelope branch, all four fields, CHi law.
3. NaN feature — B.3 `status=infeasible, exclusionKind=cost-nan`, CHi fields absent.
4. Reactive-only asset — B.4 `scored=false`, `exclusionKind=reactive-only`.
5. Each dispatch state in the B.5 table (incl. `ensure-policy-failed`, dry-run, kill-switch).
6. `not-enabled` action rows (13 on a 2-action policy).
7. `conformal-slo` reject via low `CostCeiling` — `sloGateResult` present/false.
8. Property test: every record has exactly 15 statuses, unique, canonical order, over random
   policies (your A.5 attack 4).
9. Trace-on/off byte-identical selection on all fixtures (P-C5).
10. Existing frozen-corpus equivalence extended to the new fields.
11. The two frozen live records → **validator** tests: v2-shape acceptance + ECost/netGain
    reconstruction (not builder tests).

## B.8 — agreements · confirmed

- λ tier-exit: T0-C records the field; non-zero λ is a fixture property; M-144 is the vehicle.
- Capability → `not-evaluated-by-current-model`; `not-installable` emitted by no mapping.
- v3 bump: noted that `Canonical()` forces `SchemaVersion = V2` at `decision_trace.go:214` —
  that line and the T1-A leakage test's expectations change with the bump (declared in 04).
- `ShadowCheckedOptimizer`/`DecideChecked` (`manager.go:864,982`): **confirmed ignore Trace** —
  shadow decisions feed only `shadowSafetyViolations`/`selectedDecisionKeys`/`decisionScores`
  (`:889-896`), which read Selected/Feasible/DecisionValue. Blast radius unchanged.

## B.9 — L3 band · accepted as the 06 standard

First ≥1,000 post-deploy records: 15 `actionStatus` rows/record in canonical order; vllm reads
13×`not-enabled` + 2×(`candidate`, `scored=false`, `reactive-only`); selection distribution and
the voice `rotate` rate unchanged within noise; validator reconstructs selected/noop, ordering,
ECost, CHi on 100%; 0 forbidden statuses; 0 redaction hits; size +≤5%. Any selection flip on
identical inputs = REOPENED.

---

**State → AGREED.** Next: 04-diff.patch + tests per this decision, then to you as neutral
executor for build/vet/test with raw output.
