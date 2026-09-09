# 02 — Critique · T0-C (B-5/R-2/R-9) · Skeptic = Claude

## §A — Blind derivation (written 2026-09-03 ~15:50Z, BEFORE any 01-proposal.md exists; sealed here)

Derived from the ticket text, the register rows (`B-5/R-2/R-9`, register §"audit", status "—"),
and the code at `515c56a` (v0.4.74 == deployed) plus one live record (`fixes/T1-A/evidence/live/02`).

### A.1 Premise correction: the ticket describes a record that no longer exists

The ticket quotes the anatomy at `fb52e6c`: "captures the chosen action's outcome and almost none
of the decision's inputs." Since `c53258d` (T0-D, 2026-08-30) every `phorvex.audit.v2` record
nests `decisionTrace` (`phorvex.decision-trace.v2`, `model/decision_trace.go`, builder
`decision/coverage.go:604-840`, `Canonical()`/`Validate()`/redaction present, 9 tests in
`decision/decision_trace_test.go` incl. trace-on/off selection equivalence). Live at 0.4.74 the
block is populated (165 leaf paths, 122 facts, 2 candidates on the vllm asset).

**Consequence for the proposal:** Task 1 (`AUDIT_V2_GAP_MAP.md`) must be against THIS record, and
the fix is an increment on `DecisionTraceV2`, not a new record. A proposal that rebuilds the trace
from scratch or renames existing T0-D fields to the ticket's spellings (`budget`→`maxMovesPerTick`,
`primed`→`rlsPrimed`, `costRepresentationVersion`→`costModelVersion`) breaks the 0.4.72–0.4.74
readers and is REJECTED on P-C9 grounds. Additive only; ticket spellings may be added as aliases
if wanted, never as renames.

### A.2 Ticket §§ vs the record at 515c56a — what is already there (do not rebuild)

| Ticket § | Status at 515c56a |
|---|---|
| 2 identity (13 fields) | ✅ all present, `Validate()` makes image/gitSHA/UIDs mandatory |
| 3 control | ✅ `budget`(=maxMovesPerTick), `candidateDemand`, `movesSpent`, `dryRun`, `killSwitchEngaged`; `movesSelected` ≡ movesSpent (confirm) |
| 4 λ / cost state | ✅ `lambdaConfiguredSeed`, `lambdaRuntime` (float), `inputs.primed`, `costRepresentationVersion`, `dualUpdate{}` |
| 5 cost decomposition | ◐ `cNorm`,`cFlow`,`expectedCost`,`costHigh` present; ECost reconstructs (`Validate()`: normWeight·cNorm+flowWeight·cFlow). **CHi does NOT reconstruct**: no conformal slack / GPU-envelope term, no `costCeiling`, no structured SLO-gate result (see A.3) |
| 6 physics (R-9 six) | ✅ all six present with presence flags (`physicsScanned` bool, `dispersionMult`, `imageRarity`, `coResidency`, `epss`, `modelRarity`) + SM/VRAM/GPUUtil/phase/reqRate/connCount. **`SLOHeadroom` missing from trace** (only unflagged on the v2 envelope) |
| 7 belief | ✅ all 11 present (`proactiveFloorSeconds`, `antiOverRotationWindowSeconds` as plain floats — fine, policy constants) |
| 8 facts | ◐ key/type/finalWeight/`coveredBeforeDecision`/`assetValue` present; decomposition honestly absent. **`coveringActions` missing.** ⚠ `coveredBeforeDecision` is HARD-CODED `false` (`coverage.go:709`) — a fabricated value wearing a bool, not a measurement. Trap 4 in disguise. |
| 9 one status per canonical action | ❌ **the main gap (R-2).** Trace lists generated candidates + generator `Excluded` only. Actions not in `enabledActions(pol)` (`actionset/generator.go:106`) never appear → `not-enabled` is unrecorded. Exclusion causes live as free-text `Reason` strings (`recon-cover: …`, feasibility `verdict.Reason`, `conformal-slo: …`, NaN category) and `selectionReason` snake-case strings; no closed enum, no completeness over the 16 `MutatingActions`. |
| 10 candidate economics | ✅ except `selectionRound` is trace-level (acceptable: one selection per record) |
| 11 dispatch outcome | ❌ envelope has `actuated` bool only; `runner/manager.go:1108-1129` knows Emitted / not-emitted / error. Trace is built at decision time; the outcome is known later → must be stamped on the record before `audit.Record` writes, or carried in the envelope. Proposal must prove write ordering. |
| 12 ordering | ✅ facts by key, candidates by asset→canonical rank→key, coverKeys lexical (`Canonical()`); pinned by `TestDecisionTraceFactsCandidatesAndCoverKeysSerializeInStableOrder` |
| 1 versioning | trace `Validate()` rejects any `schemaVersion != v2`; envelope has an old→new read shim. Additive fields under v2 vs bump to v3: either is defensible, but a bump must keep 0.4.72–0.4.74 records readable (P-C9) and the validator must accept both. |

### A.3 What CHi reconstruction actually needs (from `cost/p1cost.go:165-200`)
`CHi = Total` for non-rotate; for `rotate`: `Total + max(conformalQuantile≥0, [HasGPU && !RLS.Primed] ? flowWeight·GPUEnvelopeMax() : 0)`.
Required new per-candidate fields: `conformalSlack` (the quantile actually used, presence = Calibrated()?), `gpuEnvelopeApplied` (bool) + `gpuEnvelopeMax`, and trace-level `costCeiling` (= `EffectiveCostCeiling(pol)`), plus a structured `sloGate` result per candidate (`passed` / `pruned: chi > ceiling` / `not-evaluated`). NaN path: `unactionableCategory`/`nanFeature` exist on `Exclusion` (`Category`, `Detail`) but are NOT copied into the trace (`coverage.go:783-808` copies `Reason` only).

### A.4 Expected behavioural delta (Class A, derived)
- Selection sets, actuation, λ trajectory: **byte-identical** on every scenario. Any flip = REOPENED (P-C5). The existing frozen-corpus equivalence test must stay and be extended to the new fields.
- Record: only ADDED keys. Zero renamed/removed keys, zero presence-flag flips on existing fields, existing values byte-identical (modulo the fabricated `coveredBeforeDecision`, whose change to honest-absent or computed is a DECLARED delta).
- Per record, exactly 16 action-status entries (one per `MutatingActions` member, canonical order), statuses drawn from the ticket's closed vocabulary; `not-installable` / handler / RBAC statuses **must never appear** at 515c56a (never evaluated) — those actions read `not-evaluated-by-current-model` or the status the generator actually reached.
- Live (0.4.74 fleet): vllm records will show 2 candidate statuses + 14 `not-enabled`/`not-evaluated…`; selected records (endpoint-rotate / kv-migrate-invalidate churn) give the positive control for `selected` + reconstructable gain ordering.
- Metrics: zero new label dimensions (Trap 6) — `git diff internal/metrics` must be empty or label-free.

### A.5 Attacks I will run on the proposal/diff (declared in advance)
1. Rename/remove of any T0-D key → REJECT (P-C9). 2. Any change in `decision/`, `cost/`, `actionset/`, `killchain/` that is not inside the trace builder or a pure read → demand justification or REJECT (Trap 2, P-C5). 3. Fabricated values: any bool/float written as a constant where the pipeline did not compute it (the `coveredBeforeDecision` pattern) → REJECT. 4. Status enum completeness: property test over random policies that every record has exactly 16 statuses, no duplicates, canonical order. 5. CHi reconstruction: independent recompute from recorded terms on the frozen corpus AND on ≥200 live records incl. rotate on a GPU pod with RLS unprimed. 6. Redaction: a fact key / cover key / exclusion Detail containing `Bearer x`, `token=`, `://u:p@` → must redact; new string fields must be routed through `redactTraceString`. 7. Dispatch outcome: prove the record is written after actuation result is known, or the field is honestly `not-attempted`/absent at write time. 8. Independent Python validator (my Task 9 tool): reproduce selected/noop + candidate ordering from the record alone on 100% of the frozen corpus; every failure names the missing field.

### A.6 Blind band for L3
On the 0.4.7x fleet, for the first ≥1,000 post-deploy records: selection distribution identical to the pre-deploy hour within sampling noise (it is a record-only change — any drift is a bug, not noise), 100% of records validate, 100% reconstruct, 0 records with a forbidden status, 0 redaction hits.

— end of §A. Anything below this line is written AFTER reading 01-proposal.md. —

## §A-addendum — live facts received from the Proposer's cluster run (bus 271, 15:59Z), still before 01-proposal

Recorded here so the derivation's inputs are dated; §A above is unchanged (sha in evidence/).
- Selected records in the retained ~4.7 h corpus: 5, all `rotate` on the voice-bot pod; zero on vllm. Selected candidate's ECost and netGain reconstruct from recorded components (confirms A.2 §5/§10; CHi still unverified — no rotate-with-slack case checked).
- No `conformal-slo` or NaN-category exclusion exists in the corpus (prefix counts: recon-cover 101,300 / availability 24,516 / anti-over-rotation 131). `UnactionableCategory` is consulted only to omit cNorm/cFlow on excluded rows (`coverage.go:803-807`) and recorded nowhere — confirms A.3's last sentence; the positive control for the SLO-gate status must be a unit fixture, not a live capture.
- vllm policy enables 2 of 15 `MutatingActions` (`rotate`, `kv-migrate-invalidate`); the other 13 have no row — the R-2 hole measured (A.2 §9).
- `primed=true` on 4,417 / 20,044 records (22%).
- **λ-runtime is 0 on every record incl. the selected one** (demand ≤ budget ⇒ dual update never fires; M-144/M-22 trap). The ticket's tier-exit clause "λ observed non-zero on a tenant whose budget does not bind" is NOT satisfiable by observation on this fleet; T0-C must not be held to it and must not fabricate it. Expect 01 §4 to say "present numeric field, 0-valued".
- Retention ≈ 4.7 h (5 × 255 MB). The validator's "100% of the retained Tier-0 corpus" needs a frozen export as the corpus of record.
- Brain node recycled ~15:17Z; pod moved nodes on the same image. Irrelevant to T1-A's window (13:54→15:10Z).

---

## §B — Critique of 01-proposal.md (opened 16:16Z after bus 273; §A unchanged, sha in evidence/)

**Overall:** the proposal's five root-cause loci are correct and each quote checks out at `515c56a`
(generator `:187-234`, builder `:696-810`, hard-coded `CoveredBeforeDecision: false` at `:709`,
`covered` map `:343/:364/:386` never passed, dispatch `:1099-1130`). It converges with §A on every
major item. Class A is the right class. The blocking problems are all in the *definitions* of the
new fields — the places where a field would exist but not reconstruct — and in the test plan.
Each is stated as a demand with the code that motivates it; K3 answers point by point in 03.

### B.1 · BLOCKING — CHi is still not reconstructable on the case that matters
`p1cost.go:177-186`: for `rotate`, `chi = total + max(q, envelope)` where `envelope =
pol.FlowDisruption·GPUEnvelopeMax()` applies iff `HasGPU && !RLS.Primed()`. Live, `primed=true` on
22% of records (facts §3) ⇒ the envelope branch is the *majority* GPU case. The proposal records
`conformalQuantile` and, on the envelope branch, "q absent + gate result" — so CHi cannot be
recomputed exactly where the entry's reader most needs it. Also `Quantile()` returns
`ColdStartSlack = 0.1` with zero residuals (`conformal.go:83-90`): "present" would not mean
"measured" — Trap 4 in spirit.
**Demand:** per candidate record `conformalQuantile` (OptionalFloat, present whenever the cost path
computed it, i.e. rotate rows), `conformalCalibrated` (bool = `Calibrated()`), `gpuEnvelopeApplied`
(bool), `gpuEnvelopeSlack` (OptionalFloat, present iff applied). Reconstruction law to pin in
`Validate` and in my validator: `CHi = ECost + (action==rotate ? max(q, envApplied?envSlack:0) : 0)`.
Non-rotate rows: both absent, `chiSlackApplied=false`. The accessor must be side-effect-free
(`Quantile()` sorts a copy — fine; never call `Observe`).

### B.2 · BLOCKING — `coveredBeforeDecision` and `marginalCoverage` must share one round semantics
`coverage.go:364-368`: `evaluatedMarginal[candidateKey]` is **overwritten every round**, so the
recorded `marginalCoverage` of an unselected candidate is its marginal at the *last* round it was
scored, against `covered` as of the *start of that round*; the selected candidate's is at its
selection round. The `covered` map is `bool` — it knows *that* a key is covered, not *when*. The
proposal's definition ("covered by a move selected in an earlier round, excluding own selection")
is unreconstructable from the data it proposes to carry, and on a B>1 policy it can disagree with
the recorded marginal (P-C4 fails).
**Demand:** additive `coveredRound := map[string]int{}` written beside `covered[k] = true` at `:386`
(round+1; zero effect on selection), passed to the builder. Record per fact `coveredRound`
(OptionalInt, absent = never covered this tick) and per record `evaluationRound` (the round whose
marginal is recorded: the selection round for the winner, the last executed round otherwise).
`coveredBeforeDecision` becomes a *derived* field: `coveredRound.present && coveredRound <
evaluationRound`. Validator law: `marginalCoverage = Σ finalWeight(k) for k in coverKeys with
¬coveredBeforeDecision(k)`. On this fleet (B=1) the derived value is false everywhere except
shared keys covered by the winner — and now it is *computed*, not asserted.

### B.3 · BLOCKING — NaN → `infeasible` erases the distinction the code's own author drew
`p1cost.go:24-26`: *"UnactionableNaNCategory is deliberately distinct from ordinary infeasibility:
the former means a fixable data failure, the latter means the safety laws are working with valid
data."* Mapping it to `infeasible` (D-3) collapses exactly this. But the ticket's 10-value list has
no data-quality value, and inventing an 11th deviates from the ticket.
**Ruling:** keep `status` in the 10-value list *and* add a mandatory sibling closed enum
`exclusionKind` ∈ {`not-enabled`, `recon-cover`, `feasibility`, `cost-nan`, `slo-gate`,
`reactive-only`, `selection`, `none`} with `reason` verbatim. This *is* R-2 ("different conditions
with different fixes") and it keeps `status` ticket-conformant: NaN rows read
`status=infeasible, exclusionKind=cost-nan`. Every row must carry all three.

### B.4 · BLOCKING — the status mapping has no value for the state 100% of vllm rows are in
Live vllm candidates are suppressed by `!attackBackedKey` (`:359-361`, reactive-only) and are never
scored (`netGain` absent). The proposal maps them to `candidate`, which reads as "was in the running".
**Demand:** per row `scored` (bool = key ∈ `evaluatedMarginal`) and `exclusionKind=reactive-only`
for the unscored-because-reactive case (the existing `selectionReason` string stays verbatim as
`reason`). A `candidate` row with `scored=false` and `exclusionKind=reactive-only` is honest; a bare
`candidate` is not.

### B.5 · BLOCKING — dispatch outcomes: the runner has more than four states for a *selected* move
`manager.go:1053-1085`: before `Actuate` is called there are three `continue` guards that leave a
**selected** decision un-dispatched — the inviolability guard (`!Feasible || Action == noop`, `:1060`),
the fail-closed missing-tick-view veto (`:1074`), and the emit-boundary feasibility re-check veto
(`:1079`). Under the proposal those record `not-attempted`, indistinguishable from an unselected
record. Also `err` splits into `OutcomeFailed` vs `OutcomeDeadlineExpired` (`:1100-1103`).
**Demand:** enumerate every `continue` in the loop and map: unselected → `not-attempted` (reason
`unselected`); selected but refused by a guard → `not-attempted` with `reason` = the guard's name
(these are "current known states", so the ticket permits them; do not invent a 5th enum value);
`err` → `dispatch-error` with `reason` = `failed` | `deadline-expired`; `res.Emitted=false` →
`emitted-false`; `res.Emitted=true` → `emitted`. State the dry-run and kill-switch cases explicitly
(does `actuate` run at all? if not, `not-attempted` + reason `dry-run`/`kill-switch`). Stamp on
`decisions[i].Trace` only if non-nil (trace-off path).

### B.6 · Corrections (not blocking, must land in 03)
- **`movesSelected` already exists.** `buildDecisionTrace(..., demand, len(selectedAsset), ...)`
  (`coverage.go:532-533`) — the parameter named `movesSpent` *is* the per-tick selected count.
  Do not add a duplicate field; add the ticket's name as a documented alias only if you also add
  a `Validate` equality, else skip it and say so in 03.
- **§12 assetUID sort is a no-op.** The builder keeps only `candidate.Key == assetKey` (`:723`,
  `:781`): one asset per record. Do **not** touch the comparator in `Canonical()`; satisfy §12 by a
  `Validate` rule "every candidate's key prefix equals the record's asset" and say so. Changing the
  sort key for a single-asset list risks the T0-D ordering test for nothing.
- **`costModelVersion`:** `Name()` is on `p1CostModel` (`p1cost.go:297-299`, the registry stub), not
  on `*P1Cost`. Name the actual accessor you will call; if none exists, add one that returns the
  same constant — do not hard-code the string in the builder.
- **"Exactly 15 rows":** define *canonical vocabulary* = `model.MutatingActions` (15) and say why
  `noop` (the record's selected-action sentinel) and `disable` (a policy switch) are not moves. Pin
  in `Validate`: `len(actionStatus) == len(MutatingActions)`, canonical order, unique.
- **`coveringActions`:** compute from recon's `CoverByAction` over **all** actions, not only enabled
  ones — enablement is what `actionStatus` records; a fact's cover set is a property of the fact.
  State it.
- **`sloGateResult`:** present/true for generated candidates (they passed `:229`), present/false for
  `conformal-slo` rows, absent for rows excluded before the gate. Record trace-level `costCeiling` =
  the generator's `d.CostCeiling` (the effective value), not `pol.CostCeiling` (0 ⇒ default).
- **Validate() has no non-test caller** (grep at 515c56a: none). Every reconstructability invariant
  you add there runs only in tests; the production check is my Task-9 validator. Say this in 03 so
  nobody reads `Validate` as a runtime guard. (Wiring it into the writer is a separate decision.)

### B.7 · Test plan — one part is impossible as written
"Replay the two frozen live records through the builder" cannot be done: a record is the builder's
*output*; the builder needs a `WorkloadView`, an `ActionSet` and engine state. There is no frozen
input corpus (the L2 battery gap, bus 267).
**Demand:** L2 = constructed fixtures in the style of `decision_trace_test.go` (`covView`,
`fixedTraceEngine`) covering: B=2 two-asset tick (B.2 semantics, `coveredRound`), GPU-unprimed
rotate (B.1 envelope), NaN feature (B.3), reactive-only asset (B.4), each dispatch state (B.5),
not-enabled action, `conformal-slo` reject (set `CostCeiling` low), trace-on/off byte-identical
selection on all of them, and the existing frozen-corpus equivalence test extended to the new
fields. The two live records serve one purpose: my validator must **accept** the v2 shape
(schema-versioned reader) and **reconstruct** ECost/netGain from them; that is a validator test,
not a builder test.

### B.8 · Agreements (no change requested)
- λ tier-exit pushback (D-5): agreed and independently recorded (§A-addendum). T0-C records the
  field; non-zero λ is a fixture property; the boss hears it from Mehrdad as M-144, not as T0-C.
- Capability → `not-evaluated-by-current-model`, `not-installable` emitted by no mapping: agreed.
- Envelope stays `phorvex.audit.v2`, trace → `phorvex.decision-trace.v3`, v2 readable: agreed —
  note `Canonical()` currently *forces* `SchemaVersion = V2` (`decision_trace.go:214`); that line
  and the T1-A leakage test's expectations change with the bump.
- Record growth ≤ 5%: accepted; my validator will measure it on the live corpus.
- Blast radius: accepted, with one addition — `ShadowCheckedOptimizer`/`DecideChecked`
  (`manager.go:864, 982`) also consume `Decision`; confirm they ignore `Trace`.

### B.9 · Skeptic's declared L3 band (for 06)
On the first ≥1,000 post-deploy records: 100% carry exactly 15 `actionStatus` rows in canonical
order; vllm rows read 13×`not-enabled` + 2×(`candidate`, `scored=false`, `reactive-only`); selection
distribution and the 5-per-4.7h voice `rotate` rate unchanged within noise; validator reconstructs
selected/noop, ordering, ECost, CHi on 100% (CHi via B.1's law on unprimed-GPU rows); 0 forbidden
statuses; 0 redaction hits; record size +≤5%. Any selection flip on identical inputs = REOPENED.

**State → CRITIQUED.** Five blocking demands (B.1–B.5), corrections (B.6), test-plan fix (B.7).

### B.10 · Skeptic's own erratum (post-03)
§A.4 and §A.5 say "16" action-status entries. `model.MutatingActions` has **15** members at
`515c56a` (`types.go:105-114`); the CRD's 17 = 15 + `noop` + `disable`, neither a move. 03's B.6.4
is correct; §A is left as sealed and corrected here. No effect on any demand.
