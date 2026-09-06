# T0-C diff review — Skeptic first pass (read-only)

**Commit under review:** `e8180da6165aabf33336818bef099116914e6040` (tip of `t0/record-complete-decision-path`, parent `515c56a`).
Note: the branch was **amended during the review** — `f552557` (reflog @{1}, 17:37Z) → `e8180da` (@{0}, 17:41Z). `git diff f552557 e8180da` is **empty** (metadata-only amend); every file:line below is at `e8180da` and identical in `f552557`.

**Build/vet/test (neutral run, scratchpad copy of the commit tree, go1.26.1, `build/` symlinked for the phoenix `replace`):**
`go build ./...` OK · `go vet` on model/decision/cost/actionset/runner/audit OK · `go test -count=1` all six packages **PASS** (decision 11.4s, runner 0.12s). `gofmt -l` flags `internal/model/decision_trace.go` (new — the base at 515c56a was clean; const block at :39-48 mis-aligned by one column); `internal/decision/engine.go` is also flagged but is untouched by the diff (pre-existing).

---

## 1. Selection-path purity

Hunks outside the allowed loci (a)–(f):

| Hunk | Can it change a selection/belief/cost/feasibility/actuation value? |
|---|---|
| `coverage.go:344-349` — `coveredRound := map[string]int{}`, `lastRound := 0` declared beside `covered` | No. Two new locals; nothing reads them in the loop. |
| `coverage.go:357` — `lastRound = round + 1` as the first statement of each round | No. Assignment to a local never read inside the loop; no branch depends on it. |
| `coverage.go:394` — `coveredRound[k] = round + 1` written **beside** `covered[k] = true` (:393) | No. Written, never read by the loop (only reads of `coveredRound` are `:750` in the builder). Exactly as 03 B.2 specifies. |
| `coverage.go:540-546` — `evaluationRound` computed inside `if pol.TraceEnabled` from `lastRound`/`selectedRound[key]`, passed at `:550` | No. Inside the trace-on branch, after the loop and after `decision` is fully built. |
| `p1cost.go:325-331` — `P1CostModelName` const hoisted; `p1CostModel.Name()` now returns the const | No. Same string value `"rls-dual-conformal"`; the registry stub is unchanged in behaviour. |
| `generator.go:147-148` — `ActionSet{... CostCeiling: d.CostCeiling, CoverByAsset: map...}` | No. Additive fields on the output struct; `d.CostCeiling` is still read at `:229` exactly as before. |
| `generator.go:172-174` — `out.CoverByAsset[key] = af.CoverByAction` | No. Stores the pointer to recon's map (shared read-only); the generator continues to iterate `af.CoverByAction` at `:177`/`:191` unchanged. The builder only reads it (`:733`). |

Checked and **unchanged**: `Evaluation()`/`Components()`/`ECost()`/`CHi()` (p1cost.go:150-247 — the diff inserts only the three accessors at `:208-236` between `ECost` and `CHi`); `Quantile()`/`Observe()`/`Calibrated()` (conformal.go untouched); no reordering, no early return anywhere in `decideChecked`; `Canonical()` candidate comparator (`decision_trace.go:435-452`) byte-identical (asset prefix → canonical rank → key), facts sort by key (`:397`) unchanged, coverKeys lexical unchanged. The new `ActionStatus` sort (`:432-434`) and `CoveringActions` sort (`:393-395`) are on new fields only.

New accessors `Name()`, `ConformalQuantile()`, `ConformalCalibrated()` (`p1cost.go:214-236`) are pure: nil-safe, call only `Quantile()` (sorts a copy) and `Calibrated()` (len check). `Observe` is unreachable.

**Selection-equivalence evidence:** `TestTraceEnabledAndDisabledAreSelectionEquivalentOnFrozenCorpus` (`reflect.DeepEqual` of the whole `Decision` minus Trace, 4 ticks × 3 assets, B=2) and the new `TestDecisionTraceV3FixturesAreSelectionEquivalentTraceOnOff` both pass.

**Verdict Q1: Class A holds.** No value read by the selection loop, the generator's candidate/exclusion decisions, the cost evaluation, feasibility, or actuation changes.

---

## 2. Spec conformance, field by field (03-decision B.1–B.6)

### B.1 CHi reconstruction
- `conformalQuantile` — post-clamp: `p1cost.go:218-227` clamps `q<0 → 0` exactly as `Evaluation` does at `:178-181`; recorded on rotate rows at `coverage.go:836` (candidates) and `:884` (costed exclusions). ✔
- `conformalCalibrated` — `Conformal.Calibrated()` via `:230-236`; recorded `:837`/`:885`. ✔ (test asserts `present && false` on the cold-start engine.)
- `gpuEnvelopeApplied` — `candidate.Action==rotate && v.Pod.HasGPU && !primed` at `:795`/`:879` — the same predicate as `Evaluation :182`. **Deviation (arguably better):** spec says "bool, not Optional"; diff uses `OptionalBool` (`decision_trace.go:203`), present on every costed row (`:833`/`:880`), **absent** on NaN rows and pre-cost exclusions. This resolves the spec's own contradiction ("all four absent" on NaN rows vs "bool, not Optional").
- `gpuEnvelopeSlack` — present iff applied, value `pol.FlowDisruption*cost.GPUEnvelopeMax()` (`:838`/`:886`) — matches `Evaluation :183`. ✔
- NaN rows: `Exclusion.CostEvaluated` is false on the NaN branch (`generator.go:213-217`), so the `:866` block is skipped and all four are absent. ✔ Tested.
- CHi law in Validate: `decision_trace.go:650-683` implements `CostHigh = ExpectedCost + (rotate ? max(q, applied?slack:0) : 0)`, and rejects slack terms on rows without a computed cost (`:656-659`) and rotate slack terms on non-rotate rows (`:675-677`). ✔

### B.2 round semantics
- `coveredRound` per fact (`OptionalInt`, `decision_trace.go:169`; written `coverage.go:766` from the loop map at `:750`). ✔
- `evaluationRound` per record (`:271`; computed `coverage.go:543-546`: winner → `selectedRound[key]`, else `lastRound`). `lastRound` is set at the top of each round (`:357`) so a round that breaks after evaluating still counts — correct semantics for "last executed round". ✔
- `coveredBeforeDecision` derived: `:755` = `factCovered && factCoveredRound < evaluationRound`. Hard-coded `false` gone. ✔
- Marginal law in Validate: `:698-718`. ✔ Also (5) at `:685-696` pins the derivation.
- Observation (not a defect): because `Generate` rejects the whole tick on any cross-block key claim (`generator.go:150-166`) and selection is one move per asset, no record's fact can be covered by *another* asset's earlier-round move — `coveredBeforeDecision` is structurally always `false` on a non-rejected tick. The `coveredRound[k] = round+1` overwrite (`:394`) is therefore never a "last vs first" hazard. Both laws are exercised only in that degenerate regime (see §5).

### B.3 exclusionKind
- Enum of exactly eight values `decision_trace.go:54-63`; pinned in `kindOK` `:595-599`. ✔
- Every row carries `status`/`exclusionKind`/`reason` (`:78-84`; `reason` verbatim from `ex.Reason` at `coverage.go:978`, from `c.SelectionReason` at `:996`). ✔
- Mapping is structural (`:981-992`: `Category≠""` → cost-nan/infeasible; `!FeasibilityEvaluated` → recon-cover/no-cover; `!Feasible` → feasibility/infeasible; else slo-gate/conformal-slo). No string sniffing on the exclusion path. ✔
- Consistency rules: `selected ⇒ none` (`:613-617`), `cost-nan ⇒ infeasible` (`:619-621`), one selected row iff `SelectedAction≠noop` and it is that action's row (`:627-635`). **Deviation:** the spec's `⇔` is enforced only as `⇒`: the defensive default row (`coverage.go:1017-1021`, `not-evaluated-by-current-model` + `exclusionKind=none`) is accepted by Validate (probe-confirmed). Unreachable by construction today (every enabled action is written to Candidates or Excluded), but the vocabulary has no honest kind for "never evaluated", so this is the least-dishonest choice; state it in 04.

### B.4 scored
- `scored` per row (`:83`), computed only for generated rows as `candidateKey ∈ evaluatedMarginal` (`coverage.go:995`); reactive-only rows → `candidate` / `reactive-only` / `scored=false` (`:1001-1005`). ✔ Rows that were excluded/not-enabled have the zero-value `false`, which is also true.

### B.5 dispatch outcomes
Four values `decision_trace.go:67-72`; Validate (7) `:720-725`. Table check (manager.go):
- unselected → builder default `not-attempted`/`unselected` (`coverage.go:939-940`). ✔
- dry-run → `:909-915` (inside `Trace != nil`, `Selected` only). ✔ `actuate` indeed never runs (`:938`).
- kill-switch → `:927-930`. ✔ (kill-switch overwrites dry-run when both — both flags still recorded.)
- `EnsurePolicy` error → `:1058-1066`, every selected traced decision. ✔
- inviolability guard `:1088`, no-tick-view `:1105`, emit-boundary `:1111`. ✔ **Deviation:** the spec says reason `emit-boundary-infeasible` "(+ verdict.Reason in detail)"; the diff concatenates `"emit-boundary-infeasible: "+verdict.Reason` into `dispatchReason` (no separate detail field). Free-text tail is redacted (`decision_trace.go:350`); the runner test matches on prefix. Arguably fine; a closed-vocabulary validator must prefix-match.
- `Actuate` err → `dispatch-error` / `failed`|`deadline-expired` `:1128-1134`. ✔
- `Emitted=false` → `emitted-false` `:1161`, `Emitted=true` → `emitted` `:1140`. **Deviation:** spec says `emitted-false` carries "the actuator's reason string"; the diff stamps `""` — `actuator.Result` carries no reason field (checked: test fake constructs `Result{Emitted: ...}` only), so nothing was dropped, but 04 should say so.
- Stamping guarded by `Trace != nil` everywhere (`:910`, `:926`, `:1062`, `:1077`). ✔
- Write ordering: `actuate` at `:943`, `m.Audit.Record` at `:948` — the stamp lands before the write. ✔
- **Deviation (new sentinel not in the table):** the builder defaults a *selected* record to `not-attempted`/`"pending-dispatch"` (`coverage.go:935-938`). Reachable at the audit write only when `!effectiveDryRun && !killEngaged && m.Actuator == nil` (`:938`) — `selectActuator` never returns nil in production, so live this is the "stamp bug made visible" the comment describes. Honest, but it is a fifth reason string; document it.

### B.6 corrections
1. No `movesSelected` field (grep: only the pre-existing `console/benchmark_sim.go:66`). The alias is documented as a code comment at `coverage.go:667`, **not** in the schema struct comment or `docs/decision-trace-v2.md` as B.6.1 asked ("in the schema comment"). Minor.
2. Comparator untouched (`decision_trace.go:435-452`); §12 satisfied by Validate (3) `:638-648`. ✔
3. `costModelVersion` = `tcost.Name()` (`coverage.go:680`) via the new `P1Cost.Name()` accessor returning `P1CostModelName` (`p1cost.go:214`, `:327`) — no literal in the builder. ✔
4. Exactly 15 rows in `MutatingActions` order, unique: builder iterates `model.MutatingActions` (`coverage.go:970`); Validate pins count (`:585`), order (`:602-604`), vocabularies. ✔ Uniqueness follows from order+count.
5. `coveringActions` from `CoverByAsset` = recon's `CoverByAction` over ALL actions (`generator.go:174`; inverted at `coverage.go:730-741` in canonical order, disabled included). ✔
6. `sloGateResult`: present/true on generated rows (`:832`), present/false on `CostEvaluated` exclusions (`:878` — `CostEvaluated` is set **only** on the conformal-slo branch, `generator.go:221-224`), absent otherwise. ✔ `costCeiling` = `set.CostCeiling` = `d.CostCeiling` = `cost.EffectiveCostCeiling(pol)` (`coverage.go:226,236`). ✔
7. Validate doc-comment states test-only callers (`decision_trace.go:471-475`); grep confirms no non-test caller. ✔

---

## 3. Honesty traps

- **Constant presence flags:** `SLOHeadroom: traceOptional(true, ac.sig.SLOHeadroom)` (`coverage.go:719`). `ctxprov/sensed.go:152-155` sets `headroom := 1.0` and only overwrites it when `pol.P99Ms>0 && Telemetry.Present && P99Ms>0`. So a defaulted 1.0 is recorded as `present:true` — it is the value the pipeline *used* (same as the unflagged envelope field), but the flag cannot distinguish measured from default, which is the Trap-4 shape. 01 §2 promised "presence keyed on the SLO computation having run"; the diff does not deliver that (the `ContextSignals` struct carries no such flag, so fixing it needs a ctxprov change — out of Class A's file set). Also `AssetValue: traceOptional(true, …)` is pre-existing, unchanged.
- `DecompositionAvailable: false` (`:765`) is a constant by design — the named honest-absence flag from 01 §2; acceptable.
- `not-installable`: emitted by no mapping (`buildActionStatus` never assigns it); Validate **rejects** it (`:622-624`); property test asserts absence. ✔
- Redaction: every new string routed through `redactTraceString` — `CostModelVersion`/`DispatchOutcome`/`DispatchReason` (`:348-350`), `Inputs.NextStage` (`:374`), `CoveringActions` elements (`:389-392`), `ActionStatus.{Action,Status,ExclusionKind,Reason}` (`:424-431`). New OptionalFloats cleaned (`:375-376`, `:420-421`). ✔ No new string bypasses.
- Metrics: `grep 'prometheus\.\|metrics\.'` over the diff → **no matches**; `internal/metrics` untouched. ✔

---

## 4. Version semantics

- `Canonical()` no longer rewrites `SchemaVersion` (`decision_trace.go:321-324`; the old force-to-V2 line deleted). `MarshalJSON` calls `Canonical()` (`:465-469`) → a record carries whatever version it was constructed with: builder → v3 (`coverage.go:651`); a v2 record decoded from disk re-marshals as v2. Verified by the passing pre-existing `TestDecisionTraceV2NewRecordRetainsRollbackAliases` (model) and `TestAuditRecordCarriesVersionedDecisionTrace` (audit), both v2 fixtures asserting v2 on the wire.
- `Validate()` accepts v2 or v3 (`:477-480`); v2 path unchanged; `isV3` additionally requires `CostRepresentationVersion≠""` (`:560-561`) and runs `validateV3` (`:563-567`).
- v3 record missing mandatory new fields: probe confirms a v2-shaped fixture relabelled v3 is **rejected** (`actionStatus carries 0 rows, want exactly 15`); an empty `DispatchOutcome` is rejected by (7). **Gap:** `CostModelVersion == ""`, `CostCeiling == 0`, `EvaluationRound == 0` are **accepted** in a v3 record (probe-confirmed) — the "mandatory new fields" check is partial.
- **Robustness defect (test-only caller):** `validateV3` indexes `t.ActionStatus[canonicalActionRank(t.SelectedAction)]` (`:633`); for an unknown non-noop `SelectedAction` the rank is 15 → **panics** `index out of range [15] with length 15` (probe-confirmed) instead of returning an error.
- T1-A `TestDecisionTraceRecordsLeakageWithHonestAbsence` (`leakage_trace_test.go:15`) asserts Leakage presence/value and `Validate()==nil`; it never asserted the schema string, so it asserts exactly what it did and passes (now exercising the v3 branch of Validate).

---

## 5. Tests

### decision/decision_trace_v3_test.go
| Test | Load-bearing assertion (fails if the feature is removed) | Vacuity notes |
|---|---|---|
| `…ActionStatusCompletesCanonicalVocabulary` | `notEnabled != 13` and per-row canonical-order check; selected row must read `selected/none` | Real. |
| `…CoveredRoundSemantics` | winner: `f.CoveredRound.Value != tr.EvaluationRound` on covered facts; unselected asset `EvaluationRound != 2`; `selectedRounds != 2` guards the fixture | Real for `coveredRound`/`evaluationRound`. `coveredBeforeDecision` is asserted only `false` (structurally the only reachable value — see §2 B.2); the marginal law (6) is exercised only with all-false. |
| `…GPUUnprimedRotateCarriesEnvelopeTerms` | `GPUEnvelopeApplied` must be present+true; `GPUEnvelopeSlack.Value != wantSlack`; independent CHi recompute `|want-CostHigh|>1e-9` | Real; also asserts non-rotate rows carry no slack terms. |
| `…NaNExclusionKeepsDataQualityDistinct` | `nanRows != 2`; `Status != infeasible` on cost-nan; no slack/gate terms on NaN rows | Real (does not assert `GPUEnvelopeApplied` absent — it is, by the `CostEvaluated` gate). |
| `…ReactiveOnlyRowsAreHonest` | rows must be `candidate`/`reactive-only`/`scored=false` | Real. |
| `…ConformalSLOGateReject` | `CostCeiling != 1e-9`; rows `conformal-slo`/`slo-gate`; `gateRows != 2` with `SLOGateResult` present+false | Real. |
| `…ActionStatusPropertyVariedPolicies` | 15 rows, canonical, unique, no `not-installable`, `DispatchOutcome != ""` across 5 policies incl. B=0 and no-enabled | Real but **not random** — 03 B.7.8 says "over random policies"; this is a fixed 5-policy set. |
| `…FixturesAreSelectionEquivalentTraceOnOff` | `decisionsEqualSelection` (Selected/Action/ns/pod) | Real for P-C5, but weaker than the existing frozen-corpus test's `reflect.DeepEqual` (no DecisionValue/Feasible compare). |

### runner/dispatch_outcome_test.go
`TestActuateStampsDispatchOutcomeAcrossTheGuardSurface` — 9 subtests, each asserting the exact `DispatchReason`/`DispatchOutcome`; `fa.calls == 0` guards vacuity on the three refusal guards; `unselected-untouched` checks no re-stamp. Real.

### Coverage gaps vs 03 B.7
- B.7.5 **dry-run and kill-switch stamps are untested** (`manager.go:909-930` live in `processTenantWithPhysics`, which no new test drives).
- B.7.10 "frozen-corpus equivalence extended to the new fields": the pre-existing frozen-corpus test now runs `validateV3` on every record (implicitly covering the laws), but no golden/snapshot of the new fields was added.
- No **negative** fixture tests for `validateV3` in `model/`: wrong count/order/vocabulary, CHi mismatch, `coveredBeforeDecision` contradiction, marginal mismatch, bad dispatch, "v3 rejects missing mandatory fields" (01 §5) — none has a failing-fixture test; only the happy path is exercised via the builder.
- B.7.11 (validator tests on the two live records) is the Skeptic's tool, outside this diff — the validator already branches on v2/v3 (`fixes/T0-C/validator/audit_trace_validator.py:35-36, 712-719`).

---

## BLOCKERS
None that violate Class A or contradict 03's B.1–B.6 as written. Selection-path purity holds (every out-of-locus hunk is a never-read local, an additive struct field, or a constant hoist — §1). The closest calls are recorded as deviations below for the Proposer to state in 04, not to re-cut.

## DEVIATIONS
1. **Trap-4-shaped presence flag on `sloHeadroom`** — `coverage.go:719` records `present:true` unconditionally while `ctxprov/sensed.go:152-155` defaults headroom to 1.0 when P99 is unknown; 01 §2 promised presence keyed on the computation having run. Value is what the pipeline used, but "present" cannot mean "measured". State it in 04 or drop the field to the flagless envelope-only status until ctxprov carries a flag.
2. **`validateV3` panics** on an unknown non-noop `SelectedAction` — `decision_trace.go:633` indexes `ActionStatus[canonicalActionRank(...)]` with rank 15 (probe: `index out of range [15] with length 15`). Test-only caller, but a validator must return an error, not panic.
3. **Mandatory-field check is partial** — `CostModelVersion==""`, `CostCeiling==0`, `EvaluationRound==0` are accepted in a v3 record (probe-confirmed); `decision_trace.go:582-727` has no check for them.
4. **`selected ⇔ none` enforced only as `⇒`** — the defensive default row `coverage.go:1017-1021` (`not-evaluated-by-current-model`, `exclusionKind=none`) validates. Unreachable today; document the choice.
5. **`gpuEnvelopeApplied` is `OptionalBool`, not bool** (`decision_trace.go:203`; absent on NaN/pre-cost rows) — resolves the spec's internal contradiction; arguably the better shape, but 03 B.1 literally says "bool, not Optional".
6. **`emit-boundary-infeasible: <verdict.Reason>`** concatenated into `dispatchReason` (`manager.go:1111`) instead of a separate detail; readers must prefix-match.
7. **New reason string `pending-dispatch`** on selected records at build time (`coverage.go:935-938`), not in the B.5 table; reachable at the write only with `m.Actuator == nil` (never in production).
8. **`emitted-false` carries `""`** (`manager.go:1161`), not "the actuator's reason string" — `actuator.Result` has no reason field, so nothing is dropped, but 04 must say so.
9. **`movesSpent ≡ movesSelected`** documented only as a code comment at `coverage.go:667`, not in the schema struct comment / docs as B.6.1 asked.
10. **Test-plan shortfalls** — B.7.5 dry-run/kill-switch stamps untested; B.7.8 property test is a fixed 5-policy set, not random; no negative `validateV3` fixtures (v3-rejects-missing-fields from 01 §5 untested); B.7.10 new-field golden not added.
11. **gofmt** — `internal/model/decision_trace.go:39-48` const block mis-aligned (base was gofmt-clean; no CI gofmt gate found, so cosmetic).
12. Docs `decision-trace-v2.md:10-13` list `not-installable` in the status vocabulary without the "emitted by no mapping" caveat the code carries.

## CLEAN
- **Class A purity (Q1):** `coveredRound`/`lastRound` written beside `covered[k]` at `coverage.go:393-394`, never read by the loop; no reorder/early return; `Evaluation`/`Quantile`/`Observe` untouched; comparator and existing sort keys in `Canonical()` byte-identical (`decision_trace.go:397, 435-452`); `generator.go` changes are additive output fields; `P1CostModelName` hoist preserves the string. Frozen-corpus `reflect.DeepEqual` selection-equivalence test and the new v3 equivalence test pass.
- **B.1:** post-clamp quantile accessor mirrors `Evaluation :178-181`; `conformalCalibrated`, `gpuEnvelopeApplied` predicate ≡ `:182`, `gpuEnvelopeSlack` ≡ `:183`; NaN rows carry none of the four (`CostEvaluated` false on the NaN branch); CHi law pinned in Validate `:650-683` and independently recomputed in the GPU test.
- **B.2:** `coveredRound` per fact, `evaluationRound` per record with the agreed winner/last-round rule (`coverage.go:543-546`), `coveredBeforeDecision` derived at `:755`, marginal law `:698-718`, derivation law `:685-696`.
- **B.3:** exactly eight kinds (`:54-63`), structural mapping from `Exclusion` fields (`coverage.go:981-992`), `cost-nan ⇒ infeasible` and `selected ⇒ none` pinned, all three fields on every row.
- **B.4:** `scored` = key ∈ `evaluatedMarginal` (`:995`); reactive-only rows read `candidate`/`reactive-only`/`scored=false`.
- **B.5:** all guards in the table stamped incl. `ensure-policy-failed` (`manager.go:1058-1066`), dry-run (`:909-915`), kill-switch (`:927-930`); `Trace != nil` guarded everywhere; `deadline-expired` split; stamp precedes `m.Audit.Record` (`:943` → `:948`).
- **B.6:** no `movesSelected` field; comparator untouched + §12 via Validate (3); `costModelVersion` via `P1Cost.Name()` accessor, no literal; exactly 15 rows in `MutatingActions` order validated; `coveringActions` from `CoverByAction` over all actions; `sloGateResult` presence rules exactly as agreed and `costCeiling` = effective generator ceiling; Validate doc-comment names test-only callers.
- **Honesty:** `not-installable` emitted nowhere and rejected by Validate; every new string redacted in `Canonical()`; no metrics/labels touched; hard-coded `CoveredBeforeDecision: false` removed.
- **Versioning:** `Canonical()` no longer forces V2; v2 records re-marshal as v2 (two pre-existing tests prove it), builder emits v3; Validate accepts both; v3 rejects a record lacking `actionStatus` or `dispatchOutcome`; T1-A leakage test asserts exactly what it did and passes.
- **Build health:** `go build ./...`, `go vet`, and `go test` on model/decision/cost/actionset/runner/audit all green on the commit tree.
