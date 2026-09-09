# 01 — Proposal · T0-C · B-5/R-2/R-9 "record the complete decision path" (Proposer: K3 seat)

## 1. Root cause

The decision record captures the outcome of the selection, not the path to it, because the
trace builder can only see what the pipeline hands it — and the pipeline hands it less than the
decision used. Five structural loci, each quoted:

1. **The generator iterates only enabled actions** — `for _, action := range enabledActions(pol)`
   (`internal/actionset/generator.go:188`; `enabledActions` :106). A not-enabled action produces
   no candidate and no exclusion row, so downstream nothing can record it. Live: vllm has rows
   for 2 of 15 canonical actions (`evidence/live-baseline/00-facts.md` §bonus).
2. **The builder records only rows the set carries** — `set.Candidates` + `set.Excluded`
   (`internal/decision/coverage.go:722-810`). What never entered the set is invisible.
3. **Coverage state is fabricated as "not covered"** — `CoveredBeforeDecision: false` hardcoded
   (coverage.go:709); the real `covered` map exists in the greedy loop (coverage.go:344,
   :385-387) but is never passed to the builder.
4. **Cost internals stop at the engine boundary** — the conformal quantile (conformal.go:85),
   the ceiling (`EffectiveCostCeiling`, p1cost.go:33), the SLO-gate pass/fail
   (generator.go:229-234) and the cost model's identity (`rls-dual-conformal`, p1cost.go:299)
   are all computed and all dropped. `UnactionableCategory` reaches a row only when it fires at
   generation; the builder re-derives it only to *omit* CNorm/CFlow (coverage.go:803-807).
5. **Dispatch outcome is collapsed into one bool** — the runner knows all four states
   (`err` → failed, manager.go:1099-1106; `res.Emitted` true/false, :1108/:1128; never-attempted
   for unselected) but the record keeps only `actuated` (log.go:44), merging `not-attempted`
   with `emitted-false` and dropping `dispatch-error` entirely.

Why this is the cause, not a symptom: the ticket's "cannot reconstruct" list (actions
considered/excluded/why, cost decomposition, structured λ, RLS primed, dispersion multipliers)
maps one-to-one onto these five loci — every missing quantity is computed and dropped at exactly
one of them. Gap map: `AUDIT_V2_GAP_MAP.md` (field-by-field vs the live 0.4.74 record).

## 2. The fix

Bump the companion schema to **`phorvex.decision-trace.v3`** (envelope stays
`phorvex.audit.v2`; v2 records stay readable via the existing rollback-aware `Validate`).
All changes are additive recording; nothing that feeds selection, belief, cost, or actuation
changes its value. Files:

- `internal/model/decision_trace.go` — v3 schema const; new fields (below); `Canonical()`
  extended (redaction + ordering); `Validate()` extended (v3 invariants; v2 branch preserved).
- `internal/actionset/generator.go` — carry `CoverByAction` per asset into `ActionSet`
  (additive field; it is already computed at :188 as `af.CoverByAction`).
- `internal/cost/p1cost.go` + `conformal.go` — expose the conformal quantile via a read-only
  accessor on the model (`ConformalQuantile() (q float64, ok bool)`); add `CostCeiling` and
  gate outcome to `Evaluation` (additive fields). **No `Observe`/RLS mutation on this path.**
- `internal/decision/coverage.go` — `buildDecisionTrace` populates v3: the per-action status
  array, the new candidate fields, the fixed `coveredBeforeDecision`, trace-level
  `movesSelected`/`costCeiling`/`costModelVersion`, inputs += `sloHeadroom`, `nextStage`,
  `projectedNextStageSec` (with presence).
- `internal/runner/manager.go` — stamp `dispatchOutcome` on the trace alongside the existing
  `Actuated` stamp (:1099-1130).

New/changed record content:

- **`actionStatus` (per asset, exactly 15 rows, canonical order)** — one per `MutatingActions`
  entry: `action`, `status`, `reason` (the existing vocabulary string, verbatim), plus
  `evaluated` markers where the current model never looked. Status mapping from existing
  pipeline facts, nothing invented:
  - not in `enabledActions(pol)` → `not-enabled`
  - enabled, `len(coverKeys)==0` → `no-cover` (reason = `recon-cover: …`)
  - feasibility verdict false → `infeasible` (reason = verdict.Reason, e.g. `availability:*`,
    `anti-over-rotation:*`)
  - cost `UnactionableCategory != ""` → **`infeasible` with the full `category: detail` reason
    preserved** — declared judgment call: the ticket's enum has no data-quality value, the
    action WAS evaluated and fail-closed before candidacy; `not-evaluated-by-current-model`
    would be the dishonest mapping. Skeptic attack welcome (§4, D-3).
  - `conformal-slo` gate reject → `conformal-slo` (reason string already carries CHi vs ceiling)
  - generated, not selected, netGain ≤ 0 → `priced-out`; generated, not selected, budget
    exhausted → `budget-exhausted`; generated, not selected, other → `candidate`
  - selected → `selected`
  - capability/installability: **never evaluated per-asset in the decision path today**
    (M-20's witness gates nothing) → trap 3 applies: `not-evaluated-by-current-model`,
    NOT `not-installable`. `not-installable` is emitted by no mapping in this increment.
- **per-candidate += `conformalQuantile` (OptionalFloat), `sloGateResult` (OptionalBool +
  reason), `selectionRound` (OptionalInt, per candidate)**; trace-level +=
  `costCeiling` (float), `costModelVersion` (string, `tcost.Name()`), `movesSelected` (int).
- **facts += `coveringActions` ([]string, canonical order, from the plumbed `CoverByAction`),
  `decompositionAvailable` (bool, false — the named honest-absence flag the ticket asks for;
  the four decomposition OptionalFloats stay absent), and `coveredBeforeDecision` fixed**:
  covered by a move selected in an *earlier* round of this tick, excluding the record's own
  selection (builder receives the loop's `covered` map and subtracts the own-selected
  candidate's coverKeys). On the deployed fleet (maxMovesPerTick=1 everywhere) this yields
  winner-facts=false, other-assets'-facts=(covered by the winner) — honest both ways.
- **inputs += `sloHeadroom` (OptionalFloat — presence keyed on the SLO computation having run),
  `nextStage` (string), `projectedNextStageSec` (OptionalFloat)** — all three exist at the
  envelope today (log.go:55,68,84); v3 lifts them into the trace with presence.
- **`dispatchOutcome`**: `not-attempted | emitted | emitted-false | dispatch-error` — mapped
  1:1 from the runner's existing knowledge; no `confirmed`/`attack-mitigated` (ticket).
- **ordering**: candidate sort key becomes assetUID-then-canonical-action (ticket §12;
  today it is the namespace/name prefix — gap map §12).
- **redaction**: all new strings through `redactTraceString`; arrays stay in records, never
  metric labels (ticket trap 6).

Why minimal: every added quantity is already computed at the locus it is recorded from
(trap 2 — uncomputed ⇒ unavailable is preserved by absence/flags, not fabrication). The one
plumbing change (`CoverByAction`) carries existing generator output. No selection-path code
changes; `buildDecisionTrace` stays post-selection and read-only (coverage.go:601-603).

## 3. Blast radius

Writers: the five files above. Readers of the changed structs:
- `DecisionTraceV2` readers: `Validate`/`Canonical` (same file), audit read shim (old-to-new,
  log.go), the T1-A leakage trace test, console consumers of the JSON (additive fields —
  unknown-field-tolerant JSON readers unaffected). Envelope contract untouched.
- `ActionSet` readers: the greedy loop (reads `Candidates`/`FactWeights` only), the builder.
  Adding `CoverByAction` changes no selection behavior — verified by reading every
  `set.` use in coverage.go (selection reads: :355-398; builder reads: :700-810).
- `cost.Evaluation` readers: generator exclusion path (additive fields, existing reads
  unchanged), the builder's excluded-row branch.
- `runner/manager.go`: stamps one more field post-decision; the audit write happens after the
  dispatch loop, so the stamp is visible in the record.
Register entries touched behaviorally: **none** (record-only). Adjacent, NOT fixed here (and
declared so): M-152 (`vramFraction` flag drop — one-line fix, separate cycle), M-146 (envelope
`omitempty` — envelope is out of v3's scope), M-20 (capability witness gating — T0-C records
`not-evaluated-by-current-model`, it does not wire the witness), M-35 (`emitted` ≠ effect —
v3 records dispatch honestly but does not add effect confirmation; ticket §11 forbids it).
Record-size effect: +13 status rows ≈ +2–3 KB and small per-candidate additions on a ~100 KB
record ⇒ **≤ +5%**, retention 4.7 h → ≈4.5 h (facts §4). Acceptable; noted for the validator's
frozen-corpus requirement.

## 4. Declared behavioral delta — **Class A** (record-only; "nothing else changes")

Classification rationale: no change to objective, belief, cover, cost values, feasibility,
selection, or actuation; the builder remains post-selection and read-only; the cost engine
gains only read-only accessors. The ticket's own predicted range asserts "selection unchanged".

Exact delta list (the complete set of observable changes):
- D-1. `decisionTrace.schemaVersion` = `phorvex.decision-trace.v3` on new records; v2 records
  remain readable. Envelope schema unchanged.
- D-2. New fields appear, populated as in §2: `actionStatus` (exactly 15/asset, canonical
  order), per-candidate `conformalQuantile`/`sloGateResult`/`selectionRound`, trace-level
  `costCeiling`/`costModelVersion`/`movesSelected`, inputs `sloHeadroom`/`nextStage`/
  `projectedNextStageSec`, facts `coveringActions`/`decompositionAvailable`,
  `dispatchOutcome`. `coveredBeforeDecision` stops being hardcoded false (on this fleet:
  remains false on winners' facts; becomes true on facts the same-tick winner covers).
- D-3. The NaN-category → `infeasible` status mapping (declared judgment call, §2).
- D-4. Record size grows ≤ +5%; PVC retention declines proportionally (≈4.7 h → ≈4.5 h).
- D-5. **Nothing else changes.** Selections, actuations, stage/belief values, cost values,
  λ dynamics, metrics, CRD status, and all non-record behavior are byte-identical on identical
  inputs. Specifically on this fleet (facts §1a): `lambdaRuntime` remains a present numeric
  field that is **0-valued** — the ticket's tier-exit "λ observed non-zero on a tenant whose
  budget does not bind" is NOT observable on this fleet today (demand ≤ budget everywhere;
  M-19/M-22). The field is recorded; the non-zero observation requires a contended tenant and
  is asserted as a fixture property in tests, not a live-fleet prediction. `conformal-slo`
  status rows will appear only when the gate fires — zero times in the retained corpus; the
  live band for that status is therefore "absent, and its absence is not evidence of absence".

## 5. Test plan

Unit (new `decision_trace_v3_test.go` + extensions):
- v3 round-trip + canonical ordering (facts by key, candidates by assetUID→canonical action,
  coverKeys lexical); redaction on all new string fields.
- `actionStatus` completeness: exactly 15 rows, canonical order; mapping tested per branch —
  not-enabled / no-cover / infeasible / conformal-slo / NaN-category→infeasible / priced-out /
  budget-exhausted / selected / not-evaluated-by-current-model (capability).
- `coveredBeforeDecision` honesty: two-round fixture — winner's facts false, facts covered by
  an earlier-round selection true, own-selection excluded.
- Reconstruction: ECost and CHi from recorded components incl. `conformalQuantile`
  (CHi = ECost + q on the additive branch; GPU-envelope branch records q absent + gate result);
  netGain identity (existing `Validate`); dispatch enum mapping for all four states.
- v2 rollback read preserved; v3 `Validate` rejects missing mandatory v3 fields.
- Golden: replay the two frozen live records (T0-C `evidence/live-baseline/01`, T1-A
  `evidence/live/02`) through the builder — decisions byte-identical except the added fields.
Existing invariants stressed: none (record-only). Live (L3, post-deploy, mine): vllm records
show 15 `actionStatus` rows with 13 × `not-enabled`; voice selected records keep identical
economics (positive control: rotate still selected, ECost/netGain reconstruct); Skeptic's
Task-9 validator reconstructs selected/noop, ordering, ECost, CHi from the record alone on a
frozen corpus export. Post-fix register status: R-2/R-9 closed; B-5 closed; M-20/M-35/M-146/
M-152 explicitly unchanged.

## 6. Version anchor

Base `515c56a` (release v0.4.74 == deployed `phorvex:0.4.74`, verified live 2026-09-03).
Branch `t0/record-complete-decision-path` (cut from origin/main @ 515c56a by the Skeptic).

## 7. Rollback

Revert the single commit. Record-only change: no CRD, no persisted state, no migration. v3
records already written remain readable by any v3-aware reader; pre-v3 readers ignore unknown
JSON fields. The audit PVC contents are append-only history — nothing to unwind.
