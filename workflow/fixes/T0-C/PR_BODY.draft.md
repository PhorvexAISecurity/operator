## Record the complete decision path (`phorvex.decision-trace.v3`)

**Ticket:** T0-C (B-5 / R-2 / R-9, Tier 0 "instrument and unblock") · **Class:** record-only, additive · **Base:** v0.4.75 (`67acdc3`, the deployed build)

### What was wrong

The audit record could not answer, from its own content, why the brain chose an action: which of the 15 canonical actions were considered and why the rest were not, whether the worst-case cost that gated a move can be recomputed, whether a fact was already covered when a candidate was scored, and what happened at dispatch. Distinct causes (`not-enabled`, `no-cover`, `infeasible`, NaN input, SLO-gate reject, priced-out, reactive-only suppression) were absent or collapsed into free text; `coveredBeforeDecision` was hard-coded `false`; the dispatch outcome was one boolean.

### What changes

- `decisionTrace` bumps to **`phorvex.decision-trace.v3`** (envelope stays `phorvex.audit.v2`); v2 records remain readable and re-marshal as v2.
- **`actionStatus`**: exactly one row per canonical mutating action (15), canonical order, with a closed `status` (the ticket's 10 values), a closed `exclusionKind` (`not-enabled | recon-cover | feasibility | cost-nan | slo-gate | reactive-only | selection | none`), the verbatim `reason`, and a `scored` flag. Capability/installability is recorded as `not-evaluated-by-current-model`; `not-installable` is emitted by no mapping because nothing evaluates it today.
- **CHi reconstruction** per costed candidate: `conformalQuantile` (post-clamp), `conformalCalibrated`, `gpuEnvelopeApplied`, `gpuEnvelopeSlack`, `sloGateResult`; trace-level effective `costCeiling` and `costModelVersion`. Law, enforced in `Validate`: `CHi = ECost + (rotate ? max(q, applied ? slack : 0) : 0)`.
- **Round semantics**: `evaluationRound` per record, `coveredRound` per fact; `coveredBeforeDecision` is derived (`coveredRound < evaluationRound`) and `marginalCoverage` reconstructs from it.
- Facts gain `coveringActions` (all actions, canonical order) and `decompositionAvailable`; inputs gain `sloHeadroom` (present only when measured from P99), `nextStage`, `projectedNextStageSec`.
- **`dispatchOutcome` / `dispatchReason`** stamped by the runner across the whole pre-dispatch guard surface (`unselected`, `dry-run`, `kill-switch`, `ensure-policy-failed`, `inviolability-guard`, `no-tick-view`, `emit-boundary-infeasible`, `failed`, `deadline-expired`, `emitted-false`, `emitted`). No Tier-2 "confirmed" state is introduced.
- Read-only accessors on the cost model (`Name`, `ConformalQuantile`, `ConformalCalibrated`); an additive `CoverByAction` on the action set; a write-only `coveredRound` map beside the existing `covered` map in the selection loop.
- `Validate` v3 branch: mandatory `costModelVersion` and positive finite `costCeiling`; an unknown selected action is an error, not a panic.

### Behavioural delta

Selections, actuations, belief, cost values, λ dynamics and metrics are byte-identical on identical inputs; only the record gains fields. Pinned by the frozen-corpus trace-on/off selection-equivalence test, extended to the new fixtures. Record size grows ≤ 5%. `movesSpent` is the per-tick selected count (documented, no duplicate field). No Prometheus labels added.

### Evidence

- New fixtures: canonical-vocabulary completeness, two-round covered semantics, GPU-unprimed rotate envelope terms, NaN-vs-infeasible distinction, reactive-only rows, conformal SLO-gate reject, a property test over varied policies including budget 0, trace-on/off equivalence, malformed-v3 rejection; a 9-case dispatch-outcome table in the runner. Whole suite green; `go vet` clean; builds with `-mod=readonly`.
- An independent validator (stdlib Python, built against live records without sight of this diff) fails the two pre-change live records under strict v3 checking and passes all nine v3 fixture records on every reconstruction law above.

### Known limits

- Live, `lambdaRuntime` is recorded but stays 0 on this fleet (demand never exceeds budget); the non-zero observation is a fixture property.
- `conformal-slo` rows appear only when the gate fires — zero times in the retained corpus.
- The envelope's `omitempty` fields and the `vramFraction` presence flag are unchanged (separate entries).
- CI integration of the validator (a stage in the E2E job) is a follow-up; this PR is the code half of the ticket.

### Live verification after deploy

On the first ≥1,000 records of the new build, filtered on the record's own `gitSHA`: 15 `actionStatus` rows per record in canonical order; selection distribution unchanged against the previous build; the validator reconstructs selected/noop, ordering, ECost and CHi on 100% of records; zero forbidden statuses; zero redaction hits.

### Rollback

Revert the commits. Record-only; no CRD, state or migration. v3 records already written stay readable by v3-aware readers; older readers ignore unknown fields.
