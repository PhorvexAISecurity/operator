# 05 — Evidence · T0-C (B-5/R-2/R-9) · executor + Skeptic sections

**Fix commits (rebased onto `67acdc3`, v0.4.75 == deployed 16:38Z):** `18088a8` (Proposer's diff = `9098dcc`/`e8180da` content, trailer removed) + `b7235da` (Skeptic's three fixes + gofmt + negative test). **Pushed** to `origin/t0/record-complete-decision-path`. Pre-rebase SHAs cited elsewhere in this folder: `9098dcc` → `e8180da` → `18088a8`; `c03508d` → `b7235da`.

## Executor pass (Claude as neutral executor; raw output, unedited)

| # | What | File | Result |
|---|---|---|---|
| E0 | L0 baseline at `515c56a` — build, vet, test on the 6 touched packages | `evidence/L0-baseline-515c56a.txt` | BUILD-OK · VET-OK · 6 × `ok` |
| E1 | Post-fix `go build ./...`, `go vet ./...`, `go test ./...` (whole suite) at `e8180da` | `evidence/post-fix/01-build-vet-test-full.txt` | BUILD-OK · VET-OK · **28/28 `ok`**, test-exit 0 |
| E2 | CI-mode build (`GOFLAGS=-mod=readonly`) + vet | (this file) | READONLY-BUILD-OK · READONLY-VET-OK; commit touches no go.mod/go.sum |
| E3 | v3 records from the agreed fixtures (throwaway dumper test, deleted after; tree clean) | `evidence/post-fix/02-v3-fixture-records.jsonl` | 9 records: selected, B=2 ×3, GPU-unprimed rotate, NaN, reactive-only, SLO-reject, B=0 — all `phorvex.decision-trace.v3`, 15 `actionStatus` rows each |

## Red-before-green (FIX_LOOP §4)

The v3 fixtures cannot compile on the pre-fix tree (new API), so unit-level red is red-by-compile
and is **not** offered as evidence. The artifact-level red is:

| | File | Result |
|---|---|---|
| RED (pre-fix) | `evidence/pre-fix/01-validator-strict-v3-on-v2-records-RED.txt` | validator `--strict-v3` on the two pre-fix live records: **2/2 FAIL** at check 12 (`trace is v2, not v3`) |
| GREEN (post-fix) | `evidence/post-fix/03-validator-strict-v3-on-fixtures.md` (+ `.json`) | same check on the 9 v3 fixture records: **9/9 PASS** — all 12 checks incl. the v3 hooks (15-row status enum + exclusionKind consistency, CHi law with envelope, coveredRound/evaluationRound + marginal law, dispatch enum) |
| Controls | `validator/report-baseline-0.4.74.md` | v2 live records still 2/2 PASS on checks 1–11; ten mutated positive controls each caught by the intended check |

## Skeptic findings during the executor pass

1. **Rule-1 breach in the commit message** — `Co-authored-by: Cursor <cursoragent@cursor.com>`
   on `9098dcc`. Amended message-only → `e8180da`. K3 told (bus 284); K3's pre-commit grep must be
   case-insensitive.
2. **03 deviation (accepted):** `gpuEnvelopeApplied` is `OptionalBool` in the diff; 03 B.1 said
   plain bool. Present-wherever-cost-ran is the more honest encoding for NaN rows. Validator accepts both.
3. **Validator bugs found by the fixtures (mine, fixed):** (a) read `gpuEnvelopeApplied` as a bare
   bool → false CHi FAIL on the GPU fixture (record was correct: 1.09 + max(0.1, 0.6) = 1.69);
   (b) envelope `action` on an *unselected* record names the fallback candidate (M-16 residual) —
   now INFO, authoritative only when `selected=true`.
4. **Baseline record mislabelled** (K3's `live-baseline/01-…-0.4.74.json` is a 0.4.73 record:
   `brainImage`, `gitSHA 727b408`, 12:13Z, no `leakage` key). L3 must filter on `gitSHA`. Bus 280.
5. **Executor hygiene:** `GOFLAGS=-mod=mod` rewrote `phorvex/go.mod` (promoted 3 indirect requires);
   reverted. CI-mode (`readonly`) build verified separately (E2).


## Skeptic diff review vs 03 (full text: `evidence/post-fix/06-skeptic-diff-review.md`)

**Class A holds; no 03 blocker.** Every hunk outside the trace builder / schema / read-only cost
accessors / runner stamp is either a never-read local (`coveredRound`, `lastRound` written beside
`covered[k]`, read only by the builder), an additive output field (`CoverByAction`), or a constant
hoist with the same string. `Evaluation`/`Quantile`/`Observe` untouched; `Canonical()` comparator
and existing sort keys byte-identical; frozen-corpus equivalence test passes. B.1–B.6 conformant
field by field; `not-installable` emitted nowhere and rejected by `Validate`; all new strings
redacted; no Prometheus labels.

**Twelve deviations found. Three fixed before the PR (second commit, by the Skeptic — roles
swapped for these hunks; Proposer reviews after the fact):**
1. `validateV3` panicked (index out of range) on a selected action outside the canonical list → error.
2. `inputs.sloHeadroom` presence was hard-coded true; `ctxprov/sensed.go:154` defaults headroom to 1.0
   when P99 is unmeasured (Trap 4) → presence = the same predicate sensed uses.
3. `validateV3` accepted empty `costModelVersion` and non-positive `costCeiling` → mandatory.
   `evaluationRound ≥ 1` deliberately NOT required: B=0 yields 0 (no round executed; fixture b0).
Plus gofmt on the two files and a negative test (`TestDecisionTraceV3ValidateRejectsMalformed`).

**Nine accepted as follow-ups (recorded, not shipped):** `gpuEnvelopeApplied` is OptionalBool (03
said bool; the Optional shape is the more honest one for NaN rows — accepted as the spec);
`selected ⇔ none` enforced only as ⇒ (the defensive default row is unreachable today);
`emit-boundary-infeasible: <verdict>` concatenated into `dispatchReason`; new `pending-dispatch`
reason on selected records at build time (reaches the write only with no actuator); `emitted-false`
carries `""` (actuator.Result has no reason field); `movesSpent ≡ movesSelected` is a code comment
not a schema doc; dry-run/kill-switch stamps untested; the "random policies" property test is a
fixed 5-policy set; docs list `not-installable` without the "emitted by no mapping" caveat.

**Post-fix verification of the Skeptic commit:** `evidence/post-fix/05-build-vet-test-after-skeptic-fixes.txt`
(build, vet, whole suite, negative test verbose) — **BUILD-OK, VET-OK, 29 packages `ok`, test-exit 0; all 5 malformed-v3 subtests PASS.** After rebase: `07-after-rebase-v0.4.75.txt` (build OK, 7 packages ok incl. actuator touched by #99). Final v3 fixture records `08-…-final.jsonl` → validator strict-v3 `09-…-final.md`: **9/9 PASS**; `inputs.sloHeadroom` now honest-absent on every fixture (none measures P99).


## L3 (post-deploy, 2026-09-04) — deployed `phorvex:0.4.80`, gitSHA `17082b7` (contains merge `098ab89`)

| # | What | File | Result |
|---|---|---|---|
| L3-1 | K3 full-corpus structural scan (12,988 records, read-only reader pods, ledger in bus 295) | `evidence/live-l3/l3-verdict-0.4.80.txt` | 100% v3; 15 rows/record; closed enums; vllm 817 honest rows; `sloHeadroom` absent 100%; ceiling/version present 100% |
| L3-2 | **Independent validator** (Skeptic, `--strict-v3`) on K3's frozen slice: newest 2,000 + both selected records | `evidence/live/02-validator-strict-v3-0.4.80.md` (+`.json`, stdout) | **2,002 / 2,002 PASS**, 0 undecidable — selection, ordering, ECost, netGain, CHi (incl. envelope), covered-round, enums, redaction |
| L3-3 | Selection-unchanged | bus 295 step 3 | CONFOUNDED (deployed build carries #104); 2 selected / 12,988, both voice `rotate` — same signature as baseline; Class-A claim rests on the offline equivalence test |
| L3-4 | **Size band D-4 (≤ +5%)** | `evidence/live/03-size-band-measurement.md` | **FAILED PREDICTION: +26% same-pod same-fact-count** (vllm +26.0%, voice +25.6%); all added bytes ticket-mandated; retention depth roughly halved |
| L3-5 | Incidents | bus 295 | node flap 17:28–17:46Z (RWO force-detach, ~18 min brain downtime; infra); pre-0.4.80 corpus rotated out |

## Not yet produced

## Proposer after-the-fact review of b7235da (roles swapped, bus 290)

**Reviewed b7235da — clean.** Verified independently, not by inspection of his message alone:
(1) the panic guard (`rank >= len(t.ActionStatus)` → error) closes the unknown-selected-action
index-out-of-range; (2) mandatory `costModelVersion` and positive-finite `costCeiling` are
v3-only — the legacy v2 branch is untouched, and production always has `EffectiveCostCeiling > 0`;
(3) the `sloHeadroom` presence predicate (`pol.P99Ms > 0 && v.Telemetry.Present &&
v.Telemetry.P99Ms > 0`) matches the derivation predicate at `ctxprov/sensed.go:152-155` verbatim —
when it is false the 1.0 is a default, not a measurement, and the record now says absent (Trap 4);
(4) gofmt-only const realignment; (5) the negative test's five mutations each error without panic.
No defect found. 04-diff.patch regenerated as `git diff 67acdc3 b7235da` (the full PR diff).

Cluster mutation ledger (bus 282) was filed as `evidence/live-baseline/02-cluster-mutation-ledger.md`
at ~18:05Z — struck from "not yet produced".
