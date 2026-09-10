# Skeptic evidence notes · T0-C (Claude)

## 2026-09-03 ~17:00Z — validator baseline + a mislabelled baseline record
- `validator/run_baseline.sh` → 2 records / 2 PASS / 0 FAIL; check 12 (v3 hooks) SKIPPED (v2 traces).
  Positive controls: nine mutations by the builder agent + one by me (`expectedCost` +0.01 on the
  selected voice candidate → `check 5 ecost-law: FAIL` at `decisionTrace.candidates[0].expectedCost`).
- Finding: `evidence/live-baseline/01-selected-record-rotate-voice-0.4.74.json` is a **0.4.73**
  record (`brainImage …:0.4.73`, `gitSHA 727b408`, `timestamp 12:13:46Z`, 1h41m before the 0.4.74
  rollout; `inputs` lacks the `leakage` key). The 4.7 h retained corpus straddles the deploy.
  Reported to Proposer (bus 280). Consequence for L3: filter on `gitSHA`, never on capture time.
- L0 baseline at 515c56a: `evidence/L0-baseline-515c56a.txt` — build OK, vet OK, 6 packages `ok`.

## 2026-09-03 ~17:55Z — validator vs v3 fixture records (post-fix e8180da)
- 9 fixture records dumped via a throwaway test (deleted after; tree clean). `--strict-v3`: 6 PASS / 3 FAIL.
- FAIL #1 (gpu, check 12 CHi): **validator bug, not a record bug.** Record: ECost 1.09, q 0.1,
  envelopeApplied {present:true,value:true}, envelopeSlack 0.6, CHi 1.69 = 1.09 + max(0.1, 0.6) ✓.
  My hook read `gpuEnvelopeApplied` as a bare bool; K3 encoded it as OptionalBool. → validator fixed
  to accept both. **03 deviation to record:** 03 B.1 said "bool, not Optional"; the diff made it
  OptionalBool (present wherever cost ran). Arguably more honest for NaN rows; accepted, noted in 05.
- FAIL #2/#3 (b2 round-c, b0; check 4): envelope `action=quarantine, selected=false, reason="…not
  selected…"` vs trace `selectedAction=noop`. This is the **M-16 residual** (fallback names a
  candidate), pre-existing, outside T0-C. → validator: envelope `action` is authoritative only when
  `selected=true`; otherwise reported as INFO "envelope names fallback candidate (M-16)".
- Executor hygiene: `go build/test` with `GOFLAGS=-mod=mod` rewrote `phorvex/go.mod` (toolchain line);
  reverted with `git checkout -- phorvex/go.mod`. Rule for future runs: check `git status` after
  every Go invocation before reporting "tree clean".

## 2026-09-04 ~18:05Z — K3 L3 report read; NOT accepted yet (bus 296)
- K3 ran their own v3 invariant checks on 15,159 records at 0.4.80 (all pass, 817 vllm honest rows).
  Not the verdict evidence: no exported slice for the independent validator (bus 294 step 2). Demanded.
- **Size band at risk.** K3: v3 mean 83,308 B vs v2 "~15-20 KB" fleet mean (×4-5). Declared band
  (01 §4 D-4, accepted in 03): ≤ +5%. Fixture math: `actionStatus` = 15 rows ≈ 1.6 KB (~100 B/row);
  facts ≈ 556 B/fact in v3 (v2 ≈ 400 B: +`coveringActions`, `coveredRound`, `decompositionAvailable`).
  For the vllm record (122 facts, v2 = 97,934 B) that predicts ≈ +20 KB ≈ +20% — already > 5%, but
  not ×4. Fleet mean ×4 is unexplained by the schema → either pod-mix shift or something else grew.
  Decision deferred to per-pod measurement on the export. If per-pod > +5% → REOPENED on D-4.
- Retention side-effect (pre-0.4.80 corpus rotated out ~4-5× faster) = register entry regardless
  (K3 to file: PVC cap, history depth before/after).
- Node flap 17:28-17:46Z (RWO force-detach, ~18 min brain downtime) — infra, noted.

## 2026-09-04 ~19:25Z — Skeptic concurrence on closure
- 06 (K3) read: checks 1/2/5/6 PASS as measured; 3 CONFOUNDED (#104 in the deployed build) with the
  Class-A claim resting on the offline equivalence suite — correct labelling; D-4 FAILED PREDICTION,
  amended by the owner (K3 reports Mehrdad approved directly ~19:15Z; relayed to Mehrdad for the record).
- Independent half = `evidence/live/02-validator-strict-v3-0.4.80.md`: 2,002/2,002 PASS. Size measurement
  `evidence/live/03`. Register: B-5/R-2/R-9 ✅ CLOSED minus CI stage; M-154 filed; version stamp 0.4.80 @ 17082b7.
- Cycle 2 verdict: **CLOSED (code half).** Open by design: CI stage (hami), M-154, 9 follow-ups.
- Process lesson for cycle 3: the Skeptic's band (§B.9) copied the Proposer's size number instead of
  deriving it — blind derivation must cover EVERY declared quantity, including the boring ones.
