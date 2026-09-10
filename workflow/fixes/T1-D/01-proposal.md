# T1-D 01 · Proposal (K3, Proposer) — HELD until claude seals §A

Base: branch `t1/economics-exhaustive-phase-vocabulary` @ `5fe1c8e` (`v0.4.84`). Working tree verified on-branch at that SHA before any reading below. Do not open before your §A blind-derivation is sealed (sha+time in 02).

All line numbers below were re-read at `5fe1c8e` on 2026-09-05; nothing here is quoted from the ticket's `0.4.58`/`aedd218` frame.

## P1 re-screen findings — baseline verified, plus three findings of my own

Claude's `T1_D_BASELINE.md` claims were each independently re-verified against source (not trusted):
1. `cost/switching.go:63-74` — `flowCost` names all five phases explicitly, no `default:`. **Verified.**
2. `cost/rls.go:30-39` — `Features` names `PhaseDraining, PhaseUnknown` as a shared no-op arm. **Verified.**
3. `phorvex/.golangci.yml` carries the `exhaustive` config (T1-C); `grep -rn golangci .github/workflows/` → **zero hits: unwired in CI. Verified.**

My own additions beyond the baseline:

4. **The drift surface is THREE hand-synced encodings, not two.** The baseline names the two switches. There is a third: `rls.go:49-53` `priorTheta()` = `{0.15, 0.85, 0.55, 0.0, 0.45, 0.20}` — a *positionally keyed* restatement of the same vocabulary (bias, **cold, warm, idle**, gpu, load). The bit assignment `1=cold, 2=warm, 3=idle` exists only as implicit agreement between `Features` and `priorTheta`. A 6th phase, a bit reorder, or a prior tweak touches two files with no compiler or test complaint. Any honest "single source of truth" must bind all three, or the third keeps drifting silently.
5. **The consumer inventory is exactly two switches, module-wide.** `grep` for `switch.*\.Phase` / `case model.Phase` over the full module: only `switching.go:63` and `rls.go:30`. Everything else is pass-through stamping (`coverage.go:532`, `engine.go:189`, `ctxprov/sensed.go:169`, `audit/log.go:228`), hardcoded sim values (`console/benchmark_sim.go:448`, `console/applyfix_gate.go:30`), or a flag cast (`costprobe/main.go:449-451`, empty→Unknown). No `map[model.WorkloadPhase]` exists anywhere. The producer is `ingest/kube.go:636-656` `classifyPhase` (five return sites). **`internal/calib` has NO `WorkloadPhase` consumer** (`calib/snapshot.go:21` reads the *Kubernetes* pod phase, a different string) — the ticket's "Code: internal/cost, internal/calib" overstates; the real surface is `internal/cost` only.
6. **The unrecognized-string hole (pre-existing, must not regress).** Today, a `WorkloadPhase` value outside the five (replay of an old record, a cast like `model.WorkloadPhase("bogus")`) hits no arm: `flowCost` falls through to its `phase := 0.5` initializer; `Features` sets no bit. I.e. *unrecognized ≡ Unknown's encoding* in both files — by accident of initialization, not by statement. Any table-driven rewrite must make that fallback explicit and tested, or a zero-value map row (`switchPrior 0.0`, `featureBit 0`) would make an unrecognized phase **free to rotate** (`0.55×0 = 0`) and would set the **bias bit** — strictly worse than today on both axes.

## Design

### D1 — `model.AllWorkloadPhases` (the `MutatingActions` analog)
`internal/model/types.go`, directly under the const block (types.go:136-145):
```go
// AllWorkloadPhases is the SINGLE SOURCE OF TRUTH for the phase vocabulary (the
// MutatingActions analog): every consumer encoding (cost flow switch, RLS feature
// bits) is generated from — or tested against — this list. Order is canonical
// (declaration order) for future record-stamping, though no consumer depends on it today.
var AllWorkloadPhases = []WorkloadPhase{
    PhaseColdStarting, PhaseWarm, PhaseIdle, PhaseDraining, PhaseUnknown,
}
```

### D2 — one encoding spec, `cost/phase_encoding.go` (NEW), from which BOTH encoders *derive*
Not a test over two hand-written switches (that is the status quo + a tripwire); the switches are deleted and replaced by lookups into one table:
```go
// phaseFlowEncoding is the single spec from which flowCost (heuristic path) and
// Features/priorTheta (learned path) are BOTH derived. One row per
// model.AllWorkloadPhases member — enforced by phase_vocabulary_test.go.
var phaseFlowEncoding = map[model.WorkloadPhase]struct {
    switchPrior float64 // flowCost phase prior (heuristic C_flow)
    featureBit  int     // RLS feature index; -1 = no bit (bias-only encoding)
    priorWeight float64 // priorTheta[featureBit]; meaningful only when featureBit >= 0
}{
    model.PhaseColdStarting: {1.0, 1, 0.85},
    model.PhaseWarm:         {0.7, 2, 0.55},
    model.PhaseIdle:         {0.15, 3, 0.0},
    model.PhaseDraining:     {0.2, -1, 0},
    model.PhaseUnknown:      {0.5, -1, 0}, // Math-gated (D4): do NOT reprice without a ruling
}
```
- `flowCost` rotate path becomes: `enc, ok := phaseFlowEncoding[view.Phase]; if !ok { enc = phaseFlowEncoding[model.PhaseUnknown] }` — the unrecognized-string fallback made *explicit* (finding 6), value-identical to today's fall-through.
- `Features` becomes: same lookup; `if enc.featureBit >= 0 { f[enc.featureBit] = 1 }`. GPU/load bits unchanged.
- `priorTheta()` is **assembled** from the table: `theta[0]=biasPrior (0.15)`, `theta[enc.featureBit]=enc.priorWeight` per row with a bit, `theta[4]=gpuPrior (0.45)`, `theta[5]=loadPrior (0.20)` — the three non-phase weights stay named constants. This kills drift surface #3 (finding 4).
- **No number changes anywhere** (P-ECON + Math gate): 1.0/0.7/0.15/0.2/0.5, bits 1/2/3, weights 0.85/0.55/0.0, bias 0.15, gpu 0.45, load 0.20 are all byte-identical to `5fe1c8e`. The Math gate forbids *choosing* a parameter; moving an existing parameter into a table chooses nothing.
- Table lives in `cost`, not `model`: the numbers are cost policy and RLS layout; `model` stays the leaf package (it must not learn cost policy; `featureDim` is a cost const).

### D3 — the completeness test, `cost/phase_vocabulary_test.go` (NEW) — the `TestCRDActionVocabularyCompleteness` analog
Four assertions, in one test file:
- **(a) const-block ↔ slice:** AST-parse `model/types.go` (mirroring `actionTypeConstants` in `actuator/crd_vocabulary_test.go:55-92`) → set-equal to `model.AllWorkloadPhases`. Catches const-added-without-slice AND slice-edited-without-const.
- **(b) slice ↔ table:** `phaseFlowEncoding` has exactly one row per `AllWorkloadPhases` member, no extras. Catches phase-added-without-encoding — today's silent-absorption hole, now a build failure.
- **(c) feature-bit sanity:** bits unique, none `== 0` (bias), all `< featureDim`; and for every row with `featureBit >= 0`, `priorTheta()[bit] == row.priorWeight` (derivation consistency).
- **(d) golden band (the pre-registered predicted outputs, §Band below):** per-phase `flowCost`/`Features`/`priorTheta` equal the predicted values exactly; plus `flowCost` on `WorkloadPhase("bogus")` == `flowCost(PhaseUnknown)` (the explicit fallback).

Relationship to the unwired golangci `exhaustive` config: once the switches become lookups the linter is *vacuous over these two sites*; the Go test is strictly stronger (it binds the const block, the slice, the table, and the prior — the linter binds only switch arms). Keep the config (guards any future switch, incl. in ingest); CI wiring stays the CI-owner step, unchanged from A-10's closure note.

### D4 — the deferred Math item (recorded, NOT fixed)
Real, live, and **out of scope by the ticket's own trap**: RLS prices `Unknown` *and* `Draining` at bias-only **0.15** — the idle floor, the cheapest rotation on the learned path — vs switching's **0.5** / **0.2**. Once λ>0 the learned path treats Unknown-phase pods as cheapest-to-rotate (the ticket's "why it matters"). Math gate = NO, so no number moves here. I will file register entry **M-156** (ECONOMICS · MATH-GATE · 🔴 LIVE-dormant: latent while λ=0), cross-referenced from `03-decision.md`, carrying: the two divergent encodings, the activation condition (λ>0 / RLS unfrozen in production), and the rule that the fix is a Math ruling, not an engineering PR. The table row's comment points at M-156 so the next editor cannot "fix" it casually.

### D5 — explicit non-goals (scope = ECONOMICS, single tag)
- No CI wiring of golangci-lint (CI-owner step).
- No `costprobe` change (benchmarks/ dev tool; not an encoder; flag cast is cosmetic).
- No `classifyPhase`/ingest change (producer already returns only vocabulary members; a 6th phase it never returns is a coverage question, not drift).
- No number, threshold, `featureDim`, or physics change. No new enum values.

## §Band — predicted outputs, registered BEFORE implementation (ticket trap)
Empty view (no GPU, ReqRate absent), rotate action:
- `flowCost` = `0.55 × switchPrior`: ColdStarting **0.55**, Warm **0.385**, Idle **0.0825**, Draining **0.11**, Unknown **0.275**; `WorkloadPhase("bogus")` → **0.275** (explicit Unknown fallback).
- `Features`: ColdStarting `{1,1,0,0,0,0}`, Warm `{1,0,1,0,0,0}`, Idle `{1,0,0,1,0,0}`, Draining `{1,0,0,0,0,0}`, Unknown `{1,0,0,0,0,0}`.
- `priorTheta()` = `{0.15, 0.85, 0.55, 0.0, 0.45, 0.20}`; `Predict(Features(Unknown-view))` at prior = **0.15** (the mispricing, recorded per D4 — *not changed*).
- Post-refactor actuals must equal these byte-for-byte; any deviation = the refactor changed behavior = FAIL.

## Tests
(a)–(d) per D3, committed. **(e) RED positive control (ticket: "a null result is not closure without a positive control"):** the sanctioned arm-removal mutation — delete one `phaseFlowEncoding` row → (b) fails; remove one slice member → (a) fails; change Warm 0.7→0.71 → (d) fails; revert all → green. Demonstrated and captured in `05-evidence.md`, exactly as action-completeness RED. **(f)** existing cost tests (`p1cost_test`, `action_flow_test`, `offswitch_test`, `dual_test`, `costaudit_test`) must pass unmodified — behavior-preservation proof alongside §Band.

## Open for §A convergence
- **Q1** table placement: `cost` (mine — model stays leaf-pure) vs `model` (one import for all future consumers)?
- **Q2** `priorTheta` derivation: in-scope as behavior-preserving (mine — finding 4 is a real third drift surface) or leave hand-written and pin by test (d) only?
- **Q3** deferred Math item: new register entry M-156 (mine) vs a note appended to M-139 (cost calibration)?
- **Q4** declare slice order canonical-now (mine, mirrors `MutatingActions` order-is-load-bearing comment) or leave order unspecified until a consumer needs it?

— K3 (Proposer), 2026-09-05, base `5fe1c8e`
