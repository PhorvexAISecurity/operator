# PHORVEXSEC-114 (PHVX-23) — item 3 closed, plus two guard defects — report

Date: 2026-08-19 · Branch `fix/phvx-23-work-guard-calibration` · PR #55 · Commit `a15bda9`

Supersedes nothing in `reports/phvx-23-20260810/` (items 1, 2 and 4); this covers item 3 and what
validating it turned up.

## Headline

**Item 3 is closed by direct measurement rather than by bounding, and the math owner confirmed that
on 2026-08-18.** Validating the answer then exposed two defects in the work guard: it was admitting
runs of 0.68 s, 1.06 s and 1.12 s while reporting them as inside a 500 ms budget.

## 1. Item 3 — the premise had died

Item 3 asked for a bound at 76 assets, on the stated premise that *"brute force won't reach 76"*.
Item 2 had already replaced the flat 18-asset cap with a work budget, and with that in place the
exact solve reaches the live fleet in under a millisecond. So the answer was measured instead of
relaxed.

**17 of 17 configurations returned `ratio = 1.000000000000`, `gap = 0`, `disjoint = true`** — across
move budgets B = 1..4, fleet sizes to 600 assets, and six different value-distribution shapes
(from half the fleet high-value down to a single asset). Nothing was bounded, relaxed or
extrapolated.

The measurement is now executable rather than prose. It previously existed only as text in the
ticket, so nothing would have caught it decaying — the same failure this ticket was filed about.
`TestGreedyIsExactAcrossBudgetsAndShapes` re-runs it, with the work budget made injectable
(`exactObjectiveWithBudget`) so shapes the shipped guard declines can still be measured. Production
always goes through `exactObjective`.

## 2. The work guard was not enforcing the 500 ms ruling

The exact-check time budget was ruled at **500 ms** on 2026-08-11. The work guard is the mechanism
that enforces it, and it was not:

| shape | measured | guard reported |
|---|---|---|
| n=13 k=2 B=6 | **1.12 s** | inside budget |
| n=5000 k=2 B=1 | **1.06 s** | inside budget |
| n=24 k=2 B=4 | 695 ms | inside budget |
| n=300 k=2 B=2 | 677 ms | inside budget |

Two independent causes.

**Per-set cost was modelled as O(1); it is O(B).** Each node copies the running pick slice and
`setObjective` re-scores all of it, so at B=6 the guard under-counted by 7×. The estimate now scales
by B.

**The enumeration kept walking after the move budget was spent.** With `budget == 0` the recursion
still descended through every remaining asset just to skip it, costing an extra O(n) per candidate
set. Pruning is *output-identical* — with no moves left the only reachable leaf is the current pick
set — and is where the headroom came from: **n=5000 B=1 went 1.06 s → 26 ms**.

`TestPruneDoesNotChangeTheOptimum` checks the prune against an independently written exhaustive
search rather than against itself.

## 3. Recalibration

`exactWorkBudget` is re-derived from the ruling rather than guessed. At **300_000** the worst
admitted run measures **375 ms**, and everything the ticket depends on stays reachable:

```
n=76   B=1   0.8 ms
n=600  B=1   8.6 ms
n=76   B=2    30 ms
n=5000 B=1    26 ms
first skipped case just above the boundary: n=274 k=2 B=2, work 300,306
```

The four overrunning shapes are pinned as skip cases in `TestWorkBudgetReachesTheLiveFleet`, at the
shape and measured time that exposed each one, so re-flattening the estimate fails there first.

## 4. Correction to the 2026-08-10 report

That report attributed the 20.3 s vs 2.2 s difference for B=3 / n=76 to host speed. **That was
wrong.** The old timing table was recorded at **k=6** while the test fixture yields **k=2**, and k
enters as `k^j` — so the same `(n, B)` is roughly `3^B` cheaper on the fixture. Same host, different
fixture shape. The old table is kept in the code but marked historical with this note.

## 5. Review attention

The hard assertion in `TestExactArmHonorsTheTimeRuling` is **1.5 s, not 500 ms**. CI hardware is not
the calibration host and a tight wall-clock assert would flake; it is sized to catch the failure
that actually happened (2–3× overrun), and the measured worst case is always logged against the
ruling so drift stays visible.

`n=76 B=4` (1 m 16 s) passed at `ratio = 1.000000000000` but sits behind `PHVX_EXACT_SWEEP=1` rather
than running every CI build. A deliberate coverage cap, stated rather than silent.

## Verification

`go build ./...`, `go vet ./...`, full `go test ./...` green. `internal/decision` goes 16 s → 18 s.
