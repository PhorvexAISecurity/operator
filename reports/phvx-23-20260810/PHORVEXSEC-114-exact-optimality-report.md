# PHORVEXSEC-114 (PHVX-23) — exact-check completion report

Updated: 2026-08-20

Branch: `fix/phvx-23-work-guard-calibration` · PR #55

Runtime-matrix commit: `47ee2ed`

## Result

All four ticket items are implemented and testable:

1. An exact solve that did not run carries `ExactSkipped` and never renders as a measured zero or
   perfect score.
2. The flat 18-asset cap was replaced by a work estimate and an active budget of `300_000`, derived
   against the product owner's 500ms ruling.
3. The 76-asset falsification check is direct brute force at B=1 and B=2; no relaxation or
   extrapolation is used for those rows.
4. External claims separate the scale-free structural proof from the bounded empirical range.

The exact arm is present in the shipped binary's explicit ablation, console benchmark, and
apply-fix safety paths, and in tests/benchmarks. It does **not** run on the ordinary per-tick
production decision path.

## Correct skip semantics

The previous optimizer-probe path discarded the skip flag, then treated `exactObjective == 0` as
"the solve completed and correctly selected nothing," producing a green ratio of 1.0. The two
states are now separate:

- `completed` with a true zero objective may report ratio 1 and gap 0;
- `skipped`, `timeout`, or `failed` has no numeric optimality ratio or gap.

The dashboard renders an unmeasured exact result as `n/a`. Regression tests cover both the skipped
and genuinely-completed-zero cases.

## Guard and runtime model

Enumeration work is estimated as candidate sets through B picks, conservatively using the maximum
actions per asset, then scaled by B because copying/scoring a picked set is O(B). Overflow returns
positive infinity and therefore skips. Recursion stops immediately after the move budget is spent;
an independent exhaustive implementation verifies that this prune does not change the optimum.

`exactWorkBudget = 300_000`. The old flat cap was wrong in both directions: it blocked cheap large
B=1 fleets and admitted expensive high-B cases. The current matrix enforces expected statuses in
subprocesses with a hard 500ms deadline. The wall-clock matrix is skipped under `go test -race`
because startup of the race-instrumented test binary alone can exceed 500ms; all decision tests,
including the solver, still run race-clean.

## Reproducible runtime matrix

Raw and summary artifacts are committed under:

`reports/phvx-23-20260810/exact-runtime-20260820/`

Configuration: Go 1.26.1, linux/amd64, 6 CPUs, seeds `23001` and `23002`, three repetitions per
seed, active work cap `300_000`, subprocess timeout 500ms. P50/P95/max use nearest rank over all six
runs of each case.

| case | n | k | B | overlap / feasibility | status (6/6) | P50 | P95=max | max completed gap |
|---|---:|---:|---:|---|---|---:|---:|---:|
| production-76-b1 | 76 | 2 | 1 | disjoint, feasible | completed | 0.281ms | 0.836ms | 0 |
| production-76-b2 | 76 | 2 | 2 | disjoint, feasible | completed | 16.698ms | 21.165ms | 0 |
| actions-24-k3 | 24 | 3 | 2 | disjoint, feasible | completed | 3.439ms | 5.254ms | 0 |
| within-asset-overlap | 24 | 3 | 2 | shared facts within each legal asset block | completed | 5.454ms | 6.901ms | 0 |
| partially-infeasible | 30 | 3 | 2 | every fourth asset excluded | completed | 4.352ms | 6.774ms | 0 |
| fully-infeasible | 30 | 3 | 2 | all candidates excluded | completed-zero | 0.003ms | 0.006ms | 0 |
| cross-block-rejected | 20 | 2 | 2 | illegal shared key across assets | skipped | 0 | 0 | n/a |
| guard-skipped | 80 | 4 | 4 | 1,640,774,404 estimated work | skipped | 0.246ms | 0.372ms | n/a |
| same case, guard disabled | 80 | 4 | 4 | disjoint, feasible | timeout | 505.469ms | 509.777ms | n/a |

`failed` is an explicit schema status and was not observed. Every non-completed raw row has blank
`optimality_ratio` and `optimality_gap` cells in CSV and omitted fields in JSONL. The numeric zero
runtime on the structurally-rejected row is dispatch time, not an optimality gap.

## Exactness result and scope

For the current asset-keyed production substrate, cross-asset cover keys are rejected and the
remaining objective is modular under a truncated partition matroid. Under those verified
conditions, the proof is scale-free. The runtime matrix separately measures the implementation:
all completed disjoint and legal within-asset-overlap cases returned maximum gap 0.

At 76 assets the direct exact check completed for both B=1 and B=2. These are deterministic
synthetic fixtures at production **scale**, not a replay of live pods. No claim is made that the
fixture is the live fleet or that brute force is tractable for arbitrary B. The 80-asset B=4 case
demonstrates the opposite: the guard skips it and the unguarded subprocess times out.

Cross-block fact overlap is not benchmarked as a legal optimizer input because production rejects
that structure before selection. Its explicit `skipped` rows make that boundary visible.

## Commands

```text
PHVX_EXACT_RESULTS_DIR=<dir> go test ./internal/decision -run TestExactRuntimeMatrix -count=1 -v
go build ./...
go vet ./...
go test ./...
go test -race ./internal/decision
git diff --check
```

All passed on 2026-08-20. No `.github/workflows/` file was changed.

## Deliverables

- Work guard and prune: `a15bda9`.
- Executable item-3 sweep and guard tests: `a15bda9`.
- Runtime/status matrix and raw CSV/JSONL: `47ee2ed`.
- Manifest with seeds, repetitions, host/runtime, command, cap, and timeout.
- Corrected external wording and skipped display from the earlier PHVX-23 commits.

No runtime-budget product decision remains open: 500ms was ruled on 2026-08-11 and is now enforced
by the subprocess matrix. Increasing the active work cap requires re-running this matrix and
showing that every guard-admitted case still completes inside that ruling.
