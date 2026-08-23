# PHORVEXSEC-15 — deadline-aware CP-SAT exact-tier validation

Run: 2026-08-23 UTC · host `hypercopy` · OR-Tools 9.14.6206

## Verdict

The benchmark/prototype acceptance scope is implemented. CP-SAT now uses one documented integer scaling rule, receives greedy-plus-swaps as a solution hint, runs behind a hard subprocess cutoff, and is independently checked in original floating-point units. Every late, invalid, failed, non-improving, or unavailable exact result preserves the precomputed heuristic incumbent. Tiny budgets may still be missed when incumbent construction itself exceeds them; those misses are shown explicitly below.

This is deliberately not live Go operator wiring. The evidence supports a future escalation tier; it does not authorize replacing the production optimizer.

## Coefficient scaling

For every objective term, the prototype first forms its original-unit coefficient (`weight` for a fact, or `-lambda × ECost + future_reward` for an action), multiplies by the common scale, and rounds once to the nearest integer. The theoretical per-term error is at most `0.5/scale`. Every returned solution is then scored and checked against the unscaled model.

| Scale | Optimal / checker-passing | Objective matches PuLP (1e-7) | Selection matches PuLP | Max observed term error | Total p50/p95/p99/max ms |
|---:|---:|---:|---:|---:|---|
| 100 | 648/648 / 648/648 | 488/648 | 541/648 | 0.00499 | 7.701/45.224/179.646/3061.317 |
| 1,000 | 648/648 / 648/648 | 642/648 | 642/648 | 0.0005 | 7.765/41.372/248.941/3567.602 |
| 10,000 | 648/648 / 648/648 | 648/648 | 648/648 | 5e-05 | 7.826/41.786/260.246/3180.667 |
| 1,000,000 | 647/648 / 648/648 | 648/648 | 648/648 | 5e-07 | 7.498/42.984/247.927/4009.331 |

Coarse-scale discrepancies: **166** rows. They are retained in the raw CSV with instance ID, scale, PuLP objective, CP-SAT objective, and absolute difference. Scale `1,000,000` matched PuLP objective and selected actions on **648/648** fixtures; one hard instance returned the matching feasible incumbent without proving optimality inside the five-second validation cap, which is reported rather than relabeled optimal.

### CP-SAT versus the existing exact backends

| Backend on the same 648-fixture family | Mean | p50 | p95 | p99 | Max |
|---|---:|---:|---:|---:|---:|
| CP-SAT, scale 1,000,000 (yusam final run) | 28.528 | 7.498 | 42.984 | 247.927 | 4009.331 |
| PuLP + CBC (AWS) | 8.928 | 8.265 | 13.653 | 19.003 | 50.364 |
| OR-Tools MPSolver + CBC (AWS) | 3.915 | 3.531 | 6.303 | 9.951 | 51.199 |

The environments differ, so this is not a pure host-speed experiment. It is nevertheless enough to reject the claim that CP-SAT is uniformly faster: its median is competitive with PuLP, but its mean and tail are materially worse. The controlled AWS comparison remains the solver-architecture decision evidence, and MPSolver/CBC remains the lowest-latency candidate.

## Deadline and routing evidence

Each fixed-deadline cell covers 15 instances (three seeds × five budgets) at that N. `B=1` is correctly routed directly to greedy; shared-fact `B>1` cases first compute greedy-plus-swaps and then attempt CP-SAT only while time remains.

| N | Deadline | Runs | Deadline met | Reference-optimal output | Exact improved heuristic | Safe fallback | Total p50/p95/p99/max ms |
|---:|---:|---:|---:|---:|---:|---:|---|
| 60 | 50 ms | 15 | 11/15 | 11/15 | 0/15 | 12/15 | 49.172/50.690/50.690/50.690 |
| 60 | 100 ms | 15 | 13/15 | 12/15 | 1/15 | 11/15 | 93.266/100.183/100.183/100.183 |
| 60 | 250 ms | 15 | 15/15 | 12/15 | 1/15 | 11/15 | 87.806/242.229/242.229/242.229 |
| 60 | 500 ms | 15 | 15/15 | 15/15 | 4/15 | 8/15 | 94.153/465.821/465.821/465.821 |
| 60 | 1000 ms | 15 | 15/15 | 15/15 | 4/15 | 8/15 | 90.644/618.245/618.245/618.245 |
| 100 | 50 ms | 15 | 14/15 | 8/15 | 0/15 | 12/15 | 49.395/61.565/61.565/61.565 |
| 100 | 100 ms | 15 | 14/15 | 8/15 | 0/15 | 12/15 | 99.041/100.339/100.339/100.339 |
| 100 | 250 ms | 15 | 15/15 | 11/15 | 3/15 | 9/15 | 164.723/244.205/244.205/244.205 |
| 100 | 500 ms | 15 | 15/15 | 11/15 | 6/15 | 6/15 | 160.332/465.291/465.291/465.291 |
| 100 | 1000 ms | 15 | 15/15 | 12/15 | 6/15 | 6/15 | 160.272/857.276/857.276/857.276 |
| 250 | 50 ms | 15 | 11/15 | 7/15 | 0/15 | 9/15 | 49.416/184.112/184.112/184.112 |
| 250 | 100 ms | 15 | 12/15 | 7/15 | 0/15 | 10/15 | 99.176/167.508/167.508/167.508 |
| 250 | 250 ms | 15 | 15/15 | 7/15 | 0/15 | 12/15 | 243.271/248.807/248.807/248.807 |
| 250 | 500 ms | 15 | 15/15 | 7/15 | 1/15 | 11/15 | 471.225/488.818/488.818/488.818 |
| 250 | 1000 ms | 15 | 15/15 | 7/15 | 1/15 | 11/15 | 870.754/908.231/908.231/908.231 |
| 500 | 50 ms | 15 | 6/15 | 10/15 | 0/15 | 5/15 | 51.056/110.588/110.588/110.588 |
| 500 | 100 ms | 15 | 12/15 | 10/15 | 0/15 | 10/15 | 99.370/183.628/183.628/183.628 |
| 500 | 250 ms | 15 | 15/15 | 10/15 | 0/15 | 12/15 | 244.537/248.725/248.725/248.725 |
| 500 | 500 ms | 15 | 15/15 | 10/15 | 0/15 | 12/15 | 482.329/485.074/485.074/485.074 |
| 500 | 1000 ms | 15 | 15/15 | 10/15 | 0/15 | 12/15 | 895.628/913.686/913.686/913.686 |
| 1000 | 50 ms | 15 | 6/15 | 11/15 | 0/15 | 0/15 | 92.442/256.855/256.855/256.855 |
| 1000 | 100 ms | 15 | 8/15 | 11/15 | 0/15 | 0/15 | 94.957/302.033/302.033/302.033 |
| 1000 | 250 ms | 15 | 13/15 | 11/15 | 0/15 | 0/15 | 89.520/267.764/267.764/267.764 |
| 1000 | 500 ms | 15 | 15/15 | 11/15 | 0/15 | 0/15 | 87.028/228.888/228.888/228.888 |
| 1000 | 1000 ms | 15 | 15/15 | 11/15 | 0/15 | 0/15 | 93.104/279.777/279.777/279.777 |

### Repeated ticks

The 2%-candidate-cost / ~1%-fact-weight change series contains **60** consecutive decisions. Deadline met: **60/60**; reference-optimal output: **20/60**; total p50/p95/p99/max: `243.144/244.542/246.006/246.006 ms`.

CP-SAT's Python API does not provide a persistent incremental model interface. The repeated-tick rows therefore measure honest rebuilds and are not labeled persistent warm starts. The greedy-plus-swaps solution hint is supplied on each solve.

### How often exact improves the heuristic

Across the original validation set, **214/648** fixtures are eligible shared-fact `B>1` ticks. Exact improved greedy-plus-swaps by any measurable amount on **48/214 (22.43%)** and by at least 1% on **23/214 (10.75%)**. Mean positive-or-zero gap over all eligible ticks is `0.771%`; maximum is `16.240%`.

## Timing and resources

The raw rows separate input/de-dup preparation, variable creation, constraints, objective, hint transfer, solver call, extraction, and independent checking. CP-SAT exposes wall/user time, branches, conflicts, objective, and best bound, but does not expose separate presolve-versus-search wall time through the stable Python response API; both remain inside `solve_ms` rather than being fabricated.

Maximum process peak RSS observed by the benchmark: `183.7 MiB`. CPU user/system deltas are present per row. The pre-existing PuLP N=500–2000 worker benchmark remains the isolated subprocess memory control (maximum combined Python+CBC RSS below 75 MiB on AWS).

## Runtime policy

1. Use greedy immediately for disjoint coverage or `B=1`.
2. Otherwise compute greedy-plus-swaps first.
3. Invoke CP-SAT only when enabled, the candidate count is within the configured cap, and tick time remains.
4. Accept only a checker-passing result that improves the incumbent and arrives before the end-to-end deadline.
5. Return greedy-plus-swaps for every other status, including timeout, infeasible, invalid, error, late, and non-improving.

## Final decisions

- **Exact on every relevant tick? No.** It has a long CP-SAT tail and produces a material ≥1% gain on only 10.75% of eligible validation fixtures.
- **Shared coverage only? Yes.** Disjoint instances and `B=1` stay on greedy; all other ticks compute greedy-plus-swaps first.
- **Is CP-SAT faster than PuLP after build time? No as a distribution.** Its median is competitive, but mean/p95/p99/max are worse in the measured runs.
- **Persistent Pyomo advantage? No.** The tested Pyomo path is neither faster nor actually persistent/incremental.
- **Deadline and size cap?** For a CP-SAT pilot, use a 500 ms end-to-end budget and stop above `N=60`; the synthetic N=60 matrix returned reference-optimal output in 15/15 runs at 500 ms. Do not activate this policy in production until live tick snapshots reproduce it.
- **Production solver/API?** Keep PuLP+CBC as the correctness oracle. OR-Tools MPSolver/CBC remains the preferred future latency-tier API from the controlled AWS benchmark; CP-SAT is now a validated alternative, not the selected production backend.

The current Go heuristic therefore remains production. The delivered Python router is a benchmark/prototype and demonstrates the fallback contract; it does not silently wire a new solver into the operator.

Pyomo remains rejected for this model: the same-host and AWS data show no latency or correctness advantage, and the tested Pyomo path is not a persistent incremental interface.

## Validity limits

- The 648 fixtures validate the mathematical model but predate full production state.
- N=60–1000 deadline cases are deterministic production-shaped synthetic inputs, not captured live optimizer ticks.
- Solver-internal presolve/search cannot be split honestly with the stable CP-SAT Python response API.
- No workload, policy, deployment, or defensive action was changed by this benchmark.

## Artifact integrity

- Input JSONL SHA-256: `11191f9c6495d738ad1ee9ec739be4dfe9db1552c4560d155b63692180b82bc5`
- PuLP AWS reference CSV SHA-256: `1e6cd3eabdae47476ca6518589a3861c0e54dcad0aa9f33e1ca9454d74cba800`
- CP-SAT scaling CSV SHA-256: `7766c6b6db751bf303c63270589ca9a5b49ef85f60725edb2a6f1d91bad8e299`
- Deadline/routing CSV SHA-256: `1733fd822a6a014c614a656c3e0e8d7869022b6c39e9a8ac135a5c5b5571237d`
- Heuristic-gap CSV SHA-256: `43b0516f49bcf0aaebdc1bddd25160c54a4a0acd006be22d2faaef405b8f05cd`
- Unit tests cover disjoint, B=1, duplicate keys, multiple scales, improvement, timeout, error/fallback, and infeasible paths.
