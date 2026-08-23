# Phorvex MILP framework benchmark — superseding AWS decision report

**Run date:** 2026-07-21  
**Decision status:** final for the benchmarked model and fixtures; not a claim of live exact-solver integration  
**Supersedes:** the production-latency recommendation in the 2026-07-19 yusam-only report  
**Does not withdraw:** any previously reported correctness, feasibility, or failure-handling result

## Executive decision

The same PuLP, Pyomo, and OR-Tools implementations were rerun together in one resource-limited pod on the AWS EKS node that hosts the Phorvex engine. The AWS rerun confirms the yusam correctness result and preserves the same latency ordering.

- All three primary implementations returned `648/648` optimal, independently accepted solutions.
- Objectives and selected actions matched PuLP in `648/648` cases for both Pyomo and OR-Tools.
- The AWS and yusam primary results matched objective, selection, status, and acceptance on all `1944/1944` framework-instance rows.
- PuLP matched the independent brute-force oracle on `288/288` eligible cases.
- The independent production checker accepted zero known hard-constraint violations.
- Native OR-Tools MPSolver/CBC had the lowest AWS latency.
- The OR-Tools same-CBC control also remained faster than PuLP, so the AWS result is not explained only by the embedded CBC version difference.

**Recommendation:** retain PuLP+CBC as the exact correctness oracle, do not move the current model to Pyomo, and use OR-Tools MPSolver/CBC as the preferred candidate for a future latency-sensitive exact tier. The live Go greedy optimizer should remain the production path until that exact tier has a deadline, independent-checker, and greedy/greedy-then-swaps fallback integration.

This recommendation is about the exact-solver prototype. PuLP, Pyomo, and OR-Tools are not currently wired into the live Go operator.

## Environment and safety boundary

The AWS benchmark ran in EKS cluster `phorvex-dev-eks`, on t3.medium node `ip-172-27-12-134.us-east-2.compute.internal`, using a temporary pod limited to `1 CPU` and `768 MiB`.

The pod:

- ran as non-root with a read-only root filesystem;
- had no service-account token;
- invoked no Kubernetes or defensive-action API;
- changed no deployment, image, policy, CRD, workload, or production code;
- was deleted after the result files were copied and verified.

All three Phorvex deployments remained `1/1 Ready` with zero restarts after both AWS runs. The benchmark pod shared the node with production, so absolute latency includes the normal possibility of shared-node noise; every framework was nevertheless tested in the same pod and conditions.

Pinned versions:

- Python `3.12.13`
- PuLP `2.7.0`
- Pyomo `6.9.5`
- OR-Tools `9.14.6206`
- Shared external CBC `2.10.3`
- OR-Tools embedded CBC `2.10.12`
- Relative MIP gap `0`
- Input SHA-256 `11191f9c6495d738ad1ee9ec739be4dfe9db1552c4560d155b63692180b82bc5`

## AWS results on the original 648 instances

Each timing cell is `mean / median / p95 / maximum` in milliseconds.

| Framework/backend | Optimal | Accepted | Objective match | Selection match | Build | Solve | Independent check | Total |
|---|---:|---:|---:|---:|---|---|---|---|
| OR-Tools 9.14 MPSolver / embedded CBC 2.10.12 | 648/648 | 648/648 | 648/648 | 648/648 | 0.497 / 0.432 / 0.848 / 10.518 | 2.933 / 2.641 / 4.443 / 49.209 | 0.344 / 0.249 / 0.852 / 1.617 | **3.915 / 3.531 / 6.303 / 51.199** |
| PuLP 2.7 / external CBC 2.10.3 | 648/648 | 648/648 | baseline | baseline | 1.517 / 1.254 / 3.017 / 7.597 | 6.933 / 6.458 / 9.953 / 46.368 | 0.323 / 0.234 / 0.848 / 1.533 | **8.928 / 8.265 / 13.653 / 50.364** |
| Pyomo 6.9.5 / external CBC 2.10.3 | 648/648 | 648/648 | 648/648 | 648/648 | 1.323 / 1.208 / 2.233 / 6.904 | 14.032 / 13.169 / 19.374 / 67.148 | 0.327 / 0.224 / 0.850 / 1.663 | **16.538 / 15.500 / 23.106 / 71.583** |

Native OR-Tools reduced mean total latency by `56.1%` versus PuLP in this AWS run. Pyomo was `85.2%` slower than PuLP and offered no correctness advantage for the current formulation.

### Same-CBC control

The normal OR-Tools wheel embeds CBC 2.10.12, whereas PuLP and Pyomo used the same external CBC 2.10.3 executable. A controlled fourth path therefore built the model with OR-Tools, exported MPS, and solved it with that exact CBC 2.10.3 binary.

- `648/648` accepted.
- `648/648` objectives matched PuLP.
- `648/648` selected-action sets matched PuLP.
- Total time: mean `6.771 ms`, median `6.319 ms`, p95 `9.822 ms`, maximum `52.874 ms`.

This control remained `24.2%` faster than PuLP end-to-end. It does not prove that every OR-Tools advantage is framework-only, because the two adapters serialize and invoke CBC differently, but it removes the solver-binary version as the sole explanation.

## AWS versus yusam

| Path | Yusam mean total | AWS mean total | Relative change | Ranking |
|---|---:|---:|---:|---|
| OR-Tools native CBC | 9.990 ms | 3.915 ms | AWS 2.55x faster | 1st in both |
| OR-Tools same-CBC control | 20.601 ms | 6.771 ms | AWS 3.04x faster | between OR-Tools native and PuLP in both |
| PuLP + external CBC | 25.708 ms | 8.928 ms | AWS 2.88x faster | 2nd primary in both |
| Pyomo + external CBC | 46.855 ms | 16.538 ms | AWS 2.83x faster | 3rd in both |

The yusam absolute latency numbers must not be presented as AWS production-node latency. Their correctness results and framework ordering were independently reproduced on AWS.

## Cross-framework scalability on AWS

The scalability extension used deterministic non-disjoint fixtures, `B=7`, three seeds per size, and the same independent checker. All `36/36` solver/control runs were optimal and accepted; every objective and selected-action set matched PuLP.

Each row reports means across three seeds in milliseconds; `max` is the maximum total time.

| N | Framework/backend | Build | Solve | Check | Total | Max total |
|---:|---|---:|---:|---:|---:|---:|
| 500 | OR-Tools native CBC | 6.634 | 15.957 | 49.637 | **72.955** | 74.708 |
| 500 | OR-Tools same-CBC control | 5.827 | 26.151 | 49.109 | **81.570** | 86.567 |
| 500 | PuLP + CBC | 27.589 | 38.177 | 49.477 | **116.175** | 118.491 |
| 500 | Pyomo + CBC | 19.486 | 54.431 | 50.559 | **130.261** | 147.966 |
| 750 | OR-Tools native CBC | 24.828 | 25.512 | 131.134 | **182.536** | 203.957 |
| 750 | OR-Tools same-CBC control | 11.873 | 43.513 | 127.000 | **183.104** | 201.914 |
| 750 | PuLP + CBC | 53.790 | 68.770 | 145.548 | **269.827** | 299.151 |
| 750 | Pyomo + CBC | 20.753 | 98.839 | 139.815 | **269.083** | 319.815 |
| 1000 | OR-Tools native CBC | 14.743 | 25.603 | 222.938 | **264.742** | 295.314 |
| 1000 | OR-Tools same-CBC control | 11.885 | 42.373 | 246.664 | **301.576** | 357.085 |
| 1000 | PuLP + CBC | 54.757 | 86.317 | 221.656 | **364.868** | 385.615 |
| 1000 | Pyomo + CBC | 24.463 | 92.322 | 215.861 | **343.938** | 359.023 |

At larger N, the independent checker dominates total time. For example, OR-Tools at `N=1000` spent about `223 ms` of its `265 ms` mean total inside the checker. Changing solver framework alone cannot make this pipeline meet a strict 100 ms deadline at those sizes.

## Time-budget evidence from Task 2

The separate AWS PuLP scalability benchmark remains the primary evidence for `1 ms` versus `100 ms`:

- `1 ms`: `0/15` acceptable incumbents.
- `100 ms` CBC search cap: `15/15` optimal, independently feasible solutions with `0%` reference gap.
- Strict `100 ms` end-to-end deadline: `0/15` met.
- Mean totals: `127.5 ms` at N=500, `251.7 ms` at N=750, `377.4 ms` at N=1000, `693.3 ms` at N=1500, and `1310.2 ms` at N=2000.

The cross-framework test shows that OR-Tools reduces latency substantially and averaged below 100 ms for its three N=500 cases. This is not a hard 100 ms guarantee: shared-node variance exists, the fixtures are synthetic, and the repeated N=500 runs observed higher outliers. A live integration must always compute a safe greedy or greedy-then-swaps fallback first.

## Decision guide

| Question | Evidence-based choice |
|---|---|
| Which backend should remain the validated exact oracle? | **PuLP + external CBC** |
| Which backend is the best current candidate for a latency-sensitive exact tier? | **OR-Tools MPSolver + CBC** |
| Should the current formulation move to Pyomo? | **No** |
| Should the live Go greedy path be replaced immediately? | **No** |
| Can a 100 ms complete-tick guarantee be claimed? | **No** |

An OR-Tools exact tier should be accepted only when solver status is valid, variables are integral, the independent checker passes, the result improves the precomputed heuristic solution, and the overall tick deadline has not expired. Otherwise the system should return the greedy/greedy-then-swaps result.

## Validity limits

- The 648 legacy fixtures validate the shared mathematical formulation; they do not contain full production state.
- The N=500/750/1000 cases are deterministic production-shaped synthetic fixtures, not captured live ticks.
- The AWS run validates the benchmark on production hardware, not integration into the production operator.
- No production code was updated for this benchmark.
- No real defensive action was executed.
- Absolute timing can vary with shared-node load; use the measured distributions, not a single mean, when designing deadlines.

## Evidence files

- `aws-framework-benchmark-results.csv` — 2676 AWS solver rows.
- `aws-framework-scalability-results.csv` — 36 AWS N=500/750/1000 cross-framework rows.
- `aws-framework-validation-results.csv` — 28 checker/status/failure cases.
- `aws-framework-benchmark-environment.json` — versions, input digest, and run metadata.
- `task2-time-scalability-results.csv` — combined yusam/AWS 1 ms and 100 ms evidence.
- `final-benchmark-results.csv` — original yusam controlled run retained for cross-environment comparison.

Raw-file SHA-256 values:

- AWS benchmark CSV: `1e6cd3eabdae47476ca6518589a3861c0e54dcad0aa9f33e1ca9454d74cba800`
- AWS scalability CSV: `4dae9e038cef34a354e127fd8187a4cf2867d853b8fffa76a26cb8edbef6a9fa`
- AWS validation CSV: `28a9cd085485f2dbf386d4fb7d6a33608b70f4f5be92eebbd37c65527d721c4c`
- AWS environment JSON: `d5943f13e984be5797c7ced6834971f5b92250356b3cbe043e3969b7ec901efc`
