# Task 2 — Time Budget and Scalability Benchmark

**Run date:** 2026-07-21 UTC  
**Primary environment:** AWS EKS `phorvex-dev-eks`, production engine node `ip-172-27-12-134.us-east-2.compute.internal` (`t3.medium`)  
**Control environment:** yusam (`hypercopy`)  
**Optimizer:** PuLP 2.7.0 + external CBC 2.10.3, one solver thread  
**Model:** binary Phorvex coverage MILP with independent production hard-constraint acceptance checker

## Executive result

Increasing CBC's solver time limit from **1 ms to 100 ms materially changes solution availability**:

- On AWS, `1 ms` returned no acceptable incumbent in **0/15** runs.
- On AWS, `100 ms` returned an independently feasible, globally optimal solution in **15/15** runs through `N=2000`.
- Every AWS 100 ms objective matched the corresponding unlimited optimum: **15/15, 0.000% gap**.
- Zero accepted solutions violated a represented production hard constraint.

However, **a 100 ms CBC limit is not a 100 ms end-to-end decision budget**. Model construction, MPS serialization/process launch, solution extraction, and the independent checker are outside CBC's internal search limit. On the production EKS node, no 100 ms run completed end-to-end within 100 ms; mean total latency grew from `127.5 ms` at `N=500` to `1310.2 ms` at `N=2000`.

Memory is not the limiting resource. Peak combined Python+CBC RSS on AWS stayed below `75.0 MiB`. The dominant scalability bottleneck is the current independent checker, whose coverage validation scans the candidates once for every fact and therefore grows approximately quadratically for this fixture family.

## Scope and production boundary

This is the requested exact-optimizer prototype benchmark, not a claim that PuLP is already running in the live operator. The deployed Phorvex image currently uses the Go P1 greedy coverage engine; PuLP/CBC remains a benchmark/prototype exact tier.

The AWS run used the same node type and the exact node currently hosting the Phorvex engine. The test pod was limited to one CPU and 1 GiB memory, had no service-account token, and invoked no Kubernetes or defensive action API.

The `N>500` inputs are deterministic production-shaped synthetic fixtures because the live engine does not export full optimizer snapshots and the current live fleet does not provide controlled `N=750–2000` cases. The fixtures carry explicit safe workload/policy fields and are checked by the independent production-law projection, but their overlap distribution is synthetic. Therefore the AWS numbers represent production hardware and the current benchmark model, not measured latency over a real production tick distribution.

## Method

The experiment fixes `B=7` to isolate the effects of time limit and candidate count. It tests:

- `N = 500` as the existing control;
- `N = 750, 1000, 1500, 2000` for scalability;
- three deterministic seeds per size: `20260719`, `20260720`, `20260721`;
- CBC limits: unlimited reference, `0.001 s`, and `0.1 s`.

Each candidate covers one private fact and three sampled shared facts. The number of shared facts is `N/5`, so the model contains approximately `2.2N` binary variables and `1.2N` constraints.

Every recorded solve runs in a fresh Python process. Timing boundaries are:

- **build:** PuLP variables, objective, and constraints;
- **solve:** MPS serialization, CBC process launch/search, and solution loading;
- **feasibility check:** independent status, integrality, budget, coverage, production-law, and objective validation;
- **total:** build through fail-closed acceptance.

Peak RSS is the sum of the fresh Python worker's peak and its CBC child's peak. Objective quality is measured against the unlimited optimum for the exact same `N`, seed, and `B`.

## AWS results — 1 ms versus 100 ms

| N | Binary variables | Constraints | 1 ms accepted | 1 ms total mean | 100 ms accepted | 100 ms objective mean | Reference gap | 100 ms total mean / max | 100 ms peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 1,100 | 601 | 0/3 | 70.2 ms | 3/3 optimal | 24.042003829 | 0.000% | 127.5 / 142.3 ms | 54.5 MiB |
| 750 | 1,650 | 901 | 0/3 | 95.3 ms | 3/3 optimal | 23.670602274 | 0.000% | 251.7 / 267.1 ms | 57.7 MiB |
| 1,000 | 2,200 | 1,201 | 0/3 | 144.8 ms | 3/3 optimal | 24.612563612 | 0.000% | 377.4 / 405.6 ms | 60.6 MiB |
| 1,500 | 3,300 | 1,801 | 0/3 | 188.0 ms | 3/3 optimal | 24.540403836 | 0.000% | 693.3 / 733.9 ms | 67.2 MiB |
| 2,000 | 4,400 | 2,401 | 0/3 | 251.0 ms | 3/3 optimal | 24.458162777 | 0.000% | 1310.2 / 1381.8 ms | 73.0 MiB |

All 1 ms statuses were `time_limit` with no accepted incumbent. Their objective and optimality gap are correctly reported as unavailable; the unlimited runs prove the instances themselves are feasible.

All AWS 100 ms runs ended `optimal`, passed the independent checker, and selected at most seven actions. Solver-reported and unlimited-reference gaps were both zero.

## AWS latency decomposition at the 100 ms solver setting

| N | Build mean | Solve-call mean | Checker mean | Total mean | Checker share | End-to-end ≤100 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 27.8 ms | 44.3 ms | 52.7 ms | 127.5 ms | 41.3% | 0/3 |
| 750 | 46.0 ms | 68.5 ms | 133.0 ms | 251.7 ms | 52.8% | 0/3 |
| 1,000 | 63.5 ms | 80.8 ms | 227.4 ms | 377.4 ms | 60.3% | 0/3 |
| 1,500 | 74.9 ms | 109.2 ms | 502.7 ms | 693.3 ms | 72.5% | 0/3 |
| 2,000 | 121.7 ms | 160.7 ms | 1018.6 ms | 1310.2 ms | 77.7% | 0/3 |

CBC's `seconds=0.1` option limits its internal solve search. At larger sizes the measured solve call can still exceed 100 ms because PuLP must serialize the model, start an external process, and load the result around that search.

## yusam control and environment effect

The same script, generator, solver version, seeds, and acceptance checker were used on both environments. All 15 unlimited objectives matched exactly between yusam and AWS.

| N | AWS 100 ms accepted | yusam 100 ms accepted | AWS total mean | yusam total mean |
|---:|---:|---:|---:|---:|
| 500 | 3/3 | 3/3 | 127.5 ms | 241.6 ms |
| 750 | 3/3 | 3/3 | 251.7 ms | 390.9 ms |
| 1,000 | 3/3 | 3/3 | 377.4 ms | 640.8 ms |
| 1,500 | 3/3 | 3/3 | 693.3 ms | 1183.0 ms |
| 2,000 | 3/3 | 2/3 | 1310.2 ms | 1466.6 ms |

At `N=2000`, yusam produced one optimal solution, one feasible incumbent with the exact optimal objective, and one timeout with no incumbent. AWS produced three optimal solutions. Across the unlimited references, AWS was approximately `1.4–1.8×` faster than yusam, confirming that local timing should not be presented as production-node latency.

## Feasibility and solution quality

- Unlimited references: **30/30 optimal and accepted** across both environments.
- 1 ms runs: **0/30 accepted**; all safely fell back to `no-action`.
- 100 ms runs: **29/30 accepted** across both environments.
- AWS 100 ms runs: **15/15 optimal, checker-passing, 0% reference gap**.
- yusam 100 ms accepted runs: **14/14 checker-passing, 0% reference gap**.
- Accepted solutions with a hard-constraint violation: **0**.

The 100 ms budget changes availability, not objective quality on accepted runs: whenever a valid incumbent was returned, it matched the unlimited optimum. The larger action space did not materially increase the mean objective because `B` remained fixed at seven and each deterministic size uses a different sampled candidate pool.

## Scalability bottlenecks

1. **Independent checker:** the current coverage check constructs the coverer list by scanning every candidate for every fact. Since facts scale with `N`, this is approximately `O(N²)` here. Its AWS share rises from 41% at `N=500` to 78% at `N=2000`.
2. **External-process solve path:** PuLP serializes MPS and starts CBC for every solve. This fixed overhead makes a 1 ms limit operationally meaningless and prevents the CBC limit from being an end-to-end deadline.
3. **Model construction:** build time grows approximately linearly and reaches 122 ms at `N=2000`; it alone can exceed a 100 ms tick.
4. **Memory:** not a bottleneck in the tested range. The maximum observed combined RSS was `75.0 MiB` across all AWS runs.

The checker can be reduced toward `O(number of coverage edges)` by pre-indexing fact-to-candidate coverers once. A persistent/in-process exact backend would also remove repeated MPS serialization and process startup.

## Recommendation

**Replace the 1 ms exact-solver setting with 100 ms only as a solver-search cap, not as a promise of a 100 ms complete optimizer tick.**

The 1 ms setting produced no usable solution at any tested size. The 100 ms setting produced full-quality solutions on the production AWS node through `N=2000`, but the present Python/PuLP/checker pipeline missed a 100 ms end-to-end deadline in every run.

For a strict 100 ms live decision loop:

- compute greedy or greedy-then-swaps first as the safe fallback;
- invoke the exact tier only when the remaining tick budget permits;
- accept an exact result only after the independent checker passes;
- pre-index the checker and avoid a fresh external CBC process per tick before considering live integration.

If the live tick budget is larger than 100 ms, the measured AWS maxima provide conservative routing thresholds for this fixture family: approximately 142 ms at `N=500`, 267 ms at `N=750`, 406 ms at `N=1000`, 734 ms at `N=1500`, and 1382 ms at `N=2000`.

## Acceptance-criteria disposition

| Criterion | Result |
|---|---|
| Compare 0.001 s and 0.1 s objective, feasibility, runtime, and gap | **PASS** |
| Run `N>500`, including 750 and 1000 | **PASS** — through `N=2000` |
| Report runtime and solution quality | **PASS** |
| Report peak memory | **PASS** |
| Identify scalability bottlenecks | **PASS** |
| Determine whether more time changes quality/limitations | **PASS** |

## Reproducibility and artifacts

- Runner: `phorvex/benchmarks/solver-frameworks/task2_time_scalability.py`
- Independent checker: `phorvex/benchmarks/solver-frameworks/production_checker.py`
- Combined raw results: `reports/solver-frameworks/task2-time-scalability-results.csv` (90 rows)
- Runner SHA-256: `7abb6148e23d409cca56aad800bd71944b471cee8b46f84df50c5995095d3350`
- Checker SHA-256: `7412d9b12b6a383e3836290be2a721621423ca081ee0951dd382244099e45b36`
- Raw-results SHA-256: `2b12ca8779882b642b1143d3411c61fbab55af7def35dff2e2725d5852982bc2`

The files copied into the AWS pod were verified against the same runner and checker hashes before execution.

## AWS safety and cleanup

- Test pod service-account token: not mounted
- Runtime identity: non-root UID/GID 1000
- Linux capabilities: all dropped
- CPU/memory limits: 1 CPU / 1 GiB
- Defensive actions invoked: none
- Benchmark pods remaining: 0
- Hami temporary benchmark files remaining: 0
- Phorvex engine/operator after test: 1/1 Ready, zero pod restarts

No production policy, workload, CRD, deployment, image, or persistent AWS resource was modified.
