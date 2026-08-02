# Cost Model Validation Summary

**Recommendation: collect more measurements.**

This is a unitless disruption-cost benchmark. It is not a dollar/ROI calibration. C3 is an offline oracle and is never deployable. Hard feasibility remained outside the fitted objective.

## Data and split

- Observations: 77 (53 usable)
- Grouped 70/30 split: 15 train groups / 7 held-out groups
- Input SHA-256: `72b88773a35b94761cbeab250166ea9aee56ac9a6abccb7d742b480c2ad4e641`
- Observed label: equal-weight mean of available normalized availability, p99, TPS, Ready, state/KV, and GPU terms

Missing metrics stayed explicit and were omitted from the equal-weight label; `observed_label_terms` in the raw CSV shows each row's evidence count.

## Learned C2 weights

| component | weight | stability mean | stability std | stability CV |
|---|---:|---:|---:|---:|
| norm | 0.000000 | 0.038697 | 0.014516 | 0.375122 |
| flow | 0.028392 | 0.004702 | 0.000659 | 0.140132 |
| state | 0.003098 | 0.040128 | 0.015009 | 0.374037 |
| gpu | 0.000000 | 0.000000 | 0.000000 | inf |
| availability | 0.211363 | 0.140897 | 0.032928 | 0.233701 |

## Held-out prediction and ranking

| model | n | MAE | RMSE | Spearman | Kendall tau-b | pairwise accuracy |
|---|---:|---:|---:|---:|---:|---:|
| C0 | 18 | 0.284629 | 0.381380 | 0.593397 | 0.466784 | 0.724490 |
| C2 | 18 | 0.025132 | 0.039658 | 0.785486 | 0.641243 | 0.809524 |

## Held-out decision quality

| model | decisions | mean regret | p95 regret | cumulative objective | coverage/cost | SLO violations | availability loss | flips vs C0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C0 | 7 | 0.080011 | 0.225211 | 3.746050 | 11.908537 | 1 | 1.166667 | 0 |
| C1 | 7 | 0.000055 | 0.000268 | 4.305745 | 14.767467 | 1 | 1.166667 | 3 |
| C2 | 7 | 0.000055 | 0.000268 | 4.305745 | 14.767467 | 1 | 1.166667 | 3 |
| C3 | 7 | 0.000000 | 0.000000 | 4.306128 | 14.793903 | 1 | 1.166667 | 4 |

C2 held-out mean-regret change versus C0: **99.932% reduction** (ticket threshold: at least 10%).

## Generalization

| test | train n | test n | C0 MAE | C2 MAE | C0 Spearman | C2 Spearman |
|---|---:|---:|---:|---:|---:|---:|
| stateless+stateful → GPU/RAG | 44 | 9 | 0.275686 | 0.030055 | 0.706543 | 0.706543 |
| low load → high/connections/SLO-hot | 23 | 30 | 0.267990 | 0.034474 | 0.694328 | 0.723046 |

## Full action-cost coverage matrix

| action | implemented | executable | classification | candidate | cost model | components | samples | mean observed cost | C0 MAE | decision impact |
|---|---|---|---|---|---|---|---:|---:|---:|---|
| rotate | yes | yes | executable | yes | yes | norm,flow,state,gpu,availability | 12 | 0.096342 | 0.725178 | C0 selected 0 vs oracle 3 |
| quarantine | yes | yes | executable | yes | yes | norm,flow,availability | 15 | 0.095796 | 0.195037 | C0 selected 4 vs oracle 1 |
| debugger | yes | yes | executable | yes | yes | flow | 1 | 0.000692 | 0.419488 | C0 selected 1 vs oracle 0 |
| custom-inject | yes | yes | executable | yes | yes | flow | 1 | 0.000146 | 0.420094 | C0 selected 0 vs oracle 0 |
| disable | no | no | not implemented | no | yes | flow,availability | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| identity-rotate | yes | yes | executable | yes | yes | flow | 1 | 0.006996 | 0.413304 | C0 selected 0 vs oracle 0 |
| route-rotate | yes | yes | executable | yes | yes | flow | 1 | 0.000145 | 0.420095 | C0 selected 0 vs oracle 1 |
| warm-swap | yes | no | not executable | yes | yes | flow,state,gpu | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| mig-rebind | yes | no | not executable | yes | yes | flow,state,gpu,availability | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| kv-reset | yes | no | not executable | yes | yes | flow,state,gpu | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| endpoint-rotate | yes | yes | executable | yes | yes | flow | 1 | 0.001338 | 0.419022 | C0 selected 0 vs oracle 0 |
| model-shard-replace | yes | no | not executable | yes | yes | flow,state,gpu | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| adapter-rotate | yes | no | not executable | yes | yes | flow,gpu | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| request-drain | yes | no | not executable | yes | yes | flow,availability | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| guardrail-rotate | yes | no | not executable | yes | yes | flow | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| kv-migrate-invalidate | yes | no | not executable | yes | yes | flow,state,gpu | 0 | n/a | n/a | C0 selected 0 vs oracle 0 |
| noop | yes | yes | executable | yes | yes |  | 21 | 0.006281 | 0.006281 | C0 selected 2 vs oracle 2 |

## Acceptance decision

- C0 numeric acceptance checks passed: **false**.
- C2 numeric improvement criteria passed: **true**.
- C2 final promotion checks passed: **false**.
- Promotion data sufficiency (all five coefficients identified in train and held-out data): **false**.
- C0 mean signed error on high-availability-risk held-out rows: **0.374082** (negative means systematic underpricing).
- Independent decision checker: **28 checks, 0 failures**.
- A lower prediction error alone was not treated as promotion evidence; decision regret and SLO/availability are controlling.
- Unsupported/missing-prerequisite actions remain classified in the matrix rather than silently omitted.

| acceptance check | passed |
|---|---|
| C0: beats flat cumulative objective | false |
| C0: positive rank correlation | true |
| C0: no systematic high availability underpricing | true |
| C0: slo violations no worse than oracle | true |
| C0: independent checker clean | true |
| C2: regret reduction at least 10pct | true |
| C2: cumulative objective preserved | true |
| C2: slo violations not increased | true |
| C2: availability loss not increased | true |
| C2: weights stable | true |

Component support used by the promotion gate:

| component | positive train rows | positive held-out rows |
|---|---:|---:|
| norm | 20 | 7 |
| flow | 20 | 12 |
| state | 2 | 1 |
| gpu | 0 | 0 |
| availability | 20 | 7 |

## Artifacts

- `cost-validation-results.csv` — candidate inputs, outcomes, predictions, selections, and errors
- `c2-weights.json` — learned nonnegative weights and repeated-split stability
- `action-cost-coverage.csv` — complete action vocabulary
- `cost-validation-provenance.json` — environment/input/hash/split provenance
- `cost-validation-summary.json` — machine-readable metrics
- `aws-post-run-health.json` — final production readiness and benchmark cleanup proof
