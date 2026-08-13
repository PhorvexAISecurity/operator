# Cost Model Validation Summary

**Recommendation: collect more measurements.**

> ## ⚠️ CORRECTION (2026-08-05) — read before the tables
>
> The original write-up headlined **"C2 reduces held-out regret 99.932%"** as the
> calibration result. That framing is **not supported by this run's own numbers** and is
> corrected here. The data below is unchanged; only the interpretation is fixed.
>
> **1. C2 provides zero decision value over a cost-blind baseline.** In the held-out decision
> table, `C1` (cost-blind) and `C2` (calibrated) are **byte-identical** on every metric —
> mean regret `5.4694366256475515e-05`, cumulative objective `4.305745250622486`,
> coverage/cost `14.767467`, 3 flips. So the entire "99.932% reduction" comes from **not
> trusting C0's cost magnitude**, not from the calibrated weights. Crediting the calibration
> for it is wrong.
>
> **2. The real defect is C0's cost SCALE, not its formula shape.** Measured disruption is
> `rotate ≈ 0.096`, `quarantine ≈ 0.096` (nearly equal), while C0 predicts `rotate ≈ 0.82`
> (~8×) and `quarantine ≈ 0.29` (~3×). At the operative `lambda`, this inflated cost
> overwhelms security value, so C0 wrongly **avoids rotate** (`C0 selected 0 vs oracle 3`) and
> **over-uses quarantine** (`4 vs oracle 1`). Both blinding (C1) and small calibrated costs
> (C2) remove that domination identically. The cheap, correct fix is **rescaling C0 /
> retuning `lambda`**, not adopting C2's component weights.
>
> **3. C0 is actually *worse* than cost-blind here.** The acceptance table already records
> `C0: beats flat cumulative objective = false` (C0 obj `3.746` < C1/C2 obj `4.306`). The
> original summary did not surface this. So "keep C0" is justified only by **data
> insufficiency**, not by evidence that C0 is good.
>
> **4. C2's weights are not decision-validated and are unstable.** `gpu` weight `0` with
> `CV = inf` (0 support), `norm`/`state` `CV ≈ 0.37`. The "weights stable = true" gate is too
> lenient for these. Do not treat the weights as a validated formula.
>
> **5. The decision test is 7 held-out decisions over `rotate`/`quarantine` only.** The
> actions the optimizer actually competes over on GPU/RAG assets —
> `endpoint-rotate`, `warm-swap`, `model-shard-replace`, `adapter-rotate` — have **~0 usable
> samples here** (see the coverage matrix). A follow-up run against the real 4h attack trace
> (2026-08-05) confirmed those four are exactly the actions appearing in the real competing
> decision groups, so **decision regret on the decisions that matter is currently
> unmeasurable**, not "reduced 99.9%".
>
> **Corrected takeaway:** keep C0 in production *for now* only because there is not enough
> data to change it responsibly. Do **not** cite C2 as a validated improvement. The next step
> is to (a) measure the four GPU/RAG actions under load, and (b) check C0's cost **scale**
> against measured disruption and retune `lambda` — a much smaller change than swapping the
> formula.

This is a unitless disruption-cost benchmark. It is not a dollar/ROI calibration. C3 is an offline oracle and is never deployable. Hard feasibility remained outside the fitted objective.

## Data and split

- Observations: 77 (53 usable)
- Grouped 70/30 split: 15 train groups / 7 held-out groups
- Input SHA-256: `72b88773a35b94761cbeab250166ea9aee56ac9a6abccb7d742b480c2ad4e641`
- Observed label: equal-weight mean of available normalized availability, p99, TPS, Ready, state/KV, and GPU terms

Missing metrics stayed explicit and were omitted from the equal-weight label; `observed_label_terms` in the raw CSV shows each row's evidence count.

## Learned C2 weights

Note (correction §4): these are **not decision-validated** and are unstable — `gpu` is fully
unidentified (0 support, CV = inf) and `norm`/`state` have CV ≈ 0.37.

| component | weight | stability mean | stability std | stability CV |
|---|---:|---:|---:|---:|
| norm | 0.000000 | 0.038697 | 0.014516 | 0.375122 |
| flow | 0.028392 | 0.004702 | 0.000659 | 0.140132 |
| state | 0.003098 | 0.040128 | 0.015009 | 0.374037 |
| gpu | 0.000000 | 0.000000 | 0.000000 | inf |
| availability | 0.211363 | 0.140897 | 0.032928 | 0.233701 |

## Held-out prediction and ranking

Lower C2 MAE reflects that C2 is fit *to* `cost_observed` (the same quantity C3 uses); it is
not on its own evidence of better decisions (see correction §1).

| model | n | MAE | RMSE | Spearman | Kendall tau-b | pairwise accuracy |
|---|---:|---:|---:|---:|---:|---:|
| C0 | 18 | 0.284629 | 0.381380 | 0.593397 | 0.466784 | 0.724490 |
| C2 | 18 | 0.025132 | 0.039658 | 0.785486 | 0.641243 | 0.809524 |

## Held-out decision quality

**`C1` and `C2` are byte-identical** (correction §1): the improvement over `C0` is a
cost-blinding effect, not a calibration effect. `C0` also loses to `C1` on cumulative
objective (correction §3).

| model | decisions | mean regret | p95 regret | cumulative objective | coverage/cost | SLO violations | availability loss | flips vs C0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C0 | 7 | 0.080011 | 0.225211 | 3.746050 | 11.908537 | 1 | 1.166667 | 0 |
| C1 | 7 | 0.000055 | 0.000268 | 4.305745 | 14.767467 | 1 | 1.166667 | 3 |
| C2 | 7 | 0.000055 | 0.000268 | 4.305745 | 14.767467 | 1 | 1.166667 | 3 |
| C3 | 7 | 0.000000 | 0.000000 | 4.306128 | 14.793903 | 1 | 1.166667 | 4 |

C2 held-out mean-regret change versus C0 is 99.932%, but **C1 (cost-blind) achieves the
identical number** — so this is not attributable to the calibrated weights. It reflects that
C0's cost magnitude is ~3–8× the measured disruption and over-penalizes acting.

## Generalization

C2 MAE is lower here too, but for the same fit-to-label reason as above; these do not
establish decision-quality generalization.

| test | train n | test n | C0 MAE | C2 MAE | C0 Spearman | C2 Spearman |
|---|---:|---:|---:|---:|---:|---:|
| stateless+stateful → GPU/RAG | 44 | 9 | 0.275686 | 0.030055 | 0.706543 | 0.706543 |
| low load → high/connections/SLO-hot | 23 | 30 | 0.267990 | 0.034474 | 0.694328 | 0.723046 |

## Full action-cost coverage matrix

The decision-relevant GPU/RAG actions (`kv-reset`, `warm-swap`, `mig-rebind`,
`model-shard-replace`, `adapter-rotate`, `kv-migrate-invalidate`) have **0 usable samples**
in this AWS run; `endpoint-rotate` has 1 (flow-only). The held-out decisions are effectively
`rotate` vs `quarantine` only (correction §5).

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
- C2 numeric improvement criteria passed: **true** — but see correction §1: `C1` matches `C2`
  exactly, so the regret criterion is met by cost-blinding, not calibration.
- C2 final promotion checks passed: **false**.
- Promotion data sufficiency (all five coefficients identified in train and held-out data): **false**.
- C0 mean signed error on high-availability-risk held-out rows: **0.374082** (positive → C0
  *over*-prices those rows, consistent with the scale problem in correction §2).
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
| C2: regret reduction at least 10pct | true (matched exactly by cost-blind C1 — not a calibration win) |
| C2: cumulative objective preserved | true |
| C2: slo violations not increased | true |
| C2: availability loss not increased | true |
| C2: weights stable | true (too lenient — gpu unidentified, CV inf; see correction §4) |

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

---

*Correction authored 2026-08-05 after cross-checking against the 4h attack-trace decision
groups (real per-tick `lambda`). Cross-check code and outputs:
`phorvex/benchmarks/cost-validation/cost_validation_offline.py` and
`reports/cost-validation-35-20260805/` on `main`.*
