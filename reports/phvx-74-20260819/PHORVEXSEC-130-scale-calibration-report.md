# PHORVEXSEC-130 (PHVX-74) — sections 1–6 — report

Date: 2026-08-19 · Branch `feat/phvx-74-scale-calibration` · PR #58
Commits `aa3d86c`, `4be46ad`, `652a58b`, `2a2c70c`, `41b645e`

Section 7 (exact brute-force benchmark) is covered by PHVX-23 / PHORVEXSEC-114 and PR #55; it is
not repeated here.

## Headline

`internal/calib` implements sections 1–6 as a **shadow** calibrator. Production continues to run the
shipped constants. The isolation is structural, not a convention: `go list -deps` reports **zero**
dependency on the package from `decision`, `feasibility`, `recon`, `cost`, `actionset`, `platform`
and `metrics`. 57 tests, race-clean.

The OR decisions were used as given — P95, 30-minute cadence, >10% saturation warning, three-refresh
persistence, fallback to the shipped constant with `source=fallback_default` and a stated reason.

**Four findings came out of applying them to the live fleet.** None is a defect in the calibrator;
all are properties of this cluster, and all will move when the EPSS feed lands
(PHORVEXSEC-104, PR #59). Each is recorded as a test whose failure message says so, so that a
future failure reads as "re-derive" rather than "something broke".

## 1. Fleet as measured, 2026-08-19

Five nodes, all Ready and schedulable; 71 running pods; 33 distinct image digests.

```
namespaces per node  = [2, 4, 5, 8, 9]
X_node               = [1, 3, 4, 7, 8]
ImageRarity values   = 1.6224, 1.7423, 1.8374, 2.0     (four distinct)
CoResidency values   = 1.25, 1.75, 2.0                 (three distinct)
CoResidency at 2.0   = 56 / 71 pods  (78.9%)
uncapped product     = 2.03 .. 8.00
pinned at the 4.0 cap= 26.8%
EPSS coverage        = 2 / 71  (2.8%)
```

The ticket body's figures (76 pods, 38 digests, median 7 ns/node, EPSS 9.2%) no longer describe the
cluster. The central premise — the clamp is discarding real spread — holds and is if anything
sharper.

## 2. Finding: the percentile grid has no resolution on this cluster

Section 3 asks to evaluate P90 / P95 / P97.5 / P99. With five nodes, nearest rank can only ever
return one of five values:

| percentile | X_node |
|---|---|
| P80 | 7 |
| **P90, P95, P97.5, P99** | **8 — all identical** |

The four-point grid collapses to a single point and cannot justify a choice of percentile from this
sample. **Four agreeing numbers here are not consensus, they are an absence of resolution.**
`Identifiable()` returns the distinct values a grid produces so this is reported rather than
inferred.

Options if an identifiable percentile is wanted: pool observations across refreshes so the node
population varies, or measure on a unit other than the node. Flagged rather than decided — it is a
sampling limit, not a parameter choice.

## 3. Finding: the two configured parameters are mutually inconsistent

`MaxDispersionMult: P95` and `saturation warning: > 10%` cannot both be satisfied here.

| percentile | resulting cap | at ceiling | clears >10% |
|---|---|---|---|
| P90 | 4.0000 | 11.3% | ✗ |
| **P95** | **4.0000** | **11.3%** | **✗** |
| P97.5 | 6.9692 | 2.8% | ✓ |
| P99 | 8.0000 | 1.4% | ✓ |

P95 of the uncapped product is **exactly 4.0 — the shipped constant** — so calibrating at P95 is a
no-op for dispersion and still leaves 11.3% at the ceiling. The recalibration does not clear the
threshold it is being judged against.

The cause is discreteness, the same family as finding 2: `ImageRarity` takes four values and most
pods sit at co-residency 2.0, so a large mass lands on exactly `2.0 × 2.0 = 4.0` and both P90 and
P95 fall inside it.

**P97.5 is the smallest clearing percentile**, but the value it selects is set by one of the two GPU
pods — above P95 the cap is decided by **2 of 71 assets**. That fragility is measured
(`TestSmallestClearingPercentileIsSetByVeryFewAssets`), not asserted.

## 4. Finding: recalibrating co-residency moves the body, not the tail

P95 gives a co-residency scale of **8.0** against the shipped 4.0, and that is a genuine
improvement: the term goes from **3 distinct multipliers to 5**, i.e. it starts ranking nodes again
instead of labelling most of them identically.

| `CoResidencyCap` | distinct multipliers | pods at the 2.0 ceiling |
|---|---|---|
| 4.0 (shipped) | 3 — `1.25, 1.75, 2.0` | 56/71 (78.9%) |
| **8.0 (P95)** | **5** — `1.125, 1.375, 1.5, 1.875, 2.0` | 26/71 (36.6%) |

But it does not clear the invariant alone: with `MaxDispersionMult` left at 4.0, saturation only
falls **26.8% → 16.9%**.

The reason is specific. The assets setting the upper percentiles sit on the 9-namespace node, so
`X = 8`. At scale 4 that is `8/4 = 2` clamped to 1; at scale 8 it is `8/8 = 1`. **Both give exactly
2.0**, so the tail-setting pods are numerically identical either way. The minimum moves; the maximum
does not. This is why section 3's instruction to fit the two jointly is load-bearing.

## 5. Finding: cadence cannot rescue a wrong percentile

Walk-forward evaluation at the configured P95:

| interval | windows | max at ceiling | scale drift | clears |
|---|---|---|---|---|
| 5 min | 47 | 11.3% | 0.005 | ✗ |
| 15 min | 15 | 11.3% | 0.015 | ✗ |
| 30 min | 7 | 11.3% | 0.029 | ✗ |
| 60 min | 3 | 11.3% | 0.057 | ✗ |

Every candidate fails by the same margin. Section 5's ordering — *smallest percentile that keeps
saturation acceptable, **then** largest interval that stays valid* — is therefore correct and
load-bearing: until the percentile is right the cadence sweep has nothing to discriminate between,
and **four identical failures can be mistaken for a robust result**.

Drift is reported so the churn side of the trade-off is visible: 0.005 at 5 minutes rising to 0.057
at 60 minutes on a drifting fleet, and exactly 0 on a static one.

## 6. Section notes

**§1–2 shadow and co-residency.** Nearest rank is fixed rather than configurable: every scale is
later compared against raw observations to compute a clipping ratio, and a scale sitting *between*
two observed values makes that ratio incoherent. `Source` is part of the `Scale` value, not a
sidecar — the failure this ticket is about is a number whose origin got lost, and a fallback
indistinguishable from a measurement would reproduce it exactly. Empty schedulable nodes count as
X = 0 and their count is exported; deriving the node set from pods would silently drop them and bias
the fleet to look denser than it is.

**§3 dispersion.** Co-residency is deliberately not read back from the physics witness. The witness
carries the multiplier already computed at the shipped cap, so a percentile taken from products
containing it would be a percentile of an already-clipped distribution — which the spec forbids. The
raw namespace count is carried instead so the term can be recomputed at a candidate scale. Both
clip ratios are reported: at-ceiling (`≥`) answers "how much of the fleet gets the maximum
multiplier", strictly-clipped (`>`) answers "how much magnitude was actually discarded". On this
fleet they are 20% and 0% at the co-residency scale — neither is 5%, and neither is wrong.

**§4 ready-delay.** Kaplan-Meier rather than a rank over raw elapsed values. A rotation still pending
has no duration, only a lower bound on one; recording it as if it finished at the deadline biases
every statistic downward, and most when the fleet is slowest — exactly when the scale matters.
Quantiles that censoring cannot identify are reported **absent** rather than filled with the largest
observed value, and the activation gate names which condition failed: `insufficient eligible
outcomes` and `requested percentile not identifiable under censoring` call for different responses.
The reference and censor deadline are frozen at rotation start, so a later refresh cannot
retroactively reclassify a rotation that already happened.

A wrong assumption was caught here during development: with 4 of 10 records censored the survival
curve bottoms at 0.4, so nothing beyond the 60th percentile is knowable. That cut-off is a property
of how much of the sample is pending, not a tunable — which is why heavy censoring must *disable*
the estimate rather than degrade it.

**§5 cadence.** Fits strictly before each boundary, scores strictly after it; `cadenceWindows` makes
the disjointness structural rather than a discipline, and the test checks both the intersection and
the ordering. Saturation is judged on the worst window, not the mean — an average hides the interval
in which the alarm actually fired. An interval the history cannot exercise reports as **not**
clearing, the same rule as PHVX-23's unmeasured optimality ratio: an absent measurement is not a
passing one.

**§6 metrics.** Value, source, percentile, observation and invalid counts, both clip ratios, refresh
outcome, scale age, change ratio, fallback state and reason, the saturation streak and its persisted
warning, plus ready-delay censoring / exceedance / hard-saturation ratios. Four choices worth
naming: source is a separate series because a fallback and a measurement can be the same float; a
fallback counts as a **failed** refresh, or a permanently-unmeasurable scale looks healthy; age
counts from the last *successful* refresh so it keeps rising while the calibrator falls back; and
the previous fallback reason is cleared before the new one is set, or two causes are reported at
once.

The series live in `internal/calib` rather than `internal/metrics` so the isolation guarantee does
not become conditional on nobody ever adding a metric to a decision package. Names still follow the
`phorvex_` convention.

## 7. Not included, deliberately

The runner wiring that would call the calibrator on a timer, and the chart/values change to enable
it. That is the step which makes the shadow actually run on the cluster, and it is worth landing
separately: CI is failing at job-start org-wide on a GitHub billing error, so a chart change cannot
be validated, and the vendored-subchart check is the only thing that catches a stale re-pack.

## Verification

`go build ./...`, `go vet ./...`, full `go test ./...` green; `go test ./internal/calib -race`
clean; 57 tests; zero dependency on `internal/calib` from every decision-path package.
