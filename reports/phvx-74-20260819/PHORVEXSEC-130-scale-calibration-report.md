# PHORVEXSEC-130 (PHVX-74) — shadow scale calibration report

Updated: 2026-08-20

Branch: `feat/phvx-74-scale-calibration` · PR #58

Implementation commit: `49c06a7`

## Result

Sections 1–6 and 8 are implemented. The operator now samples the cluster at startup and every five
minutes, refreshes candidates every 30 minutes over a seven-day lookback, exports raw CSV/JSON,
publishes fallback/saturation/freshness metrics, records observed/censored/invalid rotation
outcomes, and evaluates production versus candidate-scale optimizer results in read-only shadow
mode.

Production scoring still uses the shipped constants. Candidate values are carried only on cloned
shadow witnesses; a zero shadow override keeps `CoResidencyCap=4.0` and
`MaxDispersionMult=4.0`. Shadow optimizer evaluation does not advance the production dual price,
cost learner, or kill-chain memory.

Section 8 is wired through `spec.brain.killChain`. Sojourn values are explicit integer seconds and
`shape` is a positive decimal string. Missing or invalid values preserve every `NewModel()` default.
Overrides are resolved per policy and do not mutate the shared kill-chain model, preserving tenant
isolation. Deep-copy code, CRD, chart CRD, sample policy, README, source chart, and the vendored
subchart were regenerated or updated.

Section 7 is owned by PHORVEXSEC-114 / PR #55. It is not claimed complete here.

## Runtime behavior

- Startup/first-opportunity calibration sample, then five-minute samples.
- Thirty-minute candidate refresh, seven-day lookback.
- Deterministic nearest-rank P90/P95/P97.5/P99 joint sweep.
- Kaplan–Meier ready-delay estimates for P50/P75/P90/P95/P97.5/P99.
- Minimum 100 eligible ready outcomes and identifiable P95 before a ready-delay candidate can be
  measured; otherwise `400s` remains with an explicit fallback reason.
- Rotation reference and censor deadline are frozen at action start. A right-censored outcome is
  never recorded as a completed Ready event.
- Production/shadow selected sets and per-asset coverage/cost/net scores are exported. Availability
  and SLO violations are counted explicitly. Missing optimizer evidence cannot count as stable.
- Raw exports are written atomically to the configured writable evidence directory.
- Helm defaults enable shadow collection and mount an `emptyDir` at
  `/var/run/phorvex-calibration`. Learned values are not activated.

## Evidence boundary — important correction

No live Kubernetes evidence was collected during this repair. `kubectl` is unavailable and
`/home/milad/.kube/config` does not exist in the verification environment. Therefore this report
does **not** claim current live pod/node counts, live ready-delay outcomes, live optimizer stability,
or zero live availability/SLO violations.

The committed bundle at `reports/phvx-74-20260819/reconstructed-evidence/` is labelled
`reconstructed_fixture_not_live` in every CSV and JSON manifest. It rebuilds the aggregate shape
reported on 2026-08-19 (five nodes and 71 pods) to exercise the formulas. Per-pod rows are
deterministic reconstructed fixtures, not raw API objects. Ready-delay and optimizer comparison
files are intentionally empty because those observations were unavailable.

On that reconstructed scenario only:

| item | result |
|---|---:|
| P95 co-residency scale | 8.0 |
| P95 dispersion cap | 4.0 |
| dispersion at-ceiling ratio | 11.2676% |
| P90/P95/P97.5/P99 co-residency resolution | all select 8.0 |
| cadence candidates | all fail |

The cadence candidates fail for two independent, correctly represented reasons: saturation exceeds
10%, and there are no live ready-delay or optimizer comparisons. A missing comparison is not an
exact match and does not produce a passing cadence.

## Deliverables

- Implementation: `49c06a7` on `feat/phvx-74-scale-calibration`.
- Raw/export code: `phorvex/internal/calib/export.go` and `runtime.go`.
- Reconstructed, explicitly non-live CSV/JSON bundle:
  `reports/phvx-74-20260819/reconstructed-evidence/`.
- Raw co-residency and dispersion component exports, including uncapped products.
- Ready-delay schema/export with honest empty reconstructed evidence.
- Joint percentile and cadence sweeps.
- Raw production/shadow optimizer comparison schema and exports.
- Policy/API/CRD/chart implementation for `SojournScale` and `Shape`.

## Acceptance status

| criterion | status |
|---|---|
| Current constants stay active in production | Pass — shadow clones only |
| Deterministic percentile method | Pass — nearest rank, tested |
| Raw values captured before clipping | Pass |
| Co-residency and dispersion evaluated jointly | Pass |
| Ready-delay censoring represented honestly | Pass |
| Pending deadlines remain frozen | Pass |
| Missing data uses explicit fallback | Pass |
| Saturation/clipping/freshness metrics emitted | Pass |
| Counterfactual optimizer effects measured without learning side effects | Pass in code/tests; live evidence pending |
| Sojourn defaults backward-compatible and overrides reach hazard model | Pass |
| Availability/SLO violations remain zero | Not established live; counters implemented |
| Exact benchmark and skipped semantics | Pending PHORVEXSEC-114 / PR #55 |
| Raw live data delivered | Blocked by absent cluster access; reconstructed bundle is not a substitute |

## Verification

Run from `phorvex/` unless noted:

```text
go build ./...
go vet ./...
go test ./...
go test -race ./internal/calib ./internal/runner ./internal/decision ./internal/recon ./internal/killchain ./api/v1alpha1
git diff --check
```

All passed on 2026-08-20. Helm v3.17.3 was downloaded from `get.helm.sh`, verified against its
published SHA-256 checksum, then used for:

```text
helm lint phorvex/charts/phorvex
helm template phorvex-test phorvex/charts/phorvex --namespace phorvex-system
helm lint deploy/helm/phorvex-stack
helm template phorvex-stack-test deploy/helm/phorvex-stack --namespace phorvex-system
```

Both charts linted and rendered successfully. Generated CRD equals the source-chart CRD, and the
CRD extracted from `deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz` is byte-identical to it.
No `.github/workflows/` file was changed.

## Remaining blockers and decisions

1. Deploy PR #58 to a real cluster long enough to collect raw snapshots, optimizer comparisons,
   and at least 100 eligible rotation outcomes; then replace the reconstructed attachment with the
   live export while retaining provenance.
2. Choose percentile/cadence only after that walk-forward evidence exists. No candidate is
   activated by this PR.
3. Finish the exact runtime matrix and explicit statuses in PHORVEXSEC-114 / PR #55.
