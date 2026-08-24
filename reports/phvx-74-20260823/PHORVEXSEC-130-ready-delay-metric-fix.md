# PHORVEXSEC-130 — ready-delay observation metric correction

Updated: 2026-08-23 · Branch `fix/phorvexsec-130-ready-delay-metric`

## Finding

The live ready-delay exporter and Kaplan–Meier estimator correctly reported 101 eligible
observations, but `phorvex_calib_observations{scale="ready_delay"}` reported zero.

The generic scale publisher used `Scale.Clip.N`. That population is correct for snapshot-derived
scales, but ready-delay intentionally has no clip distribution: its population combines observed
and right-censored rotation outcomes and is carried by `ReadyDelayReport.Eligible`.

## Correction

`Tracker.ObserveReadyDelay` now publishes `ReadyDelayReport.Eligible` as the ready-delay observation
count after the generic scale metrics. Snapshot-scale behavior is unchanged, and invalid outcomes
continue to be published separately.

This is an observability correction only. It does not change the estimator, candidate scale,
decision path, actuation, or activation policy.

## Regression coverage

The new regression test reproduces the live shape: 101 eligible observations, an intentionally
empty `Scale.Clip`, and two invalid outcomes. Before the correction the observation gauge was zero;
after the correction it is 101 while the invalid gauge remains two.

Verification on the exact branch:

- `go test ./internal/calib -count=1` — pass
- `go test -race ./internal/calib -count=1` — pass
- `go test ./...` — pass
- `go vet ./...` — pass
- `git diff --check` — pass

## Task impact

The numeric PHORVEXSEC-130 evidence remains unchanged. This correction makes the Prometheus
observation count agree with the raw exporter and estimator, so the 100-outcome readiness gate can
be audited correctly. The ticket should remain In Progress until the math owner decides whether the
voice-bot-only ready-delay population is representative enough for acceptance.
