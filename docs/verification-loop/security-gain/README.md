# Security Gain validation study

This study checks whether the P1 Security Gain matches measured defensive effect for one
scenario. The formula under test is:

```text
SecurityGain(i,a) = provenance(i) × Σ weight(k), summed over the facts k the action covers
```

It is the first measured study of that formula. It covers only the endpoint-lease family.
[REPORT.md](REPORT.md) has the results, the answers to the six Math/OR questions and the
limitations. The candidate-level export is
[2026-10-12/candidates.csv](2026-10-12/candidates.csv).

The study runs on the [one-case verification loop](../README.md):

- a private envtest API server;
- the unchanged `ucw-recon` decision engine;
- the native actuator;
- the shipped Python admission boundary;
- a synthetic downstream.

It never touches a shared cluster. The formula, the action-to-fact map, λ/β and every
gate stay unchanged.

## Design

Each episode starts from the same declared initial state with fresh credentials:

1. A stolen-credential (`endpointLeaseReuse`) attack with a `TEST_INJECTED` event.
2. The brain decides in shadow mode, on a single tick.
3. The episode takes one branch after that decision:

| `-arm` | Branch after the brain's decision |
|---|---|
| `intervention` | Dispatches the selected `endpoint-lease-revoke` (the reviewed defended path). |
| `baseline` | Withholds every action. |
| `cf-rotate` | Dispatches native `rotate` instead (counterfactual). The decision-layer availability gate marks it infeasible on this single-replica workload. The actuator's own gates still apply. |
| `cf-endpoint-rotate` | Dispatches native `endpoint-rotate` instead (counterfactual). |

The episode then measures three things:

- **Capability.** Attacker credential A and legitimate credential B are probed for the hold
  window. A probe counts only when the downstream call counter proves the protected
  operation ran (200) or did not run (exact 401).
- **Brain view.** The brain re-observes the workload: which facts it still mints, at what
  weight, and what it would now select.
- **Replacement.** After `rotate` the evicted pod is gone. envtest runs no controllers, so
  the harness creates the ReplicaSet's replacement pod, labelled as harness-simulated, and
  re-observes there.

`run_study.py` runs seeded, interleaved blocks with one episode per arm in each block.
`analyze.py` reads every `report.json`.

## Reproduce

Linux amd64, Go 1.26.1, Python 3 and the envtest assets from the
[verification-loop README](../README.md#reproduce-the-experiment) are required. Run from the
operator repository root:

```sh
(cd phorvex && go build -o "$LOOP_WORK/verification-loop" ./cmd/verification-loop)
python3 build/test-harness/security-gain-validation/run_study.py \
  --binary "$LOOP_WORK/verification-loop" --repo-root "$(pwd -P)" \
  --python "$LOOP_WORK/venv/bin/python" --assets "$LOOP_ASSETS" \
  --git-sha "$(git rev-parse HEAD)" --out "$LOOP_WORK/study" --blocks 10 --hold 20s
python3 build/test-harness/security-gain-validation/analyze.py "$LOOP_WORK/study" --out "$LOOP_WORK/analysis"
python3 -m unittest discover -s build/test-harness/security-gain-validation
```

## Reading `candidates.csv`

There is one row for each candidate in each episode's real decision state, including
`noop`. Rows from different episodes are never merged into one decision state.

- **Predicted columns** come straight from the unchanged brain's trace for that episode:
  - `predicted_security_gain` is `grossFullValue`, that is provenance × Σ covered weights;
  - the marginal and net gains follow;
  - then asset value, pHold, urgency, dispersion, provenance, cover keys and weights.
- **Measured columns** are filled only on the row for the action the episode executed
  (`executed_in_episode=yes`). Every other row leaves them blank.
- **Status columns.** Each measured column has a `*_status` companion that holds one of:
  - `MEASURED`
  - `ESTIMATE`
  - `CENSORED`, which gives a lower bound
  - `NOT APPLICABLE`
  - `UNAVAILABLE`, followed by the reason

  An unavailable value is never written as zero.
- **`confirmed_invalidated_keys`** lists fact kinds that the brain no longer mints after the
  branch and whose capability the probes measured as removed.
- **`false_invalidated_keys`** lists kinds the brain no longer mints although the
  capability is still measured as usable.
- **`unmeasured_cleared_keys`** lists kinds that have no instantiated capability in this
  fixture.
- **`attack_success_no_action`** is the episode-level rate from the baseline arm, which
  starts from the same initial state but runs in separate episodes.
- **`attack_landed_before_decision`** is this episode's own pre-decision probe.
