# Cost model validation benchmark (PHORVEXSEC-35)

This benchmark validates the current unitless `lambda * cost` term. It does not
estimate dollar ROI and it does not change hard feasibility rules.

## Safety boundary

`costprobe` calls the real `cost.P1Cost` and `actuator.NativeActuator`, but fails
closed unless the target namespace begins with `phorvex-cost-validate-`. The AWS
collector creates one disposable namespace, mutates only workloads it creates there,
and deletes the namespace at completion. The production operator and production
workloads are read-only during collection.

## Models

- C0: exact current `P1Cost.Components()` total.
- C1: one flat training-set mean cost.
- C2: nonnegative least-squares fit over norm, flow, state, GPU, and availability,
  clipped to `[0, 1]`.
- C3: observed post-action label, offline only.

The evaluator exposes the required swappable flag as
`--cost-model current|flat|calibrated|observed_oracle` (`all` is the benchmark
default). The oracle option exists only in this offline script and is not wired into
the operator. With the benchmark disabled, production continues to use the unchanged
current model.

The observed label is the equal-weight mean of available normalized availability,
p99, tokens/second, Ready delay, state/KV, and GPU terms. No business weights were
specified in the ticket. Missing terms remain JSON `null`, are listed in
`missing_measurements`, and are omitted from the mean; the count is retained in
`observed_label_terms`.

## Scenario and split contract

The collector runs three seeds for each required scenario: stateless low load,
stateless high load, stateful, low replica, RAG, high connections, and SLO hot. It
records hard-feasibility blocks rather than bypassing them. The evaluator assigns
whole `(scenario_id, seed)` groups to a deterministic 70/30 split, so repeated action
measurements from a group cannot cross the boundary.

The complete action vocabulary is attempted or explicitly classified. GPU/MIG and
serving-stack actions remain `not executable` when their real prerequisite is absent;
Kubernetes-only partial effects are not promoted to successful end-to-end samples.

## Local verification

```bash
go test ./internal/cost ./benchmarks/cost-validation/cmd/costprobe
python3 -m unittest -v benchmarks/cost-validation/test_cost_validation.py
go build -o /tmp/costprobe ./benchmarks/cost-validation/cmd/costprobe
```

## AWS collection

Run from the configured EKS gateway after copying the statically built probe and the
three benchmark files:

```bash
COSTPROBE=./costprobe \
COST_EVALUATOR=./cost_validation.py \
ACTION_CATALOG=./action-catalog.json \
REVISION=$(git rev-parse HEAD) \
OUT_DIR=./task35-results \
./aws_collect.sh
```

Required outputs are:

- `cost-validation-results.csv`
- `cost-validation-summary.md`
- `c2-weights.json`
- `action-cost-coverage.csv`
- `cost-validation-provenance.json`
- `cost-validation-summary.json`

`cost-validation-observations.jsonl` is retained as the raw evidence.
