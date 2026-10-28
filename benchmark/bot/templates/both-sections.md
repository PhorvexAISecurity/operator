# Independent brain experiments

## Bench
policy: vllm/vllm-defense
ticks: 64
sync: false
change:
In phorvex/internal/decision/ablation.go, add one explanatory comment immediately
before the existing if base.Ratio > 0 branch, explaining that the positive-ratio
check avoids division by zero. Change comments only. Preserve executable code.

## Params
policy: vllm/vllm-defense
ticks: 64
sync: false
P-FEA-006: 1.0, 1.2, 1.5
