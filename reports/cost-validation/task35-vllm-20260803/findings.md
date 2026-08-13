# Task 35 addendum — live measurements against a real vLLM serving stack

Date: 2026-08-03
Cluster: `arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks`
Probe revision: `8ceb4b917e3407c9e7f0b270010602ca92cf64a1` (same binary that produced the original 77 observations)

## Why this addendum exists

The original 77 observations were collected against `costbench`, a synthetic
Python HTTP service. It has no GPU, no model, and no KV cache. Consequently
every AI-native action was recorded as **not executable**, `c_gpu` was null in
`77/77` rows, and the calibrated model `C2` could not be promoted for lack of
component support.

This addendum measures the same actions against a **real vLLM serving stack**.

## Method

A byte-for-byte clone of the production `vllm` Deployment was created in the
disposable namespace `phorvex-cost-validate-vllm`:

- image `vllm/vllm-openai:v0.7.3`, model `Qwen2.5-0.5B-Instruct`
- prefix caching and runtime LoRA enabled, same `phorvex.ai/*` annotations
- 2 replicas, `gpu-memory-utilization 0.20`, KV cache `0.58 GiB` per replica
- **deliberately not labelled `r6th.io/rotation-target`, and no PhorvexPolicy
  in the namespace**, so the live operator could not act on it and contaminate
  attribution

Isolation was verified empirically: the operator pod IP (`172.27.12.162`) never
appears in the clone's access logs, while it continued acting on the production
`vllm` namespace during the same period.

Load and telemetry were supplied by a purpose-built snapshot adapter exposing
the schema `costprobe --metrics-url` expects, sourcing:

- latency / request rate / tokens from its own generated load (24 distinct
  ~1,323-token prefixes, held-out working set)
- `gpu_prefix_cache_hit_rate`, `gpu_cache_usage_perc` from vLLM `/metrics`
- `gpu_util`, `vram_pressure` from DCGM via `prometheus.gpu-telemetry`

## Finding 1 — the probe must run inside the cluster, or AI-native actions silently do nothing

`kv-reset` reaches the serving stack at `pod.Status.PodIP` (`172.27.x.x`), which
is not routable from the bastion host. Run from outside, the probe exits `0`,
reports `handler: kv-reset` with an empty `actuation_error`, and emits a cost
row — while **no cache is flushed**.

The actuator itself is correct and fail-closed: it records
`emitted: false`, `mutation_kind: none` rather than claiming a flush it did not
perform. The defect is in where the measurement is run.

Verified directly in the target's own logs:

| probe location | `reset_prefix_cache` calls seen by vLLM | `kv-reset-epoch` annotation |
|---|---|---|
| bastion (outside cluster) | `0` | not written |
| in-cluster runner pod | `1` | `32719056` |

**Any kv-reset cost measured from outside the cluster is vacuous.** Confirmation
must come from the target's logs, never from the probe's exit status.

## Finding 2 — kv-reset cost depends almost entirely on how full the cache is

Measured on a single pod, `max_tokens=1` to isolate prefill:

| cache state | working set | p50 warm | p50 after flush | penalty |
|---|---|---|---|---|
| near-empty (1.2% filled) | 620 tokens | `83.5 ms` | `86.2 ms` | `+3.3%` |
| filled (63%) | 31,752 tokens (24 prefixes) | `32.0 ms` | `68.6 ms` | **`+114.4%`** |

A `35x` difference. The prefix-cache hit rate fell to `0.0000` after the flush,
confirming full invalidation, and recovered to `31.5 ms` on the next sweep.

Derived unit cost: **`0.0277 ms` of extra prefill compute per cached token.**

Measuring a flush against an unpopulated cache — as the original synthetic run
necessarily did — understates its cost by more than an order of magnitude.

## Finding 3 — measured action costs

25 observations, `scenario_id=vllm-gpu`, seeds 1–8, real Phorvex actuator:

| action | n | emitted | `c_gpu` | gpu_burden | p99 delta | recovery | observed cost |
|---|---|---|---|---|---|---|---|
| noop (control) | 8 | 0/8 | `0.000` | `0.008` | `+1.8%` | — | `0.009` |
| kv-reset | 8 | 8/8 | `0.948` | `0.022` | `+59.9%` | `~0 s` | `0.111` |
| rotate | 8 | 8/8 | `0.948` | `0.148` | `+58.9%` | `68.1 s` | `0.272` |
| quarantine | 1 | 1/1 | `0.000` | `0.011` | `+2.9%` | — | `0.108` |

`p99 delta` is service-level, i.e. diluted by the second healthy replica — this
is the user-visible cost, not the single-pod cost.

Rotate is highly reproducible: `min_ready_observed = 1` in all 8 runs, recovery
`62.6–91.2 s` (median `~67 s`), dominated by model load since the image is
cached but weights are fetched per start.

## Finding 4 — quarantine leaves an orphaned GPU-holding pod

`quarantine` relabels the pod to `app=<name>-quarantined` and **removes its
`ownerReferences`**, intentionally detaching it so it survives for forensics.
The ReplicaSet then creates a replacement.

On a capacity-constrained node the replacement cannot schedule, because the
orphan still holds a full GPU allocation, CPU and memory. Observed directly:
after two quarantines the namespace held 4 pods — 2 orphaned and Running,
2 replacements Pending with `Insufficient cpu, Insufficient memory` — and the
workload stayed degraded at 1 of 2 replicas until the orphans were deleted
manually.

The current cost model charges `c_availability = 1/ready` for a momentary dip.
It does not model an **indefinite** capacity loss requiring operator
intervention. This is an unmodelled cost of `quarantine` on GPU workloads.

## Finding 5 — vLLM KV cache sizing is startup-order dependent on a shared GPU

vLLM attributes any GPU memory that appears between its init and its profiling
pass to itself as `non_torch_memory`. On a shared, time-sliced T4 this makes the
resulting KV cache non-deterministic:

| pod | `non_torch_memory` | resulting KV cache |
|---|---|---|
| production replica A (before restart) | `1.88 GiB` | `0.95 GiB` |
| production replica B (before restart) | `1.14 GiB` | `1.70 GiB` |
| clone replica starting concurrently | `2.64 GiB` | `-1.12 GiB` → **CrashLoop** |
| clone replicas started staggered | `0.05 GiB` | `0.58 GiB` (both, identical) |

Two identically-configured replicas differed by `79%`. Staggering startup
removes the variance entirely.

Practical consequence for Phorvex: **a `rotate` on a GPU workload can silently
change the replacement pod's serving capacity**, up or down, depending on what
else is allocating at that moment. That is a hidden cost of rotation not present
in the cost model.

## Effect on the promotion gate

Merging these 25 observations with the original 77 (`102` total):

| component support (positive train/test) | before | after |
|---|---|---|
| `c_gpu` | `0 / 0` | **`14 / 2`** |
| `c_state` | `2 / 1` | **`16 / 3`** |
| `c_availability` | `22 / 8` | `26 / 9` |
| `c_flow` | `25 / 13` | `33 / 15` |
| `c_norm` | `22 / 8` | `26 / 9` |

`promotion_data_sufficient` flips `False → True`, and the evaluator's
recommendation moves from *collect more measurements* to *promote the
calibrated formula*.

## Caveat — this is NOT yet sufficient to promote C2

`c2_regret_reduction` remained **exactly** `0.9993164155356914` across the 77-,
87- and 102-row datasets. That is not a coincidence and not a cached value.

Every probe invocation in this addendum was given a unique `tick-id`, and
`decision_key = (scenario_id, seed, tick_id, workload_id)`. Each vLLM decision
group therefore contains exactly **one** candidate, so every model selects the
same row and contributes regret `0` to both C0 and C2. Adding equal counts of
zeros to both means leaves the ratio `(c0 - c2)/c0` algebraically invariant.

Verified:

```
vllm decision groups: 25   with >1 candidate: 0
synthetic groups    : 22   with >1 candidate: 22
c0 mean regret: 0.08001113 -> 0.05091617   (x0.6364)
c2 mean regret: 5.469e-05  -> 3.481e-05    (x0.6365)
```

**The gate now passes on data sufficiency alone. Decision-quality evidence is
still derived entirely from the synthetic workload; not a single real GPU
decision was tested.**

To close this properly, the collection must be repeated with a **shared
`tick-id` across several candidate actions**, so the models are forced to choose
between alternatives on a GPU workload. Until then, C2 should not be promoted on
the strength of these numbers.

## Related defect filed separately

**PHORVEXSEC-67** — `kv-reset` ignores its `15m` anti-over-rotation budget;
consecutive flushes observed `10–18 s` apart against a policy ceiling of
`96/day`. Using the unit cost measured above (`0.0277 ms` per cached token), a
full production cache (`244,000` tokens) costs `~6.75 s` of extra GPU compute
per flush, i.e. `~1.39 GPU-hours/day` at the observed rate. Impact is currently
masked because the tenant served `0` inference requests in 24h; under real load
the measured `2.14x` prefix-cache speedup would be largely destroyed.

## Production safety

The production `vllm` Deployment was not used for any destructive measurement.
Two changes were made with the owner's approval, both to relieve a scheduling
constraint:

- memory request reduced `5Gi → 3Gi` per replica (actual usage `~2.1 GiB`);
  rolling, no downtime, backup at `~/task35-backup/vllm-deploy-before.yaml`
- `mock-rag-chatbot` temporarily scaled `2 → 0` (idle: `0` non-health requests
  in 24h); restore with `kubectl -n mock-rag-chatbot scale deploy chatbot --replicas=2`

A side effect worth recording: the rolling restart cleared the stale
`non_torch_memory` described in Finding 5, raising both production replicas from
`0.95`/`1.70 GiB` to `2.79 GiB` of KV cache — a genuine improvement to the
tenant's serving capacity.
