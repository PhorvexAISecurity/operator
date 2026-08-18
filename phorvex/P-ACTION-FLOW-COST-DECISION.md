# PHORVEXSEC-92 — action-specific flow-cost models

The replacement-PodReady RLS is a **respawn model**, not a universal actuator
model. P1 now routes every mutating action explicitly:

| Family | Actions | Flow shape |
|---|---|---|
| respawn | `rotate`, `mig-rebind` | existing rotation-trained RLS; `mig-rebind` is a lower-bound proxy until repartition timing exists |
| quarantine | `quarantine` | existing connection-pressure model |
| cutover | `warm-swap`, `model-shard-replace`, `endpoint-rotate`, `request-drain` | `0.10 + 0.15 × bounded serving-load pressure` |
| measured serving state | `kv-reset` | measured TTFT penalty fraction `0.820526` (paired median penalty `1486.686 ms`; raw AWS evidence in `benchmarks/kv-reset-ttft`) |
| unmeasured serving state | `kv-migrate-invalidate`, `adapter-rotate`, `guardrail-rotate` | `0.05 + 0.10 × bounded serving-load pressure` |
| lightweight | `identity-rotate`, `route-rotate`, `debugger`, `custom-inject` | constant `0.02` |

The cutover, unmeasured-serving-state, and lightweight values are dimensionless disruption
losses and are marked **`[ESTIMATE-UNVALIDATED]`**. They are not fabricated
durations and do not convert aborted-request counts into replacement-PodReady
seconds. PHVX-9d supplied the first empirical replacement: `kv-reset` uses the
measured fraction of first-post-reset TTFT attributable to the reset penalty. It
does not extrapolate a load curve that the idle AWS run did not measure.

Two safeguards prevent recurrence:

1. every entry in `model.MutatingActions` must have an explicit family;
2. an unknown runtime action receives the maximum flow-cost fallback (`2.0`), not
   the rotation RLS.

A rotation observation is proven to reprice only the respawn family. Cold-start,
GPU, and learned PodReady coefficients cannot leak into warm-swap, request-drain,
kv-reset, or other non-respawn actions.
