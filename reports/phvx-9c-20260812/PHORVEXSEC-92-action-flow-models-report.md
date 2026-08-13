# PHORVEXSEC-92 (PHVX-9c) — action-specific flow-cost models

Date: 2026-08-12
Branch: `fix/phvx-9c-action-flow-models`
Base: `main` — PR #6 is merged, and PR #35 now targets `main` directly.

## Result

The replacement-PodReady RLS no longer prices every non-quarantine action.
Every mutating action is routed to an explicit flow-cost family whose units match
the actuator's disruption shape.

## Premise correction

The ticket correctly identified the cross-action dimensional error, but its
compounding premise is now stale: `ObserveRotation` is wired in the live runner
(`cb7514d1`) and the respawn RLS does learn from completed replacement PodReady
observations. That makes isolation more important: learned respawn coefficients
must not leak into in-process cache flushes, label writes, or warm cutovers.

## Implemented routing

| Family | Actions | C_flow |
|---|---|---|
| respawn | `rotate`, `mig-rebind` | existing rotation-trained RLS; MIG is explicitly a lower-bound proxy |
| quarantine | `quarantine` | existing `0.25 + 0.15 × connection pressure` |
| cutover | `warm-swap`, `model-shard-replace`, `endpoint-rotate`, `request-drain` | `0.10 + 0.15 × bounded serving-load pressure` |
| serving state | `kv-reset`, `kv-migrate-invalidate`, `adapter-rotate`, `guardrail-rotate` | `0.05 + 0.10 × bounded serving-load pressure` |
| lightweight | `identity-rotate`, `route-rotate`, `debugger`, `custom-inject` | `0.02` |

Cutover, serving-state, and lightweight values are marked
**`[ESTIMATE-UNVALIDATED]`**. They are dimensionless disruption-loss priors, not
fabricated durations. In particular, request/connection counts are bounded within
their own family and are never converted into replacement-PodReady seconds.

PHVX-9d remains the measurement follow-up: replace the kv-reset serving-state
estimate with observed TTFT degradation. Warm-swap, MIG, and adapter calibration
remain unavailable on the current fleet for the hardware/workload reasons recorded
on that task.

## Recurrence guards

- `TestEveryMutatingActionHasExplicitFlowFamily` fails when a newly generatable
  action is not classified.
- An unknown runtime action receives the conservative maximum flow cost (`2.0`),
  never the rotation RLS.
- `TestRotationObservationOnlyRepricesRespawnFamily` proves a live rotation sample
  changes only `rotate` and `mig-rebind` costs.
- Cold-start phase and GPU coefficients are proven not to leak into warm-swap or
  kv-reset; load pressure remains bounded.

## Verification

```text
go build ./...                                                   PASS
go vet ./...                                                     PASS
go test -count=1 ./internal/cost                                PASS
go test -count=1 -skip TestScenariosExport ./internal/...       PASS
TestGreedyIsExactOnShippedFleets ratio=1.000000000000           PASS
TestO1SingleTenantByteIdentical                                 PASS
```

The unfiltered suite still invokes `TestScenariosExport`, a benchmark artifact
generator that defaults to an absent `internal/decision/bin` output directory.
That main-branch failure is unrelated to this change.
