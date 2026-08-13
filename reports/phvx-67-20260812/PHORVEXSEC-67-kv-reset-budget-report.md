# PHORVEXSEC-67 — kv-reset ignores its anti-over-rotation budget — fix report

Date: 2026-08-12 · Branch `fix/phvx-67-kv-reset-budget`

## Measured on production first

```
pod            vllm/vllm-cc4988699-5tqpq   (the cluster's only model-serving pod)
window         10h 21m
decisions      2360, every one a kv-reset on that same pod
interval       median 20s   (min 9s, max 21s)
policy budget  antiOverRotationWindow = 15m
```

**45× over budget, on one pod, continuously.** Each flush costs ~0.534 s of re-encode by the team's
own measurement (`console/cost.go`), so roughly **21 minutes of redundant re-encode in 10 hours —
about 3.4% of wall time** — and a first-token stall for whoever was talking to the model each time.

## The cause: the gate ran, and read the wrong clock

Not a bypassed gate. `antiOverRotation.Check` discarded the move entirely —

```go
func (antiOverRotation) Check(view *model.WorkloadView, _ model.Move, pol model.Policy) Verdict {
    since, ok := view.ExposureByVariable[model.VarPodIdentity]
```

— and always consulted `podIdentity`. That is right for actions that **replace the pod**. `kv-reset`
flushes the KV cache and leaves the pod alive, so `podIdentity` never changes, its clock only grows,
and `since < window` could never be true.

`model.VarSession` was already declared for exactly this ("KV-cache / agent session state") but sat in
`DeclaredExposureVariables` — scaffolded, never clocked, referenced nowhere else.

## The fix, in three parts

1. **`ingest/kube.go`** reads the epoch annotations the actuators already write —
   `phorvex.ai/kv-reset-epoch` and `phorvex.ai/kv-migrate-epoch` — into a new `Pod.SessionEpoch`.
   Pod annotations were not reaching the decision path at all; only a few named ones were lifted into
   specific fields.
2. **`runner/manager.go`** feeds `SessionEpoch` as the `VarSession` fingerprint. Both actuators stamp
   `pod.ResourceVersion`, so the value changes on every flush and the exposure clock resets — the
   mechanism the clock already had, simply never wired for this dimension.
3. **`feasibility/defaults.go`** selects the clock **by action**: `kv-reset` and
   `kv-migrate-invalidate` read `VarSession`; everything else reads `VarPodIdentity`.

An unmapped action falls back to `podIdentity`. That is the conservative direction — a shared clock
over-restricts rather than under-restricts — and `TestUnknownActionFallsBackConservatively` pins it,
so a future action cannot silently lose its budget by being forgotten.

## Tests

| test | pins |
|---|---|
| `TestKVResetRespectsItsOwnBudget` | the live shape: pod alive 10h, session flushed 20s ago → **blocked**. Fails on the old code with *"was allowed against a 15m budget"* |
| `TestKVResetAllowedOnceTheBudgetElapses` | 16m after a flush → allowed. The fix must not disable the action |
| `TestRotateStillUsesPodIdentity` | `rotate`/`quarantine`/`warm-swap` 20s after a pod replacement stay blocked — the old behaviour was correct for them |
| `TestUnknownActionFallsBackConservatively` | the default is the restrictive clock |

## Expected effect

`kv-reset` on that pod drops from ~180/hour to at most 4/hour. It is a **feasibility** change, not a
priority one: the action stays available and is still chosen when it is the best move — it simply
cannot re-fire inside its own budget.

This also explains the PHORVEXSEC-98 observation from a different angle. That ticket found 2360
decisions in 10h and all of them `kv-reset`; the reason the engine looked so monotonous is that one
pod could be re-selected every tick. The cost calibrator's starvation is a *symptom* of the same bug.

## Not claimed

- **Not verified on the live cluster.** The fix is proven by tests against the real `Check` path and
  by the production measurement of the defect; the corrected interval has not been observed running.
- The `[SP-0-PENDING]`-style gap that `VarSession` was declared but never clocked is closed only for
  these two actions. `VarImage`, `VarEnv`, `VarGPUBinding` and `VarNetworkIdentity` remain declared
  and unclocked — that is PHVX-1's marker sweep, not this ticket.
- Full suite green apart from `TestScenariosExport`, which fails identically on `origin/main` and is
  fixed under PHORVEXSEC-123.
