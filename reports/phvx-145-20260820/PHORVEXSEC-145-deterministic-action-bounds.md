# PHORVEXSEC-145 — deterministic per-action disruption bounds

Updated: 2026-08-20

Branch: `fix/phvx-145-deterministic-bounds`

Implementation commit: `627967c`

## Result

The merged PHORVEXSEC-141 implementation treated the worst observed vLLM recovery, 117 seconds,
as the deterministic `rotate` duration and inferred zero impact from the availability-floor action
predicate. Both claims were too strong.

This correction implements the PHORVEXSEC-145 proof rule:

```text
max over every permitted path p of sum over serial phases k: n[p,k] * tau[p,k]
```

Parallel phases use the conservative envelope `max(n) * max(tau)`. A positive phase is finite only
when its deadline is enforced, expiry stops the unsafe work or enters another bounded phase, and
return to a safe state is verified. A caller timeout that only returns an error is rejected.

No positive shipped action currently satisfies that contract. This report therefore does not invent
deadlines: four actions are proven `zero`; the remaining thirteen are explicitly `unknown`. The
117-second vLLM result remains stored only as `ObservedMaxRecovery` validation evidence.

## Implementation

- `internal/slo/contract.go` implements serial, parallel, worst-path, safe-return and provenance
  checks, plus a separate service-specific availability derivation.
- `internal/slo/bound.go` holds an explicit classification for all 17 shipped/declared actions.
  `BoundFor` returns false for `unknown`; `ReplicaSeconds` returns `(value, finite)` so unknown cannot
  serialize as numeric zero.
- `internal/slo/ledger.go` separates measured zero from missing impact, stores action outcome and
  the bound frozen at selection, and keeps replica-seconds separate from availability-breach seconds.
- `internal/runner/manager.go` writes terminal synchronous outcomes for every attempted action. It
  continues tracking rotations after right-censoring until the replacement actually becomes Ready.
- The remaining-budget gate is unchanged and remains uncalibrated. Nothing in this branch admits or
  blocks a production move.

Code provenance: `internal/slo/bound.go:19`, `internal/slo/bound.go:89`,
`internal/slo/contract.go:31`, `internal/slo/contract.go:130`,
`internal/slo/contract.go:192`, `internal/slo/ledger.go:58`,
`internal/slo/ledger.go:174`, `internal/runner/manager.go:415`,
`internal/runner/manager.go:449`, and `internal/runner/manager.go:837` at implementation commit
`627967c`.

## Complete shipped-action path inventory

Notation: `n` is the maximum unavailable Ready-serving replicas in the phase; `tau` is its enforced
deadline. `tau=?` means the implementation has no valid deterministic end condition. `N=?` means a
shared route/group operation has no proven finite replica-loss cardinality.

| Action | Success path | Failure path | Deadline-expiry path | Rollback / safe recovery | Proven result |
|---|---|---|---|---|---|
| `noop` | no mutation, `n=0` | no failure mutation, `n=0` | no asynchronous work, `n=0` | none required | disruption `zero`; availability `zero` |
| `disable` | handler always returns `Emitted=false`, `n=0` | no mutation path | no asynchronous work | none required | disruption `zero`; availability `zero` |
| `identity-rotate` | atomic Pod metadata update, `n=0` | API error leaves readiness/routing unchanged, `n=0` | request may resolve ambiguously but both states are metadata-only, `n=0` | label restore is also metadata-only | disruption `zero`; availability `zero` |
| `route-rotate` | atomic epoch-label update; no Service/EndpointSlice change, `n=0` | API error leaves serving route unchanged, `n=0` | request may resolve ambiguously but both states are metadata-only, `n=0` | label restore is metadata-only | disruption `zero`; availability `zero` |
| `rotate` | delete target (`n=1`), owner replacement/readiness `tau=?` | delete can be accepted before an error is returned; recovery `tau=?` | caller context can end while deletion/recovery continues | owner respawn is recovery, but has no end-to-end deadline or safe-state deadline | `unknown` |
| `quarantine` | deny-all + detach target (`n<=1`), replacement/readiness `tau=?` | NetworkPolicy may exist while detach fails; no automatic compensation | timeout can leave a partial two-object mutation | a manual Rollbacker exists, but the runner does not invoke it and it has no deadline/safe-state verification | `unknown` |
| `debugger` | irreversible ephemeral-container injection on one target; serving effect has `tau=?` | subresource result can be ambiguous | caller timeout does not remove the container or verify target safety | Kubernetes cannot remove an ephemeral container | `unknown` |
| `custom-inject` | irreversible ephemeral-container injection on one target; serving effect has `tau=?` | subresource result can be ambiguous | caller timeout does not remove the container or verify target safety | Kubernetes cannot remove an ephemeral container | `unknown` |
| `kv-reset` | external serving-stack cache flush then Pod annotation; target effect `n<=1`, `tau=?` | stack error/timeout does not prove whether flush applied or readiness remained safe | HTTP/caller timeout is not a safe-return deadline | no rollback or post-flush safe-state verification | `unknown` |
| `warm-swap` | choose Ready shadow, cut over, retire old, rewarm; loss/cutover `n<=1`, `tau=?` | partial role flip/delete/re-warm paths lack a bounded terminal state | caller timeout can leave a wedged swap | reconciliation exists, but retry cadence is not an end-to-end recovery deadline | `unknown` |
| `mig-rebind` | drain, delete target, repartition GPU, owner reschedule; `n<=1`, `tau=?` | repartition may fail after pod deletion | caller timeout can leave pod absent/GPU state unknown | no bounded reverse repartition plus verified Ready recovery | `unknown` |
| `endpoint-rotate` | Pod route-key then optional shared Service selector update; `N=?`, `tau=?` | Pod update can succeed before Service update fails | timeout can leave either half applied | label Rollbacker does not restore the Service selector and is not automatically invoked | `unknown` |
| `model-shard-replace` | single or group-coherent warm cutover; `N=?`, `tau=?` | partial group transition/re-warm has no bounded terminal state | caller timeout can leave a mixed group | reconciliation has no enforced safe-return deadline | `unknown` |
| `adapter-rotate` | external unload, optional clean reload, metadata; `n<=1`, `tau=?` | unload can succeed before reload/metadata fails | timeout can leave adapter state unknown | clean-source rollback is optional, externally applied, and has no safe-return deadline | `unknown` |
| `request-drain` | remove target from serving then abort inflight; `n<=1`, `tau=?` | restore after abort error is best effort | timeout can leave target drained | Rollbacker re-admits, but is not automatically invoked and has no deadline | `unknown` |
| `guardrail-rotate` | external shared guardrail change then Pod record; `N=?`, `tau=?` | record failure triggers restore, but restore itself may fail | timeout leaves external variant outcome unknown | rollback applies the live restore best effort and ignores its error | `unknown` |
| `kv-migrate-invalidate` | local invalidate plus optional remote peers; `N=?`, `tau=?` | local may succeed while remote migration is deferred/fails | timeout leaves local/remote outcome unknown | no rollback or bounded cross-worker safe-state verification | `unknown` |

Handler provenance: `internal/actuator/handlers_k8s.go:43-346`,
`internal/actuator/handlers_ai.go:202-382`, and
`internal/actuator/handlers_ai_p4set.go:153-438`.

## Per-action summary

Availability is service-specific. For an action with proven `N=1`, availability is `zero` when
`readyReplicas - 1 >= minAvailableReplicas`; it remains `unknown` when the floor can be crossed. A
shared-path action with `N=?` cannot use that headroom proof.

| Action | `Nmax` | Longest bounded loss path | Replica-seconds bound | Availability-breach bound | Disruption | Availability at no headroom | Exact missing proof |
|---|---:|---:|---:|---:|---|---|---|
| `noop` | 0 | 0 | 0 | 0 | zero | zero | none |
| `disable` | 0 | 0 | 0 | 0 | zero | zero | none |
| `identity-rotate` | 0 | 0 | 0 | 0 | zero | zero | none |
| `route-rotate` | 0 | 0 | 0 | 0 | zero | zero | none |
| `rotate` | 1 | unavailable | unavailable | unavailable | unknown | unknown | replacement + rollback/safe-recovery deadline |
| `quarantine` | 1 | unavailable | unavailable | unavailable | unknown | unknown | quarantine duration + automatic bounded rollback/replacement recovery |
| `debugger` | 1 | unavailable | unavailable | unavailable | unknown | unknown | payload operating range, completion and recovery/cleanup contract |
| `custom-inject` | 1 | unavailable | unavailable | unavailable | unknown | unknown | payload operating range, completion and recovery/cleanup contract |
| `kv-reset` | 1 | unavailable | unavailable | unavailable | unknown | unknown | serving-stack timeout outcome + verified readiness/safe-return contract |
| `warm-swap` | 1 | unavailable | unavailable | unavailable | unknown | unknown | bounded warm/cutover/retire/failure/reconciliation paths |
| `mig-rebind` | 1 | unavailable | unavailable | unavailable | unknown | unknown | bounded repartition, reschedule and reverse-recovery paths |
| `endpoint-rotate` | unknown | unavailable | unavailable | unavailable | unknown | unknown | service-wide `Nmax`, atomic cutover and Service-aware rollback |
| `model-shard-replace` | unknown | unavailable | unavailable | unavailable | unknown | unknown | group `Nmax`, bounded group cutover and recovery |
| `adapter-rotate` | 1 | unavailable | unavailable | unavailable | unknown | unknown | bounded external unload/reload plus verified rollback |
| `request-drain` | 1 | unavailable | unavailable | unavailable | unknown | unknown | bounded drain plus automatic bounded re-admission |
| `guardrail-rotate` | unknown | unavailable | unavailable | unavailable | unknown | unknown | shared-tier `Nmax`, bounded apply and verified rollback |
| `kv-migrate-invalidate` | unknown | unavailable | unavailable | unavailable | unknown | unknown | peer-set `Nmax`, bounded distributed completion and recovery |

## Ledger contract

Each retained action entry now carries:

- tenant/service, namespace, target Pod and action;
- action start and observed/completion timestamps;
- outcome: completed, failed, deadline-expired, rolled-back, not-emitted, emitted-with-unobserved
  outcome, or right-censored;
- pre-action Ready replicas and `minAvailableReplicas` when available;
- separately measured replica-seconds and availability-breach seconds;
- explicit measured/unmeasured impact, so missing evidence is not zero;
- selection-time bound status, finite flag, numeric value only when finite, and provenance; and
- `cause=phorvex`.

Rotations receive measured/censored replica impact until recovery. Structural-zero synchronous
actions receive measured zero. Non-zero asynchronous actions whose serving outcome is not observed
remain explicitly unmeasured. The ledger is still in-memory and Phorvex-only; it is not total service
consumption and is not a 30-day SLO history.

## Verification

Commands run from `phorvex/` at commit `627967c`:

```text
git diff --check
go test ./...
go test -race ./internal/slo ./internal/runner
```

All passed. Direct tests cover:

- deterministic repeatability;
- success, failure, deadline-expiry and rollback inventories;
- caller-only timeout rejection;
- missing recovery/safe-state rejection;
- serial addition, parallel conservative envelope and worst-path selection;
- zero-loss warm-up exclusion;
- positive disruption with zero availability breach;
- explicit zero/bounded/unknown behavior;
- 117 seconds retained only as observed evidence;
- unknown never exposed as numeric zero;
- separate replica and availability ledger dimensions;
- selection-time bound provenance; and
- runner recording for structural-zero, unknown and censored/recovered rotations.

## Remaining blockers — not hidden by this implementation

1. No positive action can become `bounded` until its full mutation, failure and rollback/recovery
   paths enforce safe-return deadlines. Adding a caller context alone is insufficient.
2. `Rollbacker` handlers exist, but the runner has no automatic rollback orchestration; therefore no
   live rolled-back result can yet be emitted. The ledger vocabulary is ready, but the event source is
   absent.
3. Only rotation currently has post-actuation Ready-recovery observation. Other non-zero actions are
   retained as `ImpactUnmeasured`, not fabricated as zero.
4. The ledger is process-local and observes only Phorvex-caused effects. Durable full-window service
   history, total outage attribution and remaining-budget fields remain PHORVEXSEC-142/143 work.
5. No full SLO gate was activated, and this branch does not replace it with the old heuristic.

These blockers are why the honest production result is currently `4 zero / 0 bounded / 13 unknown`,
not a table of apparently precise but unenforced durations.
