# Actuator service

The actuator acts. It owns the backends that enact moves (`internal/actuator`:
native client-go handlers, Phoenix SecurityEvents and AMTD strategies, and the
hybrid router), their operation journals, the retained-quarantine capacity
ledger, and the standing route policy. It is the only service that writes to
workloads, and every live re-read before a mutation happens inside it. See
[ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The dispatcher reaches it through one contract, `phorvex/internal/actuatorapi`.
`actuatorsvc.Local` implements it in process. `actuatorsvc.Server` serves the
same adapter over gRPC (`phorvex.actuator.v1.ActuatorService`), and
`actuatorclient.Client` is the dispatcher's side of it. The `cmd/actuator`
binary and the manager's `--actuator-endpoint` follow in phase 4c-3.

## Contract

| Call | When | Effect |
|---|---|---|
| `Backend`, `RequiredVerbs` | per question | the configured backend and the access each action needs; pure |
| `SupportsAction`, `CapabilityAdvisory` | per candidate, during the brain's gate questions and the ActionsSupported status | runtime-fixture checks; some read the cluster or probe the workload (request drain, voice and endpoint-lease readbacks, MIG node agent) |
| `MaintainsStandingPolicy`, `ObserveStandingPolicy`, `ReconcileStandingPolicy` | every policy tick | observe route drift, or repair it after fresh owner and brake checks |
| `PrepareRoutes` | dispatch, for a backend without standing-policy maintenance | prepares routes; an error refuses the tick |
| `RetirePolicyBinding` | lifecycle drain | forgets a removed policy's authorization; reports whether the backend keeps one |
| `RecoverOperations` | every tick unless the kill switch is engaged | journal-driven rollbacks and route restoration |
| `QuarantineCapacity` | every policy tick | the namespace's retained-quarantine bound and usage, which the brain prices |
| `PendingOperation` | per selected move | same-Pod fences from the protected-operation journals |
| `Actuate` | per selected move | reserves quarantine capacity when bounded, then enacts; reports whether the backend was reached |

The values that cross (`Request`, `Result`, `Target`, `TenantTarget`, the route
preparation, `NoEffectRefusal` and the dispositions, the route table and the
shared rejection reasons) are defined in `actuatorapi`, with aliases in
`internal/actuator`.

`actuatorsvc.Local` discovers a backend's optional capabilities (standing
policy, policy bindings, operation recovery, route preparation, advisories) the
way the runner did, so test doubles that implement only the base interface keep
working.

## Over gRPC

Domain values (`Target`, `TenantTarget`, `Request`, `Result`) travel as CBOR
(`phorvex/internal/wire`), as on the brain and sensor services. Errors travel as
`actuatorpb.Error`: the text, and whether the error was a `NoEffectRefusal` or
wrapped `context.DeadlineExceeded` or `context.Canceled`. Those are the only
identities the dispatcher branches on; it reads every other error by its text.
The route preparation, standing-policy results and recovery events carry their
errors the same way.

**Handshake.** `Hello` carries the contract version (`actuatorapi.ContractVersion`)
and the SHA-256 of `actuatorapi.Config`: the operator namespace, the trusted
detector identities (compared as a set) and the endpoint lease authority. It
returns the answers that are fixed for a backend: its name, whether it keeps
standing policy, and the access every known action needs, so `Backend`,
`MaintainsStandingPolicy` and `RequiredVerbs` cost no call.

**Deadlines.** Questions (support, advisory, standing-policy observation,
capacity, fences, binding retirement) are bounded by the client's call timeout.
Calls that may mutate (`Actuate`, `ReconcileStandingPolicy`, `PrepareRoutes`,
`RecoverOperations`) are bounded only by the caller's context, as in process, so
the client never cancels a mutation halfway. The caller's deadline and
cancellation reach the actuator.

**Failure semantics.** Every unanswered call fails closed:

| Call | Unanswered reads as |
|---|---|
| `SupportsAction` | unsupported, `backend-unavailable: actuator service: ...` |
| `CapabilityAdvisory` | no advisory (posture only) |
| `ObserveStandingPolicy`, `ReconcileStandingPolicy` | the backend's routes `unknown` and refused for the tick |
| `PrepareRoutes` | an error, which refuses every dispatch of the tick |
| `RetirePolicyBinding` | not retired, with the error logged |
| `RecoverOperations` | a failed journal read, logged and audited |
| `QuarantineCapacity` | a configured bound of unknown use, which admits no new quarantine |
| `PendingOperation` | unresolved, which fences the dispatch |
| `Actuate` | possibly enacted: the backend counts as invoked and the error is never a refusal without effect |

## What stays with the dispatcher

The kill switch and namespace brakes, the decision of what to act on, failure
cooldowns, emit intents, rotation feedback, shared capacity and the audit stay
with the dispatcher. It builds each `Request` from the selected decision and the
view, and reads the `Result` and its error identity (`NoEffectRefusal`, context
cancellation) to decide fallbacks.

## Testing

```sh
go -C phorvex test -race ./internal/actuatorpb ./internal/actuatorsvc ./internal/actuatorclient ./internal/capability ./internal/runner
```

`actuatorclient`'s parity tests run a scripted contract behind the real server
and client. They check every answer and argument for parity, error identities
included. They also check that each unanswered call fails closed, and that a
mutation keeps the caller's deadline while a question keeps the call timeout.
