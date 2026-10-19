# Actuator service

The actuator acts. It owns the backends that enact moves (`internal/actuator`:
native client-go handlers, Phoenix SecurityEvents and AMTD strategies, and the
hybrid router), their operation journals, the retained-quarantine capacity
ledger, and the standing route policy. It is the only service that writes to
workloads, and every live re-read before a mutation happens inside it. See
[ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The dispatcher reaches it through one contract, `phorvex/internal/actuatorapi`.
Phase 4c-1 implements it in process (`actuatorsvc.Local`); phase 4c-2 serves the
same adapter over gRPC.

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

## What stays with the dispatcher

The kill switch and namespace brakes, the decision of what to act on, failure
cooldowns, emit intents, rotation feedback, shared capacity and the audit stay
with the dispatcher. It builds each `Request` from the selected decision and the
view, and reads the `Result` and its error identity (`NoEffectRefusal`, context
cancellation) to decide fallbacks.

## Testing

```sh
go -C phorvex test ./internal/actuatorsvc ./internal/capability ./internal/runner
```
