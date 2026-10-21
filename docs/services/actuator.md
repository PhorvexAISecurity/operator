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
`actuatorclient.Client` is the dispatcher's side of it. `cmd/actuator` runs it
as its own service, which the manager reaches with `--actuator-endpoint`.

## Contract

| Call | When | Effect |
|---|---|---|
| `Backend`, `RequiredVerbs` | per question | the configured backend and the access each action needs; pure |
| `SupportsAction`, `CapabilityAdvisory` | per candidate, during the brain's gate questions and the ActionsSupported status | runtime-fixture checks; some read the cluster or probe the workload (request drain, voice and endpoint-lease readbacks, MIG node agent) |
| `ReviewsAccess`, `AccessAllowed`, `AccessObserved` | per candidate, the capability gate's RBAC leg (last) | whether the identity the actuator acts as may use the action's verbs; `AccessObserved` answers from reviews already made and issues none |
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
standing policy, whether it reviews access, and the access every known action
needs, so `Backend`, `MaintainsStandingPolicy`, `ReviewsAccess` and
`RequiredVerbs` cost no call.

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
| `AccessAllowed`, `AccessObserved` | unknown, which the gate flags without excluding, as a failed review in process; the move itself still fails on real authorization |
| `ObserveStandingPolicy`, `ReconcileStandingPolicy` | the backend's routes `unknown` and refused for the tick |
| `PrepareRoutes` | an error, which refuses every dispatch of the tick |
| `RetirePolicyBinding` | not retired, with the error logged |
| `RecoverOperations` | a failed journal read, logged and audited |
| `QuarantineCapacity` | a configured bound of unknown use, which admits no new quarantine |
| `PendingOperation` | unresolved, which fences the dispatch |
| `Actuate` | possibly enacted: the backend counts as invoked and the error is never a refusal without effect |

## Running

```sh
PHORVEX_ACTUATOR=hybrid go -C phorvex run ./cmd/actuator --listen=:9090 \
  --operator-namespace=phorvex-system --trusted-detectors=vllm/detector-adapter-inv
```

The `phorvex-actuator` image is built from `deploy/docker/service.Dockerfile`:

```sh
docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=actuator -t phorvex-actuator .
```

It holds the one binary as `/service` on distroless nonroot. PR validation builds
it, without pushing, beside the manager and console images.

`deploy/charts/phorvex-actuator` deploys it: one replica replaced with the
Recreate strategy, its own ServiceAccount bound to the actuator's share of the
services' access (`phorvex-common`: the reads and the workload writes), and a
NetworkPolicy that admits the gRPC port only from the manager's pods. Egress stays
open: the actuator acts through the API server and calls the workloads' control
endpoints. The chart reads the manager chart's keys under `phorvex`: it derives
the operator namespace, the trust, the backend flags and environment as that chart
does, and renders the operator-owned files it reads (adapter reload sources, MIG
profiles, serving security bindings) as its own ConfigMaps.
`tools/test_service_charts.py` renders both charts from the same values and
requires the same actuator flags, environment and file contents, and that the
actuator chart refuses every invalid configuration the manager chart refuses.

With `codeExecAdmission` enabled, the admission policy admits ephemeral containers
only from the manager's identity, so a separate actuator's code-exec is refused.
Admitting the actuator's identity changes that reviewed admission contract (M-6)
and is left to its own step.

The actuator needs the actuation RBAC the selected backend uses (the manager's
today) under its own ServiceAccount; before it serves it runs the startup
authorization preflight (`startupauthz`) against that identity and refuses to
start without a known allow for every permission an active policy may use. Run
one replica, replaced with the Recreate strategy: the native backend keeps its
policy bindings in memory, and the manager re-establishes them through
standing-policy maintenance after a restart. The journals and the quarantine
ledger are durable ConfigMaps.

| Flag or variable | Default | Meaning |
|---|---|---|
| `--listen` | `:9090` | gRPC address; the gRPC health service is also served |
| `--metrics-bind-address`, `--health-probe-bind-address` | `:8080`, `:8081` | metrics (the actuation metrics now publish here) and probes |
| `--operator-namespace` | `$POD_NAMESPACE` | journals and quarantine ledger; must match the manager |
| `--trusted-detectors`, `--endpoint-lease-approved-*` | as the manager | must match the manager, or the handshake refuses it |
| `--serving-security-*`, `--lora-clean-sources-file`, `--mig-profiles-file`, `--mig-*`, `--voice-mcp-approved-image`, `--max-retained-quarantines-per-namespace` | as the manager | the backends' configuration now reads here |
| `PHORVEX_ACTUATOR`, `PHORVEX_VOICE_ADMISSION_ENABLED` | as the manager | the backend and the Voice admission flag |

`phorvex/cmd/internal/actuatorconfig` defines the backend flags and
`phorvex/cmd/internal/trustconfig` the shared trust flags, for both binaries;
`actuatorconfig.Shared` derives the handshake configuration on both sides.

Manager flags for remote mode: `--actuator-endpoint`, `--actuator-connect-timeout`
(startup waits this long for the handshake, default 2m) and
`--actuator-call-timeout` (30s per question; an actuation keeps the tick's own
deadline). With `--actuator-endpoint` the manager builds no backend, quarantine
ledger, MIG transport or SSAR checker, skips the startup preflight, and needs no
actuation RBAC; the backend flags are read by the actuator instead.

## Whose access the gate reviews

The capability gate's RBAC leg asks the actuator, because the actuator's identity
is the one that acts. In process `Local` reviews with this process's own checker
(`Manager.Authz`), so nothing changes. A remote actuator reviews its own
ServiceAccount, and the dispatcher's checker is never consulted for it. An
actuator that reviews no access leaves the gate without an RBAC leg; the M99
fallback then still excludes candidates with a qualified outcome.

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
