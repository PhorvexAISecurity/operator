# ADR-0001: Split the operator into independently released services

- **Status:** Accepted (2026-10-17)
- **Date:** 2026-10-16
- **Scope:** `phorvex/`, `build/test-harness`, `dashboard-web`, `deploy/`, CI

## Context

Today one Go module (`phorvex/`, about 158k lines plus 145k lines of tests) builds
one manager binary. That binary runs every domain inside a single leader-elected
tick loop (`internal/runner`):

```
ingest snapshot ─► physics witness ─► per tenant: capability gate ─► decide ─► actuate ─► audit
```

Everything ships as one image (`phorvex`), and a second image (`phorvex-console`)
carries the UI, the attack harness and a copy of the manager binary. Both share one
version sequence (`v0.4.x`). Argo CD syncs a single umbrella Application
(`phorvex-stack`). Logs use zap in development mode.

Measured couplings that block a naive split (see `internal/runner/manager.go`):

1. The optimizer calls the actuator synchronously for every candidate
   (`Capability`/`ShadowCapability` closures → `actuator.SupportsAction`, SSAR).
2. Actuation failures and fallbacks round-trip into the brain within the same
   tick (`FailureExclusion`, `SelectAlternative`/`ReserveAlternative`).
3. Outcomes feed back into brain state (`ObserveRotation`,
   `AdmitPersistenceObservation`).
4. Process-global configuration and caches (`Configure*` setters, the EPSS
   cache, the GPU envelope, adapter detector identities).
5. Domain-level import cycles: `platform→recon`, `ingest→actuator` constants,
   `actuator→actionset`, `model→voiceadmissionpolicy`, `api→model`.
6. One ServiceAccount holds the read, write and admission permissions of every
   domain.

## Decision

### Services

| Service | Responsibility | Owns today's packages (moved in phase 3) | Kubernetes access |
|---|---|---|---|
| **sensor** | Observe the cluster and derive physics and context | `ingest`, `graph`, `platform`, `physics`, `ctxprov`, `calib`, `epssfeed`, `epssmeta`, `gpudevice` | Read-only (`phorvex-scanner` role) |
| **brain** | Choose actions | `decision`, `actionset`, `recon`, `cost`, `feasibility`, `killchain`, `mathlab` | None (no token mounted) |
| **dispatcher** | Run the tick: policy reconcile, gates, kill switch, dispatch, audit | `runner`, `controller`, `capability`, `capacity`, `actuationbrake`, `slo`, `codeexec`, `exposure` | PhorvexPolicy, Leases, kill-switch and capacity ConfigMaps, webhooks |
| **actuator** | Execute actions against workloads | `actuator`, `ownership`, `podresources`, workload contracts (`crmrefund`, `endpointlease`, `litellmclient`, `outputpolicy`, `voice*policy`); `recovery`, `mig-allocation-helper` | Namespaced write (`phorvex-actuator` role) |
| **attacks** | Fire catalogue attacks and produce independent observations | `cataloguev1`, `build/test-harness`, `loss-observer`, `current-inventory-observer` | Scoped to attack targets |
| **console** | UI and API for operators | `console`, `dashboard-web` | Read, plus the grants it has today |

Shared libraries (`libs/`): `api` (CRD types), `model`, `proto` (service
contracts), and platform code: logging, metrics, build info, `authz`, `audit`,
`audittransport`, `registry`. The extended Phoenix operator stays a separate
third-party component with its own chart.

### Communication: gRPC with protobuf, driven by the dispatcher

Each tick, per tenant:

1. `Sensor.Snapshot(tenant)` returns workloads, physics witnesses and context features.
2. `Actuator.Capabilities(targets)` returns one capability set per target. This
   replaces the per-candidate callback, so the brain never calls the actuator.
3. `Brain.Decide(snapshot, capabilities, recent failures)` returns decisions,
   each with ranked alternatives. A fallback then needs no second call.
4. `Actuator.Actuate(decision)` returns the result, and the dispatcher retries the
   next alternative within the tick when the first is refused.
5. `Brain.Observe(outcomes)` feeds rotation and persistence outcomes back.

Rules:

- Contracts live in `libs/proto` and are versioned with buf lint and
  breaking-change checks. Every call carries a deadline.
- **Fail closed.** If any dependency errors or times out, the tick actuates
  nothing, records why in the audit stream, and exports a metric. The kill
  switch stays in the dispatcher and is evaluated before any call.
- Services authenticate with mTLS. NetworkPolicies allow only dispatcher →
  sensor/brain/actuator and console → read APIs.
- Process-global setters become per-service configuration. Nothing is shared
  in memory across services.

### State and availability

- **dispatcher:** leader-elected, as the manager is today. It owns cross-tick
  state: exposure clock, failures, emits ledger, pending rotations.
- **brain:** one active replica per tenant set, holding its learning state in
  memory as today. A restart re-learns, as a manager restart does today. Durable
  snapshots via `mathlab` are a later option.
- **actuator:** one active replica. Its operation journals already persist in
  ConfigMaps.
- **sensor:** stateless apart from caches, so it can run more than one replica.

### Repository layout

```
services/<name>/        cmd/, internal/, Dockerfile, go.mod
libs/<name>/            shared Go modules (api, model, proto, platform)
third_party/phoenix/    extended Phoenix operator
deploy/charts/<name>/   one Helm chart per service
deploy/environments/<env>/<name>.yaml   environment values
deploy/argocd/          AppProject + ApplicationSet
go.work                 local development across modules
```

Each service and lib is its own Go module with a `phorvex.ai/<directory>`
module path (for example `phorvex.ai/libs/logging`), independent of the
repository name. Services consume libs through `replace` directives, the pattern
`phorvex` already uses for `build/phoenix-extended`; CI and images build every
module on its own. `go.work` joins them for local development once several
service modules exist. A test keeps
every Docker build context complete for its module's replace targets (today's
`buildctx` check, per service).

### Versioning and release

- release-please in manifest mode gives one component per service, lib and chart,
  each with its own changelog and tag (`brain-v1.4.0`).
- A release builds one image per service (`<registry>/phorvex/<service>:<version>`,
  pinned by digest) and packages its chart.
- Deployment stays GitOps: CI commits the new tag and digest into
  `deploy/environments/<env>/<service>.yaml`, and Argo CD syncs it.
- CI path filters build and test only the affected services, plus every
  service that depends on a changed lib.

### Argo CD

- An `AppProject` named `phorvex` restricts the source repository and the
  destination namespaces.
- An `ApplicationSet` generates one Application per service and environment
  (`phorvex-<service>-<env>`), so each service appears in Argo CD with its own
  health, sync state, history and pod logs.
- First deployment is side by side in a separate namespace on the existing
  cluster. The current `phorvex-stack` Application stays untouched until cutover.

### Logging and observability

- Every service logs structured JSON to stdout with `log/slog`.
  controller-runtime uses it through the logr bridge.
- Every line carries `service`, `version`, `tenant`, `tick` and `trace_id`.
- Metrics keep their names, gain a `service` label, and get a ServiceMonitor
  per service.
- Argo CD shows per-service pod logs; a log store such as Loki is optional and
  out of scope.

## Migration (strangler, one PR per phase)

| Phase | Change | Behaviour |
|---|---|---|
| 1 | Clean up, archive, adapt the workflow harness | Unchanged |
| 2 | Foundation: first shared lib (`libs/logging`, slog JSON) adopted by the manager and console; gofmt/vet and image builds in CI | Unchanged (log format changes) |
| 3 | `go.work`; move packages into `libs/` and service modules, break the cycles above, replace the per-candidate capability callback with a per-tick capability set; still one binary; import-boundary tests | Unchanged; parity tests on recorded ticks |
| 4 | gRPC contracts and one binary per service, with an in-process mode kept behind a flag for rollback | Unchanged in in-process mode |
| 5 | One image, chart and Argo CD Application per service; release-please components and per-service CI path filters; deploy side by side with actuation disabled and compare decisions against the live manager's audit stream; cut over when they match | Shadow, then cutover |
| 6 | Move attack firing and harness runs out of the console into the attacks service | Console calls the attacks API |

Cutover criteria for phase 5 are decided separately. They must include decision
parity on live ticks, and rollback to the current `phorvex-stack` Application.

## Consequences

- **Positive:**
  - Each service is released, scaled, rolled back and observed on its own.
  - Least-privilege RBAC: only the actuator can write to workloads, and the
    brain has no cluster access.
  - Domain boundaries are enforced by modules and tests rather than convention.
- **Negative:**
  - Network hops add latency and new failure modes inside the tick; fail-closed
    turns them into missed ticks, never into wrong actions.
  - More moving parts to deploy and secure: certificates, NetworkPolicies, and
    six charts instead of one.
  - The brain's in-memory learning state now has its own restart lifecycle.
- **Neutral:**
  - The old repository keeps deploying production until cutover.
  - Its evidence stays archived there (`docs/provenance`).
