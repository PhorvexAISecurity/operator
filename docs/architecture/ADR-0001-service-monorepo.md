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
| **sensor** | Observe the cluster and derive physics and context | `ingest`, `graph`, `platform`, `physics`, `ctxprov`, `calib`, `epssfeed` | Read-only (`phorvex-scanner` role) |
| **brain** | Choose actions | `decision`, `actionset`, `recon`, `cost`, `feasibility`, `killchain`, `mathlab` | None (no token mounted) |
| **dispatcher** | Run the tick: policy reconcile, gates, kill switch, dispatch, audit | `runner`, `controller`, `capability`, `capacity`, `slo`, `codeexec`, `exposure`, `scopedoutcome` | PhorvexPolicy, Leases, kill-switch and capacity ConfigMaps, webhooks |
| **actuator** | Execute actions against workloads | `actuator`, `podresources`, `startupauthz`; commands `recovery`, `mig-allocation-helper` | Namespaced write (`phorvex-actuator` role) |
| **attacks** | Fire catalogue attacks and produce independent observations | `cataloguev1`, `lossobserver`, `currentobserver`, `build/test-harness` | Scoped to attack targets |
| **console** | UI and API for operators | `console`, `dashboard-web` | Read, plus the grants it has today |

Shared libraries (`libs/`): `api` (CRD types), `model`, `proto` (service
contracts), and platform code: logging, metrics, build info, `authz`, `audit`,
`audittransport`, `registry`. Contracts one service writes and another reads are
shared too: the workload policy formats (`crmrefund`, `endpointlease`,
`litellmclient`, `outputpolicy`, `voice*policy`), the actuation brake
annotations, workload ownership resolution, GPU device and serving declarations,
and EPSS metadata. The Phorvex-controlled SecurityEvent vocabulary lives in the
Phoenix `api/v1beta1` package, beside the type it extends. The extended Phoenix
operator stays a separate third-party component with its own chart.

`phorvex/internal/archtest` enforces this table while the services share one
module: every package has a domain, a domain imports only shared code, and each
remaining crossing is listed as debt with what removes it. The list may only
shrink. Since phase 4 this holds for the dispatcher too: it reaches the other
services through their contracts, and its remaining in-process crossings (the
Local adapters it composes, and brain and sensor logic it still runs itself) are
listed individually.

### Communication: gRPC with protobuf, driven by the dispatcher

Each tick, per tenant:

1. `Sensor.Observe(tick)` returns one observation of the cluster for every due
   policy: inventories, events, graph and event context per Pod, physics
   witnesses. `Sensor.Telemetry(policy)` then reads each policy's telemetry. The
   dispatcher builds the views from them and from the state it owns (exposure
   clocks, emit intents, failure cooldowns).
2. `Brain.Decide(snapshot)` is one bidirectional stream. While the brain generates
   candidates it asks a capability question for each (asset, action) that
   survives its structural filters; the dispatcher answers each one from the same
   cheapest-first witness as today (actuator support, code-exec admission, cached
   RBAC review) and its failure cooldowns. The stream ends with the decisions.
3. `Actuator.Actuate(decision)` returns the result. When the actuator refuses
   without effect, the dispatcher asks `Brain.SelectAlternative`, which picks from
   the already-gated candidates and needs no new capability answer.
4. `Brain.ObserveRotation(outcome)` feeds measured rotation outcomes back, as the
   runner does today; scoped persistence observations stay reporting-only.

The capability gate stays lazy and per candidate on purpose. Candidate generation
asks it once per surviving (asset, action), and some answers run live probes (the
request-drain readiness check is an HTTP call to the workload). Pre-resolving a
batch would need a second brain pass that must not advance kill-chain or cost
state, for a few hundred in-cluster round trips per tick. Over a stream the probe
set, its order and the decisions stay identical to the single binary, which
`mathlab` replays verify byte for byte.

Rules:

- Contracts live in `phorvex/api/proto` (the services share one Go module) and
  generate into `phorvex/internal/<service>pb`. CI runs buf lint and fails when
  the generated code is stale; breaking-change checks start with a contract's
  first release. Every call carries a deadline.
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
- **sensor:** stateless apart from caches and the telemetry source's previous
  samples, which its rates are derived from. One replica, unless the telemetry
  source's rate state moves out of the process.

### Repository layout

```
phorvex/cmd/<service>/  one binary per service (sensor, brain, dispatcher, actuator, attacks, console)
phorvex/internal/       service and shared packages, one domain each (archtest)
libs/<name>/            Go modules shared with other modules (phorvex.ai/libs/...)
deploy/charts/<name>/   one Helm chart per service
deploy/environments/<env>/<name>.yaml   environment values
deploy/argocd/          AppProject + ApplicationSet
```

The services share one Go module. Splitting modules per service would force the
dispatcher's in-process code to be exported until phase 4 removes those calls,
and buys little: each service still has its own binary, image, chart, version
tag and Argo CD Application. `phorvex/internal/archtest` enforces the domain
boundaries the compiler would otherwise enforce between modules, and CI derives
the services a change affects from the import graph (`go list -deps`). Code that
other modules also need, such as `libs/logging`, is a separate module with a
`phorvex.ai/<directory>` path, consumed through `replace` directives; a test keeps
every Docker build context complete for those targets.

### Versioning and release

- release-please in manifest mode gives one component per service, lib and chart,
  each with its own changelog and tag (`brain-v1.4.0`).
- A release builds one image per service (`<registry>/phorvex/<service>:<version>`,
  pinned by digest) and packages its chart.
- Deployment stays GitOps: CI commits the new tag and digest into
  `deploy/environments/<env>/<service>.yaml`, and Argo CD syncs it.
- CI builds and releases only the services whose binary's import graph contains a
  changed file, plus every service that depends on a changed lib.

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
| 3 | Break the domain cycles above and enforce the boundaries (`archtest`, done in 3a); turn the process-global brain configuration into per-service flags | Unchanged |
| 4 | gRPC contracts (sensor snapshot, brain decide stream with capability questions, actuator actuate and journals) and one binary per service, with the in-process wiring kept behind a flag for rollback; `mathlab` replays prove decision parity | Unchanged in in-process mode |
| 5 | One image, chart and Argo CD Application per service; release-please components and affected-service CI; deploy side by side with actuation disabled and compare decisions against the live manager's audit stream; cut over when they match | Shadow, then cutover |
| 6 | Move attack firing and harness runs out of the console into the attacks service | Console calls the attacks API |

Cutover criteria for phase 5 are decided separately. They must include decision
parity on live ticks, and rollback to the current `phorvex-stack` Application.

## Follow-ups

- **Shadow evaluation probed live workloads (fixed after phase 4).**
  `ShadowCapability` is documented as free of externally visible effects, but
  `capability.Witness.EligibleObserved` only swapped the RBAC leg to the cache. It
  still called `SupportsAction`, which for request drain issues the authenticated
  v11 readiness HTTP probe and reads journals, so a calibration-enabled tick probed
  workloads a second time. The witness now records every support answer the
  tick's reviewing passes get from the actuator (the ActionsSupported status asks
  about every enabled action on every allocatable Pod before the brain runs), and
  the shadow answers from those records only. A question nobody asked excludes
  with a `capability-unobserved` detail; calibration's shadow views keep the
  production Pods, so a live tick never meets one.

- **Service transport security.** Phases 4a-2 and 4b-2 connect the manager to the
  brain and the sensor over plaintext gRPC behind `--brain-endpoint` and
  `--sensor-endpoint`, both off by default. Before phase 5 deploys either, add mTLS
  and the NetworkPolicy above. The sensor reads Secrets for its bindings, so its
  RBAC must stay read-only and its endpoint reachable only from the dispatcher.
- **Math Lab snapshots of a remote brain.** With `--brain-endpoint` the brain
  records the snapshots, so the manager's audit source no longer serves them.
  Phase 5 gives the brain its own snapshot source for the console.

- **Sensor packages the dispatcher still imported.** After phase 4b-1 the tick
  observed through `sensorapi`, but the runner still used `ingest` for the
  detector trust configuration, the existential admission-boundary check and the
  completed-disclosure and current-inventory admission. The trust boundary is now
  the shared `eventtrust` package, and each admission lives beside its ledger
  (`losshistory.Admit`, `currentinventory.Admit`). The runner's remaining `ingest`
  use is the in-process sensor's telemetry wiring.

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
