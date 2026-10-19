# Sensor service

The sensor observes the cluster. It owns the inventory projection (`ingest`), the
reachability graph (`graph`), the physics witnesses (`platform`, `physics`), the
EPSS feed (`epssfeed`) and the telemetry source with its cross-tick cache. It
reads the cluster and never writes it. See
[ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The dispatcher reaches it through one contract, `phorvex/internal/sensorapi`,
in one of two ways:

| Mode | Manager flag | Implementation |
|---|---|---|
| In process (default) | none | `sensorsvc.Local` over the manager's readers |
| Remote | `--sensor-endpoint=<host:port>` | `sensorclient.Client` calls `phorvex-sensor` over gRPC; `sensorsvc.Server` serves the same `sensorsvc.Local` |

`internal/sensorclient/parity_test.go` observes one fixture cluster both ways and
requires the same observation, field by field, and the same telemetry.

## Contract

**`Observe(ObserveRequest) → Observation`**, once per tick for every due policy.

- The request carries what only the dispatcher knows: the tick time, the due
  policies' scopes (namespace and label selector), and whether native rotation
  needs rotation-owner and warm-pool evidence. Owner evidence is read only for
  Pods a scope selects.
- The observation is data only:
  - the Pod, Node, Service and namespace inventories and their completeness;
  - the SecurityEvents, the per-Pod events, the outcome evidence and the Phoenix
    receipts;
  - for each Pod a scope selects, its graph context: blast radius, neighbours
    with their generic asset value, its own and its neighbours' events, and the
    infection frontier;
  - the physics witness per Pod, with the platform adapter that derived it and
    any GPU-feed failure;
  - which policies select each Pod.

**`Telemetry(TelemetryRequest) → TelemetryResult`**, once per policy, as before.
The result is best effort: a partial scrape returns what it has, the source's
health verdict and the error. The dispatcher keeps the outage state and the
TelemetryDegraded condition.

## Running

```sh
go -C phorvex run ./cmd/sensor --listen=:9090 --prometheus-url=http://prometheus:9090 \
  --trusted-detectors=vllm/detector-kv-canary
```

The sensor needs a Kubernetes configuration with read access to the inventories
it lists and the evidence it binds (Pods, Services, EndpointSlices, Namespaces,
Nodes, NetworkPolicies, RBAC, PodDisruptionBudgets, ServiceAccounts,
PhorvexPolicies, SecurityEvents, and the ConfigMaps, ReplicaSets, Deployments and
Secrets the bindings read). It never writes. Run one replica: the telemetry
source derives rates from its own previous samples, so reads spread across
replicas would compute them over the wrong interval.

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `:9090` | gRPC address; the gRPC health service is also served |
| `--metrics-bind-address`, `--health-probe-bind-address` | `:8080`, `:8081` | metrics and probes |
| `--trusted-detectors`, `--trusted-loss-observers`, `--trusted-current-inventory-observers`, `--endpoint-lease-approved-*` | as the manager | must match the manager, or the handshake refuses it |
| `--prometheus-url`, `--pcie-class-table`, `--epss-*` | as the manager | telemetry, the GPU witness and the EPSS feed now read here |

`phorvex/cmd/internal/sensorconfig` defines these flags for both binaries.
Manager flags for remote mode: `--sensor-endpoint`, `--sensor-connect-timeout`
(startup waits this long for the handshake, default 2m) and
`--sensor-call-timeout` (30s per observation or telemetry read).

**Handshake.** `Hello` carries the contract version (`sensorapi.ContractVersion`)
and the SHA-256 of `sensorapi.Config`: the trusted detector and observer
identities (compared as sets) and the endpoint lease authority. The dispatcher
reads the same trust when it scopes claims and admits evidence.

**Failure semantics.** An observation the service cannot deliver is an error and
the tick is skipped, as when the snapshot fails in process. A telemetry read it
cannot deliver reads as an unreachable telemetry source: the tick continues
without telemetry, and the TelemetryDegraded condition records the outage.

## What stays with the dispatcher

The dispatcher combines the observation with state only it owns: the exposure
clock and emit intents (`ExposureByVariable`, `IntentByVariable`), failure
cooldowns, rotation feedback, capacity ledgers, the capability witness and the
standing-policy reads. The phase classification (`model.ClassifyPhase`) is a
pure function of a Pod and its telemetry, so it lives in the shared model.

## Testing

```sh
go -C phorvex test -race ./internal/sensorsvc ./internal/sensorclient ./internal/runner
```

`sensorsvc.FromSnapshot` is the pure derivation `Local.Observe` applies to the
collected snapshot. Runner tests feed their snapshot fixtures through it, so
they exercise the same derivation as production.
