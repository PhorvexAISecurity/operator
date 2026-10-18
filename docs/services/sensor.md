# Sensor service

The sensor observes the cluster. It owns the inventory projection (`ingest`), the
reachability graph (`graph`), the physics witnesses (`platform`, `physics`), the
EPSS feed (`epssfeed`) and the telemetry source with its cross-tick cache. It
reads the cluster and never writes it. See
[ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The dispatcher reaches it through one contract, `phorvex/internal/sensorapi`.
Phase 4b-1 implements it in process (`sensorsvc.Local`); phase 4b-2 serves the
same adapter over gRPC.

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

## What stays with the dispatcher

The dispatcher combines the observation with state only it owns: the exposure
clock and emit intents (`ExposureByVariable`, `IntentByVariable`), failure
cooldowns, rotation feedback, capacity ledgers, the capability witness and the
standing-policy reads. The phase classification (`model.ClassifyPhase`) is a
pure function of a Pod and its telemetry, so it lives in the shared model.

## Testing

```sh
go -C phorvex test -race ./internal/sensorsvc ./internal/runner
```

`sensorsvc.FromSnapshot` is the pure derivation `Local.Observe` applies to the
collected snapshot. Runner tests feed their snapshot fixtures through it, so
they exercise the same derivation as production.
