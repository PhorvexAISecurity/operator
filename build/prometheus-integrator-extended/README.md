<p align="center">
  <img alt="Phoenix", src="docs/img/phoenix-logo.png" width="30%" height="30%"></br>
</p>

# Prometheus-integrator

> Warning: This project is in active development, consider this before deploying it in a production environment.  All APIs, SDKs, and packages are subject to change.

## Documentation

The Prometheus-integrator is an integration backend between [prometheus](https://prometheus.io/) and the [Phoenix AMTD Operator](https://github.com/r6security/phoenix). To check what is an integration backend and how it is connected to other modules please consult with [the concepts page in phoenix operator](https://github.com/r6security/phoenix/blob/main/docs/CONCEPTS.md).

This integration is responsible to provide an entry point for Prometheus and to create Phoenix SecurityEvents. 

For more details about the Phoenix AMTD operator please visit its [repository](https://github.com/r6security/phoenix/).

### Delivery acknowledgement

The webhook validates the whole Alertmanager batch before its first write and replies
`200` only when every alert's SecurityEvent was persisted by the API in that request
or read back as a proven identical retry (per-item outcomes and counts are returned); downstream failures are `503`,
unverified name collisions `409`, and invalid input `400`/`405`/`413` — always with a
JSON body. Event names are deterministic (`prometheus-<40 hex>` of the canonical alert),
so a resent or reordered batch — and a repeat/resolved notification of the same alert,
whose top-level `status`/`endsAt` are excluded from identity — never creates a second
event while distinct alerts in the same pod and second never collide. The per-call API deadline is `SECURITYEVENT_API_TIMEOUT`
(default `10s`; at most two calls per event). The ServiceAccount needs `get` and
`create` on `securityevents`, and the installed SecurityEvent CRD must declare
`spec.anomalyScore`/`metrics`/`evidence` (the synchronized Phoenix chart does) — a
pruning schema is reported as `409 conflict`, never as delivered.
See [docs/DELIVERY.md](docs/DELIVERY.md).

## Caveats

* The project is in an early stage where the current focus is to be able to provide a proof-of-concept implementation that a wider range of potential users can try out. We are welcome all feedbacks and ideas as we continuously improve the project and introduc new features.

## Help

Phoenix development is coordinated in Discord, feel free to [join](https://discord.gg/zMt663CG).

## License

Copyright 2021-2024 by [R6 Security](https://www.r6security.com), Inc. Some rights reserved.

Server Side Public License - see [LICENSE](/LICENSE) for full text.