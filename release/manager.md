# manager changelog

## 0.10.1 (2026-10-23)

- fix(attacks): mount grants rendered in the attacks release (2b5412f6)

## 0.10.0 (2026-10-22)

- feat(charts): confine the attacks service's SecurityEvents to its namespaces (329b7cc3)

## 0.9.0 (2026-10-22)

- feat(charts): expose the console on its own and confine its policy edits (9b828da3)

## 0.8.0 (2026-10-22)

- feat(charts): scrape the services and chart them per environment (123dc5c9)
- feat(metrics): count and time the services' gRPC calls (b90984eb)
- feat(trust): trust detectors beside a release that installs the identity guard (fd4f47c8)
- fix(rbac): give the native backend no Phoenix writes (4ed5ccf6)
- feat(charts): deploy the attacks service beside the console (c4a522d1)

## 0.7.0 (2026-10-22)

- refactor(charts): render the console Deployment from the library (bf125858)
- feat(charts): pass the injector identity (fc076791)
- feat(trust): make the injector identity configuration (4d782ff6)
- fix(charts): pin the manager by digest and outlast its service handshakes (4206245a)

## 0.6.0 (2026-10-22)

- feat(charts): pass the policy scope (b973fc03)
- feat(scope): limit a deployment to its policy namespaces (c7e69292)

## 0.5.0 (2026-10-22)

First release, from 503 commits.

