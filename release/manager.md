# manager changelog

## 0.12.0 (2026-10-27)

- fix(charts): complete agent-action-deny + controller-stop chart wiring; re-vendor (7d0c2226)
- chore(gen): regenerate CRD + cover-map; extend covermap/servicerelease fixtures (a65a3b0e)
- style: gofmt the changed Go files (9bd5c170)
- tests: update enumeration/vocab fixtures for the 7 combined actuators (slo bounds, costaudit, taxonomy views, gate skip, m021 case, python validator, archtest domains, vocab chain) (21e40b78)
- registry-rollback: port partial lane source + reconstruct handler/ExposureVar/vocab (Live33) from k8s-object-revert sibling (a118f768)
- lane p4: NEW namespace-parametric actuator agent-action-deny (EXTEND crm/voice deny) (ff4d653a)
- credential-revoke (lane p3): NEW namespace-parametric actuator (Live26) (30625635)
- network-isolate (lane p3): surgical egress edge-cut actuator (9480b969)
- lane p4: NEW native actuator node-cordon-drain-replace (AML.T0105 Escape to Host) (d6ce72f0)
- datastore-restore (lane p3): NEW namespace-parametric datastore-restore actuator (6ce41049)
- k8s-object-revert: NEW native actuator (lane p1) — restore tampered operator-trusted ConfigMap to its trusted snapshot (AML.T0081) (74a21c3d)
- fix(cost): stop one rotation from self-locking rotate behind the conformal SLO gate (8db1fc25)
- build(operator): bake cost-budget-admin into the operator image (c1e9d5f0)
- feat(ingest): trusted serving-rate-budget binder + scoped detector trust (722d99b7)
- feat(brain): wire throttle into gate/generator/recon/slo/cost/runner (3844a7da)
- feat(actuator): port throttle actuator + cost-admission tooling (428577ff)
- feat(model): throttle + serving-rate-budget vocabulary + servingbudget contract (aade7183)
- feat(audit): surface controller-stop receipt in the decision record (0eeb7f25)
- fix(actuator): force grace=0 on controller-stop child eviction (895feaf6)
- feat(actuator): port controller-stop synchronous owner-removal + wiring (615116dc)
- feat(model): controller-stop vocabulary + persistence authority package (4eb11f3c)
- fix(runner): set OperationID for identity-rotate protected operation (3be1880a)
- feat(actuator): port LIGHT identity-rotate credential invalidation (brain core) (5879529c)

## 0.11.1 (2026-10-23)

- refactor(dispatcher): compose the in-process services in cmd (bfa2e4f1)

## 0.11.0 (2026-10-23)

- feat(console): the console's own chart and Application (fee81475)
- feat(services): mutual TLS between the dispatcher and the services (032d14ec)

## 0.10.2 (2026-10-23)

- fix(dispatcher): check a native backend's routes as native (02cad93e)

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

