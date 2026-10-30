# actuator changelog

## 0.11.0 (2026-10-30)

- feat(actuator): stateful rotation metrics, dashboard and staging NATS demo (22f0e192)
- fix(release): enforce reproducible images and source identity (748ed22a)

## 0.10.0 (2026-10-29)

- fix(packaging): close catalogue staging release gates (56c5e6d4)
- feat(actuator): contract-bounded stateful rotation family (70d1bfb9)
- feat(console): enable immutable agent-action catalogue cases (146578d4)

## 0.9.0 (2026-10-29)

- feat(console): retain Prometheus evidence per catalogue run (73f99da7)

## 0.8.0 (2026-10-28)

- fix(console): preserve staging tenant isolation (bb35615b)
- feat(console): integrate pinned attack catalogue (c8bbcb7d)

## 0.7.0 (2026-10-27)

- fix(charts): complete agent-action-deny + controller-stop chart wiring; re-vendor (7d0c2226)
- style: gofmt the changed Go files (9bd5c170)
- tests: update enumeration/vocab fixtures for the 7 combined actuators (slo bounds, costaudit, taxonomy views, gate skip, m021 case, python validator, archtest domains, vocab chain) (21e40b78)
- registry-rollback: port partial lane source + reconstruct handler/ExposureVar/vocab (Live33) from k8s-object-revert sibling (a118f768)
- lane p4: NEW namespace-parametric actuator agent-action-deny (EXTEND crm/voice deny) (ff4d653a)
- credential-revoke (lane p3): NEW namespace-parametric actuator (Live26) (30625635)
- network-isolate (lane p3): surgical egress edge-cut actuator (9480b969)
- lane p4: NEW native actuator node-cordon-drain-replace (AML.T0105 Escape to Host) (d6ce72f0)
- datastore-restore (lane p3): NEW namespace-parametric datastore-restore actuator (6ce41049)
- k8s-object-revert: NEW native actuator (lane p1) — restore tampered operator-trusted ConfigMap to its trusted snapshot (AML.T0081) (74a21c3d)
- feat(ingest): trusted serving-rate-budget binder + scoped detector trust (722d99b7)
- feat(brain): wire throttle into gate/generator/recon/slo/cost/runner (3844a7da)
- feat(actuator): port throttle actuator + cost-admission tooling (428577ff)
- feat(model): throttle + serving-rate-budget vocabulary + servingbudget contract (aade7183)
- feat(audit): surface controller-stop receipt in the decision record (0eeb7f25)
- fix(actuator): force grace=0 on controller-stop child eviction (895feaf6)
- feat(actuator): port controller-stop synchronous owner-removal + wiring (615116dc)
- feat(model): controller-stop vocabulary + persistence authority package (4eb11f3c)
- deploy(staging): enable identity-rotate for the console-identity-shared fixture (5dc3a99d)
- fix(runner): set OperationID for identity-rotate protected operation (3be1880a)
- feat(actuator): port LIGHT identity-rotate credential invalidation (brain core) (5879529c)

## 0.6.1 (2026-10-23)

- refactor(dispatcher): compose the in-process services in cmd (bfa2e4f1)

## 0.6.0 (2026-10-23)

- feat(console): the console's own chart and Application (fee81475)
- feat(services): mutual TLS between the dispatcher and the services (032d14ec)

## 0.5.2 (2026-10-23)

- fix(dispatcher): check a native backend's routes as native (02cad93e)

## 0.5.1 (2026-10-23)

- fix(attacks): mount grants rendered in the attacks release (2b5412f6)

## 0.5.0 (2026-10-22)

- feat(charts): confine the attacks service's SecurityEvents to its namespaces (329b7cc3)

## 0.4.0 (2026-10-22)

- feat(charts): scrape the services and chart them per environment (123dc5c9)
- feat(metrics): count and time the services' gRPC calls (b90984eb)
- feat(trust): trust detectors beside a release that installs the identity guard (fd4f47c8)
- fix(rbac): give the native backend no Phoenix writes (4ed5ccf6)
- feat(charts): deploy the attacks service beside the console (c4a522d1)

## 0.3.0 (2026-10-22)

- refactor(charts): render the console Deployment from the library (bf125858)
- feat(charts): pass the injector identity (fc076791)
- feat(trust): make the injector identity configuration (4d782ff6)

## 0.2.0 (2026-10-22)

- feat(charts): pass the policy scope (b973fc03)
- feat(scope): limit a deployment to its policy namespaces (c7e69292)

## 0.1.0 (2026-10-22)

First release, from 309 commits.

