# console changelog

## 0.13.0 (2026-10-28)

- fix(console): preserve staging tenant isolation (bb35615b)
- feat(console): integrate pinned attack catalogue (c8bbcb7d)

## 0.12.0 (2026-10-28)

- feat(console): add reactive defense switch (3294439c)

## 0.11.0 (2026-10-27)

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
- fix(cost): stop one rotation from self-locking rotate behind the conformal SLO gate (8db1fc25)
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

## 0.10.0 (2026-10-23)

- feat(attacks): add three generic defense loops to the attack catalogue (025fd9c1)

## 0.9.2 (2026-10-23)

- fix(attacks): never target a Pod the native backend quarantined (4f62fae0)

## 0.9.1 (2026-10-23)

- refactor(dispatcher): compose the in-process services in cmd (bfa2e4f1)

## 0.9.0 (2026-10-23)

- feat(console): the console's own chart and Application (fee81475)
- feat(services): mutual TLS between the dispatcher and the services (032d14ec)

## 0.8.4 (2026-10-23)

- fix(dispatcher): check a native backend's routes as native (02cad93e)

## 0.8.3 (2026-10-23)

- fix(test-harness): outlast the JetStream consumer store-removal race (02c0bdd9)

## 0.8.2 (2026-10-22)

- fix(console): scope a tenant-limited grant's scans to its tenant (29bc056c)

## 0.8.1 (2026-10-22)

- fix(attacks): reap only this environment's SecurityEvents (26816294)

## 0.8.0 (2026-10-22)

- feat(metrics): count and time the services' gRPC calls (b90984eb)
- fix(harness): know every stream's admission before the busy reset (8b743e8e)
- feat(trust): trust detectors beside a release that installs the identity guard (fd4f47c8)
- feat(release): build and release the attacks image (072d38d0)
- fix(harness): wait out a pending duplicate when reconciling after a quorum pause (7ed19800)

## 0.7.0 (2026-10-22)

- feat(attacks): serve the attack routes from their own service (b00d464e)
- feat(trust): make the injector identity configuration (4d782ff6)

## 0.6.0 (2026-10-22)

- feat(scope): limit a deployment to its policy namespaces (c7e69292)

## 0.5.2 (2026-10-22)

- test(jetstreamprobe): give the quorum test's fetches room on CI runners (3d7313fd)

## 0.5.1 (2026-10-22)

- fix(cataloguev1): wait out execve before reading a started command line (257a63c9)

## 0.5.0 (2026-10-22)

First release, from 876 commits.

