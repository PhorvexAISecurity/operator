# console changelog

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

