# Production recovery plan (approval pending)

Prepared by `root` on 2026-09-12.

The repository's existing `force_release` path can recover the exact artifacts
built successfully by run `34707032598`, but dispatching it also writes a release
commit/tag to `main` and triggers the production ArgoCD rollout. That consequential
operation is pending explicit user approval and has not been invoked.

The bounded dispatch is `ci.yml` on `main`, with `force_release=true` and
`release_from=sha-6624065`. Build logs prove both `phorvex` and
`phorvex-console` published that tag from source
`6624065dba0b4ee0ef325360baebb294b643742f`. The workflow must fail before the
GitOps commit if either source is absent, and its existing waiter and post-deploy
E2E remain mandatory. No arbitrary image, manual registry mutation, or direct
cluster write is authorized.
