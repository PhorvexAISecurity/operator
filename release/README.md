# Releases

Written by the release workflow (`.github/workflows/release.yml`), not by hand:

- `versions.json`: the versions the open release PR releases, by service;
- `batch.json`: the schema-versioned canonical prepared/partial/complete batch
  record, including its immutable source SHA, canonical one-to-six
  `expectedComponents` set, ordered source-derived component
  build/image/identity/deployment/record contract, pinned Argo render inputs and
  exhaustive workload/container image-field consumers, and every published
  digest. Release tooling rejects symlinked/hard-linked authority paths, stages
  only the exact contract-derived file allowlist, verifies committed `HEAD` from
  a clean detached worktree, and requires an exact-set aggregate immutable-ECR
  preflight before any image build or push;
- `<service>.md`: each service's changelog.

See `docs/services/releasing.md`.

The independently invoked Console QA lane is defined by
`staging-target.json`, `staging-fixture-identities.json`, and
`.github/workflows/staging-isolated-release.yml`. It publishes only to
`phorvex/staging/*` and opens a separate digest-pin PR; it never changes the
normal shared release defaults or deploys directly. A committed
`staging-batch.json` is accepted only after PR validation reconstructs its six
service contracts from the exact recorded Git source and verifies both fixture
identities and all rendered staging consumers. Its embedded authority records
the exact main commit/tree and helper/config Git objects, the validated shared
batch digest/status/pending set, the disjoint repository sets and the exact
nine-file staging proposal allowlist. A valid prepared/partial shared batch is
preserved unchanged and is not a blocker for deriving this separate authority;
the normal shared immutable-ECR gate is unchanged. See
`docs/services/staging-isolated-release.md`.
