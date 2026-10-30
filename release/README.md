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
