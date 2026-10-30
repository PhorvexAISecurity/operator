# Releases

Written by the release workflow (`.github/workflows/release.yml`), not by hand:

- `versions.json`: the versions the open release PR releases, by service;
- `batch.json`: the schema-versioned canonical prepared/partial/complete batch
  record, including its immutable source SHA, ordered source-derived component
  build/image/identity/deployment/record contract, pinned Argo render inputs and
  workload image consumers, and every published digest;
- `<service>.md`: each service's changelog.

See `docs/services/releasing.md`.
