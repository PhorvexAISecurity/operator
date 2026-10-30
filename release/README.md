# Releases

Written by the release workflow (`.github/workflows/release.yml`), not by hand:

- `versions.json`: the versions the open release PR releases, by service;
- `batch.json`: the canonical prepared/partial/complete batch record, including
  its immutable source SHA and every published image digest;
- `<service>.md`: each service's changelog.

See `docs/services/releasing.md`.
