# Provenance

This repository was imported from `PhorvexSecurity/operator` at
`65af1c99265e29f72d6dba8f8216d5dfbe2fa9bb` with `git filter-repo`. Stripping the
moved-out workflow evidence and repository junk rewrote every commit hash.

`operator-commit-map.tsv` maps each `operator` commit to its rewritten commit
here. Commits that only touched stripped paths are `pruned`.

## Which hash to use

- **Records of what was built or reviewed** (image receipts, `PROVENANCE.json`,
  `releaseSourceSHA` values, workflow evidence) keep the original `operator`
  hash. Images carry it in their `org.opencontainers.image.revision` label, and
  the evidence that backs it lives only in `operator`. Verify those against
  `operator`.
- **Code that resolves a commit in this repository** (for example `git show
  <sha>:<path>` in a test) uses the rewritten hash from the map. Content of every
  path outside the stripped set is byte-identical at both commits.

```sh
awk -F'\t' -v sha=<operator-sha> '$1 == sha {print $2}' docs/provenance/operator-commit-map.tsv
```
