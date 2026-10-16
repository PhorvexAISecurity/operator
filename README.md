# Phorvex — operator-refactored

Successor of [PhorvexSecurity/operator](https://github.com/PhorvexSecurity/operator),
being restructured into a monorepo of independently versioned services.

**Status: phase 0 (imported).** Production is still built and deployed from
`PhorvexSecurity/operator`. Nothing in this repository deploys yet.

## Provenance

- Imported from `operator@65af1c99` with `git filter-repo`. Code history is
  intact (3,284 commits); every kept file is byte-identical to the source.
- Stripped from every commit: workflow evidence under `workflow/fixes`,
  `workflow/assessments`, `workflow/campaigns` and `workflow/archive` (except the
  files the workflow framework references), plus `repos/` (upstream snapshots),
  `phorvex/bin/` and `*.exe~` binaries.
- `PhorvexSecurity/operator` remains the complete evidence archive.

## CI

Only GitHub-hosted, secret-free validation runs here. The legacy build, release
and deploy pipeline (`ci.yml`, `publish-*.yml`, self-hosted runner jobs) stays in
`operator`. `tools/test_pr_validation.py` fails if any workflow here uses a
self-hosted runner, a secret, OIDC write access or AWS actions.

## Plan

Each phase lands as its own pull request.

| Phase | Scope |
|---|---|
| 1 | Remove unreferenced code, archive historical docs, adapt the workflow harness, architecture decision record |
| 2 | Monorepo skeleton: `go.work`, `services/`, `libs/`, structured JSON logging, per-service CI |
| 3 | Decouple domains inside one binary: break import cycles, enforce boundaries |
| 4 | gRPC/protobuf contracts and one binary per service: sensor, brain, dispatcher, actuator, attacks, console |
| 5 | One image, chart and Argo CD Application per service; independent release tags; side-by-side namespace on the cluster |
| 6 | Move attack tooling out of the console |
