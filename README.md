# Phorvex — operator-refactored

Successor of [PhorvexSecurity/operator](https://github.com/PhorvexSecurity/operator),
being restructured into a monorepo of independently versioned services.

**Status: phase 2 (foundation).** Production is still built and deployed from
`PhorvexSecurity/operator`. Nothing in this repository deploys yet. The target
architecture is [ADR-0001](docs/architecture/ADR-0001-service-monorepo.md).

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

| Phase | Scope | State |
|---|---|---|
| 1 | Remove unreferenced code, archive historical docs, adapt the workflow harness, green CI | Done |
| 2 | Foundation: `libs/logging` (JSON logs), gofmt/vet and image builds in CI | Done |
| 3 | Break the domain cycles and enforce the service boundaries (`archtest`); per-service brain configuration | In progress |
| 4 | gRPC/protobuf contracts and one binary per service in the one module: sensor, brain, dispatcher, actuator, attacks, console | |
| 5 | One image, chart and Argo CD Application per service; release-please tags; side-by-side namespace on the cluster | |
| 6 | Move attack tooling out of the console | |

## Layout

| Path | Contents |
|---|---|
| `phorvex/` | Operator module (manager, console backend, all domains today) |
| `libs/` | Shared Go modules (`phorvex.ai/libs/...`) |
| `build/test-harness/` | Attack harness |
| `build/phoenix-extended/` | Extended Phoenix operator (third party) |
| `build/integrations/` | Workload runtime recipes |
| `dashboard-web/` | Console frontend |
| `deploy/` | Helm charts, Argo CD, monitoring |
| `docs/` | Architecture, runbooks, provenance, archive |
| `workflow/` | Agent workflow framework (archived records frozen) |
