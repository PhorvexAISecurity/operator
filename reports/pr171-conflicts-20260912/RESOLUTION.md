# PR171 conflict resolution

Resolved by `pr171_conflict_worker` on 2026-09-12 for independent review by
`root`.

## Frozen inputs

- PR171 parent: `f5f75cd9d672240a5a1d7900f28951cfe234ff10`
- Main parent: `528f3341f180e47fb687f3e86f3fabeba8713222`
- Target branch: `parallel/record-m018-phoenix-forensic-fields`

## Resolution

`git merge --no-ff 528f3341f180e47fb687f3e86f3fabeba8713222`
reported one content conflict: the generated `workflow/fixes/INDEX.yaml`.
The index was resolved by retaining both parent keys, `M-18` and `M-21`, and
then rebuilding its projections from the authoritative `STATUS.yaml` records
with:

```text
/private/tmp/phorvex-pr171-venv/bin/python workflow/tools/workflow.py sync-index
```

`sync-index --check` passes. `git diff --exit-code
f5f75cd9d672240a5a1d7900f28951cfe234ff10 -- workflow/fixes/M-18` also passes,
so the complete signed M-18 record and its evidence remain byte-identical to
the PR parent.

The auto-merged product code composes the two changes without changing either
contract:

- `actuator/phoenix.go` keeps M-21's support decision derived from the same
  Phoenix dispatch predicate, while successful SecurityEvent creation still
  returns M-18's API-server-assigned name and UID.
- `runner/manager.go` keeps M-21's validated, once-per-entrypoint backend
  resolution and construction. Its actuation path still clears stale Phoenix
  data before early exits and maps each attempt's AMTD, SecurityEvent and rule
  identifiers to an owned per-decision M-18 payload before success/error
  handling.
- Main's merged E2E capture and stream-stub fixes remain ancestors through the
  PR parent, and M-21 is incorporated through the new main parent.

## Validation

Toolchain: Go 1.26.1 darwin/arm64, Helm 3.16.4, Python 3.12 with the pinned
workflow requirements. Tests used `KUBECONFIG=/dev/null`,
`USE_EXISTING_CLUSTER=false`, `KUBEBUILDER_ASSETS=`, `GOMAXPROCS=2`, and Go
package parallelism `-p 2`.

- Focused M-18/M-21 tests across `internal/actuator`, `internal/runner`,
  `internal/audit`, `internal/console`, `internal/capability`, and `cmd`:
  PASS.
- Full tests for those six relevant packages: PASS. The first restricted
  sandbox attempt could not bind `httptest` localhost sockets; the identical
  command passed with localhost binding available.
- `TMPDIR=/private/tmp PATH=/private/tmp/phorvex-pr171-venv/bin:/opt/homebrew/bin:/usr/bin:/bin KUBECONFIG=/dev/null USE_EXISTING_CLUSTER=false bash workflow/tools/check.sh`:
  PASS, 113 tests, 5 declared skips; doctor reports 0 errors and 17 historical
  warnings.
- `bash tools/check-vendored-chart.sh`: PASS.
- `helm lint phorvex/charts/phorvex --kube-version 1.30.0 --set phorvex.audit.enabled=true,phorvex.audit.volumeGuard.enabled=true`:
  PASS.
- `helm template phorvex deploy/helm/phorvex-stack -n phorvex-system --kube-version 1.36.2 -f deploy/helm/phorvex-stack/values.yaml -f deploy/helm/phorvex-stack/values-eks.yaml --include-crds`:
  PASS.
- Both `git diff --cached --check` and `git diff --check`: PASS; no unmerged
  path remains.

## Limits

No envtest assets were available, so integration cases that require a local
API server retain their declared skip behavior. No live cluster test or write
was performed. The legacy M-18 workflow record does not assign the temporary
`pr171_conflict_worker` identity a participant role, so `brief M-18 --agent
pr171_conflict_worker` rejects that identity; the signed record was preserved
instead of changing historical role metadata for this conflict-only update.
