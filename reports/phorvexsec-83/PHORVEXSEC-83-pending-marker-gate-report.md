# PHORVEXSEC-83 — Pending-marker inventory and production gate

Date: 2026-08-23
Branch: `feat/phorvexsec-83-pending-gate`

## Result

The pending-marker discipline is now executable and build-gated.

- Initial repository sweep: **176** hits.
- Initial non-test Go production hits: **43**.
- Final inventory: **130** historical/design/test hits, all with an owning Plane task.
- Final production hits: **0**.
- Orphans: **0** after creating PHORVEXSEC-152 for the previously unowned console authn/RBAC boundary.

`phorvex/PENDING-INVENTORY.md` is generated deterministically with file path, marker, production classification, exact text, and owner. The committed build fails if:

1. a marker appears in a production-tagged Go/config/chart/hack/Grafana path;
2. any marker lacks a Plane owner; or
3. the source changes without regenerating the inventory.

**Amendment 2026-08-24 — rows no longer carry line numbers.** As originally shipped each row was keyed on `file:line`, which made rule 3 fire on edits that changed no marker at all. PRs #63 and #64 were each green and merged into a red `main`: #64 removed a line above a marker in `internal/actionset/generator_test.go`, shifting it 121 → 120 and staling the inventory while the marker set was byte-identical. Line numbers were dropped from the rendered rows, so an unrelated edit above a marker is no longer a build failure. `Hit.Line` is unchanged and gate failures still name an exact `file:line`; `TestRenderSurvivesLineDrift` and `TestProductionFailureNamesTheLine` hold both halves of that contract.

## CI enforcement

The existing CI does not run `go test ./...`; it builds the operator and console Dockerfiles. The gate is therefore invoked in both existing build paths:

```text
go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md
```

No workflow file was modified. A separate repository test also runs the same full gate whenever Go tests are executed.

## Ownership map

| Owner | Rows | Scope |
|---|---:|---|
| PHORVEXSEC-87 | 83 | real GPU/AI actuator and magnitude validation |
| PHORVEXSEC-23 | 15 | RL red-team pending evidence |
| PHORVEXSEC-151 | 12 | real-cluster/live validation surfaces |
| PHORVEXSEC-115 | 6 | physics/kill-chain constants and calibration |
| PHORVEXSEC-104 | 6 | EPSS wiring/evidence |
| PHORVEXSEC-12 | 4 | dashboard/physics UI |
| PHORVEXSEC-98 | 3 | RLS live-learning validation |
| PHORVEXSEC-152 | 1 | console authn/RBAC tenant boundary |

## Corrections made during the sweep

- Renamed the legitimate no-backend sentinel from `nilSource` to `absentSource`; the old name was a false positive that read like unfinished work.
- Replaced generic production status markers with precise ticketed language or capability-unavailable reasons.
- Removed stale `FactSideChannel`/blanket `AUDIT-ONLY` claims from the physics and vCluster documents. The current distinction is explicit: GPU contention has conditional MIG cover, while GPU co-location remains audit-only.
- Extended the false-bound scan from a hand-maintained document list to every module-level Markdown document.
- Added a regression check forbidding the retired umbrella GPU side-channel fact in shipped documents.

## Orphan created

PHORVEXSEC-152 — **Console tenant scoping trusts request parameter; add real authn/RBAC** — was created in Backlog and assigned to Milad. This is intentionally not implemented inside this marker-sweep PR; it is a separate security-boundary change with cross-tenant negative-test requirements.

## Validation

- `go run ./cmd/pendingcheck -write` → 130 owned markers, zero production markers.
- `go run ./cmd/pendingcheck` → pass.
- Gate unit tests cover production rejection, stale-inventory rejection, orphan exposure, classification, and repository-wide enforcement.
- `go test ./...` → all packages pass.
- `git diff --check` → pass.

## Scope note

Historical point-in-time reports retain their original status labels because rewriting measured history would be misleading. They are allowed only outside production paths and only while their exact row remains inventoried with an owner. Any new or moved row breaks the build until reviewed.
