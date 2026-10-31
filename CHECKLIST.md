# Campaign fixture-image build — Checklist (op-192 blocker #6)

Goal: ship the missing phorvex campaign fixture IMAGE + release/render wiring that
serving-rate (20), serving-kv (3) and datastore (5) need, WITHOUT changing the locked
8-component staging-isolated-release consumer/authority contract. Prepare a reviewed PR;
do NOT merge/deploy.

## Phase 1: Inventory (DONE during assessment)
- [x] Confirm cmd/{ragstore-fixture,cost-admission,cost-load-detector} exist and compile
- [x] Confirm chart contract (attack-catalog-family-fixture.yaml): commands/ports/probes
- [x] Confirm render tool already supports --phorvex-image for datastore/serving-kv/serving-rate
- [x] Confirm 8-component authority contract is locked (staging_release.py / staging-target.json)
- [x] Decide design: separate parallel reproducible build/publish path, consumed by digest only

## Phase 2: The image
- [x] Create deploy/docker/phorvex-fixture.Dockerfile (multi-binary, distroless nonroot, reproducible)
- [x] Test: docker build succeeds; image = non-root 65532, 3 binaries 0555 root:root, pendingcheck gate

## Phase 3: Provenance + verifier + publish wiring
- [x] Create release/staging-phorvex-fixture.json (immutable repo + build/command authority)
- [x] Create tools/verify_phorvex_fixture_image.py (inspect + twice-build reproduce modes)
- [x] Create .github/workflows/staging-phorvex-fixture.yml (dedicated reproducible publish, no PR/batch)
- [x] Wire phorvex-fixture into pr-validation.yml `images` matrix (local build + verify)

## Phase 4: Tests
- [x] tools/test_phorvex_fixture_image.py (Docker/static: Dockerfile + authority invariants)
- [x] tools/test_phorvex_fixture_render.py (Python + chart render: exact digest/commands/probes)
- [x] Go: minimal testable refactor of ragstore-fixture + main_test.go (/healthz + datastore paths)
- [x] Test: new python tests + go tests green (CI-style discovery confirmed)

## Phase 5: Validate + ship
- [x] Chart lint, render, staging_release (locked contract intact), workflow YAML, gofmt checks green
- [x] Reproducibility: binaries byte-identical; app layer deterministic (agentsim idiom); twice-build gate
- [x] Commit (2a728027), push campaign/parallel-fixture-image-20261031, open PR #171 vs main (NOT merged)
- [x] Final report: design, files, tests, commit SHA, PR URL, build/release invocation, residuals

**Complete?** [x]
→ <promise>COMPLETE</promise>

---

## Phase 6: Make the fixture binaries deployable in the serving-rate (p5) tenant
Blocker found after the image shipped: the image was correct but two of its binaries
hardcoded the costbench-opus benchmark tenant, so serving-rate (20 IDs) could not deploy.
- [x] cost-admission: resolve namespace+backend from POD_NAMESPACE/POD_UID/PHORVEX_THROTTLE_BACKEND
      (validated), default cost-target-backend.<ns>.svc:8080 (byte-identical for costbench-opus);
      fail closed on bad namespace / non-http / cross-namespace / non-.svc backend
- [x] ragstore-fixture: tolerate no in-cluster identity so the serving-rate rate-target
      backend (automountServiceAccountToken:false) serves /healthz instead of crash-looping
- [x] Go unit tests: defaults, p5-demo override, default-follows-namespace, cluster.local,
      fail-closed matrix; ragstore degraded-backend readiness
- [x] Chart render test: rate-admission downward POD_NAMESPACE/POD_UID + in-namespace backend
- [x] Scope guard: servingbudget contract/detector/live + ingest/actuator left intact (no
      weakening of detector/actuator proof); full serving-rate DEFENDED (detector port) deferred
- [x] Tests green: go test ./cmd/..., go vet, gofmt gate, fixture render (helm), static image +
      claim-language gate, docker image build + pendingcheck + identity inspect

**Complete?** [x]
→ <promise>COMPLETE</promise>

---

## Phase 7: Reconcile the CI contract so the PR is genuinely green (continuation fix)
Phase 1-6 shipped the image + code but PR #171 was RED: adding `phorvex-fixture` to the
release `images` matrix and landing a third AWS-reaching workflow broke the repo's
source-validation contracts. Fixed WITHOUT loosening any security/proof contract:
- [x] go-unit: `TestComponentsBuildWhatTheirImagesBuild` — the `images` matrix must equal the
      eight release components. Moved the fixture image build+identity-inspect OUT of that
      matrix and INTO the `fixture-images` job (built from candidate source, nothing pushed).
- [x] e2e-contract `test_real_source_checks_are_wired_without_masking_failures` — same matrix
      revert restores the exact six-service matrix.
- [x] e2e-contract `test_no_workflow_reaches_live_infrastructure` — the fixture publish
      workflow legitimately needs OIDC (id-token) to push to ECR. Followed the repo's
      sanctioned pattern: added `staging-phorvex-fixture.yml` to the exempt set AND a dedicated
      `StagingPhorvexFixtureWorkflowTests` class pinning its exact shape (workflow_dispatch-only,
      main-source-gated, permissions == {contents:read,id-token:write}, reproduce-before-push,
      immutable-repo preflight, commit-pinned actions, no batch write / PR / deploy). The
      invariant "every AWS-reaching workflow is individually shape-pinned" is preserved, not
      loosened.
- [x] Verified green locally: `go test ./tools/servicerelease/... ./internal/buildctx/...
      ./cmd/cost-admission/... ./cmd/ragstore-fixture/...`; full `unittest discover -s tools`
      (425 tests OK, e2e-contract parity); gofmt + vet clean; fixture twice-build reproduce.
- [x] Pre-existing/out-of-scope reds documented: `charts` (verify_committed_staging_batch drift
      from pinned 0c369dc2 — RED on main HEAD too) and `go-envtest` (RED on main HEAD) are not
      introduced by this branch and are not within its scope.

**Complete?** [x]
→ <promise>COMPLETE</promise>
