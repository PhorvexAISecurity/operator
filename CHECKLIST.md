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
- [ ] Commit, push campaign/parallel-fixture-image-20261031, open PR vs main (no merge)
- [ ] Final report: design, files, tests, commit SHA, PR URL, build/release invocation, residuals

**Complete?** [ ]
