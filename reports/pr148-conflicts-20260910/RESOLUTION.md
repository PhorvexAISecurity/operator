# PR148 conflict resolution — 2026-09-10

Scope: merge pinned main into the existing PR branch; no rebase, force push,
PR merge, live deployment or cluster test. This is a bounded conflict-resolution
record, not a product campaign or formal P3 sign-off. Existing evidence is retained.

Parents:

- PR head: `1d2e8ff8bf0a8cd729edfe9f0bffaab81b7addc1`.
- Main: `0db24b0b61f45d07c4650af99e8e480c5fe4f86d`.

The sole conflict was `phorvex/internal/runner/manager.go`. Keep main's full
M6 pre-submit admission re-verification and unwired-verifier fail-closed gate;
after it, keep PR148's raw non-P0 CoverageValue pointer and score=-1 sentinel,
with ThreatRisk/clamping only for p0-greedy. Main's audit persistence and
owner-lifecycle changes remain intact. The independent lead inspected and approved
this semantic plan before editing, and separately tests the composition.

## Local checks

Go 1.26.1, `GOTOOLCHAIN=local`, `GOPATH=/private/tmp/phorvex-review-go`,
`GOCACHE=/private/tmp/phorvex-review-go-cache`, `GOMAXPROCS=1`,
`KUBECONFIG=/dev/null`, `KUBEBUILDER_ASSETS=`,
`HELM_BIN=/opt/homebrew/bin/helm`. From `phorvex/`:

- `go test -mod=readonly -p 1 -count=1 ./internal/runner ./internal/actuator ./internal/audit`:
  runner and audit PASS; actuator initially blocked by sandbox localhost bind in
  httptest, then its isolated package rerun with localhost permission PASS.
- `go test -mod=readonly -p 1 -count=1 ./internal/codeexec ./cmd/...`: PASS
  (utility command packages have no tests).
- `go test -mod=readonly -p 1 -count=1 -v ./internal/runner -run 'TestM032|TestCodeExecPreSubmit'`:
  both raw coverage and fail-closed admission controls PASS.
- `TestM47APIServerPreconditions` explicitly SKIP: isolated envtest assets absent.

From repository root, Helm 3.16.4 and Python 3.11 venv:

- `bash tools/check-vendored-chart.sh`: PASS, extracted source equality.
- CRD source/chart `diff -u`: PASS.
- `helm template phorvex deploy/helm/phorvex-stack -n phorvex-system -f deploy/helm/phorvex-stack/values.yaml -f deploy/helm/phorvex-stack/values-eks.yaml --include-crds`: PASS.
- `python tools/test_chart_sync.py`: 8 PASS.
- No unmerged index entries; conflict-source diff whitespace check PASS.

One preliminary chart check ran from `phorvex/` instead of the repository root
and failed path lookup; the correctly rooted check above passed. Imported main
historical records retain their existing formatting; they were not reformatted.
No live API-server behavior, remote CI, publication, rollout or PR merge is claimed.
