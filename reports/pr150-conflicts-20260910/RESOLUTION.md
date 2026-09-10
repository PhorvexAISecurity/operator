# PR150 conflict resolution — 2026-09-10

Scope: merge pinned main into the existing PR branch; no rebase, force push,
PR merge, live deployment or cluster test. This is a bounded conflict-resolution
record, not a product campaign or formal P3 sign-off. Existing evidence is retained.

Parents:

- Local branch first fast-forwarded from `b221b4e74fe23bcb6eeb54561b100f9d94853065`
  to current PR head `e3c9600f5b9caa0813d92cefda278a89c5bea4c6`.
- Main: `0db24b0b61f45d07c4650af99e8e480c5fe4f86d`.

## Semantic resolution

- `runner/manager.go` Upsert keeps PR150's replacement-UID emission-history
  deletion and main's entry assignment, lifecycle enqueue and epoch management.
- Retain main's complete capturedEpoch/ownerEpoch, liveness and lifecycle helpers.
  Remove its obsolete recordEmits helper: PR150 uses emissionHistory rather than
  a timestamp slice, and all callers use emissionWindow. Preserve PR150's accurate
  leader-election comment, source-side emission counting and quiet status expiry.
- Adapt only the obsolete emission-map type in the M140 test factory. Add
  `emission_lifecycle_test.go` to exercise real Upsert same-UID retention, replacement
  reset, stale old-UID rejection, epoch invalidation/drain and independent expiry.
- Regenerate the conflicted `phorvex-0.1.4.tgz` with
  `helm package phorvex/charts/phorvex --destination deploy/helm/phorvex-stack/charts`.
  No archive side was arbitrarily chosen. Combined source retains main's M6 admission
  contract and PR150's lease RBAC and NetworkPolicy list permission.
- Auto-merged audit/model changes preserve main's persistence/error-return integrity
  and add PR150 representation. Main's fresh code-exec gate remains before actuation;
  PR150 notification and partial-mutation evidence remain intact.

The independent lead approved the semantic plan before editing and separately
reviews/tests composition. This implementation record does not self-sign that review.

## Local checks

Go 1.26.1, `GOTOOLCHAIN=local`, `GOPATH=/private/tmp/phorvex-review-go`,
`GOCACHE=/private/tmp/phorvex-review-go-cache`, `GOMAXPROCS=1`,
`KUBECONFIG=/dev/null`, `KUBEBUILDER_ASSETS=`,
`HELM_BIN=/opt/homebrew/bin/helm`. From `phorvex/`:

- `go test -mod=readonly -p 1 -count=1 ./internal/runner ./internal/actuator ./internal/audit ./internal/console ./internal/representation`:
  all packages PASS after actuator's isolated rerun with localhost permission.
  Its first attempt was blocked by sandbox httptest listener binding, not an assertion.
- `go test -mod=readonly -p 1 -count=1 ./internal/codeexec ./internal/controller ./internal/decision ./cmd/...`:
  PASS (utility command packages have no tests).
- `go test -mod=readonly -p 1 -count=1 -v ./internal/runner -run 'TestM011|TestCodeExecPreSubmit|TestM140'`:
  PASS, including the new composition regression and blocked-real-tick lifecycle tests.
- Explicit envtest SKIPs (assets absent): TestM005TwoManagersAndHandoff,
  TestM013RealEventSink, TestM007RestrictedRequests, TestM47APIServerPreconditions,
  TestM038APIServerConditionalDetach.

From repository root, Helm 3.16.4 and Python 3.11 venv:

- `bash tools/check-vendored-chart.sh`: PASS, extracted source equality.
- CRD source/chart `diff -u`: PASS.
- `helm template phorvex deploy/helm/phorvex-stack -n phorvex-system -f deploy/helm/phorvex-stack/values.yaml -f deploy/helm/phorvex-stack/values-eks.yaml --include-crds`: PASS.
- `python tools/test_chart_sync.py`: 8 PASS.
- `python -m unittest discover -s End-to-End/pipeline -p 'test_*.py'`: 44 PASS,
  offline fixtures only; printed preflight aborts are intentional test cases.
- No unmerged index entries. Source delta whitespace check against pinned main PASS.
  Unrestricted cached diff-check against the old branch reports pre-existing
  whitespace/CRLF in imported main historical workflow evidence; those records
  are intentionally preserved, not rewritten to manufacture a clean check.

No live API-server behavior, remote CI, publication, rollout or PR merge is claimed.
