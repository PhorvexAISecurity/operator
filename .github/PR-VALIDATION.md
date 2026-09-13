# Candidate source validation

`pr-validation.yml` runs on every pull-request base, including stacked, draft,
and fork PRs. Checkout uses the event's merge revision, not the deployed image.
There is no paths filter or draft guard on these source checks:

- `charts`: current CRD and vendored subchart equality, Helm render, claim-language
  checks, and tool regressions. The vendored-chart script is shared with release CI.
- `go-unit`: the Phorvex module unit tests (`go -C phorvex test ... ./...`) plus the
  explicitly executed suites of the separate `build/metricvalidity`, `build/test-harness`,
  `build/phoenix-extended`, `build/falco-integrator-extended` and
  `build/prometheus-integrator-extended` modules, on one local Go toolchain (the highest
  module `go` directive). These are unit tests with mocks, fake clients and local
  fixtures; `KUBEBUILDER_ASSETS` is deliberately blank, so the eight API-server tests
  skip here and no existing cluster is used.
- `go-envtest`: local API-server proof. `tools/provision-envtest.sh` downloads the pinned
  envtest v1.34.0 binaries (SHA256-verified, `kube-apiserver --version` checked) and
  `tools/envtest_gate.py` runs exactly the eight `KUBEBUILDER_ASSETS`-guarded tests
  (`internal/actuator`: M47 preconditions, M038 conditional detach, M048 lifecycle and
  restricted role, M007 restricted requests, M032 coverage readback; `internal/runner`:
  M005 two-manager handoff, M013 real event sink) with `go test -json`. Every one must
  run and pass: a skip, failure, missing test, missing terminal event, malformed or
  empty report, or non-zero `go test` exit fails the job even when the output looks
  green. The verbatim JSON stream is uploaded as the `envtest-evidence` artifact. envtest
  is a local kube-apiserver/etcd only — no kubelet, CNI, garbage collector, cloud API or
  AI serving backend — so this job proves API semantics, not deployed behaviour.
- `frontend`: locked npm install, TypeScript checking, and the full static Next build.
- `PR validation`: stable aggregate; failure, cancellation, or a skipped dependency
  is not success. If branch protection is available, require this check name for
  protected PR bases. Repository administrators must configure that policy separately;
  installing the workflow does not change protection settings or bypass plan limits.

All jobs use GitHub-hosted runners and read-only permissions, with no AWS, SSH,
image publication, or deployment credentials. Existing `ci.yml` main/tag release
and live-E2E routing is unchanged. Live E2E checks the deployed release; it is not
a candidate-source validation verdict. This workflow does not replace live tests.
