# Candidate source validation

`pr-validation.yml` runs on every pull-request base, including stacked, draft,
and fork PRs. Checkout uses the event's merge revision, not the deployed image.
There is no paths filter or draft guard on these source checks:

- `charts`: current CRD and vendored subchart equality, Helm render, claim-language
  checks, and tool regressions.
- `go-unit`: the Phorvex module unit tests (`go -C phorvex test ... ./...`) plus the
  explicitly executed suites of the separate `build/metricvalidity`, `build/test-harness`
  and `build/phoenix-extended` modules, on one local Go toolchain (the highest
  module `go` directive). These are unit tests with mocks, fake clients and local
  fixtures; `KUBEBUILDER_ASSETS` is deliberately blank, so the eight API-server tests
  skip here and no existing cluster is used.
- `go-envtest`: local API-server proof. `tools/provision-envtest.sh` downloads the pinned
  envtest v1.34.0 binaries (SHA256-verified, `kube-apiserver --version` checked), Helm
  v3.16.4 is installed for the actuator chart tests, the pinned kube-controller-manager
  v1.34.0 (SHA256-verified) supplies the real ReplicaSet and EndpointSlice controllers, and
  `tools/envtest_gate.py` runs the complete suites of the packages in its `PACKAGES` list
  (`api/v1alpha1`, `internal/actuator`, `internal/runner`, `internal/controller`,
  `internal/scopedoutcome`, `internal/platform`, `internal/authz`, `internal/startupauthz`,
  `internal/console`, `cmd`) with `go test -json` and no `-run` filter, so every
  envtest-backed test in those packages executes whatever helper performs its setup. The
  gate's `REQUIRED` list names the controls that must additionally be observed running and
  passing. Every observed test/subtest must run and reach a passing terminal event: a skip
  (including a prerequisite skip), failure, missing required test, missing terminal event,
  package outside the selection, malformed or empty report, or non-zero `go test` exit fails
  the job even when the output looks green. The only exception is the gate's exact
  `ALLOWED_SKIPS` list: four top-level `internal/console` tests that replay private
  originals or a cross-module harness output CI never has, each opted in by a named
  variable (`NATS_RESPONSE_WIRE_OUT`, `PHORVEX_PRIOR_VOICE_ORIGINALS`, `CPU_RUN23_ORIGINALS`,
  `PHORVEX_DRAIN_ARCHIVE_399`). They may terminate with `skip`, never `fail`; any other skip
  still fails, and each entry's verdict (skip, pass or missing) is recorded under
  `allowed_skips` in `summary.json`. The verbatim JSON stream and the full `go test` stderr
  are uploaded as the `envtest-evidence` artifact. envtest is a local kube-apiserver/etcd
  only — no kubelet, CNI, garbage collector, cloud API or AI serving backend — so this job
  proves API semantics, not deployed behaviour.
- `frontend`: locked npm install, TypeScript checking, and the full static Next build.
- `PR validation`: stable aggregate; failure, cancellation, or a skipped dependency
  is not success. If branch protection is available, require this check name for
  protected PR bases. Repository administrators must configure that policy separately;
  installing the workflow does not change protection settings or bypass plan limits.

All jobs use GitHub-hosted runners and read-only permissions, with no AWS, SSH,
image publication, or deployment credentials. The legacy release and live-E2E
pipeline stays in PhorvexSecurity/operator. Live E2E checks the deployed release;
it is not a candidate-source validation verdict. This workflow does not replace live tests.
