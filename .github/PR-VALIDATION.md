# Candidate source validation

`pr-validation.yml` runs on every pull-request base, including stacked, draft,
and fork PRs. Checkout uses the event's merge revision, not the deployed image.
There is no paths filter or draft guard on these source checks:

- `charts`: current CRD and vendored subchart equality, Helm render, claim-language
  checks, tool regressions, and the offline recipe and fixture suites listed in the
  workflow. The benchmark wrapper builds the brain-owned endpoint reference with
  the exact Go version in `build/test-harness/go.mod`, then runs every bot, worker
  and stage Python test. All tests must pass with no skips, including both real
  Go integration controls. Python workbook dependencies are pinned in
  `tools/benchmark-test-requirements.txt`. Suites that need tools CI does not install are not run yet:
  `build/integrations/{vllm-0.7.3-drain-v11,vllm-0.7.3-reset-ack,voice-admission,voice-mcp,voice-memory}`,
  `build/test-harness/{fixtures/crm,guardrail}`, `deploy/loadgen` (cloud CLIs or extra
  Python packages) and `deploy/runner/tests` (self-hosted runner host).
- `go-unit`: the unit tests of every Go module, executed explicitly because compiling a
  module as a dependency runs none of its tests: `phorvex`, `build/metricvalidity`,
  `build/test-harness`, `build/phoenix-extended`, `build/integrations/epss-ecr-auth-runtime`
  and `libs/logging`, on one local Go toolchain (the highest module `go` directive). A test
  fails if a tracked `go.mod` outside `workflow/` is missing here or from `lint`. These are unit tests with mocks, fake clients and local
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
- `lint`: `go vet` for every Go module, and gofmt for every Go file changed since the base
  (`tools/check-go-format.py`). Untouched files are not reformatted wholesale because some
  are pinned by content hash.
- `images`: builds the operator and console images from candidate source and discards
  them, so a missing replace target or broken Dockerfile fails the PR instead of the release.
- `PR validation`: stable aggregate; failure, cancellation, or a skipped dependency
  is not success. If branch protection is available, require this check name for
  protected PR bases. Repository administrators must configure that policy separately;
  installing the workflow does not change protection settings or bypass plan limits.

All jobs run on fresh GitHub-hosted runners (`ubuntu-24.04`), which hold no
cluster or AWS credentials, with read-only permissions, and use no secrets, OIDC
tokens, AWS, SSH, image publication, or deployment credentials; the release
workflow (`release.yml`) is the one exception, held to its shape by
`ReleaseWorkflowTests`. Images use per-run tags and are removed after the build.
Python comes from `tools/provision-python.sh`, a pinned, SHA256-verified
python-build-standalone build, which starts in the minimal environments several
tests use; `actions/setup-python` is not used. The legacy release and live-E2E
pipeline stays in PhorvexSecurity/operator. Live E2E checks the deployed release;
it is not a candidate-source validation verdict. This workflow does not replace live tests.
