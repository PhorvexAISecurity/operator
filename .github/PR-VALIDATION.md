# Candidate source validation

`pr-validation.yml` runs on every pull-request base, including stacked, draft,
and fork PRs. Checkout uses the event's merge revision, not the deployed image.
There is no paths filter or draft guard on these source checks:

- `charts`: current CRD and vendored subchart equality, Helm render, claim-language
  checks, and tool regressions. The vendored-chart script is shared with release CI.
- `go-unit`: all Phorvex module unit tests (`go -C phorvex test ... ./...`), using
  the Go version in its go.mod and the local Phoenix replacement module. This
  compiles referenced Phoenix code, but does not run the separate Phoenix test suite.
  Optional API-server tests skip without envtest assets; no existing cluster is used.
- `frontend`: locked npm install, TypeScript checking, and the full static Next build.
- `PR validation`: stable aggregate; failure, cancellation, or a skipped dependency
  is not success. If branch protection is available, require this check name for
  protected PR bases. Repository administrators must configure that policy separately;
  installing the workflow does not change protection settings or bypass plan limits.

All jobs use GitHub-hosted runners and read-only permissions, with no AWS, SSH,
image publication, or deployment credentials. Existing `ci.yml` main/tag release
and live-E2E routing is unchanged. Live E2E checks the deployed release; it is not
a candidate-source validation verdict. This workflow does not replace live tests.
