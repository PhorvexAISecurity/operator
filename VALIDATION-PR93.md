# PR #93 validation — 2026-10-24

## Result and scope

The dispatcher eviction grant and all seven affected vendored archives are restored to their `origin/main` contents. The existing workload-write invariant is unchanged. Native routing and production Go authorization logic are unchanged: commit `0e523729997dd1ac0a96e324575ed4688e44f4ad` already sends authorization questions to the remote executor. See [PLAN.md](PLAN.md) for the routing/identity trace and staging source pin.

The new runner regression uses the real native actuator's capability checks, actuator gRPC server/client, manager access wiring, capability gate and coverage selector. Only the two identities' apiserver review clients are substituted. It proves an authorized executor offers/selects rotate while a denied dispatcher is never consulted, an executor denial excludes as `no-rbac`, and review errors remain unknown/fail-open and uncached. It also checks TTL expiry, observation-only shadows, and executor-side reviews for native WarmSwap, Quarantine and MIGRebind verb sets. The latter checks authorization, without claiming those actions' additional runtime prerequisites are satisfied.

No new architecture decision was required; no `DECISION.md` was created. No live deployment, containment claim, benchmark or heavy/e2e suite is part of this validation. The reported staging NOOP incident still needs deployed image/configuration and actual exclusion-trace verification; can-i results alone do not establish the identity the live gate used.

## Go tests

From `phorvex/` (Go automatically selected module toolchain `go1.26.1`):

```sh
PATH=/tmp:$PATH GOMAXPROCS=2 go test -p 2 \
  ./internal/actuator/... ./internal/authz/... ./internal/capability/... \
  ./internal/runner/... ./internal/actuatorclient/... ./internal/actuatorsvc/...
```

```text
ok  	github.com/phorvex/phorvex/internal/actuator	34.081s
ok  	github.com/phorvex/phorvex/internal/authz	(cached)
ok  	github.com/phorvex/phorvex/internal/capability	(cached)
ok  	github.com/phorvex/phorvex/internal/runner	(cached)
ok  	github.com/phorvex/phorvex/internal/actuatorclient	(cached)
ok  	github.com/phorvex/phorvex/internal/actuatorsvc	(cached)
```

An initial invocation omitted `/tmp` from PATH and failed the two actuator tests that invoke Helm (`TestM007LiteLLMExactOptInGrant`, `TestM007LiteLLMRevokeVerbsMatchExactGrant`). The corrected invocation above passed; the other five packages had already passed and reused their cache.

Focused regression (before the complete suite):

```sh
GOMAXPROCS=2 go test -p 2 ./internal/runner -run '^TestRemoteExecutor' -v -count=1
```

```text
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate/dispatcher-denied-executor-allowed
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate/executor-denied
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate/executor-review-error
--- PASS: TestRemoteExecutorAuthorizationOffersAndSelectsRotate (0.03s)
    --- PASS: TestRemoteExecutorAuthorizationOffersAndSelectsRotate/dispatcher-denied-executor-allowed (0.01s)
    --- PASS: TestRemoteExecutorAuthorizationOffersAndSelectsRotate/executor-denied (0.01s)
    --- PASS: TestRemoteExecutorAuthorizationOffersAndSelectsRotate/executor-review-error (0.01s)
=== RUN   TestRemoteExecutorReviewsEveryWorkloadActionsVerbs
=== RUN   TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/rotate
=== RUN   TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/warm-swap
=== RUN   TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/quarantine
=== RUN   TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/mig-rebind
--- PASS: TestRemoteExecutorReviewsEveryWorkloadActionsVerbs (0.01s)
    --- PASS: TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/rotate (0.00s)
    --- PASS: TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/warm-swap (0.00s)
    --- PASS: TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/quarantine (0.00s)
    --- PASS: TestRemoteExecutorReviewsEveryWorkloadActionsVerbs/mig-rebind (0.00s)
PASS
ok  	github.com/phorvex/phorvex/internal/runner	0.132s
```

## Discriminating wrong-identity control

A temporary Go `-overlay` replaced only `Manager.access()` with `return capability.CheckerAccess(m.Authz)`, recreating the reported dispatcher-self-review path without editing tracked production code. The authorized-executor/denied-dispatcher test then failed as expected:

```text
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate
=== RUN   TestRemoteExecutorAuthorizationOffersAndSelectsRotate/dispatcher-denied-executor-allowed
    capability_remote_access_test.go:123: rotate selected=false, want true: action=noop reason=noop: no candidate won strict gain > 0 (reported gain=0.00 lambdaRuntimeLegacy=0.00) stage=recon pHold=0.60
--- FAIL: TestRemoteExecutorAuthorizationOffersAndSelectsRotate (0.02s)
    --- FAIL: TestRemoteExecutorAuthorizationOffersAndSelectsRotate/dispatcher-denied-executor-allowed (0.02s)
FAIL
FAIL	github.com/phorvex/phorvex/internal/runner	0.117s
FAIL
```

The same test passes on the unchanged production access wiring. This proves the regression detects substitution of the dispatcher identity.

## Chart tests and packaging

Helm: `v3.16.3+gcfd0749` (`/tmp/helm`). From repository root:

```sh
PATH=/tmp:$PATH python3 -m unittest tools.test_service_charts -v
```

```text
test_workload_writes_stay_with_the_actuator (tools.test_service_charts.RBACLibraryTests.test_workload_writes_stay_with_the_actuator) ... ok
test_every_chart_vendors_the_current_library (tools.test_service_charts.VendoredLibraryTests.test_every_chart_vendors_the_current_library) ... ok

----------------------------------------------------------------------
Ran 63 tests in 141.468s

OK
```

Additional focused invariant and catalogue checks:

```sh
PATH=/tmp:$PATH python3 -m unittest \
  tools.test_service_charts.RBACLibraryTests.test_workload_writes_stay_with_the_actuator \
  tools.test_catalogue_stack_chart -v
```

```text
test_workload_writes_stay_with_the_actuator (tools.test_service_charts.RBACLibraryTests.test_workload_writes_stay_with_the_actuator) ... ok
test_default_has_no_roles_or_source_authority (tools.test_catalogue_stack_chart.StackCatalogueChart.test_default_has_no_roles_or_source_authority) ... ok
test_opt_in_roles_only_read_and_exact_pod_exec (tools.test_catalogue_stack_chart.StackCatalogueChart.test_opt_in_roles_only_read_and_exact_pod_exec) ... ok

----------------------------------------------------------------------
Ran 3 tests in 3.873s

OK
```

Before the rollback, the unchanged invariant failed specifically on dispatcher `('pods/eviction', 'create')`; after the rollback it passes legitimately.

Packaged `deploy/charts/phorvex-common` with Helm 3.16.3, copied that package into its six consumers, then packaged `phorvex/charts/phorvex` into the umbrella. Compared every extracted file (Chart metadata as parsed YAML) against `origin/main`; all seven archives were identical in content. Reused `origin/main`'s archive bytes to avoid timestamp/compression noise in the final PR.

```sh
bash tools/check-vendored-chart.sh
```

```text
  Chart.yaml, Chart.lock and dependencies match
```

`git diff --check` passes. No existing test or invariant was edited, skipped, weakened or marked xfail. Full hosted-suite replay was not run under the focused-test scope.
