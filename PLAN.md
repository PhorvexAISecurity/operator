# PR #93: executor authorization without dispatcher workload writes

Written before implementation on 2026-10-24.

## Source and scope

- Branch: `rbac-dispatcher-eviction-selfsar`; initial HEAD: `b63c36932adbba91a77bbd89f2e11e1e51ce9950`.
- Fetched `origin/main`: `e1d1a35e4f1e1056feeedd92ed4c1aab8b20ccc9`.
- Authorized scope: correct this PR, focused local tests, commit/push and update its description. No deployment, benchmark, heavy/e2e suite, or live workload mutation.
- `workflow.py doctor`: 0 errors, 20 historical/synchronization warnings. This is a direct PR correction, not a new M-issue or live campaign.

## Root-cause finding and evidence limit

Confirmed: `RequiredVerbsForBackend(native, rotate)` requires `pods/eviction:create`. A capability review using a dispatcher identity denied that verb would explicitly exclude rotate as `no-rbac`. Giving the dispatcher that verb violates the actuator-only workload-write invariant and must be reverted.

However, the supplied assertion that the **current remote-mode source** uses the dispatcher's self-review is contradicted by the code. Existing commit `0e523729997dd1ac0a96e324575ed4688e44f4ad` (2026-10-19, `feat(capability): review access as the identity that acts`) already corrected this class of bug:

1. `runner.Manager.actuation()` prefers `ActuatorService` over the in-process backend.
2. `runner.Manager.access()` returns that same actuator when `ReviewsAccess()` is true; it never substitutes `Manager.Authz` for a remote actuator.
3. The tick passes this access provider to `capability.BuildWitness` and the gate calls `AccessAllowed` / observation-only `AccessObserved`.
4. `actuatorclient.Client` sends `ReviewAccess` to `actuatorsvc.Server`, which invokes the actuator's `actuatorsvc.Local.Access` checker.
5. `cmd/actuator/main.go` constructs that checker with the actuator process's Kubernetes credentials. `cmd/main.go` only installs a manager checker for in-process actuation.

This wiring also exists in staging's checked-in manager source pin `f34bc429582fc1418b680b9e159942c07aea4438`. Source pins are not proof of the running image/configuration. The reported can-i results demonstrate the intended identity split, but cannot alone prove which identity the running gate reviewed. The reported live NOOP incident therefore remains unresolved pending deployed provenance and its actual exclusion trace. Do not claim that local tests prove live containment or that this PR newly introduces executor-side reviews.

## Exact routing and identity comparison

`deploy/environments/staging/phorvex.yaml` selects `phorvex.actuator: native` and `services.actuator.endpoint: staging-actuator:9090`, with routine authority limited to `phorvex-staging-demo`.

| Action | Staging native route requirements (summary) | Hybrid route | Review identity with remote actuator |
| --- | --- | --- | --- |
| rotate | pods/eviction create | native | actuator SA |
| warm-swap | pods update/patch/delete, Service get, EndpointSlice list | native | actuator SA |
| quarantine | NetworkPolicy create/update/delete, pods update | Phoenix | actuator SA |
| mig-rebind | pods update/delete; node-exec transport separately required | native | actuator SA |

There is no namespace-specific RouteFor exception. Native always routes native. Hybrid deliberately routes rotate native to preserve the current policy's bounded graceful termination; pure Phoenix explicitly refuses rotate because its Delete strategy cannot carry that contract (`actuatorapi.RouteFor`, `actuator.phoenixAccepts`, generated `docs/actuator-repertoire.md`). M-160 still supplies `securityevents:create` for accepted Phoenix routes such as hybrid quarantine. Even that SecurityEvent write belongs to the actuator in the split-service architecture.

## Chosen approach

Reuse the existing executor-side `ReviewAccess` RPC and actuator-local cached SelfSubjectAccessReview. This answers option (b)'s identity question without a new SubjectAccessReview client, arbitrary-subject review grant, impersonation, SA-name configuration, protocol change, or action-specific exception. It is already shared by every workload-write action.

Do not reroute rotate through Phoenix or widen dispatcher RBAC. Do not add redundant production gate machinery to code that already implements the required identity choice. The correction will remove the invalid grant and add a focused regression that exercises the existing runtime wiring across the real actuator gRPC boundary and real candidate selection. If that regression exposes an actual source defect, fix the demonstrated defect before delivery; if a new routing/architecture choice becomes necessary, write concrete options to `DECISION.md` and stop.

## Implementation and validation

1. Restore the eviction catalog rule to `writers: [actuator]` and remove its incorrect dispatcher-self-review comment. Leave every existing invariant test unchanged.
2. Add runner tests for a dispatcher denied workload writes and an independently authorized remote actuator. Drive the real service/client, `Manager.access()`, capability witness/gate and candidate selector; assert rotate is offered and selected with no dispatcher reviews. Include executor-deny and review-error controls, cached repeat/expiry checks, and observation-only behavior where appropriate. Check native workload actions consistently without inventing their prerequisites.
3. Repackage every consumer's `phorvex-common` dependency with Helm 3.16.x, then the umbrella's phorvex dependency. Verify extracted content with `bash tools/check-vendored-chart.sh` and the existing service chart vendor test.
4. Run the focused regression and existing gate/verbs tests. Run from `phorvex/`: `go test ./internal/actuator/... ./internal/authz/... ./internal/capability/... ./internal/runner/...`; include actuator client/service tests for the RPC boundary. No benchmarks or heavy/e2e suites.
5. Run `python -m unittest tools.test_service_charts` (Helm available in PATH) and any additional chart tests touched by the final diff; record exact output. Explicitly show `test_workload_writes_stay_with_the_actuator` passes without modification.
6. Review the diff, verify the configured author `milad <mrashidikhah32@gmail.com>` and absence of attribution trailers, commit/push this branch, and correct PR #93's title/body to explain the actual change and the live-evidence limit.

## Decisions made

- Preserve native staging routing and bounded-grace behavior.
- Keep authorization on the executor through its existing RPC; retain the existing per-(namespace, verb) TTL cache, fail-open-on-error, uncached errors and read-only observation path unchanged.
- Distinguish the demonstrated invalid RBAC grant from the unverified live gate-identity diagnosis. A new dispatcher-side SAR is unnecessary for the architecture present in this clone.
