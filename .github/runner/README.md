# Shared runner workflow bookkeeping

Every shared-runner job refreshes registered prior runs before other steps through
the root-installed `/usr/local/libexec/phvx-disk-hygiene`, including
CI path detection and chart checks when no image builds run. Only that refresh step
receives the automatic `github.token` through `GH_TOKEN`; `actions: read` augments
the workflow's existing permissions. Normal CI, publication, deploy and E2E refresh
steps use `continue-on-error: true`: API, lock, retention or helper errors are
reported while later job steps can proceed. The manual `runner-disk-cleanup.yml`
refresh remains required and explicitly fails if the helper is absent.

Every shared-runner Buildx setup has `id: buildx`. Its immediately following required
registration step passes `steps.buildx.outputs.name` through `BUILDER_NAME`, together
with `GITHUB_REPOSITORY`, `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`. A registration
failure prevents expensive build/publication steps and leaves normal action post
cleanup available. Phoenix registration follows the existing setup condition.
Isolated AWS jobs do not use this host helper.

A refresh can establish terminal metadata for prior cancelled/failed/successful runs;
it cannot establish completion of the current workflow while that workflow runs.
The next shared-runner job refreshes again. The timer consumes persisted verified
completion records without holding an API token. If no later job runs, an unrefreshed
lease stays excluded until another authorized metadata refresh; deletion never infers
completion from age or a cancelled shell step.

The manual cleanup workflow refreshes, reports inventory, requests reclaim, and
reports pending work. It never deletes its workspace or runs Docker prunes. The
installed timer owns exact-object deletion behind its idle/provenance/race checks.
Before publishing this patch, the coordinator must verify live completed-run reclaim.
An absent helper, report-only timer or unverified orphan removal blocks rollout.

Hygiene rollback after merging these workflows requires reverting the workflow
bookkeeping and manual cleanup replacement first, or retaining the compatible
helper until that revert is effective for every queued/in-progress run. Normal
refresh errors are tolerated, but all nine builder registrations and manual
cleanup remain required. Removing the helper first prevents new builds from
reaching publication and makes manual cleanup fail. Coordinate that source revert
before invoking the host hygiene rollback that removes the helper.

CI's parent concurrency group includes event/ref/run ID for every event and uses
`cancel-in-progress: false`. A newer PR commit cannot cancel the parent of a running
shared live E2E job through concurrency. Same-PR cancellation is confined to CI jobs
`changes`, `build-operator`, `build-console` and `build-phoenix`, with a distinct
`operator-ci-<job>` prefix. Those jobs use unique event/ref/run ID keys and false
cancellation for main/tag pushes and dispatches, preserving image publication.
Chart-sync has no job concurrency block; E2E, E2E-main and deploy (which performs
release publication) retain their serialized non-cancelling groups. Other safe PR workflows retain
same-PR parent cancellation and unique non-PR keys.

Protected publish/deploy/E2E groups retain false cancellation and `queue: max`.
GitHub documents a 100-entry pending limit; overflow arrivals may be cancelled.
Manual cancellation, timeout and resource failure remain possible. This policy
change does not establish remote attack cleanup on cancellation.
See [GitHub concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

`runner-hardening-verification.yml` runs on `pull_request` changes only to
`.github/workflows/**` or `.github/runner/**`, including draft PRs. Its distinct
parent prefix cancels only older runs for the same PR. Permissions are exactly
`contents: read` and `actions: read`; the automatic token reaches only the first,
best-effort completion refresh. Checkout disables credential persistence. Default
`docker/setup-buildx-action@v3` creates a docker-container builder, followed
immediately by required registration for this repository/run/attempt and its
`outputs.name`. Cleanup is true and keep-state false. No driver/image override or
intentional BuildKit daemon image upgrade is configured.

The job creates only a Dockerfile in a fresh fixture directory under `RUNNER_TEMP`:
`FROM alpine:3.21` and `RUN echo verification && sleep 12`. Buildx receives that
filesystem directory as its only context. `--no-cache` makes RUN execute each time;
no exporter, image tag, push, load or external cache is selected. The default
container driver retains the result only in its build cache, which setup's post
cleanup removes with the per-job builder. The job body never deletes the fixture
or `RUNNER_TEMP`. There is no main/push/dispatch trigger, secret input, deployment,
publication, E2E, Telegram, SSH or artificial GitHub completion provenance.
See [Buildx action v3 inputs](https://github.com/docker/setup-buildx-action/blob/v3/action.yml)
and [Docker exporter defaults](https://docs.docker.com/build/exporters/#cache-only-export).

Before merge, the coordinator must capture the real PR run/attempt, successful
registration and exact builder identities, plus the builder container's
`HostConfig.CgroupParent` and host PID cgroup under `phvxci.slice`. During the
12-second RUN, capture its executing child and cgroup ancestry. Afterward capture
the setup action's post cleanup, successful installed `.sh` completion hook and
unchanged successful job conclusion. The next genuine job/authorized refresh may
establish terminal API evidence; this job cannot attest its own completion. This
fixture establishes registration, execution topology and hook behavior; it is not
heavy-build capacity evidence. The review's live reclaim, complete runner process
tree and no-new-failure-against-main conditions also remain merge gates.

Run the review checks against the exact fetched baseline (requires PyYAML):

```sh
RUNNER_WORKFLOW_BASELINE=26bf823cf2c68171472a85a3d1a15a714ba7befc \
  python3 -B .github/runner/test_workflow_policy.py
```

The baseline pin is deliberate; change it after reviewing new main workflows.
Without the environment override, checks compare with local `origin/main`.
Checks cover all workflow YAML, allowed-delta equivalence, the CI parent exception,
the four safe-job PR/non-PR key matrices, exact job concurrency scope, protected
queues, isolated jobs, existing permissions/conditions, exact shell
arguments and token scope. Shell checks distinguish best-effort normal refresh
from required manual refresh, and prove required registration errors prevent a
disposable later build/publication marker. The local continuation harness applies
the literal YAML `continue-on-error` flag at each step boundary.
The existing 14 policy tests remain, with two additional checks for the narrow
verification workflow and its actual fixture/build shell. Those shell checks use
a disposable Docker executable, validate exact argv and error propagation, reject
an unexpected context and preserve sibling temporary data. They never call real
Docker, GitHub or the installed helper.
They do not prove GitHub acceptance, cancelled remote E2E cleanup, installed-helper
reclamation, self-hosted CI, isolated AWS checks or release/deploy behavior.
