# Versioning the services

Each service is released on its own (ADR-0001): `manager`, `brain`, `sensor`,
`actuator`, `console` and `attacks`, one image each, with tags such as
`brain-v0.1.0`. The attacks image is the `attacks` stage of the console's
Dockerfile (`docker build --target attacks`), so both build the same binaries.
`phorvex/tools/servicerelease` decides what a release contains.

The Console reactive-QA staging-isolated lane is a separate, manually invoked
target with its own immutable repositories and batch. It does not override this
workflow's repositories or deployment transaction. See
`docs/services/staging-isolated-release.md`.

## What belongs to a service

The services share one Go module, so a change to a shared package belongs to every
service whose binary imports it. A service's **inputs** are:

- the source files of every package its image's binaries import, read from the
  import graph for linux/amd64 without cgo (`go list -deps`), including the shared
  libraries such as `libs/logging`, and the `go.mod` and `go.sum` of their modules;
- its Dockerfile and its chart;
- the other paths its image copies in, such as the console's `dashboard-web`.

Test files, documentation and other services' charts are not inputs. The
component table in `phorvex/tools/servicerelease/components.go` names each
service's image, Dockerfile, chart and binaries. A test checks it against the
Dockerfiles and the PR validation images matrix.

## The next version

A commit is part of a service's next release when it touches one of the service's
inputs. Its conventional-commit type sets the bump:

| Commit | Bump |
|---|---|
| `!` after the type, or a `BREAKING CHANGE:` footer | major (minor before 1.0.0) |
| `feat` | minor |
| anything else | patch: it still changed what the image is built from |

A service's first release takes its initial version: 0.5.0 for the manager and
console, which continue the 0.4.x line, and 0.1.0 for the brain, sensor,
actuator and attacks service.

```sh
go -C phorvex run ./tools/servicerelease plan            # every service's next version
go -C phorvex run ./tools/servicerelease plan --json     # with its commits
go -C phorvex run ./tools/servicerelease affected --base origin/main
```

PR validation reports the services each change affects in the go-unit job's
summary.

## The release workflow

`.github/workflows/release.yml` runs on every push to main.

1. **The release PR.** The `release-pr` job brings the PR from `release/next`
   up to date (`servicerelease prepare`, then `pull-request`). The PR holds
   `release/versions.json`, the versions to release, and each service's
   changelog, `release/<service>.md`. Every merged change that affects a
   service updates it.
2. **Merging it publishes.** The `pending` job finds the versions in
   `release/versions.json`, selects the first-parent commit that introduced that
   exact version set, builds `servicerelease` from that commit, and uses that
   source-built helper to commit schema-v2 `release/batch.json` before
   publication. The record contains the source SHA, version set, one ordered
   `expectedComponents` set derived from that source's prepared versions, and an
   immutable contract for every member of exactly that set: canonical service and
   validation-image identities, identity-reporting command, aliases, Dockerfile,
   context, target and complete build arguments, registry/repository/tag, chart
   and exact values-file/key path, the Argo ApplicationSet render route, canonical
   chart and values fingerprints, and every rendered workload image consumer's
   API version, kind, namespace, object name, container section/name, exact image
   field path, release component and expected repository/value source. Batch
   release keys and Git tags are pinned too. Missing, extra, duplicate,
   reordered, aliased or changed contracts are rejected.

   That record is the source-of-truth for push-triggered runs, workflow reruns,
   manual dispatches and the record-commit runs that advance `main`. A helper
   compiled from current `main` has one narrow bootstrap authority: it may read
   only the versioned schema/source pointer and locate the commit that introduced
   `versions.json`. The workflow then checks out that candidate, compiles the
   authoritative helper there, returns to the record branch, and uses only the
   source-built helper for `batch`, `pending`, `batch-source` and `record`.
   The expected set may contain one through six canonical components. Its order,
   membership, versions, contracts, pending work, releases and deployment pins
   must remain exactly equal on every retry; a full set remains six-way atomic,
   while a subset is atomic only across its persisted members and cannot bless
   an untouched service. Component metadata compiled into a later `main` can
   therefore neither alter nor validate an in-flight batch. The sole migration
   exception is an already-terminal legacy version set whose source predates
   `batch.go` (the historical instance is a six-tag release): current main may
   persist it only after every expected tag resolves to that one source and every
   expected existing pin validates. The migration command
   rejects prepared or partial state, so it cannot authorize a build, push,
   record or deployment change.

   Before `release-pr` prepares the next version set, it selects the exact
   upstream publication commit: the `publish` output when publication succeeded,
   or the `pending` output only when publication was legitimately skipped. It
   checks out the latest `main`, creates clean detached worktrees for that
   expected commit and the latest commit, and locates the batch source through
   the narrow bootstrap pointer. The helper compiled at that source validates
   the complete batch, tags, pins, deployment routes and rendered consumers at
   both endpoints, then validates the expected-to-latest state transition. The
   immutable schema, source, versions, ordered expected set and full component
   contract must remain exactly equivalent as structured data; every existing
   release record must remain unchanged. The only accepted difference is
   additive completion of previously pending records. A malformed, missing,
   semantically invalid, rewritten or rolled-back expected state therefore
   cannot be hidden by a descendant that repairs or replaces it. Only after
   both endpoints and the transition pass does the job bind preparation to the
   validated latest SHA. The complete legacy import uses the exact publication
   commit's helper because its historical source predates `batch.go`.

   `servicerelease pending` then validates the batch record, existing component
   tags and staging pins before reporting its unrecorded components. It renders
   every chart in the persisted expected set through the exact Argo value-file
   order at both the pinned source and current record head. A unique probe
   repository/tag/digest must
   change the same exhaustive pinned workload-consumer set, including the
   component's primary Deployment container. Standard Deployments, StatefulSets,
   DaemonSets, ReplicaSets, Jobs, CronJobs and Pods, Helm hooks/tests, every
   container/initContainer/ephemeralContainer, and pod templates in custom
   objects are inspected. Every rendered image slot that is not bound to the
   component's one persisted values source is rejected, including arbitrary
   sidecars and alternate registry/repository strings. Rendered objects without
   a Pod spec are the only intentional exclusion. Chart, helper, subchart, ApplicationSet,
   shared-values or consumer drift fails before a build while a batch is in flight.
   An existing release path that is unused, shadowed, ambiguous, aliased,
   duplicated, absent or the wrong YAML type also fails. Once a batch is complete
   it is a historical record: a later head may change the charts and values that
   the next version set pins anew, but every image consumer rendered through the
   current route must still be bound to the component's values source and select
   exactly the released image, and every recorded pin must still match its release.

   Before any fixture or service image build, push, version-tag creation or Git
   publication, one aggregate read-only ECR preflight covers the entire persisted
   expected set. It proves every exact account/region/repository exists and is
   already `IMMUTABLE`, and snapshots every planned version tag as absent,
   recorded at its persisted digest, or recoverable from an interrupted push
   after exact digest and embedded service/version/source identity verification.
   The snapshot is bound to the complete batch and every component contract;
   each component is re-read against it immediately before push. An absent tag
   that appears concurrently, a repository setting change, target drift or a
   digest change fails safely without overwrite. A matching recoverable tag is
   recorded without another push, closing the push-acknowledged/runner-stopped
   retry window.

   Every release-authoritative repository path is canonicalized below the exact
   worktree root. The root ancestry, batch/version files, ApplicationSet, every
   chart/template and ordered values file, writable target, Dockerfile/context,
   generated candidate and Git staging path reject symlink components and
   hard-linked files. Reads and atomic replacements compare device/inode/path
   identities before and after the authority boundary, so a validation-time
   symlink, rename or parent swap cannot redirect the later read/write. For each
   pending component, the `publish` job:
   - proves both fixture images reproduce the same complete OCI identity across
     two clean no-cache builds;
   - checks out the batch source in detached-HEAD state and refuses a missing,
     malformed, mismatched or dirty source revision;
   - builds the image from that pinned release-PR merge commit and passes the
     same SHA to every service build;
   - runs the built service binary's `-version` endpoint and checks its exact
     release version and Git SHA against the image's OCI labels;
   - re-proves the exact ECR target still equals the aggregate preflight. No
     existing tag is overwritten. A recorded idempotent retry must equal its
     persisted repository/tag/digest; an interrupted unrecorded push may be
     recovered only when two exact reads agree on its digest and its platform,
     service, version and source identity match the immutable batch contract;
   - pushes a new image only to the contract's ECR registry as
     `phorvex/<service>:<version>`, reads that exact repository/tag back from ECR,
     pulls it, and re-verifies that the returned digest owns the expected service
     binary, source SHA and version before any record is written;
   - tags the commit `<service>-v<version>`;
   - pins staging to the pushed digest (`servicerelease record`), in
     `deploy/environments/staging/<service>.yaml`: `manager.yaml` for the
     manager, `console.yaml` for the console. Release mutation changes only the
     exact existing string fields: it never creates a missing key or parent.
     Before either the pin or batch record is written, the candidate chart is
     rendered and every pinned consumer must select the verified
     `repository:tag@digest`; source metadata is also checked where the contract
     has a source key. Every pod therefore pulls its image by that digest.

   One commit to main appends every successful component repository/digest to
   `release/batch.json` and records its staging pin. That commit and all of its
   component tags are pushed atomically, so a tag can never be skipped without
   its matching record. Before commit, Git's index must contain exactly the
   batch file and values files selected by that attempt, with no deletion, extra
   staged file, unstaged change or untracked file. After commit, the workflow
   creates a clean detached worktree from committed `HEAD` and re-runs
   whole-batch and exhaustive consumer verification there. It re-reads every
   recorded ECR repository setting and exact version-tag digest immediately
   before the commit boundary and again immediately before each atomic push. A
   concurrent main advance, ECR identity change or partial Git push fails
   closed. Argo CD syncs the pin commit. A service whose build or
   push fails is absent from both the record and Git tags; a retry skips the
   already-recorded services and builds the remainder from the original batch
   source even after `main` advances. A new version set can replace the batch
   record only after the prior batch is complete and validates against its tags
   and pins.

   A retry fails closed if the schema/source pointer, any immutable component
   field, component order, tag, repository, digest, deployment route/input or
   rendered consumer differs. In particular, a source-A `brain` can never be
   built, recorded or pinned via source-B `sensor` metadata, and a later chart
   cannot rename `.Values.image` while the source helper recreates an obsolete
   `image` mapping. A failed atomic push never fetches or rebases while the
   contents-write credential is present. It fails the run; the queued/fresh run
   checks out the newer main through the normal non-persisted checkout path,
   reconstructs the record (including an exactly matching interrupted ECR push),
   and repeats every source, committed-HEAD and ECR proof before a new push.

   All third-party actions in the three privileged release jobs are pinned to
   reviewed 40-character commits with their human version in an inline comment.
   Checkout never persists credentials. There is no credentialed fetch or
   rebase in any write-token step; remote advancement is retried only by a fresh
   normal checkout.
   The contents-write Git credential is supplied only to the exact push
   subprocess through an ephemeral Git configuration environment; hooks are
   disabled for that subprocess, failure/success traps clear shell material, and
   the workflow proves no credential/header was left in local Git config or any
   remote URL before and after every push and retry.

   Before `batch.json` existed, completed releases were represented only by a
   unanimous set of component tags and pins. `import-terminal-batch` imports
   that legacy state only when every prepared component is tagged at the same
   prepared source, every pin matches and every current workload renders that
   exact immutable image. A missing, partial, mixed or disconnected consumer is
   rejected without writing a batch. This terminal-only bridge has no weaker
   consumer-verification exception.

The workflow is the only one in this repository that writes or reaches AWS.
`ReleaseWorkflowTests` in `tools/test_pr_validation.py` holds it to that shape:
it runs only for main, only the publish job assumes an AWS role, and it does so
inside the `release` environment.

### Setup

Release prerequisites (the workflow validates but never reconfigures them):

- **ECR.** The repositories `phorvex/manager`, `phorvex/brain`,
  `phorvex/sensor`, `phorvex/actuator`, `phorvex/console` and `phorvex/attacks`
  exist in account 753556437180, us-east-2. Every repository in a batch's exact
  persisted expected set **must be configured with immutable tags** before that
  batch can build or push; a full six-component batch therefore requires all six.
  `MUTABLE` and exclusion-based modes fail closed. This repository deliberately
  does not change that live setting. The last reviewed inventory described the
  repositories as mutable,
  so the reviewed infrastructure owner must apply and independently verify the
  immutability prerequisite before release. Scan/encryption policy is separate.
  The production stack's repositories (`phorvex`, `phorvex-console`) are not
  used or modified by this workflow.
- **IAM.** The role `phorvex-refactored-release` trusts GitHub's OIDC provider
  for exactly `repo:PhorvexSecurity@289469515/operator-refactored@1421933320:environment:release`:
  the repository issues immutable subjects, which carry the owner's and the
  repository's IDs, so a renamed or recreated repository cannot match it.
  Its only policy, `phorvex-refactored-release-ecr`, allows `ecr:GetAuthorizationToken`
  and pushing to those six repositories. The production repository's role,
  `github-actions-phorvex`, is unchanged.
- **The repository variable.** `PHORVEX_RELEASE_ROLE_ARN` names that role. The
  publish job refuses to run without it.
- **The `release` environment.** It admits deployments from `main` only. This
  plan cannot require reviewers on it, so merging the release PR is the approval.
- **Pushes to main.** Branch protection is not available on this plan, so
  `github-actions[bot]` can push the staging pins. If protection is added
  later, it must allow that actor.
- **Opening the release PR.** The organization lets GitHub Actions create pull
  requests (enabled 2026-10-22), so the release-pr job opens the PR itself. If
  that is ever refused, the job writes a link to open the PR into its job summary
  instead, and keeps the PR up to date once it is open.
- **CI on the release PR.** GitHub starts no `pull_request` run for a PR the
  workflow's token opened or updated. The release-pr job therefore starts PR
  validation, the E2E harness contracts and the native RBAC contract on
  `release/next` itself (`servicerelease dispatch`), and their checks show on
  the PR.
- **Runners.** Every job runs on a fresh GitHub-hosted runner (`ubuntu-24.04`),
  so nothing of one build is left for the next.
