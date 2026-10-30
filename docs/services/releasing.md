# Versioning the services

Each service is released on its own (ADR-0001): `manager`, `brain`, `sensor`,
`actuator`, `console` and `attacks`, one image each, with tags such as
`brain-v0.1.0`. The attacks image is the `attacks` stage of the console's
Dockerfile (`docker build --target attacks`), so both build the same binaries.
`phorvex/tools/servicerelease` decides what a release contains.

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
   publication. The record contains the source SHA, version set and an ordered,
   immutable contract for every prepared component: canonical service and
   validation-image identities, identity-reporting command, aliases, Dockerfile,
   context, target and complete build arguments, registry/repository/tag, chart
   and exact values-file/key path, batch release key and Git tag. Missing, extra,
   duplicate, reordered, aliased or changed contracts are rejected.

   That record is the source-of-truth for push-triggered runs, workflow reruns,
   manual dispatches and the record-commit runs that advance `main`. A helper
   compiled from current `main` has one narrow bootstrap authority: it may read
   only the versioned schema/source pointer and locate the commit that introduced
   `versions.json`. The workflow then checks out that candidate, compiles the
   authoritative helper there, returns to the record branch, and uses only the
   source-built helper for `batch`, `pending`, `batch-source` and `record`.
   Component metadata compiled into a later `main` can therefore neither alter
   nor validate an in-flight batch. The sole migration exception is the
   historical six-tag release whose source predates `batch.go`: current main may
   persist it only as an already-complete batch after all six tags resolve to
   that one source and all six existing pins validate. The migration command
   rejects prepared or partial state, so it cannot authorize a build, push,
   record or deployment change.

   `servicerelease pending` then validates the batch record, existing component
   tags and staging pins before reporting its unrecorded components. For each
   pending component, the `publish` job:
   - proves both fixture images reproduce the same complete OCI identity across
     two clean no-cache builds;
   - checks out the batch source in detached-HEAD state and refuses a missing,
     malformed, mismatched or dirty source revision;
   - builds the image from that pinned release-PR merge commit and passes the
     same SHA to every service build;
   - runs the built service binary's `-version` endpoint and checks its exact
     release version and Git SHA against the image's OCI labels;
   - pushes it only to the contract's ECR registry as
     `phorvex/<service>:<version>`, reads that exact repository/tag back from
     ECR, pulls it, and re-verifies that the returned digest owns the expected
     service binary, source SHA and version before any record is written;
   - tags the commit `<service>-v<version>`;
   - pins staging to the pushed digest (`servicerelease deploy`), in
     `deploy/environments/staging/<service>.yaml`: `manager.yaml` for the
     manager, `console.yaml` for the console. Every pod pulls its image by that
     digest: the ECR tags are mutable, so a tag alone could change what a
     release runs.

   One commit to main appends every successful component repository/digest to
   `release/batch.json` and records its staging pin. That commit and all of its
   component tags are pushed atomically, so a tag can never be skipped without
   its matching record. Argo CD syncs the pin commit. A service whose build or
   push fails is absent from both the record and Git tags; a retry skips the
   already-recorded services and builds the remainder from the original batch
   source even after `main` advances. A new version set can replace the batch
   record only after the prior batch is complete and validates against its tags
   and pins.

   A retry fails closed if the schema/source pointer, any immutable component
   field, component order, tag, repository, digest or deployment target differs.
   In particular, a source-A `brain` can never be built, recorded or pinned via
   source-B `sensor` metadata.

   Before `batch.json` existed, completed releases were represented only by a
   unanimous set of component tags and pins. `import-terminal-batch` imports
   that legacy state only when every prepared component is tagged at the same
   prepared source and every pin matches; a missing, partial or mixed set is
   rejected without writing a batch.

The workflow is the only one in this repository that writes or reaches AWS.
`ReleaseWorkflowTests` in `tools/test_pr_validation.py` holds it to that shape:
it runs only for main, only the publish job assumes an AWS role, and it does so
inside the `release` environment.

### Setup

In place since 2026-10-22:

- **ECR.** The repositories `phorvex/manager`, `phorvex/brain`,
  `phorvex/sensor`, `phorvex/actuator`, `phorvex/console` and `phorvex/attacks`
  exist in account
  753556437180, us-east-2: mutable tags, scan on push, AES256. The production
  stack's repositories (`phorvex`, `phorvex-console`) are not used.
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
