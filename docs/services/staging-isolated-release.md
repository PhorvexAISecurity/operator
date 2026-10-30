# Staging-isolated release lane

This lane publishes one reviewed Git SHA to repositories that are reserved for
the Console 192-attack reactive-QA campaign. It is separate from the normal
service release in `.github/workflows/release.yml`; its shared
`phorvex/{manager,brain,sensor,actuator,console,attacks}` targets and publication
defaults are unchanged. The normal workflow gains one compatibility bridge for
an already-complete shared batch whose source predates this lane: the old
source-built helper proves the byte-identical batch at its last record commit,
then the current reviewed helper may apply only the isolated-deployment
supersession rule. Batch drift, partial authority, or invalid records fail closed.

The lane is manual and accepts one input: the complete 40-character commit at
current `main`. The dispatch ref, event SHA, input, clean detached checkout and
remote `refs/heads/main` must all resolve to that exact commit. The check is
repeated before every push and before the proposal is pushed, so a main advance
fails closed and the run is retried from the new reviewed head. There is no repository override input. The only accepted target is
the reviewed `staging-isolated` profile in `release/staging-target.json`. Before
assuming AWS credentials or building anything, `servicerelease
staging-authority` validates the complete normal shared-batch schema, source,
ancestry, contracts, records, consumers and pending set with the source-built
helper. A valid prepared or partial shared batch is recorded as evidence rather
than treated as staging authority. Its bytes, status, releases and six pending
components remain untouched; the normal workflow retains its aggregate
immutable-ECR gate and still cannot publish to a `MUTABLE` shared repository.
Malformed, tampered, unknown-schema or non-ancestor shared state fails closed.

The resulting authority binds the source commit/tree, dispatch ref, Git object
identity of the workflow, Python helper, Go helper tree, target and fixture
configuration; the exact shared batch digest/status/source/pending set and six
shared repositories; and the separate staging batch path, exact eight isolated
repositories and nine-file proposal allowlist. `release/staging-batch.json`
persists that authority with every version, build, fixture and rendered
consumer. It never marks, rewrites, completes, supersedes or records anything in
`release/batch.json`.

## Provisioned ECR inventory

The following repositories were absent before provisioning and were created in
account `753556437180`, region `us-east-2`, on 2026-10-30 between 14:09:33 and
14:10:01 UTC:

| Component | Repository ARN |
|---|---|
| manager | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/manager` |
| brain | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/brain` |
| sensor | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/sensor` |
| actuator | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/actuator` |
| console | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/console` |
| attacks | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/attacks` |
| agent-sim | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/agent-sim` |
| catalogue-workload | `arn:aws:ecr:us-east-2:753556437180:repository/phorvex/staging/catalogue-workload` |

Every repository was created `IMMUTABLE`, with AES-256 encryption and scan on
push. Each has the exact tags `environment=staging`, `project=phorvex`,
`managed-by=PhorvexSecurity/operator-refactored`,
`campaign=console-reactive-qa-192`, and `isolation=staging-only`. No repository
resource policy or account registry policy is present: access is not widened
and remains controlled by the account's identity-based IAM/OIDC permissions.
The registry uses policy scope `V2`, scan type `BASIC`, and native basic scanning.
The release gate proves the exact caller account, both policy absences, effective
registry scan mode, account settings and each repository state again at publication
boundaries.

The lifecycle policy removes untagged build remnants after seven days and keeps
the 30 newest immutable release images. It exists only on the eight repositories
above and cannot select or modify a shared/production repository.

At provisioning handoff all eight repositories contained zero images. The
shared baseline, observed immediately before provisioning, was AES-256,
scan-on-push, `MUTABLE`, with no lifecycle policy:

| Shared repository | Image count |
|---|---:|
| `phorvex/manager` | 37 |
| `phorvex/brain` | 28 |
| `phorvex/sensor` | 28 |
| `phorvex/actuator` | 29 |
| `phorvex/console` | 21 |
| `phorvex/attacks` | 15 |

These shared repositories are read-only evidence for this lane. The workflow has
no source path that names them as a publication target.

## Contract and publication sequence

1. `servicerelease staging-authority` validates and snapshots the shared state
   without changing it. `servicerelease staging-contract` then derives all six service build, embedded
   identity, staging Argo route, values, and rendered workload-consumer contracts
   from the exact source. It fails unless all six services are present.
2. `tools/staging_release.py prepare` joins those six contracts to the two
   reviewed fixture contracts. The resulting batch persists the target digest,
   Git source and tree, exact eight repositories, both immutable tags per image,
   fixture OCI identities, and every deployment consumer.
3. `tools/verify_staging_ecr.py preflight` reads all eight repositories before
   the first build or push. It proves identity, immutability, encryption,
   scanning, ownership tags, repository- and registry-policy absence, registry
   policy/scan scope, lifecycle policy, and existing tag state. Its sealed state
   is rechecked immediately before each publication.
4. Both fixtures are rebuilt twice in independent clean contexts and compared
   byte-for-byte. Their index, manifest, config, and application-layer digests
   must also equal `release/staging-fixture-identities.json`, the reviewed PR #118
   identities.
5. The six services are built from the one SHA with service/version/SHA identity
   embedded and locally verified. Services and fixtures publish only a
   `staging-<version>-git-<full-sha>` tag and
   `staging-git-<full-sha>` alias. These tags cannot equal a normal shared
   release version tag. Interrupted alias
   creation is recoverable only after the existing digest and identity pass the
   same gate. Alias creation preserves either OCI or Docker schema-2 media type,
   rejects ECR batch failures, hashes the returned manifest bytes back to the
   expected digest, and verifies the final exact tag set.
6. Remote repository/tag/digest and embedded identities are reverified. A
   complete `release/staging-batch.json` is then created.
7. The existing release consumer writer pins only the six files under
   `deploy/environments/staging/`; the fixture writer pins the two disabled-by-
   default catalogue image values already present in `phorvex.yaml` and
   `catalogue-family.yaml`. Helm renders prove the service and fixture consumers
   select the exact digests after every Argo values file has been applied in order;
   an added workload image consumer is rejected even when the recorded consumer
   remains correct.
8. The workflow stages only those eight staging values files plus the batch
   record, rejects any changed path outside that allowlist, and reconstructs each
   values file from the source to prove that only the contracted image-pin scalars
   changed. It requires the batch record, commits the changed subset to
   `release/staging-isolated-<sha12>`, and requires GitHub to return the exact open
   PR before dispatching its checks. It also proves `release/batch.json`,
   `release/versions.json` and every shared release record are byte-identical to
   the source.
   It never pushes deployment state to `main`, merges, syncs Argo, or runs an
   attack.

The ApplicationSet is also checked as an exact six-service, one-environment
matrix whose only destination is release `staging` in namespace
`phorvex-staging`. Generator templates, `templatePatch`, extra generators,
source/revision substitutions and unknown application-spec routes are rejected;
both chart and values sources must be this repository at `main`. Any production
destination, values root, shared repository, extra consumer, mutable tag,
missing digest, partial result, or non-allowlisted file makes the lane fail
closed.

The complete batch records the actual Git tree, source authority and the exact
source-derived Go contracts. Normal PR validation reconstructs those contracts
in a detached worktree at the recorded source before accepting a digest-pin PR.
For a prepared/partial shared batch it validates the shared record in that
immutable pre-selection worktree and separately proves the current shared batch
bytes did not change; isolated consumer pins are never mistaken for a shared
batch transition. It also diffs
the proposal against that source, so a production/shared or unrelated change is
rejected even when all staging pins are valid. A complete isolated batch may
supersede only an older shared deployment selection; shared
publication records and tags remain validated on every PR even while their old
deployment pins are superseded, and a later shared release
source switches the same staging consumers back through the normal lane. This
shared → isolated → shared transition is covered by the release-tool tests.

## Reviewed publication and deployment

After this source PR is independently reviewed and merged, dispatch only from
the new exact `main` SHA. That commit must contain this workflow/tooling and all
catalogue/Console changes intended for staging. The current prepared shared
batch does not need to complete and is not changed. If `main` advances after the
dispatch, the run fails before its next publication boundary and must be
retried from the newly reviewed exact head:

```sh
repo=PhorvexSecurity/operator-refactored
merge_sha="$(gh pr view <source-pr> --repo "$repo" --json mergeCommit --jq .mergeCommit.oid)"
git fetch origin main
source_sha="$(git rev-parse origin/main)"
test "$source_sha" = "$merge_sha"
gh workflow run staging-isolated-release.yml \
  --repo "$repo" \
  --ref main -f source="$source_sha"
staging_run="$(gh run list --repo "$repo" --workflow staging-isolated-release.yml \
  --branch main --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$staging_run" --repo "$repo" --exit-status
```

That run publishes the images and opens/updates a separate staging digest-pin
PR. Review its `release/staging-batch.json`, ECR evidence, exact eight staging
values diffs, and required PR checks. Merging that second PR is the separate
deployment authorization because the existing staging ApplicationSet watches
`main`; do not merge it until the staging rollout is authorized. Argo sync and
the 192-attack campaign remain out of scope for the publication workflow.
