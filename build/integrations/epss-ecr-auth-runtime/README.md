# EPSS ECR authentication init helper

This standalone Go module obtains an ECR token using only the approved EPSS web
identity role. It feeds the existing `epssfeed.LoadDockerConfigAuth` contract;
there is no change to the operator loader, scanner environment or dry-run defaults.
Activation is a separate E3 change after E1 apply and merged helper publication.

The helper accepts no arguments. It requires UID/GID 65532 and these exact settings:

| Setting | Required value |
| --- | --- |
| `AWS_ROLE_ARN` | `arn:aws:iam::753556437180:role/phorvex-dev-epss-feed` |
| `AWS_REGION` | `us-east-2` |
| `AWS_WEB_IDENTITY_TOKEN_FILE` | `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` |
| Optional `AWS_DEFAULT_REGION` | `us-east-2` |

`stscreds.NewWebIdentityRoleProvider` is constructed directly with the regional STS
client and a bounded token-file reader. No default configuration/credential chain
is used. Static credentials, shared profiles/files, container credentials and endpoint
overrides are rejected. Metadata is never consulted. HTTP proxy environment settings
are ignored, redirects are refused, retries are bounded and the whole operation has
a two-minute context deadline. A failure emits only a fixed safe message.

The response must contain exactly one canonical endpoint belonging to either
`753556437180.dkr.ecr.us-east-2.amazonaws.com` or
`602401143452.dkr.ecr.us-east-2.amazonaws.com`. The same bounded `AWS:` token is
written for exactly both hosts; repository authority remains E1's policy and each
publisher's repository policy. The whole-second RFC3339 expiry must exceed the
response time by **3600 + 600 seconds**, strictly. ECR need not return two entries.
See [AWS ECR authentication](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html)
and [explicit SDK credentials](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html).

The fresh output directory must be empty. The writer creates a same-directory
private temporary file, writes and fsyncs it, chmods it to `0400`, syncs again,
checks regular-file ownership 65532, closes it, atomically renames it to
`config.json` and fsyncs the directory. No chown or elevated capability is needed.
A directory-sync failure removes the published file before failing. An unsuccessful
init fails the pod; the Job retry gets a new volume. No token is logged, passed in
argv or stored in a Kubernetes credential Secret. The chart supplies a dedicated
`emptyDir` with `medium: Memory`, `sizeLimit: 1Mi`, writable only by this init
container and read-only in the feed. The token projection has audience
`sts.amazonaws.com`; it is mounted explicitly so the helper needs no credential
chain or dependency on webhook-injected environment variables.

## Tests and publication

Local light checks:

```sh
python3 build/integrations/epss-ecr-auth-runtime/verify_recipe.py
python3 -m unittest discover -s build/integrations/epss-ecr-auth-runtime -p test_publication.py -v
python3 tools/test_epss_irsa_chart.py
python3 -m unittest discover -s deploy/eks/epss -p test_verify_dry_run.py -v
bash tools/check-vendored-chart.sh
```

Go/race/loader/image tests run only in approved CI or isolated AWS. The workflow
`.github/workflows/publish-epss-ecr-auth-runtime.yml` runs the standalone module and
existing `phorvex/internal/epssfeed` suite. It compiles a helper **test binary** and
executes the real writer plus unchanged loader under UID/GID 65532. Required
controls cover `0400` success, permitted `0440`, rejected `0600`/`0460`, wrong
filename, foreign hosts, endpoint/expiry/token failures, static-provider poisoning,
missing web identity, safe process errors and existing feed timeout/strict-partial
behavior. Test fixtures are absent from the published binary.

The workflow uses hosted CI and publishes only on manual dispatch from merged
`main`, after its tests pass. No runner host or AWS capacity is changed. Both Docker
base images and all SDK modules are pinned; `go.sum` verifies dependencies and the
builder uses `-mod=readonly`/`GOTOOLCHAIN=local`. The image is linux/amd64,
UID/GID 65532, with only the production helper and distroless CA/runtime files.

Later, after review/merge and green CI, the publication owner runs:

```sh
gh workflow run publish-epss-ecr-auth-runtime.yml --repo PhorvexSecurity/operator --ref main
```

Publication uses the existing `phorvex` ECR repository and existing GitHub role.
The durable tag is `epss-ecr-auth-<full-source-SHA>`, outside the historical
`sha-*` expiration scope. Every publication checks the actual existing lifecycle
policy and refuses any rule that can expire this tag, as well as refusing to overwrite
an existing source tag. It does not create repositories or change lifecycle/IAM.
It verifies the remote digest, checks the published image exits safely without
web identity (read-only, no network/capabilities), and uploads a
source/recipe/digest receipt. E3 must
consume that receipt's verified `imageByDigest`; the contract deliberately has no
published digest and no active values are populated here. An inability to read
lifecycle policy or run hosted CI remains a release blocker.

See [activation, full-inventory evidence and rollback](../../../deploy/eks/epss/README.md).

The heavy race/feed/UID fixture and image publication jobs require the reserved `phorvex-isolated-aws` executor label. Its availability is not verified in stage 1. The deployment owner must provide already approved isolated AWS capacity before these jobs can run; never assign that label to the shared gateway/CI runner. Source-only hosted checks run separately. This source change provisions no capacity or runner. All isolated checks and the publication receipt remain required before activation.
