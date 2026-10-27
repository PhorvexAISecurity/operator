# Self-service benchmark lab

Old Brain versus new Brain, from one command, on a throwaway EKS cluster. Nothing
here edits the Brain, product code, or the dev, staging and prod clusters. Only
files under `benchmark/` belong to the lab.

Status: step 1 (image build). The run, teardown and fixture scripts are next.

## Step 1: build a Brain image from a Git tag

```sh
benchmark/build-image.sh --tag manager-v0.11.0 \
  --commit 8acb43ad7ce088460a457e3055d74c53df5e67a5 \
  --run-id bench-001 --aws-account 753556437180 --out /tmp/bench-001/image.json
```

It prints `<registry>/phorvex-bench/<run-id>/brain@sha256:...` and writes the same
reference, with its source tag and commit, to `--out`. `--dry-run` checks the tag,
commit and names without calling AWS or Docker.

- **Source:** the tag's committed tree via `git archive`, built with that tree's
  own `deploy/docker/service.Dockerfile --build-arg SERVICE=brain`, as
  `release.yml` builds it. The binary links the tag's commit SHA. The repository
  is not checked out, fetched, tagged or edited, and the working tree is not read.
  `manager-v0.11.0` and `brain-v0.5.0` are the same commit.
- **Refusals:** the tag must already exist locally and resolve to exactly
  `--commit`. The AWS credentials must belong to `--aws-account`.
- **Registry:** the image goes to a new repository, `phorvex-bench/<run-id>/brain`.
  It has immutable tags, carries `phorvex-bench-run=<run-id>` for
  `teardown-by-tag.sh`, and has a 3-day image-expiry rule as a safety net. A
  repository of that name without this run's tag is refused. Product repositories
  (`phorvex/*`) are never touched.
- **Credentials:** the registry login goes to a temporary Docker config that is
  deleted on exit. `~/.docker` is unchanged.

Tools: `git`, `jq`, `tar`, `docker` with BuildKit, and AWS CLI v2. The IAM
principal needs `sts:GetCallerIdentity`, `ecr:GetAuthorizationToken`,
`ecr:CreateRepository`, `ecr:TagResource`, `ecr:PutLifecyclePolicy`,
`ecr:DescribeRepositories`, `ecr:ListTagsForResource`, `ecr:DescribeImages` and
the image push actions on `phorvex-bench/*`.

## To confirm on the first real lab run

These depend on real Docker and AWS, which the offline tests stub out:

1. BuildKit accepts the empty `.git/refs/heads/` directory in the archived context
   (`COPY .git/refs/heads/`).
2. The running Brain reports `linkedGitSHA` equal to `--commit`.
3. The jump-host IAM principal has the ECR permissions above.
4. The Resource Groups Tagging API lists the repository by
   `phorvex-bench-run=<run-id>`, which teardown depends on.

## Tests

```sh
python3 -m unittest discover -s benchmark/lab/tests -v
```

The tests are offline: `lab/tests/stubs` replaces `aws` and `docker`. Benchmark
CI runs them through `benchmark/worker/test_lab.py`, so the existing workflow
needs no change. ShellCheck runs when it is installed, as on GitHub runners.
