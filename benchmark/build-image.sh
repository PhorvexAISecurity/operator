#!/usr/bin/env bash
# Builds the Brain image of one Git tag, unchanged, into a per-run ECR repository
# and prints its digest-pinned reference.
#
#   benchmark/build-image.sh --tag manager-v0.11.0 --commit <40-hex sha> \
#     --run-id bench-001 --aws-account 753556437180 [--region us-east-2] \
#     [--platform linux/amd64] [--out RUN_DIR/image.json] [--repo PATH] [--dry-run]
#
# The source is the tag's own tree (git archive), built with the tag's own
# Dockerfile and the build arguments release.yml uses. Nothing in the repository
# is edited, checked out, fetched or tagged. The tag must resolve to exactly
# --commit, so a moved tag is refused rather than silently built.
#
# The image goes to ECR repository phorvex-bench/<run-id>/brain, created here and
# tagged phorvex-bench-run=<run-id> for teardown-by-tag.sh. A repository with that
# name but without this run's tag is refused, never reused. Product repositories
# (phorvex/*) are never touched. Registry credentials live in a temporary Docker
# config that is deleted on exit; ~/.docker is not modified.
set -Eeuo pipefail

BENCH_SCRIPT=build-image
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lab/lib/common.sh
source "$here/lab/lib/common.sh"

usage="build-image.sh --tag TAG --commit SHA --run-id ID --aws-account ACCOUNT [--region REGION] [--platform PLATFORM] [--out FILE] [--repo PATH] [--dry-run]"

tag= commit= run_id= account= region=us-east-2 platform=linux/amd64 out= repo= dry_run=0
while (($#)); do
  case $1 in
    --tag|--commit|--run-id|--aws-account|--region|--platform|--out|--repo)
      (($# >= 2)) || bench_usage_die "$1 needs a value; $usage"
      case $1 in
        --tag) tag=$2 ;; --commit) commit=$2 ;; --run-id) run_id=$2 ;;
        --aws-account) account=$2 ;; --region) region=$2 ;; --platform) platform=$2 ;;
        --out) out=$2 ;; --repo) repo=$2 ;;
      esac
      shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) printf '%s\n' "$usage"; exit 0 ;;
    *) bench_usage_die "unknown argument '$1'; $usage" ;;
  esac
done

[[ -n $tag && -n $commit && -n $run_id && -n $account ]] || bench_usage_die "$usage"
bench_valid_commit "$commit" || bench_usage_die "--commit must be a full 40-character lowercase SHA"
bench_valid_run_id "$run_id" || bench_usage_die "--run-id must be lowercase letters, digits and single dashes, at most 40 characters"
bench_valid_account "$account" || bench_usage_die "--aws-account must be 12 digits"
bench_valid_region "$region" || bench_usage_die "--region '$region' is not an AWS region name"
[[ $platform =~ ^linux/(amd64|arm64)$ ]] || bench_usage_die "--platform must be linux/amd64 or linux/arm64"
[[ $tag != -* ]] && git check-ref-format "refs/tags/$tag" || bench_usage_die "--tag '$tag' is not a valid tag name"
[[ -z $out || -d $(dirname -- "$out") ]] || bench_usage_die "--out directory $(dirname -- "$out") does not exist"

bench_require_tools git jq tar
repo=${repo:-$(git -C "$here" rev-parse --show-toplevel)}

# The component table mirrors phorvex/tools/servicerelease/components.go.
component=brain
dockerfile=deploy/docker/service.Dockerfile
build_args=(--build-arg SERVICE=brain)

resolved=$(git -C "$repo" rev-parse --verify --quiet "refs/tags/$tag^{commit}") \
  || bench_die "tag '$tag' is not in $repo (fetch it first; this script never fetches)"
[[ $resolved == "$commit" ]] || bench_die "tag '$tag' points to $resolved, not --commit $commit"
git -C "$repo" cat-file -e "$commit:$dockerfile" 2>/dev/null \
  || bench_die "$dockerfile does not exist at $tag; this tag has no separately built $component image"

registry="$account.dkr.ecr.$region.amazonaws.com"
ecr_repo="$BENCH_ECR_PREFIX/$run_id/$component"
image_tag="${tag//\//-}-${commit:0:12}"
image="$registry/$ecr_repo:$image_tag"
[[ $ecr_repo == "$BENCH_ECR_PREFIX/"* ]] || bench_die "internal: refusing ECR repository outside $BENCH_ECR_PREFIX/"

bench_log "source:     $tag = $commit"
bench_log "component:  $component ($dockerfile ${build_args[*]}, $platform)"
bench_log "repository: $registry/$ecr_repo"
if ((dry_run)); then
  bench_log "dry run: no AWS or Docker calls were made"
  printf '%s\n' "$image"
  exit 0
fi

bench_require_tools aws docker
export AWS_PAGER=''
bench_assert_aws_account "$account" "$region"

work=$(mktemp -d "${TMPDIR:-/tmp}/phorvex-bench-image.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Reuse the repository only if this run created it.
ensure_repository() {
  local err=$work/describe.err arn tags
  if arn=$(aws ecr describe-repositories --region "$region" --repository-names "$ecr_repo" \
      --query 'repositories[0].repositoryArn' --output text 2>"$err"); then
    tags=$(aws ecr list-tags-for-resource --region "$region" --resource-arn "$arn" --output json)
    jq -e --arg k "$BENCH_RUN_TAG_KEY" --arg v "$run_id" 'any(.tags[]; .Key == $k and .Value == $v)' \
      <<<"$tags" >/dev/null \
      || bench_die "ECR repository $ecr_repo exists without tag $BENCH_RUN_TAG_KEY=$run_id; refusing to reuse it"
    bench_log "reusing this run's ECR repository $ecr_repo"
    return
  fi
  grep -q RepositoryNotFoundException "$err" || { cat "$err" >&2; bench_die "could not look up ECR repository $ecr_repo"; }
  aws ecr create-repository --region "$region" --repository-name "$ecr_repo" \
    --image-tag-mutability IMMUTABLE \
    --tags "Key=$BENCH_RUN_TAG_KEY,Value=$run_id" "Key=$BENCH_MARK_TAG_KEY,Value=true" \
    --output json >/dev/null
  # A safety net only: if teardown never runs, images still expire.
  aws ecr put-lifecycle-policy --region "$region" --repository-name "$ecr_repo" \
    --lifecycle-policy-text '{"rules":[{"rulePriority":1,"description":"phorvex-bench safety net","selection":{"tagStatus":"any","countType":"sinceImagePushed","countUnit":"days","countNumber":3},"action":{"type":"expire"}}]}' \
    --output json >/dev/null
  bench_log "created ECR repository $ecr_repo"
}
ensure_repository

# The tag's tree plus the one Git file the Dockerfile reads, so the binary
# links the exact source SHA as a release build does.
ctx=$work/context
mkdir -p "$ctx/.git/refs/heads"
git -C "$repo" archive --format=tar "$commit" | tar -x -C "$ctx"
printf '%s\n' "$commit" >"$ctx/.git/HEAD"

export DOCKER_CONFIG=$work/docker-config
mkdir -p "$DOCKER_CONFIG"
[[ -d $HOME/.docker/cli-plugins ]] && ln -s "$HOME/.docker/cli-plugins" "$DOCKER_CONFIG/cli-plugins"
aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry" >/dev/null

bench_log "building $image"
DOCKER_BUILDKIT=1 docker build --platform "$platform" --file "$ctx/$dockerfile" "${build_args[@]}" \
  --label "org.opencontainers.image.revision=$commit" \
  --label "org.opencontainers.image.version=$tag" \
  --label "$BENCH_RUN_TAG_KEY=$run_id" \
  --tag "$image" "$ctx" </dev/null >&2
docker push "$image" </dev/null >&2
docker image rm "$image" >/dev/null 2>&1 || true

# The registry, not the local daemon, is the authority for the pushed digest.
digest=$(aws ecr describe-images --region "$region" --repository-name "$ecr_repo" \
  --image-ids "imageTag=$image_tag" --query 'imageDetails[0].imageDigest' --output text)
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || bench_die "ECR returned no valid digest for $image (got '$digest')"
pinned="$registry/$ecr_repo@$digest"

record=$(jq -n \
  --arg runId "$run_id" --arg component "$component" --arg sourceTag "$tag" --arg sourceCommit "$commit" \
  --arg repository "$registry/$ecr_repo" --arg imageTag "$image_tag" --arg digest "$digest" \
  --arg image "$pinned" --arg platform "$platform" --arg region "$region" --arg awsAccount "$account" \
  --arg builtAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schema: "phorvex-bench/image/v1", runId: $runId, component: $component, sourceTag: $sourceTag,
    sourceCommit: $sourceCommit, repository: $repository, imageTag: $imageTag, digest: $digest,
    image: $image, platform: $platform, region: $region, awsAccount: $awsAccount, builtAt: $builtAt}')
[[ -n $out ]] && bench_write_atomic "$out" <<<"$record"
bench_log "pushed $pinned"
printf '%s\n' "$pinned"
