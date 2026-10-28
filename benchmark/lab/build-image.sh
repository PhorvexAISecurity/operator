#!/usr/bin/env bash
# Builds the manager image of one Git tag, unedited, into a run-scoped ECR
# repository and writes IMAGE.json (ticket Part 3).
#
#   build-image.sh --run-dir D --run-id ID --ledger LEDGER --src-repo REPO \
#     --tag T --commit C [--src-remote URL [--git-askpass HELPER]] \
#     [--region us-east-2] --account A [--expires RFC3339]
#   build-image.sh --delete --run-id ID --ledger LEDGER [--region us-east-2] --account A
#
# The tag is cloned into D/src and checked out detached at C; the working
# repository is only read. The clone's whole operator.Dockerfile must have a
# sha256 listed in images.lock, which holds that Dockerfile's two build sets.
# They are built with go build as the Dockerfile builds them, appended as one
# layer to the pinned distroless base with crane, and pushed to
# phorvex-281-temp-<ID>, created IMMUTABLE and tagged phorvex.ai/lab-run=<ID>.
# No source file is edited. In a run.sh run teardown-by-tag.sh deletes the
# repository; --delete is for standalone tests only.
#
# Exit codes: 10 bad arguments, ledger or AWS account; 11 clone or ref mismatch;
# 13 pendingcheck; 14 build; 15 registry create or push; 16 repository name
# collision; 17 delete not proven; 18 Dockerfile drift.
set -Eeuo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock=$here/images.lock
stage=10
log() { printf '[build-image] %s\n' "$*" >&2; }
fail() { local code=$1; shift; log "ERROR: $*"; exit "$code"; }
usage() {
  log 'usage: build-image.sh --run-dir D --run-id ID --ledger LEDGER --src-repo REPO --tag T --commit C [--src-remote URL [--git-askpass HELPER]] [--region R] --account A [--expires RFC3339]'
  log '       build-image.sh --delete --run-id ID --ledger LEDGER [--region R] --account A'
}
bad() { usage; fail 10 "$*"; }
need() { local t; for t; do command -v "$t" >/dev/null 2>&1 || fail 10 "required tool not on PATH: $t"; done; }
trap 'log "ERROR: command failed at line $LINENO"; exit "$stage"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM HUP

mode=build run_dir='' run_id='' ledger='' src_repo='' tag='' commit='' src_remote='' askpass=''
region=us-east-2 account='' expires=''
while (($#)); do
  case $1 in
    --delete) mode=delete; shift; continue ;;
    --run-dir|--run-id|--ledger|--src-repo|--tag|--commit|--src-remote|--git-askpass|--region|--account|--expires)
      (($# >= 2)) || bad "$1 needs a value" ;;
    *) bad "unknown argument: $1" ;;
  esac
  case $1 in
    --run-dir) run_dir=$2 ;; --run-id) run_id=$2 ;; --ledger) ledger=$2 ;; --src-repo) src_repo=$2 ;;
    --tag) tag=$2 ;; --commit) commit=$2 ;; --src-remote) src_remote=$2 ;; --git-askpass) askpass=$2 ;;
    --region) region=$2 ;; --account) account=$2 ;; --expires) expires=$2 ;;
  esac
  shift 2
done

[[ $run_id =~ ^[0-9a-f]{6}$ ]] || bad "--run-id must be 6 lowercase hex digits"
[[ $account =~ ^[0-9]{12}$ ]] || bad "--account must be 12 digits"
[[ $region =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || bad "--region is not an AWS region name: $region"
need jq aws
[[ -f $ledger ]] && jq -e --arg id "$run_id" '.runId == $id and (.entries | type == "array")' "$ledger" >/dev/null 2>&1 \
  || bad "--ledger must be a JSON file {\"runId\":\"$run_id\",\"entries\":[...]}"
repo_name=phorvex-281-temp-$run_id
registry=$account.dkr.ecr.$region.amazonaws.com
export AWS_PAGER=''

D='' made_src=0 made_cfg=0
tmp=$(mktemp -d)
cleanup() {
  rm -rf -- "$tmp"
  if ((made_cfg)); then rm -rf -- "$D/dockercfg"; fi
  if ((made_src)); then rm -rf -- "$D/src"; fi
  return 0
}
trap cleanup EXIT

assert_account() {
  local actual
  actual=$(aws sts get-caller-identity --region "$region" --query Account --output text) \
    || fail 10 "aws sts get-caller-identity failed; check AWS credentials"
  [[ $actual == "$account" ]] || fail 10 "AWS credentials are for account $actual, not --account $account"
}
# Prints the repository ARN, or "absent".
describe_repo() {
  local out
  if out=$(aws ecr describe-repositories --region "$region" --repository-names "$repo_name" \
      --query 'repositories[0].repositoryArn' --output text 2>"$tmp/describe.err"); then
    printf '%s\n' "$out"
  elif grep -q RepositoryNotFoundException "$tmp/describe.err"; then
    echo absent
  else
    cat "$tmp/describe.err" >&2; return 1
  fi
}
ledger_update() {
  local t; t=$(mktemp "$ledger.XXXXXX")
  jq "$@" "$ledger" >"$t" && mv -f -- "$t" "$ledger" || { rm -f -- "$t"; return 1; }
}

if [[ $mode == delete ]]; then
  assert_account
  stage=17
  arn=$(describe_repo) || fail 17 "could not look up ECR repository $repo_name"
  if [[ $arn != absent ]]; then
    if jq -e --arg n "$repo_name" 'any(.entries[]; .name == $n and .status == "collision")' "$ledger" >/dev/null; then
      fail 17 "$repo_name is a recorded name collision, not this run's repository; it is never deleted"
    fi
    owner=$(aws ecr list-tags-for-resource --region "$region" --resource-arn "$arn" --output json \
      | jq -r '[.tags[] | select(.Key == "phorvex.ai/lab-run") | .Value][0] // ""')
    [[ $owner == "$run_id" ]] || fail 17 "$repo_name is not tagged phorvex.ai/lab-run=$run_id; not deleting it"
    aws ecr delete-repository --region "$region" --repository-name "$repo_name" --force --output json >/dev/null \
      || log "delete-repository failed; checking whether $repo_name is gone"
  fi
  arn=$(describe_repo) || fail 17 "could not confirm that $repo_name is gone"
  [[ $arn == absent ]] || fail 17 "$repo_name still exists"
  log "$repo_name: RepositoryNotFoundException"
  exit 0
fi

[[ -n $run_dir && -n $src_repo && -n $tag && -n $commit ]] || bad "--run-dir, --src-repo, --tag and --commit are required"
[[ $commit =~ ^[0-9a-f]{40}$ ]] || bad "--commit must be a full 40-character lowercase SHA"
{ [[ $tag != -* ]] && git check-ref-format "refs/tags/$tag"; } || bad "--tag is not a valid tag name: $tag"
[[ $run_dir == /* && -d $run_dir ]] || bad "--run-dir must be an existing absolute directory"
D=$(realpath -e -- "$run_dir")
[[ $D != / ]] || bad "--run-dir must not be /"
work_repo=$(git -C "$src_repo" rev-parse --show-toplevel 2>/dev/null) || bad "--src-repo is not a Git repository: $src_repo"
work_repo=$(realpath -e -- "$work_repo")
case $D/ in "$work_repo"/*) bad "--run-dir must be outside the working repository" ;; esac
case $work_repo/ in "$D"/*) bad "--run-dir must not contain the working repository" ;; esac
if [[ -n $src_remote ]]; then
  if [[ $src_remote =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*@ ]]; then bad "--src-remote must not carry credentials; use --git-askpass"; fi
  [[ -z $askpass || ( -f $askpass && -x $askpass ) ]] || bad "--git-askpass must be an executable file"
elif [[ -n $askpass ]]; then
  bad "--git-askpass needs --src-remote"
fi
expires=${expires:-$(date -u -d '+6 hours' +%Y-%m-%dT%H:%M:%SZ)}
[[ $expires =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || bad "--expires must be RFC 3339 UTC, like 2026-10-28T03:00:00Z"
for p in src build dockercfg IMAGE.json; do
  [[ ! -e $D/$p && ! -L $D/$p ]] || bad "$D/$p already exists"
done
jq -e '(.goToolchain | test("^go[0-9]+[.][0-9]+[.][0-9]+$")) and (.base.image | type == "string")
  and (.base.digest | test("^sha256:[0-9a-f]{64}$")) and (.operatorDockerfiles | length > 0)
  and all(.operatorDockerfiles[]; (.setOne | length > 0) and (.setTwo | length > 0))' "$lock" >/dev/null 2>&1 \
  || fail 10 "images.lock is missing or malformed: $lock"
need git tar sha256sum grep cmp go crane
tar --version 2>/dev/null | grep -q 'GNU tar' || fail 10 "GNU tar is required (--owner, --sort, --mtime)"
toolchain=$(jq -r .goToolchain "$lock")
base_image=$(jq -r .base.image "$lock")
base_digest=$(jq -r .base.digest "$lock")
base_ref=$base_image@$base_digest

assert_account

# 1. Clone the tag; the working repository is only read. No global or system Git
# configuration applies, so no hook, rewrite or credential helper runs.
stage=11
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0
made_src=1
if [[ -n $src_remote ]]; then
  env ${askpass:+"GIT_ASKPASS=$askpass"} git -c credential.helper= clone --quiet --no-checkout -- "$src_remote" "$D/src"
else
  git clone --quiet --no-hardlinks --no-checkout -- "$work_repo" "$D/src"
fi
git -C "$D/src" -c advice.detachedHead=false checkout --quiet --detach "$commit" 2>/dev/null \
  || fail 11 "commit $commit is not in the source repository"
tagged=$(git -C "$D/src" rev-parse --verify --quiet "refs/tags/$tag^{commit}") || fail 11 "tag $tag is not in the source repository"
head=$(git -C "$D/src" rev-parse HEAD)
[[ $tagged == "$commit" && $head == "$commit" ]] || fail 11 "tag $tag points to $tagged, not --commit $commit"
log "source: $tag = $commit"

# 2. The build sets are valid only for a Dockerfile images.lock lists.
stage=18
dockerfile=$D/src/deploy/docker/operator.Dockerfile
[[ -f $dockerfile ]] || fail 18 "deploy/docker/operator.Dockerfile does not exist at $tag"
dockerfile_sha=$(sha256sum "$dockerfile" | cut -d' ' -f1)
profile=$(jq -c --arg s "$dockerfile_sha" '.operatorDockerfiles[$s] // empty' "$lock")
[[ -n $profile ]] || fail 18 "Dockerfile drift: operator.Dockerfile at $tag has sha256 $dockerfile_sha, which images.lock does not list"
log "operator.Dockerfile $dockerfile_sha: $(jq -r '.source' <<<"$profile")"

# The Docker build has no .git in its workspace, so it links no VCS stamp; nor may this.
export GOTOOLCHAIN=$toolchain GOFLAGS='-mod=readonly -buildvcs=false'

# 3. The same unfinished-work gate as the Dockerfile.
stage=13
(cd "$D/src/phorvex" && go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md) >&2 \
  || fail 13 "pendingcheck failed at $tag"

# 4. Both build sets, as the Dockerfile builds them, for linux/amd64.
stage=14
go_version=$(cd "$D/src/phorvex" && go env GOVERSION)
[[ $go_version == "$toolchain" ]] || fail 14 "go resolved toolchain $go_version, not $toolchain"
mapfile -t set_one < <(jq -r '.setOne[].package' <<<"$profile")
mapfile -t set_two < <(jq -r '.setTwo[].package' <<<"$profile")
# build_sets OUT [GOCACHE]
build_sets() {
  local -a env_vars=(CGO_ENABLED=0 GOOS=linux GOARCH=amd64)
  [[ -z ${2:-} ]] || env_vars+=("GOCACHE=$2")
  mkdir -p -- "$1"
  (cd "$D/src/phorvex" &&
    env "${env_vars[@]}" go build -trimpath \
      -ldflags="-s -w -X github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA=$commit" -o "$1/" "${set_one[@]}" &&
    env "${env_vars[@]}" go build -trimpath -ldflags="-s -w" -o "$1/" "${set_two[@]}") >&2
}
build=$D/build
mkdir -- "$build"
mkdir -m 0755 -- "$build/rootfs"
build_sets "$build/out" || fail 14 "go build failed at $tag"

binaries='[]'
while IFS=$'\t' read -r package name set; do
  bin=$build/out/${package##*/}
  [[ -f $bin ]] || fail 14 "go build produced no binary for $package"
  mv -- "$bin" "$build/rootfs/$name"
  chmod 0755 -- "$build/rootfs/$name"
  if grep -aqF -- "$commit" "$build/rootfs/$name"; then stamped=true; else stamped=false; fi
  if [[ $set == one && $stamped != true ]]; then fail 14 "$name does not carry linkedGitSHA $commit"; fi
  if [[ $set == two && $stamped != false ]]; then fail 14 "$name carries $commit, but build set two is never stamped"; fi
  sha=$(sha256sum "$build/rootfs/$name" | cut -d' ' -f1)
  binaries=$(jq -c --arg n "$name" --arg s "$sha" --argjson t "$stamped" '. + [{name: $n, sha256: $s, stamped: $t}]' <<<"$binaries")
done < <(jq -r '(.setOne[] | [.package, .name, "one"]), (.setTwo[] | [.package, .name, "two"]) | @tsv' <<<"$profile")
rmdir -- "$build/out"
log "built $(jq length <<<"$binaries") binaries; linkedGitSHA $commit in build set one only"

# 5. Reproducibility: a second build with an empty build cache.
build_sets "$build/rebuild" "$build/gocache-rebuild" || fail 14 "rebuild failed at $tag"
reproducible=true
while IFS=$'\t' read -r package name; do
  cmp -s -- "$build/rebuild/${package##*/}" "$build/rootfs/$name" || reproducible=false
done < <(jq -r '(.setOne[], .setTwo[]) | [.package, .name] | @tsv' <<<"$profile")
rm -rf -- "$build/rebuild" "$build/gocache-rebuild"
log "reproducible: $reproducible"

# 6. One root-owned layer.
tar --owner=0 --group=0 --numeric-owner --sort=name --mtime=@0 -C "$build/rootfs" -cf "$build/rootfs.tar" .

# 7. The run's own repository; any existing repository of that name is a collision.
stage=15
target=$registry/$repo_name:${commit:0:8}
[[ $target =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/phorvex-281-temp-[0-9a-f]{6}:[0-9a-f]{8}$ ]] \
  || fail 15 "refusing push target $target"
entry=$(jq -nc --arg n "$repo_name" --arg r "$region" --arg a "$account" --arg e "$expires" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{kind: "ecr-repository", name: $n, region: $r, account: $a, expires: $e, at: $t, status: "creating"}')
index=$(jq '.entries | length' "$ledger")
ledger_update --argjson e "$entry" '.entries += [$e]'
if aws ecr create-repository --region "$region" --repository-name "$repo_name" --image-tag-mutability IMMUTABLE \
    --tags "Key=phorvex.ai/lab-run,Value=$run_id" "Key=phorvex.ai/benchmark,Value=true" "Key=phorvex.ai/lab-expires,Value=$expires" \
    --output json >/dev/null 2>"$tmp/create.err"; then
  ledger_update --argjson i "$index" '.entries[$i].status = "created"'
elif grep -q RepositoryAlreadyExistsException "$tmp/create.err"; then
  ledger_update --argjson i "$index" '.entries[$i].status = "collision"'
  fail 16 "ECR repository $repo_name already exists and is not this run's; nothing was pushed or deleted"
else
  cat "$tmp/create.err" >&2
  ledger_update --argjson i "$index" '.entries[$i].status = "failed"'
  fail 15 "could not create ECR repository $repo_name"
fi
log "created ECR repository $repo_name (IMMUTABLE, phorvex.ai/lab-run=$run_id)"

# 8. Assemble and push in one step. The registry token is registry-wide for
# 12 h, so its config directory is deleted as soon as the push is verified.
mkdir -- "$D/dockercfg"
made_cfg=1
export DOCKER_CONFIG=$D/dockercfg
aws ecr get-login-password --region "$region" | crane auth login --password-stdin -u AWS "$registry" >&2
crane mutate "$base_ref" --platform linux/amd64 --append "$build/rootfs.tar" \
  -u 65532:65532 --entrypoint /manager -w / -t "$target" >&2
digest=$(crane digest "$target")
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || fail 15 "no valid digest for $target: $digest"
image=$registry/$repo_name@$digest

# I-3: the pushed image is the base plus exactly one layer, with the Dockerfile's config.
crane config "$image" | jq -e '.config.User == "65532:65532" and .config.Entrypoint == ["/manager"] and .config.WorkingDir == "/"' >/dev/null \
  || fail 15 "$image is not user 65532:65532, entrypoint [/manager], workdir /"
base_manifest=$(crane manifest "$base_ref")
if jq -e 'has("manifests")' <<<"$base_manifest" >/dev/null; then
  amd64=$(jq -r '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")][0].digest // ""' <<<"$base_manifest")
  [[ -n $amd64 ]] || fail 15 "$base_ref has no linux/amd64 image"
  base_manifest=$(crane manifest "$base_image@$amd64")
fi
crane manifest "$image" | jq -e --argjson b "$base_manifest" \
  '([.layers[].digest] | .[:-1]) == [$b.layers[].digest] and (.layers | length) == ($b.layers | length) + 1' >/dev/null \
  || fail 15 "$image layers are not the base's layers plus one"
rm -rf -- "$D/dockercfg"
made_cfg=0
unset DOCKER_CONFIG
log "pushed $image"

jq -n --arg tag "$tag" --arg commit "$commit" --arg repository "$registry/$repo_name" --arg digest "$digest" \
  --arg image "$image" --argjson binaries "$binaries" --arg baseImage "$base_image" --arg baseDigest "$base_digest" \
  --arg go "$toolchain" --argjson reproducible "$reproducible" --arg builtAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg dockerfile "$dockerfile_sha" --arg runId "$run_id" \
  '{tag: $tag, commit: $commit, component: "manager", repository: $repository, digest: $digest, image: $image,
    binaries: $binaries, base: {image: $baseImage, digest: $baseDigest}, goToolchain: $go, linkedGitSHA: $commit,
    reproducible: $reproducible, builtAt: $builtAt, operatorDockerfileSha256: $dockerfile, runId: $runId}' \
  >"$D/IMAGE.json.tmp"
mv -f -- "$D/IMAGE.json.tmp" "$D/IMAGE.json"
printf '%s\n' "$image"
