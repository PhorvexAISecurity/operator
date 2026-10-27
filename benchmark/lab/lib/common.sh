# Shared helpers for the self-service benchmark lab scripts (build-image.sh,
# and later run.sh / teardown-by-tag.sh). Source it; it defines functions and
# constants only and has no side effects.
#
# Every AWS resource a lab run creates carries BENCH_RUN_TAG_KEY=<run id>, and
# teardown deletes by that tag alone. The account is shared with prod, so names
# also live under a prefix that no product resource uses.

BENCH_RUN_TAG_KEY='phorvex-bench-run'
BENCH_MARK_TAG_KEY='phorvex-bench'
BENCH_ECR_PREFIX='phorvex-bench'

bench_log() { printf '[%s] %s\n' "${BENCH_SCRIPT:-bench}" "$*" >&2; }
bench_die() { bench_log "ERROR: $*"; exit 1; }
# Usage errors exit 2 so callers can tell them from a failed step.
bench_usage_die() { bench_log "usage: $*"; exit 2; }

bench_require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || bench_die "required tool not found on PATH: $tool"
  done
}

# Lowercase, dash-separated, at most 40 characters: valid inside ECR repository
# names, EKS cluster names and tag values.
bench_valid_run_id() { [[ $1 =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && ${#1} -le 40 ]]; }
bench_valid_commit() { [[ $1 =~ ^[0-9a-f]{40}$ ]]; }
bench_valid_account() { [[ $1 =~ ^[0-9]{12}$ ]]; }
bench_valid_region() { [[ $1 =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]]; }

# Refuses unless the credentials in use belong to the expected account.
bench_assert_aws_account() {
  local expected=$1 region=$2 actual
  actual=$(aws sts get-caller-identity --region "$region" --query Account --output text) \
    || bench_die "aws sts get-caller-identity failed; check AWS credentials"
  [[ $actual == "$expected" ]] || bench_die "AWS credentials are for account $actual, not --aws-account $expected"
}

# Writes stdin to $1 through a temporary file in the same directory, so readers
# never see a partial file.
bench_write_atomic() {
  local dest=$1 tmp
  tmp=$(mktemp "${dest}.tmp.XXXXXX") || return 1
  if cat >"$tmp"; then mv -f "$tmp" "$dest"; else rm -f "$tmp"; return 1; fi
}
