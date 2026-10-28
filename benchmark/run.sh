#!/usr/bin/env bash
# One command for the PHORVEXSEC-281 benchmark lab (ticket Part 2).
#
#   benchmark/run.sh --run-dir D --aws-account A [--region us-east-2] \
#     --new-tag TAG --new-commit SHA [--src-remote URL --git-askpass HELPER] \
#     [--brain-extra-args "ARGS"] --scenarios A,B,D [--max-hours 6] --m23 stopped|fixed \
#     [--fixtures-only [--fixture-set stub|real] [--after-golden SCRIPT]] --plan
#
# This build runs P0 (inputs, process identity, the isolated lab environment)
# and P1 (the read-only preflight), prints what P2-P9 would do, and has the exit
# handler that runs P8 (teardown-by-tag.sh, only once a create has started) and
# P9 (the local proofs). P2-P7 are not built yet, so only --plan is accepted.
#
# Exit codes (§12): 10 preflight refusal; 20 lab create; 25 image build; 30
# platform; 40 fixture; 50 scenario; 60 report; 70 teardown did not print PASS;
# 80 repo or kubeconfig changed; 90 interrupted, teardown passed; 97 a non-lab
# target was refused. Precedence: 70 > 80 > 97 > first failing phase > 90 > 0.
#
# Test hook: BENCH_TEST_PAUSE_AT=<step> waits at that step until the file
# RUN_DIR/PAUSED-<step> is removed. Honoured only with --fixture-set stub.
set -uo pipefail
trap '' PIPE
umask 077

SELF=$(realpath -e -- "${BASH_SOURCE[0]}")
HERE=$(dirname -- "$SELF")
LAB_DIR=$HERE/lab
# shellcheck source=lab/shims/shim-lib.sh
source "$LAB_DIR/shims/shim-lib.sh"

EKS_VERSION=1.36            # DR-50
GPU_VCPUS=4                 # one GPU node, DR-20
COST_CENTS_PER_HOUR=160     # DR-27
COST_CAP_CENTS=2500         # C-6
DEV_CLUSTER=phorvex-dev-eks
BUDGET=phorvex-benchmark-lab  # DR-51
M23_PATTERN='m23_watch|reader-l3'
TOOLS=(kubectl helm aws eksctl crane git python3 jq go)
SHIMMED=(kubectl helm aws)

RUN_DIR='' run_id='' phase=P0 failed_code='' run_dir_ready=0
lab_context='' lab_server='' forbidden_servers='' aws_config='' aws_credentials=''
export BENCH_DEV_CLUSTER=$DEV_CLUSTER

log() {
  printf '[run %s %s] %s\n' "${run_id:-......}" "$phase" "$*" >&2
  if ((run_dir_ready)); then printf '%s %s %s\n' "$(date -u +%H:%M:%S)" "$phase" "$*" >>"$RUN_DIR/run.log"; fi
}
fail() { local code=$1; shift; log "ERROR: $*"; failed_code=${failed_code:-$code}; exit "$code"; }
phase_code() { case $1 in P2) echo 25 ;; P3) echo 20 ;; P4) echo 30 ;; P5) echo 40 ;; P6) echo 50 ;; P7) echo 60 ;; *) echo 10 ;; esac; }
refuse() { fail 10 "$@"; }

# --- arguments ----------------------------------------------------------------
run_dir_arg='' account='' region=us-east-2 new_tag='' new_commit='' src_remote='' askpass='' extra_args=''
scenarios='' max_hours=6 m23='' fixtures_only=0 fixture_set='' after_golden='' plan=0
while (($#)); do
  case $1 in
    --fixtures-only) fixtures_only=1; shift; continue ;;
    --plan) plan=1; shift; continue ;;
    --run-dir|--aws-account|--region|--new-tag|--new-commit|--src-remote|--git-askpass|--brain-extra-args|\
      --scenarios|--max-hours|--m23|--fixture-set|--after-golden)
      (($# >= 2)) || refuse "$1 needs a value" ;;
    *) refuse "unknown argument: $1" ;;
  esac
  case $1 in
    --run-dir) run_dir_arg=$2 ;; --aws-account) account=$2 ;; --region) region=$2 ;;
    --new-tag) new_tag=$2 ;; --new-commit) new_commit=$2 ;; --src-remote) src_remote=$2 ;;
    --git-askpass) askpass=$2 ;; --brain-extra-args) extra_args=$2 ;; --scenarios) scenarios=$2 ;;
    --max-hours) max_hours=$2 ;; --m23) m23=$2 ;; --fixture-set) fixture_set=$2 ;; --after-golden) after_golden=$2 ;;
  esac
  shift 2
done

# --- P0.2 capture before isolation ---------------------------------------------
REAL_HOME=$HOME
real_kubeconfig=${KUBECONFIG:-$REAL_HOME/.kube/config}
[[ $real_kubeconfig != *:* ]] || refuse "KUBECONFIG lists several files; point it at one, or unset it"
declare -A REAL=()
for t in "${TOOLS[@]}"; do
  p=$(command -v "$t" 2>/dev/null) || p=''
  [[ -z $p || $p == /* ]] || p=''
  REAL[$t]=$p
done
[[ -n ${REAL[git]} && -n ${REAL[jq]} ]] || refuse "git and jq are required"
WORKING_REPO=$("${REAL[git]}" -C "$HERE" rev-parse --show-toplevel 2>/dev/null) || refuse "run.sh is not inside a Git repository"
WORKING_REPO=$(realpath -e -- "$WORKING_REPO")

# --- P0.3 validate --------------------------------------------------------------
((plan)) || refuse "only --plan is available in this build: P2-P7 are not implemented yet"
[[ $account =~ ^[0-9]{12}$ ]] || refuse "--aws-account must be 12 digits"
[[ $region =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || refuse "--region is not an AWS region name: $region"
[[ $new_commit =~ ^[0-9a-f]{40}$ ]] || refuse "--new-commit must be a full 40-character lowercase SHA"
{ [[ -n $new_tag && $new_tag != -* ]] && "${REAL[git]}" check-ref-format "refs/tags/$new_tag"; } || refuse "--new-tag is not a valid tag name: ${new_tag:-<none>}"
if [[ -n $src_remote ]]; then
  [[ ! $src_remote =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*@ ]] || refuse "--src-remote must not carry credentials; use --git-askpass"
  [[ -z $askpass || ( -f $askpass && -x $askpass ) ]] || refuse "--git-askpass must be an executable file"
elif [[ -n $askpass ]]; then refuse "--git-askpass needs --src-remote"; fi
[[ $extra_args != *$'\n'* ]] || refuse "--brain-extra-args must be one line"
[[ $m23 == stopped || $m23 == fixed ]] || refuse "--m23 must be stopped (recommended) or fixed (DR-26)"
[[ $max_hours =~ ^[0-9]+$ ]] || refuse "--max-hours must be a whole number"
min_hours=$((fixtures_only ? 2 : 3))
((max_hours >= min_hours && max_hours <= 15)) || refuse "--max-hours must be $min_hours to 15 (DR-27)"
((max_hours * COST_CENTS_PER_HOUR <= COST_CAP_CENTS)) || refuse "--max-hours $max_hours at \$1.60/h exceeds the \$25 cap (DR-27)"
if ((fixtures_only)); then
  fixture_set=${fixture_set:-real}
  [[ $fixture_set == stub || $fixture_set == real ]] || refuse "--fixture-set must be stub or real"
  [[ -z $after_golden || -f $WORKING_REPO/$after_golden ]] || refuse "--after-golden $after_golden is not a file in the repository"
else
  [[ -z $fixture_set && -z $after_golden ]] || refuse "--fixture-set and --after-golden need --fixtures-only"
  [[ $scenarios =~ ^[ABCD](,[ABCD])*$ ]] || refuse "--scenarios must be a comma list of A, B, C, D"
  [[ $(tr ',' '\n' <<<"$scenarios" | sort | uniq -d) == '' ]] || refuse "--scenarios lists a scenario twice"
fi
[[ -z ${BENCH_TEST_PAUSE_AT:-} || $fixture_set == stub ]] || refuse "BENCH_TEST_PAUSE_AT is honoured only with --fixture-set stub"

# The guard P9 repeats before deleting anything in the run directory.
run_dir_refusal() {
  local d=$1
  [[ $d == /* ]] || { echo "--run-dir must be an absolute path"; return; }
  d=$(realpath -m -- "$d")
  [[ $d != / ]] || { echo "--run-dir must not be /"; return; }
  [[ $d != "$(realpath -m -- "$REAL_HOME")" ]] || { echo "--run-dir must not be your home directory"; return; }
  case $d/ in "$WORKING_REPO"/*) echo "--run-dir must be outside the repository"; return ;; esac
  case $WORKING_REPO/ in "$d"/*) echo "--run-dir must not contain the repository"; return ;; esac
}
[[ -n $run_dir_arg ]] || refuse "--run-dir is required"
why=$(run_dir_refusal "$run_dir_arg"); [[ -z $why ]] || refuse "$why"
RUN_DIR=$(realpath -m -- "$run_dir_arg")
[[ ! -e $RUN_DIR && ! -L $RUN_DIR ]] || refuse "--run-dir $RUN_DIR already exists; it must be new"
mkdir -m 700 -- "$RUN_DIR" || refuse "cannot create --run-dir $RUN_DIR (its parent must exist)"

# --- P0.4 run id, then the exit handler ----------------------------------------
run_id=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
[[ $run_id =~ ^[0-9a-f]{6}$ ]] || refuse "could not generate a run id"
LAB=phorvex-281-lab-$run_id REPO_NAME=phorvex-281-temp-$run_id
run_dir_ready=1

# The lab environment: env -i semantics, but built by unsetting and exporting in
# a subshell, so no credential is ever on a command line (DR-23).
labenv() (
  local v
  for v in $(compgen -e); do
    case $v in AWS_PROFILE|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN) ;; *) unset "$v" 2>/dev/null ;; esac
  done
  export HOME=$RUN_DIR/home TMPDIR=$RUN_DIR/tmp PATH=$RUN_DIR/shims:$RUN_DIR/bin:/usr/bin:/bin LANG=C.UTF-8 \
    KUBECONFIG=$RUN_DIR/kubeconfig LAB_KUBECONFIG=$RUN_DIR/kubeconfig LAB_CONTEXT=$lab_context \
    LAB_EXPECTED_SERVER=$lab_server LAB_FORBIDDEN_SERVERS=$forbidden_servers BENCH_DEV_CLUSTER=$DEV_CLUSTER \
    RUN_DIR=$RUN_DIR REPO_SNAPSHOT=$RUN_DIR/repo WORKING_REPO=$WORKING_REPO GOLDEN_DIR=$RUN_DIR/golden \
    LITELLM_LIVE_WORK=$RUN_DIR/litellm-work GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_NOSYSTEM=1 PYTHONDONTWRITEBYTECODE=1 \
    AWS_CONFIG_FILE=$aws_config AWS_SHARED_CREDENTIALS_FILE=$aws_credentials AWS_REGION=$region \
    AWS_DEFAULT_REGION=$region AWS_PAGER=
  exec "$@"
)

# P8: only once P2 has started a create; the teardown script decides PASS.
p8_teardown() {
  local td=$RUN_DIR/repo/benchmark/lab/teardown-by-tag.sh
  [[ -x $td ]] || td=$LAB_DIR/teardown-by-tag.sh
  log "$td --run-id $run_id --region $region --account $account --proof $RUN_DIR/TEARDOWN-PROOF.txt"
  labenv "$td" --run-id "$run_id" --region "$region" --account "$account" --proof "$RUN_DIR/TEARDOWN-PROOF.txt" \
    >>"$RUN_DIR/run.log" 2>&1
  local rc=$?
  ((rc == 0)) && [[ $(tail -n 1 "$RUN_DIR/TEARDOWN-PROOF.txt" 2>/dev/null) == PASS ]]
}

repo_state() {
  local g
  g=$(GIT_OPTIONAL_LOCKS=0 "${REAL[git]}" -C "$WORKING_REPO" rev-parse --absolute-git-dir) || return 1
  gitw() { GIT_OPTIONAL_LOCKS=0 "${REAL[git]}" -C "$WORKING_REPO" "$@"; }
  echo '## rev-parse HEAD'; gitw rev-parse HEAD
  echo '## status --porcelain=v1 --ignored -uall'; gitw status --porcelain=v1 --ignored -uall
  echo '## stash list'; gitw stash list
  echo '## worktree list --porcelain'; gitw worktree list --porcelain
  echo '## for-each-ref'; gitw for-each-ref
  echo '## ls-files -s | sha256sum'; gitw ls-files -s | sha256sum
  echo '## .git HEAD, config, packed-refs, hooks/*, info/*'
  # packed-refs and hooks may not exist; list only the files that do.
  (cd "$g" && for f in HEAD config packed-refs hooks/* info/*; do if [[ -f $f ]]; then printf '%s\n' "$f"; fi; done |
    LC_ALL=C sort | xargs -r sha256sum)
}

kubeconfig_state() {
  if [[ -e $real_kubeconfig ]]; then sha256sum -- "$real_kubeconfig"; else echo "absent $real_kubeconfig"; fi
}

# P9: local proofs, then the run-directory cleanup behind its guard.
p9_changed=0 p9_refused=0
p9_local() {
  local teardown=$1 n
  if [[ -f $RUN_DIR/COMMANDS.log ]]; then
    p9_refused=$(awk -F'\t' '$3 == "refused"' "$RUN_DIR/COMMANDS.log" | wc -l)
    n=$(awk -F'\t' '$4 == "dev" && $3 != "read" && $3 != "dev-read"' "$RUN_DIR/COMMANDS.log" | wc -l)
    ((n == 0)) || { log "COMMANDS.log: $n call(s) other than reads targeted dev"; p9_refused=$((p9_refused + n)); }
    ((p9_refused == 0)) || log "COMMANDS.log: $p9_refused refusal(s) or dev write(s)"
  fi
  if [[ -f $RUN_DIR/KUBECONFIG-BEFORE.sha256 ]]; then
    kubeconfig_state >"$RUN_DIR/KUBECONFIG-AFTER.sha256"
    cmp -s "$RUN_DIR/KUBECONFIG-BEFORE.sha256" "$RUN_DIR/KUBECONFIG-AFTER.sha256" \
      || { log "the real kubeconfig $real_kubeconfig changed"; p9_changed=1; }
  fi
  if [[ -f $RUN_DIR/REPO-BEFORE.txt ]]; then
    repo_state >"$RUN_DIR/REPO-AFTER.txt" 2>&1
    cmp -s "$RUN_DIR/REPO-BEFORE.txt" "$RUN_DIR/REPO-AFTER.txt" || { log "REPO-AFTER.txt differs from REPO-BEFORE.txt"; p9_changed=1; }
    find "$WORKING_REPO" -path "$WORKING_REPO/.git" -prune -o -cnewer "$RUN_DIR/REPO-BEFORE.stamp" -print \
      >"$RUN_DIR/REPO-CHANGED.txt" 2>/dev/null
    [[ ! -s $RUN_DIR/REPO-CHANGED.txt ]] || { log "files changed in the repository: see REPO-CHANGED.txt"; p9_changed=1; }
  fi
  # Delete only inside this run's own directory, and only if it is provably ours.
  if [[ -n $(run_dir_refusal "$RUN_DIR") ]] \
      || [[ $(jq -r '.runId // ""' "$RUN_DIR/run.json" 2>/dev/null) != "$run_id" ]]; then
    log "WARNING: run.json does not carry run $run_id, or the run directory failed its guard; deleting nothing"
    return
  fi
  rm -rf -- "${RUN_DIR:?}/secrets" "${RUN_DIR:?}/dockercfg" "${RUN_DIR:?}/kubeconfig"
  if [[ $teardown == fail ]]; then
    log "teardown did not print PASS; keeping $RUN_DIR for diagnosis. Re-run: $(cat "$RUN_DIR/TEARDOWN-COMMAND.txt")"
    return
  fi
  find "$RUN_DIR" -xdev ! -type l -exec chmod u+w {} + 2>/dev/null
  rm -rf -- "${RUN_DIR:?}/litellm-work" "${RUN_DIR:?}"/voice-render-* "${RUN_DIR:?}/home" "${RUN_DIR:?}/tmp" \
    "${RUN_DIR:?}/src" "${RUN_DIR:?}/repo" "${RUN_DIR:?}/shims" "${RUN_DIR:?}/bin" "${RUN_DIR:?}/build"
}

on_exit() {
  local why=$1 rc=$2 at=$phase teardown=none code
  trap '' INT TERM HUP
  trap - EXIT
  phase=P8
  if [[ -e $RUN_DIR/P2-STARTED ]]; then
    if p8_teardown; then teardown=pass; else teardown=fail; fi
  else
    log "no AWS create was started; nothing to tear down"
  fi
  phase=P9
  p9_local "$teardown"
  local at_code
  at_code=$(phase_code "$at")
  if [[ $teardown == fail ]]; then code=70
  elif ((p9_changed)); then code=80
  elif ((p9_refused)); then code=97
  elif [[ -n $failed_code ]]; then code=$failed_code
  elif [[ $why != EXIT ]]; then code=$([[ $teardown == pass ]] && echo 90 || echo "$at_code")
  elif ((rc != 0)); then code=$at_code
  else code=0
  fi
  if [[ $m23 == stopped ]]; then
    log "the M-23 watcher was required stopped; DEVOPS restarts it as recorded in benchmark/lab/README.md (run.sh never does)"
  fi
  log "exit $code${why:+ ($why)}"
  exit "$code"
}
for sig in EXIT INT TERM HUP; do
  # shellcheck disable=SC2064  # $sig is meant to be expanded now
  trap "on_exit $sig \$?" "$sig"
done

pause_at() {
  [[ ${BENCH_TEST_PAUSE_AT:-} == "$1" ]] || return 0
  log "test hook: paused at $1 until $RUN_DIR/PAUSED-$1 is removed"
  : >"$RUN_DIR/PAUSED-$1"
  local i=0
  while [[ -e $RUN_DIR/PAUSED-$1 ]] && ((i++ < 1500)); do sleep 0.2; done
}

# --- P0.5 run.json, the teardown command, the ledger ----------------------------
tools_json=$(for t in "${TOOLS[@]}"; do printf '%s\t%s\n' "$t" "${REAL[$t]}"; done | jq -Rn '[inputs | split("\t") | {(.[0]): .[1]}] | add')
jq -n --arg runId "$run_id" --arg lab "$LAB" --arg repository "$REPO_NAME" --arg account "$account" --arg region "$region" \
  --arg newTag "$new_tag" --arg newCommit "$new_commit" --arg srcRemote "$src_remote" --arg extra "$extra_args" \
  --arg scenarios "$scenarios" --argjson maxHours "$max_hours" --arg m23 "$m23" --argjson fixturesOnly "$fixtures_only" \
  --arg fixtureSet "$fixture_set" --arg afterGolden "$after_golden" --argjson plan "$plan" \
  --arg home "$REAL_HOME" --arg kubeconfig "$real_kubeconfig" --argjson tools "$tools_json" \
  --arg workingRepo "$WORKING_REPO" --arg runDir "$RUN_DIR" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schema: "phorvex-bench/run/v1", runId: $runId, lab: $lab, repository: $repository, account: $account,
    region: $region, inputs: {newTag: $newTag, newCommit: $newCommit, srcRemote: $srcRemote, brainExtraArgs: $extra,
    scenarios: $scenarios, maxHours: $maxHours, m23: $m23, fixturesOnly: ($fixturesOnly == 1), fixtureSet: $fixtureSet,
    afterGolden: $afterGolden, plan: ($plan == 1)}, real: {home: $home, kubeconfig: $kubeconfig, tools: $tools},
    workingRepo: $workingRepo, runDir: $runDir, createdAt: $at}' >"$RUN_DIR/run.json.tmp" \
  && mv -f -- "$RUN_DIR/run.json.tmp" "$RUN_DIR/run.json" || fail 10 "cannot write run.json"
teardown_cmd="benchmark/lab/teardown-by-tag.sh --run-id $run_id --region $region --account $account"
printf '%s\n' "$teardown_cmd" >"$RUN_DIR/TEARDOWN-COMMAND.txt"
printf '{"runId":"%s","entries":[]}\n' "$run_id" >"$RUN_DIR/CREATED.json"
log "run $run_id: lab $LAB, repository $REPO_NAME, run directory $RUN_DIR"
log "if this host dies, tear down by hand from any machine: $teardown_cmd"

# --- P0.6 the lab environment's directories ------------------------------------
mkdir -m 700 -- "$RUN_DIR/home" "$RUN_DIR/tmp" "$RUN_DIR/bin" || fail 10 "cannot create the lab directories"
aws_config=${AWS_CONFIG_FILE:-$REAL_HOME/.aws/config}
aws_credentials=${AWS_SHARED_CREDENTIALS_FILE:-$REAL_HOME/.aws/credentials}
pause_at P0.6

# --- P1 preflight (read-only) ---------------------------------------------------
phase=P1
real() { local t=$1; shift; bench_cmdlog run.sh "$(bench_access "$t" "$@")" "$(bench_target "$@")" "$t" "$@"; "${REAL[$t]}" "$@"; }
awsr() { real aws --region "$region" --output json "$@" 2>"$RUN_DIR/tmp/aws.err"; }
aws_err() { head -c 300 "$RUN_DIR/tmp/aws.err" | tr '\n' ' '; }

# P1.1 tools match tools.lock; the unshimmed ones are linked into RUN_DIR/bin.
version_of() {
  local p=${REAL[$1]}
  case $1 in
    kubectl) "$p" version --client -o json | jq -r '.clientVersion.gitVersion' ;;
    helm) "$p" version --template '{{.Version}}' ;;
    aws) "$p" --version 2>&1 | sed -n 's#^aws-cli/\([^ ]*\).*#\1#p' ;;
    eksctl|crane) "$p" version ;;
    git) "$p" --version | awk '{print $3}' ;;
    python3) "$p" --version 2>&1 | awk '{print $2}' ;;
    jq) "$p" --version | sed 's/^jq-//' ;;
    go) "$p" version | awk '{print $3}' | sed 's/^go//' ;;
  esac 2>/dev/null | head -n 1 | sed 's/^v//'
}
[[ -f $LAB_DIR/tools.lock ]] || refuse "benchmark/lab/tools.lock is missing"
problems=()
for t in "${TOOLS[@]}"; do
  want=$(awk -v t="$t" '$1 == t {print $2}' "$LAB_DIR/tools.lock")
  want=${want#v}
  if [[ -z $want ]]; then problems+=("$t: not listed in tools.lock")
  elif [[ $want == UNSET ]]; then problems+=("$t: tools.lock is UNSET (DEVOPS owner step 1 pins it)")
  elif [[ -z ${REAL[$t]} ]]; then problems+=("$t: not installed (need $want)")
  else
    have=$(version_of "$t")
    [[ $have == "$want" ]] || problems+=("$t: ${have:-unknown}, tools.lock says $want")
  fi
done
((${#problems[@]} == 0)) || refuse "tools do not match benchmark/lab/tools.lock: ${problems[*]}"
for t in "${TOOLS[@]}"; do
  [[ " ${SHIMMED[*]} " == *" $t "* ]] || ln -s -- "${REAL[$t]}" "$RUN_DIR/bin/$t"
done
log "tools match tools.lock"
pause_at P1.1

# P1.2 identity.
for v in AWS_REGION AWS_DEFAULT_REGION; do
  [[ -z ${!v:-} || ${!v} == "$region" ]] || refuse "$v=${!v} differs from --region $region"
done
caller=$(awsr sts get-caller-identity | jq -r .Account) || refuse "aws sts get-caller-identity failed: $(aws_err)"
[[ $caller == "$account" ]] || refuse "AWS credentials are for account $caller, not --aws-account $account"
log "AWS account $account, region $region"
pause_at P1.2

# P1.3 the repository is clean; record it; snapshot it read-only; install the shims.
dirty=$(GIT_OPTIONAL_LOCKS=0 "${REAL[git]}" -C "$WORKING_REPO" status --porcelain --ignored) || refuse "git status failed"
[[ -z $dirty ]] || refuse "the repository is not clean (git status --porcelain --ignored): $(head -n 3 <<<"$dirty" | tr '\n' ' ')"
repo_state >"$RUN_DIR/REPO-BEFORE.txt" || refuse "cannot record the repository state"
touch -- "$RUN_DIR/REPO-BEFORE.stamp"
head=$(GIT_OPTIONAL_LOCKS=0 "${REAL[git]}" -C "$WORKING_REPO" rev-parse HEAD)
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
  "${REAL[git]}" clone --quiet --no-hardlinks -- "$WORKING_REPO" "$RUN_DIR/repo" || refuse "cannot snapshot the repository"
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "${REAL[git]}" -C "$RUN_DIR/repo" -c advice.detachedHead=false \
  checkout --quiet --detach "$head" || refuse "cannot check out $head in the snapshot"
[[ $("${REAL[git]}" -C "$RUN_DIR/repo" rev-parse HEAD) == "$head" ]] || refuse "the snapshot is not at $head"
chmod -R a-w -- "$RUN_DIR/repo"
mkdir -m 700 -- "$RUN_DIR/shims"
cp -- "$RUN_DIR/repo/benchmark/lab/shims/"* "$RUN_DIR/shims/" || refuse "the snapshot has no benchmark/lab/shims"
resolved=$(labenv bash -c 'command -v kubectl; command -v helm; command -v aws')
expected=$(printf '%s\n' "$RUN_DIR/shims/kubectl" "$RUN_DIR/shims/helm" "$RUN_DIR/shims/aws")
[[ $resolved == "$expected" ]] || refuse "in the lab environment kubectl, helm and aws do not resolve to $RUN_DIR/shims"
# The lab environment carries the allowlist and nothing else (names only are recorded).
lab_env_allowed=' HOME TMPDIR PATH LANG KUBECONFIG LAB_KUBECONFIG LAB_CONTEXT LAB_EXPECTED_SERVER LAB_FORBIDDEN_SERVERS
  BENCH_DEV_CLUSTER RUN_DIR REPO_SNAPSHOT WORKING_REPO GOLDEN_DIR LITELLM_LIVE_WORK GIT_OPTIONAL_LOCKS GIT_CONFIG_NOSYSTEM
  PYTHONDONTWRITEBYTECODE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_REGION AWS_DEFAULT_REGION AWS_PAGER AWS_PROFILE
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN PWD OLDPWD SHLVL _ '
labenv env -0 | tr '\0' '\n' | sed 's/=.*//' | LC_ALL=C sort -u >"$RUN_DIR/LAB-ENV.txt"
unexpected=$(while read -r n; do [[ $lab_env_allowed == *[[:space:]]"$n"[[:space:]]* ]] || printf '%s ' "$n"; done <"$RUN_DIR/LAB-ENV.txt")
[[ -z $unexpected ]] || refuse "the lab environment carries variables outside the allowlist: $unexpected"
log "repository clean at $head; read-only snapshot at $RUN_DIR/repo; kubectl, helm and aws resolve to the shims"
pause_at P1.3

# P1.4 the real kubeconfig, before.
kubeconfig_state >"$RUN_DIR/KUBECONFIG-BEFORE.sha256"
if [[ -e $real_kubeconfig ]]; then
  context=$("${REAL[kubectl]}" --kubeconfig "$real_kubeconfig" config current-context 2>/dev/null) || context='(none)'
else context='(absent)'; fi
log "real kubeconfig $real_kubeconfig, current context $context"
pause_at P1.4

# P1.5 dev, informational, and the server the lab must never reach.
dev=$(awsr eks describe-cluster --name "$DEV_CLUSTER") \
  || refuse "cannot describe $DEV_CLUSTER, whose endpoint the lab must never reach: $(aws_err)"
forbidden_servers=$(jq -r '.cluster.endpoint // ""' <<<"$dev")
[[ -n $forbidden_servers ]] || refuse "$DEV_CLUSTER has no endpoint"
export LAB_FORBIDDEN_SERVERS=$forbidden_servers  # COMMANDS.log classifies the dev endpoint as dev
jq -r '.cluster | "cluster \(.name)\nstatus \(.status)\nversion \(.version)\nendpoint \(.endpoint)"' <<<"$dev" >"$RUN_DIR/DEV-INFO.txt"
jq -n --arg lab "$LAB" --arg dev "$forbidden_servers" \
  '{labName: $lab, labContext: "", labServer: "", forbiddenServers: [$dev], oidcIssuer: "", oidcProviderArn: ""}' \
  >"$RUN_DIR/state.json.tmp" && mv -f -- "$RUN_DIR/state.json.tmp" "$RUN_DIR/state.json"
dev_context=''
if [[ -e $real_kubeconfig ]]; then
  dev_context=$("${REAL[kubectl]}" --kubeconfig "$real_kubeconfig" config view -o json 2>/dev/null | jq -r --arg s "$forbidden_servers" \
    '(.clusters // []) as $c | (.contexts // [])[] | select(.context.cluster as $n | any($c[]; .name == $n and .cluster.server == $s)) | .name' |
    head -n 1)
fi
# dev_read: get only, against dev, through the real kubeconfig; logged (DR-37).
dev_read() {
  [[ $1 == get ]] || fail 97 "dev_read allows only get, not $1"
  bench_cmdlog dev_read dev-read dev kubectl --context "$dev_context" "$@"
  "${REAL[kubectl]}" --kubeconfig "$real_kubeconfig" --context "$dev_context" --request-timeout=20s "$@"
}
dev_image=unavailable dev_image_ids=unavailable
if [[ -n $dev_context ]]; then
  dev_image=$(dev_read get deployment phorvex-phorvex -n phorvex-system \
    -o 'jsonpath={.spec.template.spec.containers[0].image}' 2>/dev/null) || dev_image=unavailable
  dev_image_ids=$(dev_read get pods -n phorvex-system -o json 2>/dev/null | jq -r \
    '[.items[] | select(.metadata.name | startswith("phorvex-phorvex-")) | .status.containerStatuses[]?.imageID] | unique | join(" ")') \
    || dev_image_ids=unavailable
else
  log "no context in $real_kubeconfig points at $DEV_CLUSTER; the Old image for page 1 is unavailable"
fi
printf 'image %s\nimageIDs %s\n' "${dev_image:-unavailable}" "${dev_image_ids:-unavailable}" >>"$RUN_DIR/DEV-INFO.txt"
log "dev $DEV_CLUSTER at $forbidden_servers is forbidden to the lab; Old image ${dev_image:-unavailable}"
pause_at P1.5

# P1.6 the M-23 gate (DR-26).
all=$(ps -eo pid=,args=)
watchers=$(grep -E "$M23_PATTERN" <<<"$all" || true)
{
  echo "## M-23 watcher processes (/$M23_PATTERN/)"; echo "${watchers:-none}"
  echo '## /tmp/m23_* and /tmp/reader-l3.yaml'
  ls -l --time-style=+%Y-%m-%dT%H:%M:%S /tmp/m23_* /tmp/reader-l3.yaml 2>/dev/null || echo none
  echo '## kubectl processes without --context'
  grep -E '(^|[ /])kubectl( |$)' <<<"$all" | grep -v -- '--context' || echo none
} >>"$RUN_DIR/PREFLIGHT.txt"
if [[ -n $watchers ]]; then
  [[ $m23 == fixed ]] || refuse "--m23 stopped, but the M-23 watcher is running: $(awk '{print $1}' <<<"$watchers" | paste -sd' ')"
  unrecorded=()
  while read -r pid args; do
    script=$(awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.sh$/) {print $i; exit}}' <<<"$args")
    sha=''
    [[ -n $script && -f $script ]] && sha=$(sha256sum <"$script" | cut -d' ' -f1)
    grep -vE '^[[:space:]]*(#|$)' "$LAB_DIR/m23-fixed.sha256" | awk '{print $1}' | grep -qx "${sha:-none}" \
      || unrecorded+=("$pid${script:+ ($script)}")
  done <<<"$watchers"
  ((${#unrecorded[@]} == 0)) || refuse "--m23 fixed, but these watchers are not a recorded fixed version: ${unrecorded[*]}"
fi
log "M-23 gate: --m23 $m23, $( [[ -n $watchers ]] && echo 'watcher(s) are a recorded fixed version' || echo 'no watcher running')"
pause_at P1.6

# P1.7 the run's names are free.
[[ $LAB =~ ^phorvex-281-lab-[0-9a-f]{6}$ && $REPO_NAME =~ ^phorvex-281-temp-[0-9a-f]{6}$ ]] || refuse "derived names are not in the allowlist"
must_be_absent() {
  local what=$1; shift
  if awsr "$@" >/dev/null; then refuse "$what already exists"; fi
  grep -qE 'NotFound|does not exist' "$RUN_DIR/tmp/aws.err" || refuse "cannot check $what: $(aws_err)"
}
must_be_absent "EKS cluster $LAB" eks describe-cluster --name "$LAB"
must_be_absent "ECR repository $REPO_NAME" ecr describe-repositories --repository-names "$REPO_NAME"
stacks=$(awsr cloudformation list-stacks | jq -r --arg p "eksctl-$LAB-" \
  '.StackSummaries[] | select((.StackName | startswith($p)) and .StackStatus != "DELETE_COMPLETE") | .StackName') \
  || refuse "cannot list CloudFormation stacks: $(aws_err)"
[[ -z $stacks ]] || refuse "stacks for $LAB already exist: $stacks"
log "no cluster, repository or stack named for run $run_id exists"
pause_at P1.7

# P1.8 EKS 1.36 is in standard support.
support=$(awsr eks describe-cluster-versions --cluster-versions "$EKS_VERSION" |
  jq -r '.clusterVersions[0] | (.versionStatus // .status // "absent")') || refuse "cannot read EKS versions: $(aws_err)"
[[ $support == STANDARD_SUPPORT ]] || refuse "EKS $EKS_VERSION is $support, not STANDARD_SUPPORT (DR-50)"
log "EKS $EKS_VERSION is in standard support"
pause_at P1.8

# P1.9 GPU quota: on-demand G and VT vCPUs free (L-DB2E81BA), re-checked at P3.
gpu_free() {
  local quota inst types vcpus used=0
  quota=$(awsr service-quotas get-service-quota --service-code ec2 --quota-code L-DB2E81BA | jq -r '.Quota.Value') || return 1
  inst=$(awsr ec2 describe-instances --filters Name=instance-state-name,Values=pending,running) || return 1
  types=$(jq -r '.Reservations[].Instances[] | select((.InstanceLifecycle // "") != "spot") | .InstanceType
    | select(test("^(g|vt)[0-9]"))' <<<"$inst")
  if [[ -n $types ]]; then
    # shellcheck disable=SC2046  # one argument per distinct instance type
    vcpus=$(awsr ec2 describe-instance-types --instance-types $(sort -u <<<"$types") |
      jq -r '.InstanceTypes[] | "\(.InstanceType) \(.VCpuInfo.DefaultVCpus)"') || return 1
    used=$(awk 'NR == FNR {v[$1] = $2; next} {s += v[$1]} END {print s + 0}' <(echo "$vcpus") <(echo "$types"))
  fi
  awk -v q="$quota" -v u="$used" 'BEGIN {printf "%d\n", q - u}'
}
free=$(gpu_free) || refuse "cannot read the G and VT vCPU quota or usage: $(aws_err)"
((free >= GPU_VCPUS)) || refuse "only $free on-demand G/VT vCPUs are free; the GPU node needs $GPU_VCPUS (quota L-DB2E81BA)"
log "$free on-demand G/VT vCPUs free"
pause_at P1.9

# P1.10 cost: the cap (checked with the arguments) and the budget alert.
awsr budgets describe-budget --account-id "$account" --budget-name "$BUDGET" >/dev/null \
  || refuse "the AWS Budgets alert $BUDGET is missing (DEVOPS prerequisite C-7, DR-51): $(aws_err)"
if ! awsr ce list-cost-allocation-tags --tag-keys phorvex.ai/benchmark --status Active |
    jq -e '(.CostAllocationTags // []) | length > 0' >/dev/null 2>&1; then
  log "WARNING: cost-allocation tag phorvex.ai/benchmark is not active (R7-1); DEVOPS activates it after the first lab"
  echo 'WARNING cost-allocation tag phorvex.ai/benchmark is not active' >>"$RUN_DIR/PREFLIGHT.txt"
fi
log "budget $BUDGET exists; at most $max_hours h x \$1.60 = \$$((max_hours * COST_CENTS_PER_HOUR / 100)).$(printf '%02d' $((max_hours * COST_CENTS_PER_HOUR % 100)))"
pause_at P1.10

# --- the plan for P2-P9 --------------------------------------------------------
phase=PLAN
not_built='[not implemented yet]'
log "P2: touch $RUN_DIR/P2-STARTED; benchmark/lab/build-image.sh --run-dir $RUN_DIR --run-id $run_id --ledger $RUN_DIR/CREATED.json --src-repo $WORKING_REPO --tag $new_tag --commit $new_commit${src_remote:+ --src-remote $src_remote} --region $region --account $account $not_built"
log "P3: render $RUN_DIR/cluster.yaml from benchmark/lab/cluster.lab.yaml.tmpl (EKS $EKS_VERSION, nodegroups system and gpu, tags phorvex.ai/lab-run=$run_id); eksctl create cluster -f $RUN_DIR/cluster.yaml --write-kubeconfig=false; eksctl utils write-kubeconfig --cluster $LAB --region $region --kubeconfig $RUN_DIR/kubeconfig $not_built"
log "P4: CRDs; namespaces; ConfigMap phorvex-system/phorvex-killswitch engaged=true; audit mTLS $not_built"
log "P5: fixtures (${fixture_set:-real}); policies to dryRun; helm upgrade --install phorvex <snapshot>/phorvex/charts/phorvex -n phorvex-system${extra_args:+ with extraArgs [$extra_args]}; golden $not_built"
if ((fixtures_only)); then
  log "P6-P7: skipped (--fixtures-only)${after_golden:+; after golden: $after_golden}"
else
  log "P6: scenarios $scenarios, arms Baseline then Old, New shadow-only; P7: PDFs and INPUTS in $RUN_DIR/out $not_built"
fi
log "P8: $teardown_cmd --proof $RUN_DIR/TEARDOWN-PROOF.txt (only once P2 has started a create)"
log "P9: COMMANDS.log, kubeconfig sha256, REPO-BEFORE = REPO-AFTER, then the run-directory cleanup"
exit 0
