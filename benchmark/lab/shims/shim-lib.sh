# Shared by the lab shims (kubectl, helm, aws) and run.sh. Source it; it only
# defines functions. Not executable, so it is never found as a command on PATH.
#
# COMMANDS.log is one line per command, tab-separated:
#   time  source  access  target  argv
# source is run.sh, shim or dev_read; access is read, write, dev-read or
# refused; target is dev when the argv names the dev cluster or a forbidden API
# server, else lab. argv is recorded with secret values redacted, and command
# output is never recorded (ticket Part 2 §10.3). P9 fails the run on any
# refusal (97) and on any write that targets dev.

bench_redact() {
  local a redact=0
  for a in "$@"; do
    if ((redact)); then printf '%s\n' '<redacted>'; redact=0; continue; fi
    case $a in
      --token|--password|--client-secret|--kube-token) printf '%s\n' "$a"; redact=1 ;;
      --token=*|--password=*|--client-secret=*|--kube-token=*) printf '%s\n' "${a%%=*}=<redacted>" ;;
      --from-literal=*=*) a=${a#--from-literal=}; printf '%s\n' "--from-literal=${a%%=*}=<redacted>" ;;
      *) printf '%s\n' "$a" ;;
    esac
  done
}

# dev when the argv names the dev cluster or one of LAB_FORBIDDEN_SERVERS.
bench_target() {
  local a f
  for a in "$@"; do
    [[ -n ${BENCH_DEV_CLUSTER:-} && $a == *"$BENCH_DEV_CLUSTER"* ]] && { echo dev; return; }
    for f in ${LAB_FORBIDDEN_SERVERS:-}; do [[ $a == *"$f"* ]] && { echo dev; return; }; done
  done
  echo lab
}

# The first two words of an aws argv that are neither flags nor flag values.
bench_aws_op() {
  local -a words=()
  while (($#)); do
    case $1 in
      --region|--output|--profile|--query|--color|--endpoint-url|--cli-read-timeout|--cli-connect-timeout) shift 2 ;;
      -*) shift ;;
      *) words+=("$1"); shift ;;
    esac
  done
  echo "${words[0]:-} ${words[1]:-}"
}

# read or write, by the verb of the command.
bench_access() {
  local tool=$1 op; shift
  case $tool in
    aws)
      [[ " $* " == *" --version "* ]] && { echo read; return; }
      op=$(bench_aws_op "$@")
      case ${op#* } in describe-*|list-*|get-*|wait|batch-get-*) echo read ;; *) echo write ;; esac ;;
    kubectl)
      case ${BENCH_VERB:-} in
        get|describe|logs|top|explain|api-resources|api-versions|version|auth|cluster-info|wait|diff|events|port-forward) echo read ;;
        config) case ${BENCH_SUBVERB:-} in view|current-context|get-contexts|get-clusters|get-users) echo read ;; *) echo write ;; esac ;;
        *) echo write ;;
      esac ;;
    helm)
      case ${BENCH_VERB:-} in list|ls|status|get|history|show|template|version|lint) echo read ;; *) echo write ;; esac ;;
    *) echo write ;;
  esac
}

bench_cmdlog() {  # source access target argv...
  local source=$1 access=$2 target=$3; shift 3
  [[ -n ${RUN_DIR:-} && -d $RUN_DIR ]] || return 0
  local -a red=()
  mapfile -t red < <(bench_redact "$@")
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$source" "$access" "$target" "${red[*]}" \
    >>"$RUN_DIR/COMMANDS.log"
}

# --- shims only below -------------------------------------------------------

# A refusal reason is free text; scrub secret-bearing flag values from it too.
bench_scrub() {
  sed -E 's/(--(token|password|client-secret|kube-token))(=| +)[^ ]*/\1=<redacted>/g; s/(--from-literal=[^= ]*)=[^ ]*/\1=<redacted>/g' <<<"$*"
}

bench_refuse() {
  local reason
  reason=$(bench_scrub "$*")
  bench_cmdlog shim refused "$(bench_target "${BENCH_ARGS[@]}")" "$BENCH_TOOL" "${BENCH_ARGS[@]}" "# refused: $reason"
  printf 'lab %s shim: refused: %s\n' "$BENCH_TOOL" "$reason" >&2
  exit 97
}

# bench_init TOOL "$@": the real binary recorded in run.json, as REAL.
bench_init() {
  BENCH_TOOL=$1; shift
  BENCH_ARGS=("$@")
  [[ -n ${RUN_DIR:-} && -f $RUN_DIR/run.json ]] \
    || bench_refuse "RUN_DIR/run.json is missing; the lab shims run only inside run.sh's lab environment"
  REAL=$(jq -r --arg t "$BENCH_TOOL" '.real.tools[$t] // ""' "$RUN_DIR/run.json")
  REAL_KUBECTL=$(jq -r '.real.tools.kubectl // ""' "$RUN_DIR/run.json")
  [[ $REAL == /* && -x $REAL ]] || bench_refuse "run.json records no real $BENCH_TOOL"
}

# The environment, and the server the lab kubeconfig really points at, must be
# the lab's. Any helm or kubectl override of the target is refused by the caller.
bench_lab_target() {
  local v server current f
  [[ -n ${LAB_EXPECTED_SERVER:-} ]] || bench_refuse "LAB_EXPECTED_SERVER is empty: there is no lab cluster yet"
  [[ -n ${LAB_CONTEXT:-} && -n ${LAB_KUBECONFIG:-} ]] || bench_refuse "LAB_CONTEXT or LAB_KUBECONFIG is empty"
  [[ ${KUBECONFIG:-} != *:* && $LAB_KUBECONFIG != *:* ]] || bench_refuse "KUBECONFIG must be one file, not a list"
  [[ ${KUBECONFIG:-} == "$LAB_KUBECONFIG" ]] || bench_refuse "KUBECONFIG is ${KUBECONFIG:-unset}, not the lab kubeconfig"
  for v in $(compgen -e); do
    [[ $v != HELM_KUBE* ]] || bench_refuse "$v is set; helm must not be pointed anywhere but the lab"
  done
  [[ -n $REAL_KUBECTL && -x $REAL_KUBECTL ]] || bench_refuse "run.json records no real kubectl to check the lab kubeconfig with"
  current=$("$REAL_KUBECTL" --kubeconfig "$LAB_KUBECONFIG" config current-context 2>/dev/null) \
    || bench_refuse "the lab kubeconfig has no current context"
  [[ $current == "$LAB_CONTEXT" ]] || bench_refuse "the lab kubeconfig's current context is $current, not $LAB_CONTEXT"
  server=$("$REAL_KUBECTL" --kubeconfig "$LAB_KUBECONFIG" --context "$LAB_CONTEXT" config view --minify \
    -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null) || bench_refuse "cannot read the lab kubeconfig"
  for f in ${LAB_FORBIDDEN_SERVERS:-}; do
    [[ $server != "$f" ]] || bench_refuse "the kubeconfig points at forbidden server $server"
  done
  [[ $server == "$LAB_EXPECTED_SERVER" ]] || bench_refuse "the kubeconfig points at $server, not the lab's $LAB_EXPECTED_SERVER"
}
