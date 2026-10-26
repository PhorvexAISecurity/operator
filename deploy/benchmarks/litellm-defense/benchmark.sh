#!/usr/bin/env bash
# Run the LiteLLM/vLLM defense benchmark: several attacks against each workload, in two modes,
# collecting the attacker dwell time and the brain's decision record for every attack.
#
#   defended   — operator-refactored acting (kill switch off): the foothold is contained by
#                the appropriate actuator; dwell = fire -> target contained.
#   undefended — operator-refactored actuation off (kill switch engaged): nothing contains the
#                target, so the attack lands and the attacker dwells for the whole window.
#
# The "attack" is the product's own catalogue foothold: a trusted SecurityEvent, the same
# signal the console's workload attack creates. The operator's own ValidatingAdmissionPolicy
# stamps its creator-identity, so the benchmark fires it as the bench-redteam identity
# (kubectl --as) and the brain believes it. No exploit or model payload is involved.
#
# Targets, each in its OWN namespace/tenant (a cluster-scoped SecurityEvent routes to a
# policy by its target's namespace), both with a measured request rate so actions are priced:
#   litellm (namespace litellm) — the 3-replica proxy, defended by rotate
#   vllm    (namespace vllm)    — the single GPU model server, defended by quarantine
#
# Run as root (it reads the K3s kubeconfig and drives Helm):
#   sudo deploy/benchmarks/litellm-defense/benchmark.sh
#   sudo ATTACKS=5 TARGETS="litellm vllm" deploy/benchmarks/litellm-defense/benchmark.sh
#
# Then build the reports:
#   python3 deploy/benchmarks/litellm-defense/report.py
set -euo pipefail

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
REDTEAM="${REDTEAM:-system:serviceaccount:phorvex-system:bench-redteam}"
TARGETS="${TARGETS:-litellm vllm}"   # workloads to attack (deployment == app.kubernetes.io/name)
ATTACKS="${ATTACKS:-3}"              # attacks per workload per mode (3..5)
WINDOW_DEF="${WINDOW_DEF:-120}"      # defended: seconds to wait for containment
WINDOW_UNDEF="${WINDOW_UNDEF:-45}"   # undefended: seconds to confirm non-containment
SETTLE="${SETTLE:-45}"               # seconds for a fresh (just-rotated) pod to re-accumulate a request rate
POLL="${POLL:-3}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"
DATA="$HERE/data"
RESULTS="$DATA/results.jsonl"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

K() { k3s kubectl "$@"; }
HELM() { helm "$@"; }
say() { printf '\n==> %s\n' "$*"; }
manager_deploy="${RELEASE}-phorvex"

# Each workload lives in its own namespace, named after the workload (vllm -> vllm); the
# LiteLLM proxy's namespace is litellm.
ns_for() { case "$1" in litellm) echo litellm;; *) echo "$1";; esac; }

set_defense() {    # $1 = on|off  (on => kill switch false => actuator acts)
  local kill=true; [ "$1" = on ] && kill=false
  say "defense $1 (globalKillSwitch=$kill)"
  HELM upgrade "$RELEASE" "$CHART" -n "$OPNS" --reuse-values \
    --set phorvex.globalKillSwitch="$kill" --wait --timeout 6m >/dev/null
  K -n "$OPNS" rollout status deploy/"$manager_deploy" --timeout=5m >/dev/null
}

# Bring a target deployment back to a clean, loaded state before the next attack.
reset_target() {   # $1 = deployment/app name
  local ns; ns="$(ns_for "$1")"
  K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
  # Clear any quarantine left by a previous attack so each attack starts from an un-isolated
  # pod. The threat (SecurityEvent) is already deleted, so the operator will not re-create it;
  # this also covers the switch into undefended mode, where the operator is off and cannot
  # recover its own quarantine.
  K -n "$ns" delete networkpolicy -l app.kubernetes.io/managed-by=phorvex --ignore-not-found >/dev/null 2>&1 || true
  local p
  for p in $(K -n "$ns" get pod -l app.kubernetes.io/name="$1" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null); do
    K -n "$ns" label pod "$p" phorvex.ai/quarantine-epoch- >/dev/null 2>&1 || true
  done
  K -n "$ns" rollout status deploy/"$1" --timeout=6m >/dev/null 2>&1 || true
  # Wait out any still-terminating pod from a previous rotation, so the next attack targets a
  # fresh, live pod rather than one already being deleted (vLLM terminates slowly).
  local i term
  for i in $(seq 1 60); do
    term="$(K -n "$ns" get pod -l app.kubernetes.io/name="$1" \
      -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"\n"}{end}' 2>/dev/null | grep -c . || true)"
    [ "${term:-0}" -eq 0 ] && break
    sleep 3
  done
  sleep "$SETTLE"   # let the (possibly fresh) single-replica pod re-accumulate a request rate
}

# The latest decision record the manager logged for a pod, as compact JSON (or "null").
# Tolerant of no match (grep returns 1 on an empty poll, which must not abort under set -e).
capture_decision() {   # $1 = pod name
  local out
  out="$(K -n "$OPNS" logs deploy/"$manager_deploy" -c manager --since=5m 2>/dev/null \
    | { grep '"msg":"decision"' || true; } | { grep -- "$1" || true; } | tail -1)"
  [ -n "$out" ] || { echo null; return 0; }
  printf '%s' "$out" | python3 -c 'import sys,json; l=sys.stdin.read().strip(); print(json.dumps(json.loads(l)) if l else "null")' 2>/dev/null || echo null
}

run_attack() {   # $1 = mode (defended|undefended) ; $2 = defense on|off ; $3 = target app ; $4 = attempt
  local mode="$1" target="$3" attempt="$4"
  local ns; ns="$(ns_for "$target")"
  local window="$WINDOW_DEF"; [ "$mode" = undefended ] && window="$WINDOW_UNDEF"
  reset_target "$target"

  # Pick a Running pod that is NOT already terminating (empty deletionTimestamp).
  local pod; pod="$(K -n "$ns" get pod -l app.kubernetes.io/name="$target" \
    --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"~"}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | awk -F'~' '$1==""{print $2; exit}')"
  [ -n "$pod" ] || { echo "  no running $target pod to target; skipping" >&2; return 0; }

  local event="redteam-${mode}-${target}-${attempt}-$(date +%s)"
  local fired_at; fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "$mode #$attempt: firing the trusted foothold at $ns/$pod ($target)"
  cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: $event
  labels: {benchmark: litellm-defense, benchmark-target: $target}
  annotations:
    phorvex.ai/creator-identity: $REDTEAM
    phorvex.ai/redteam: "true"
spec:
  description: "benchmark foothold on $ns/$pod"
  rule: {source: ExternalDetector, threatLevel: critical, type: Panic}
  targets: ["$ns/$pod"]
YAML

  # Containment is observed as either effect: the target pod rotated away (deleted), or the
  # target network-isolated in place by a quarantine NetworkPolicy / quarantine-epoch label.
  local rotated_at="null" mechanism="null" decision="null" t=0
  while [ "$t" -lt "$window" ]; do
    local d; d="$(capture_decision "$pod")"
    [ "$d" != "null" ] && decision="$d"
    if ! K -n "$ns" get pod "$pod" >/dev/null 2>&1 \
       || [ -n "$(K -n "$ns" get pod "$pod" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]; then
      rotated_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; mechanism='"rotated"'; break
    fi
    if K -n "$ns" get networkpolicy "phorvex-quarantine-$pod" >/dev/null 2>&1 \
       || [ -n "$(K -n "$ns" get pod "$pod" -o jsonpath='{.metadata.labels.phorvex\.ai/quarantine-epoch}' 2>/dev/null)" ]; then
      rotated_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; mechanism='"quarantined"'; break
    fi
    sleep "$POLL"; t=$((t + POLL))
  done
  [ "$decision" = null ] && decision="$(capture_decision "$pod")"

  python3 - "$RESULTS" "$mode" "$2" "$target" "$attempt" "$fired_at" "$rotated_at" "$mechanism" "$event" "$pod" "$decision" <<'PY'
import sys, json
path, mode, defense, target, attempt, fired, rotated, mechanism, ev, pod, decision = sys.argv[1:]
rec = {"mode": mode, "defense": defense, "target": target, "attempt": int(attempt),
       "firedAt": fired, "rotatedAt": json.loads(rotated), "mechanism": json.loads(mechanism),
       "attackId": ev, "targetPod": pod, "decision": json.loads(decision)}
with open(path, "a") as f:
    f.write(json.dumps(rec) + "\n")
print("  recorded", mode, target, "#"+attempt,
      "contained=" + ("no" if rotated == "null" else json.loads(mechanism)))
PY
}

run_mode() {   # $1 = mode (defended|undefended) ; $2 = defense on|off
  set_defense "$2"
  local target n
  for target in $TARGETS; do
    for n in $(seq 1 "$ATTACKS"); do
      run_attack "$1" "$2" "$target" "$n"
    done
  done
}

mkdir -p "$DATA"
: > "$RESULTS"   # fresh run
run_mode defended on
run_mode undefended off
set_defense on   # leave the operator acting
K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
for ns in $TARGETS; do K -n "$(ns_for "$ns")" delete networkpolicy -l app.kubernetes.io/managed-by=phorvex --ignore-not-found >/dev/null 2>&1 || true; done

say "collected $(wc -l < "$RESULTS" | tr -d ' ') attack records in $RESULTS"
echo "build the reports:  python3 $HERE/report.py"
