#!/usr/bin/env bash
# Run the LiteLLM/vLLM defense benchmark: several attacks against each workload, in two modes,
# collecting the attacker dwell time and the brain's decision record for every attack.
#
#   defended   — operator-refactored acting (kill switch off): the foothold is contained by
#                the native rotate actuator; dwell = fire -> target pod rotated away.
#   undefended — operator-refactored actuation off (kill switch engaged): nothing rotates the
#                target, so the attack lands and the attacker dwells for the whole window.
#
# The "attack" is the product's own catalogue foothold: a trusted SecurityEvent, the same
# signal the console's workload attack creates. The operator's own ValidatingAdmissionPolicy
# stamps its creator-identity, so the benchmark fires it as the bench-redteam identity
# (kubectl --as) and the brain believes it. No exploit or model payload is involved.
#
# Targets (both carry a measured request rate via their nginx sidecar, so rotate is priced):
#   litellm — the 3-replica proxy
#   vllm    — the single GPU-backed model server
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
NS="${NS:-litellm}"
REDTEAM="${REDTEAM:-system:serviceaccount:phorvex-system:bench-redteam}"
TARGETS="${TARGETS:-litellm vllm}"   # workloads to attack (deployment == app.kubernetes.io/name)
ATTACKS="${ATTACKS:-3}"              # attacks per workload per mode (3..5)
WINDOW_DEF="${WINDOW_DEF:-120}"      # defended: seconds to wait for containment
WINDOW_UNDEF="${WINDOW_UNDEF:-45}"   # undefended: seconds to confirm non-containment
SETTLE="${SETTLE:-20}"               # seconds for fresh pods to accumulate a request rate
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

set_defense() {    # $1 = on|off  (on => kill switch false => actuator acts)
  local kill=true; [ "$1" = on ] && kill=false
  say "defense $1 (globalKillSwitch=$kill)"
  HELM upgrade "$RELEASE" "$CHART" -n "$OPNS" --reuse-values \
    --set phorvex.globalKillSwitch="$kill" --wait --timeout 6m >/dev/null
  K -n "$OPNS" rollout status deploy/"$manager_deploy" --timeout=5m >/dev/null
}

# Bring a target deployment back to a clean, loaded state before the next attack.
reset_target() {   # $1 = deployment/app name
  K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
  K -n "$NS" rollout status deploy/"$1" --timeout=6m >/dev/null 2>&1 || true
  sleep "$SETTLE"   # let the (possibly fresh) pods accumulate a request rate before pricing
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
  local window="$WINDOW_DEF"; [ "$mode" = undefended ] && window="$WINDOW_UNDEF"
  reset_target "$target"

  local pod; pod="$(K -n "$NS" get pod -l app.kubernetes.io/name="$target" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  [ -n "$pod" ] || { echo "  no running $target pod to target; skipping" >&2; return 0; }

  local event="redteam-${mode}-${target}-${attempt}-$(date +%s)"
  local fired_at; fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "$mode #$attempt: firing the trusted foothold at $NS/$pod ($target)"
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
  description: "benchmark foothold on $NS/$pod"
  rule: {source: ExternalDetector, threatLevel: critical, type: Panic}
  targets: ["$NS/$pod"]
YAML

  local rotated_at="null" decision="null" t=0
  while [ "$t" -lt "$window" ]; do
    local d; d="$(capture_decision "$pod")"
    [ "$d" != "null" ] && decision="$d"
    if ! K -n "$NS" get pod "$pod" >/dev/null 2>&1 \
       || [ -n "$(K -n "$NS" get pod "$pod" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]; then
      rotated_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; break
    fi
    sleep "$POLL"; t=$((t + POLL))
  done
  [ "$decision" = null ] && decision="$(capture_decision "$pod")"

  python3 - "$RESULTS" "$mode" "$2" "$target" "$attempt" "$fired_at" "$rotated_at" "$event" "$pod" "$decision" <<'PY'
import sys, json
path, mode, defense, target, attempt, fired, rotated, ev, pod, decision = sys.argv[1:]
rec = {"mode": mode, "defense": defense, "target": target, "attempt": int(attempt),
       "firedAt": fired, "rotatedAt": json.loads(rotated), "attackId": ev,
       "targetPod": pod, "decision": json.loads(decision)}
with open(path, "a") as f:
    f.write(json.dumps(rec) + "\n")
print("  recorded", mode, target, "#"+attempt, "rotated=" + ("yes" if rotated != "null" else "no"))
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

say "collected $(wc -l < "$RESULTS" | tr -d ' ') attack records in $RESULTS"
echo "build the reports:  python3 $HERE/report.py"
