#!/usr/bin/env bash
# Run the LiteLLM-defense benchmark in two modes and collect the brain's decision records.
#
#   defended   — operator-refactored acting (kill switch off): the foothold is contained
#                by the native rotate actuator; dwell time = fire -> rotation.
#   undefended — operator-refactored actuation off (kill switch engaged): the brain still
#                believes and evaluates the foothold, but does not act, so the attack lands
#                and the attacker dwells for the whole observation window.
#
# The "attack" is the product's own catalogue foothold: a trusted SecurityEvent, the same
# signal the console's workload attack creates. The operator's own ValidatingAdmissionPolicy
# stamps its creator-identity, so the benchmark fires it as the bench-redteam identity
# (kubectl --as) and the brain believes it. No exploit or model payload is involved.
#
# Run as root (it reads the K3s kubeconfig and drives Helm):
#   sudo deploy/benchmarks/litellm-defense/benchmark.sh
#   sudo WINDOW=180 deploy/benchmarks/litellm-defense/benchmark.sh
#
# Then build the reports:
#   python3 deploy/benchmarks/litellm-defense/report.py
set -euo pipefail

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
NS="${NS:-litellm}"
REDTEAM="${REDTEAM:-system:serviceaccount:phorvex-system:bench-redteam}"
WINDOW="${WINDOW:-150}"     # seconds to watch for containment
POLL="${POLL:-3}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"
DATA="$HERE/data"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

K() { k3s kubectl "$@"; }
HELM() { helm "$@"; }
say() { printf '\n==> %s\n' "$*"; }
manager_deploy="${RELEASE}-phorvex"

set_defense() {    # $1 = on|off
  local kill=false; [ "$1" = off ] && kill=true
  say "defense $1 (globalKillSwitch=$kill)"
  HELM upgrade "$RELEASE" "$CHART" -n "$OPNS" --reuse-values \
    --set phorvex.globalKillSwitch="$kill" --wait --timeout 6m >/dev/null
  K -n "$OPNS" rollout status deploy/"$manager_deploy" --timeout=5m >/dev/null
}

reset_target() {
  K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
  K -n "$NS" rollout restart deploy/litellm >/dev/null
  K -n "$NS" rollout status deploy/litellm --timeout=4m >/dev/null
  sleep 20   # let the fresh pods accumulate a request rate before the brain prices a move
}

# The latest decision record the manager logged for a pod, as compact JSON (or "null").
# Tolerant of no match (grep returns 1 on an empty poll, which must not abort under set -e).
capture_decision() {   # $1 = pod short name
  local out
  out="$(K -n "$OPNS" logs deploy/"$manager_deploy" -c manager --since=4m 2>/dev/null \
    | { grep '"msg":"decision"' || true; } | { grep -- "$1" || true; } | tail -1)"
  [ -n "$out" ] || { echo null; return 0; }
  printf '%s' "$out" | python3 -c 'import sys,json; l=sys.stdin.read().strip(); print(json.dumps(json.loads(l)) if l else "null")' 2>/dev/null || echo null
}

run_mode() {   # $1 = defended|undefended ; $2 = on|off
  local mode="$1"
  set_defense "$2"
  reset_target
  local target; target="$(K -n "$NS" get pod -l app.kubernetes.io/name=litellm -o jsonpath='{.items[0].metadata.name}')"
  [ -n "$target" ] || { echo "no litellm pod to target" >&2; return 1; }
  local before; before="$(K -n "$NS" get pods -l app.kubernetes.io/name=litellm -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')"
  local event="redteam-${mode}-$(date +%s)"
  local fired_at; fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "$mode: firing the trusted foothold at $NS/$target"
  cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: $event
  labels: {benchmark: litellm-defense}
  annotations:
    phorvex.ai/creator-identity: $REDTEAM
    phorvex.ai/redteam: "true"
spec:
  description: "benchmark foothold on $NS/$target"
  rule: {source: ExternalDetector, threatLevel: critical, type: Panic}
  targets: ["$NS/$target"]
YAML

  local rotated_at="null" decision="null" t=0
  while [ "$t" -lt "$WINDOW" ]; do
    local d; d="$(capture_decision "$target")"
    [ "$d" != "null" ] && decision="$d"
    if ! K -n "$NS" get pod "$target" >/dev/null 2>&1 \
       || [ -n "$(K -n "$NS" get pod "$target" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]; then
      rotated_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; break
    fi
    sleep "$POLL"; t=$((t + POLL))
  done
  [ "$decision" = null ] && decision="$(capture_decision "$target")"
  local after; after="$(K -n "$NS" get pods -l app.kubernetes.io/name=litellm -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')"

  python3 - "$DATA/$mode.json" "$mode" "$2" "$fired_at" "$rotated_at" "$event" "$target" "$before" "$after" "$decision" <<'PY'
import sys, json
path, mode, defense, fired, rotated, ev, pod, before, after, decision = sys.argv[1:]
json.dump({"mode": mode, "defense": defense, "firedAt": fired, "rotatedAt": json.loads(rotated),
           "attackId": ev, "targetPod": pod, "podsBefore": before.split(), "podsAfter": after.split(),
           "decision": json.loads(decision)}, open(path, "w"), indent=2)
print("wrote", path)
PY
}

mkdir -p "$DATA"
run_mode defended on
run_mode undefended off
set_defense on   # leave the operator acting
K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true

say "collected $DATA/defended.json and $DATA/undefended.json"
echo "build the reports:  python3 $HERE/report.py"
