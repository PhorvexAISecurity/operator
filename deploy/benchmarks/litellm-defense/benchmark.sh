#!/usr/bin/env bash
# Run the LiteLLM-defense benchmark in two modes and collect the brain's decision records.
#
#   defended   — operator-refactored acting (kill switch off): the foothold is contained
#                by the native rotate actuator; dwell time = fire -> rotation.
#   undefended — operator-refactored actuation off (kill switch engaged): the operator
#                still sees and evaluates the foothold, but does not act, so the attack
#                lands and the attacker dwells for the whole observation window.
#
# The "attack" is the product's own catalogue foothold: a synthetic, trusted SecurityEvent
# fired through the console API (POST /api/workload/attack) — the same signal the console
# fires at any governed workload. No exploit or model payload is involved.
#
#   deploy/benchmarks/litellm-defense/benchmark.sh
#   WINDOW=180 deploy/benchmarks/litellm-defense/benchmark.sh    # longer observation
#
# Then build the reports:
#   python3 deploy/benchmarks/litellm-defense/report.py
set -euo pipefail

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
NS="${NS:-litellm}"
AUDIENCE="${AUDIENCE:-phorvex-bench-console}"
WINDOW="${WINDOW:-150}"      # seconds to watch for containment
POLL="${POLL:-3}"

HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HERE/data"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
KUBECTL=(k3s kubectl)
command -v k3s >/dev/null 2>&1 || KUBECTL=(kubectl)

say() { printf '\n==> %s\n' "$*"; }
console_sa="${RELEASE}-phorvex-console-e2e"
console_deploy="${RELEASE}-phorvex-console"
manager_deploy="${RELEASE}-phorvex"

# A port-forward to the console pod (no Service without an ingress; it listens on 8090),
# torn down on exit.
PF_PID=""
open_console() {
  local port=$((20000 + RANDOM % 10000))
  "${KUBECTL[@]}" -n "$OPNS" port-forward "deploy/$console_deploy" "$port:8090" >/tmp/bench-pf.log 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$port/api/health" && break; sleep 1; done
  CONSOLE="http://127.0.0.1:$port"
}
close_console() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true; PF_PID=""; }
trap close_console EXIT

api() { curl -sS -m 150 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

reset_target() {
  # Fresh, non-quarantined pods, and no leftover rotation NetworkPolicy.
  "${KUBECTL[@]}" -n "$NS" delete networkpolicy -l app.kubernetes.io/managed-by=phorvex --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" -n "$NS" rollout restart deploy/litellm >/dev/null
  "${KUBECTL[@]}" -n "$NS" rollout status deploy/litellm --timeout=3m >/dev/null
}

set_defense() {    # $1 = on|off
  local kill=false; [ "$1" = off ] && kill=true
  say "defense $1 (globalKillSwitch=$kill)"
  helm upgrade "$RELEASE" "$HERE/../../../phorvex/charts/phorvex" -n "$OPNS" --reuse-values \
    --set phorvex.globalKillSwitch="$kill" --wait --timeout 5m >/dev/null
  "${KUBECTL[@]}" -n "$OPNS" rollout status deploy/"$manager_deploy" --timeout=5m >/dev/null
}

# Capture the latest decision for a pod from the live stream, as compact JSON (or "null").
capture_decision() {   # $1 = pod
  api "$CONSOLE/api/live?ms=3000" 2>/dev/null | python3 -c '
import sys, json
pod = sys.argv[1]; latest = None
for line in sys.stdin:
    if line.startswith("data: "):
        try:
            d = json.loads(line[6:])
        except Exception:
            continue
        if (d.get("pod") or "") == pod:
            latest = d
print(json.dumps(latest))
' "$1"
}

run_mode() {   # $1 = defended|undefended ; $2 = on|off
  local mode="$1"
  set_defense "$2"
  reset_target
  open_console
  TOKEN="$("${KUBECTL[@]}" -n "$OPNS" create token "$console_sa" --audience "$AUDIENCE" --duration 20m)"

  local before; before="$("${KUBECTL[@]}" -n "$NS" get pods -l app.kubernetes.io/name=litellm -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')"
  local fired_at; fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "$mode: firing the catalogue foothold at $NS"
  local resp; resp="$(api -X POST "$CONSOLE/api/workload/attack" -d "{\"namespace\":\"$NS\",\"action\":\"foothold\"}")"
  echo "    $resp"
  local attack_id target_pod
  attack_id="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("attackId",""))' 2>/dev/null || true)"
  target_pod="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("pod",""))' 2>/dev/null || true)"
  [ -n "$target_pod" ] || { echo "no target pod in response; aborting mode" >&2; close_console; return 1; }

  # Watch the target pod until it is gone (rotated/contained) or the window expires,
  # sampling the decision as we go.
  local rotated_at="null" decision="null" t=0
  while [ "$t" -lt "$WINDOW" ]; do
    local d; d="$(capture_decision "$target_pod")"
    [ "$d" != "null" ] && decision="$d"
    if ! "${KUBECTL[@]}" -n "$NS" get pod "$target_pod" >/dev/null 2>&1 \
       || [ "$("${KUBECTL[@]}" -n "$NS" get pod "$target_pod" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" != "" ]; then
      rotated_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""
      break
    fi
    sleep "$POLL"; t=$((t + POLL))
  done

  local after; after="$("${KUBECTL[@]}" -n "$NS" get pods -l app.kubernetes.io/name=litellm -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')"
  close_console
  python3 - "$DATA/$mode.json" "$mode" "$2" "$fired_at" "$rotated_at" "$attack_id" "$target_pod" "$before" "$after" "$decision" <<'PY'
import sys, json
path, mode, defense, fired, rotated, aid, pod, before, after, decision = sys.argv[1:]
json.dump({
    "mode": mode, "defense": defense, "firedAt": fired,
    "rotatedAt": json.loads(rotated), "attackId": aid, "targetPod": pod,
    "podsBefore": before.split(), "podsAfter": after.split(),
    "decision": json.loads(decision),
}, open(path, "w"), indent=2)
print("wrote", path)
PY
}

mkdir -p "$DATA"
run_mode defended on
run_mode undefended off
# Leave the operator acting when the benchmark ends.
set_defense on

say "collected $DATA/defended.json and $DATA/undefended.json"
echo "build the reports:  python3 $HERE/report.py"
