#!/usr/bin/env bash
# Scenario benchmark: run several named catalogue attacks against the serving workloads,
# each defended by the actuator the attack library assigns it, in two modes.
#
#   defended   — operator-refactored acting (kill switch off): the attack is contained by
#                its actuator (quarantine isolates the pod in place; rotate replaces it).
#   undefended — operator-refactored actuation off (kill switch engaged): nothing contains
#                the attack, so it lands and the attacker dwells the whole window.
#
# Each attack is injected as the product's own foothold signal — a trusted SecurityEvent
# fired as the bench-redteam identity (kubectl --as), admitted by the operator's own
# creator-identity policy. The attack's designated actuator is enabled on its workload's
# PhorvexPolicy for the run, so the brain contains it with that actuator. No exploit,
# model payload, or third party is involved; the attacks are catalogue scenarios from the
# ATLAS/OWASP mapping (phorvex attack library), scoped to what the native backend
# implements (rotate, quarantine).
#
# SCENARIOS: one per line, "atlasId|name|actuator|target". Defaults below.
#
# Run as root:
#   sudo deploy/benchmarks/litellm-defense/scenarios.sh
# Then: python3 deploy/benchmarks/litellm-defense/report-scenarios.py
set -euo pipefail

OPNS="${OPNS:-phorvex-system}"
RELEASE="${RELEASE:-bench}"
REDTEAM="${REDTEAM:-system:serviceaccount:phorvex-system:bench-redteam}"
WINDOW_DEF="${WINDOW_DEF:-120}"
WINDOW_UNDEF="${WINDOW_UNDEF:-45}"
SETTLE="${SETTLE:-45}"
POLL="${POLL:-3}"

# Each serving foothold is contained by ROTATE (replace the compromised pod) — the native
# MTD action that fires reproducibly in this harness. The attack library prefers `quarantine`
# (isolate in place) for several of these; quarantine is implemented and fired once in an
# isolated manual test, but did not reproduce reliably when driven in-run here, so the
# reproducible benchmark uses rotate. See README "Notes and limits".
SCENARIOS="${SCENARIOS:-$(cat <<'EOF'
AML.T0029|Denial of AI Service|rotate|litellm
AML.T0044|Full AI Model Access|rotate|litellm
AML.T0046|Spamming AI System with Chaff Data|rotate|litellm
MTD.FOOTHOLD|Compromised serving-pod foothold|rotate|litellm
AML.T0029|Denial of AI Service|rotate|vllm
EOF
)}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"
DATA="$HERE/data"
RESULTS="$DATA/scenarios.jsonl"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

K() { k3s kubectl "$@"; }
HELM() { helm "$@"; }
say() { printf '\n==> %s\n' "$*"; }
manager_deploy="${RELEASE}-phorvex"
ns_for() { case "$1" in litellm) echo litellm;; *) echo "$1";; esac; }
policy_for() { echo "$1-defense"; }

set_defense() {    # $1 = on|off
  local kill=true; [ "$1" = on ] && kill=false
  say "defense $1 (globalKillSwitch=$kill)"
  HELM upgrade "$RELEASE" "$CHART" -n "$OPNS" --reuse-values \
    --set phorvex.globalKillSwitch="$kill" --wait --timeout 6m >/dev/null
  K -n "$OPNS" rollout status deploy/"$manager_deploy" --timeout=5m >/dev/null
}

set_actuator() {   # $1 = target ; $2 = actuator
  K -n "$(ns_for "$1")" patch phorvexpolicy "$(policy_for "$1")" --type merge \
    -p "{\"spec\":{\"actions\":{\"enabled\":[\"$2\"]}}}" >/dev/null 2>&1 || true
}

reset_target() {   # $1 = target
  local ns; ns="$(ns_for "$1")"
  K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
  K -n "$ns" delete networkpolicy -l app.kubernetes.io/managed-by=phorvex --ignore-not-found >/dev/null 2>&1 || true
  local p
  for p in $(K -n "$ns" get pod -l app.kubernetes.io/name="$1" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null); do
    K -n "$ns" label pod "$p" phorvex.ai/quarantine-epoch- >/dev/null 2>&1 || true
  done
  K -n "$ns" rollout status deploy/"$1" --timeout=6m >/dev/null 2>&1 || true
  local i term
  for i in $(seq 1 60); do
    term="$(K -n "$ns" get pod -l app.kubernetes.io/name="$1" -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"\n"}{end}' 2>/dev/null | grep -c . || true)"
    [ "${term:-0}" -eq 0 ] && break; sleep 3
  done
  sleep "$SETTLE"
}

capture_decision() {   # $1 = pod name
  local out
  out="$(K -n "$OPNS" logs deploy/"$manager_deploy" -c manager --since=5m 2>/dev/null \
    | { grep '"msg":"decision"' || true; } | { grep -- "$1" || true; } | tail -1)"
  [ -n "$out" ] || { echo null; return 0; }
  printf '%s' "$out" | python3 -c 'import sys,json; l=sys.stdin.read().strip(); print(json.dumps(json.loads(l)) if l else "null")' 2>/dev/null || echo null
}

run_scenario() {   # $1 mode ; $2 defense on|off ; $3 atlasId ; $4 name ; $5 actuator ; $6 target
  local mode="$1" atlas="$3" name="$4" actuator="$5" target="$6"
  local ns; ns="$(ns_for "$target")"
  local window="$WINDOW_DEF"; [ "$mode" = undefended ] && window="$WINDOW_UNDEF"
  set_actuator "$target" "$actuator"
  reset_target "$target"
  local pod; pod="$(K -n "$ns" get pod -l app.kubernetes.io/name="$target" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"~"}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | awk -F'~' '$1==""{print $2; exit}')"
  [ -n "$pod" ] || { echo "  no running $target pod; skipping $atlas" >&2; return 0; }
  local event="redteam-${mode}-${target}-$(echo "$atlas" | tr '.:' '--' | tr 'A-Z' 'a-z')-$(date +%s)"
  local fired_at; fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "$mode: $atlas ($name) -> $actuator on $ns/$pod"
  cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: $event
  labels: {benchmark: litellm-defense}
  annotations:
    phorvex.ai/creator-identity: $REDTEAM
    phorvex.ai/redteam: "true"
    benchmark.phorvex.ai/atlas: "$atlas"
spec:
  description: "$atlas $name on $ns/$pod"
  rule: {source: ExternalDetector, threatLevel: critical, type: Panic}
  targets: ["$ns/$pod"]
YAML
  local contained_at="null" mechanism="null" decision="null" t=0
  while [ "$t" -lt "$window" ]; do
    local d; d="$(capture_decision "$pod")"; [ "$d" != "null" ] && decision="$d"
    if ! K -n "$ns" get pod "$pod" >/dev/null 2>&1 \
       || [ -n "$(K -n "$ns" get pod "$pod" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]; then
      contained_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; mechanism='"rotated"'; break
    fi
    if [ -n "$(K -n "$ns" get networkpolicy -l app.kubernetes.io/managed-by=phorvex -o name 2>/dev/null)" ] \
       || [ -n "$(K -n "$ns" get pod "$pod" -o jsonpath='{.metadata.labels.phorvex\.ai/quarantine-epoch}' 2>/dev/null)" ]; then
      contained_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; mechanism='"quarantined"'; break
    fi
    sleep "$POLL"; t=$((t + POLL))
  done
  [ "$decision" = null ] && decision="$(capture_decision "$pod")"

  python3 - "$RESULTS" "$mode" "$2" "$atlas" "$name" "$actuator" "$target" "$fired_at" "$contained_at" "$mechanism" "$event" "$pod" "$decision" <<'PY'
import sys, json
path, mode, defense, atlas, name, actuator, target, fired, contained, mechanism, ev, pod, decision = sys.argv[1:]
rec = {"mode": mode, "defense": defense, "atlasId": atlas, "name": name, "actuator": actuator,
       "target": target, "firedAt": fired, "containedAt": json.loads(contained),
       "mechanism": json.loads(mechanism), "attackId": ev, "targetPod": pod,
       "decision": json.loads(decision)}
open(path, "a").write(json.dumps(rec) + "\n")
print("  recorded", mode, atlas, target, "contained=" + ("no" if contained == "null" else json.loads(mechanism)))
PY
}

run_mode() {   # $1 mode ; $2 defense on|off
  set_defense "$2"
  while IFS='|' read -r atlas name actuator target; do
    [ -n "${atlas:-}" ] || continue
    run_scenario "$1" "$2" "$atlas" "$name" "$actuator" "$target"
  done <<EOF
$SCENARIOS
EOF
}

mkdir -p "$DATA"; : > "$RESULTS"
run_mode defended on
run_mode undefended off
set_defense on
K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
for t in litellm vllm; do K -n "$(ns_for "$t")" delete networkpolicy -l app.kubernetes.io/managed-by=phorvex --ignore-not-found >/dev/null 2>&1 || true; done

say "collected $(wc -l < "$RESULTS" | tr -d ' ') scenario records in $RESULTS"
echo "build the report:  python3 $HERE/report-scenarios.py"
