#!/usr/bin/env bash
# Read-only CI waiter, streamed to the jump host over SSH. Never resumes a paused app.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }
[[ ${V:-} =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || fail 'V must be an exact image tag'
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-60}
WAIT_INTERVAL_SECONDS=${WAIT_INTERVAL_SECONDS:-15}
[[ $WAIT_ATTEMPTS =~ ^[1-9][0-9]?$ ]] && (( WAIT_ATTEMPTS <= 60 )) || fail 'WAIT_ATTEMPTS must be 1..60'
[[ $WAIT_INTERVAL_SECONDS =~ ^[1-9][0-9]?$ ]] && (( WAIT_INTERVAL_SECONDS <= 15 )) || fail 'WAIT_INTERVAL_SECONDS must be 1..15'
for tool in kubectl python3; do
  command -v "$tool" >/dev/null || fail "Required tool is missing: $tool"
done
# Which components this release actually re-tagged (the ci: markers CI rewrote in
# values-eks.yaml). A console-only change re-tags only the console; the operator keeps its
# previous tag, so demanding :$V on the operator would spin until timeout and fail a rollout
# ArgoCD completed minutes earlier. Default to the operator alone for callers that predate
# MARKERS.
declare -A DEPLOY_FOR=( [ci:phorvex-tag]=phorvex-phorvex [ci:console-tag]=phorvex-phorvex-console )
declare -A CONTAINER_FOR=( [ci:phorvex-tag]=manager [ci:console-tag]=console )
TARGETS=()
for m in ${MARKERS:-ci:phorvex-tag}; do
  [[ -n ${DEPLOY_FOR[$m]:-} ]] || fail "Unknown release marker: $m"
  TARGETS+=("$m")
done

for (( attempt=1; attempt<=WAIT_ATTEMPTS; attempt++ )); do
  # Check the policy on each poll: an intentional pause must not be overridden,
  # and authorization/read failures must not masquerade as an image timeout.
  APP=$(kubectl -n argocd get application phorvex-stack --request-timeout=10s -o json) \
    || fail 'Cannot read argocd/phorvex-stack; check the Application and read permissions'
  POLICY=$(printf '%s' "$APP" | python3 -c '
import json, sys
try:
    app = json.load(sys.stdin)
    spec = app["spec"]
    if not isinstance(spec, dict):
        raise ValueError("spec is not an object")
    policy = spec.get("syncPolicy")
    if policy is not None and not isinstance(policy, dict):
        raise ValueError("syncPolicy is not an object")
    automated = (policy or {}).get("automated")
    if automated is None:
        print("absent")
    elif not isinstance(automated, dict):
        raise ValueError("automated is not an object")
    else:
        enabled = automated.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("enabled is not a boolean or null")
        print("disabled" if enabled is False else "enabled")
except (ValueError, KeyError, TypeError):
    sys.exit("Invalid Application response or automated sync policy")
') || fail 'Cannot determine automated sync policy; refusing to wait on invalid data'

  PENDING=()
  SUMMARY=""
  for m in "${TARGETS[@]}"; do
    D=${DEPLOY_FOR[$m]}; C=${CONTAINER_FOR[$m]}
    IMG=$(kubectl -n phorvex-system get deploy "$D" --request-timeout=10s \
      -o jsonpath="{.spec.template.spec.containers[?(@.name==\"$C\")].image}") \
      || fail "Cannot read phorvex-system/$D; check deployment and read permissions"
    [[ -n $IMG ]] || fail "Deployment $D has no $C image; cannot verify this release"
    SUMMARY+="$D=$IMG "
    case "$IMG" in *:"$V") ;; *) PENDING+=("$D") ;; esac
  done
  echo "[$attempt/$WAIT_ATTEMPTS] $SUMMARY; automated sync: $POLICY"
  if (( ${#PENDING[@]} == 0 )); then
    # Matching desired state is not proof of ready pods. Even an intentionally
    # paused app can already have this release; preserve the real rollout gate.
    for m in "${TARGETS[@]}"; do
      D=${DEPLOY_FOR[$m]}
      kubectl -n phorvex-system rollout status "deploy/$D" --timeout=180s \
        || fail "Deployment $D specifies $V but rollout readiness failed"
    done
    echo "Released deployments are ready at $V: ${TARGETS[*]} (automated sync: $POLICY)"
    exit 0
  fi
  IMG="${PENDING[*]}"
  case "$POLICY" in
    disabled) fail "argocd/phorvex-stack has spec.syncPolicy.automated.enabled=false; still pending on $IMG, expected :$V. Review the pending GitOps diff and intentionally resume/sync the application. This waiter does not change cluster state." ;;
    absent) fail "argocd/phorvex-stack has no automated sync policy; still pending on $IMG, expected :$V. Review the application configuration; this waiter does not enable sync." ;;
  esac
  if (( attempt < WAIT_ATTEMPTS )); then
    sleep "$WAIT_INTERVAL_SECONDS"
  fi
done
fail "ArgoCD did not roll out exact tag $V after $WAIT_ATTEMPTS polls (interval ${WAIT_INTERVAL_SECONDS}s, plus API latency). Inspect application sync errors and deployment events; do not rerun a release merely to restart this wait."
