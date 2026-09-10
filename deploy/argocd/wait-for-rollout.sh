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
  command -v "$tool" >/dev/null || fail "Required jump-host tool is missing: $tool"
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

  IMG=$(kubectl -n phorvex-system get deploy phorvex-phorvex --request-timeout=10s \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="manager")].image}') \
    || fail 'Cannot read phorvex-system/phorvex-phorvex; check deployment and read permissions'
  [[ -n $IMG ]] || fail 'Deployment has no manager image; cannot verify this release'
  echo "[$attempt/$WAIT_ATTEMPTS] deployment image: $IMG; automated sync: $POLICY"
  case "$IMG" in
    *:"$V")
      # Matching desired state is not proof of ready pods. Even an intentionally
      # paused app can already have this release; preserve the real rollout gate.
      kubectl -n phorvex-system rollout status deploy/phorvex-phorvex --timeout=180s \
        || fail "Deployment specifies $V but rollout readiness failed"
      echo "Deployment is ready at $V (automated sync: $POLICY)"
      exit 0
      ;;
  esac
  case "$POLICY" in
    disabled) fail "argocd/phorvex-stack has spec.syncPolicy.automated.enabled=false; deployment is $IMG, expected :$V. Review the pending GitOps diff and intentionally resume/sync the application. This waiter does not change cluster state." ;;
    absent) fail "argocd/phorvex-stack has no automated sync policy; deployment is $IMG, expected :$V. Review the application configuration; this waiter does not enable sync." ;;
  esac
  if (( attempt < WAIT_ATTEMPTS )); then
    sleep "$WAIT_INTERVAL_SECONDS"
  fi
done
fail "ArgoCD did not roll out exact tag $V after $WAIT_ATTEMPTS polls (interval ${WAIT_INTERVAL_SECONDS}s, plus API latency). Inspect application sync errors and deployment events; do not rerun a release merely to restart this wait."
