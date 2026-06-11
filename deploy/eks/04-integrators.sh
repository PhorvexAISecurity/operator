#!/usr/bin/env bash
# Step 4 (OPTIONAL) — deploy Phoenix signal-source integrators.
#
# Phorvex decides; Phoenix executes; integrators are what FEED Phoenix real-world
# attack signals. They are optional for standing the stack up (the operators run fine
# without them) but needed for live end-to-end detection.
#
# Tiers, by how much they touch the node:
#   time-based-trigger : self-contained, no node/host deps        -> applied by default
#   prometheus         : needs a Prometheus in-cluster            -> INTEGRATORS=prometheus
#   falco / kubearmor  : privileged DaemonSets, need Falco/KubeArmor installed first
#                        -> INTEGRATORS="falco kubearmor" (read prerequisites below)
#
# Usage:  INTEGRATORS="time-based-trigger" ./04-integrators.sh
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

M="$REPO_ROOT/build/phoenix-extended/deploy/manifests"
INTEGRATORS="${INTEGRATORS:-time-based-trigger}"

echo "==> Applying integrators: $INTEGRATORS"
for i in $INTEGRATORS; do
  case "$i" in
    time-based-trigger)
      kubectl apply -f "$M/deploy-time-based-trigger/deploy.yaml" ;;
    falco)
      echo "    NOTE: Falco itself must be installed first:"
      echo "      helm repo add falcosecurity https://falcosecurity.github.io/charts"
      echo "      helm install falco falcosecurity/falco -n falco --create-namespace"
      echo "      kubectl apply -f $M/config-falco/   # Phoenix rules/patch"
      kubectl apply -f "$M/deploy-falco-integrator/deploy.yaml" ;;
    kubearmor)
      echo "    NOTE: install KubeArmor first (https://kubearmor.io)."
      kubectl apply -f "$M/deploy-kubearmor-integrator/deploy.yaml" ;;
    prometheus)
      echo "    NOTE: set phorvex.phorvex.prometheusUrl in the Helm release so the"
      echo "          brain ingests Prometheus metrics (re-run 03-deploy.sh --set ...)."
      ;;
    *) echo "    !! unknown integrator '$i' — skipping" ;;
  esac
done

echo "==> Integrator pods:"
kubectl get pods -A | grep -E 'integrator|time-based' || true
