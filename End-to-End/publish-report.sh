#!/usr/bin/env bash
#
# Publish an End-to-End run to https://ci-report.phorvex.ai.
#
# GitHub's runners cannot reach the EKS API, but the jump host can — the same host the
# pipeline already drives the cluster through. So the report travels: runner --scp--> jump
# host --kubectl cp--> the ci-reports nginx pod's PVC.
#
#   ./publish-report.sh <runs-dir> <prefix> <run-id>
#     runs-dir  directory holding run-<stamp>.html / .json (End-to-End/runs)
#     prefix    destination path segment, e.g. "pr-42" or "main"
#
# Requires PHORVEX_SSH_HOST / PHORVEX_SSH_USER / PHORVEX_SSH_PASSWORD in the environment.
# Writes `url` and `stamp` to $GITHUB_OUTPUT when running under Actions.

set -euo pipefail

RUNS_DIR="${1:?usage: publish-report.sh <runs-dir> <prefix> <run-id>}"
PREFIX="${2:?usage: publish-report.sh <runs-dir> <prefix> <run-id>}"
STAMP="${3:?an exact run-id is required; latest-report discovery is not safe}"
if [[ ! "$STAMP" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$ ]]; then
  echo "invalid run-id" >&2
  exit 2
fi
REPORT="$RUNS_DIR/run-$STAMP.html"
JSON="$RUNS_DIR/run-$STAMP.json"
if [[ ! -s "$REPORT" || ! -s "$JSON" ]]; then
  echo "current attempt has no complete HTML/JSON report pair" >&2
  exit 1
fi
python3 - "$JSON" "$STAMP" <<'PY'
import json, os, sys
with open(sys.argv[1]) as stream:
    doc = json.load(stream)
if doc.get('runId') != sys.argv[2] or (os.getenv('GITHUB_SHA') and doc.get('sourceCommit') != os.environ['GITHUB_SHA']):
    sys.exit('refusing to publish a report from a different attempt/source')
PY

HOST="${PHORVEX_SSH_HOST:?PHORVEX_SSH_HOST not set}"
USER_="${PHORVEX_SSH_USER:?PHORVEX_SSH_USER not set}"
: "${PHORVEX_SSH_PASSWORD:?PHORVEX_SSH_PASSWORD not set}"

BASE_URL="${CI_REPORT_BASE_URL:-https://ci-report.phorvex.ai}"
NS="${CI_REPORT_NAMESPACE:-ci-reports}"

# The prefix lands in a URL and in a shell path on the jump host. Anything outside this
# set could escape the document root, so it is rejected rather than sanitised — a silently
# rewritten destination is worse than a failed publish.
if [[ ! "$PREFIX" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "refusing to publish: prefix '$PREFIX' is not [A-Za-z0-9._-]+" >&2
  exit 2
fi

# sshpass reads the password from the environment, so it never appears in `ps` or in a log.
SSHPASS="$PHORVEX_SSH_PASSWORD"; export SSHPASS
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
          -o ConnectTimeout=15)
ssh_() { sshpass -e ssh "${SSH_OPTS[@]}" "$USER_@$HOST" "$@"; }
scp_() { sshpass -e scp "${SSH_OPTS[@]}" "$@"; }

echo "publishing $STAMP → $BASE_URL/$PREFIX/"

REMOTE_TMP="/tmp/ci-report-$PREFIX-$STAMP"
ssh_ "rm -rf '$REMOTE_TMP' && mkdir -p '$REMOTE_TMP'"
scp_ "$REPORT" "$USER_@$HOST:$REMOTE_TMP/run-$STAMP.html"
[[ -f "$JSON" ]] && scp_ "$JSON" "$USER_@$HOST:$REMOTE_TMP/run-$STAMP.json"
# latest.html is a copy, not a symlink: `kubectl cp` does not follow symlinks into the pod,
# and a dangling link would serve a 404 from the one URL people bookmark.
scp_ "$REPORT" "$USER_@$HOST:$REMOTE_TMP/latest.html"

# `kubectl cp` needs a concrete pod name. A restarted node can leave a completed pod with
# the deployment label behind, so select only a running pod and wait for it to be ready.
# Sorting newest-first also avoids choosing a terminating predecessor during a rollout.
ssh_ bash -s <<REMOTE
set -euo pipefail
POD="\$(kubectl get pod -n '$NS' -l app.kubernetes.io/name=ci-reports \
        --field-selector=status.phase=Running --sort-by=.metadata.creationTimestamp \
        -o jsonpath='{.items[-1:].metadata.name}')"
if [ -z "\$POD" ]; then echo "no running ci-reports pod in namespace $NS" >&2; exit 1; fi
kubectl wait -n '$NS' --for=condition=Ready "pod/\$POD" --timeout=60s >/dev/null
kubectl exec -n '$NS' "\$POD" -- mkdir -p "/usr/share/nginx/html/$PREFIX"
for f in '$REMOTE_TMP'/*; do
  kubectl cp "\$f" "$NS/\$POD:/usr/share/nginx/html/$PREFIX/\$(basename "\$f")"
done
rm -rf '$REMOTE_TMP'
echo "copied into \$POD:/usr/share/nginx/html/$PREFIX/"
REMOTE

URL="$BASE_URL/$PREFIX/run-$STAMP.html"
echo "published: $URL"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "url=$URL"
    echo "latest_url=$BASE_URL/$PREFIX/latest.html"
    echo "stamp=$STAMP"
  } >> "$GITHUB_OUTPUT"
fi
