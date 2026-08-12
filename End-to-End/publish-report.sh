#!/usr/bin/env bash
#
# Publish an End-to-End run to https://ci-report.phorvex.ai.
#
# GitHub's runners cannot reach the EKS API, but the jump host can — the same host the
# pipeline already drives the cluster through. So the report travels: runner --scp--> jump
# host --kubectl cp--> the ci-reports nginx pod's PVC.
#
#   ./publish-report.sh <runs-dir> <prefix>
#     runs-dir  directory holding run-<stamp>.html / .json (End-to-End/runs)
#     prefix    destination path segment, e.g. "pr-42" or "main"
#
# Requires PHORVEX_SSH_HOST / PHORVEX_SSH_USER / PHORVEX_SSH_PASSWORD in the environment.
# Writes `url` and `stamp` to $GITHUB_OUTPUT when running under Actions.

set -euo pipefail

RUNS_DIR="${1:?usage: publish-report.sh <runs-dir> <prefix>}"
PREFIX="${2:?usage: publish-report.sh <runs-dir> <prefix>}"

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

REPORT="$(ls -1 "$RUNS_DIR"/run-*.html 2>/dev/null | sort | tail -1 || true)"
if [[ -z "$REPORT" ]]; then
  echo "no run-*.html in $RUNS_DIR — the pipeline produced no report" >&2
  exit 1
fi
STAMP="$(basename "$REPORT" .html)"; STAMP="${STAMP#run-}"
JSON="$RUNS_DIR/run-$STAMP.json"

echo "publishing $STAMP → $BASE_URL/$PREFIX/"

REMOTE_TMP="/tmp/ci-report-$PREFIX-$STAMP"
ssh_ "rm -rf '$REMOTE_TMP' && mkdir -p '$REMOTE_TMP'"
scp_ "$REPORT" "$USER_@$HOST:$REMOTE_TMP/run-$STAMP.html"
[[ -f "$JSON" ]] && scp_ "$JSON" "$USER_@$HOST:$REMOTE_TMP/run-$STAMP.json"
# latest.html is a copy, not a symlink: `kubectl cp` does not follow symlinks into the pod,
# and a dangling link would serve a 404 from the one URL people bookmark.
scp_ "$REPORT" "$USER_@$HOST:$REMOTE_TMP/latest.html"

# `kubectl cp` needs a concrete pod name, and the deployment is Recreate/1-replica so there
# is exactly one. Resolving it per run means a rollout between runs is not a broken publish.
ssh_ bash -s <<REMOTE
set -euo pipefail
POD="\$(kubectl get pod -n '$NS' -l app.kubernetes.io/name=ci-reports \
        -o jsonpath='{.items[0].metadata.name}')"
if [ -z "\$POD" ]; then echo "no ci-reports pod in namespace $NS" >&2; exit 1; fi
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
