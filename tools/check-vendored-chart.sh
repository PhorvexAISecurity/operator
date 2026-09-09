#!/usr/bin/env bash
set -euo pipefail

# ArgoCD renders the chart from the vendored charts/*.tgz, NOT from
# phorvex/charts/phorvex — so a subchart edit that is never re-packaged is
# invisible until it silently fails to deploy.
#
# This compares EXTRACTED CONTENTS, not the .tgz bytes: `helm package` stamps
# gzip metadata at build time, so the archive is not byte-reproducible and a
# byte comparison would fail on every single run.
V=$(grep -E '^version:' phorvex/charts/phorvex/Chart.yaml | awk '{print $2}')
TGZ="deploy/helm/phorvex-stack/charts/phorvex-$V.tgz"
if [ ! -f "$TGZ" ]; then
  echo "::error::$TGZ is missing — phorvex/charts/phorvex is at version $V."
  echo "::error::Run: helm dependency update deploy/helm/phorvex-stack (and bump the dependency in Chart.yaml)"
  exit 1
fi
# Self-hosted runners retain /tmp between jobs. Never merge an archive
# into a shared directory: deleted templates from older runs survive.
VENDORED_DIR=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/phorvex-vendored.XXXXXX")
trap 'rm -rf -- "$VENDORED_DIR"' EXIT
tar xzf "$TGZ" -C "$VENDORED_DIR"
# templates/, values.yaml and crds/ are archived verbatim, so they diff directly.
# Chart.yaml does NOT: `helm package` reorders its keys and reflows the folded
# description, so it is compared as parsed data instead of as text.
if ! diff -r --exclude=.helmignore --exclude=Chart.yaml \
       phorvex/charts/phorvex "$VENDORED_DIR/phorvex"; then
  echo "::error::the vendored subchart differs from phorvex/charts/phorvex."
  echo "::error::Run: helm dependency update deploy/helm/phorvex-stack && git add deploy/helm/phorvex-stack"
  exit 1
fi
python3 - "$VENDORED_DIR/phorvex/Chart.yaml" <<'PY'
import sys, yaml
a = yaml.safe_load(open("phorvex/charts/phorvex/Chart.yaml"))
b = yaml.safe_load(open(sys.argv[1]))
drift = {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}
if drift:
    for k, (x, y) in drift.items():
        print(f"::error::Chart.yaml {k}: source={x!r} vendored={y!r}")
    sys.exit("vendored Chart.yaml is stale — helm dependency update")
print("  Chart.yaml matches")
PY
