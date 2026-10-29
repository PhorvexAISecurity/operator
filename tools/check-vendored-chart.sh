#!/usr/bin/env bash
set -euo pipefail

# ArgoCD renders the chart from the vendored charts/*.tgz, NOT from
# phorvex/charts/phorvex — so a subchart edit that is never re-packaged is
# invisible until it silently fails to deploy.
#
# The packager normalizes tar ownership, order and mtimes and uses `gzip -n`, so
# archives are byte-reproducible as well as content-equivalent.
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
# Chart.yaml and Chart.lock do NOT: `helm package` reorders their keys and
# reflows the folded description, so they are compared as parsed data below.
# The chart's own dependencies, vendored in it as charts/<name>-<version>.tgz,
# are stored expanded as charts/<name>/, so they are compared separately.
if ! diff -r --exclude=.helmignore --exclude=Chart.yaml --exclude=Chart.lock --exclude=charts \
       phorvex/charts/phorvex "$VENDORED_DIR/phorvex"; then
  echo "::error::the vendored subchart differs from phorvex/charts/phorvex."
  echo "::error::Run: helm dependency update deploy/helm/phorvex-stack && git add deploy/helm/phorvex-stack"
  exit 1
fi
mkdir -p "$VENDORED_DIR/dependencies" "$VENDORED_DIR/phorvex/charts"
for dependency in phorvex/charts/phorvex/charts/*.tgz; do
  [ -e "$dependency" ] || continue
  tar xzf "$dependency" -C "$VENDORED_DIR/dependencies"
done
if ! diff -r --exclude=Chart.yaml "$VENDORED_DIR/dependencies" "$VENDORED_DIR/phorvex/charts"; then
  echo "::error::the vendored subchart's dependencies differ from phorvex/charts/phorvex/charts."
  echo "::error::Run: helm dependency update deploy/helm/phorvex-stack && git add deploy/helm/phorvex-stack"
  exit 1
fi
python3 - "$VENDORED_DIR" <<'PY'
import os, sys, yaml
vendored = sys.argv[1]

def load(path):
    return (yaml.safe_load(open(path)) or {}) if os.path.exists(path) else {}

pairs = [("Chart.yaml", "phorvex/charts/phorvex/Chart.yaml", f"{vendored}/phorvex/Chart.yaml")]
for name in sorted(os.listdir(f"{vendored}/dependencies")):
    pairs.append((f"charts/{name}/Chart.yaml", f"{vendored}/dependencies/{name}/Chart.yaml",
                  f"{vendored}/phorvex/charts/{name}/Chart.yaml"))
stale = False
for label, source, copy in pairs:
    a, b = load(source), load(copy)
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            print(f"::error::{label} {k}: source={a.get(k)!r} vendored={b.get(k)!r}")
            stale = True
a, b = load("phorvex/charts/phorvex/Chart.lock"), load(f"{vendored}/phorvex/Chart.lock")
for k in ("dependencies", "digest"):
    if a.get(k) != b.get(k):
        print(f"::error::Chart.lock {k}: source={a.get(k)!r} vendored={b.get(k)!r}")
        stale = True
if stale:
    sys.exit("vendored chart metadata is stale — helm dependency update")
print("  Chart.yaml, Chart.lock and dependencies match")
PY

"$(dirname "$0")/package-vendored-charts.sh" --check
