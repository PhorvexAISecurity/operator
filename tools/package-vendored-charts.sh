#!/usr/bin/env bash
set -euo pipefail

# Rebuild every checked-in chart archive with normalized tar/gzip metadata.
# The same source tree therefore produces byte-identical archives on every host.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELM_BIN=${HELM_BIN:-helm}
MODE=${1:-write}
if [[ "$MODE" != write && "$MODE" != --check ]]; then
  echo "usage: tools/package-vendored-charts.sh [--check]" >&2
  exit 2
fi
command -v "$HELM_BIN" >/dev/null 2>&1 || {
  echo "helm is required (set HELM_BIN to an absolute binary)" >&2
  exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/phorvex-chart-package.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

chart_version() {
  awk '$1 == "version:" {gsub(/"/, "", $2); print $2; exit}' "$1/Chart.yaml"
}

normalize_archive() {
  local input=$1 output=$2 unpack
  unpack=$work/unpack-$(basename "$output" .tgz)
  mkdir -p "$unpack"
  tar --warning=no-timestamp -xzf "$input" -C "$unpack"
  local root
  root=$(find "$unpack" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
  [[ -n "$root" && $(find "$unpack" -mindepth 1 -maxdepth 1 | wc -l) -eq 1 ]] || {
    echo "archive $input does not contain one chart root" >&2
    exit 1
  }
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
      --format=ustar -C "$unpack" -cf - "$root" | gzip -n -9 >"$output"
}

package_chart() {
  local source=$1 name=$2 version=$3 raw
  raw=$work/raw-$name-$version.tgz
  "$HELM_BIN" package "$source" --destination "$work" >/dev/null
  mv "$work/$name-$version.tgz" "$raw"
  normalize_archive "$raw" "$work/$name-$version.tgz"
}

common_source=$ROOT/deploy/charts/phorvex-common
common_version=$(chart_version "$common_source")
package_chart "$common_source" phorvex-common "$common_version"
common_archive=$work/phorvex-common-$common_version.tgz

phorvex_stage=$work/phorvex
cp -a "$ROOT/phorvex/charts/phorvex" "$phorvex_stage"
mkdir -p "$phorvex_stage/charts"
cp "$common_archive" "$phorvex_stage/charts/phorvex-common-$common_version.tgz"
phorvex_version=$(chart_version "$phorvex_stage")
package_chart "$phorvex_stage" phorvex "$phorvex_version"

phoenix_source=$ROOT/build/phoenix-extended/charts/phoenix
phoenix_version=$(chart_version "$phoenix_source")
package_chart "$phoenix_source" phoenix "$phoenix_version"

targets=(
  "$ROOT/phorvex/charts/phorvex/charts/phorvex-common-$common_version.tgz"
  "$ROOT/deploy/charts/phorvex-actuator/charts/phorvex-common-$common_version.tgz"
  "$ROOT/deploy/charts/phorvex-attacks/charts/phorvex-common-$common_version.tgz"
  "$ROOT/deploy/charts/phorvex-brain/charts/phorvex-common-$common_version.tgz"
  "$ROOT/deploy/charts/phorvex-console/charts/phorvex-common-$common_version.tgz"
  "$ROOT/deploy/charts/phorvex-sensor/charts/phorvex-common-$common_version.tgz"
)

install_or_check() {
  local source=$1 target=$2
  if [[ "$MODE" == --check ]]; then
    cmp -s "$source" "$target" || {
      echo "stale vendored archive: ${target#$ROOT/}" >&2
      return 1
    }
  else
    mkdir -p "$(dirname "$target")"
    cp "$source" "$target"
  fi
}

status=0
for target in "${targets[@]}"; do
  install_or_check "$common_archive" "$target" || status=1
done
install_or_check "$work/phorvex-$phorvex_version.tgz" \
  "$ROOT/deploy/helm/phorvex-stack/charts/phorvex-$phorvex_version.tgz" || status=1
install_or_check "$work/phoenix-$phoenix_version.tgz" \
  "$ROOT/deploy/helm/phorvex-stack/charts/phoenix-$phoenix_version.tgz" || status=1

if (( status != 0 )); then
  echo "run tools/package-vendored-charts.sh and commit every regenerated archive" >&2
  exit "$status"
fi
if [[ "$MODE" == --check ]]; then
  echo "all vendored chart archives are byte-reproducible and current"
else
  echo "regenerated ${#targets[@]} common archives plus phorvex and phoenix deterministically"
fi
