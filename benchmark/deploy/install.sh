#!/usr/bin/env bash
set -euo pipefail

# Run as the jump-host account that already owns the authorized kubeconfig.
# The administrator enables lingering once: loginctl enable-linger hami.
BASE="${BENCHMARK_INSTALL_DIR:-/home/hami/phorvex-benchmark}"
RELEASE="${1:?usage: install.sh RELEASE_DIRECTORY}"
NODE_VERSION=22.23.3
NODE_SHA256=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
mkdir -p "$BASE/runtime" "$BASE/data" "$BASE/config" "$HOME/.config/systemd/user"
chmod 700 "$BASE/config" "$BASE/data"
if [[ ! -x "$BASE/runtime/node/bin/node" ]]; then
  curl --fail --silent --show-error --location --retry 2 \
    "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
    --output "$BASE/runtime/node.tar.xz"
  printf '%s  %s\n' "$NODE_SHA256" "$BASE/runtime/node.tar.xz" | sha256sum --check --status
  tar -xJf "$BASE/runtime/node.tar.xz" -C "$BASE/runtime"
  ln -s "node-v${NODE_VERSION}-linux-x64" "$BASE/runtime/node"
fi
export PATH="$BASE/runtime/node/bin:/usr/local/bin:/usr/bin:/bin"
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=768}"
export NEXT_TELEMETRY_DISABLED=1
if [[ ! -x "$BASE/runtime/python/bin/pip" ]]; then
  python3 -m venv "$BASE/runtime/python"
fi
"$BASE/runtime/python/bin/pip" install --disable-pip-version-check -r "$RELEASE/benchmark/worker/requirements.txt"
npm --prefix "$RELEASE/benchmark/apps/api" ci --no-audit --no-fund
npm --prefix "$RELEASE/benchmark/apps/api" run build
npm --prefix "$RELEASE/benchmark/apps/web" ci --no-audit --no-fund
npm --prefix "$RELEASE/benchmark/apps/web" run build
mkdir -p "$RELEASE/benchmark/apps/web/.next/standalone/.next"
cp -R "$RELEASE/benchmark/apps/web/.next/static" "$RELEASE/benchmark/apps/web/.next/standalone/.next/static"
if [[ -d "$RELEASE/benchmark/apps/web/public" ]]; then
  cp -R "$RELEASE/benchmark/apps/web/public" "$RELEASE/benchmark/apps/web/.next/standalone/public"
fi
install -m 644 "$RELEASE/benchmark/deploy/phorvex-benchmark-api.service" "$HOME/.config/systemd/user/"
install -m 644 "$RELEASE/benchmark/deploy/phorvex-benchmark-web.service" "$HOME/.config/systemd/user/"
install -m 644 "$RELEASE/benchmark/deploy/phorvex-benchmark-proxy.service" "$HOME/.config/systemd/user/"
if [[ ! -x "$BASE/runtime/caddy/caddy" ]]; then
  mkdir -p "$BASE/runtime/caddy"
  curl --fail --silent --show-error --location --retry 2 \
    https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_checksums.txt \
    --output "$BASE/runtime/caddy/checksums.txt"
  curl --fail --silent --show-error --location --retry 2 \
    https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_amd64.tar.gz \
    --output "$BASE/runtime/caddy/caddy_2.10.2_linux_amd64.tar.gz"
  (cd "$BASE/runtime/caddy" && awk '$2=="caddy_2.10.2_linux_amd64.tar.gz" {print}' checksums.txt | sha512sum --check --status)
  tar -xzf "$BASE/runtime/caddy/caddy_2.10.2_linux_amd64.tar.gz" -C "$BASE/runtime/caddy" caddy
fi
if [[ ! -f "$BASE/config/Caddyfile" ]]; then
  install -m 600 "$RELEASE/benchmark/deploy/Caddyfile" "$BASE/config/Caddyfile"
fi
XDG_DATA_HOME="$BASE/runtime/caddy-data" XDG_CONFIG_HOME="$BASE/runtime/caddy-config" \
  "$BASE/runtime/caddy/caddy" validate --config "$BASE/config/Caddyfile" --adapter caddyfile
ln -sfn "$RELEASE" "$BASE/current"
systemctl --user daemon-reload
systemctl --user enable phorvex-benchmark-api phorvex-benchmark-web phorvex-benchmark-proxy
systemctl --user restart phorvex-benchmark-api phorvex-benchmark-web phorvex-benchmark-proxy
systemctl --user is-active phorvex-benchmark-api phorvex-benchmark-web phorvex-benchmark-proxy
