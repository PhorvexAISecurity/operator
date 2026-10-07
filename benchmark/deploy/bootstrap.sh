#!/usr/bin/env bash
set -euo pipefail
BASE=/home/hami/phorvex-benchmark
mkdir -p "$BASE/runtime" "$BASE/config" "$BASE/data" "$BASE/releases"
chmod 700 "$BASE/config" "$BASE/data"
if [[ ! -x "$BASE/runtime/node/bin/node" ]]; then
  curl -fSL --retry 2 https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz -o "$BASE/runtime/node.tar.xz"
  printf '%s  %s\n' df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de "$BASE/runtime/node.tar.xz" | sha256sum --check --status
  tar -xJf "$BASE/runtime/node.tar.xz" -C "$BASE/runtime"
  ln -s node-v22.23.3-linux-x64 "$BASE/runtime/node"
fi
if [[ ! -x "$BASE/runtime/caddy/caddy" ]]; then
  mkdir -p "$BASE/runtime/caddy"
  curl -fsSL --retry 2 https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_checksums.txt -o "$BASE/runtime/caddy/checksums.txt"
  curl -fSL --retry 2 https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_amd64.tar.gz -o "$BASE/runtime/caddy/caddy_2.10.2_linux_amd64.tar.gz"
  (cd "$BASE/runtime/caddy" && awk '$2=="caddy_2.10.2_linux_amd64.tar.gz" {print}' checksums.txt | sha512sum --check --status)
  tar -xzf "$BASE/runtime/caddy/caddy_2.10.2_linux_amd64.tar.gz" -C "$BASE/runtime/caddy" caddy
fi
if [[ ! -x "$BASE/runtime/python/bin/pip" ]]; then python3 -m venv "$BASE/runtime/python"; fi
"$BASE/runtime/node/bin/node" --version
"$BASE/runtime/caddy/caddy" version
