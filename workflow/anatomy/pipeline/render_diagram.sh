#!/usr/bin/env bash
# Render ANATOMY_V2.mmd to PDF + PNG with the REAL mermaid engine.
#
# Why this exists: ANATOMY_V2.mmd was reviewed as text and accepted at bus 232 without ever being
# run through mermaid. It did not parse -- the cluster-graph node's id was the reserved word
# `graph`. A diagram that is never rendered is not a verified diagram.
#
# Layout: mermaid's default (dagre) scatters 15 lanes and routes edges across the whole canvas.
# ELK layered + NETWORK_SIMPLEX gives the pipeline ordering the anatomy actually has. The ELK
# frontmatter lives HERE, not in the .mmd, because a viewer whose mermaid build has no ELK
# registered throws on `layout: elk` -- the .mmd itself must stay portable dagre.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATED="$(cd "$HERE/.." && pwd)/generated"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
IMG=minlag/mermaid-cli
DOCKER="docker"; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"

mkdir -p "$GENERATED"
printf '{"args":["--no-sandbox","--disable-setuid-sandbox"]}\n' > "$WORK/puppeteer.json"
cp "$GENERATED/ANATOMY.mmd" "$WORK/render.mmd"
chmod 777 "$WORK"

WIDTH="${WIDTH:-900}"   # narrow column -> TALL page you scroll, not a poster you pan
run() {  # $1 = output filename, remaining args = extra mmdc flags
  local out="$1"; shift
  $DOCKER run --rm -e PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser \
    -v "$WORK":/data "$IMG" -i /data/render.mmd -o "/data/$out" \
    -p /data/puppeteer.json -b white -w "$WIDTH" "$@"
  cp "$WORK/$out" "$GENERATED/$out"
}
run ANATOMY-map.pdf --pdfFit
run ANATOMY-map.png
ls -la "$GENERATED/ANATOMY-map.pdf" "$GENERATED/ANATOMY-map.png"
