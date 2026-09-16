#!/usr/bin/env bash
# Provision the pinned kube-controller-manager used by local controller-backed tests.
#
# The binary comes from the official Kubernetes release bucket. Its URL, SHA256 and
# expected version are source constants: changing any of them requires review here.
# The verified executable path is the only stdout output; diagnostics go to stderr.
set -euo pipefail

VERSION=1.34.0
URL="https://dl.k8s.io/release/v${VERSION}/bin/linux/amd64/kube-controller-manager"
SHA256=dd49fc2991df033c1eef6c12574795d64633a95e665d1b369afe0760472c24d1

dest="${1:?usage: $0 <destination-dir>}"
mkdir -p "$dest"
binary="$dest/kube-controller-manager"

curl -fsSL --retry 3 --retry-all-errors --max-time 300 -o "$binary" "$URL" >&2
echo "$SHA256  $binary" | sha256sum -c - >&2
chmod 0755 "$binary"

version=''
if ! version="$("$binary" --version 2>&1)"; then
  echo "kube-controller-manager binary does not run" >&2
  printf '%s\n' "$version" >&2
  exit 1
fi
if [[ "$version" != "Kubernetes v${VERSION}" ]]; then
  echo "kube-controller-manager is not Kubernetes v${VERSION}" >&2
  printf '%s\n' "$version" >&2
  exit 1
fi

{
  echo "kube-controller-manager v${VERSION} provisioned at $binary"
  printf '%s\n' "$version"
} >&2
echo "$binary"
