#!/usr/bin/env bash
# Provision the pinned local envtest control plane (kube-apiserver + etcd) for CI.
#
# Downloads ONE pinned kubernetes-sigs/controller-tools release archive, refuses it
# unless its SHA256 matches the digest recorded here, extracts it and proves the
# binaries run and report the pinned Kubernetes version. Prints the assets directory
# (KUBEBUILDER_ASSETS) on stdout and nothing else; everything else goes to stderr.
#
# There are deliberately no override knobs: a different version, URL or digest is a
# source change to this file, not an environment variable. Kubernetes API module
# pin: k8s.io/api v0.34.0 (phorvex/go.mod, build/phoenix-extended/go.mod).
set -euo pipefail

VERSION=1.34.0
URL="https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v${VERSION}/envtest-v${VERSION}-linux-amd64.tar.gz"
SHA256=9c45e40aa56971b105e596ebb3e84af6742e8709cc0523733baf8d9bb725e69c

dest="${1:?usage: $0 <destination-dir>}"
mkdir -p "$dest"
archive="$dest/envtest-v${VERSION}-linux-amd64.tar.gz"

curl -fsSL --retry 3 --retry-all-errors --max-time 300 -o "$archive" "$URL" >&2
echo "$SHA256  $archive" | sha256sum -c - >&2

tar -xzf "$archive" -C "$dest"
assets="$dest/controller-tools/envtest"
for bin in kube-apiserver etcd; do
  test -x "$assets/$bin" || { echo "missing envtest binary: $assets/$bin" >&2; exit 1; }
done
kube_version=''
if ! kube_version="$("$assets/kube-apiserver" --version 2>&1)"; then
  echo "kube-apiserver binary does not run" >&2
  printf '%s\n' "$kube_version" >&2
  exit 1
fi
if [[ "$kube_version" != "Kubernetes v${VERSION}" ]]; then
  echo "kube-apiserver is not Kubernetes v${VERSION}" >&2
  printf '%s\n' "$kube_version" >&2
  exit 1
fi

etcd_version=''
if ! etcd_version="$("$assets/etcd" --version 2>&1)"; then
  echo "etcd binary does not run" >&2
  printf '%s\n' "$etcd_version" >&2
  exit 1
fi
if ! grep -F 'etcd Version:' <<<"$etcd_version" >/dev/null; then
  echo "etcd version marker is missing" >&2
  printf '%s\n' "$etcd_version" >&2
  exit 1
fi
{
  echo "envtest v${VERSION} provisioned at $assets"
  printf '%s\n' "$kube_version"
  printf '%s\n' "$etcd_version"
} >&2
echo "$assets"
