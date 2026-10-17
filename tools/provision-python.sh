#!/usr/bin/env bash
# Provision a pinned, relocatable CPython for CI: provision-python.sh <3.11|3.12> <destination-dir>.
#
# The build runner is self-hosted, where actions/setup-python installs interpreters
# that find libpython only through LD_LIBRARY_PATH (they are linked for
# /opt/hostedtoolcache). Tests that start Python with a minimal environment then
# cannot start it. python-build-standalone builds resolve their libraries relative to
# the executable, so they run with any environment.
#
# Downloads ONE pinned archive, refuses it unless its SHA256 matches the digest
# recorded here, extracts it and proves the interpreter reports the pinned version
# with an empty environment. Prints the interpreter's bin directory on stdout and
# nothing else. There are no override knobs: another version or digest is a source
# change to this file.
set -euo pipefail

RELEASE=20261001
case "${1:?usage: $0 <3.11|3.12> <destination-dir>}" in
  3.11) VERSION=3.11.17 SHA256=5b6d0a6b59b5b792368d182bbcaab0e60ed476d444ee78470513a99acde890b6 ;;
  3.12) VERSION=3.12.15 SHA256=0e56475e23f61a9c7d254fe16bc4931544026d591fc1cb8b770712ee94fa6260 ;;
  *) echo "unsupported Python $1" >&2; exit 2 ;;
esac
dest="${2:?usage: $0 <3.11|3.12> <destination-dir>}"
name="cpython-${VERSION}+${RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz"
URL="https://github.com/astral-sh/python-build-standalone/releases/download/${RELEASE}/${name/+/%2B}"

mkdir -p "$dest"
archive="$dest/$name"
curl -fsSL --retry 3 --retry-all-errors --max-time 300 -o "$archive" "$URL" >&2
echo "$SHA256  $archive" | sha256sum -c - >&2
tar -xzf "$archive" -C "$dest"
rm -f "$archive"

bin="$dest/python/bin"
reported="$(env -i "$bin/python3" -c 'import platform; print(platform.python_version())' 2>&1)" || {
  echo "python $VERSION does not start with an empty environment" >&2
  printf '%s\n' "$reported" >&2
  exit 1
}
if [[ "$reported" != "$VERSION" ]]; then
  echo "interpreter reports $reported, not $VERSION" >&2
  exit 1
fi
echo "$bin"
