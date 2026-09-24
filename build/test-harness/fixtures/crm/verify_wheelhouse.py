"""Verify one exact, SHA-256 pinned offline wheel for each locked distribution."""
import hashlib
import re
import sys
from pathlib import Path


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def main(argv):
    if len(argv) != 4:
        raise SystemExit("usage: verify_wheelhouse.py requirements manifest wheelhouse")
    requirements, manifest, wheelhouse = map(Path, argv[1:])
    required = {}
    for line in requirements.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+]+)", line)
        if not match:
            raise RuntimeError("invalid pinned requirement")
        name = canonical(match.group(1))
        if name in required:
            raise RuntimeError("duplicate requirement")
        required[name] = match.group(2)
    if not required:
        raise RuntimeError("empty dependency closure")

    checksums = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.+-]+\.whl)", line)
        if not match or match.group(2) in checksums:
            raise RuntimeError("invalid wheelhouse checksum manifest")
        checksums[match.group(2)] = match.group(1)
    entries = list(wheelhouse.iterdir())
    if any(not p.is_file() or p.is_symlink() for p in entries):
        raise RuntimeError("wheelhouse contains non-regular entries")
    files = {p.name: p for p in entries}
    if set(files) != set(checksums) or len(files) != len(required):
        raise RuntimeError("wheelhouse file set differs from exact closure")

    seen = {}
    for filename, path in files.items():
        components = filename[:-4].split("-")
        if len(components) < 5:
            raise RuntimeError("invalid wheel filename")
        name, version = canonical(components[0]), components[1]
        if name in seen or required.get(name) != version:
            raise RuntimeError("wheel package/version differs from closure")
        seen[name] = filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksums[filename]:
            raise RuntimeError("wheel SHA-256 mismatch")
    if set(seen) != set(required):
        raise RuntimeError("wheelhouse package set incomplete")
    print(f"verified {len(seen)} offline wheel SHA-256 pins")


if __name__ == "__main__":
    main(sys.argv)
