"""Verify the complete, offline Python wheel closure before an image build."""

import hashlib
import os
from pathlib import Path
import re
import stat
import sys


REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9_-]*)==([A-Za-z0-9.]+) --hash=sha256:([0-9a-f]{64})")
WHEEL = re.compile(r"([A-Za-z0-9_]+)-([A-Za-z0-9.]+)-(?:py3-none-any|cp311-cp311-manylinux_2_17_x86_64\.manylinux2014_x86_64)\.whl")
MANIFEST = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+\.whl)")


def _lines(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536 or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ValueError(f"{path} must be newline-terminated plain text")
    return [line for line in raw.decode("ascii").splitlines()
            if line and not line.startswith("#")]


def parse_lock(path):
    result = {}
    for line in _lines(path):
        match = REQUIREMENT.fullmatch(line)
        if not match:
            raise ValueError("invalid pinned requirement")
        name, version, digest = match.groups()
        normalized = name.lower().replace("-", "_")
        if normalized in result:
            raise ValueError("duplicate pinned requirement")
        result[normalized] = (version, digest)
    if not result:
        raise ValueError("empty requirement lock")
    return result


def verify(lock_path, manifest_path, wheelhouse_path):
    requirements = parse_lock(lock_path)
    entries = {}
    for line in _lines(manifest_path):
        match = MANIFEST.fullmatch(line)
        if not match:
            raise ValueError("invalid wheel manifest entry")
        digest, filename = match.groups()
        wheel = WHEEL.fullmatch(filename)
        if not wheel:
            raise ValueError("unexpected wheel filename or platform")
        name, version = wheel.groups()
        normalized = name.lower()
        if normalized in entries:
            raise ValueError("duplicate wheel package")
        if requirements.get(normalized) != (version, digest):
            raise ValueError("wheel differs from pinned requirement")
        entries[normalized] = (filename, digest)
    if set(entries) != set(requirements):
        raise ValueError("wheel manifest differs from requirement closure")
    wheelhouse = Path(wheelhouse_path)
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise ValueError("wheelhouse must be a directory")
    expected = {filename for filename, _ in entries.values()}
    if {part.name for part in wheelhouse.iterdir()} != expected:
        raise ValueError("wheelhouse has missing or extra files")
    for filename, digest in entries.values():
        path = wheelhouse / filename
        if path.is_symlink():
            raise ValueError("wheel must be a regular file")
        checksum = hashlib.sha256()
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as wheel_file:
            details = os.fstat(wheel_file.fileno())
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("wheel must be a regular file")
            if details.st_size > 32 * 1024 * 1024:
                raise ValueError("wheel exceeds 32 MiB")
            for chunk in iter(lambda: wheel_file.read(1024 * 1024), b""):
                checksum.update(chunk)
        actual = checksum.hexdigest()
        if actual != digest:
            raise ValueError(f"wheel SHA-256 differs: {filename}")
    return len(entries)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_wheelhouse.py LOCK MANIFEST WHEELHOUSE")
    try:
        count = verify(*sys.argv[1:])
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"wheelhouse verification failed: {exc}") from exc
    print(f"verified {count} pinned wheels")
