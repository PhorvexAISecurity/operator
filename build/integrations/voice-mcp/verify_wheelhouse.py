"""Reject wheelhouse drift before a disconnected MCP dependency image build."""

import hashlib
import os
from pathlib import Path
import re
import stat
import sys


REQUIREMENT = re.compile(r"([a-z0-9][a-z0-9.-]*)==([A-Za-z0-9.]+) --hash=sha256:([0-9a-f]{64})")
MANIFEST = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+\.whl)")


def lines(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536 or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ValueError("invalid lock or manifest text")
    return [line for line in raw.decode("ascii").splitlines() if line and not line.startswith("#")]


def verify(lock_path, manifest_path, wheelhouse_path):
    requirements = {}
    for line in lines(lock_path):
        match = REQUIREMENT.fullmatch(line)
        if not match:
            raise ValueError("invalid locked requirement")
        name, version, digest = match.groups()
        if name in requirements:
            raise ValueError("duplicate requirement")
        requirements[name] = (version, digest)
    if not requirements or requirements.get("fastmcp", (None,))[0] != "3.4.7":
        raise ValueError("FastMCP version missing")
    wheels = {}
    for line in lines(manifest_path):
        match = MANIFEST.fullmatch(line)
        if not match:
            raise ValueError("invalid wheel manifest")
        digest, filename = match.groups()
        parts = filename[:-4].split("-")
        if len(parts) < 5:
            raise ValueError("invalid wheel filename")
        name, version = parts[0].lower().replace("_", "-").replace(".", "-"), parts[1]
        if name in wheels or requirements.get(name) != (version, digest):
            raise ValueError("wheel differs from lock")
        if not (filename.endswith(("-py3-none-any.whl", "-py2.py3-none-any.whl")) or
                "manylinux" in filename):
            raise ValueError("non-linux wheel")
        wheels[name] = filename
    if set(wheels) != set(requirements):
        raise ValueError("wheel closure incomplete")
    folder = Path(wheelhouse_path)
    if not folder.is_dir() or folder.is_symlink() or {path.name for path in folder.iterdir()} != set(wheels.values()):
        raise ValueError("wheelhouse file set differs")
    for name, filename in wheels.items():
        path = folder / filename
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 32 * 1024 * 1024:
                raise ValueError("invalid wheel file")
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != requirements[name][1]:
            raise ValueError("wheel digest mismatch")
    return len(wheels)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_wheelhouse.py LOCK MANIFEST WHEELHOUSE")
    try:
        print("verified", verify(*sys.argv[1:]), "pinned wheels")
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"wheelhouse verification failed: {exc}") from exc
