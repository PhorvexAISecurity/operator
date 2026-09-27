"""Verify the exact Linux/amd64 Python 3.11 proxy wheel closure."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys


REQUIREMENT = re.compile(r"([a-z0-9][a-z0-9-]*)==([A-Za-z0-9.+]+) --hash=sha256:([0-9a-f]{64})")
MANIFEST = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+\.whl)")
ROOT_VERSIONS = {
    "torch": "2.14.0+cpu",
    "transformers": "5.17.0",
    "fastapi": "0.141.1",
    "uvicorn": "0.53.0",
    "httpx": "0.28.1",
    "numpy": "2.4.6",
    "tokenizers": "0.23.2",
    "safetensors": "0.8.0",
}


def lines(path: Path) -> list[str]:
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise ValueError("invalid lock or manifest text")
    return [line for line in raw.decode("ascii").splitlines() if line and not line.startswith("#")]


def declared(lock_path: Path, manifest_path: Path) -> tuple[dict, dict]:
    requirements = {}
    for line in lines(lock_path):
        match = REQUIREMENT.fullmatch(line)
        if not match or match.group(1) in requirements:
            raise ValueError("invalid or repeated locked requirement")
        name, version, digest = match.groups()
        requirements[name] = (version, digest)
    if len(requirements) != 41 or any(requirements.get(name, (None,))[0] != version
                                   for name, version in ROOT_VERSIONS.items()):
        raise ValueError("proxy wheel closure or root version changed")

    wheels = {}
    for line in lines(manifest_path):
        match = MANIFEST.fullmatch(line)
        if not match:
            raise ValueError("invalid wheel manifest")
        digest, filename = match.groups()
        parts = filename[:-4].split("-")
        if len(parts) != 5:
            raise ValueError("wheel filename is outside the reviewed shape")
        name, version, py_tag, abi_tag, platform_tag = parts
        name = name.lower().replace("_", "-")
        if name in wheels or requirements.get(name) != (version, digest):
            raise ValueError("wheel differs from locked requirement")
        pure = py_tag in ("py3", "py2.py3") and abi_tag == "none" and platform_tag == "any"
        linux = py_tag in ("cp311", "cp310", "cp38") and abi_tag in ("cp311", "abi3") and \
            "manylinux" in platform_tag and "x86_64" in platform_tag
        if not (pure or linux):
            raise ValueError("wheel has wrong Python/platform tag")
        wheels[name] = filename
    if set(wheels) != set(requirements):
        raise ValueError("wheel manifest omits a locked dependency")
    return requirements, wheels


def verify(lock_path: Path, manifest_path: Path, wheelhouse_path: Path) -> int:
    requirements, wheels = declared(Path(lock_path), Path(manifest_path))
    folder = Path(wheelhouse_path)
    if not folder.is_dir() or folder.is_symlink() or \
            {p.name for p in folder.iterdir()} != set(wheels.values()):
        raise ValueError("wheelhouse file set differs from manifest")
    total = 0
    for name, filename in wheels.items():
        descriptor = os.open(folder / filename, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 384 * 1024 * 1024:
                raise ValueError("wheel file size or type differs")
            total += info.st_size
            if total > 1024 * 1024 * 1024:
                raise ValueError("wheel closure exceeds resource bound")
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != requirements[name][1]:
            raise ValueError("wheel hash differs")
    return len(wheels)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_wheelhouse.py LOCK MANIFEST WHEELHOUSE")
    print("verified", verify(*(Path(arg) for arg in sys.argv[1:])), "exact wheels")
