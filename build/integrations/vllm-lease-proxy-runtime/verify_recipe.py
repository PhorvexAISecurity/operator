"""Check the fixed image recipe before registry credentials are loaded."""

from __future__ import annotations

import hashlib
from pathlib import Path

from verify_wheelhouse import declared


HERE = Path(__file__).resolve().parent
BASE_IMAGE = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
COMMAND = '["python3", "-B", "/src/dual_server.py"]'
RECIPE_FILES = (
    ".dockerignore", "Dockerfile", "requirements.lock", "wheelhouse.sha256",
    "verify_wheelhouse.py", "prepare_wheelhouse.py", "verify_runtime.py",
    "verify_recipe.py", "test_recipe.py", "write_publish_receipt.py", "README.md",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path = HERE) -> dict:
    root = Path(root)
    dockerfile = (root / "Dockerfile").read_text()
    if not dockerfile.startswith("FROM --platform=linux/amd64 " + BASE_IMAGE + "\n") or \
            dockerfile.count("--no-index") < 1 or \
            "--require-hashes" not in dockerfile or \
            "USER 10001:10001" not in dockerfile or \
            dockerfile.count("verify_runtime.py") != 3 or \
            "CMD " + COMMAND not in dockerfile or \
            "COPY wheelhouse/" not in dockerfile:
        raise ValueError("proxy Dockerfile differs from reviewed offline runtime contract")
    lock, wheels = declared(root / "requirements.lock", root / "wheelhouse.sha256")
    ignored = (root / ".dockerignore").read_text()
    if "!wheelhouse/*.whl" not in ignored or "!wheelhouse/" not in ignored:
        raise ValueError("exact wheels omitted from Docker context")
    for name in RECIPE_FILES:
        if not (root / name).is_file():
            raise ValueError("proxy recipe file absent: " + name)
    return {"baseImage": BASE_IMAGE, "platform": "linux/amd64", "command": COMMAND,
            "wheelCount": len(wheels), "rootVersions": {name: lock[name][0] for name in sorted(lock)},
            "recipeSHA256": {name: digest(root / name) for name in RECIPE_FILES}}


if __name__ == "__main__":
    result = verify()
    print("verified proxy image recipe with", result["wheelCount"], "locked wheels")
