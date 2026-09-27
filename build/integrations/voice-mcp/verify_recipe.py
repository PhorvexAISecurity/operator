"""Verify the reviewed MCP image recipe before any registry credential is loaded."""

import hashlib
from pathlib import Path
import re

from verify_wheelhouse import MANIFEST, REQUIREMENT, lines


HERE = Path(__file__).resolve().parent
SOURCE_SHA256 = "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252"
BASE_IMAGE = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
ATTACK_AUDIO_SHA256 = "843b6fce61bae1a62ab069c889352b55e271bfb32ca23b6bba2d63461ce22b90"
BENIGN_AUDIO_SHA256 = "6b634936283ce28c2e25b71fa3575d0e23c69839999eed6e917fb52d8d176e37"
RECIPE_FILES = (
    ".dockerignore", "Dockerfile", "requirements.lock", "wheelhouse.sha256",
    "server.py", "test_server.py", "verify_runtime.py", "verify_wheelhouse.py",
    "prepare_wheelhouse.py", "publish_image.py", "verify_recipe.py", "test_recipe.py",
    "write_publish_receipt.py",
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(root=HERE):
    root = Path(root)
    if digest(root / "server.py") != SOURCE_SHA256:
        raise ValueError("MCP server source differs from reviewed hash")
    dockerfile = (root / "Dockerfile").read_text()
    if not dockerfile.startswith("FROM --platform=linux/amd64 " + BASE_IMAGE + "\n") or \
            "--no-index" not in dockerfile or "--require-hashes" not in dockerfile or \
            "USER 10001:10001" not in dockerfile or \
            dockerfile.count("python3 -m unittest test_server.py") != 2 or \
            'CMD ["python3", "-B", "/app/server.py"]' not in dockerfile:
        raise ValueError("MCP image Dockerfile changed its pinned runtime contract")
    lock = {}
    for line in lines(root / "requirements.lock"):
        match = REQUIREMENT.fullmatch(line)
        if not match or match.group(1) in lock:
            raise ValueError("MCP requirement lock changed")
        lock[match.group(1)] = (match.group(2), match.group(3))
    if len(lock) != 71 or lock.get("fastmcp", (None,))[0] != "3.4.7" or \
            lock.get("mcp", (None,))[0] != "1.30.0":
        raise ValueError("MCP wheel closure version/count differs")
    manifest = {}
    for line in lines(root / "wheelhouse.sha256"):
        match = MANIFEST.fullmatch(line)
        if not match or match.group(2) in manifest:
            raise ValueError("MCP wheel manifest changed")
        manifest[match.group(2)] = match.group(1)
    if len(manifest) != len(lock) or \
            digest(root / "fixtures" / "attack.ulaw") != ATTACK_AUDIO_SHA256 or \
            digest(root / "fixtures" / "benign.ulaw") != BENIGN_AUDIO_SHA256:
        raise ValueError("MCP manifest or fixed audio differs")
    if not re.search(r"^!wheelhouse/\*\.whl$", (root / ".dockerignore").read_text(), re.M):
        raise ValueError("MCP wheelhouse excluded from build context")
    for filename in RECIPE_FILES:
        if not (root / filename).is_file():
            raise ValueError("MCP image recipe file absent: " + filename)
    return {"sourceSHA256": SOURCE_SHA256, "baseImage": BASE_IMAGE,
            "wheelCount": len(lock),
            "recipeSHA256": {name: digest(root / name) for name in RECIPE_FILES},
            "attackAudioSHA256": ATTACK_AUDIO_SHA256,
            "benignAudioSHA256": BENIGN_AUDIO_SHA256}


if __name__ == "__main__":
    result = verify()
    print("verified MCP image source", result["sourceSHA256"],
          "and", result["wheelCount"], "locked wheels")
