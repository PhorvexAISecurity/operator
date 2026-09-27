"""Check the installed classifier and web dependency closure without model downloads."""

from importlib import metadata
from pathlib import Path
import platform
import sys

from verify_wheelhouse import REQUIREMENT, ROOT_VERSIONS, lines


def verify(lock_path: Path) -> int:
    if sys.version_info[:2] != (3, 11) or platform.system() != "Linux" or \
            platform.machine() != "x86_64":
        raise ValueError("proxy runtime requires linux/amd64 CPython 3.11")
    pinned = {}
    for line in lines(Path(lock_path)):
        match = REQUIREMENT.fullmatch(line)
        if not match:
            raise ValueError("invalid locked requirement")
        name, version, _ = match.groups()
        if metadata.version(name) != version:
            raise ValueError("installed proxy dependency differs: " + name)
        pinned[name] = version
    if len(pinned) != 41 or any(pinned.get(name) != version for name, version in ROOT_VERSIONS.items()):
        raise ValueError("installed proxy root closure differs")
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    import torch
    import uvicorn  # noqa: F401
    from transformers import pipeline
    if not callable(pipeline) or not callable(torch.set_num_threads):
        raise ValueError("real classifier pipeline import unavailable")
    return len(pinned)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_runtime.py REQUIREMENTS_LOCK")
    print("verified", verify(Path(sys.argv[1])), "installed proxy distributions and real pipeline import")
