"""Check the installed, non-root fixture runtime without network access."""

from importlib import metadata
import importlib
from pathlib import Path
import platform
import sys

from verify_wheelhouse import parse_lock


def verify(lock_path):
    if sys.version_info[:2] != (3, 11) or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("fixture runtime requires Linux x86_64 Python 3.11")
    pinned = parse_lock(lock_path)
    for name, (version, _) in pinned.items():
        if metadata.version(name.replace("_", "-")) != version:
            raise ValueError(f"installed package version differs: {name}")
    for name in ("fastapi", "httpx", "uvicorn"):
        importlib.import_module(name)
    return len(pinned)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_runtime.py LOCK")
    try:
        count = verify(Path(sys.argv[1]))
    except (OSError, UnicodeError, ValueError, metadata.PackageNotFoundError, ImportError) as exc:
        raise SystemExit(f"runtime verification failed: {exc}") from exc
    print(f"verified {count} installed pinned packages")
