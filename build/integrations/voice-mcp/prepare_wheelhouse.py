"""Fetch exact locked wheels for the disconnected MCP image build context."""

import argparse
from pathlib import Path
import subprocess
import sys

from verify_wheelhouse import verify


HERE = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    if not args.prepare or sys.version_info[:2] != (3, 11):
        raise SystemExit("use Python 3.11 with exact --prepare")
    wheelhouse = HERE / "wheelhouse"
    if wheelhouse.exists():
        raise SystemExit("wheelhouse already exists; refuse ambiguous reuse")
    wheelhouse.mkdir(mode=0o700)
    subprocess.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:",
                    "--no-deps", "--require-hashes", "--dest", str(wheelhouse),
                    "-r", str(HERE / "requirements.lock")], check=True, timeout=300)
    print("prepared", verify(HERE / "requirements.lock", HERE / "wheelhouse.sha256", wheelhouse),
          "exact wheels")


if __name__ == "__main__":
    main()
