"""Reject a built CRM image whose source or installed package set has drifted."""
import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: verify_runtime_closure.py lock app.py")
    lock = json.loads(Path(argv[1]).read_text())
    source_hash = hashlib.sha256(Path(argv[2]).read_bytes()).hexdigest()
    if lock["schema"] != "phorvex.crm-installed-dependencies.v1" or source_hash != lock["sourceSHA256"]:
        raise RuntimeError("installed CRM source differs")
    installed = {d.metadata["Name"].lower().replace("_", "-"): d.version for d in importlib.metadata.distributions()}
    if platform.python_version() != lock["python"] or installed != lock["packages"]:
        raise RuntimeError("installed Python distribution closure differs")
    print(f"verified source and {len(installed)} installed Python distributions")


if __name__ == "__main__":
    main(sys.argv)
