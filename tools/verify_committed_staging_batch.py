#!/usr/bin/env python3
"""Reconstruct and verify a committed staging batch from its exact source."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import staging_release as release


ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "release/staging-batch.json"


def run(*command: str, cwd: Path = ROOT) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    if not BATCH.exists():
        print("no committed staging batch")
        return 0
    batch = release.read_json(BATCH)
    source = batch.get("source", "") if isinstance(batch, dict) else ""
    if not release.SHA.fullmatch(source):
        raise ValueError("committed staging batch source is malformed")
    run("git", "merge-base", "--is-ancestor", source, "HEAD")
    temporary = Path(tempfile.mkdtemp(prefix="phorvex-staging-source-"))
    source_root = temporary / "source"
    helper = temporary / "servicerelease"
    services = temporary / "services.json"
    try:
        run("git", "worktree", "add", "--detach", str(source_root), source)
        run("go", "-C", str(source_root / "phorvex"), "build", "-o", str(helper), "./tools/servicerelease")
        run(
            str(helper), "staging-contract", "--target", "staging-isolated",
            "--source", source, "--output", str(services), cwd=source_root,
        )
        canonical = release.read_json(services)
        value = release.validate_batch(release.read_json(BATCH), require_complete=True, canonical_services=canonical)
        # The recorded source is the only allowed base: this rejects a digest-pin
        # proposal that also changes any production/shared or unrelated path.
        release.verify_deployment(value, source, canonical)
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(source_root)], cwd=ROOT, check=False)
        shutil.rmtree(temporary, ignore_errors=True)
    print(f"verified committed staging batch {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
