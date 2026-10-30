#!/usr/bin/env python3
"""Reconstruct and verify a committed staging batch from its exact source."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import staging_release as release


ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "release/staging-batch.json"
SHARED_BATCH = ROOT / "release/batch.json"


def run(*command: str, cwd: Path = ROOT) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def superseding_shared_source(isolated_source: str) -> str | None:
    if not SHARED_BATCH.exists():
        return None
    shared = release.read_json(SHARED_BATCH)
    if not isinstance(shared, dict) or shared.get("status") != "complete":
        return None
    source = shared.get("source", "")
    if source == isolated_source or not release.SHA.fullmatch(source):
        return None
    relation = subprocess.run(
        ["git", "merge-base", "--is-ancestor", isolated_source, source], cwd=ROOT
    )
    if relation.returncode == 0:
        return source
    if relation.returncode == 1:
        return None
    raise RuntimeError("cannot compare isolated and shared release sources")


def isolated_selection_commit(source: str) -> str:
    selection = subprocess.run(
        ["git", "log", "-1", "--format=%H", "HEAD", "--", "release/staging-batch.json"],
        cwd=ROOT, check=True, text=True, capture_output=True,
    ).stdout.strip()
    if not release.SHA.fullmatch(selection):
        raise ValueError("committed staging batch has no exact selection commit")
    run("git", "merge-base", "--is-ancestor", source, selection)
    run("git", "merge-base", "--is-ancestor", selection, "HEAD")
    selected = subprocess.run(
        ["git", "show", f"{selection}:release/staging-batch.json"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout
    if selected != BATCH.read_bytes():
        raise ValueError("committed staging batch differs from its selection commit")
    return selection


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
    shared_root = temporary / "shared-source"
    selection_root = temporary / "isolated-selection"
    try:
        run("git", "worktree", "add", "--detach", str(source_root), source)
        run("go", "-C", str(source_root / "phorvex"), "build", "-o", str(helper), "./tools/servicerelease")
        run(
            str(helper), "staging-contract", "--target", "staging-isolated",
            "--source", source, "--output", str(services), cwd=source_root,
        )
        # Bind every staging target and fixture authority to the recorded source,
        # rather than accepting a later PR's internally consistent replacement.
        run(
            sys.executable, str(source_root / "tools/staging_release.py"), "verify",
            "--batch", str(BATCH), "--services", str(services), "--complete", cwd=source_root,
        )
        canonical = release.read_json(services)
        value = release.validate_batch(
            release.read_json(BATCH), require_complete=True, canonical_services=canonical
        )
        selection = isolated_selection_commit(source)
        run("git", "worktree", "add", "--detach", str(selection_root), selection)
        # Re-run the source-pinned proposal gate at the exact commit that selected
        # this batch even after a later shared publication supersedes its consumers.
        # This retains the original production/staging non-diff proof permanently.
        run(
            sys.executable, str(selection_root / "tools/staging_release.py"),
            "verify-deployment", "--batch", str(selection_root / "release/staging-batch.json"),
            "--services", str(services), "--base", source, cwd=selection_root,
        )
        shared_source = superseding_shared_source(source)
        if shared_source:
            shared_helper = temporary / "shared-servicerelease"
            run("git", "worktree", "add", "--detach", str(shared_root), shared_source)
            run(
                "go", "-C", str(shared_root / "phorvex"), "build", "-o", str(shared_helper),
                "./tools/servicerelease",
            )
            # The source-built shared helper must prove the current batch, tags,
            # deployment consumers and clean working tree before it supersedes
            # the historical isolated selection.
            run(str(shared_helper), "pending", "--json", cwd=ROOT)
            # Shared releases are legitimately component subsets. Only those
            # exact components supersede isolated pins; every retained service
            # and both fixtures must still match the isolated batch. Fixture
            # renders also bind a shared attacks image when attacks is selected.
            release.verify_deployment(
                value, None, canonical, superseding_shared=release.read_json(SHARED_BATCH)
            )
        else:
            # Current source PRs may evolve unrelated reviewed code after the pin
            # selection, but the retained staging consumers must remain exact.
            release.verify_deployment(value, None, canonical)
    finally:
        if selection_root.exists():
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(selection_root)], cwd=ROOT, check=False
            )
        if shared_root.exists():
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(shared_root)], cwd=ROOT, check=False
            )
        subprocess.run(["git", "worktree", "remove", "--force", str(source_root)], cwd=ROOT, check=False)
        shutil.rmtree(temporary, ignore_errors=True)
    print(f"verified committed staging batch {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
