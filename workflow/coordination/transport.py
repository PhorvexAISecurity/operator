"""One runtime bus per Git repository, independent of issue worktree contents."""
from pathlib import Path
import subprocess


def shared_root(coordination: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(coordination.parents[1]), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode:
        # Standalone copied harnesses have no sibling worktrees to coordinate.
        return coordination
    return Path(result.stdout.strip()) / "phorvex-workflow" / "bus"
