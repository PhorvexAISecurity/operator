#!/usr/bin/env python3
"""Reject repository-local Claude settings from the Git index without reading them."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROHIBITED = ('.claude/settings.json', '.claude/settings.local.json')


def tracked(repo: Path) -> list[str]:
    output = subprocess.check_output(['git', 'ls-files', '-z', '--', *PROHIBITED], cwd=repo)
    return [part.decode() for part in output.split(b'\0') if part]


def main() -> int:
    found = tracked(Path(__file__).resolve().parents[2])
    if found:
        print('prohibited private settings tracked in Git: ' + ', '.join(found), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
