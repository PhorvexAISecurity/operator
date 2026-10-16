#!/usr/bin/env python3
"""Fail if a Go file changed since the base revision is not gofmt-clean.

Only changed files are checked. Several existing files are pinned by content hash
(harness scenario sourceSHA256 values, generated cover maps), so reformatting the
whole tree at once would break those pins; instead every change formats what it
touches. Usage: check-go-format.py <base-revision>
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True).stdout


def changed_go_files(base, root=ROOT):
    merge_base = git(root, 'merge-base', base, 'HEAD').strip()
    out = git(root, 'diff', '--name-only', '--diff-filter=ACMR', merge_base, 'HEAD', '--', '*.go')
    return [path for path in out.splitlines() if path]


def unformatted(files, root=ROOT, gofmt='gofmt'):
    if not files:
        return []
    out = subprocess.run([gofmt, '-l', *files], cwd=root, check=True,
                         capture_output=True, text=True).stdout
    return [path for path in out.splitlines() if path]


def main(argv):
    if len(argv) != 2 or not argv[1].strip():
        print('usage: check-go-format.py <base-revision>', file=sys.stderr)
        return 2
    files = changed_go_files(argv[1])
    bad = unformatted(files)
    if bad:
        print('gofmt would reformat these changed files (run gofmt -w):', file=sys.stderr)
        print('\n'.join(bad), file=sys.stderr)
        return 1
    print(f'Go format gate passed ({len(files)} changed Go files)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
