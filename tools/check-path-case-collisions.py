#!/usr/bin/env python3
"""Reject tracked paths that collide on case-insensitive checkouts.

macOS (APFS/HFS+) and Windows compare names case- and Unicode-normalization-
insensitively. Git then keeps one file per colliding group in the working tree
and reports the others as modified, so a commit from that checkout overwrites
one file with the other's bytes. Each group is reported at its shortest
colliding prefix: a directory collision is not repeated for every file below it.
"""
from collections import defaultdict
from pathlib import Path
import subprocess
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]


def fold(path):
    return unicodedata.normalize('NFC', path).casefold()


def collisions(paths):
    groups = defaultdict(set)
    for path in paths:
        parts = path.split('/')
        for end in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:end])
            groups[fold(prefix)].add(prefix)
    colliding = {key for key, names in groups.items() if len(names) > 1}

    def under_collision(key):
        parts = key.split('/')
        return any('/'.join(parts[:end]) in colliding for end in range(1, len(parts)))

    return sorted(sorted(groups[key]) for key in colliding if not under_collision(key))


def tracked_paths():
    raw = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'],
                         check=True, capture_output=True).stdout
    return [p for p in raw.decode('utf-8', 'surrogateescape').split('\0') if p]


def main():
    paths = tracked_paths()
    groups = collisions(paths)
    if groups:
        for group in groups:
            print('case-insensitive path collision: ' + ' | '.join(group), file=sys.stderr)
        print('Rename all but one path per group; sealed records keep recorded paths and '
              'bind content by SHA-256 (see a PATH-RELOCATIONS.json beside renamed evidence).',
              file=sys.stderr)
        return 1
    print(f'Path portability gate passed ({len(paths)} tracked paths, no case-insensitive collisions)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
