"""Canonical rendering and portable comparison of reviewed `04-diff.patch` artifacts.

`git diff --binary` abbreviates text-file `index OLD..NEW` headers to a length chosen
from the local object population, so the same pinned source pair renders 7-character
ids in one clone and 8-character ids in a fresh clone. New artifacts are rendered with
`--full-index`; recorded artifacts are compared byte-for-byte except that an index
header may carry a valid prefix of the pinned full id. Nothing else is normalized.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

# Git's MINIMUM_ABBREV; shorter ids are never emitted by any core.abbrev setting.
MIN_ABBREV = 4
HEX_SIZE = {'sha1': 40, 'sha256': 64}
DIFF_ARGS = ('--binary', '--full-index', '--no-color', '--no-ext-diff', '--no-textconv')
CANONICAL_COMMAND = 'git diff ' + ' '.join(DIFF_ARGS) + ' base_sha head_sha'
GATE_MESSAGE = ('04-diff.patch must equal nonempty ' + CANONICAL_COMMAND
                + ' (index headers may only abbreviate the pinned full ids)')
INDEX_LINE = re.compile(rb'index ([0-9a-f]+)\.\.([0-9a-f]+)( [0-7]{6})?')
# Extended header keywords that may sit between `diff --git` and the patch body.
EXTENDED_HEADERS = (b'old mode ', b'new mode ', b'deleted file mode ', b'new file mode ',
                    b'copy from ', b'copy to ', b'rename from ', b'rename to ',
                    b'similarity index ', b'dissimilarity index ', b'index ')


def hex_size(repo: Path) -> int:
    """Object id width of this repository; unsupported hash formats are refused, not guessed."""
    fmt = subprocess.check_output(['git', 'rev-parse', '--show-object-format'], cwd=repo).decode().strip()
    if fmt not in HEX_SIZE:
        raise ValueError(f'unsupported repository object format {fmt!r}')
    return HEX_SIZE[fmt]


def render(repo: Path, base: str, head: str) -> bytes:
    """Canonical patch bytes for a pinned source pair; identical in every clone."""
    return subprocess.check_output(['git', 'diff', *DIFF_ARGS, str(base), str(head)], cwd=repo)


def index_header_mismatch(recorded: bytes, canonical: bytes, hexsz: int) -> str | None:
    full = INDEX_LINE.fullmatch(canonical)
    if not full or len(full[1]) != hexsz or len(full[2]) != hexsz:
        return 'canonical index header is not a full-index header'
    short = INDEX_LINE.fullmatch(recorded)
    if not short:
        return 'recorded index header is malformed'
    if short[3] != full[3]:
        return 'index header mode differs'
    for side, prefix, oid in (('old', short[1], full[1]), ('new', short[2], full[2])):
        if not MIN_ABBREV <= len(prefix) <= hexsz:
            return f'{side} object id abbreviation length {len(prefix)} is outside {MIN_ABBREV}..{hexsz}'
        if not oid.startswith(prefix):
            return f'{side} object id {prefix.decode()} is not a prefix of pinned {oid.decode()}'
        if (prefix == b'0' * len(prefix)) != (oid == b'0' * hexsz):
            return f'{side} object id zero placeholder is only valid for an absent side'
    return None


def mismatch(recorded: bytes, canonical: bytes, hexsz: int) -> str | None:
    """None when `recorded` equals `canonical` modulo valid index abbreviation; else the first defect."""
    if not canonical:
        return 'canonical diff is empty'
    if recorded == canonical:
        return None
    if not recorded:
        return 'recorded patch is empty'
    ours, theirs = recorded.split(b'\n'), canonical.split(b'\n')
    if len(ours) != len(theirs):
        return f'line count differs ({len(ours)} recorded, {len(theirs)} canonical)'
    in_header = False
    for number, (mine, expected) in enumerate(zip(ours, theirs), start=1):
        if expected.startswith(b'diff --git '):
            in_header = True
        elif not expected.startswith(EXTENDED_HEADERS):
            in_header = False
        if mine == expected:
            continue
        if in_header and expected.startswith(b'index ') and mine.startswith(b'index '):
            reason = index_header_mismatch(mine, expected, hexsz)
            if reason is None:
                continue
            return f'line {number}: {reason}'
        return f'line {number} differs from the pinned source diff'
    return None


def verify(repo: Path, patch: Path | None, base: str, head: str) -> str | None:
    """Gate contract: the recorded artifact must be the nonempty pinned diff modulo index abbreviation."""
    if not patch:
        return GATE_MESSAGE
    try:
        canonical = render(repo, base, head)
        hexsz = hex_size(repo)
    except (subprocess.CalledProcessError, ValueError) as error:
        return f'{GATE_MESSAGE}: {error}'
    reason = mismatch(patch.read_bytes(), canonical, hexsz)
    return None if reason is None else f'{GATE_MESSAGE}: {reason}'
