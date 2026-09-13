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
import hashlib
from pathlib import Path

# Git's MINIMUM_ABBREV; shorter ids are never emitted by any core.abbrev setting.
MIN_ABBREV = 4
HEX_SIZE = {'sha1': 40, 'sha256': 64}
DIFF_ARGS = ('--binary', '--full-index', '--no-color', '--no-ext-diff', '--no-textconv')
CANONICAL_COMMAND = 'git diff ' + ' '.join(DIFF_ARGS) + ' base_sha head_sha'
GATE_MESSAGE = ('04-diff.patch must equal nonempty ' + CANONICAL_COMMAND
                + ' (index headers may only abbreviate the pinned full ids)')
DIGEST_FORMAT = 'git-diff-digest-v1'
DIGEST_GATE_MESSAGE = ('04-diff.patch must be a strict git-diff-digest-v1 envelope for nonempty '
                       + CANONICAL_COMMAND)
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


def canonical_diff(repo: Path, base: str, head: str) -> bytes:
    """Canonical patch bytes for a pinned source pair; identical in every clone."""
    return subprocess.check_output(['git', 'diff', *DIFF_ARGS, str(base), str(head)], cwd=repo)


def resolved_commit(repo: Path, revision: str) -> str:
    return subprocess.check_output(['git', 'rev-parse', '--verify', revision + '^{commit}'], cwd=repo).decode().strip()


def render(repo: Path, base: str, head: str, diff_format: str | None = None) -> bytes:
    """Render the selected evidence format; absent format retains the full-patch contract."""
    canonical = canonical_diff(repo, base, head)
    if diff_format is None or diff_format == 'full-patch':
        return canonical
    if diff_format != DIGEST_FORMAT:
        raise ValueError(f'unknown implementation.diff_format {diff_format!r}')
    if not canonical:
        raise ValueError('canonical diff is empty')
    resolved_base = resolved_commit(repo, base)
    resolved_head = resolved_commit(repo, head)
    return (f'format: {DIGEST_FORMAT}\nbase_sha: {resolved_base}\nhead_sha: {resolved_head}\n'
            f'diff_sha256: {hashlib.sha256(canonical).hexdigest()}\n').encode()


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


def verify(repo: Path, patch: Path | None, base: str, head: str, diff_format: str | None = None) -> str | None:
    """Gate contract: the recorded artifact must be the nonempty pinned diff modulo index abbreviation."""
    message = DIGEST_GATE_MESSAGE if diff_format == DIGEST_FORMAT else GATE_MESSAGE
    if not patch:
        return message
    try:
        canonical = canonical_diff(repo, base, head)
        resolved_base = resolved_commit(repo, base)
        resolved_head = resolved_commit(repo, head)
        if diff_format == DIGEST_FORMAT:
            if not canonical:
                return f'{message}: canonical diff is empty'
            expected = render(repo, resolved_base, resolved_head, diff_format)
            recorded = patch.read_bytes()
            lines = recorded.splitlines(keepends=True)
            if len(lines) != 4 or any(not line.endswith(b'\n') for line in lines):
                return f'{message}: malformed envelope'
            return None if recorded == expected else f'{message}: envelope fields or digest differ from pinned source diff'
        if diff_format not in (None, 'full-patch'):
            return f'{message}: unknown implementation.diff_format {diff_format!r}'
        hexsz = hex_size(repo)
    except (subprocess.CalledProcessError, ValueError) as error:
        return f'{message}: {error}'
    reason = mismatch(patch.read_bytes(), canonical, hexsz)
    return None if reason is None else f'{message}: {reason}'
