"""Explicit, independently approved evidence reuse; never infer test dependencies."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

REUSABLE = {'l0', 'l1', 'l2', 'positive_control', 'incident'}


def signature(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def fingerprint(repo: Path, source: str, inputs: list[str]) -> str:
    if not isinstance(inputs, list) or not inputs or any(not isinstance(p, str) for p in inputs) or len(set(inputs)) != len(inputs):
        raise ValueError('inputs must be nonempty, unique repository paths')
    records = []
    for item in sorted(inputs):
        if not isinstance(item, str): raise ValueError('inputs must be strings')
        path = Path(item)
        if (path.is_absolute() or '..' in path.parts
                or item in {'', '.'} or any(c in item for c in '*?[:\\\n')):
            raise ValueError('inputs must be literal repository-relative file/directory paths')
        raw = subprocess.check_output(['git', 'ls-tree', '-rz', '--full-tree', source,
                                       '--', item], cwd=repo)
        if not raw:
            raise ValueError(f'input {item} does not exist at {source}')
        if any(row.startswith(b'120000 ') for row in raw.split(b'\0')):
            raise ValueError('symlink inputs need their actual tracked dependencies; do not infer reuse')
        records.append((item, raw.decode()))
    return signature({'tree_entries': records})


def validate(root: Path, fix: Path, check: dict, *, archived=False) -> list[str]:
    """Archived records (ARCHIVE.yaml) pin source-repository commits that this history
    lacks: their input fingerprints are not recomputed and a stripped verdict may be absent."""
    problems = []
    if 'inputs' in check and not archived:
        try:
            if fingerprint(root.parent, check['source_sha'], check['inputs']) != check.get('inputs_sha256'):
                problems.append('declared evidence inputs changed')
        except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
            problems.append(f'invalid evidence inputs: {exc}')
    if 'reused_from' in check:
        approved = check.get('reuse_approval', {})
        verdict = fix / approved.get('artifact', '')
        stripped = (archived and bool(approved.get('artifact')) and not verdict.exists()
                    and fix.resolve() in verdict.resolve().parents)
        if (not approved.get('by') or approved.get('inputs_sha256') != check.get('inputs_sha256')
                or approved.get('inputs') != check.get('inputs')
                or approved.get('check_sha256') != check['reused_from'].get('check_sha256')
                or (not stripped and (not verdict.is_file() or fix.resolve() not in verdict.resolve().parents
                    or hashlib.sha256(verdict.read_bytes()).hexdigest() != approved.get('sha256')))):
            problems.append('reused evidence lacks its retained independent scope approval')
    return problems


def prepare_reuse(w, fix: Path, status: dict, key: str, by: str) -> dict:
    if key not in REUSABLE or by not in w.gates.signers(status, key):
        raise ValueError('this participant cannot reuse that check')
    old = copy.deepcopy(status.get('checks', {}).get(key, {}))
    approved = status.get('reuse_approvals', {}).get(key, {})
    if old.get('result') != 'PASS' or not old.get('inputs'):
        raise ValueError(f'{key}: reuse requires prior PASS and explicit dependency inputs')
    if (approved.get('by') != status['roles']['skeptic']
            or approved.get('check_sha256') != signature(old)):
        raise ValueError(f'{key}: reviewer has not approved this exact check and its scope')
    previous = copy.deepcopy(status)
    previous['implementation']['head_sha'] = old['source_sha']
    errors = w.gates.check_errors(w.ROOT, fix, previous, key)
    if errors:
        raise ValueError('; '.join(errors))
    current = w.gates.source_for(status, key)
    if fingerprint(w.ROOT.parent, current, old['inputs']) != old['inputs_sha256']:
        raise ValueError(f'{key}: inputs changed; execute the affected checks again')
    return {'old': old, 'approval': approved, 'source_sha': current}
