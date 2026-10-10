"""Read-only snapshot sync from the operator through the Console relay.

Snapshots are immutable and content-addressed: a file is accepted only when its bytes hash
to the digest it was listed under and its header names the requested namespace/policy.
Nothing here can write to the cluster.
"""
import hashlib
import json
import os
import struct
import tempfile
import urllib.parse
from pathlib import Path

from .common import DIGEST, corpus_dir, utc, write_json

MAGIC = b'PXMLSNP1'
MAX_SNAPSHOT_BYTES = 64 << 20


def read_header(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = bytes(path_or_bytes[:len(MAGIC) + 4 + (1 << 20)])
    else:
        with open(path_or_bytes, 'rb') as f:
            raw = f.read(len(MAGIC) + 4 + (1 << 20))
    if raw[:len(MAGIC)] != MAGIC:
        raise ValueError('not a math-lab snapshot')
    (size,) = struct.unpack('>I', raw[len(MAGIC):len(MAGIC) + 4])
    if size == 0 or size > (1 << 20) or len(raw) < len(MAGIC) + 4 + size:
        raise ValueError('snapshot header length out of range')
    header = json.loads(raw[len(MAGIC) + 4:len(MAGIC) + 4 + size])
    if header.get('schema') != 'math-lab.snapshot.v1':
        raise ValueError('unsupported snapshot schema')
    return header


def local_index(data_dir, namespace, policy):
    """Headers of every locally held snapshot, in capture order."""
    out = []
    for path in sorted(corpus_dir(data_dir, namespace, policy).glob('*.pxms')):
        digest = path.stem
        if not DIGEST.match(digest):
            continue
        try:
            header = read_header(path)
        except (OSError, ValueError):
            continue
        out.append({'digest': digest, 'size': path.stat().st_size, 'header': header})
    out.sort(key=lambda e: (e['header'].get('capturedAt') or '', e['digest']))
    return out


def corpus_summary(entries):
    if not entries:
        return {'snapshots': 0}
    def groups(key):
        counts = {}
        for e in entries:
            v = e['header'].get(key) or 'unknown'
            counts[v] = counts.get(v, 0) + 1
        return counts
    return {'snapshots': len(entries), 'first_captured_at': entries[0]['header'].get('capturedAt'),
            'last_captured_at': entries[-1]['header'].get('capturedAt'), 'bytes': sum(e['size'] for e in entries),
            'git_sha': groups('gitSHA'), 'economics_mode': groups('economicsMode'), 'policy_uid': groups('policyUID'),
            'process_config_hash': groups('processConfigHash'), 'parameter_manifest_hash': groups('parameterManifestHash'),
            'policy_overrides_hash': groups('policyOverridesHash'),
            'finalized': sum(1 for e in entries if e['header'].get('finalized')),
            'with_unreplayable_fields': sum(1 for e in entries if e['header'].get('unreplayableFields'))}


def sync(data_dir, namespace, policy, console, since=None, limit=5000, progress=None):
    """Download every listed snapshot not held locally. Returns a sync record."""
    target = corpus_dir(data_dir, namespace, policy)
    query = {'namespace': namespace, 'policy': policy, 'limit': str(limit)}
    if since:
        query['since'] = since
    listing = console.request('/api/math-lab/snapshots?' + urllib.parse.urlencode(query))
    entries = listing.get('entries') or []
    held = {p.stem for p in target.glob('*.pxms')}
    record = {'schema_version': 'math-lab.sync.v1', 'started_at': utc(), 'namespace': namespace, 'policy': policy,
              'listed': len(entries), 'already_held': 0, 'downloaded': 0, 'rejected': []}
    for i, entry in enumerate(entries):
        digest = entry.get('digest', '')
        if not DIGEST.match(digest):
            record['rejected'].append({'digest': digest, 'reason': 'invalid digest'})
            continue
        if digest in held:
            record['already_held'] += 1
            continue
        path = '/api/math-lab/snapshot?' + urllib.parse.urlencode({'namespace': namespace, 'digest': digest})
        with console.open(path, timeout=60) as response:
            raw = response.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES or hashlib.sha256(raw).hexdigest() != digest:
            record['rejected'].append({'digest': digest, 'reason': 'content-address check failed'})
            continue
        try:
            header = read_header(raw)
        except ValueError as error:
            record['rejected'].append({'digest': digest, 'reason': str(error)})
            continue
        if header.get('namespace') != namespace or header.get('policyName') != policy:
            record['rejected'].append({'digest': digest, 'reason': 'snapshot belongs to another policy'})
            continue
        fd, tmp = tempfile.mkstemp(dir=target, prefix='.tmp-')
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
        os.replace(tmp, target / (digest + '.pxms'))
        record['downloaded'] += 1
        if progress:
            progress(i + 1, len(entries))
    record['finished_at'] = utc()
    record['corpus'] = corpus_summary(local_index(data_dir, namespace, policy))
    write_json(target / 'last-sync.json', record)
    return record
