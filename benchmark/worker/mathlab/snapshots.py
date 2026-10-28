"""Read-only snapshot sync from the operator through the Console relay.

Snapshots are immutable and content-addressed: a file is accepted only when its bytes hash
to the digest it was listed under and its header names the requested namespace/policy.
Nothing here can write to the cluster.
"""
import concurrent.futures
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
    if not since:
        # Incremental: the operator index is in capture order and bounded, so resume from the
        # newest tick already held instead of re-listing the oldest ones forever.
        held_entries = local_index(data_dir, namespace, policy)
        if held_entries:
            since = held_entries[-1]['header'].get('capturedAt')
    query = {'namespace': namespace, 'policy': policy, 'limit': str(limit)}
    if since:
        query['since'] = since
    listing = console.request('/api/math-lab/snapshots?' + urllib.parse.urlencode(query))
    entries = listing.get('entries') or []
    held = {p.stem for p in target.glob('*.pxms')}
    record = {'schema_version': 'math-lab.sync.v1', 'started_at': utc(), 'namespace': namespace, 'policy': policy,
              'since': since, 'listed': len(entries), 'already_held': 0, 'downloaded': 0, 'rejected': [],
              'more_available': len(entries) >= limit}
    def fetch(entry):
        digest = entry.get('digest', '')
        if not DIGEST.match(digest):
            return digest, None, 'invalid digest'
        path = '/api/math-lab/snapshot?' + urllib.parse.urlencode({'namespace': namespace, 'digest': digest})
        try:
            with console.open(path, timeout=60) as response:
                raw = response.read(MAX_SNAPSHOT_BYTES + 1)
        except Exception as error:
            # The bounded producer may evict an indexed tick while we download
            # the batch. Keep that gap visible without losing other valid ticks.
            if getattr(error, 'status', None) == 404:
                return digest, None, 'snapshot no longer available (HTTP 404)'
            raise
        if len(raw) > MAX_SNAPSHOT_BYTES or hashlib.sha256(raw).hexdigest() != digest:
            return digest, None, 'content-address check failed'
        try:
            header = read_header(raw)
        except ValueError as error:
            return digest, None, str(error)
        if header.get('namespace') != namespace or header.get('policyName') != policy:
            return digest, None, 'snapshot belongs to another policy'
        return digest, raw, None

    pending = []
    for entry in entries:
        if entry.get('digest') in held:
            record['already_held'] += 1
        else:
            pending.append(entry)
    pending.reverse()  # Prefer the newest ticks before the producer can evict them.
    done = 0
    # A few concurrent reads keep the relay busy without exceeding the operator listener's
    # four-reader bound (the console's own audit cursor also uses it).
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for digest, raw, reason in pool.map(fetch, pending):
            done += 1
            if raw is None:
                record['rejected'].append({'digest': digest, 'reason': reason})
            else:
                fd, tmp = tempfile.mkstemp(dir=target, prefix='.tmp-')
                with os.fdopen(fd, 'wb') as f:
                    f.write(raw)
                os.replace(tmp, target / (digest + '.pxms'))
                record['downloaded'] += 1
            if progress and (done % 10 == 0 or done == len(pending)):
                progress(done, len(pending))
    record['finished_at'] = utc()
    record['corpus'] = corpus_summary(local_index(data_dir, namespace, policy))
    write_json(target / 'last-sync.json', record)
    return record
