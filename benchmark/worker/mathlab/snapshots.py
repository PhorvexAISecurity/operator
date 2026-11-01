"""Read-only snapshot sync from the operator through the Console relay.

Snapshots are immutable and content-addressed: a file is accepted only when its bytes hash
to the digest it was listed under and its header names the requested namespace/policy.
Nothing here can write to the cluster.
"""
import concurrent.futures
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import shutil
import struct
import tempfile
import urllib.parse
from datetime import datetime
from pathlib import Path

from .common import DIGEST, corpus_dir, utc, write_json, read_json, sha256_file

MAGIC = b'PXMLSNP1'
MAX_SNAPSHOT_BYTES = 64 << 20
MAX_INDEX_PAGES = 8


@contextmanager
def sync_lock(data_dir, namespace, policy):
    """Serialize stage download→ownership registration across processes.

    Acquire before any cache lock, never while holding a cache lock. This
    avoids exposing a second writer's ownership before the first registers.
    """
    corpus = corpus_dir(data_dir, namespace, policy)
    descriptor = os.open(corpus.parent/(policy+'.sync.lock'), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def cache_lock(data_dir, namespace, policy, exclusive=False):
    """One policy cache lock; callers must not nest acquisitions.

    Shared readers hold it through selection and verified freezing. Pruning and
    endpoint pointer publication use the exclusive form. Frozen run directories
    are independent of this cache and never need this lock during replay.
    """
    corpus = corpus_dir(data_dir, namespace, policy)
    descriptor = os.open(corpus.parent/(policy+'.cache.lock'), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def freeze_cohort(data_dir, namespace, policy, entries, target):
    """Copy immutable snapshots under the caller's shared cache lock."""
    source = corpus_dir(data_dir, namespace, policy)
    target = Path(target); target.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        if not DIGEST.fullmatch(entry['digest']):
            raise ValueError('invalid cohort digest')
        destination = target/(entry['digest']+'.pxms')
        if not destination.exists():
            shutil.copy2(source/destination.name, destination)
        if sha256_file(destination) != entry['digest']:
            raise ValueError('cohort snapshot %s failed its content check' % entry['digest'])
    return target


def _clock(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else None
    except (AttributeError, ValueError, TypeError):
        return None


def stage_listing(console, query, expected_header, *, newest=False, initial_entries=()):
    """Bounded, inclusive pagination; never jump over equal-time rows.

    Index headers can reject an obsolete cohort cheaply. They never establish
    acceptance: downloaded bytes still undergo the complete header/hash check.
    """
    query = dict(query)
    entries, rejected = list(initial_entries), []
    seen = {entry['digest'] for entry in entries}
    pages, more, reason, cursor = 0, False, None, query.get('since')
    wanted = page_limit = int(query['limit'])
    while pages < MAX_INDEX_PAGES:
        query['limit'] = str(page_limit)
        if cursor: query['since'] = cursor
        page = console.request('/api/math-lab/snapshots?' + urllib.parse.urlencode(query)).get('entries') or []
        pages += 1
        fresh = 0
        for entry in page:
            digest = entry.get('digest')
            if digest in seen: continue
            seen.add(digest); fresh += 1
            header = entry.get('header') or {}
            if header and any(header.get(key) != value for key, value in expected_header.items()):
                rejected.append({'digest': digest, 'reason': 'index header differs from pinned stage capture'})
            else:
                entries.append(entry)
        if newest:
            if any(_clock((entry.get('header') or {}).get('capturedAt')) is None for entry in entries):
                reason = 'recent snapshot index lacks valid capture timestamps'
                more = True
                break
            # Keep producer order, including its nanosecond timestamp ordering;
            # Python datetime comparison truncates sub-microsecond fractions.
            entries = entries[-wanted:]
        more = len(page) >= page_limit
        if not more: break
        next_cursor = (page[-1].get('header') or {}).get('capturedAt')
        clock = _clock(next_cursor)
        if clock is None or (cursor and (_clock(cursor) is None or clock < _clock(cursor))):
            reason = 'snapshot index has no monotonic capture-time cursor; cannot safely paginate'
            break
        if cursor and clock == _clock(cursor) and not fresh:
            if page_limit < 5000:
                page_limit = min(5000, max(page_limit + 1, page_limit * 2))
                continue
            reason = '5000 or more snapshots share a capture timestamp; the index cannot safely advance without a digest cursor'
            break
        cursor = next_cursor  # inclusive: boundary records must be rechecked
        if len(entries) >= wanted and not newest:
            break
    result = {'index_pages': pages, 'index_scanned': len(seen), 'rejected': rejected,
                     'more_available': more, 'next_since': cursor if more else None,
                     'pagination_blocked': reason}
    if newest:
        result['latest_scan_complete'] = not more and reason is None
    return entries, result


def read_header(path_or_bytes):
    def length(prefix):
        if prefix[:len(MAGIC)] != MAGIC:
            raise ValueError('not a math-lab snapshot')
        if len(prefix) != len(MAGIC) + 4:
            raise ValueError('snapshot header length out of range')
        size = struct.unpack('>I', prefix[len(MAGIC):])[0]
        if not 0 < size <= (1 << 20):
            raise ValueError('snapshot header length out of range')
        return size

    if isinstance(path_or_bytes, (bytes, bytearray)):
        size = length(path_or_bytes[:len(MAGIC) + 4])
        raw = bytes(path_or_bytes[len(MAGIC) + 4:len(MAGIC) + 4 + size])
    else:
        with open(path_or_bytes, 'rb') as f:
            size = length(f.read(len(MAGIC) + 4))
            raw = f.read(size)
    if len(raw) != size:
        raise ValueError('snapshot header length out of range')
    header = json.loads(raw)
    if header.get('schema') != 'math-lab.snapshot.v1':
        raise ValueError('unsupported snapshot schema')
    return header


def local_index(data_dir, namespace, policy, expected_header=None):
    """Headers of every locally held snapshot, in capture order."""
    return frozen_index(corpus_dir(data_dir, namespace, policy), expected_header)


def frozen_index(directory, expected_header=None):
    """Read an immutable run cohort, or a cache held under its policy lock."""
    out = []
    for path in sorted(Path(directory).glob('*.pxms')):
        digest = path.stem
        if not DIGEST.match(digest):
            continue
        try:
            header = read_header(path)
            size = path.stat().st_size
        except (OSError, ValueError):
            continue
        if expected_header and any(header.get(key) != value for key, value in expected_header.items()):
            continue
        out.append({'digest': digest, 'size': size, 'header': header})
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


def sync(data_dir, namespace, policy, console, since=None, limit=5000, progress=None, expected_header=None, max_bytes=None):
    """Download every listed snapshot not held locally. Returns a sync record."""
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
        raise ValueError('snapshot sync byte limit must be a positive integer')
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError('snapshot sync limit must be 1..5000')
    with cache_lock(data_dir, namespace, policy):
        return _sync(data_dir, namespace, policy, console, since, limit, progress, expected_header, max_bytes)


def _sync(data_dir, namespace, policy, console, since, limit, progress, expected_header, max_bytes):
    target = corpus_dir(data_dir, namespace, policy)
    if not since:
        # Incremental: the operator index is in capture order and bounded, so resume from the
        # newest tick already held instead of re-listing the oldest ones forever.
        held_entries = local_index(data_dir, namespace, policy, expected_header)
        if held_entries:
            since = held_entries[-1]['header'].get('capturedAt')
    query = {'namespace': namespace, 'policy': policy, 'limit': str(limit)}
    if expected_header:
        previous = read_json(target/'last-sync.json', {}) or {}
        continuation = previous.get('next_since')
        if previous.get('expected_header') == expected_header and previous.get('retry_from_since'):
            since = previous.get('since')
        elif (previous.get('expected_header') == expected_header and previous.get('more_available') and
                _clock(continuation) is not None and (not since or _clock(continuation) > _clock(since))):
            since = continuation
        query['policyUID'] = expected_header['policyUID']
        # Freeze this scan at the reader clock. Unrelated future-dated index
        # entries cannot create a cursor that skips later current capture.
        query['until'] = utc()
    if since:
        query['since'] = since
    scan = {}
    if expected_header:
        entries, scan = stage_listing(console, query, expected_header)
    else:
        entries = console.request('/api/math-lab/snapshots?' + urllib.parse.urlencode(query)).get('entries') or []
    held = {entry['digest'] for entry in local_index(data_dir, namespace, policy, expected_header)}
    record = {'schema_version': 'math-lab.sync.v1', 'started_at': utc(), 'namespace': namespace, 'policy': policy,
              'since': since, 'listed': len(entries), 'already_held': 0, 'downloaded': 0, 'rejected': [],
              'more_available': len(entries) >= limit, 'downloaded_bytes': 0, 'transferred_bytes': 0,
              'downloaded_digests': [], 'byte_limit_reached': False, 'max_bytes': max_bytes}
    record.update(scan)
    def fetch(entry, remaining=None):
        digest = entry.get('digest', '')
        if not DIGEST.match(digest):
            return digest, None, 'invalid digest', 0
        path = '/api/math-lab/snapshot?' + urllib.parse.urlencode({'namespace': namespace, 'digest': digest})
        try:
            with console.open(path, timeout=60) as response:
                raw = response.read(min(MAX_SNAPSHOT_BYTES + 1, remaining) if remaining is not None else MAX_SNAPSHOT_BYTES + 1)
        except Exception as error:
            # The bounded producer may evict an indexed tick while we download
            # the batch. Keep that gap visible without losing other valid ticks.
            if getattr(error, 'status', None) == 404:
                return digest, None, 'snapshot no longer available (HTTP 404)', 0
            raise
        if len(raw) > MAX_SNAPSHOT_BYTES or hashlib.sha256(raw).hexdigest() != digest:
            return digest, None, 'content-address check failed or transfer exceeded remaining byte limit', len(raw)
        try:
            header = read_header(raw)
        except ValueError as error:
            return digest, None, str(error), len(raw)
        if header.get('namespace') != namespace or header.get('policyName') != policy:
            return digest, None, 'snapshot belongs to another policy', len(raw)
        if expected_header and any(header.get(key) != value for key, value in expected_header.items()):
            return digest, None, 'snapshot source, brain image or policy UID differs from the pinned stage capture', len(raw)
        return digest, raw, None, len(raw)

    pending = []
    for entry in entries:
        if entry.get('digest') in held:
            record['already_held'] += 1
        else:
            pending.append(entry)
    pending.reverse()  # Prefer the newest ticks before the producer can evict them.
    record['deferred_snapshots'] = max(0, len(pending)-limit)
    pending = pending[:limit]
    done = 0
    def consume(results):
        nonlocal done
        for digest, raw, reason, transferred in results:
            done += 1
            record['transferred_bytes'] += transferred
            if raw is None:
                record['rejected'].append({'digest': digest, 'reason': reason})
            else:
                fd, tmp = tempfile.mkstemp(dir=target, prefix='.tmp-')
                with os.fdopen(fd, 'wb') as f:
                    f.write(raw)
                os.replace(tmp, target / (digest + '.pxms'))
                record['downloaded'] += 1
                record['downloaded_bytes'] += len(raw)
                record['downloaded_digests'].append(digest)
            if progress and (done % 10 == 0 or done == len(pending)):
                progress(done, len(pending))
    if max_bytes is None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            consume(pool.map(fetch, pending))
    else:
        # A sequential bounded transfer avoids queuing unbounded raw blobs or
        # allowing concurrent requests to overspend the shared byte allowance.
        for entry in pending:
            remaining = max_bytes - record['transferred_bytes']
            if remaining <= 0:
                record['byte_limit_reached'] = True
                break
            outcome = fetch(entry, remaining)
            consume([outcome])
            if record['transferred_bytes'] == max_bytes and (done < len(pending) or outcome[1] is None):
                record['byte_limit_reached'] = True
    if record['byte_limit_reached'] or record['deferred_snapshots']:
        record['more_available'] = True
        # Do not let a newly downloaded later tick skip earlier pending blobs.
        record['retry_from_since'] = True
        record['next_since'] = since
    record['finished_at'] = utc()
    record['corpus'] = corpus_summary(local_index(data_dir, namespace, policy, expected_header))
    if expected_header:
        record['expected_header'] = dict(expected_header)
    write_json(target / 'last-sync.json', record)
    return record
