"""Opt-in recent inventory for reconciliation; ordinary sync stays incremental.

Metadata pagination reaches a frozen upper bound before downloading the retained
tail. Incomplete scans persist scoped progress and never claim latest data.
This operational inventory horizon does not alter study W/L or evidence coverage.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import urllib.parse

from . import snapshots
from .common import read_json, write_json, sha256_json

MAX_PROGRESS_BYTES = 8 << 20


def sync(data_dir, namespace, policy, console, *, expected_header, scope, progress_root,
         recent_seconds=3600, limit=256, max_bytes=None, progress=None):
    if type(recent_seconds) is not int or not 60 <= recent_seconds <= 86400 or not 1 <= limit <= 4999:
        raise ValueError('recent inventory requires60..86400 seconds and1..4999 retained headers')
    now = datetime.now(timezone.utc)
    identity = {'expected_header': expected_header, 'namespace': namespace, 'policy': policy,
                'scope': scope, 'recent_seconds': recent_seconds, 'limit': limit}
    path = Path(progress_root)/(sha256_json(identity)+'.json')
    if path.exists() and (path.is_symlink() or path.stat().st_size > MAX_PROGRESS_BYTES):
        raise ValueError('recent inventory progress exceeds its safe bound')
    held = read_json(path, {}) or {}
    start = (now-timedelta(seconds=recent_seconds)).isoformat().replace('+00:00','Z')
    until = now.isoformat().replace('+00:00','Z')
    carry = []
    held_until = snapshots._clock(held.get('until'))
    cursor = snapshots._clock(held.get('next_since'))
    if (held.get('identity') == identity and held.get('complete') is False and held_until is not None
            and 0 <= (now-held_until).total_seconds() <= 900 and cursor is not None
            and snapshots._clock(held.get('since')) is not None
            and snapshots._clock(held['since']) <= cursor <= held_until):
        start, until, carry = held['next_since'], held['until'], held.get('entries') or []
        if not isinstance(carry,list) or len(carry)>limit or any(
                not isinstance(e,dict) or not snapshots.DIGEST.fullmatch(str(e.get('digest','')))
                or any((e.get('header') or {}).get(k)!=v for k,v in expected_header.items())
                or snapshots._clock((e.get('header') or {}).get('capturedAt')) is None for e in carry):
            raise ValueError('recent inventory progress contains invalid retained headers')
    query = {'namespace':namespace,'policy':policy,'policyUID':expected_header['policyUID'],
             'since':start,'until':until,'limit':str(limit)}
    entries, scan = snapshots.stage_listing(console,query,expected_header,newest=True,initial_entries=carry)
    complete = scan['latest_scan_complete']
    state = {'schema':'math-lab.recent-inventory.v1','identity':identity,'since':held.get('since',start) if carry else start,
             'until':until,'next_since':scan.get('next_since'),'complete':complete,'entries':entries}
    if len(json.dumps(state).encode()) > MAX_PROGRESS_BYTES:
        raise ValueError('recent inventory retained headers exceed8MiB')
    write_json(path,state)
    inventory = {**scan,'since':state['since'],'until':until,'recent_seconds':recent_seconds,
                 'retained_headers':len(entries),'progress_path':str(path),
                 'semantics':'Operational latest-tick inventory only; requested study windows and journal history are unchanged.'}
    if not complete:
        return {'downloaded':0,'downloaded_digests':[],'transferred_bytes':0,'downloaded_bytes':0,
                'recent_inventory':inventory,'latest_scan_complete':False}

    class FrozenIndex:
        def request(self, url):
            values=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if values.get('namespace') != [namespace] or values.get('policy') != [policy]:
                raise ValueError('frozen recent index scope mismatch')
            # The complete frozen tail is authoritative only as a list to fetch.
            # snapshots.sync still verifies every downloaded content hash/header.
            return {'entries':entries}
        def open(self,*args,**kwargs):
            return console.open(*args,**kwargs)
    # One spare index slot makes this complete bounded tail a terminal page.
    # Existing local incremental cursors cannot silently remove its older rows.
    result = snapshots.sync(data_dir,namespace,policy,FrozenIndex(),since=start,limit=limit+1,
                            progress=progress,expected_header=expected_header,max_bytes=max_bytes)
    result.update(recent_inventory=inventory,latest_scan_complete=True)
    return result
