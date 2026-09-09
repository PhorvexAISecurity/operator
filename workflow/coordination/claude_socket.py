"""Notify an explicitly bound, existing Claude Code session on Linux.

Uses the installed runner's peer inbox protocol; never launches a model, reads
authentication tokens, changes permission modes, or impersonates a human message.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import uuid


def private_path(path: Path, *, directory=False) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError(f'unsafe Claude endpoint path: {path}')
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError(f'not a directory: {path}')


def process_start(pid: int) -> str:
    # comm can contain spaces/parentheses; fields after the last ')' start at #3.
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def resolve_session(session: str, registry: Path) -> dict:
    if sys.platform != 'linux':
        raise ValueError('Claude socket adapter currently supports Linux only')
    private_path(registry, directory=True)
    matches = []
    for path in registry.glob('*.json'):
        try:
            private_path(path)
            entry = json.loads(path.read_text())
            if entry.get('sessionId') != session:
                continue
            if entry.get('peerProtocol') != 1:
                raise ValueError('unsupported Claude peer protocol; validate adapter compatibility')
            pid = entry.get('pid')
            if type(pid) is not int or pid <= 0 or path.name != f'{pid}.json':
                raise ValueError('invalid Claude session process identity')
            if str(entry.get('procStart')) != process_start(pid):
                continue  # Stale registry entry or recycled PID.
            if Path(f'/proc/{pid}').stat().st_uid != os.getuid():
                raise ValueError('Claude process owner mismatch')
            endpoint = Path(entry.get('messagingSocketPath', ''))
            if not endpoint.is_absolute():
                raise ValueError('Claude session has no absolute messaging socket')
            private_path(endpoint.parent, directory=True)
            private_path(endpoint)
            if not stat.S_ISSOCK(endpoint.lstat().st_mode):
                raise ValueError('Claude endpoint is not a socket')
            matches.append(entry)
        except FileNotFoundError:
            continue  # Session exited while scanning.
    if len(matches) != 1:
        raise ValueError(f'expected one live Claude session for {session}; found {len(matches)}')
    return matches[0]


def notify(session: str, registry: Path, agent: str, message: str) -> str:
    entry = resolve_session(session, registry)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(entry['messagingSocketPath'])
        pid, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != entry['pid'] or uid != os.getuid() or process_start(pid) != str(entry['procStart']):
            raise ValueError('connected Claude endpoint identity differs from pinned session')
        frame = {'type': 'user', 'session_id': session, 'uuid': str(uuid.uuid4()),
                 'from': f'phorvex-bus:{agent}',
                 'message': {'role': 'user', 'content': message}}
        # Claude routes socket input as origin=peer, subject to inbound controls.
        # A successful write is NOT a model acknowledgement; bus ack proves that.
        client.sendall((json.dumps(frame) + '\n').encode())
    return f'socket-written session={session} pid={pid}'
