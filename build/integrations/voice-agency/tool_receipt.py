"""Read only exact digest-only Voice refund callback receipts in the pinned Pod."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys


STAGES = ("started", "denied", "crm-returned", "result-delivered")
KEYS = frozenset({"version", "callSIDHash", "callerSHA256", "sourceSHA256", "podUID", "tool",
                  "sequence", "stage", "orderSHA256", "amountCents", "crmIssued", "refundIDSHA256",
                  "responseOrderSHA256", "observedAtUnixMs"})
READ_KEYS = frozenset({"version", "callSIDHash", "callerSHA256", "sourceSHA256", "podUID", "tool",
                       "sequence", "stage", "argumentSHA256", "responseSHA256", "observedAtUnixMs"})
READ_TOOLS = ("lookup_account", "list_orders", "recall_memory")


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate receipt key")
        out[key] = value
    return out


def read_receipts(state_dir: Path, call_hash: str, caller_hash: str, pod_uid: str, source_sha: str) -> list[dict]:
    if any(not re.fullmatch(r"[0-9a-f]{64}", x) for x in (call_hash, caller_hash, source_sha)) or \
            not re.fullmatch(r"[0-9a-f-]{36}", pod_uid):
        raise ValueError("exact callback receipt identity invalid")
    root = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        mode = os.fstat(root).st_mode
        if not stat.S_ISDIR(mode) or mode & 0o077:
            raise ValueError("Voice callback receipt directory is not private")
        rows = []
        for sequence in range(4):
            for stage in STAGES:
                name = f"refund-{call_hash}-{sequence}-{stage}.json"
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root)
                except FileNotFoundError:
                    continue
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 2048:
                        raise ValueError("Voice callback receipt file differs")
                    raw = os.read(fd, 2049)
                    if not raw or len(raw) > 2048:
                        raise ValueError("Voice callback receipt too large")
                finally:
                    os.close(fd)
                row = json.loads(raw, object_pairs_hook=unique_object)
                canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                if raw != canonical or set(row) != KEYS or row.get("version") != 1 or \
                        row.get("callSIDHash") != call_hash or row.get("callerSHA256") != caller_hash or \
                        row.get("podUID") != pod_uid or row.get("sourceSHA256") != source_sha or \
                        row.get("tool") != "issue_refund" or row.get("sequence") != sequence or \
                        row.get("stage") != stage or type(row.get("amountCents")) is not int or \
                        type(row.get("crmIssued")) is not bool or \
                        type(row.get("observedAtUnixMs")) is not int or row["observedAtUnixMs"] <= 0 or \
                        any(not re.fullmatch(r"[0-9a-f]{64}|", row.get(key, "")) for key in
                            ("orderSHA256", "refundIDSHA256", "responseOrderSHA256")):
                    raise ValueError("Voice callback receipt content differs")
                rows.append(row)
        return rows
    finally:
        os.close(root)


def read_read_receipts(state_dir: Path, call_hash: str, caller_hash: str,
                       pod_uid: str, source_sha: str) -> list[dict]:
    if any(not re.fullmatch(r"[0-9a-f]{64}", x) for x in (call_hash, caller_hash, source_sha)) or \
            not re.fullmatch(r"[0-9a-f-]{36}", pod_uid):
        raise ValueError("exact read receipt identity invalid")
    root = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        mode = os.fstat(root).st_mode
        if not stat.S_ISDIR(mode) or mode & 0o077:
            raise ValueError("Voice read receipt directory is not private")
        rows = []
        for tool in READ_TOOLS:
            for sequence in range(4):
                for stage in ("started", "result-delivered"):
                    name = f"read-{call_hash}-{tool}-{sequence}-{stage}.json"
                    try:
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root)
                    except FileNotFoundError:
                        continue
                    try:
                        info = os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 2048:
                            raise ValueError("Voice read receipt file differs")
                        raw = os.read(fd, 2049)
                        if not raw or len(raw) > 2048:
                            raise ValueError("Voice read receipt too large")
                    finally:
                        os.close(fd)
                    row = json.loads(raw, object_pairs_hook=unique_object)
                    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                    if raw != canonical or set(row) != READ_KEYS or row.get("version") != 1 or \
                            row.get("callSIDHash") != call_hash or row.get("callerSHA256") != caller_hash or \
                            row.get("podUID") != pod_uid or row.get("sourceSHA256") != source_sha or \
                            row.get("tool") != tool or row.get("sequence") != sequence or row.get("stage") != stage or \
                            type(row.get("observedAtUnixMs")) is not int or row["observedAtUnixMs"] <= 0 or \
                            not isinstance(row.get("argumentSHA256"), str) or \
                            not re.fullmatch(r"[0-9a-f]{64}", row["argumentSHA256"]) or \
                            not isinstance(row.get("responseSHA256"), str) or \
                            not re.fullmatch(r"[0-9a-f]{64}|", row["responseSHA256"]):
                        raise ValueError("Voice read receipt content differs")
                    rows.append(row)
        return rows
    finally:
        os.close(root)


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("exact callback identity required")
    path = Path(os.environ.get("VOICE_MEMORY_STATE_DIR", "/var/lib/phorvex-voice-memory"))
    rows = {"refund": read_receipts(path, *sys.argv[1:]),
            "read": read_read_receipts(path, *sys.argv[1:])}
    print("VOICE_TOOL_JSON=" + json.dumps(rows, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
