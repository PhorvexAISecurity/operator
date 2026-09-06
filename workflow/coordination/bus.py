#!/usr/bin/env python3
"""Small, atomic, non-authoritative coordination bus."""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
INBOX = ROOT / "inbox"
ARCHIVE = ROOT / "archive"
LOCK = ROOT / ".bus.lock"
SEQUENCE = ROOT / "sequence.txt"


def utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def agents() -> set[str]:
    data = yaml.safe_load((ROOT / "AGENTS.yaml").read_text(encoding="utf-8"))
    return {a["id"] for a in data["agents"] if a.get("active")}


def validate_agent(agent: str) -> None:
    if agent not in agents():
        raise SystemExit(f"unknown or inactive agent: {agent}")


def next_id() -> int:
    LOCK.touch()
    with LOCK.open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = int(SEQUENCE.read_text().strip()) if SEQUENCE.exists() else 0
        for root in (INBOX, ARCHIVE):
            if not root.exists():
                continue
            for path in root.rglob("*.md"):
                match = re.match(r"^(\d+)-", path.name)
                if match:
                    current = max(current, int(match.group(1)))
        current += 1
        tmp = SEQUENCE.with_suffix(".tmp")
        tmp.write_text(f"{current}\n", encoding="utf-8")
        with tmp.open("r+") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(SEQUENCE)
        return current


def safe_subject(subject: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")
    return value[:48] or "message"


def cmd_send(args: argparse.Namespace) -> int:
    validate_agent(args.sender)
    validate_agent(args.recipient)
    if args.sender == args.recipient:
        raise SystemExit("sender and recipient must differ")
    msg_id = next_id()
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "id": msg_id,
        "created_at": utc(),
        "from": args.sender,
        "to": args.recipient,
        "fix_id": args.fix_id,
        "role": args.role,
        "state_from": args.state_from,
        "requested_transition": args.requested_transition,
        "needs_reply": args.needs_reply,
        "subject": args.subject,
        "refs": args.ref,
    }
    body = args.body or ""
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8")
    text = (
        "---\n"
        + yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True)
        + "---\n\n"
        + body.rstrip()
        + "\n"
    )
    inbox = INBOX / args.recipient
    inbox.mkdir(parents=True, exist_ok=True)
    name = f"{msg_id:06d}-{args.sender}-{safe_subject(args.subject)}.md"
    target = inbox / name
    temp = inbox / f".{name}.{os.getpid()}.tmp"
    with temp.open("x", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    temp.replace(target)
    dir_fd = os.open(inbox, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    print(target)
    return 0


def inbox_files(agent: str) -> list[Path]:
    validate_agent(agent)
    directory = INBOX / agent
    if not directory.exists():
        return []
    return sorted(p for p in directory.glob("*.md") if p.is_file())


def cmd_list(args: argparse.Namespace) -> int:
    for path in inbox_files(args.agent):
        print(path)
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    path = Path(args.message).resolve()
    if not path.is_file() or INBOX.resolve() not in path.parents:
        raise SystemExit("message must be a current inbox file")
    print(path.read_text(encoding="utf-8"), end="")
    return 0


def cmd_ack(args: argparse.Namespace) -> int:
    validate_agent(args.by)
    path = Path(args.message).resolve()
    if not path.is_file() or INBOX.resolve() not in path.parents:
        raise SystemExit("message must be a current inbox file")
    if path.parent.name != args.by:
        raise SystemExit("only the recipient may acknowledge a message")
    year = str(datetime.now(timezone.utc).year)
    destination = ARCHIVE / year / path.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise SystemExit(f"archive collision: {destination}")
    ack = destination.with_suffix(".ack.yaml")
    ack_temp = ack.with_suffix(".tmp")
    ack_temp.write_text(
        yaml.safe_dump({"message": path.name, "acknowledged_by": args.by, "acknowledged_at": utc()}),
        encoding="utf-8",
    )
    ack_temp.replace(ack)
    path.replace(destination)
    print(destination)
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    known = set() if args.existing else {p.name for p in inbox_files(args.agent)}
    print(f"BUS_MONITOR_READY {args.agent}", flush=True)
    while True:
        current = {p.name for p in inbox_files(args.agent)}
        for name in sorted(current - known):
            print(f"BUS_MESSAGE_READY {INBOX / args.agent / name}", flush=True)
        known = current
        time.sleep(args.interval)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    send = sub.add_parser("send")
    send.add_argument("--from", dest="sender", required=True)
    send.add_argument("--to", dest="recipient", required=True)
    send.add_argument("--fix", dest="fix_id", required=True)
    send.add_argument("--role", required=True)
    send.add_argument("--state-from", required=True)
    send.add_argument("--request", dest="requested_transition", required=True)
    send.add_argument("--subject", required=True)
    send.add_argument("--ref", action="append", default=[])
    send.add_argument("--needs-reply", action="store_true")
    body = send.add_mutually_exclusive_group()
    body.add_argument("--body")
    body.add_argument("--body-file")
    send.set_defaults(func=cmd_send)

    listing = sub.add_parser("list")
    listing.add_argument("--agent", required=True)
    listing.set_defaults(func=cmd_list)

    read = sub.add_parser("read")
    read.add_argument("message")
    read.set_defaults(func=cmd_read)

    ack = sub.add_parser("ack")
    ack.add_argument("message")
    ack.add_argument("--by", required=True)
    ack.set_defaults(func=cmd_ack)

    monitor = sub.add_parser("monitor")
    monitor.add_argument("--agent", required=True)
    monitor.add_argument("--interval", type=float, default=2.0)
    monitor.add_argument("--existing", action="store_true")
    monitor.set_defaults(func=cmd_monitor)
    return root


def main() -> int:
    args = parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
