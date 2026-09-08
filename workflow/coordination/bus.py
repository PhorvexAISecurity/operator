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
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport import shared_root


SCRIPT = Path(__file__).resolve()
LOCAL = SCRIPT.parent
WORKFLOW_ROOT = LOCAL.parent
ROOT = shared_root(LOCAL)
INBOX = ROOT / "inbox"
ARCHIVE = ROOT / "archive"
LOCK = ROOT / ".bus.lock"
SEQUENCE = ROOT / "sequence.txt"
SUBJECT_KINDS = {"fix", "intake", "issue", "release", "campaign"}


def utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def agents() -> set[str]:
    registry = ROOT / "AGENTS.yaml"
    if not registry.exists():
        registry = LOCAL / "AGENTS.yaml"
    data = yaml.safe_load(registry.read_text(encoding="utf-8"))
    return {a["id"] for a in data["agents"] if a.get("active")}


def validate_agent(agent: str) -> None:
    if agent not in agents():
        raise SystemExit(f"unknown or inactive agent: {agent}")


def next_id() -> int:
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    if args.fix_id:
        if args.subject_kind or args.subject_id:
            raise SystemExit("--fix cannot be combined with --subject-kind/--subject-id")
        subject_kind, subject_id = "fix", args.fix_id
    else:
        if not args.subject_kind or not args.subject_id:
            raise SystemExit("provide --fix or both --subject-kind and --subject-id")
        subject_kind, subject_id = args.subject_kind, args.subject_id
    if subject_kind not in SUBJECT_KINDS:
        raise SystemExit(f"unknown subject kind: {subject_kind}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", subject_id):
        raise SystemExit(f"unsafe subject id: {subject_id!r}")
    msg_id = next_id()
    metadata: dict[str, Any] = {
        "schema_version": 2,
        "id": msg_id,
        "created_at": utc(),
        "from": args.sender,
        "to": args.recipient,
        "subject": {"kind": subject_kind, "id": subject_id},
        "role": args.role,
        "state_from": args.state_from,
        "requested_transition": args.requested_transition,
        "needs_reply": args.needs_reply,
        "subject_line": args.subject,
        "refs": args.ref,
        "workflow_root": str(WORKFLOW_ROOT),
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
    known = {p.name for p in inbox_files(args.agent)} if args.new_only else set()
    print(f"BUS_MONITOR_READY {args.agent}", flush=True)
    while True:
        current = {p.name for p in inbox_files(args.agent)}
        for name in sorted(current - known):
            print(f"BUS_MESSAGE_READY {INBOX / args.agent / name}", flush=True)
        known = current
        time.sleep(args.interval)


def positive_seconds(value: str) -> float:
    number = float(value)
    if not 0 < number <= 60:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 60 seconds")
    return number


def cmd_wait(args: argparse.Namespace) -> int:
    """Finite foreground wait: completion is surfaced even by non-streaming runners."""
    deadline = time.monotonic() + args.timeout
    while True:
        pending = inbox_files(args.agent)
        if pending:
            for path in pending:
                print(f"BUS_MESSAGE_READY {path}", flush=True)
            return 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"BUS_WAIT_TIMEOUT {args.agent}", flush=True)
            return 0
        time.sleep(min(args.interval, remaining))


def cmd_layout(args: argparse.Namespace) -> int:
    print(f"workflow_root: {WORKFLOW_ROOT}\nbus_root: {ROOT}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", args.agent):
        raise SystemExit("unsafe agent id")
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    with LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        registry = ROOT / "AGENTS.yaml"
        source = registry if registry.exists() else LOCAL / "AGENTS.yaml"
        data = yaml.safe_load(source.read_text())
        matches = [entry for entry in data["agents"] if entry["id"] == args.agent]
        if matches:
            if not matches[0].get("active"):
                raise SystemExit("agent is inactive; resolve its registration explicitly")
        else:
            data["agents"].append({"id": args.agent, "kind": "agent", "active": True})
        temp = registry.with_suffix(".tmp")
        with temp.open("w") as stream:
            yaml.safe_dump(data, stream, sort_keys=False)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(registry)
    print(f"registered {args.agent}: {registry}")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    send = sub.add_parser("send")
    send.add_argument("--from", dest="sender", required=True)
    send.add_argument("--to", dest="recipient", required=True)
    send.add_argument("--fix", dest="fix_id")
    send.add_argument("--subject-kind", choices=sorted(SUBJECT_KINDS))
    send.add_argument("--subject-id")
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
    monitor.add_argument("--interval", type=positive_seconds, default=2.0)
    monitor.add_argument("--existing", action="store_true")
    monitor.add_argument("--new-only", action="store_true", help="explicitly skip pending messages")
    monitor.set_defaults(func=cmd_monitor)

    waiting = sub.add_parser("wait", help="return on pending mail or timeout; never acknowledge")
    waiting.add_argument("--agent", required=True)
    waiting.add_argument("--timeout", type=positive_seconds, default=45.0)
    waiting.add_argument("--interval", type=positive_seconds, default=1.0)
    waiting.set_defaults(func=cmd_wait)
    layout = sub.add_parser("layout", help="show this worktree and its shared runtime bus")
    layout.set_defaults(func=cmd_layout)
    register = sub.add_parser("register", help="register a new assigned identity in the shared runtime registry")
    register.add_argument("--agent", required=True)
    register.set_defaults(func=cmd_register)
    return root


def main() -> int:
    args = parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
