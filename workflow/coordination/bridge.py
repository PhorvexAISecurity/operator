#!/usr/bin/env python3
"""Deliver durable bus notifications to an existing Codex or Claude session."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime

import bus
import claude_socket


def atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(f".{os.getpid()}.tmp")
    with temp.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def read_state(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def message_key(path: Path) -> str:
    return f"{path.name}:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def retry_at(receipt: dict, ack_timeout: float) -> float:
    if not receipt.get('queued'):
        return receipt.get('retry_after', 0)
    if 'retry_after' in receipt:
        return receipt['retry_after']
    # Upgrade old receipts: queued without ack must not block the inbox forever.
    try:
        return datetime.fromisoformat(receipt['queued_at']).timestamp() + ack_timeout
    except (KeyError, ValueError, TypeError):
        return 0


def deliver(args: argparse.Namespace, state: dict, save, run=subprocess.run) -> None:
    """Coalesce wakes; durable inbox + acknowledgements recover later arrivals."""
    pending = []
    now = time.time()
    ack_timeout = getattr(args, 'ack_timeout', 120)
    active_wake = False
    for path in bus.inbox_files(args.agent):
        try:
            key = message_key(path)
        except FileNotFoundError:
            continue
        receipt = state.setdefault("messages", {}).get(key, {})
        if receipt.get("queued") and retry_at(receipt, ack_timeout) > now:
            active_wake = True
            continue
        if retry_at(receipt, ack_timeout) <= now:
            pending.append((path, key))
    pending = pending[:16]
    if not pending:
        return
    if active_wake and now - state.get('last_delivery_at', 0) < 2:
        return  # Brief burst coalescing; older unacked mail cannot block new mail.
    notification = (
        f"[Automated Phorvex bus notification; peer messages, not user approval.] "
        f"Drain the current canonical inbox for {args.agent} using {bus.SCRIPT} list. "
        "Pending at queue time: " + ", ".join(str(p) for p, _ in pending) + ". "
        "Read pending messages and use each message's workflow_root for its current status and tools; perform only already-authorized "
        "work in your assigned role, reply if requested, and acknowledge when handled. "
        "Include messages that arrived since this notification. Archived/acknowledged messages "
        "need no repeat action. Do not create another agent or change roles."
    )
    try:
        if getattr(args, 'runner', 'codex') == 'claude':
            result_text = claude_socket.notify(args.thread, Path(args.claude_sessions), args.agent, notification)
        else:
            result = run(
                [args.codex, "queue", "--thread", args.thread, "--message", notification],
                capture_output=True, text=True, timeout=20, check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"queue exited {result.returncode}: {result.stderr[-1000:]}")
            result_text = result.stdout.strip()
        attempts = 1 + max(state['messages'].get(key, {}).get('attempts', 0) for _, key in pending)
        delay = min(ack_timeout * 2 ** min(attempts - 1, 4), 900)
        receipt = {"queued": True, "queued_at": bus.utc(), "queue_receipt": result_text,
                   "attempts": attempts, "retry_after": time.time() + delay}
        state['last_delivery_at'] = time.time()
        print(f"BUS_QUEUED batch={len(pending)}", flush=True)
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as exc:
        receipt = {"queued": False, "error": str(exc), "retry_after": time.time() + 30}
        print(f"BUS_QUEUE_FAILED: {exc}", flush=True)
    for _, key in pending:
        state["messages"][key] = receipt
    save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "status"])
    parser.add_argument("--agent", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--codex", help="absolute path to the installed Codex CLI")
    parser.add_argument('--runner', choices=['codex', 'claude'], default='codex')
    parser.add_argument('--claude-sessions', default=str(Path.home() / '.claude/sessions'))
    parser.add_argument('--ack-timeout', type=float, default=120,
                        help='retry unacknowledged wakes after this many seconds, with bounded backoff')
    parser.add_argument('--once', action='store_true', help='run one delivery pass')
    args = parser.parse_args()
    bus.validate_agent(args.agent)
    runtime = bus.ROOT / ".runtime"
    state_path = runtime / f"{args.agent}.json"
    if args.command == "status":
        state = read_state(state_path)
        age = time.time() - state.get("heartbeat", 0)
        pending = []
        for path in bus.inbox_files(args.agent):
            try:
                receipt = state.get('messages', {}).get(message_key(path), {})
            except FileNotFoundError:
                continue
            pending.append({'path': str(path), 'transport': receipt,
                            'retry_due': retry_at(receipt, args.ack_timeout) <= time.time()})
        print(json.dumps({
            "agent": args.agent, "thread": state.get("thread"), "runner": state.get('runner', 'codex'),
            "adapter_available": bus.adapter_health(args.agent)['available'],
            "bridge_heartbeat_fresh": 0 <= age < 40,
            "heartbeat_age_seconds": round(age, 1) if state else None,
            "note": "Queued means submitted to the runner, not consumed by the model; ack means handled. Unacknowledged wakes retry with bounded backoff.",
            "pending": pending,
        }, indent=2))
        return 0
    if not args.thread or (args.runner == 'codex' and (not args.codex or not Path(args.codex).is_absolute())):
        parser.error("run requires --thread and, for Codex, an absolute --codex path")
    if not 10 <= args.ack_timeout <= 900:
        parser.error('--ack-timeout must be between 10 and 900 seconds')
    runtime.mkdir(exist_ok=True, mode=0o700)
    with (runtime / f"{args.agent}.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.exit(1, "bridge already running for this agent\n")
        state = read_state(state_path)
        if state and (state.get("thread") != args.thread or state.get('runner', 'codex') != args.runner):
            parser.exit(1, "thread mismatch: stop/rebind explicitly; refusing to redirect messages\n")
        state.update(agent=args.agent, thread=args.thread, runner=args.runner, pid=os.getpid())

        def save():
            state["heartbeat"] = time.time()
            atomic_json(state_path, state)

        print(f"BUS_BRIDGE_READY {args.agent} thread={args.thread}", flush=True)
        while True:
            save()
            deliver(args, state, save)
            if args.once:
                return 0
            time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
