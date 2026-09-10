#!/usr/bin/env python3
"""Supervised, noninteractive Claude implementation workers.

Each registered worker owns one explicit Claude session and runs at most one
bounded job at a time. A per-invocation child wrapper records both its own and
the Claude CLI's process identity, so results survive supervisor death and no
CLI process can keep working unnoticed. Nothing here approves work: a finished
turn is submitted for independent review, with any denials still visible.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport import shared_root

SCRIPT = Path(__file__).resolve()
LOCAL = SCRIPT.parent
WORKFLOW_ROOT = LOCAL.parent
RUNTIME = shared_root(LOCAL).parent / "workers"
# Runtime and registrations belong to one repository: the Git common directory
# that already scopes the coordination bus.
COMMON_DIR = RUNTIME.parents[1] if RUNTIME.parent.name == "phorvex-workflow" else LOCAL
SCHEMA_VERSION = 1
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SAFE_TOOL = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(\([^()\n]{0,120}\))?")
# Installed CLI 2.1.267 accepts these and rejects "default"; bypassPermissions
# is supported by the CLI but deliberately unavailable here.
PERMISSION_MODES = ("manual", "auto", "acceptEdits", "dontAsk", "plan")
DEFAULT_PERMISSION_MODE = "manual"
# User-directed for this campaign: pinned Opus 5 at maximum reasoning effort,
# with no floating alias and no fallback model.
DEFAULT_MODEL = "claude-opus-5"
DEFAULT_EFFORT = "max"
EFFORTS = ("low", "medium", "high", "max")
MODEL_ALIASES = ("default", "opus", "sonnet", "haiku", "opusplan", "sonnet[1m]")
PINNED_MODEL = re.compile(r"claude-[a-z]+-\d+[A-Za-z0-9.\-]*")
SUCCESS_SUBTYPES = ("success",)
ACTIVE_STATES = ("starting", "running")
TERMINAL_STATES = ("done", "failed", "interrupted", "canceled")
MAX_PROMPT_BYTES = 256 * 1024
SPAWN_GRACE_SECONDS = 10.0
NOTICE_BACKOFF = (60.0, 120.0, 300.0, 600.0, 900.0)
SPAWNED: list[subprocess.Popen] = []  # Live wrappers of this supervisor, reaped each pass.
DENIAL_PATTERN = re.compile(
    r"permission (?:denied|to use)|requested permissions|"
    r"user (?:doesn't|does not) want|tool use was (?:denied|rejected)",
    re.IGNORECASE,
)
STANDING_RULES = """Standing rules for this assignment (they override convenience):
- Work only inside your assigned worktree; preserve unrelated and other agents' work.
- Never add `Co-authored-by` trailers or any AI-assistant attribution to commits or PRs.
- Never review, approve or live-verify work you authored yourself; that gate belongs
  to another agent. Perform your assigned role only.
- No merge, deploy, release, or live-system mutation.
- Do not create, spawn or impersonate other agents, and do not change your assigned role.
- Report permission denials, missing tools and errors honestly. Never bypass a denial,
  weaken permissions, or route around a tool restriction to make progress.
- Finishing your turn submits the work for independent review. It is not approval, and a
  turn that hit denials is still submitted with those denials visible."""
# Per-invocation settings: current attribution keys, emptied so no commit or
# pull request carries assistant attribution. The deprecated
# `includeCoAuthoredBy` flag is deliberately not used.
INVOCATION_SETTINGS = {"attribution": {"commit": "", "pr": ""}}
# A worker never starts another agent or watches the bus itself.
FORBIDDEN_TOOLS = ("Agent", "Task", "Monitor")


def utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --- small filesystem and process primitives ---------------------------------

def check_private(path: Path, *, directory: bool = False) -> Path:
    """Refuse symlinks, foreign owners and group/world-writable runtime paths."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"refusing symlinked runner path: {path}")
    if info.st_uid != os.getuid():
        raise SystemExit(f"refusing runner path owned by another user: {path}")
    if info.st_mode & 0o022:
        raise SystemExit(f"refusing group/world-writable runner path: {path} "
                         f"(mode {stat.S_IMODE(info.st_mode):04o}). A permissive umask can "
                         f"create it that way; fix it explicitly with "
                         f"`chmod g-w,o-w {path}` rather than relaxing this check")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"runner path is not a directory: {path}")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"runner path is not a regular file: {path}")
    return path


def check_owned(path: Path) -> Path:
    """A repository file we will execute: ours, real, and not a symlink.

    Tracked files inherit the checkout's umask, so unlike runtime state they may
    legitimately be group-writable; refusing that would break ordinary clones.
    """
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"refusing symlinked repository script: {path}")
    if info.st_uid != os.getuid():
        raise SystemExit(f"refusing repository script owned by another user: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"not a regular file: {path}")
    return path


def ensure_runtime() -> None:
    """Create the private runtime, validating every level that already exists."""
    for path in (Path(COMMON_DIR), RUNTIME.parent, RUNTIME, RUNTIME / "jobs"):
        try:
            check_private(path, directory=True)
            continue
        except FileNotFoundError:
            if path == Path(COMMON_DIR):
                raise SystemExit(f"missing Git common directory: {path}")
        try:
            path.mkdir(mode=0o700)
        except OSError as exc:
            raise SystemExit(f"cannot create runner runtime {path}: {exc}")
        check_private(path, directory=True)


def ensure_job_dir(identifier: str) -> Path:
    directory = job_dir(identifier)
    try:
        check_private(directory, directory=True)
    except FileNotFoundError:
        directory.mkdir(mode=0o700)
        check_private(directory, directory=True)
    return directory


def write_private(path: Path, text: str) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def read_json(path: Path) -> dict:
    """Best-effort read of a non-authoritative record; {} when absent or unusable."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def read_head(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as stream:
            return stream.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def proc_fields(pid: int) -> list[str]:
    # comm can contain spaces/parentheses; fields after the last ')' start at #3,
    # so index 0 is run state and index 19 is starttime.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()


def process_start(pid: int) -> str | None:
    try:
        return proc_fields(pid)[19]
    except (OSError, IndexError):
        return None


def pid_present(pid) -> bool:
    """A process with this number exists; identity is NOT established."""
    return type(pid) is int and pid > 0 and Path(f"/proc/{pid}").exists()


def process_alive(pid, pid_start) -> bool:
    """True only for a live, own-uid process whose exact start time still matches."""
    if type(pid) is not int or pid <= 0 or not pid_start:
        return False
    try:
        fields = proc_fields(pid)
        owner = Path(f"/proc/{pid}").stat().st_uid
    except (OSError, IndexError):
        return False
    return fields[19] == str(pid_start) and fields[0] != "Z" and owner == os.getuid()


def group_present(pgid: int) -> bool:
    """Cheap probe: does this process group still have any member at all?"""
    if type(pgid) is not int or pgid <= 0:
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # It exists, but is not ours to signal.


def group_members(pgid: int) -> dict[int, str]:
    """Live, own-uid PIDs currently in this process group, with their start times."""
    members: dict[int, str] = {}
    if type(pgid) is not int or pgid <= 0:
        return members
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return members
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = proc_fields(int(entry.name))
            # Index 2 after the comm field is pgrp; index 0 is run state.
            if int(fields[2]) != pgid or fields[0] == "Z":
                continue
            if entry.stat().st_uid != os.getuid():
                continue
        except (OSError, IndexError, ValueError):
            continue  # Exited while scanning, or not ours to look at.
        members[int(entry.name)] = fields[19]
    return members


def surviving(known: dict[int, str]) -> list[int]:
    return sorted(pid for pid, start in known.items() if process_alive(pid, start))


def terminate_group(pid: int, pid_start, grace: float = 5.0) -> bool:
    """End every owned member of one verified process group; True when all are gone.

    A group leader that exits on SIGTERM while a same-group descendant ignores it
    is not cleanup, so members are enumerated, re-signalled and re-checked. The
    group is only signalled while its leader is verified as ours: a non-empty
    group pins its id, but a leader that already exited cannot be re-identified,
    so leftovers are reported instead of blindly signalled.
    """
    if not process_alive(pid, pid_start):
        return not (group_present(pid) and group_members(pid))
    known = group_members(pid)
    known[pid] = str(pid_start)
    for number in (signal.SIGTERM, signal.SIGKILL):
        if not surviving(known):
            return True
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pid, number)
        for member in surviving(known):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(member, number)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            known.update(group_members(pid))  # Descendants forked while we waited.
            if not surviving(known):
                return True
            time.sleep(0.05)
    known.update(group_members(pid))
    return not surviving(known)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- validation --------------------------------------------------------------

def safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value) or ".." in value:
        raise SystemExit(f"unsafe {label}: {value!r}")
    return value


def tool_names(specs: list[str]) -> list[str]:
    """Bare tool names behind the registered rules: `Bash(git status:*)` -> `Bash`."""
    names: list[str] = []
    for spec in specs:
        name = spec.split("(", 1)[0]
        if name not in names:
            names.append(name)
    return names


def validate_model(value: str) -> str:
    """Only an explicitly pinned model id; aliases can float to another model."""
    safe_id(value, "model")
    if value in MODEL_ALIASES or "latest" in value or not PINNED_MODEL.fullmatch(value):
        raise SystemExit(f"model must be an explicit pinned id, not {value!r} "
                         f"(campaign default: {DEFAULT_MODEL})")
    return value


def same_model_family(requested: str, observed: str) -> bool:
    """A dated variant of the requested id is the same model; anything else is not."""
    return bool(observed) and (observed.startswith(requested) or requested.startswith(observed))


def bounded_seconds(maximum: float):
    """argparse type rejecting NaN, infinity and non-positive durations."""
    def convert(raw: str) -> float:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"{raw!r} is not a number")
        if not math.isfinite(value) or not 0 < value <= maximum:
            raise argparse.ArgumentTypeError(
                f"must be a finite number greater than 0 and at most {maximum}")
        return value
    return convert


def job_id(worker: str, key: str) -> str:
    # ':' cannot appear in a validated id, so this split is unambiguous.
    return f"{safe_id(worker, 'worker id')}:{safe_id(key, 'idempotency key')}"


def job_dir(identifier: str) -> Path:
    worker, _, key = identifier.partition(":")
    safe_id(worker, "worker id")
    safe_id(key, "idempotency key")
    path = RUNTIME / "jobs" / identifier
    if path.parent.resolve() != (RUNTIME / "jobs").resolve():
        raise SystemExit(f"refusing job path outside runtime: {path}")
    return path


def git_lines(path: Path, *args: str) -> list[str]:
    result = subprocess.run(["git", "-C", str(path), *args],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise SystemExit(f"git {args[0]} failed in {path}: {result.stderr.strip()[-200:]}")
    return result.stdout.splitlines()


def resolve_worktree(raw: str) -> Path:
    """Accept only an existing worktree root of this same repository."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise SystemExit("--worktree must be an absolute path")
    path = path.resolve()
    if not path.is_dir():
        raise SystemExit(f"worktree does not exist: {path}")
    # One path per line: worktree paths may legitimately contain spaces.
    lines = git_lines(path, "rev-parse", "--path-format=absolute",
                      "--show-toplevel", "--git-common-dir")
    if len(lines) != 2:
        raise SystemExit(f"not a Git worktree: {path}")
    toplevel, common = (Path(line).resolve() for line in lines)
    if toplevel != path:
        raise SystemExit(f"--worktree must be a worktree root, not {path} (root is {toplevel})")
    if common != Path(COMMON_DIR).resolve():
        raise SystemExit(f"worktree belongs to another repository: {common} != {COMMON_DIR}")
    registered = {Path(line.split(" ", 1)[1]).resolve()
                  for line in git_lines(path, "worktree", "list", "--porcelain")
                  if line.startswith("worktree ")}
    if path not in registered:
        raise SystemExit(f"{path} is not a registered worktree; this tool never creates one")
    return path


def worker_bus(worker: dict) -> Path:
    """The assigned worktree's own bus CLI, so notices carry its workflow_root."""
    bus_cli = Path(worker["worktree"]) / "workflow" / "coordination" / "bus.py"
    try:
        check_owned(bus_cli)
    except FileNotFoundError:
        raise SystemExit(f"assigned worktree has no bus CLI at {bus_cli}")
    return bus_cli


def resolve_claude(explicit: str | None) -> Path:
    """Explicit path, then PATH, then the installed VS Code native binary."""
    candidates: list[Path] = []
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            raise SystemExit("--claude must be an absolute path")
        candidates = [path]
    else:
        found = shutil.which("claude")
        if found:
            candidates = [Path(found)]
        else:
            versions = []
            root = Path.home() / ".vscode-server/extensions"
            for entry in sorted(root.glob("anthropic.claude-code-*/resources/native-binary/claude")):
                match = re.search(r"anthropic\.claude-code-(\d+)\.(\d+)\.(\d+)", str(entry))
                if match:
                    versions.append((tuple(int(part) for part in match.groups()), entry))
            if versions:
                # Deterministic: highest parsed version, ties impossible per directory name.
                candidates = [max(versions, key=lambda item: item[0])[1]]
    for candidate in candidates:
        if not candidate.exists():
            raise SystemExit(f"Claude CLI not found at {candidate}")
        real = candidate.resolve()
        if not real.is_file() or not os.access(real, os.X_OK):
            raise SystemExit(f"Claude CLI is not an executable file: {real}")
        if real.stat().st_mode & 0o022:
            raise SystemExit(f"refusing group/world-writable Claude CLI: {real}")
        return real
    raise SystemExit("no Claude CLI found; pass --claude with the installed binary path")


# --- durable state -----------------------------------------------------------

def fresh_state() -> dict:
    return {"schema_version": SCHEMA_VERSION, "workers": {}, "jobs": {}, "sequence": 0}


def corrupt_state(path: Path, detail: str) -> str:
    note = path.with_name(f"state.corrupt.{int(time.time())}.txt")
    with contextlib.suppress(OSError, SystemExit):
        write_private(note, f"{utc()} refusing to use unusable runner state\n"
                            f"state: {path}\nproblem: {detail}\n")
    return (f"runner state at {path} is unusable ({detail}); it was left untouched. "
            f"Diagnostic: {note}. Resolve it explicitly; the runner will not start "
            f"an empty registry over existing state.")


def load_state() -> dict:
    """Authoritative read that fails closed instead of inventing an empty registry."""
    path = RUNTIME / "state.json"
    if not path.exists() and not path.is_symlink():
        return fresh_state()
    check_private(path)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(corrupt_state(path, f"{type(exc).__name__}: {exc}"))
    problems = []
    if not isinstance(state, dict):
        problems.append("top level is not an object")
    else:
        if state.get("schema_version") != SCHEMA_VERSION:
            problems.append(f"unsupported schema_version {state.get('schema_version')!r}")
        for field, kind in (("workers", dict), ("jobs", dict), ("sequence", int)):
            if not isinstance(state.get(field), kind):
                problems.append(f"{field} is not a {kind.__name__}")
    if problems:
        raise SystemExit(corrupt_state(path, "; ".join(problems)))
    return state


def save_state(state: dict) -> None:
    write_private(RUNTIME / "state.json", json.dumps(state, indent=2, sort_keys=True) + "\n")


@contextlib.contextmanager
def locked_state():
    ensure_runtime()
    with (RUNTIME / "state.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load_state()
        yield state
        save_state(state)


def read_state() -> dict:
    """Shared-lock read that never creates a runtime it did not find."""
    if not RUNTIME.exists():
        return fresh_state()
    check_private(RUNTIME, directory=True)
    with (RUNTIME / "state.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        return load_state()


# --- prompt composition ------------------------------------------------------

def compose_prompt(worker: dict, job: dict, prompt: str) -> str:
    return "\n".join([
        "[Automated Phorvex worker assignment issued by codex-lead. This is a queued job, "
        "not user approval and not a review verdict.]",
        f"Worker id: {worker['id']}",
        f"Assigned role: {worker['role']}",
        f"Assigned worktree (your only working directory): {worker['worktree']}",
        f"Workflow root for this job: {Path(worker['worktree']) / 'workflow'}",
        f"Job scope: {job.get('scope') or 'as stated in the task below'}",
        f"Job id: {job['job_id']}",
        "",
        STANDING_RULES,
        "",
        "Task:",
        prompt.rstrip(),
        "",
    ])


def build_argv(claude: Path, worker: dict, resume: bool, settings: Path) -> list[str]:
    """Noninteractive argv with an explicit session, tools and no inherited config."""
    argv = [str(claude), "-p", "--output-format", "stream-json", "--verbose"]
    argv += ["--resume", worker["session_id"]] if resume else ["--session-id", worker["session_id"]]
    argv += [
        "--model", worker["model"],
        # Reasoning effort is part of the assignment: sent on launch and resume.
        "--effort", worker["effort"],
        "--permission-mode", worker["permission_mode"],
        # No host is present to answer a prompt: an unallowed tool is denied, not queued.
        "--permission-prompts", "none",
        # Load no user/project/local settings, hooks or MCP servers; only ours.
        "--setting-sources", "",
        "--strict-mcp-config", "--mcp-config", json.dumps({"mcpServers": {}}),
        "--settings", str(settings),
        # Expose only the tool names the registered rules actually need, then
        # scope them with the rules themselves.
        "--tools", ",".join(tool_names(worker["allowed_tools"])),
        "--allowedTools", ",".join(worker["allowed_tools"]),
    ]
    if worker.get("disallowed_tools"):
        argv += ["--disallowedTools", ",".join(worker["disallowed_tools"])]
    return argv


# --- stream-json interpretation ---------------------------------------------

def read_events(path: Path) -> tuple[list[dict], int, int]:
    """Parsed object events, malformed line count, and non-object JSON line count."""
    events: list[dict] = []
    malformed = non_object = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events, malformed, non_object
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            malformed += 1  # Truncated tail after a hard kill, for example.
            continue
        if isinstance(value, dict):
            events.append(value)
        else:
            non_object += 1
    return events, malformed, non_object


def as_dict(value) -> dict:
    """Stream fields are untrusted: the same key can hold a string or an object."""
    return value if isinstance(value, dict) else {}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def as_text(value) -> str | None:
    return value if isinstance(value, str) else None


def collect_denials(events: list[dict]) -> list[dict]:
    """Every denial the CLI reported, from all three shapes it uses.

    `system`/`permission_denied` carries a plain string `message`, so no field
    may be assumed to be an object. Nothing is dropped: a denial reported both
    as a system event and in the final `permission_denials` array appears once
    per source, since each is separate evidence.
    """
    denials = []
    for event in events:
        kind, subtype = event.get("type"), event.get("subtype")
        if kind == "system" and subtype == "permission_denied":
            note = as_text(event.get("decision_reason")) or as_text(event.get("message")) or ""
            denials.append({"tool": as_text(event.get("tool_name")),
                            "tool_use_id": as_text(event.get("tool_use_id")),
                            "source": "system",
                            "reason_type": as_text(event.get("decision_reason_type")),
                            "detail": note[:200] or None})
        if kind == "result":
            for denial in as_list(event.get("permission_denials")):
                entry = as_dict(denial)
                denials.append({"tool": as_text(entry.get("tool_name")),
                                "tool_use_id": as_text(entry.get("tool_use_id")),
                                "source": "result"})
        for block in as_list(as_dict(event.get("message")).get("content")):
            entry = as_dict(block)
            if entry.get("type") != "tool_result" or not entry.get("is_error"):
                continue
            if DENIAL_PATTERN.search(json.dumps(entry.get("content"), default=str)):
                denials.append({"tool": as_text(entry.get("tool_name")),
                                "tool_use_id": as_text(entry.get("tool_use_id")),
                                "source": "tool_result"})
    return denials


def summarize(events: list[dict], session_id: str, malformed: int = 0,
              non_object: int = 0, requested_model: str | None = None) -> dict:
    """Success is explicit: one matching init, one successful matching result, no noise."""
    inits = [event for event in events
             if event.get("type") == "system" and event.get("subtype") == "init"]
    results = [event for event in events if event.get("type") == "result"]
    problems: list[str] = []
    model = None
    observed: list[str] = []
    for position, event in enumerate(events, 1):
        if event.get("type") == "assistant":
            message = event.get("message")
            if message is not None and not isinstance(message, dict):
                problems.append(f"assistant event {position} has a "
                                f"{type(message).__name__} message, not an object")
            reported = as_dict(message).get("model")
        else:
            reported = event.get("model")
        if reported is not None and not isinstance(reported, str):
            problems.append(f"event {position} reports a non-string model id "
                            f"({type(reported).__name__})")
            reported = None
        # Every model id the CLI reported, so a substitution cannot hide.
        model = reported or model
        if model and model not in observed:
            observed.append(model)
    substituted = [name for name in observed
                   if requested_model and not same_model_family(requested_model, name)]
    if substituted:
        problems.append(f"model mismatch: requested {requested_model}, "
                        f"observed {', '.join(substituted)}")
    if malformed:
        problems.append(f"{malformed} malformed stream line(s)")
    if non_object:
        problems.append(f"{non_object} non-object JSON stream line(s)")
    if len(inits) != 1:
        problems.append(f"expected exactly one init event, found {len(inits)}")
    elif inits[0].get("session_id") != session_id:
        problems.append("init session id does not match the assigned session")
    final = results[-1] if results else {}
    if len(results) != 1:
        problems.append(f"expected exactly one final result event, found {len(results)}")
    if results:
        if final.get("session_id") != session_id:
            problems.append("result session id does not match the assigned session")
        if final.get("is_error") is not False:
            problems.append(f"result.is_error is {final.get('is_error')!r}, not an explicit false")
        if final.get("subtype") not in SUCCESS_SUBTYPES:
            problems.append(f"result subtype {final.get('subtype')!r} is not a success subtype")
        text = final.get("result")
        if not isinstance(text, str) or not text.strip():
            problems.append("final result text is missing or empty")
        # Final metadata is untrusted too: a wrong shape is reported, never
        # crashed on and never quietly accepted as a clean run.
        for field, kind in (("permission_denials", list), ("modelUsage", dict),
                            ("num_turns", int), ("usage", dict)):
            value = final.get(field)
            if value is not None and not isinstance(value, kind):
                problems.append(f"final {field} is a {type(value).__name__}, "
                                f"not a {kind.__name__}")
    # Auxiliary models the CLI billed (helper models appear here); reported, but
    # only the turn's own model ids decide a substitution.
    usage_ids = sorted(name for name in as_dict(final.get("modelUsage")) if isinstance(name, str))
    return {
        "init_session": inits[0].get("session_id") if len(inits) == 1 else None,
        "result_session": final.get("session_id"),
        "result_count": len(results),
        "init_count": len(inits),
        "model": model,
        "models_observed": observed,
        "model_usage_ids": usage_ids,
        "model_mismatch": bool(substituted),
        "is_error": final.get("is_error") if results else None,
        "result_subtype": final.get("subtype") if results else None,
        "result_chars": len(final["result"]) if isinstance(final.get("result"), str) else 0,
        "num_turns": final.get("num_turns"),
        "error_text": (str(final.get("result") or final.get("error") or "")[:500]
                       if results and final.get("is_error") else None),
        "denials": collect_denials(events),
        "malformed_stream_lines": malformed,
        "non_object_stream_lines": non_object,
        "session_match": (len(inits) == 1 and len(results) == 1
                          and inits[0].get("session_id") == session_id
                          and final.get("session_id") == session_id),
        "problems": problems,
    }


def tail(path: Path, limit: int = 1000) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text[-limit:].strip() or None


# --- the per-invocation child wrapper ---------------------------------------

def cmd_child(args: argparse.Namespace) -> int:
    """Run one Claude invocation and leave durable identity and receipt records.

    Deliberately independent of the supervisor: if the supervisor dies, this
    process still records the CLI's identity and how the invocation ended.
    """
    directory = Path(args.job_dir).resolve()
    check_private(directory, directory=True)
    command = read_json(directory / "command.json")
    if not command:
        return 2
    identity = {"invocation_id": command["invocation_id"], "pid": os.getpid(),
                "pid_start": process_start(os.getpid()), "written_at": utc(),
                "cli_pid": None, "cli_pid_start": None}
    write_private(directory / "child.json", json.dumps(identity, indent=2) + "\n")
    receipt = dict(identity, started_at=utc(), exit_status=None, timed_out=False,
                   launch_error=None, cli_survived=False)
    out = os.open(directory / "stdout.jsonl", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    err = os.open(directory / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with open(directory / "composed.txt", "rb") as prompt:
            # Own session for the CLI: its whole process tree can be ended on
            # timeout or cancellation without the wrapper killing itself first.
            cli = subprocess.Popen(command["argv"], cwd=command["cwd"], stdin=prompt,
                                   stdout=out, stderr=err, start_new_session=True,
                                   close_fds=True)
    except (OSError, ValueError) as exc:
        receipt["launch_error"] = f"{type(exc).__name__}: {exc}"
    else:
        identity.update(cli_pid=cli.pid, cli_pid_start=process_start(cli.pid))
        write_private(directory / "child.json", json.dumps(identity, indent=2) + "\n")
        receipt.update(cli_pid=identity["cli_pid"], cli_pid_start=identity["cli_pid_start"])
        try:
            receipt["exit_status"] = cli.wait(timeout=command["timeout"])
        except subprocess.TimeoutExpired:
            receipt["timed_out"] = True
            gone = terminate_group(cli.pid, identity["cli_pid_start"])
            receipt["cli_survived"] = not gone
            with contextlib.suppress(subprocess.TimeoutExpired):
                receipt["exit_status"] = cli.wait(timeout=10)
    finally:
        os.close(out)
        os.close(err)
    receipt["finished_at"] = utc()
    write_private(directory / "receipt.json", json.dumps(receipt, indent=2) + "\n")
    return 0


# --- process bookkeeping shared by reconcile, stop and resolve ---------------

PROCESS_KEYS = (("cli", "cli_pid", "cli_pid_start"), ("wrapper", "pid", "pid_start"))


def process_records(job: dict, child: dict) -> list[dict]:
    """Verdicts for both owned processes: do all records agree, and is it alive?"""
    records = []
    for label, pid_key, start_key in PROCESS_KEYS:
        pid, start = child.get(pid_key), child.get(start_key)
        recorded, recorded_start = job.get(pid_key), job.get(start_key)
        agree = recorded is None or (recorded == pid and str(recorded_start) == str(start))
        # Descendants share the leader's group, so the group is part of the verdict.
        # A non-empty group pins its id, so leftovers stay visible after the
        # leader exits; the cheap probe avoids scanning /proc for empty groups.
        group = ({member: member_start for member, member_start in group_members(pid).items()
                  if member != pid} if group_present(pid) else {})
        records.append({"label": label, "pid": pid, "pid_start": start, "agree": agree,
                        "alive": process_alive(pid, start), "present": pid_present(pid),
                        "group": group})
    return records


def owned_processes(job: dict) -> list[dict]:
    child = read_json(job_dir(job["job_id"]) / "child.json")
    if child.get("invocation_id") != job.get("invocation_id"):
        return []
    return process_records(job, child)


def await_child_record(job: dict, timeout: float = 5.0) -> dict:
    """Wait briefly for the wrapper's own report, so cancelling is never blind.

    Ending a wrapper without knowing the CLI it started would orphan that CLI,
    so a stop issued inside the spawn window waits for the identity record.
    """
    directory = job_dir(job["job_id"])
    deadline = time.monotonic() + timeout
    while True:
        child = read_json(directory / "child.json")
        complete = child.get("invocation_id") == job.get("invocation_id") and (
            child.get("cli_pid") or (directory / "receipt.json").exists()
            or not process_alive(child.get("pid"), child.get("pid_start")))
        if complete or time.monotonic() >= deadline:
            return child
        time.sleep(0.05)


def unresolved_processes(records: list[dict], labels=("cli", "wrapper")) -> list[str]:
    """Anything still running, or claiming a PID we cannot verify as ours."""
    problems = []
    for record in records:
        if record["label"] not in labels:
            continue
        if record["alive"]:
            problems.append(f"{record['label']} pid {record['pid']} is still running")
        elif not record["agree"] and record["present"]:
            problems.append(f"{record['label']} pid {record['pid']} records disagree while a "
                            f"process with that pid exists; refused to signal it")
        if record.get("group"):
            problems.append(f"{len(record['group'])} owned process(es) remain in the process "
                            f"group of {record['label']} pid {record['pid']}: "
                            f"{sorted(record['group'])}")
    return problems


def blocks_worker(job: dict) -> bool:
    """Active work, or an unresolved outcome that must not be overtaken."""
    return job["state"] in ACTIVE_STATES or bool(job.get("unresolved"))


# --- reconcile, dispatch, launch --------------------------------------------

def note_session_evidence(state: dict, job: dict, directory: Path) -> None:
    """Durable proof the session exists, so the next job resumes it."""
    worker = state["workers"].get(job["worker"])
    if not worker or worker.get("session_started"):
        return
    for line in read_head(directory / "stdout.jsonl", 65536).splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (isinstance(event, dict) and event.get("type") == "system"
                and event.get("subtype") == "init"
                and event.get("session_id") == worker.get("session_id")):
            worker.update(session_started=True, session_started_at=utc(),
                          session_evidence=f"init event recorded by job {job['job_id']}")
            return


def reconcile(state: dict) -> None:
    """Recover every in-flight job from durable evidence, never by replaying it."""
    for identifier, job in state["jobs"].items():
        if job["state"] not in ACTIVE_STATES:
            continue
        try:
            reconcile_job(state, identifier, job)
        except Exception as exc:  # One bad job must not stop the supervisor.
            job.update(state="failed", unresolved=True, finished_at=utc(),
                       reason=f"reconcile error: {type(exc).__name__}: {exc}")


def reconcile_job(state: dict, identifier: str, job: dict) -> None:
    directory = job_dir(identifier)
    child = read_json(directory / "child.json")
    matching = child.get("invocation_id") == job.get("invocation_id")
    if matching:
        job.update(pid=child.get("pid"), pid_start=child.get("pid_start"),
                   cli_pid=child.get("cli_pid"), cli_pid_start=child.get("cli_pid_start"))
    note_session_evidence(state, job, directory)
    receipt = read_json(directory / "receipt.json")
    records = process_records(job, child) if matching else []
    if receipt.get("invocation_id") == job.get("invocation_id"):
        finalize(state, job, directory, receipt)
        return
    if any(record["alive"] and record["label"] == "wrapper" for record in records):
        job["state"] = "running"  # Adopt the existing wrapper; never start a second one.
        return
    orphans = unresolved_processes(records)
    if orphans:
        interrupt(job, "wrapper is gone but its Claude CLI work is not accounted for: "
                       + "; ".join(orphans) + ". Resolve it before this worker runs again")
    elif matching:
        interrupt(job, "child exited without a receipt (killed or crashed mid-invocation)")
    elif time.time() - job.get("requested_at", 0) > SPAWN_GRACE_SECONDS:
        interrupt(job, "supervisor stopped inside the spawn window; whether a Claude CLI ran "
                       "is unknown, so this job is reported rather than replayed")


def interrupt(job: dict, reason: str) -> None:
    job.update(state="interrupted", reason=reason, finished_at=utc(),
               needs_lead_decision=True, unresolved=True)


def finalize(state: dict, job: dict, directory: Path, receipt: dict) -> None:
    worker = state["workers"].get(job["worker"], {})
    session = worker.get("session_id", "")
    events, malformed, non_object = read_events(directory / "stdout.jsonl")
    summary = summarize(events, session, malformed, non_object,
                        requested_model=job.get("model_requested"))
    reasons = []
    if receipt.get("launch_error"):
        reasons.append(f"launch failed: {receipt['launch_error']}")
    if receipt.get("timed_out"):
        reasons.append(f"timed out after {job['timeout_seconds']}s")
    if receipt.get("exit_status") != 0:
        reasons.append(f"exit status {receipt.get('exit_status')}")
    reasons += summary["problems"]
    # The wrapper is still exiting while it writes this receipt; only the CLI
    # process can still be doing work.
    survivors = unresolved_processes(process_records(job, receipt), labels=("cli",))
    if receipt.get("cli_survived") or survivors:
        reasons.append("Claude CLI process may still be running: "
                       + "; ".join(survivors or ["wrapper reported a surviving CLI"]))
    denials = summary["denials"]
    job.update(
        state="failed" if reasons else "done",
        reason="; ".join(reasons) or None,
        unresolved=bool(receipt.get("cli_survived") or survivors),
        exit_status=receipt.get("exit_status"),
        timed_out=receipt.get("timed_out"),
        started_at=receipt.get("started_at"),
        finished_at=receipt.get("finished_at") or utc(),
        # Execution outcome only. Denied calls are a normal, reportable result of
        # a scoped permission surface, not an execution failure and not review.
        execution_verdict=("failed" if reasons else
                           "succeeded with denials" if denials else "succeeded"),
        denial_count=len(denials),
        model_reported=summary["model"],
        models_observed=summary["models_observed"],
        model_usage_ids=summary["model_usage_ids"],
        model_mismatch=summary["model_mismatch"],
        is_error=summary["is_error"],
        result_subtype=summary["result_subtype"],
        result_chars=summary["result_chars"],
        num_turns=summary["num_turns"],
        session_match=summary["session_match"],
        denials=denials,
        malformed_stream_lines=malformed,
        non_object_stream_lines=non_object,
        error_text=summary["error_text"],
        stderr_tail=tail(directory / "stderr.log"),
        submitted="for independent review; execution outcome only, denials stay visible",
    )
    note_session_evidence(state, job, directory)


def dispatch(state: dict, claude: Path, concurrency: int) -> None:
    """Launch queued work, holding every worker with unfinished business."""
    held: dict[str, str] = {}
    slots = 0
    for job in state["jobs"].values():
        if blocks_worker(job):
            held[job["worker"]] = job["job_id"]
            slots += 1
    for job in sorted((j for j in state["jobs"].values() if j["state"] == "queued"),
                      key=lambda j: j["sequence"]):
        if slots >= concurrency:
            return
        if job["worker"] in held:
            continue  # One active invocation per worker, in queue order.
        worker = state["workers"].get(job["worker"])
        if not worker:
            job.update(state="failed", reason="worker registration is missing",
                       finished_at=utc(), unresolved=True)
            continue
        try:
            # Revalidate immediately before dispatch: a removed or replaced
            # worktree must never run.
            resolve_worktree(worker["worktree"])
        except SystemExit as exc:
            job.update(state="failed", finished_at=utc(),
                       reason=f"assigned worktree failed revalidation: {exc}")
            held[job["worker"]] = job["job_id"]
            continue
        launch(state, job, worker, claude)
        held[job["worker"]] = job["job_id"]
        slots += 1


def launch(state: dict, job: dict, worker: dict, claude: Path) -> None:
    directory = ensure_job_dir(job["job_id"])
    for stale in ("child.json", "receipt.json"):
        (directory / stale).unlink(missing_ok=True)
    invocation = str(uuid.uuid4())
    resume = bool(worker.get("session_started"))
    settings = directory / "settings.json"
    write_private(settings, json.dumps(INVOCATION_SETTINGS, indent=2) + "\n")
    argv = build_argv(claude, worker, resume, settings)
    write_private(directory / "command.json", json.dumps({
        "invocation_id": invocation, "argv": argv, "cwd": worker["worktree"],
        "timeout": job["timeout_seconds"]}, indent=2) + "\n")
    job.update(invocation_id=invocation, resumed=resume, state="starting",
               requested_at=time.time(), requested_at_utc=utc(), claude=str(claude),
               attempts=job.get("attempts", 0) + 1, model_requested=worker["model"],
               effort_requested=worker["effort"],
               permission_mode=worker["permission_mode"], reason=None, unresolved=False,
               pid=None, pid_start=None, cli_pid=None, cli_pid_start=None)
    save_state(state)  # Durable spawn intent: a crash here is reported, never replayed.
    log = os.open(directory / "wrapper.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    devnull = os.open(os.devnull, os.O_RDONLY)
    try:
        child = subprocess.Popen(
            [sys.executable, str(SCRIPT), "_child", "--job-dir", str(directory)],
            stdin=devnull, stdout=log, stderr=log, cwd=str(RUNTIME),
            start_new_session=True, close_fds=True,
        )
    except OSError as exc:
        job.update(state="failed", reason=f"could not spawn wrapper: {exc}", finished_at=utc())
        return
    finally:
        os.close(log)
        os.close(devnull)
    SPAWNED.append(child)
    job.update(state="running", pid=child.pid, pid_start=process_start(child.pid))
    save_state(state)


# --- completion notices ------------------------------------------------------

def notice_backoff(attempts: int) -> float:
    return NOTICE_BACKOFF[min(max(attempts, 1), len(NOTICE_BACKOFF)) - 1]


def notice_body(state: dict, identifier: str, job: dict, worker: dict) -> str:
    return "\n".join([
        f"Runner job {identifier} finished with state {job['state']}.",
        f"Worker {job['worker']} ({worker['role']}) in {worker['worktree']}.",
        f"Reason: {job.get('reason') or 'none'}.",
        f"Requested {job.get('model_requested')} at effort {job.get('effort_requested')}; "
        f"observed {job.get('models_observed') or 'none'}"
        f"{' -- MODEL MISMATCH' if job.get('model_mismatch') else ''}.",
        f"Exit status: {job.get('exit_status')}. Execution verdict: "
        f"{job.get('execution_verdict')}. Denials recorded: {len(job.get('denials') or [])}.",
        f"Unresolved owned process: {bool(job.get('unresolved'))}.",
        f"Authoritative record: {SCRIPT} status --worker {job['worker']}",
        "Submitted for independent lead review, with any denials visible. Not an approval.",
    ])


def plan_notices(state: dict, now: float | None = None) -> list[dict]:
    """Under the state lock: pick due notices, charge the retry, prepare argv."""
    now = time.time() if now is None else now
    planned = []
    for identifier, job in state["jobs"].items():
        notice = job.get("notice")
        if not notice or not notice.get("requested") or notice.get("sent"):
            continue
        if job["state"] not in TERMINAL_STATES or notice.get("retry_after", 0) > now:
            continue
        worker = state["workers"].get(job["worker"], {})
        notice["attempts"] = notice.get("attempts", 0) + 1
        notice["last_attempt_at"] = utc()
        # Charge the backoff before sending: a crash mid-send cannot hot-loop.
        notice["retry_after"] = now + notice_backoff(notice["attempts"])
        try:
            bus_cli = worker_bus(worker)
        except SystemExit as exc:
            notice.update(sent=False, error=str(exc))
            continue
        directory = job_dir(identifier)
        body = directory / "notice.txt"
        write_private(body, notice_body(state, identifier, job, worker) + "\n")
        planned.append({"job_id": identifier, "argv": [
            sys.executable, str(bus_cli), "send", "--from", job["worker"],
            "--to", notice["to"], "--subject-kind", notice["subject_kind"],
            "--subject-id", notice["subject_id"], "--role", worker.get("role", "implementer"),
            "--state-from", job["state"], "--request", "review",
            "--subject", f"runner job {identifier} {job['state']}",
            "--body-file", str(body)]})
    return planned


def send_notice(item: dict, timeout: float = 15.0) -> dict:
    """Outside the state lock: one bus call, never holding up other jobs."""
    try:
        result = subprocess.run(item["argv"], capture_output=True, text=True,
                                timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip()[-300:] or f"bus exited {result.returncode}")
        return {"sent": True, "receipt": result.stdout.strip()[-300:]}
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return {"sent": False, "error": f"{type(exc).__name__}: {exc}"}


def record_notice(state: dict, item: dict, outcome: dict) -> None:
    notice = (state["jobs"].get(item["job_id"], {}) or {}).get("notice")
    if not notice or notice.get("sent"):
        return
    if outcome["sent"]:
        notice.update(sent=True, sent_at=utc(), receipt=outcome["receipt"],
                      error=None, retry_after=None)
    else:
        notice.update(sent=False, error=outcome["error"])


def notices_pass(timeout: float = 15.0) -> int:
    """At-least-once completion notices; retries are persisted with bounded backoff."""
    with locked_state() as state:
        planned = plan_notices(state)
    outcomes = [(item, send_notice(item, timeout)) for item in planned]
    if outcomes:
        with locked_state() as state:
            for item, outcome in outcomes:
                record_notice(state, item, outcome)
    return len(outcomes)


# --- supervisor --------------------------------------------------------------

def reap() -> None:
    """Collect finished wrappers so no zombie process can look alive."""
    SPAWNED[:] = [child for child in SPAWNED if child.poll() is None]


def supervisor_pass(state: dict, claude: Path, concurrency: int) -> None:
    reap()
    reconcile(state)
    dispatch(state, claude, concurrency)


def cmd_run(args: argparse.Namespace) -> int:
    claude = resolve_claude(args.claude)
    if not 1 <= args.concurrency <= 8:
        raise SystemExit("--concurrency must be between 1 and 8")
    ensure_runtime()
    with (RUNTIME / "supervisor.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another supervisor is already running for this runtime")
        print(f"WORKERS_SUPERVISOR_READY claude={claude} concurrency={args.concurrency}", flush=True)
        stopping: list[int] = []
        # Stop between passes so a shutdown never lands inside a spawn window.
        signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
        while True:
            write_private(RUNTIME / "supervisor.json", json.dumps({
                "pid": os.getpid(), "pid_start": process_start(os.getpid()),
                "heartbeat": time.time(), "claude": str(claude),
                "concurrency": args.concurrency}, indent=2) + "\n")
            with locked_state() as state:
                supervisor_pass(state, claude, args.concurrency)
                blocked = {job["worker"]: job["job_id"] for job in state["jobs"].values()
                           if job.get("unresolved")}
                # Work that can still progress on its own; a job held by an
                # unresolved outcome cannot, and must not keep a drain spinning.
                pending = [job["job_id"] for job in state["jobs"].values()
                           if job["state"] in ACTIVE_STATES
                           or (job["state"] == "queued" and job["worker"] not in blocked)]
            if not args.no_notices:
                notices_pass()  # Deliberately outside the state lock.
            if stopping or args.once or (args.drain and not pending):
                if args.drain and blocked:
                    print("WORKERS_DRAIN_BLOCKED unresolved jobs hold workers: "
                          + json.dumps(blocked, sort_keys=True), flush=True)
                return 0
            time.sleep(args.interval)


# --- read-only reporting -----------------------------------------------------

def public_job(job: dict) -> dict:
    """Everything the lead needs, and no prompt text or raw session identity."""
    fields = ("job_id", "worker", "key", "state", "reason", "created_at", "requested_at_utc",
              "started_at", "finished_at", "resumed", "attempts", "exit_status", "timed_out",
              "is_error", "result_subtype", "result_chars", "num_turns", "session_match",
              "model_requested", "model_reported", "models_observed", "model_usage_ids",
              "model_mismatch", "effort_requested", "permission_mode", "execution_verdict",
              "denial_count", "denials",
              "malformed_stream_lines", "non_object_stream_lines", "error_text", "stderr_tail",
              "scope", "timeout_seconds", "prompt_sha256", "prompt_bytes", "needs_lead_decision",
              "unresolved", "resolved_at", "resolution", "submitted", "notice", "pid", "cli_pid")
    view = {name: job[name] for name in fields if name in job}
    view["blocks_worker"] = blocks_worker(job)
    view["log"] = str(job_dir(job["job_id"]) / "stdout.jsonl")
    return view


def cmd_status(args: argparse.Namespace) -> int:
    state = read_state()
    supervisor = read_json(RUNTIME / "supervisor.json") if RUNTIME.exists() else {}
    blocking = {job["worker"]: job["job_id"] for job in state["jobs"].values()
                if blocks_worker(job)}
    workers = []
    for worker in state["workers"].values():
        if args.worker and worker["id"] != args.worker:
            continue
        workers.append({"id": worker["id"], "role": worker["role"], "worktree": worker["worktree"],
                        "model": worker["model"], "effort": worker.get("effort"),
                        "permission_mode": worker["permission_mode"],
                        "allowed_tools": worker["allowed_tools"],
                        "disallowed_tools": worker["disallowed_tools"],
                        "tools_exposed": tool_names(worker["allowed_tools"]),
                        "session_fingerprint": sha256(worker["session_id"])[:12],
                        "session_started": worker["session_started"],
                        "session_started_at": worker.get("session_started_at"),
                        "blocked_by": blocking.get(worker["id"])})
    jobs = [public_job(job) for job in sorted(state["jobs"].values(), key=lambda j: j["sequence"])
            if not args.worker or job["worker"] == args.worker]
    print(json.dumps({
        "runtime_root": str(RUNTIME),
        "runtime_present": RUNTIME.exists(),
        "supervisor": {"pid": supervisor.get("pid"),
                       "alive": process_alive(supervisor.get("pid"), supervisor.get("pid_start")),
                       "heartbeat_age_seconds": round(time.time() - supervisor["heartbeat"], 1)
                       if supervisor.get("heartbeat") else None},
        "held_slots": len(blocking),
        "unresolved_jobs": sorted(job["job_id"] for job in state["jobs"].values()
                                  if job.get("unresolved")),
        "note": "Runner state records execution only: `execution_verdict` never means the "
                "implementation was reviewed or accepted, and denied tool calls are a "
                "reportable execution outcome, not a failure. Review, approval and live "
                "verification stay with the lead and the workflow records. Unresolved jobs "
                "hold their worker and a concurrency slot until `resolve` clears them.",
        "workers": workers, "jobs": jobs,
    }, indent=2))
    return 0


def cmd_result(args: argparse.Namespace) -> int:
    job = read_state()["jobs"].get(args.job)
    if not job:
        raise SystemExit(f"unknown job: {args.job}")
    events, _, _ = read_events(job_dir(args.job) / "stdout.jsonl")
    final = [event for event in events if event.get("type") == "result"]
    print(json.dumps(public_job(job), indent=2))
    if final:
        print("\n--- final result text ---")
        print(str(final[-1].get("result") or "").strip())
    return 0


# --- cancellation and resolution --------------------------------------------

def cmd_stop(args: argparse.Namespace) -> int:
    outcome: dict = {}
    with locked_state() as state:
        if args.supervisor:
            supervisor = read_json(RUNTIME / "supervisor.json")
            if not process_alive(supervisor.get("pid"), supervisor.get("pid_start")):
                outcome = {"supervisor": "not running"}
            else:
                os.kill(supervisor["pid"], signal.SIGTERM)
                outcome = {"supervisor": f"SIGTERM sent to {supervisor['pid']}"}
        else:
            job = state["jobs"].get(args.job)
            if not job:
                raise SystemExit(f"unknown job: {args.job}")
            if job["state"] == "queued":
                job.update(state="canceled", reason="canceled before launch",
                           finished_at=utc(), unresolved=False)
                outcome = {"job": args.job, "state": "canceled"}
            elif job["state"] in ACTIVE_STATES:
                outcome = stop_job(state, job)
            else:
                outcome = {"job": args.job, "state": job["state"], "action": "already finished",
                           "unresolved": bool(job.get("unresolved"))}
    print(json.dumps(outcome, indent=2))
    return 0


def stop_job(state: dict, job: dict) -> dict:
    """End both owned processes, verified by identity; a dead wrapper is not enough."""
    child = await_child_record(job)
    # A cancelled turn may already have created the session; that evidence must
    # survive, or the next job would open a second session with --session-id.
    note_session_evidence(state, job, job_dir(job["job_id"]))
    if child.get("invocation_id") != job.get("invocation_id"):
        interrupt(job, "no matching child record for this invocation; refused to signal "
                       "any process. Resolve it explicitly")
        return {"job": job["job_id"], "state": job["state"], "signaled": [],
                "unresolved": True}
    signaled = []
    # CLI first: ending only the wrapper would orphan the CLI it started.
    for record in process_records(job, child):
        if record["agree"] and record["alive"]:
            terminate_group(record["pid"], record["pid_start"])
            signaled.append({record["label"]: record["pid"]})
    # Late-flushed output can still carry the init line for a cancelled turn.
    note_session_evidence(state, job, job_dir(job["job_id"]))
    problems = unresolved_processes(process_records(job, child))
    if problems:
        interrupt(job, "stop could not account for every owned process: " + "; ".join(problems))
        return {"job": job["job_id"], "state": job["state"], "signaled": signaled,
                "unresolved": True, "problems": problems}
    job.update(state="canceled", reason="canceled by stop request", finished_at=utc(),
               unresolved=False, resolution="stopped by request", resolved_at=utc())
    return {"job": job["job_id"], "state": "canceled", "signaled": signaled, "unresolved": False}


def cmd_resolve(args: argparse.Namespace) -> int:
    outcome: dict = {}
    with locked_state() as state:
        job = state["jobs"].get(args.job)
        if not job:
            raise SystemExit(f"unknown job: {args.job}")
        directory = job_dir(args.job)
        # Every recovery transition keeps session evidence, whatever it decides.
        note_session_evidence(state, job, directory)
        receipt = read_json(directory / "receipt.json")
        if (receipt.get("invocation_id") == job.get("invocation_id")
                and job["state"] in (*ACTIVE_STATES, "interrupted")):
            # A receipt is better evidence than an interruption guess.
            finalize(state, job, directory, receipt)
        if not job.get("unresolved"):
            outcome = {"job": args.job, "state": job["state"], "unresolved": False,
                       "action": "nothing to resolve"}
        else:
            records = owned_processes(job)
            signaled = []
            if args.terminate:
                for record in records:
                    if record["agree"] and record["alive"]:
                        terminate_group(record["pid"], record["pid_start"])
                        signaled.append({record["label"]: record["pid"]})
            problems = unresolved_processes(owned_processes(job))
            if problems:
                job["reason"] = (job.get("reason") or "") + " | unresolved at " + utc() + ": " \
                                + "; ".join(problems)
                outcome = {"job": args.job, "state": job["state"], "unresolved": True,
                           "signaled": signaled, "problems": problems,
                           "action": "still running; pass --terminate to end the owned "
                                     "process, or wait for it to finish"}
            else:
                job.update(unresolved=False, resolved_at=utc(), needs_lead_decision=False,
                           resolution=f"resolved by lead{' with --terminate' if args.terminate else ''}")
                outcome = {"job": args.job, "state": job["state"], "unresolved": False,
                           "signaled": signaled,
                           "action": "worker released; queued jobs may dispatch again"}
    print(json.dumps(outcome, indent=2))
    return int(bool(outcome.get("unresolved")))


# --- registration and queueing ----------------------------------------------

def cmd_register(args: argparse.Namespace) -> int:
    worker_id = safe_id(args.worker, "worker id")
    worktree = resolve_worktree(args.worktree)
    validate_model(args.model)
    safe_id(args.role, "role")
    if not args.allow_tool:
        raise SystemExit("--allow-tool is required: a worker's tool surface must be explicit")
    for label, values in (("allowed", args.allow_tool), ("disallowed", args.deny_tool)):
        for value in values:
            if not SAFE_TOOL.fullmatch(value):
                raise SystemExit(f"unsafe {label} tool specification: {value!r}")
    exposed = [name for name in tool_names(args.allow_tool) if name in FORBIDDEN_TOOLS]
    if exposed:
        raise SystemExit(f"refusing to expose {exposed}: a worker must not start another "
                         f"agent or run the coordination monitor itself")
    with locked_state() as state:
        existing = state["workers"].get(worker_id)
        record = {
            "id": worker_id, "role": args.role, "worktree": str(worktree), "model": args.model,
            "effort": args.effort, "permission_mode": args.permission_mode,
            "allowed_tools": args.allow_tool, "disallowed_tools": args.deny_tool,
        }
        if existing:
            drift = {k: v for k, v in record.items() if existing.get(k) != v}
            if drift and not args.update:
                raise SystemExit(f"worker {worker_id} already registered with different "
                                 f"{sorted(drift)}; pass --update to change it explicitly")
            blocking = [job["job_id"] for job in state["jobs"].values()
                        if job["worker"] == worker_id
                        and (job["state"] == "queued" or blocks_worker(job))]
            if blocking:
                raise SystemExit(f"worker {worker_id} still owns {blocking}; stop or resolve "
                                 f"them before re-registering")
            existing.update(record)
        else:
            record.update(session_id=str(uuid.uuid4()), session_started=False, created_at=utc())
            state["workers"][worker_id] = record
        session = state["workers"][worker_id]["session_id"]
        started = state["workers"][worker_id]["session_started"]
    print(json.dumps({"worker": worker_id, "worktree": str(worktree), "role": args.role,
                      "model": args.model, "effort": args.effort,
                      "permission_mode": args.permission_mode,
                      "session_fingerprint": sha256(session)[:12],
                      "session_started": started}, indent=2))
    return 0


def cmd_enqueue(args: argparse.Namespace) -> int:
    identifier = job_id(args.worker, args.key)
    prompt_path = Path(args.prompt_file).expanduser().resolve()
    if not prompt_path.is_file():
        raise SystemExit(f"prompt file is not a regular file: {prompt_path}")
    if prompt_path.stat().st_size > MAX_PROMPT_BYTES:
        raise SystemExit(f"prompt file exceeds {MAX_PROMPT_BYTES} bytes")
    prompt = prompt_path.read_text(encoding="utf-8")
    if not prompt.strip():
        raise SystemExit("prompt file is empty")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 86400:
        raise SystemExit("--timeout must be a finite number of seconds in (0, 86400]")
    digest = sha256(prompt)
    if args.notify_lead and not (args.subject_kind and args.subject_id):
        raise SystemExit("--notify-lead requires --subject-kind and --subject-id")
    if args.subject_id:
        safe_id(args.subject_id, "subject id")
    safe_id(args.to, "notice recipient")
    with locked_state() as state:
        if args.worker not in state["workers"]:
            raise SystemExit(f"unknown worker: {args.worker}; register it first")
        existing = state["jobs"].get(identifier)
        if existing:
            if existing["prompt_sha256"] != digest:
                raise SystemExit(f"idempotency key {args.key!r} already used for worker "
                                 f"{args.worker} with a different prompt; choose a new key")
            print(json.dumps({"job_id": identifier, "state": existing["state"],
                              "duplicate": True}, indent=2))
            return 0
        state["sequence"] += 1
        job = {
            "job_id": identifier, "worker": args.worker, "key": args.key,
            "sequence": state["sequence"], "state": "queued", "created_at": utc(),
            "prompt_sha256": digest, "prompt_bytes": len(prompt.encode("utf-8")),
            "scope": args.scope, "timeout_seconds": args.timeout, "attempts": 0,
            "unresolved": False,
        }
        if args.notify_lead:
            job["notice"] = {"requested": True, "to": args.to, "subject_kind": args.subject_kind,
                             "subject_id": args.subject_id, "sent": False, "attempts": 0,
                             "retry_after": 0}
        directory = ensure_job_dir(identifier)
        write_private(directory / "prompt.txt", prompt)
        write_private(directory / "composed.txt",
                      compose_prompt(state["workers"][args.worker], job, prompt))
        state["jobs"][identifier] = job
    print(json.dumps({"job_id": identifier, "state": "queued", "duplicate": False}, indent=2))
    return 0


# --- CLI ---------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="bind a worker id to one existing worktree and session")
    register.add_argument("--worker", required=True)
    register.add_argument("--worktree", required=True, help="absolute path to an existing worktree root")
    register.add_argument("--role", required=True, help="the role this worker performs, as assigned")
    register.add_argument("--model", default=DEFAULT_MODEL,
                          help=f"explicit pinned model id (default {DEFAULT_MODEL}); "
                               "floating aliases are rejected")
    register.add_argument("--effort", choices=EFFORTS, default=DEFAULT_EFFORT,
                          help=f"reasoning effort sent on every launch and resume "
                               f"(default {DEFAULT_EFFORT})")
    register.add_argument("--permission-mode", choices=PERMISSION_MODES,
                          default=DEFAULT_PERMISSION_MODE,
                          help="bypassPermissions is deliberately not available")
    register.add_argument("--allow-tool", action="append", default=[], required=False,
                          help="repeatable; at least one is required")
    register.add_argument("--deny-tool", action="append", default=[])
    register.add_argument("--update", action="store_true", help="accept changes to an existing worker")
    register.set_defaults(func=cmd_register)

    enqueue = sub.add_parser("enqueue", help="queue one bounded job for a registered worker")
    enqueue.add_argument("--worker", required=True)
    enqueue.add_argument("--key", required=True, help="idempotency key, unique per worker")
    enqueue.add_argument("--prompt-file", required=True)
    enqueue.add_argument("--scope", default="")
    enqueue.add_argument("--timeout", type=bounded_seconds(86400), default=3600.0)
    enqueue.add_argument("--notify-lead", action="store_true")
    enqueue.add_argument("--to", default="codex-lead")
    enqueue.add_argument("--subject-kind", choices=("fix", "campaign"))
    enqueue.add_argument("--subject-id")
    enqueue.set_defaults(func=cmd_enqueue)

    run = sub.add_parser("run", help="supervise queued jobs")
    run.add_argument("--claude", help="absolute path to the installed Claude CLI")
    run.add_argument("--concurrency", type=int, default=3)
    run.add_argument("--interval", type=bounded_seconds(60), default=2.0)
    run.add_argument("--once", action="store_true", help="one reconcile/dispatch pass")
    run.add_argument("--drain", action="store_true", help="exit when no job is pending")
    run.add_argument("--no-notices", action="store_true", help="skip bus completion notices")
    run.set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="JSON runner state without prompts or session ids")
    status.add_argument("--worker")
    status.set_defaults(func=cmd_status)

    result = sub.add_parser("result", help="print one job record and its final result text")
    result.add_argument("--job", required=True)
    result.set_defaults(func=cmd_result)

    stop = sub.add_parser("stop", help="cancel an owned job or stop the supervisor")
    target = stop.add_mutually_exclusive_group(required=True)
    target.add_argument("--job")
    target.add_argument("--supervisor", action="store_true")
    stop.set_defaults(func=cmd_stop)

    resolve = sub.add_parser("resolve", help="release a worker held by an unresolved job")
    resolve.add_argument("--job", required=True)
    resolve.add_argument("--terminate", action="store_true",
                         help="end the verified owned process instead of only inspecting it")
    resolve.set_defaults(func=cmd_resolve)

    child = sub.add_parser("_child", help=argparse.SUPPRESS)
    child.add_argument("--job-dir", required=True)
    child.set_defaults(func=cmd_child)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
