#!/usr/bin/env python3
"""Operator for the versioned Phorvex workflow directory."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from functools import wraps
from threading import local
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Direct CLI and importlib-based test loading use the same sibling contracts.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gates
import attacks
import evidence_scope
import delivery
import preflight
from types import SimpleNamespace
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
ISSUES = ROOT / "issues"
FIXES = ROOT / "fixes"
INTAKE = ROOT / "intake"
RELEASES = ROOT / "releases"
CAMPAIGNS = ROOT / "campaigns"
OPERATIONS = ROOT / "operations"
ALLOWED_STATES = {
    "TRIAGED",
    "DESIGNING",
    "CRITIQUED",
    "AGREED",
    "IMPLEMENTED",
    "OFFLINE_VERIFIED",
    "DIFF_REVIEW_PASSED",
    "PR_READY",
    "IN_PR",
    "MERGED",
    "DEPLOYED",
    "LIVE_VERIFIED",
    "SYNCHRONIZED",
    "CLOSED",
    "HELD",
    "BLOCKED",
    "DEFERRED",
    "ACCEPTED_RISK",
    "REOPENED",
    "INVALIDATED",
}
TRANSITIONS = {
    "TRIAGED": {"DESIGNING", "HELD", "DEFERRED", "ACCEPTED_RISK"},
    "DESIGNING": {"CRITIQUED", "HELD", "BLOCKED", "INVALIDATED"},
    "CRITIQUED": {"AGREED", "DESIGNING", "BLOCKED", "INVALIDATED"},
    "AGREED": {"IMPLEMENTED", "HELD", "BLOCKED"},
    "IMPLEMENTED": {"OFFLINE_VERIFIED", "DESIGNING", "BLOCKED"},
    "OFFLINE_VERIFIED": {"DIFF_REVIEW_PASSED", "IMPLEMENTED", "BLOCKED"},
    "DIFF_REVIEW_PASSED": {"PR_READY", "IMPLEMENTED"},
    "PR_READY": {"IN_PR", "IMPLEMENTED", "HELD", "BLOCKED"},
    "IN_PR": {"MERGED", "IMPLEMENTED", "BLOCKED"},
    "MERGED": {"DEPLOYED", "BLOCKED"},
    "DEPLOYED": {"LIVE_VERIFIED", "REOPENED", "INVALIDATED", "BLOCKED"},
    "LIVE_VERIFIED": {"SYNCHRONIZED", "REOPENED", "INVALIDATED"},
    "SYNCHRONIZED": {"CLOSED", "REOPENED", "INVALIDATED"},
    "REOPENED": {"DESIGNING", "IMPLEMENTED", "HELD", "BLOCKED"},
    "INVALIDATED": {"DESIGNING", "DEFERRED", "CLOSED"},
    "HELD": {"TRIAGED", "DESIGNING", "PR_READY", "DEPLOYED", "DEFERRED"},
    "BLOCKED": {"DESIGNING", "IMPLEMENTED", "PR_READY", "IN_PR", "MERGED", "DEPLOYED"},
    "DEFERRED": {"TRIAGED", "DESIGNING", "HELD"},
    "ACCEPTED_RISK": {"CLOSED", "REOPENED"},
    "CLOSED": {"REOPENED"},
}
HUMAN_GATED_STATES = {"IN_PR", "MERGED", "DEPLOYED", "CLOSED", "ACCEPTED_RISK"}
ISSUE_STATES = {
    "OPEN",
    "IN_PROGRESS",
    "MAIN_PENDING_DEPLOY",
    "DEPLOYED_PENDING_L3",
    "CLOSED",
    "REOPENED",
    "DEFERRED",
    "ACCEPTED_RISK",
    "SUPERSEDED",
}
ISSUE_TRANSITIONS = {
    "OPEN": {
        "IN_PROGRESS",
        "MAIN_PENDING_DEPLOY",
        "DEFERRED",
        "ACCEPTED_RISK",
        "SUPERSEDED",
    },
    "IN_PROGRESS": {
        "OPEN",
        "MAIN_PENDING_DEPLOY",
        "DEFERRED",
        "ACCEPTED_RISK",
        "SUPERSEDED",
    },
    "MAIN_PENDING_DEPLOY": {
        "DEPLOYED_PENDING_L3",
        "REOPENED",
        "DEFERRED",
        "SUPERSEDED",
    },
    "DEPLOYED_PENDING_L3": {"CLOSED", "REOPENED", "DEFERRED", "SUPERSEDED"},
    "CLOSED": {"REOPENED", "SUPERSEDED"},
    "REOPENED": {"IN_PROGRESS", "DEFERRED", "ACCEPTED_RISK", "SUPERSEDED"},
    "DEFERRED": {"OPEN", "IN_PROGRESS", "SUPERSEDED"},
    "ACCEPTED_RISK": {"REOPENED", "SUPERSEDED"},
    "SUPERSEDED": {"REOPENED"},
}
ISSUE_HUMAN_GATED_STATES = {"ACCEPTED_RISK", "SUPERSEDED"}
INTAKE_KINDS = {"BUG", "INCIDENT", "OBSERVATION", "RISK", "ENHANCEMENT"}
INTAKE_STATES = {
    "REPORTED",
    "TRIAGED",
    "VERIFYING",
    "VERIFIED",
    "DEDUP_REVIEW",
    "NEEDS_DEDUP_RULING",
    "DUPLICATE",
    "FILED",
    "REJECTED",
    "UNAVAILABLE",
}
INTAKE_TRANSITIONS = {
    "REPORTED": {"TRIAGED", "REJECTED"},
    "TRIAGED": {"VERIFYING", "DEDUP_REVIEW", "REJECTED", "UNAVAILABLE"},
    "VERIFYING": {"VERIFIED", "REJECTED", "UNAVAILABLE"},
    "VERIFIED": {"DEDUP_REVIEW", "REJECTED"},
    "DEDUP_REVIEW": {
        "NEEDS_DEDUP_RULING",
        "DUPLICATE",
        "REJECTED",
    },
    "NEEDS_DEDUP_RULING": {"DEDUP_REVIEW", "DUPLICATE", "REJECTED"},
    "UNAVAILABLE": {"VERIFYING", "REJECTED"},
    "DUPLICATE": set(),
    "FILED": set(),
    "REJECTED": {"TRIAGED"},
}
CAMPAIGN_STATES = {
    "DRAFT",
    "APPROVED",
    "BASELINED",
    "RUNNING",
    "ANALYZING",
    "REVIEWED",
    "CLOSED",
    "PAUSED",
    "ABORTED",
}
CAMPAIGN_TRANSITIONS = {
    "DRAFT": {"APPROVED", "ABORTED"},
    "APPROVED": {"BASELINED", "PAUSED", "ABORTED"},
    "BASELINED": {"RUNNING", "PAUSED", "ABORTED"},
    "RUNNING": {"ANALYZING", "PAUSED", "ABORTED"},
    "ANALYZING": {"REVIEWED", "RUNNING", "PAUSED", "ABORTED"},
    "REVIEWED": {"CLOSED", "RUNNING", "PAUSED", "ABORTED"},
    "PAUSED": {"BASELINED", "ABORTED"},
    "CLOSED": set(),
    "ABORTED": set(),
}
CAMPAIGN_PERMISSIONS = {"read-only", "dry-run", "controlled-mutation", "attack"}
LEGACY_ENTRY_START = re.compile(r"^### (M-\d+) ·", re.MULTILINE)
LEGACY_BOUNDARY = re.compile(
    r"^(?:### M-\d+ ·|## |### (?!M-\d+ ·))", re.MULTILINE
)
WORKFLOW_LOCK = ROOT / ".workflow.lock"
NEW_ISSUES_MARKER = "<!-- WORKFLOW_NEW_ISSUES -->"


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def write_yaml(path: Path, value: Any) -> None:
    text = yaml.safe_dump(value, sort_keys=False, allow_unicode=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


_lock_state = local()


@contextmanager
def workflow_lock():
    # Hold the lock before reading state. Reentrant within one command/thread;
    # nested helpers use the same transaction lock, other processes still wait.
    if getattr(_lock_state, "depth", 0):
        _lock_state.depth += 1
        try:
            yield
        finally:
            _lock_state.depth -= 1
        return
    WORKFLOW_LOCK.touch()
    with WORKFLOW_LOCK.open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _lock_state.depth = 1
        try:
            yield
        finally:
            _lock_state.depth = 0
            fcntl.flock(lock, fcntl.LOCK_UN)


def serialized(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        with workflow_lock():
            return func(*args, **kwargs)
    return wrapped


@contextmanager
def workflow_transaction(
    paths: list[Path], new_directories: list[Path] | None = None
):
    """Restore a bounded set of workflow files if a multi-file update fails."""
    snapshots: dict[Path, bytes | None] = {}
    for path in paths:
        snapshots[path] = path.read_bytes() if path.is_file() else None
    directory_state = {
        path: path.exists() for path in (new_directories or [])
    }
    try:
        yield
    except BaseException:
        for path, content in snapshots.items():
            if content is None:
                if path.exists() and path.is_file():
                    path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        for path, existed in directory_state.items():
            if not existed and path.exists():
                shutil.rmtree(path)
        raise


def safe_slug(value: str, limit: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug[:limit].rstrip("-") or "report")


def validate_intake_id(intake_id: str) -> None:
    if not re.fullmatch(
        r"RPT-\d{8}-\d{6}-[a-z0-9][a-z0-9-]*", intake_id
    ):
        raise ValueError(f"unsafe intake id: {intake_id!r}")


def require_main_ancestor(repo: Path, source_ref: str = "origin/main") -> str:
    try:
        source = run_checked(
            ["git", "-C", str(repo), "rev-parse", source_ref]
        ).stdout.strip()
        relation = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", source, "HEAD"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError(exc.stdout or f"cannot resolve {source_ref}") from exc
    if relation.returncode != 0:
        raise ValueError(
            f"workflow branch does not contain current {source_ref} ({source[:12]})"
        )
    return source


def pins_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    return len(shorter) >= 12 and len(longer) >= 40 and longer.startswith(shorter)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pad_issue(issue_id: str) -> str:
    return f"M-{int(issue_id.split('-', 1)[1]):03d}"


def validate_fix_id(fix_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fix_id) or fix_id == "_template":
        raise ValueError(f"unsafe fix id: {fix_id!r}")


def parse_entry(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing YAML front matter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"{path}: unterminated YAML front matter")
    metadata = yaml.safe_load(text[4:end]) or {}
    body = text[end + 5 :]
    if body.startswith("\n"):
        body = body[1:]
    return metadata, body


def write_entry(path: Path, metadata: dict[str, Any], body: str) -> None:
    front = yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True)
    temp = path.with_suffix(".md.tmp")
    temp.write_text(f"---\n{front}---\n\n{body}", encoding="utf-8")
    temp.replace(path)


def issue_tokens(layout: str) -> list[str]:
    return re.findall(r"\{\{ISSUE:(M-\d+)\}\}", layout)


def split_legacy_register(text: str) -> tuple[str, dict[str, str], list[str]]:
    entries: dict[str, str] = {}
    order: list[str] = []
    chunks: list[str] = []
    cursor = 0
    for match in LEGACY_ENTRY_START.finditer(text):
        if match.start() < cursor:
            continue
        following = LEGACY_BOUNDARY.search(text, match.end())
        end = following.start() if following else len(text)
        issue_id = match.group(1)
        chunks.append(text[cursor : match.start()])
        chunks.append(f"{{{{ISSUE:{issue_id}}}}}")
        entries[issue_id] = text[match.start() : end]
        order.append(issue_id)
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks), entries, order


def render_base() -> tuple[str, dict[str, dict[str, Any]], list[str]]:
    layout = (ISSUES / "layout.md").read_text(encoding="utf-8")
    tokens = issue_tokens(layout)
    if len(tokens) != len(set(tokens)):
        raise ValueError("duplicate issue token in issues/layout.md")
    rendered = layout
    metadata: dict[str, dict[str, Any]] = {}
    for issue_id in tokens:
        path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        meta, body = parse_entry(path)
        if meta.get("id") != issue_id:
            raise ValueError(f"{path}: front-matter id {meta.get('id')!r} != {issue_id}")
        expected = meta.get("source_body_sha256")
        actual = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if expected and expected != actual:
            raise ValueError(f"{path}: body SHA mismatch")
        metadata[issue_id] = meta
        rendered = rendered.replace(f"{{{{ISSUE:{issue_id}}}}}", body, 1)
    if issue_tokens(rendered):
        raise ValueError("unrendered issue tokens")
    return rendered, metadata, tokens


def render_master() -> str:
    # Preserve historical source bodies, but never render historical counts or
    # headings as current operational state.
    _, metadata, tokens = render_base()
    joins_doc = load_yaml(ISSUES / "joins.yaml") or {}
    joins = joins_doc.get("joins", {})
    unknown = sorted(set(joins) - set(tokens))
    if unknown:
        raise ValueError(f"joins reference unknown issues: {unknown}")
    states = Counter(metadata[i].get("workflow_state", "UNKNOWN") for i in tokens)
    tiers = Counter(str(metadata[i].get("tier", "unassigned")) for i in tokens)
    lines = ["# Phorvex — current issue register", "",
             "> Generated from entries and reviewed joins. Do not edit this file.",
             "> State is authoritative; evidence below is historical unless its pin matches the current release.", "",
             f"Entries: {len(tokens)} · joins: {len(joins)} · anatomy pin: `{joins_doc.get('anatomy_pin', 'unknown')}`.", "",
             "| State | Count |", "|---|---|"]
    lines += [f"| {state} | {count} |" for state, count in sorted(states.items())]
    lines += ["", "| Tier | Entries |", "|---|---|"]
    lines += [f"| {tier} | {count} |" for tier, count in sorted(tiers.items())]
    lines += ["", "Historical audit narrative and migration layout: [layout.md](layout.md). "
              "Current deployment: [CURRENT.yaml](../releases/CURRENT.yaml).", ""]
    for issue_id in tokens:
        meta, body = parse_entry(ISSUES / "entries" / f"{pad_issue(issue_id)}.md")
        title = str(meta['title']).replace('\n', ' ')
        lines += [f"### {issue_id} · {title} · **{meta['workflow_state']}** · `{meta['anatomy_tag']}`", "",
                  f"Severity: {meta.get('severity') or 'unspecified'} · Tier: {meta.get('tier', 'unassigned')} · "
                  f"Fixes: {', '.join(meta.get('fixes', [])) or 'none'}", ""]
        if meta.get('superseded_by'):
            lines += [f"Superseded by `{meta['superseded_by']}`.", ""]
        if meta.get('dedup_candidates'):
            lines += ["Dedup review candidates: " + ", ".join(meta['dedup_candidates']) + ".", ""]
        join = joins.get(issue_id)
        if join:
            lines += [f"> Anatomy join review: **{join.get('review', 'required')}**."]
            lines += [str(join.get('rendered', '')).rstrip(), ""]
        # Strip just the imported heading; preserve all subsequent evidence verbatim.
        narrative = re.sub(r"^\s*### M-\d+ ·[^\n]*\n", "", body, count=1)
        lines += ["*Evidence history (claims retain their original versions):*", "", narrative.strip(), ""]
    return "\n".join(lines).rstrip() + "\n"


def resolve_fix(identifier: str) -> list[str]:
    index = load_yaml(FIXES / "INDEX.yaml") or {}
    fixes = index.get("fixes", {})
    if identifier in fixes:
        return [identifier]
    matches = []
    for fix_id, record in fixes.items():
        keys = set(record.get("aliases", [])) | set(record.get("issues", []))
        if identifier in keys:
            matches.append(fix_id)
    return matches


def synchronized_index(index: dict[str, Any]) -> dict[str, Any]:
    result = {"schema_version": index.get("schema_version", 1), "fixes": {}}
    for fix_id, record in index.get("fixes", {}).items():
        status = load_yaml(FIXES / fix_id / "STATUS.yaml")
        result["fixes"][fix_id] = {
            "directory": f"fixes/{fix_id}",
            "aliases": record.get("aliases", []),
            "issues": status.get("issues", []),
            "related_issues": status.get("related_issues", []),
            "state": status.get("state"),
            "dependencies": status.get("dependencies", []),
            "stacked_on": status.get("implementation", {}).get("stacked_on", []),
            "branch": status.get("implementation", {}).get("branch"),
            "head_sha": status.get("implementation", {}).get("head_sha"),
        }
    return result


def sync_issue_fix_links(index: dict[str, Any], check: bool) -> list[str]:
    expected: dict[str, list[str]] = {}
    for fix_id, record in index.get("fixes", {}).items():
        for issue_id in record.get("issues", []):
            expected.setdefault(issue_id, []).append(fix_id)
    stale: list[str] = []
    for path in sorted((ISSUES / "entries").glob("M-*.md")):
        metadata, body = parse_entry(path)
        issue_id = metadata["id"]
        wanted = sorted(expected.get(issue_id, []))
        if metadata.get("fixes", []) == wanted:
            continue
        stale.append(issue_id)
        if not check:
            metadata["fixes"] = wanted
            write_entry(path, metadata, body)
    return stale


@serialized
def cmd_sync_index(args: argparse.Namespace) -> int:
    path = FIXES / "INDEX.yaml"
    current = load_yaml(path)
    expected = synchronized_index(current)
    intake_path = INTAKE / "INDEX.yaml"
    intake_current = load_yaml(intake_path) or {}
    intake_expected = synchronized_intake_index(intake_current)
    campaign_path = CAMPAIGNS / "INDEX.yaml"
    campaign_current = load_yaml(campaign_path) or {}
    campaign_expected = synchronized_campaign_index(campaign_current)
    stale_links = sync_issue_fix_links(expected, check=True)
    if args.check:
        if (
            current != expected
            or intake_current != intake_expected
            or campaign_current != campaign_expected
            or stale_links
        ):
            if current != expected:
                print("FAIL: fixes/INDEX.yaml is stale", file=sys.stderr)
            if intake_current != intake_expected:
                print("FAIL: intake/INDEX.yaml is stale", file=sys.stderr)
            if campaign_current != campaign_expected:
                print("FAIL: campaigns/INDEX.yaml is stale", file=sys.stderr)
            if stale_links:
                print(
                    "FAIL: issue-to-fix links are stale: " + ", ".join(stale_links),
                    file=sys.stderr,
                )
            return 1
        print("fix index: PASS")
        return 0
    try:
        with workflow_lock(), workflow_transaction(
            [path, intake_path, campaign_path, ISSUES / "MASTER_ISSUES.md"]
        ):
            write_yaml(path, expected)
            write_yaml(intake_path, intake_expected)
            write_yaml(campaign_path, campaign_expected)
            sync_issue_fix_links(expected, check=False)
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {path}")
    return 0


@serialized
def cmd_render_issues(args: argparse.Namespace) -> int:
    target = ISSUES / "MASTER_ISSUES.md"
    rendered = render_master()
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != rendered:
            print(f"FAIL: {target} is stale", file=sys.stderr)
            return 1
        print("issues render: PASS")
        return 0
    try:
        with workflow_lock(), workflow_transaction([target]):
            write_text(target, rendered)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {target}")
    return 0


@serialized
def cmd_rehash_issue(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"M-\d+", args.issue_id):
        print(f"FAIL: invalid issue id {args.issue_id!r}", file=sys.stderr)
        return 1
    path = ISSUES / "entries" / f"{pad_issue(args.issue_id)}.md"
    if not path.is_file():
        print(f"FAIL: unknown issue {args.issue_id}", file=sys.stderr)
        return 1
    metadata, body = parse_entry(path)
    heading = re.match(r"^### (M-\d+) ·", body)
    if not heading or heading.group(1) != args.issue_id or metadata.get("id") != args.issue_id:
        print("FAIL: entry id, filename, and body heading do not agree", file=sys.stderr)
        return 1
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    metadata["source_body_sha256"] = digest
    metadata["updated_at"] = utcnow()
    try:
        with workflow_lock(), workflow_transaction([path]):
            write_entry(path, metadata, body)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"rehashed {args.issue_id}: {digest}")
    return 0


def synchronized_intake_index(index: dict[str, Any] | None = None) -> dict[str, Any]:
    aliases = (index or {}).get("intakes", {})
    result: dict[str, Any] = {"schema_version": 1, "intakes": {}}
    if not INTAKE.exists():
        return result
    for status_path in sorted(INTAKE.glob("RPT-*/STATUS.yaml")):
        status = load_yaml(status_path) or {}
        intake_id = status_path.parent.name
        result["intakes"][intake_id] = {
            "directory": f"intake/{intake_id}",
            "kind": status.get("kind"),
            "title": status.get("title"),
            "state": status.get("state"),
            "issue_id": status.get("promotion", {}).get("issue_id"),
            "aliases": aliases.get(intake_id, {}).get("aliases", []),
        }
    return result


def write_intake_index() -> None:
    path = INTAKE / "INDEX.yaml"
    write_yaml(path, synchronized_intake_index(load_yaml(path) or {}))


def new_intake_id(title: str, now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    stem = f"RPT-{moment.strftime('%Y%m%d-%H%M%S')}-{safe_slug(title)}"
    candidate = stem
    suffix = 2
    while (INTAKE / candidate).exists():
        candidate = f"{stem}-{suffix}"
        suffix += 1
    return candidate


@serialized
def cmd_new_intake(args: argparse.Namespace) -> int:
    intake_id = args.intake_id or new_intake_id(args.title)
    try:
        validate_intake_id(intake_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.kind not in INTAKE_KINDS:
        print(f"FAIL: unknown intake kind {args.kind}", file=sys.stderr)
        return 1
    target = INTAKE / intake_id
    if target.exists():
        print(f"FAIL: {target.relative_to(ROOT)} already exists", file=sys.stderr)
        return 1
    index_path = INTAKE / "INDEX.yaml"
    try:
        with workflow_lock(), workflow_transaction([index_path], [target]):
            shutil.copytree(INTAKE / "_template", target)
            status_path = target / "STATUS.yaml"
            status = load_yaml(status_path)
            now = utcnow()
            status.update(
                {
                    "intake_id": intake_id,
                    "kind": args.kind,
                    "title": args.title,
                    "reporter": args.reporter,
                    "approval_ref": args.approval_ref,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            status["pins"] = {
                "source_main_sha": args.source_main_sha,
                "source_release": args.source_release,
                "deployed_image": args.deployed_image,
                "deployed_digest": args.deployed_digest,
                "deployed_git_sha": args.deployed_git_sha,
                "environment": args.environment,
            }
            status["roles"]["investigator"] = args.investigator or args.reporter
            status["roles"]["coordinator"] = args.coordinator or args.reporter
            write_yaml(status_path, status)
            manifest_path = target / "evidence" / "manifest.yaml"
            manifest = load_yaml(manifest_path)
            manifest["subject"]["id"] = intake_id
            write_yaml(manifest_path, manifest)
            report_path = target / "REPORT.md"
            if args.report_file:
                source = Path(args.report_file).resolve()
                if ROOT.resolve() not in source.parents or not source.is_file():
                    raise ValueError("report file must exist under the workflow tree")
                report = source.read_text(encoding="utf-8")
                write_text(report_path, report.rstrip() + "\n")
            elif args.claim:
                report = report_path.read_text(encoding="utf-8")
                report = report.replace(
                    "State one falsifiable symptom or requested change.",
                    args.claim.strip(),
                    1,
                )
                write_text(report_path, report)
            write_intake_index()
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"created intake/{intake_id}")
    return 0


def intake_transition_prerequisites(
    intake_dir: Path, status: dict[str, Any], target: str
) -> list[str]:
    missing: list[str] = []
    kind = status.get("kind")
    current = status.get("state")
    if target == "TRIAGED":
        if not status.get("pins", {}).get("source_main_sha"):
            missing.append("pins.source_main_sha")
        if not status.get("pins", {}).get("environment"):
            missing.append("pins.environment")
    if target == "DEDUP_REVIEW" and current == "TRIAGED":
        if kind not in {"RISK", "ENHANCEMENT"}:
            missing.append("bugs/incidents/observations must be VERIFIED before dedup")
    if target == "VERIFIED":
        verification = status.get("verification", {})
        if verification.get("result") != "PASS":
            missing.append("verification.result must be PASS")
        if verification.get("positive_control") not in {"PASS", "NOT_REQUIRED"}:
            missing.append("verification.positive_control must be PASS or NOT_REQUIRED")
        artifact = intake_dir / str(verification.get("artifact", ""))
        if not artifact.is_file():
            missing.append("verification artifact")
    if target == "NEEDS_DEDUP_RULING":
        if status.get("dedup", {}).get("determination") != "AMBIGUOUS":
            missing.append("dedup.determination must be AMBIGUOUS")
    if target == "DUPLICATE":
        dedup = status.get("dedup", {})
        if dedup.get("determination") != "DUPLICATE":
            missing.append("dedup.determination must be DUPLICATE")
        issue_id = dedup.get("issue_id")
        if not issue_id or not (
            ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        ).is_file():
            missing.append("dedup.issue_id must name an existing issue")
    return missing


@serialized
def cmd_intake_transition(args: argparse.Namespace) -> int:
    try:
        validate_intake_id(args.intake_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    intake_dir = INTAKE / args.intake_id
    status_path = intake_dir / "STATUS.yaml"
    if not status_path.is_file():
        print(f"FAIL: unknown intake {args.intake_id}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    current = status.get("state")
    if args.verification_result:
        status["verification"]["result"] = args.verification_result
    if args.positive_control:
        status["verification"]["positive_control"] = args.positive_control
    if args.target == "FILED":
        print("FAIL: use promote-intake to enter FILED", file=sys.stderr)
        return 1
    if args.target not in INTAKE_STATES:
        print(f"FAIL: unknown intake state {args.target}", file=sys.stderr)
        return 1
    if args.target not in INTAKE_TRANSITIONS.get(current, set()) and not args.force:
        print(
            f"FAIL: transition {current} -> {args.target} is not allowed",
            file=sys.stderr,
        )
        return 1
    human_ruling = current == "NEEDS_DEDUP_RULING"
    if (human_ruling or args.force) and not args.approval_ref:
        print("FAIL: transition requires --approval-ref", file=sys.stderr)
        return 1
    if args.force and args.target in {"VERIFIED", "DUPLICATE"}:
        print("FAIL: --force cannot skip verification/dedup prerequisites", file=sys.stderr)
        return 1
    missing = [] if args.force else intake_transition_prerequisites(
        intake_dir, status, args.target
    )
    if missing:
        print("FAIL: transition prerequisites: " + "; ".join(missing), file=sys.stderr)
        return 1
    artifact = args.artifact
    if artifact:
        artifact_path = (intake_dir / artifact).resolve()
        if intake_dir.resolve() not in artifact_path.parents or not artifact_path.is_file():
            print(f"FAIL: missing/outside artifact {artifact}", file=sys.stderr)
            return 1
    now = utcnow()
    status.setdefault("transitions", []).append(
        {
            "from": current,
            "to": args.target,
            "at": now,
            "by": args.by,
            "artifact": artifact,
            "note": args.note,
            "approval_ref": args.approval_ref,
            "forced": bool(args.force),
        }
    )
    status["state"] = args.target
    status["revision"] = status.get("revision", 0) + 1
    status["next_action"] = {
        "owner": args.next_owner,
        "action": args.next_action,
    }
    if human_ruling:
        status["dedup"]["human_ruling_ref"] = args.approval_ref
    status["updated_at"] = now
    with workflow_lock():
        write_yaml(status_path, status)
        write_intake_index()
    print(f"{args.intake_id}: {current} -> {args.target}")
    return 0


DEDUP_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}


def dedup_terms(text: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text.lower())
        if word not in DEDUP_STOPWORDS
    }


def dedup_candidates(intake_dir: Path, limit: int = 10) -> list[dict[str, Any]]:
    status = load_yaml(intake_dir / "STATUS.yaml")
    report = (intake_dir / "REPORT.md").read_text(encoding="utf-8")
    query = dedup_terms(f"{status.get('title', '')}\n{report}")
    ranked: list[dict[str, Any]] = []
    for path in sorted((ISSUES / "entries").glob("M-*.md")):
        metadata, body = parse_entry(path)
        terms = dedup_terms(f"{metadata.get('title', '')}\n{body}")
        overlap = sorted(query & terms)
        if not overlap:
            continue
        title_terms = dedup_terms(str(metadata.get("title", "")))
        score = len(overlap) + 2 * len(query & title_terms)
        ranked.append(
            {
                "issue_id": metadata["id"],
                "score": score,
                "overlap": overlap[:20],
                "title": metadata.get("title"),
            }
        )
    ranked.sort(key=lambda item: (-item["score"], int(item["issue_id"].split("-")[1])))
    return ranked[:limit]


@serialized
def cmd_dedup_intake(args: argparse.Namespace) -> int:
    try:
        validate_intake_id(args.intake_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    intake_dir = INTAKE / args.intake_id
    status_path = intake_dir / "STATUS.yaml"
    if not status_path.is_file():
        print(f"FAIL: unknown intake {args.intake_id}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if status.get("state") not in {"VERIFIED", "DEDUP_REVIEW", "NEEDS_DEDUP_RULING"}:
        print("FAIL: intake is not ready for dedup review", file=sys.stderr)
        return 1
    candidates = dedup_candidates(intake_dir, args.limit)
    for candidate in candidates:
        print(
            f"{candidate['issue_id']}\tscore={candidate['score']}\t"
            f"{candidate['title']}\tterms={','.join(candidate['overlap'])}"
        )
    if not args.record and not args.determination:
        return 0
    determination = args.determination
    if determination == "DUPLICATE":
        if not args.issue:
            print("FAIL: DUPLICATE requires --issue", file=sys.stderr)
            return 1
        issue_path = ISSUES / "entries" / f"{pad_issue(args.issue)}.md"
        if not issue_path.is_file():
            print(f"FAIL: unknown duplicate issue {args.issue}", file=sys.stderr)
            return 1
    elif args.issue:
        print("FAIL: --issue is only valid with DUPLICATE", file=sys.stderr)
        return 1
    if determination == "NEW" and status.get("state") == "NEEDS_DEDUP_RULING":
        if not args.human_ruling_ref:
            print("FAIL: resolving ambiguous dedup requires --human-ruling-ref", file=sys.stderr)
            return 1
    status["dedup"]["candidates"] = candidates
    status["dedup"]["status"] = "reviewed" if determination else "candidates-recorded"
    if determination:
        status["dedup"]["determination"] = determination
        status["dedup"]["issue_id"] = args.issue
        status["dedup"]["human_ruling_ref"] = args.human_ruling_ref
    status["updated_at"] = utcnow()
    with workflow_lock():
        write_yaml(status_path, status)
        write_intake_index()
    print(f"recorded dedup candidates for {args.intake_id}")
    return 0


def next_issue_number() -> int:
    counter_path = ISSUES / "NEXT_ID"
    try:
        candidate = int(counter_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        raise ValueError("issues/NEXT_ID is missing or invalid") from exc
    existing = {
        int(path.stem.split("-")[1])
        for path in (ISSUES / "entries").glob("M-*.md")
    }
    while candidate in existing:
        candidate += 1
    return candidate


def create_issue_record(
    *,
    issue_number: int,
    title: str,
    severity: str,
    anatomy_tag: str,
    kind: str,
    approval_ref: str,
    intake_id: str | None = None,
    claim: str | None = None,
    evidence: str | None = None,
    required_correction: str | None = None,
    source_main_sha: str | None = None,
) -> tuple[str, Path]:
    if kind not in INTAKE_KINDS:
        raise ValueError(f"unknown issue kind {kind}")
    if not approval_ref:
        raise ValueError("canonical issue filing requires an approval reference")
    issue_id = f"M-{issue_number}"
    path = ISSUES / "entries" / f"M-{issue_number:03d}.md"
    if path.exists():
        raise ValueError(f"issue already exists: {issue_id}")
    now = utcnow()
    body = (
        f"### {issue_id} · {title} · **{severity}** · NEW · `{anatomy_tag}`\n\n"
        f"**What:** {claim or 'Replace with the accepted, falsifiable issue claim.'}\n\n"
        f"**Evidence:** {evidence or 'Reference retained evidence and source anchors.'}\n\n"
        f"**Required correction:** "
        f"{required_correction or 'State the required outcome before implementation design.'}\n"
    )
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "id": issue_id,
        "title": title,
        "severity": severity,
        "register_label": "NEW",
        "workflow_state": "OPEN",
        "workflow_state_source": "workflow-v2-filing",
        "anatomy_tag": anatomy_tag,
        "kind": kind,
        "source_body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "migration_body_sha256": None,
        "migration_review": "not-applicable",
        "fixes": [],
        "dependencies": [],
        "blockers": [],
        "verdicts": [],
        "intake_id": intake_id,
        "filing_approval_ref": approval_ref,
        "source_main_sha": source_main_sha,
        "created_at": now,
        "updated_at": now,
        "transitions": [],
    }
    layout_path = ISSUES / "layout.md"
    layout = layout_path.read_text(encoding="utf-8")
    if NEW_ISSUES_MARKER not in layout:
        raise ValueError("issues/layout.md lacks the workflow new-issue marker")
    token = f"{{{{ISSUE:{issue_id}}}}}"
    layout = layout.replace(NEW_ISSUES_MARKER, f"{token}\n\n{NEW_ISSUES_MARKER}", 1)
    joins_path = ISSUES / "joins.yaml"
    joins_doc = load_yaml(joins_path) or {}
    joins = joins_doc.setdefault("joins", {})
    joins[issue_id] = {
        "kind": "PENDING",
        "rendered": (
            f"> `V2` **PENDING** · `{anatomy_tag}` — anatomy locus review required."
        ),
        "source": "workflow-v2-filing",
        "review": "required",
        "accepted_at": None,
    }
    write_entry(path, metadata, body)
    write_text(layout_path, layout)
    write_yaml(joins_path, joins_doc)
    write_text(ISSUES / "NEXT_ID", f"{issue_number + 1}\n")
    write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    return issue_id, path


@serialized
def cmd_new_issue(args: argparse.Namespace) -> int:
    if args.intake_id:
        try:
            validate_intake_id(args.intake_id)
        except ValueError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        intake_status = INTAKE / args.intake_id / "STATUS.yaml"
        if not intake_status.is_file():
            print(f"FAIL: unknown intake {args.intake_id}", file=sys.stderr)
            return 1
        print(
            "FAIL: use promote-intake when filing from an intake record",
            file=sys.stderr,
        )
        return 1
    try:
        repo = Path(args.repo or ROOT.parent).resolve()
        source_main_sha = require_main_ancestor(repo, args.source_ref)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    global_paths = [
        ISSUES / "layout.md",
        ISSUES / "joins.yaml",
        ISSUES / "NEXT_ID",
        ISSUES / "MASTER_ISSUES.md",
    ]
    try:
        with workflow_lock():
            issue_number = next_issue_number()
            issue_path = ISSUES / "entries" / f"M-{issue_number:03d}.md"
            with workflow_transaction(global_paths + [issue_path]):
                issue_id, _ = create_issue_record(
                    issue_number=issue_number,
                    title=args.title,
                    severity=args.severity,
                    anatomy_tag=args.anatomy_tag,
                    kind=args.kind,
                    approval_ref=args.approval_ref,
                    intake_id=args.intake_id,
                    claim=args.claim,
                    evidence=args.evidence,
                    required_correction=args.required_correction,
                    source_main_sha=source_main_sha,
                )
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"created {issue_id}")
    return 0


@serialized
def cmd_issue_transition(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"M-\d+", args.issue_id):
        print(f"FAIL: invalid issue id {args.issue_id}", file=sys.stderr)
        return 1
    path = ISSUES / "entries" / f"{pad_issue(args.issue_id)}.md"
    if not path.is_file():
        print(f"FAIL: unknown issue {args.issue_id}", file=sys.stderr)
        return 1
    metadata, body = parse_entry(path)
    current = metadata.get("workflow_state")
    if args.target not in ISSUE_STATES:
        print(f"FAIL: unknown issue state {args.target}", file=sys.stderr)
        return 1
    if args.target not in ISSUE_TRANSITIONS.get(current, set()) and not args.force:
        print(
            f"FAIL: transition {current} -> {args.target} is not allowed",
            file=sys.stderr,
        )
        return 1
    if args.target in {"MAIN_PENDING_DEPLOY", "DEPLOYED_PENDING_L3", "CLOSED"}:
        print(
            "FAIL: use sync-main, release-sync --publish, or release-sync --finalize "
            f"for {args.target}",
            file=sys.stderr,
        )
        return 1
    if (args.target in ISSUE_HUMAN_GATED_STATES or args.force) and not args.approval_ref:
        print("FAIL: transition requires --approval-ref", file=sys.stderr)
        return 1
    evidence_states = {"MAIN_PENDING_DEPLOY", "DEPLOYED_PENDING_L3", "CLOSED"}
    if args.target in evidence_states and not args.artifact and not args.force:
        print("FAIL: transition requires --artifact", file=sys.stderr)
        return 1
    if args.artifact and not re.match(r"^https?://", args.artifact):
        artifact_path = (ROOT / args.artifact).resolve()
        if ROOT.resolve() not in artifact_path.parents or not artifact_path.is_file():
            print(f"FAIL: missing/outside artifact {args.artifact}", file=sys.stderr)
            return 1
    now = utcnow()
    metadata.setdefault("transitions", []).append(
        {
            "from": current,
            "to": args.target,
            "at": now,
            "by": args.by,
            "artifact": args.artifact,
            "note": args.note,
            "approval_ref": args.approval_ref,
            "forced": bool(args.force),
        }
    )
    metadata["workflow_state"] = args.target
    metadata["workflow_state_source"] = args.source
    metadata["updated_at"] = now
    if args.target == "CLOSED" and args.artifact:
        verdicts = metadata.setdefault("verdicts", [])
        if args.artifact not in verdicts:
            verdicts.append(args.artifact)
    try:
        with workflow_lock(), workflow_transaction(
            [path, ISSUES / "MASTER_ISSUES.md"]
        ):
            write_entry(path, metadata, body)
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"{args.issue_id}: {current} -> {args.target}")
    return 0


@serialized
def cmd_promote_intake(args: argparse.Namespace) -> int:
    try:
        validate_intake_id(args.intake_id)
        repo = Path(args.repo or ROOT.parent).resolve()
        source_main_sha = require_main_ancestor(repo, args.source_ref)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    intake_dir = INTAKE / args.intake_id
    status_path = intake_dir / "STATUS.yaml"
    if not status_path.is_file():
        print(f"FAIL: unknown intake {args.intake_id}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if status.get("state") not in {"DEDUP_REVIEW", "NEEDS_DEDUP_RULING"}:
        print("FAIL: intake has not reached dedup review", file=sys.stderr)
        return 1
    if status.get("dedup", {}).get("determination") != "NEW":
        print("FAIL: only a NEW root-cause determination may be promoted", file=sys.stderr)
        return 1
    if status.get("state") == "NEEDS_DEDUP_RULING" and not (
        args.human_ruling_ref or status.get("dedup", {}).get("human_ruling_ref")
    ):
        print("FAIL: ambiguous dedup requires a human ruling", file=sys.stderr)
        return 1
    if not args.approval_ref:
        print("FAIL: promotion requires --approval-ref", file=sys.stderr)
        return 1
    if status.get("kind") in {"BUG", "INCIDENT", "OBSERVATION"}:
        verification = status.get("verification", {})
        if verification.get("result") != "PASS":
            print("FAIL: this intake kind requires verified evidence", file=sys.stderr)
            return 1
        if verification.get("positive_control") not in {"PASS", "NOT_REQUIRED"}:
            print(
                "FAIL: this intake kind requires a PASS or NOT_REQUIRED positive control",
                file=sys.stderr,
            )
            return 1
    global_paths = [
        ISSUES / "layout.md",
        ISSUES / "joins.yaml",
        ISSUES / "NEXT_ID",
        ISSUES / "MASTER_ISSUES.md",
        INTAKE / "INDEX.yaml",
        status_path,
        FIXES / "INDEX.yaml",
    ]
    fix_dir = FIXES / args.start_fix if args.start_fix else None
    try:
        with workflow_lock():
            issue_number = next_issue_number()
            issue_path = ISSUES / "entries" / f"M-{issue_number:03d}.md"
            with workflow_transaction(
                global_paths + [issue_path],
                [fix_dir] if fix_dir else [],
            ):
                issue_id, _ = create_issue_record(
                    issue_number=issue_number,
                    title=status["title"],
                    severity=args.severity,
                    anatomy_tag=args.anatomy_tag,
                    kind=status["kind"],
                    approval_ref=args.approval_ref,
                    intake_id=args.intake_id,
                    claim=args.claim,
                    evidence=args.evidence or f"`intake/{args.intake_id}/`",
                    required_correction=args.required_correction,
                    source_main_sha=source_main_sha,
                )
                if args.start_fix:
                    create_fix_record(
                        args.start_fix,
                        [issue_id],
                        args.fix_title or status["title"],
                    )
                now = utcnow()
                current = status["state"]
                status.setdefault("transitions", []).append(
                    {
                        "from": current,
                        "to": "FILED",
                        "at": now,
                        "by": args.by,
                        "artifact": f"issues/entries/{issue_path.name}",
                        "approval_ref": args.approval_ref,
                        "human_ruling_ref": args.human_ruling_ref,
                        "forced": False,
                    }
                )
                status["state"] = "FILED"
                status["promotion"] = {
                    "issue_id": issue_id,
                    "fix_id": args.start_fix,
                    "approval_ref": args.approval_ref,
                }
                status["next_action"] = {
                    "owner": "coordinator",
                    "action": f"Continue in canonical issue {issue_id}.",
                }
                status["updated_at"] = now
                write_yaml(status_path, status)
                write_intake_index()
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"{args.intake_id}: FILED as {issue_id}"
        + (f"; started {args.start_fix}" if args.start_fix else "")
    )
    return 0


@serialized
def cmd_configure(args: argparse.Namespace) -> int:
    """Edit inputs without permitting state/check/seal forgery or stale updates."""
    try:
        validate_fix_id(args.fix_id)
        fix = FIXES / args.fix_id
        path = fix / "STATUS.yaml"
        status = load_yaml(path)
        if args.expect_revision != status.get("revision", 0):
            raise ValueError("stale revision; read brief again")
        update = load_yaml(Path(args.file))
        allowed = {"title", "roles", "capabilities", "capabilities_required", "baseline", "implementation",
                   "pull_request", "deployment", "verification", "synchronization", "approvals",
                   "dependencies", "blockers", "residuals", "next_action", "change_class"}
        if not isinstance(update, dict) or set(update) - allowed:
            raise ValueError("configure accepts only role/pin/plan inputs, not state, profile, seals or checks")
        roles = {**status.get("roles", {}), **update.get("roles", {})}
        existing_roles = status.get("roles", {})
        initialized = any(gates.assigned(v) for v in existing_roles.values())
        authority = existing_roles if initialized else roles
        if args.by not in {authority.get("coordinator"), authority.get("human_owner")}:
            # Authors may record their own source pins, never roles, approvals or review results.
            pins = update.get("implementation", {})
            if (args.by != authority.get("implementer") or set(update) != {"implementation"}
                    or not isinstance(pins, dict) or not pins
                    or set(pins) - {"branch", "base_sha", "head_sha"}):
                raise ValueError("implementer may configure only implementation branch/base/head")
            if status.get("state") not in {"AGREED", "IMPLEMENTED", "OFFLINE_VERIFIED", "DIFF_REVIEW_PASSED", "PR_READY", "IN_PR"}:
                raise ValueError("implementation pins require an agreed contract")
            impl = {**status.get("implementation", {}), **pins}
            for key in ("base_sha", "head_sha"):
                if impl.get(key):
                    commit = subprocess.run(["git", "-C", str(ROOT.parent), "rev-parse", "--verify",
                                             f"{impl[key]}^{{commit}}"], capture_output=True, text=True)
                    if commit.returncode or commit.stdout.strip() != impl[key]:
                        raise ValueError(f"implementation.{key} must be an existing full commit SHA")
            if impl.get("base_sha") and impl.get("head_sha"):
                if subprocess.run(["git", "-C", str(ROOT.parent), "merge-base", "--is-ancestor",
                                   impl["base_sha"], impl["head_sha"]], capture_output=True).returncode:
                    raise ValueError("implementation head must descend from its base")
        if "approvals" in update and not getattr(args, "approval_ref", None):
            raise ValueError("recording approval scopes requires the user's approval reference")
        if "verification" in update:
            if set(update['verification']) - {'required', 'live_required', 'soak_required'}:
                raise ValueError("use record-check for verification results")
        for key, value in update.items():
            if isinstance(value, dict) and isinstance(status.get(key), dict):
                status[key] = {**status[key], **value}
            else:
                status[key] = value
        if roles.get("skeptic") in {roles.get("proposer"), roles.get("implementer")} and gates.assigned(roles.get("skeptic")):
            raise ValueError("skeptic must be independent of both authors")
        now = utcnow()
        status['revision'] = status.get('revision', 0) + 1
        status['updated_at'] = now
        status.setdefault('configuration_history', []).append({
            'at': now, 'by': args.by, 'fields': sorted(update),
            'approval_ref': getattr(args, 'approval_ref', None),
        })
        errors: list[str] = []
        validate_schema_instance("fix-status.schema.json", status, args.fix_id, errors)
        if errors:
            raise ValueError("; ".join(errors))
        index_path = FIXES / 'INDEX.yaml'
        with workflow_transaction([path, index_path]):
            write_yaml(path, status)
            write_yaml(index_path, synchronized_index(load_yaml(index_path)))
        print(f"{args.fix_id}: configured; revision={status['revision']}")
        return 0
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


@serialized
def cmd_record_check(args: argparse.Namespace) -> int:
    try:
        validate_fix_id(args.fix_id)
        fix = FIXES / args.fix_id
        path = fix / "STATUS.yaml"
        status = load_yaml(path)
        if getattr(args, "expect_revision", None) != status.get("revision", 0):
            raise ValueError("stale/missing revision; read brief again")
        key = args.check
        if key not in gates.CHECK_ROLES:
            raise ValueError("unknown check")
        expected_by = status.get("roles", {}).get(gates.CHECK_ROLES[key])
        if args.result == "NOT_REQUIRED":
            expected_by = status.get("roles", {}).get("human_owner")
            if key not in {"l2", "l3", "l4", "positive_control"} or not args.approval_ref or not args.rationale:
                raise ValueError("waiver needs an eligible level, approval reference and rationale")
        if not gates.assigned(args.by) or args.by not in ({expected_by} if args.result == "NOT_REQUIRED" else gates.signers(status, key)):
            raise ValueError(f"check must be signed by {expected_by}")
        if key in {"critique", "decision", "incident", "p3", "patch_equivalence", "final"} and args.by in {
            status.get("roles", {}).get("proposer"), status.get("roles", {}).get("implementer")
        }:
            raise ValueError("independent review cannot be signed by an author")
        if (key in {"critique", "decision", "base_review"} or (key == "red" and args.by == status.get("roles", {}).get("skeptic"))) and status.get("profile") != "legacy-migrated":
            blind = status.get("blind_derivation", {})
            blind_path = gates.local_file(fix, "02A-blind-derivation.md")
            if blind.get("status") != "sealed" or not blind_path or blind.get("sha256") != sha256(blind_path) or blind.get("source_sha") != status.get("baseline", {}).get("code_sha"):
                raise ValueError("seal independent derivation before reading/reviewing proposal")
        expected_file = gates.REVIEW_FILES.get(key)
        if expected_file and args.artifact != expected_file:
            raise ValueError(f"{key}: must attest {expected_file}")
        if not gates.substantive(fix, args.artifact):
            raise ValueError("artifact missing, outside fix, or unchanged template")
        source = gates.source_for(status, key)
        if not source:
            raise ValueError("pin the check's source before recording evidence")
        artifact = gates.local_file(fix, args.artifact)
        now = utcnow()
        check = {"result": args.result, "by": args.by, "artifact": args.artifact,
                 "sha256": sha256(artifact), "source_sha": source, "at": now}
        if key in {"l3", "l4", "final"} and (fix / "attack-plan.yaml").exists():
            check["attack_plan_sha256"] = sha256(fix / "attack-plan.yaml")
        if key == "decision":
            check["contract_sha256"] = gates.contract_digest(status)
        if key in {"incident", "base_review"}:
            check["baseline_sha"] = status.get("baseline", {}).get("code_sha")
            if not check["baseline_sha"]:
                raise ValueError("pin the incident baseline before recording evidence")
        if key == "p3" and args.result == "PASS":
            problems = gates.check_errors(ROOT, fix, status, "incident")
            if problems:
                raise ValueError("P3 requires independent incident evidence: " + "; ".join(problems))
            check["incident_sha256"] = status["checks"]["incident"]["sha256"]
        if getattr(args, "inputs", None):
            if key not in evidence_scope.REUSABLE or args.result != "PASS":
                raise ValueError("dependency scopes apply only to reusable PASS checks")
            check["inputs"] = sorted(args.inputs)
            check["inputs_sha256"] = evidence_scope.fingerprint(ROOT.parent, source, check["inputs"])
        if key in gates.LIVE_CHECKS:
            check["deployment_digest"] = status.get("deployment", {}).get("digest")
        if args.approval_ref:
            check["approval_ref"] = args.approval_ref
        if args.rationale:
            check["rationale"] = args.rationale
        previous = status.get("checks", {}).get(key)
        if key == "decision" and previous and (previous.get("sha256") != check["sha256"] or previous.get("contract_sha256") != check.get("contract_sha256")) and not args.approval_ref:
            raise ValueError("changing an agreed decision requires a recorded human amendment")
        manifest_path = fix / "evidence/manifest.yaml"
        with workflow_transaction([path, manifest_path]):
            manifest = load_yaml(manifest_path) or {"schema_version": 1, "fix_id": args.fix_id, "artifacts": []}
            rows = manifest.setdefault("artifacts", [])
            record = {"id": f"check-{key}", "path": args.artifact, "sha256": check["sha256"],
                      "bytes": artifact.stat().st_size, "producer": args.by, "created_at": now,
                      "source_sha": source, "command": args.command, "evidence_class": {"critique": "DESIGN", "decision": "DESIGN", "base_review": "DESIGN", "implementation": "IMPLEMENTATION",
                                         "positive_control": "CONTROL", "final": "FINAL",
                                         "patch_equivalence": "EQUIVALENCE"}.get(key, key.upper()),
                      "expected_result": "PASS", "actual_result": args.result,
                      "positive_control_for": None, "retention": "git", "sensitivity": None}
            # Several check signatures may share an evidence file; retain only its current hash.
            rows[:] = [r for r in rows if r.get("id") != record["id"]]
            rows.append(record)
            status.setdefault("checks", {})[key] = check
            if previous:
                status.setdefault("check_history", []).append({"check": key, **previous})
            if key in {"p3", "l0", "l1", "l2", "l3", "l4", "positive_control"}:
                status.setdefault("verification", {})[key] = args.result
            status["revision"] = status.get("revision", 0) + 1
            status["updated_at"] = now
            write_yaml(manifest_path, manifest)
            write_yaml(path, status)
        print(f"{args.fix_id}: {key}={args.result}; revision={status['revision']}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


def cmd_submit_review(args):
    return delivery.transaction(SimpleNamespace(**globals()), args, 'submit')


def cmd_review_verdict(args):
    return delivery.transaction(SimpleNamespace(**globals()), args, 'review')


def cmd_review_delta(args):
    return delivery.delta(SimpleNamespace(**globals()), args)


def cmd_handoff_notify(args):
    try:
        validate_fix_id(args.fix_id)
        print(delivery.notification(SimpleNamespace(**globals()), args.fix_id, args.by))
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1


def cmd_preflight(args):
    try:
        fix = None
        status = {}
        if args.fix_id:
            validate_fix_id(args.fix_id)
            fix = FIXES / args.fix_id
            status = load_yaml(fix / 'STATUS.yaml')
        base = args.base or status.get('implementation', {}).get('base_sha') or status.get('baseline', {}).get('code_sha') or 'origin/main'
        head = args.head or status.get('implementation', {}).get('head_sha') or 'HEAD'
        base = preflight.git(ROOT.parent, 'rev-parse', base + '^{commit}').decode().strip()
        head = preflight.git(ROOT.parent, 'rev-parse', head + '^{commit}').decode().strip()
        selected = preflight.plan(ROOT.parent, base, head)
        if not args.run:
            shown = selected if getattr(args, 'verbose', False) else {
                'base_sha': selected['base_sha'], 'head_sha': selected['head_sha'],
                'changed_path_count': len(selected['changed_paths']),
                'checks': [{k: job[k] for k in ('id','cwd','tool','version','name') if k in job} for job in selected['jobs']],
                'external': selected['external']}
            print(yaml.safe_dump(shown, sort_keys=False)); return 0
        output = Path(args.output or ('evidence/preflight/receipt.json' if fix else '/tmp/phorvex-preflight.json'))
        if fix:
            output = (fix / output).resolve()
            if fix.resolve() not in output.parents: raise ValueError('receipt must remain inside the fix')
        output.parent.mkdir(parents=True, exist_ok=True)
        receipt = preflight.run_plan(ROOT.parent, selected, output, args)
        print(f'preflight: {receipt["result"]}; receipt={output}')
        return 0 if receipt['result'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr); return 1


@serialized
def cmd_packet(args: argparse.Namespace) -> int:
    matches = resolve_fix(args.identifier)
    if len(matches) != 1:
        print("FAIL: select one fix ID: " + ", ".join(matches), file=sys.stderr)
        return 1
    fix_id = matches[0]
    status = load_yaml(FIXES / fix_id / "STATUS.yaml")
    roles = [role for role, participant in status.get("roles", {}).items() if participant == args.agent]
    if not roles:
        print("FAIL: participant has no assigned role; coordinator must assign it first", file=sys.stderr)
        return 1
    blind = "skeptic" in roles and status.get("blind_derivation", {}).get("status") == "pending"
    state = status.get("state")
    phase = ("design" if state in {"TRIAGED", "DESIGNING", "CRITIQUED"}
             else "verify" if state in {"AGREED", "IMPLEMENTED", "OFFLINE_VERIFIED", "DIFF_REVIEW_PASSED"}
             else "release")
    if state == 'IN_PR' and status.get('next_action', {}).get('owner') in {'implementer', 'skeptic'}:
        phase = 'verify'
    read = [f"fixes/{fix_id}/STATUS.yaml", f"stages/{phase}.md"]
    read += [f"issues/entries/{pad_issue(i)}.md" for i in status.get("issues", [])]
    if (FIXES / fix_id / "00-intake.md").is_file():
        read += [f"fixes/{fix_id}/00-intake.md"]
    forbidden = []
    if blind:
        write = [f"fixes/{fix_id}/02A-blind-derivation.md"]
        forbidden = ["01-proposal.md", "02B-critique.md", "03-decision.md", "04-diff.patch",
                     "implementation branch/commits", "proposal/diff messages", "checks from other participants"]
        action = "Derive independently from the pinned baseline, then seal; only then open the proposal."
    else:
        scopes = {
            "design": {"proposer": ["01-proposal.md"], "skeptic": ["02A-blind-derivation.md", "02B-critique.md", "03-decision.md", "evidence/baseline/", "evidence/repro/", "red attestation"]},
            "verify": {"implementer": ["implementation code/tests", "04-diff.patch", "05-evidence.md", "evidence/"],
                       "skeptic": ["evidence/incident.md", "evidence/base-review.md", "evidence/p3/verdict.md"]},
            "release": {"live_verifier": ["evidence/l3/", "evidence/l4/"], "skeptic": ["06-verdict.md"]},
        }
        write = [path for role in roles for path in scopes[phase].get(role, [])]
        if "coordinator" in roles:
            write += ["STATUS.yaml via commands", "issue/release synchronization"]
        elif "implementer" in roles:
            write += ["implementation branch/base/head via configure"]
        action = status.get("next_action", {}).get("action")
        for name in {"design": ["02A-blind-derivation.md", "01-proposal.md", "02B-critique.md"],
                     "verify": ["03-decision.md", "04-diff.patch", "05-evidence.md", "evidence/incident.md"],
                     "release": ["03-decision.md", "evidence/incident.md", "evidence/p3/verdict.md", "05-evidence.md"]}[phase]:
            if (FIXES / fix_id / name).is_file(): read.append(f"fixes/{fix_id}/{name}")
    packet = {"fix": fix_id, "participant": args.agent, "roles": roles, "state": state,
              "revision": status.get("revision", 0), "baseline": status.get("baseline", {}),
              "default_delivery_target": "IN_PR", "pr_open_authorized": bool(status.get("approvals", {}).get("pr_open")),
              "read": read, "write_scope": write, "do_not_read": forbidden,
              "next_owner": status.get("next_action", {}).get("owner"), "next_action": action,
              "handoff": "record result + source/hash; transition with expected revision; send artifact refs only"}
    packet["owns_next_action"] = status.get("roles", {}).get(
        status.get("next_action", {}).get("owner"), status.get("next_action", {}).get("owner")) == args.agent
    if not blind:
        packet["checks"] = {key: value.get("result") for key, value in status.get("checks", {}).items()}
        packet["handoff_commands"] = {
            "implementer": "preflight --run; submit-review --file submit.yaml",
            "skeptic": "review-delta; review-verdict --result PASS|FAIL --file review.yaml",
            "coordinator": "deliver PR under recorded scope; preserve live obligations",
        }
        packet["implementation"] = status.get("implementation", {})
        packet["deployment"] = status.get("deployment", {})
        packet["allowed_transitions"] = sorted(TRANSITIONS.get(state, []))
    joins = (load_yaml(ISSUES / "joins.yaml") or {}).get("joins", {})
    packet["anatomy"] = {i: {"review": joins.get(i, {}).get("review"),
                             "locus": joins.get(i, {}).get("locus"),
                             "warning": "Read only the target locus; unreviewed joins are search hints."}
                         for i in status.get("issues", [])}
    print(yaml.safe_dump(packet, sort_keys=False), end="")
    return 0


def cmd_guide(args: argparse.Namespace) -> int:
    policy = load_yaml(OPERATIONS / "POLICY.yaml") or {}
    operations = policy.get("operations", {})
    record = operations.get(args.operation)
    if not record:
        print(
            "FAIL: unknown operation; choose " + ", ".join(sorted(operations)),
            file=sys.stderr,
        )
        return 1
    runbook = ROOT / str(record["runbook"])
    if not runbook.is_file():
        print(f"FAIL: missing runbook {record['runbook']}", file=sys.stderr)
        return 1
    print(f"operation: {args.operation}")
    print(f"runbook: {runbook.relative_to(ROOT)}")
    print(f"authority: {record.get('authority')}")
    print(f"mutating: {bool(record.get('mutating'))}")
    print("terminal_states: " + ", ".join(record.get("terminal_states", [])))
    if args.show:
        print()
        print(runbook.read_text(encoding="utf-8"), end="")
    return 0


def cmd_brief(args: argparse.Namespace) -> int:
    if getattr(args, "agent", None):
        return cmd_packet(args)
    if re.fullmatch(r"RPT-\d{8}-\d{6}-[a-z0-9][a-z0-9-]*", args.identifier):
        status_path = INTAKE / args.identifier / "STATUS.yaml"
        if not status_path.is_file():
            print(f"FAIL: unknown intake {args.identifier}", file=sys.stderr)
            return 1
        status = load_yaml(status_path)
        print(f"intake: {args.identifier}")
        print(f"status_file: intake/{args.identifier}/STATUS.yaml")
        print(f"kind: {status.get('kind')}")
        print(f"title: {status.get('title')}")
        print(f"state: {status.get('state')}")
        print(f"dedup: {status.get('dedup', {}).get('determination')}")
        print(f"issue: {status.get('promotion', {}).get('issue_id')}")
        print(f"next_owner: {status.get('next_action', {}).get('owner')}")
        print(f"next_action: {status.get('next_action', {}).get('action')}")
        return 0
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9-]*", args.identifier):
        status_path = CAMPAIGNS / args.identifier / "STATUS.yaml"
        if status_path.is_file():
            status = load_yaml(status_path)
            print(f"campaign: {args.identifier}")
            print(f"status_file: campaigns/{args.identifier}/STATUS.yaml")
            print(f"state: {status.get('state')}")
            print(f"question: {status.get('question')}")
            print(f"permission: {status.get('scope', {}).get('permission')}")
            print(f"deployment_sha: {status.get('pins', {}).get('embedded_git_sha')}")
            print(f"next_owner: {status.get('next_action', {}).get('owner')}")
            print(f"next_action: {status.get('next_action', {}).get('action')}")
            return 0
    if re.fullmatch(r"(?:MAIN|DEPLOY)-\d{8}-\d{6}-[a-f0-9]{7,40}", args.identifier):
        status_path = RELEASES / args.identifier / "STATUS.yaml"
        if not status_path.is_file():
            print(f"FAIL: unknown release sync {args.identifier}", file=sys.stderr)
            return 1
        status = load_yaml(status_path)
        print(f"release_sync: {args.identifier}")
        print(f"status_file: releases/{args.identifier}/STATUS.yaml")
        print(f"kind: {status.get('kind')}")
        print(f"state: {status.get('state')}")
        print(
            "source_main: "
            + str(status.get("code_repository", {}).get("observed_main_sha"))
        )
        print(
            "deployment_sha: "
            + str(status.get("deployment", {}).get("embedded_git_sha"))
        )
        print(f"next_owner: {status.get('next_action', {}).get('owner')}")
        print(f"next_action: {status.get('next_action', {}).get('action')}")
        return 0
    matches = resolve_fix(args.identifier)
    issue_id = args.identifier if re.fullmatch(r"M-\d+", args.identifier) else None
    if issue_id:
        issue_path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        if issue_path.exists():
            meta, _ = parse_entry(issue_path)
            print(f"issue: {issue_id}")
            print(f"issue_file: {issue_path.relative_to(ROOT)}")
            print(f"title: {meta.get('title')}")
            print(f"register_state: {meta.get('workflow_state')}")
            print(f"anatomy_tag: {meta.get('anatomy_tag')}")
        joins = (load_yaml(ISSUES / "joins.yaml") or {}).get("joins", {})
        join = joins.get(issue_id)
        if join:
            print(f"anatomy_join: {join.get('kind')}")
            for line in str(join.get("rendered", "")).splitlines():
                print(f"  {line}")
    if not matches:
        if issue_id:
            print("fix: none indexed")
            return 0
        print(f"FAIL: no fix or alias matches {args.identifier}", file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(f"matching_fixes: {', '.join(matches)}")
    for fix_id in matches:
        status = load_yaml(FIXES / fix_id / "STATUS.yaml")
        print(f"fix: {fix_id}")
        print(f"  status_file: fixes/{fix_id}/STATUS.yaml")
        print(f"  state: {status.get('state')}")
        print(f"  revision: {status.get('revision', 0)}")
        print(f"  branch: {status.get('implementation', {}).get('branch')}")
        print(f"  stacked_on: {status.get('implementation', {}).get('stacked_on', [])}")
        next_action = status.get("next_action", {})
        print(f"  next_owner: {next_action.get('owner')}")
        print(f"  next_action: {next_action.get('action')}")
    return 0


@serialized
def cmd_seal(args: argparse.Namespace) -> int:
    try:
        validate_fix_id(args.fix_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    fix_dir = FIXES / args.fix_id
    status_path = fix_dir / "STATUS.yaml"
    blind_path = fix_dir / "02A-blind-derivation.md"
    seal_path = fix_dir / "02A-blind-derivation.sha256"
    if not status_path.is_file() or not blind_path.is_file():
        print("FAIL: fix status or 02A blind derivation is missing", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if getattr(args, "by", None) != status.get("roles", {}).get("skeptic"):
        print("FAIL: only the assigned skeptic may seal", file=sys.stderr)
        return 1
    if not gates.substantive(fix_dir, blind_path.name) or not status.get("baseline", {}).get("code_sha"):
        print("FAIL: complete blind derivation and source pin first", file=sys.stderr)
        return 1
    if getattr(args, "expect_revision", None) != status.get("revision", 0):
        print("FAIL: stale/missing revision; read brief again", file=sys.stderr)
        return 1
    if status.get("state") != "DESIGNING":
        print("FAIL: seal belongs to DESIGNING, before proposal review", file=sys.stderr)
        return 1
    existing = status.get("blind_derivation", {}).get("status")
    if existing == "sealed" and not args.force:
        print("FAIL: blind derivation already sealed; pass --force only for a recorded amendment", file=sys.stderr)
        return 1
    if args.force and not getattr(args, "approval_ref", None):
        print("FAIL: resealing a blind derivation requires --approval-ref", file=sys.stderr)
        return 1
    digest = sha256(blind_path)
    now = utcnow()
    try:
        with workflow_lock(), workflow_transaction([status_path, seal_path]):
            seal_path.write_text(
                f"{digest}  {blind_path.name}\nsealed_at: {now}\n",
                encoding="utf-8",
            )
            status["blind_derivation"] = {
                "status": "sealed",
                "by": args.by,
                "source_sha": status["baseline"]["code_sha"],
                "sha256": digest,
                "sealed_at": now,
                "amendment_approval_ref": args.approval_ref if args.force else None,
            }
            status["updated_at"] = now
            status["revision"] = status.get("revision", 0) + 1
            write_yaml(status_path, status)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"sealed {args.fix_id}: {digest}")
    return 0


def fix_delivery_ref() -> str | None:
    policy = load_yaml(OPERATIONS / "POLICY.yaml") or {}
    delivery = policy.get("fix_delivery", {})
    if delivery.get("target") != "IN_PR":
        return None
    reference = delivery.get("authorization_ref")
    if not reference or not gates.local_file(ROOT, reference):
        raise ValueError("autonomous PR delivery requires a retained authorization reference")
    return reference


@serialized
def cmd_start(args: argparse.Namespace) -> int:
    """Apply the standing PR-delivery scope to an already selected fix; never waive gates."""
    try:
        validate_fix_id(args.fix_id)
        reference = fix_delivery_ref()
        if not reference:
            raise ValueError("no standing PR-delivery authorization configured")
        status = load_yaml(FIXES / args.fix_id / "STATUS.yaml")
        if not status:
            raise ValueError("select/create a fix before start")
        if status.get("state") in {"HELD", "DEFERRED", "CLOSED", "ACCEPTED_RISK", "INVALIDATED", "BLOCKED"}:
            raise ValueError("start does not silently resume a held, terminal or blocked fix")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="utf-8") as temp:
            yaml.safe_dump({"approvals": {"pr_open": reference}}, temp)
            temp.flush()
            return cmd_configure(argparse.Namespace(fix_id=args.fix_id, file=temp.name, by=args.by,
                                 expect_revision=args.expect_revision, approval_ref=reference))
    except (ValueError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


def create_fix_record(
    fix_id: str,
    issue_ids: list[str],
    title: str | None = None,
    follow_up_to: str | None = None,
) -> Path:
    validate_fix_id(fix_id)
    target = FIXES / fix_id
    if target.exists():
        raise ValueError(f"{target} already exists")
    for issue_id in issue_ids:
        if not re.fullmatch(r"M-\d+", issue_id):
            raise ValueError(f"invalid issue id {issue_id!r}")
        issue_path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        if not issue_path.is_file():
            raise ValueError(f"unknown issue {issue_id}")
    index_path = FIXES / "INDEX.yaml"
    index = load_yaml(index_path)
    owners: dict[str, list[str]] = {}
    for owner_fix_id, record in index["fixes"].items():
        for issue_id in record.get("issues", []):
            owners.setdefault(issue_id, []).append(owner_fix_id)
    duplicates = {issue: owners[issue] for issue in issue_ids if issue in owners}
    if duplicates:
        valid_follow_up = follow_up_to and all(
            follow_up_to in issue_owners for issue_owners in duplicates.values()
        )
        if not valid_follow_up:
            raise ValueError(
                "issue already owned; pass --follow-up-to with an owning fix: "
                + ", ".join(f"{issue}={fixes}" for issue, fixes in duplicates.items()),
            )
    shutil.copytree(FIXES / "_template", target)
    (target / "06-verdict.md").unlink(missing_ok=True)
    status_path = target / "STATUS.yaml"
    status = load_yaml(status_path)
    status["fix_id"] = fix_id
    status["issues"] = issue_ids
    status["title"] = title or "UNSET — complete 00-intake.md"
    reference = fix_delivery_ref()
    if reference:
        status.setdefault("approvals", {})["pr_open"] = reference
    if follow_up_to:
        status["follow_up_to"] = follow_up_to
    status["updated_at"] = utcnow()
    write_yaml(status_path, status)
    evidence_manifest_path = target / "evidence" / "manifest.yaml"
    evidence_manifest = load_yaml(evidence_manifest_path)
    evidence_manifest["fix_id"] = fix_id
    write_yaml(evidence_manifest_path, evidence_manifest)
    index["fixes"][fix_id] = {
        "directory": f"fixes/{fix_id}",
        "aliases": [],
        "issues": issue_ids,
        "related_issues": [],
        "state": "TRIAGED",
        "dependencies": [],
        "stacked_on": [],
        "branch": None,
        "head_sha": None,
    }
    write_yaml(index_path, index)
    sync_issue_fix_links(index, check=False)
    write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    return target


@serialized
def cmd_new_fix(args: argparse.Namespace) -> int:
    target = FIXES / args.fix_id
    paths = [
        FIXES / "INDEX.yaml",
        ISSUES / "MASTER_ISSUES.md",
        *[
            ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
            for issue_id in args.issue
            if re.fullmatch(r"M-\d+", issue_id)
        ],
    ]
    try:
        with workflow_lock(), workflow_transaction(paths, [target]):
            created = create_fix_record(
                args.fix_id, args.issue, args.title, args.follow_up_to
            )
    except (ValueError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"created {created.relative_to(ROOT)}")
    return 0


def transition_prerequisites(fix_dir: Path, status: dict[str, Any], target: str) -> list[str]:
    return gates.prerequisites(ROOT, fix_dir, status, target)


@serialized
def cmd_transition(args: argparse.Namespace) -> int:
    try:
        validate_fix_id(args.fix_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.target not in ALLOWED_STATES:
        print(f"FAIL: unknown target state {args.target}", file=sys.stderr)
        return 1
    fix_dir = FIXES / args.fix_id
    status_path = fix_dir / "STATUS.yaml"
    if not status_path.is_file():
        print(f"FAIL: unknown fix {args.fix_id}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    revision = status.get("revision", 0)
    if getattr(args, "expect_revision", None) != revision:
        print(f"FAIL: stale/missing revision; read brief again (current revision {revision})", file=sys.stderr)
        return 1
    roles = status.get("roles", {})
    if args.by not in roles.values():
        print("FAIL: --by must be an assigned participant", file=sys.stderr)
        return 1
    owner = roles.get(args.next_owner, args.next_owner)
    if owner not in roles.values():
        print("FAIL: next owner must be an assigned participant or role", file=sys.stderr)
        return 1
    responsible = {"CRITIQUED": "skeptic", "AGREED": "skeptic", "IMPLEMENTED": "implementer",
                   "OFFLINE_VERIFIED": "implementer", "DIFF_REVIEW_PASSED": "skeptic",
                   "PR_READY": "skeptic", "LIVE_VERIFIED": "live_verifier", "CLOSED": "skeptic"}.get(args.target, "coordinator")
    review_return = (args.target == "IMPLEMENTED" and status.get("state") == "OFFLINE_VERIFIED"
                     and args.by == roles.get("skeptic")
                     and status.get("checks", {}).get("p3", {}).get("result") == "FAIL"
                     and status["checks"]["p3"].get("source_sha") == status.get("implementation", {}).get("head_sha"))
    if args.target in gates.STAGES and not review_return and args.by not in {
        roles.get("coordinator"), roles.get("human_owner"), roles.get(responsible)
    }:
        print(f"FAIL: transition belongs to {responsible} or coordinator", file=sys.stderr)
        return 1
    current = status.get("state")
    allowed = args.target in TRANSITIONS.get(current, set())
    if not allowed and not args.force:
        print(f"FAIL: transition {current} -> {args.target} is not allowed", file=sys.stderr)
        return 1
    approval_scope = {"IN_PR": "pr_open", "MERGED": "merge", "DEPLOYED": "deploy",
                      "CLOSED": "close", "ACCEPTED_RISK": "accepted_risk"}.get(args.target)
    if not args.approval_ref and approval_scope:
        args.approval_ref = status.get("approvals", {}).get(approval_scope)
    if (args.target in HUMAN_GATED_STATES or args.force) and not args.approval_ref:
        print("FAIL: this transition requires --approval-ref", file=sys.stderr)
        return 1
    if args.force and args.target in gates.STAGES[1:]:
        print(
            "FAIL: --force cannot skip a forward protocol gate",
            file=sys.stderr,
        )
        return 1
    if True:
        missing = transition_prerequisites(fix_dir, status, args.target)
        if missing:
            print("FAIL: transition prerequisites: " + "; ".join(missing), file=sys.stderr)
            return 1
    artifact = args.artifact
    if artifact and not re.match(r"^https?://", artifact):
        artifact_path = (fix_dir / artifact).resolve()
        if fix_dir.resolve() not in artifact_path.parents or not artifact_path.is_file():
            print(f"FAIL: transition artifact is missing or outside the fix: {artifact}", file=sys.stderr)
            return 1
    now = utcnow()
    transition = {
        "from": current,
        "to": args.target,
        "at": now,
        "by": args.by,
        "artifact": artifact,
        "note": args.note,
        "approval_ref": args.approval_ref,
        "forced": bool(args.force),
    }
    status.setdefault("transitions", []).append(transition)
    status["state"] = args.target
    status["revision"] = revision + 1
    status["next_action"] = {"owner": args.next_owner, "action": args.next_action}
    status["updated_at"] = now
    index_path = FIXES / "INDEX.yaml"
    issue_paths = [
        ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        for issue_id in status.get("issues", [])
        if re.fullmatch(r"M-\d+", str(issue_id))
    ]
    try:
        with workflow_lock(), workflow_transaction(
            [status_path, index_path, ISSUES / "MASTER_ISSUES.md", *issue_paths]
        ):
            write_yaml(status_path, status)
            index = synchronized_index(load_yaml(index_path))
            write_yaml(index_path, index)
            sync_issue_fix_links(index, check=False)
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"{args.fix_id}: {current} -> {args.target}")
    return 0


def run_checked(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )


def exact_tag(repo: Path, commit: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "describe", "--tags", "--exact-match", commit],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def scan_main(repo: Path, source_ref: str) -> dict[str, Any]:
    current = load_yaml(RELEASES / "CURRENT.yaml") or {}
    previous = str(current.get("code_repository", {}).get("origin_main_sha", ""))
    if not previous:
        raise ValueError("CURRENT.yaml lacks code_repository.origin_main_sha")
    observed = run_checked(
        ["git", "-C", str(repo), "rev-parse", source_ref]
    ).stdout.strip()
    relation = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", previous, observed],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if relation.returncode != 0:
        raise ValueError(
            f"recorded main {previous[:12]} is not an ancestor of {observed[:12]}"
        )
    log_text = run_checked(
        [
            "git",
            "-C",
            str(repo),
            "log",
            "--format=%H%x09%s",
            f"{previous}..{observed}",
        ]
    ).stdout
    commits = []
    referenced_issues: set[str] = set()
    referenced_fixes: set[str] = set()
    unattributed = []
    for line in log_text.splitlines():
        commit, _, subject = line.partition("\t")
        issues = set(re.findall(r"\bM-\d+\b", subject))
        fixes = set(re.findall(r"\bT\d+-M\d+\b", subject))
        referenced_issues.update(issues)
        referenced_fixes.update(fixes)
        item = {"sha": commit, "subject": subject}
        commits.append(item)
        if not issues and not fixes:
            unattributed.append(item)
    diff_text = run_checked(
        ["git", "-C", str(repo), "diff", "--name-only", f"{previous}..{observed}"]
    ).stdout
    changed_files = [line for line in diff_text.splitlines() if line]
    anatomy_path = ROOT / "anatomy" / "ANATOMY.md"
    anatomy_text = (
        anatomy_path.read_text(encoding="utf-8") if anatomy_path.is_file() else ""
    )
    anatomy_candidates = []
    for path in changed_files:
        relative = path.removeprefix("phorvex/")
        if relative in anatomy_text:
            anatomy_candidates.append(path)
    return {
        "schema_version": 1,
        "commit_range": {"from": previous, "to": observed},
        "source_ref": source_ref,
        "source_release": exact_tag(repo, observed),
        "commits": commits,
        "changed_files": changed_files,
        "anatomy_candidates": anatomy_candidates,
        "referenced_issues": sorted(
            referenced_issues, key=lambda value: int(value.split("-")[1])
        ),
        "referenced_fixes": sorted(referenced_fixes),
        "unattributed_commits": unattributed,
        "review_decisions": [],
    }


def reconciliation_id(prefix: str, commit: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{commit[:12]}"


def write_issue_state(
    issue_id: str,
    target: str,
    *,
    by: str,
    source: str,
    artifact: str,
    note: str | None = None,
    approval_ref: str | None = None,
) -> Path:
    path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
    if not path.is_file():
        raise ValueError(f"unknown issue {issue_id}")
    metadata, body = parse_entry(path)
    current = metadata.get("workflow_state")
    if current == target:
        return path
    if target not in ISSUE_TRANSITIONS.get(current, set()):
        raise ValueError(f"issue transition {issue_id}: {current} -> {target} is not allowed")
    now = utcnow()
    metadata.setdefault("transitions", []).append(
        {
            "from": current,
            "to": target,
            "at": now,
            "by": by,
            "artifact": artifact,
            "note": note,
            "approval_ref": approval_ref,
            "forced": False,
        }
    )
    metadata["workflow_state"] = target
    metadata["workflow_state_source"] = source
    metadata["updated_at"] = now
    if target == "CLOSED" and artifact not in metadata.setdefault("verdicts", []):
        metadata["verdicts"].append(artifact)
    write_entry(path, metadata, body)
    return path


@serialized
def cmd_sync_main(args: argparse.Namespace) -> int:
    repo = Path(args.repo or ROOT.parent).resolve()
    try:
        scan = scan_main(repo, args.source_ref)
    except (ValueError, subprocess.CalledProcessError) as exc:
        detail = exc.stdout if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print(f"FAIL: {detail}", file=sys.stderr)
        return 1
    previous = scan["commit_range"]["from"]
    observed = scan["commit_range"]["to"]
    if args.check:
        if previous == observed:
            print(f"main sync: PASS at {observed}")
            return 0
        print(yaml.safe_dump(scan, sort_keys=False, allow_unicode=True), end="")
        print(
            f"FAIL: main advanced from {previous[:12]} to {observed[:12]}",
            file=sys.stderr,
        )
        return 1
    if previous == observed:
        print(f"main already synchronized at {observed}")
        return 0
    if not args.approval_ref:
        print("FAIL: --publish requires --approval-ref", file=sys.stderr)
        return 1
    referenced = set(scan["referenced_issues"])
    reviewed = set(args.issue) | set(args.ignore_issue)
    missing_reviews = sorted(referenced - reviewed)
    if missing_reviews:
        print(
            "FAIL: referenced issues need --issue or --ignore-issue: "
            + ", ".join(missing_reviews),
            file=sys.stderr,
        )
        return 1
    if scan["unattributed_commits"] and not args.unattributed_reviewed:
        print(
            "FAIL: unattributed commits require --unattributed-reviewed",
            file=sys.stderr,
        )
        return 1
    try:
        require_main_ancestor(repo, args.source_ref)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for issue_id in args.issue + args.ignore_issue:
        if not (ISSUES / "entries" / f"{pad_issue(issue_id)}.md").is_file():
            print(f"FAIL: unknown issue {issue_id}", file=sys.stderr)
            return 1
    sync_id = reconciliation_id("MAIN", observed)
    target = RELEASES / sync_id
    issue_paths = [
        ISSUES / "entries" / f"{pad_issue(issue_id)}.md" for issue_id in args.issue
    ]
    paths = [
        RELEASES / "CURRENT.yaml",
        ISSUES / "MASTER_ISSUES.md",
        *issue_paths,
    ]
    try:
        with workflow_lock(), workflow_transaction(paths, [target]):
            shutil.copytree(RELEASES / "_template", target)
            scan["review_decisions"] = [
                *[
                    {"issue_id": issue_id, "decision": "MAIN_PENDING_DEPLOY"}
                    for issue_id in args.issue
                ],
                *[
                    {"issue_id": issue_id, "decision": "REVIEWED_NO_TRANSITION"}
                    for issue_id in args.ignore_issue
                ],
            ]
            write_yaml(target / "changes.yaml", scan)
            now = utcnow()
            status = load_yaml(target / "STATUS.yaml")
            status.update(
                {
                    "sync_id": sync_id,
                    "kind": "main",
                    "state": "MAIN_RECORDED",
                    "created_at": now,
                    "updated_at": now,
                    "approval_ref": args.approval_ref,
                }
            )
            status["code_repository"] = {
                "previous_main_sha": previous,
                "observed_main_sha": observed,
                "source_release": scan["source_release"],
            }
            status["included_issues"] = sorted(set(args.issue))
            status["next_action"] = {
                "owner": "release-synchronizer",
                "action": "Observe deployment and create a deployment reconciliation.",
            }
            status["transitions"] = [
                {
                    "from": "SCANNED",
                    "to": "MAIN_RECORDED",
                    "at": now,
                    "by": args.by,
                    "approval_ref": args.approval_ref,
                }
            ]
            write_yaml(target / "STATUS.yaml", status)
            manifest = load_yaml(target / "evidence" / "manifest.yaml")
            manifest["subject"]["id"] = sync_id
            write_yaml(target / "evidence" / "manifest.yaml", manifest)
            summary = (
                "# Main reconciliation\n\n"
                f"- Previous main: `{previous}`\n"
                f"- Observed main: `{observed}`\n"
                f"- Source release: `{scan['source_release'] or 'untagged'}`\n"
                f"- Commits reviewed: {len(scan['commits'])}\n"
                f"- Unattributed commits reviewed: {len(scan['unattributed_commits'])}\n"
                f"- Issues moved to main-pending-deploy: "
                f"{', '.join(args.issue) or 'none'}\n"
                f"- Approval: `{args.approval_ref}`\n"
            )
            write_text(target / "MAIN_SYNC.md", summary)
            artifact = f"releases/{sync_id}/STATUS.yaml"
            for issue_id in args.issue:
                write_issue_state(
                    issue_id,
                    "MAIN_PENDING_DEPLOY",
                    by=args.by,
                    source=f"main-sync:{sync_id}",
                    artifact=artifact,
                )
            current = load_yaml(RELEASES / "CURRENT.yaml")
            current["recorded_at"] = now
            current["status"] = "main-synchronized-deployment-pending"
            current["code_repository"]["origin_main_sha"] = observed
            current["code_repository"]["source_release"] = scan["source_release"]
            pending = set(current.get("main_pending_deploy_issues", []))
            pending.update(args.issue)
            current["main_pending_deploy_issues"] = sorted(
                pending, key=lambda value: int(value.split("-")[1])
            )
            write_yaml(RELEASES / "CURRENT.yaml", current)
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"published releases/{sync_id}")
    return 0


def parse_issue_results(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        issue_id, separator, artifact = value.partition("=")
        if not separator or not re.fullmatch(r"M-\d+", issue_id) or not artifact:
            raise ValueError(f"{label} expects M-NNN=artifact, got {value!r}")
        if issue_id in result:
            raise ValueError(f"duplicate {label} result for {issue_id}")
        result[issue_id] = artifact
    return result


def validate_artifact_reference(value: str) -> None:
    if re.match(r"^https?://", value):
        return
    path = (ROOT / value).resolve()
    if ROOT.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"missing/outside artifact {value}")


def local_artifact_path(value: str) -> Path | None:
    if re.match(r"^https?://", value):
        return None
    path = (ROOT / value).resolve()
    return path if path.is_file() and ROOT.resolve() in path.parents else None


def artifact_declares_result(value: str, expected: str) -> bool:
    path = local_artifact_path(value)
    if path is None or path.stat().st_size > 10 * 1024 * 1024:
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix in {".yaml", ".yml"}:
        try:
            documents = list(yaml.safe_load_all(text))
            for document in documents:
                if not isinstance(document, dict):
                    continue
                actual = document.get("result") or document.get("verdict")
                if str(actual).upper() == expected:
                    return True
        except yaml.YAMLError:
            pass
    patterns = [
        rf"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?"
        rf"(?:result|verdict|l3|l4)(?:\*\*)?\s*[:=-]?\s*"
        rf"\**`?{re.escape(expected)}\b",
        rf"(?im)^\s*#+\s+.*\b{re.escape(expected)}\b",
    ]
    return any(re.search(pattern, text) for pattern in patterns)


def evidence_indexes_artifact(value: str, release_dir: Path) -> bool:
    path = local_artifact_path(value)
    if path is None:
        return False
    candidates: list[tuple[Path, Path]] = [
        (release_dir, release_dir / "evidence" / "manifest.yaml")
    ]
    try:
        relative = path.relative_to(FIXES.resolve())
        fix_root = FIXES / relative.parts[0]
        candidates.append((fix_root, fix_root / "evidence" / "manifest.yaml"))
    except (ValueError, IndexError):
        pass
    for record_root, manifest_path in candidates:
        if not manifest_path.is_file():
            continue
        manifest = load_yaml(manifest_path) or {}
        for artifact in manifest.get("artifacts", []):
            candidate = (record_root / str(artifact.get("path", ""))).resolve()
            if candidate != path:
                continue
            expected = artifact.get("sha256")
            if expected and sha256(path) != expected:
                continue
            return True
    return False


def append_fix_transition(
    status: dict[str, Any],
    target: str,
    *,
    by: str,
    artifact: str,
    approval_ref: str | None,
    note: str,
) -> None:
    current = status.get("state")
    if current == target:
        return
    if target not in TRANSITIONS.get(current, set()):
        raise ValueError(
            f"{status.get('fix_id')}: transition {current} -> {target} is not allowed"
        )
    now = utcnow()
    status.setdefault("transitions", []).append(
        {
            "from": current,
            "to": target,
            "at": now,
            "by": by,
            "artifact": artifact,
            "note": note,
            "approval_ref": approval_ref,
            "forced": False,
        }
    )
    status["state"] = target
    status["revision"] = status.get("revision", 0) + 1
    status["updated_at"] = now


def validate_fix_finalization(
    fix_dir: Path, status: dict[str, Any], issue_results: dict[str, str]
) -> list[str]:
    missing: list[str] = gates.prerequisites(ROOT, fix_dir, status, "CLOSED", finalizing=True)
    if status.get("state") not in {
        "DEPLOYED",
        "LIVE_VERIFIED",
        "SYNCHRONIZED",
        "CLOSED",
    }:
        missing.append(f"state is {status.get('state')}, expected DEPLOYED or later")
    if any(issue_results.get(issue_id) != "PASS" for issue_id in status.get("issues", [])):
        missing.append("every owned issue must have a PASS release result")
    final_verdict = fix_dir / "06-verdict.md"
    if not final_verdict.is_file():
        missing.append("06-verdict.md")
    elif not artifact_declares_result(
        str(final_verdict.relative_to(ROOT)), "PASS"
    ):
        missing.append("06-verdict.md must declare PASS")
    permanent = str(
        status.get("synchronization", {}).get("permanent_tests", "")
    ).lower()
    if not permanent or any(
        token in permanent for token in ("pending", "missing", "stale", "gap")
    ):
        missing.append("synchronization.permanent_tests must be current")
    verify = fix_dir / "verify.sh"
    if not verify.is_file():
        missing.append("verify.sh")
    else:
        try:
            result = subprocess.run(
                ["bash", str(verify), "--offline"],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=fix_dir,
            )
        except OSError as exc:
            missing.append(f"verify.sh could not run: {exc}")
        else:
            if result.returncode != 0:
                missing.append(f"verify.sh --offline exited {result.returncode}")
    return missing


def record_fix_deployment(
    fix_id: str,
    observation: dict[str, Any],
    *,
    artifact: str,
    by: str,
    approval_ref: str,
) -> None:
    status_path = FIXES / fix_id / "STATUS.yaml"
    status = load_yaml(status_path) or {}
    if status.get("state") not in {
        "MERGED",
        "DEPLOYED",
        "LIVE_VERIFIED",
        "SYNCHRONIZED",
        "CLOSED",
    }:
        raise ValueError(
            f"{fix_id}: deployment requires MERGED state, found {status.get('state')}"
        )
    existing_sha = status.get("deployment", {}).get("git_sha")
    if existing_sha and existing_sha != observation["embedded_git_sha"]:
        raise ValueError(f"{fix_id}: deployment SHA conflicts with existing record")
    status["deployment"] = {
        "image": observation["image"],
        "digest": observation["digest"],
        "git_sha": observation["embedded_git_sha"],
        "rolled_out_at": observation["observed_at"],
    }
    if status.get("state") == "MERGED":
        append_fix_transition(
            status,
            "DEPLOYED",
            by=by,
            artifact=artifact,
            approval_ref=approval_ref,
            note="Observed in deployment reconciliation.",
        )
        status["next_action"] = {
            "owner": status.get("roles", {}).get("live_verifier"),
            "action": "Run the required scoped live verification.",
        }
    write_yaml(status_path, status)


def record_fix_final_result(
    fix_id: str,
    issue_results: dict[str, str],
    issue_artifacts: dict[str, str],
    *,
    release_record: str,
    by: str,
    approval_ref: str,
) -> None:
    fix_dir = FIXES / fix_id
    status_path = fix_dir / "STATUS.yaml"
    status = load_yaml(status_path) or {}
    results = {issue_results.get(issue_id) for issue_id in status.get("issues", [])}
    if "FAIL" in results:
        if status.get("state") in {"DEPLOYED", "LIVE_VERIFIED", "SYNCHRONIZED", "CLOSED"}:
            append_fix_transition(
                status,
                "REOPENED",
                by=by,
                artifact=next(
                    issue_artifacts[issue_id]
                    for issue_id in status.get("issues", [])
                    if issue_results.get(issue_id) == "FAIL"
                ),
                approval_ref=approval_ref,
                note="Scoped deployed verification failed.",
            )
        status["next_action"] = {
            "owner": status.get("roles", {}).get("coordinator"),
            "action": "Re-triage the failed deployed verification.",
        }
        write_yaml(status_path, status)
        return
    if "BLOCKED" in results:
        status["next_action"] = {
            "owner": status.get("roles", {}).get("live_verifier"),
            "action": "Resolve the blocked deployed verification.",
        }
        write_yaml(status_path, status)
        return
    missing = validate_fix_finalization(fix_dir, status, issue_results)
    if missing:
        raise ValueError(f"{fix_id}: cannot close: {'; '.join(missing)}")
    l3_artifact = next(
        (issue_artifacts[issue_id] for issue_id in status.get("issues", [])),
        release_record,
    )
    if status.get("state") == "DEPLOYED":
        append_fix_transition(
            status,
            "LIVE_VERIFIED",
            by=by,
            artifact=l3_artifact,
            approval_ref=approval_ref,
            note="All required deployed verification passed.",
        )
    synchronization = status.setdefault("synchronization", {})
    synchronization["issue_entries"] = f"PASS:{release_record}"
    synchronization["master_register"] = f"PASS:{release_record}"
    synchronization["anatomy_release"] = f"PASS:{release_record}"
    if status.get("state") == "LIVE_VERIFIED":
        append_fix_transition(
            status,
            "SYNCHRONIZED",
            by=by,
            artifact=release_record,
            approval_ref=approval_ref,
            note="Issue, register, Anatomy and release records synchronized.",
        )
    if status.get("state") == "SYNCHRONIZED":
        append_fix_transition(
            status,
            "CLOSED",
            by=by,
            artifact="06-verdict.md",
            approval_ref=approval_ref,
            note="Independent final verdict and synchronization complete.",
        )
    status["next_action"] = {
        "owner": status.get("roles", {}).get("coordinator"),
        "action": "No action; fix is closed.",
    }
    write_yaml(status_path, status)


@serialized
def cmd_release_sync(args: argparse.Namespace) -> int:
    repo = Path(args.repo or ROOT.parent).resolve()
    if args.finalize:
        return finalize_release_sync(args)
    required = {
        "--image": args.image,
        "--digest": args.digest,
        "--git-sha": args.git_sha,
        "--release-commit": args.release_commit,
        "--observed-at": args.observed_at,
        "--observed-by": args.observed_by,
        "--environment": args.environment,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        print("FAIL: missing deployment observation " + ", ".join(missing), file=sys.stderr)
        return 1
    try:
        embedded = run_checked(
            ["git", "-C", str(repo), "rev-parse", args.git_sha]
        ).stdout.strip()
        release_commit = run_checked(
            ["git", "-C", str(repo), "rev-parse", args.release_commit]
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: {exc.stdout}", file=sys.stderr)
        return 1
    observation = {
        "image": args.image,
        "digest": args.digest,
        "embedded_git_sha": embedded,
        "release_commit": release_commit,
        "observed_at": args.observed_at,
        "observed_by": args.observed_by,
        "environment": args.environment,
        "source_release": args.source_release or exact_tag(repo, release_commit),
        "issues": sorted(set(args.issue)),
        "fixes": sorted(set(args.fix)),
    }
    if args.check:
        current = load_yaml(RELEASES / "CURRENT.yaml") or {}
        print(yaml.safe_dump(observation, sort_keys=False), end="")
        deployed = current.get("deployed", {})
        same = (
            deployed.get("image") == args.image
            and deployed.get("digest") == args.digest
            and str(deployed.get("embedded_git_sha")) == embedded
        )
        print("deployment observation: " + ("already recorded" if same else "requires publish"))
        return 0 if same else 1
    if not args.approval_ref:
        print("FAIL: deployment publish requires --approval-ref", file=sys.stderr)
        return 1
    for issue_id in observation["issues"]:
        path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        if not path.is_file():
            print(f"FAIL: unknown issue {issue_id}", file=sys.stderr)
            return 1
        state = parse_entry(path)[0].get("workflow_state")
        if state not in {"MAIN_PENDING_DEPLOY", "DEPLOYED_PENDING_L3"}:
            print(
                f"FAIL: {issue_id} is {state}, expected MAIN_PENDING_DEPLOY",
                file=sys.stderr,
            )
            return 1
    fix_index = (load_yaml(FIXES / "INDEX.yaml") or {}).get("fixes", {})
    unknown_fixes = sorted(set(observation["fixes"]) - set(fix_index))
    if unknown_fixes:
        print(f"FAIL: unknown fixes {unknown_fixes}", file=sys.stderr)
        return 1
    for fix_id in observation["fixes"]:
        fix_status = load_yaml(FIXES / fix_id / "STATUS.yaml") or {}
        if fix_status.get("state") not in {
            "MERGED",
            "DEPLOYED",
            "LIVE_VERIFIED",
            "SYNCHRONIZED",
            "CLOSED",
        }:
            print(
                f"FAIL: {fix_id} must be MERGED before deployment; "
                f"found {fix_status.get('state')}",
                file=sys.stderr,
            )
            return 1
    sync_id = reconciliation_id("DEPLOY", embedded)
    target = RELEASES / sync_id
    issue_paths = [
        ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        for issue_id in observation["issues"]
    ]
    paths = [
        RELEASES / "CURRENT.yaml",
        ISSUES / "MASTER_ISSUES.md",
        FIXES / "INDEX.yaml",
        *issue_paths,
        *[FIXES / fix_id / "STATUS.yaml" for fix_id in observation["fixes"]],
    ]
    try:
        with workflow_lock(), workflow_transaction(paths, [target]):
            shutil.copytree(RELEASES / "_template", target)
            now = utcnow()
            status = load_yaml(target / "STATUS.yaml")
            status.update(
                {
                    "sync_id": sync_id,
                    "kind": "deployment",
                    "state": "DEPLOY_OBSERVED",
                    "created_at": now,
                    "updated_at": now,
                    "approval_ref": args.approval_ref,
                }
            )
            status["deployment"] = observation
            status["included_fixes"] = observation["fixes"]
            status["included_issues"] = observation["issues"]
            status["anatomy"] = {
                "source_commit": embedded,
                "status": "pending",
            }
            status["next_action"] = {
                "owner": "release-synchronizer",
                "action": (
                    "Publish Anatomy at the observed SHA, run scoped verifiers, "
                    f"then finalize {sync_id}."
                ),
            }
            status["transitions"] = [
                {
                    "from": "DRAFT",
                    "to": "DEPLOY_OBSERVED",
                    "at": now,
                    "by": args.by,
                    "approval_ref": args.approval_ref,
                }
            ]
            write_yaml(target / "STATUS.yaml", status)
            write_yaml(
                target / "fixes.yaml",
                {"schema_version": 1, "fixes": observation["fixes"]},
            )
            manifest = load_yaml(target / "evidence" / "manifest.yaml")
            manifest["subject"]["id"] = sync_id
            write_yaml(target / "evidence" / "manifest.yaml", manifest)
            write_text(
                target / "RELEASE_SYNC.md",
                "# Deployment reconciliation\n\n"
                f"- Image: `{args.image}`\n"
                f"- Digest: `{args.digest}`\n"
                f"- Embedded source: `{embedded}`\n"
                f"- Release commit: `{release_commit}`\n"
                f"- Observed at: `{args.observed_at}`\n"
                f"- Observed by: `{args.observed_by}`\n"
                f"- Environment: `{args.environment}`\n"
                f"- Issues awaiting verdict: {', '.join(observation['issues']) or 'none'}\n",
            )
            artifact = f"releases/{sync_id}/STATUS.yaml"
            for issue_id in observation["issues"]:
                write_issue_state(
                    issue_id,
                    "DEPLOYED_PENDING_L3",
                    by=args.by,
                    source=f"deployment-sync:{sync_id}",
                    artifact=artifact,
                )
            for fix_id in observation["fixes"]:
                record_fix_deployment(
                    fix_id,
                    observation,
                    artifact=artifact,
                    by=args.by,
                    approval_ref=args.approval_ref,
                )
            write_yaml(
                FIXES / "INDEX.yaml",
                synchronized_index(load_yaml(FIXES / "INDEX.yaml")),
            )
            current = load_yaml(RELEASES / "CURRENT.yaml")
            current["recorded_at"] = now
            current["status"] = "deployment-observed-verification-pending"
            current["deployed"] = {
                "image": args.image,
                "release_commit": release_commit,
                "embedded_git_sha": embedded,
                "digest": args.digest,
                "observed_by": args.observed_by,
                "observed_at": args.observed_at,
                "environment": args.environment,
                "must_reverify_before_next_live_claim": True,
                "sync_record": f"releases/{sync_id}/STATUS.yaml",
            }
            anatomy_pin = load_yaml(ROOT / "anatomy" / "PIN.yaml")
            anatomy_source = str(anatomy_pin["anatomy"]["source_commit"])
            anatomy_current = pins_match(embedded, anatomy_source)
            current["anatomy"]["current_for_deployed_release"] = anatomy_current
            current["anatomy"]["refresh_status"] = (
                "PASS" if anatomy_current else "pending"
            )
            current["main_pending_deploy_issues"] = sorted(
                set(current.get("main_pending_deploy_issues", []))
                - set(observation["issues"]),
                key=lambda value: int(value.split("-")[1]),
            )
            current["pending_release_fixes"] = sorted(
                set(current.get("pending_release_fixes", []))
                - set(observation["fixes"])
            )
            write_yaml(RELEASES / "CURRENT.yaml", current)
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"published releases/{sync_id}; verification remains pending")
    return 0


@serialized
def finalize_release_sync(args: argparse.Namespace) -> int:
    if not args.record:
        print("FAIL: --finalize requires --record", file=sys.stderr)
        return 1
    if not args.approval_ref:
        print("FAIL: --finalize requires --approval-ref", file=sys.stderr)
        return 1
    target = RELEASES / args.record
    status_path = target / "STATUS.yaml"
    if not status_path.is_file() or not re.fullmatch(
        r"DEPLOY-\d{8}-\d{6}-[a-f0-9]{7,40}", args.record
    ):
        print(f"FAIL: unknown deployment record {args.record}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if status.get("state") in {"RECONCILED", "BLOCKED"}:
        print(f"FAIL: deployment record is already terminal: {status.get('state')}", file=sys.stderr)
        return 1
    try:
        passed = parse_issue_results(args.pass_issue, "--pass-issue")
        failed = parse_issue_results(args.fail_issue, "--fail-issue")
        deferred = parse_issue_results(args.defer_issue, "--defer-issue")
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    overlaps = (set(passed) & set(failed)) | (set(passed) & set(deferred)) | (
        set(failed) & set(deferred)
    )
    if overlaps:
        print(f"FAIL: duplicate issue results {sorted(overlaps)}", file=sys.stderr)
        return 1
    included = set(status.get("included_issues", []))
    results = set(passed) | set(failed) | set(deferred)
    if included != results:
        print(
            f"FAIL: results must cover included issues; missing={sorted(included-results)}, "
            f"extra={sorted(results-included)}",
            file=sys.stderr,
        )
        return 1
    try:
        for expected, artifacts in (
            ("PASS", passed.values()),
            ("FAIL", failed.values()),
            ("BLOCKED", deferred.values()),
        ):
            for artifact in artifacts:
                validate_artifact_reference(artifact)
                if not artifact_declares_result(artifact, expected):
                    raise ValueError(
                        f"artifact does not declare {expected}: {artifact}"
                    )
                if not evidence_indexes_artifact(artifact, target):
                    raise ValueError(
                        f"artifact is not indexed by fix/release evidence: {artifact}"
                    )
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    issue_results = {
        **{issue_id: "PASS" for issue_id in passed},
        **{issue_id: "FAIL" for issue_id in failed},
        **{issue_id: "BLOCKED" for issue_id in deferred},
    }
    issue_artifacts = {**passed, **failed, **deferred}
    included_fixes = status.get("included_fixes", [])
    for fix_id in included_fixes:
        fix_status = load_yaml(FIXES / fix_id / "STATUS.yaml") or {}
        owned = set(fix_status.get("issues", []))
        if not owned or not owned <= included:
            print(
                f"FAIL: {fix_id} owned issues are not fully included in release results",
                file=sys.stderr,
            )
            return 1
        if all(issue_results.get(issue_id) == "PASS" for issue_id in owned):
            missing_fix = validate_fix_finalization(
                FIXES / fix_id, fix_status, issue_results
            )
            if missing_fix:
                print(
                    f"FAIL: {fix_id}: cannot close: {'; '.join(missing_fix)}",
                    file=sys.stderr,
                )
                return 1
    current_path = RELEASES / "CURRENT.yaml"
    current = load_yaml(current_path)
    deployed = str(status.get("deployment", {}).get("embedded_git_sha", ""))
    if deployed != current.get("deployed", {}).get("embedded_git_sha"):
        print("FAIL: deployment moved; reconcile and reverify the current release", file=sys.stderr)
        return 1
    anatomy = current.get("anatomy", {})
    anatomy_pin = load_yaml(ROOT / "anatomy" / "PIN.yaml") or {}
    anatomy_source = str(anatomy_pin.get("anatomy", {}).get("source_commit", ""))
    current_anatomy_source = str(anatomy.get("source_commit", ""))
    if not anatomy.get("current_for_deployed_release") or not pins_match(
        deployed, anatomy_source
    ) or not pins_match(current_anatomy_source, anatomy_source):
        print("FAIL: canonical Anatomy is not published for this deployment", file=sys.stderr)
        return 1
    issue_paths = [
        ISSUES / "entries" / f"{pad_issue(issue_id)}.md" for issue_id in included
    ]
    paths = [
        status_path,
        target / "verifier-results.yaml",
        target / "RELEASE_SYNC.md",
        current_path,
        ISSUES / "MASTER_ISSUES.md",
        FIXES / "INDEX.yaml",
        *issue_paths,
        *[FIXES / fix_id / "STATUS.yaml" for fix_id in included_fixes],
    ]
    try:
        with workflow_lock(), workflow_transaction(paths):
            artifact_base = f"releases/{args.record}"
            for issue_id, artifact in passed.items():
                write_issue_state(
                    issue_id,
                    "CLOSED",
                    by=args.by,
                    source=f"release-finalize:{args.record}",
                    artifact=artifact,
                    approval_ref=args.approval_ref,
                )
            for issue_id, artifact in failed.items():
                write_issue_state(
                    issue_id,
                    "REOPENED",
                    by=args.by,
                    source=f"release-finalize:{args.record}",
                    artifact=artifact,
                    approval_ref=args.approval_ref,
                )
            for fix_id in included_fixes:
                record_fix_final_result(
                    fix_id,
                    issue_results,
                    issue_artifacts,
                    release_record=f"releases/{args.record}/STATUS.yaml",
                    by=args.by,
                    approval_ref=args.approval_ref,
                )
            write_yaml(
                FIXES / "INDEX.yaml",
                synchronized_index(load_yaml(FIXES / "INDEX.yaml")),
            )
            result_rows = [
                *[
                    {"issue_id": issue_id, "result": "PASS", "artifact": artifact}
                    for issue_id, artifact in passed.items()
                ],
                *[
                    {"issue_id": issue_id, "result": "FAIL", "artifact": artifact}
                    for issue_id, artifact in failed.items()
                ],
                *[
                    {"issue_id": issue_id, "result": "BLOCKED", "artifact": artifact}
                    for issue_id, artifact in deferred.items()
                ],
            ]
            write_yaml(
                target / "verifier-results.yaml",
                {"schema_version": 1, "results": result_rows},
            )
            now = utcnow()
            terminal = "BLOCKED" if deferred else "RECONCILED"
            prior = status["state"]
            status["state"] = terminal
            status["updated_at"] = now
            status["issue_results"] = {
                row["issue_id"]: {
                    "result": row["result"],
                    "artifact": row["artifact"],
                }
                for row in result_rows
            }
            status["anatomy"] = {
                "source_commit": anatomy_source,
                "status": "PASS",
            }
            status.setdefault("transitions", []).append(
                {
                    "from": prior,
                    "to": terminal,
                    "at": now,
                    "by": args.by,
                    "approval_ref": args.approval_ref,
                    "artifact": f"{artifact_base}/verifier-results.yaml",
                }
            )
            status["next_action"] = {
                "owner": "coordinator",
                "action": (
                    "Resolve blocked issue verification."
                    if deferred
                    else "No action; included issue and fix records are synchronized."
                ),
            }
            write_yaml(status_path, status)
            current["recorded_at"] = now
            current["status"] = (
                "release-verification-blocked" if deferred else "release-reconciled"
            )
            current["deployed"]["must_reverify_before_next_live_claim"] = False
            write_yaml(current_path, current)
            with (target / "RELEASE_SYNC.md").open("a", encoding="utf-8") as fh:
                fh.write(
                    "\n## Final result\n\n"
                    f"- State: `{terminal}`\n"
                    f"- Results: `{artifact_base}/verifier-results.yaml`\n"
                    f"- Anatomy source: `{anatomy_source}`\n"
                    f"- Approval: `{args.approval_ref}`\n"
                )
            write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"{args.record}: {terminal}")
    return 0


def synchronized_campaign_index(index: dict[str, Any] | None = None) -> dict[str, Any]:
    existing = (index or {}).get("campaigns", {})
    result: dict[str, Any] = {"schema_version": 1, "campaigns": {}}
    if not CAMPAIGNS.exists():
        return result
    for status_path in sorted(CAMPAIGNS.glob("*/STATUS.yaml")):
        campaign_id = status_path.parent.name
        if campaign_id == "_template":
            continue
        status = load_yaml(status_path) or {}
        profile = status.get("profile") or existing.get(campaign_id, {}).get(
            "profile", "legacy-migrated"
        )
        result["campaigns"][campaign_id] = {
            "directory": f"campaigns/{campaign_id}",
            "state": status.get("state"),
            "profile": profile,
        }
    return result


def write_campaign_index() -> None:
    path = CAMPAIGNS / "INDEX.yaml"
    write_yaml(path, synchronized_campaign_index(load_yaml(path) or {}))


def validate_campaign_id(campaign_id: str) -> None:
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9-]*", campaign_id
    ):
        raise ValueError(f"unsafe campaign id: {campaign_id!r}")


def new_campaign_id(question: str) -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}-{safe_slug(question)}"


@serialized
def cmd_new_campaign(args: argparse.Namespace) -> int:
    campaign_id = args.campaign_id or new_campaign_id(args.question)
    try:
        validate_campaign_id(campaign_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    target = CAMPAIGNS / campaign_id
    if target.exists():
        print(f"FAIL: campaigns/{campaign_id} already exists", file=sys.stderr)
        return 1
    if not args.approval_ref:
        print("FAIL: campaign creation requires --approval-ref", file=sys.stderr)
        return 1
    current = load_yaml(RELEASES / "CURRENT.yaml") or {}
    deployed = current.get("deployed", {})
    paths = [CAMPAIGNS / "INDEX.yaml"]
    try:
        with workflow_lock(), workflow_transaction(paths, [target]):
            shutil.copytree(CAMPAIGNS / "_template", target)
            now = utcnow()
            status = load_yaml(target / "STATUS.yaml")
            status.update(
                {
                    "campaign_id": campaign_id,
                    "question": args.question,
                    "owner": args.owner,
                    "approval_ref": args.approval_ref,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            status["scope"] = {
                "environment": args.environment,
                "source_release": args.source_release
                or current.get("code_repository", {}).get("source_release"),
                "included_fixes": sorted(set(args.fix)),
                "duration_ceiling": args.duration_ceiling,
                "cost_ceiling": args.cost_ceiling,
                "permission": args.permission,
            }
            status["pins"] = {
                "image": args.image or deployed.get("image"),
                "digest": args.digest or deployed.get("digest"),
                "embedded_git_sha": args.git_sha
                or deployed.get("embedded_git_sha"),
            }
            status["safety"]["stop_conditions"] = args.stop_condition
            status["roles"] = {
                "campaign_lead": args.campaign_lead,
                "independent_reviewer": args.independent_reviewer,
                "coordinator": args.coordinator,
            }
            write_yaml(target / "STATUS.yaml", status)
            manifest_path = (
                target / "rounds" / "round-1" / "evidence" / "manifest.yaml"
            )
            manifest = load_yaml(manifest_path)
            manifest["subject"]["id"] = campaign_id
            write_yaml(manifest_path, manifest)
            write_campaign_index()
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"created campaigns/{campaign_id}")
    return 0


def apply_round_states(status: dict[str, Any], values: list[str]) -> None:
    rounds = {record["id"]: record for record in status.get("rounds", [])}
    for value in values:
        round_id, separator, state = value.partition("=")
        if not separator or state not in {"PLANNED", "RUNNING", "COMPLETE", "ABORTED"}:
            raise ValueError(f"--round-state expects round-id=STATE, got {value!r}")
        if round_id not in rounds:
            raise ValueError(f"unknown campaign round {round_id}")
        rounds[round_id]["state"] = state


def campaign_transition_prerequisites(
    campaign_dir: Path, status: dict[str, Any], target: str
) -> list[str]:
    missing: list[str] = []
    if target == "APPROVED":
        hypotheses = load_yaml(campaign_dir / "hypotheses.yaml") or {}
        records = hypotheses.get("hypotheses", [])
        required = (
            "claim",
            "falsifier",
            "sample_unit",
            "minimum_observations",
            "positive_control",
            "acceptance_threshold",
        )
        if not records or any(
            any(record.get(field) in (None, "") for field in required)
            for record in records
        ):
            missing.append("complete hypotheses.yaml pre-registration")
        if not status.get("safety", {}).get("stop_conditions"):
            missing.append("safety.stop_conditions")
        if not status.get("approval_ref"):
            missing.append("owner campaign approval")
    if target == "BASELINED":
        for field in ("image", "digest", "embedded_git_sha"):
            if not status.get("pins", {}).get(field):
                missing.append(f"pins.{field}")
        if status.get("positive_control") != "PASS":
            missing.append("positive_control must be PASS")
    if target == "RUNNING":
        permission = status.get("scope", {}).get("permission")
        if permission in {"controlled-mutation", "attack"} and not status.get(
            "safety", {}
        ).get("phase_approval_ref"):
            missing.append("safety.phase_approval_ref")
        if status.get("safety", {}).get("unresolved"):
            missing.append("safety.unresolved must be empty")
    if target == "ANALYZING":
        rounds = status.get("rounds", [])
        if not any(record.get("state") == "COMPLETE" for record in rounds):
            missing.append("at least one complete round")
        if any(record.get("state") == "RUNNING" for record in rounds):
            missing.append("no round may remain RUNNING")
    if target in {"REVIEWED", "CLOSED"}:
        for round_record in status.get("rounds", []):
            missing.extend(attacks.gate_errors(ROOT, campaign_dir / "rounds" / round_record['id'], closure=True))
    if target == "REVIEWED":
        verdict = status.get("verdict", {})
        if verdict.get("result") not in {
            "PASS",
            "FAIL",
            "UNAVAILABLE",
            "NON_DISCRIMINATING",
        }:
            missing.append("verdict.result")
        reviewer = verdict.get("reviewer")
        if not reviewer:
            missing.append("verdict.reviewer")
        if reviewer and reviewer == status.get("roles", {}).get("campaign_lead"):
            missing.append("independent reviewer must differ from campaign lead")
        if not (campaign_dir / str(verdict.get("artifact", ""))).is_file():
            missing.append("verdict artifact")
    if target == "CLOSED":
        if status.get("safety", {}).get("cleanup") != "PASS":
            missing.append("safety.cleanup must be PASS")
        if status.get("safety", {}).get("unresolved"):
            missing.append("safety.unresolved must be empty")
        for round_record in status.get("rounds", []):
            if round_record.get("state") == "COMPLETE":
                manifest = (
                    campaign_dir
                    / "rounds"
                    / round_record["id"]
                    / "evidence"
                    / "manifest.yaml"
                )
                if not manifest.is_file():
                    missing.append(f"{round_record['id']} evidence manifest")
    return missing


@serialized
def cmd_campaign_transition(args: argparse.Namespace) -> int:
    try:
        validate_campaign_id(args.campaign_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    campaign_dir = CAMPAIGNS / args.campaign_id
    status_path = campaign_dir / "STATUS.yaml"
    if not status_path.is_file():
        print(f"FAIL: unknown campaign {args.campaign_id}", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if status.get("profile") != "workflow-v2":
        print("FAIL: migrated campaigns cannot use the v2 state machine", file=sys.stderr)
        return 1
    current = status.get("state")
    if args.target not in CAMPAIGN_STATES:
        print(f"FAIL: unknown campaign state {args.target}", file=sys.stderr)
        return 1
    if args.target not in CAMPAIGN_TRANSITIONS.get(current, set()) and not args.force:
        print(f"FAIL: transition {current} -> {args.target} is not allowed", file=sys.stderr)
        return 1
    if args.force and not args.approval_ref:
        print("FAIL: forced transition requires --approval-ref", file=sys.stderr)
        return 1
    if args.force and args.target in {"REVIEWED", "CLOSED"}:
        print("FAIL: --force cannot skip campaign verdict/cleanup prerequisites", file=sys.stderr)
        return 1
    try:
        apply_round_states(status, args.round_state)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for key, value in (
        ("image", args.image),
        ("digest", args.digest),
        ("embedded_git_sha", args.git_sha),
    ):
        if value:
            status["pins"][key] = value
    if args.positive_control:
        status["positive_control"] = args.positive_control
    if args.phase_approval_ref:
        status["safety"]["phase_approval_ref"] = args.phase_approval_ref
    if args.cleanup:
        status["safety"]["cleanup"] = args.cleanup
    if args.verdict:
        status["verdict"]["result"] = args.verdict
    if args.reviewer:
        status["verdict"]["reviewer"] = args.reviewer
        status["roles"]["independent_reviewer"] = args.reviewer
    if args.finding:
        known = set(status.get("findings", []))
        for intake_id in args.finding:
            try:
                validate_intake_id(intake_id)
            except ValueError as exc:
                print(f"FAIL: {exc}", file=sys.stderr)
                return 1
            if not (INTAKE / intake_id / "STATUS.yaml").is_file():
                print(f"FAIL: unknown intake finding {intake_id}", file=sys.stderr)
                return 1
            known.add(intake_id)
        status["findings"] = sorted(known)
    if args.target == "RUNNING" and status.get("scope", {}).get("permission") in {
        "controlled-mutation",
        "attack",
    }:
        if not args.phase_approval_ref:
            print("FAIL: mutating phase requires --phase-approval-ref", file=sys.stderr)
            return 1
    missing = [] if args.force else campaign_transition_prerequisites(
        campaign_dir, status, args.target
    )
    if missing:
        print("FAIL: transition prerequisites: " + "; ".join(missing), file=sys.stderr)
        return 1
    artifact = args.artifact
    if artifact and not re.match(r"^https?://", artifact):
        path = (campaign_dir / artifact).resolve()
        if campaign_dir.resolve() not in path.parents or not path.is_file():
            print(f"FAIL: missing/outside artifact {artifact}", file=sys.stderr)
            return 1
    now = utcnow()
    status.setdefault("transitions", []).append(
        {
            "from": current,
            "to": args.target,
            "at": now,
            "by": args.by,
            "artifact": artifact,
            "approval_ref": args.approval_ref,
            "phase_approval_ref": args.phase_approval_ref,
            "note": args.note,
            "forced": bool(args.force),
        }
    )
    status["state"] = args.target
    status["updated_at"] = now
    status["next_action"] = {
        "owner": args.next_owner,
        "action": args.next_action,
    }
    with workflow_lock(), workflow_transaction(
        [status_path, CAMPAIGNS / "INDEX.yaml"]
    ):
        write_yaml(status_path, status)
        write_campaign_index()
    print(f"{args.campaign_id}: {current} -> {args.target}")
    return 0


@serialized
def cmd_new_campaign_round(args: argparse.Namespace) -> int:
    try:
        validate_campaign_id(args.campaign_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if not re.fullmatch(r"round-[1-9]\d*", args.round_id):
        print("FAIL: round id must use round-N", file=sys.stderr)
        return 1
    campaign_dir = CAMPAIGNS / args.campaign_id
    status_path = campaign_dir / "STATUS.yaml"
    target = campaign_dir / "rounds" / args.round_id
    if not status_path.is_file() or target.exists():
        print("FAIL: unknown campaign or existing round", file=sys.stderr)
        return 1
    status = load_yaml(status_path)
    if status.get("profile") != "workflow-v2":
        print("FAIL: cannot extend a migrated campaign", file=sys.stderr)
        return 1
    source = CAMPAIGNS / "_template" / "rounds" / "round-1"
    try:
        with workflow_lock(), workflow_transaction([status_path], [target]):
            shutil.copytree(source, target)
            manifest_path = target / "evidence" / "manifest.yaml"
            manifest = load_yaml(manifest_path)
            manifest["subject"]["id"] = args.campaign_id
            write_yaml(manifest_path, manifest)
            status.setdefault("rounds", []).append(
                {"id": args.round_id, "state": "PLANNED"}
            )
            status["updated_at"] = utcnow()
            write_yaml(status_path, status)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"created campaigns/{args.campaign_id}/rounds/{args.round_id}")
    return 0


@serialized
def cmd_anatomy_refresh(args: argparse.Namespace) -> int:
    repo = Path(args.repo or ROOT.parent).resolve()
    if not (repo / ".git").exists() and not (repo / ".git").is_file():
        print(f"FAIL: not a Git worktree: {repo}", file=sys.stderr)
        return 1
    try:
        target = run_checked(["git", "-C", str(repo), "rev-parse", args.source_ref]).stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout, file=sys.stderr)
        return 1
    if args.publish:
        current_path = ROOT / "releases" / "CURRENT.yaml"
        current = load_yaml(current_path)
        deployed_ref = current.get("deployed", {}).get("embedded_git_sha")
        if not deployed_ref:
            print("FAIL: CURRENT.yaml has no observed deployed embedded_git_sha", file=sys.stderr)
            return 1
        try:
            deployed = run_checked(
                ["git", "-C", str(repo), "rev-parse", str(deployed_ref)]
            ).stdout.strip()
        except subprocess.CalledProcessError as exc:
            print(exc.stdout, file=sys.stderr)
            return 1
        if target != deployed:
            print(
                f"FAIL: refusing to publish anatomy for {target}; observed deployment is {deployed}",
                file=sys.stderr,
            )
            return 1

    with tempfile.TemporaryDirectory(prefix="phorvex-anatomy-") as td:
        temp = Path(td)
        source = temp / "source"
        workflow = temp / "workflow"
        try:
            run_checked(["git", "-C", str(repo), "worktree", "add", "--detach", str(source), target])
            shutil.copytree(
                ROOT,
                workflow,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".workflow.lock"),
            )
            pipeline = workflow / "anatomy" / "pipeline"
            pin_path = pipeline / "SOURCE_PIN.json"
            pin = json.loads(pin_path.read_text(encoding="utf-8"))
            same_source = pins_match(str(pin.get("commit", "")), target)
            if not same_source:
                pin["commit"] = target
            tag = subprocess.run(
                ["git", "-C", str(source), "describe", "--tags", "--exact-match", target],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if not same_source:
                pin["release"] = tag.stdout.strip() if tag.returncode == 0 else args.source_ref
                pin["frozen_at"] = "release-sync"
            if not same_source:
                pin_path.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")

            env = os.environ.copy()
            env["PHORVEX_CODE_REPO"] = str(source)
            commands = [
                ["bash", str(pipeline / "run_full_suite.sh")],
                [sys.executable, str(pipeline / "build_diagram_v2.py")],
                [sys.executable, str(pipeline / "build_svg.py")],
                [sys.executable, str(pipeline / "build_anatomy_doc.py")],
            ]
            for command in commands:
                result = run_checked(command, cwd=pipeline, env=env)
                if result.stdout:
                    print(result.stdout, end="")

            comparisons = [
                Path("anatomy/ANATOMY.md"),
                Path("anatomy/generated/ANATOMY.mmd"),
                Path("anatomy/generated/ANATOMY.svg"),
                Path("anatomy/pipeline/SOURCE_PIN.json"),
                Path("anatomy/pipeline/NODES.tsv"),
                Path("anatomy/pipeline/OPERATIONS_GEN.tsv"),
                Path("anatomy/pipeline/OPERATION_MATRIX.tsv"),
                Path("anatomy/pipeline/EFFECT_MATRIX.tsv"),
                Path("anatomy/pipeline/CALL_INVENTORY.json"),
                Path("anatomy/pipeline/packages.json"),
                Path("anatomy/pipeline/reference_census.json"),
            ]
            changed = []
            for rel in comparisons:
                old, new = ROOT / rel, workflow / rel
                if new.is_file() and (not old.is_file() or sha256(old) != sha256(new)):
                    changed.append(str(rel))
            print(f"anatomy suite: PASS at {target}")
            print("generated drift: " + (", ".join(changed) if changed else "none"))

            if not args.publish and changed:
                print(
                    "FAIL: generated anatomy differs from committed outputs",
                    file=sys.stderr,
                )
                return 1
            if args.publish:
                anatomy_pin_path = ROOT / "anatomy" / "PIN.yaml"
                joins_path = ISSUES / "joins.yaml"
                master_path = ISSUES / "MASTER_ISSUES.md"
                sync_status_path: Path | None = None
                sync_record = current.get("deployed", {}).get("sync_record")
                if sync_record:
                    candidate = (ROOT / str(sync_record)).resolve()
                    if ROOT.resolve() in candidate.parents and candidate.is_file():
                        sync_status_path = candidate
                publish_paths = [
                    *[ROOT / rel for rel in comparisons],
                    anatomy_pin_path,
                    joins_path,
                    master_path,
                    current_path,
                ]
                if sync_status_path:
                    publish_paths.append(sync_status_path)
                with workflow_lock(), workflow_transaction(publish_paths):
                    for rel in comparisons:
                        src, dst = workflow / rel, ROOT / rel
                        if src.is_file():
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            temp_dst = dst.with_suffix(dst.suffix + ".tmp")
                            shutil.copy2(src, temp_dst)
                            temp_dst.replace(dst)
                    anatomy_pin = load_yaml(anatomy_pin_path)
                    anatomy_pin["anatomy"]["source_commit"] = target
                    anatomy_pin["anatomy"]["source_release"] = pin["release"]
                    anatomy_pin["anatomy"]["frozen_at_bus"] = None
                    anatomy_pin["anatomy"]["migration_status"] = "release-sync-published"
                    anatomy_pin["currency"] = {
                        "status": "validated_for_source",
                        "reason": f"Full anatomy audit suite passed at {target}.",
                    }
                    write_yaml(anatomy_pin_path, anatomy_pin)
                    joins_doc = load_yaml(joins_path) or {}
                    prior_pin = joins_doc.get("anatomy_pin")
                    joins_doc["anatomy_pin"] = target
                    if not pins_match(str(prior_pin or ""), target):
                        for join in joins_doc.get("joins", {}).values():
                            if join.get("kind") != "CLOSED":
                                join["review"] = "required"
                                join["review_reason"] = "Source changed; revalidate locus before using it as authority."
                    write_yaml(joins_path, joins_doc)
                    current["recorded_at"] = utcnow()
                    current["anatomy"] = {
                        "source_commit": target,
                        "current_for_deployed_release": True,
                        "refresh_status": "PASS",
                    }
                    write_yaml(current_path, current)
                    if sync_status_path:
                        release_status = load_yaml(sync_status_path)
                        prior = release_status.get("state")
                        if prior == "DEPLOY_OBSERVED":
                            now = utcnow()
                            release_status["state"] = "ANATOMY_PUBLISHED"
                            release_status["updated_at"] = now
                            release_status["anatomy"] = {
                                "source_commit": target,
                                "status": "PASS",
                            }
                            release_status.setdefault("transitions", []).append(
                                {
                                    "from": prior,
                                    "to": "ANATOMY_PUBLISHED",
                                    "at": now,
                                    "by": "anatomy-refresh",
                                    "artifact": "anatomy/PIN.yaml",
                                }
                            )
                            write_yaml(sync_status_path, release_status)
                    write_text(master_path, render_master())
                print("published validated anatomy outputs and pin")
        except (subprocess.CalledProcessError, OSError, ValueError) as exc:
            detail = (
                exc.stdout
                if isinstance(exc, subprocess.CalledProcessError)
                else str(exc)
            )
            print(detail or str(exc), file=sys.stderr)
            print(f"FAIL: anatomy suite at {target}", file=sys.stderr)
            return 1
        finally:
            if source.exists():
                subprocess.run(
                    ["git", "-C", str(repo), "worktree", "remove", "--force", str(source)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
    return 0


def validate_schema_instance(
    schema_name: str,
    instance: Any,
    label: str,
    errors: list[str],
) -> None:
    schema_path = ROOT / "schemas" / schema_name
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.path) or "<root>"
            errors.append(f"{label}: schema {location}: {error.message}")
    except Exception as exc:
        errors.append(f"{label}: schema validation failed: {exc}")


def validate_typed_evidence(
    manifest_path: Path,
    *,
    record_root: Path,
    expected_kind: str,
    expected_id: str,
    errors: list[str],
    warnings: list[str],
    deep: bool,
    hash_cache: dict[Path, str],
) -> None:
    label = str(manifest_path.relative_to(ROOT))
    if not manifest_path.is_file():
        errors.append(f"{label}: missing evidence manifest")
        return
    manifest = load_yaml(manifest_path) or {}
    validate_schema_instance(
        "evidence-manifest.schema.json", manifest, label, errors
    )
    version = manifest.get("schema_version")
    if version == 1:
        if expected_kind != "fix" or manifest.get("fix_id") != expected_id:
            errors.append(f"{label}: v1 evidence owner mismatch")
    elif version == 2:
        subject = manifest.get("subject", {})
        if subject != {"kind": expected_kind, "id": expected_id}:
            errors.append(
                f"{label}: subject mismatch; expected {expected_kind}:{expected_id}"
            )
    seen: set[str] = set()
    for artifact in manifest.get("artifacts", []):
        artifact_id = artifact.get("id")
        if not artifact_id or artifact_id in seen:
            errors.append(f"{label}: duplicate/empty artifact id {artifact_id!r}")
        seen.add(artifact_id)
        retention = artifact.get("retention")
        source_path: Path | None = None
        if retention == "git":
            candidate = (record_root / str(artifact.get("path", ""))).resolve()
            if record_root.resolve() not in candidate.parents:
                errors.append(f"{label}: artifact escapes record root {artifact_id!r}")
                continue
            source_path = candidate
            if not source_path.is_file():
                errors.append(f"{label}: missing artifact {artifact.get('path')}")
                continue
        elif retention == "local-original":
            if not artifact.get("local_source"):
                errors.append(f"{label}: local-original lacks local_source {artifact_id!r}")
                continue
            source_path = Path(str(artifact["local_source"]))
            if not source_path.is_file():
                warnings.append(f"{label}: local-original unavailable {artifact_id!r}")
                continue
        elif retention == "artifact-store":
            continue
        else:
            errors.append(f"{label}: unknown retention {retention!r}")
            continue
        if source_path.stat().st_size != artifact.get("bytes"):
            errors.append(f"{label}: byte-count mismatch {artifact_id!r}")
        if retention == "git" or deep:
            actual = hash_cache.setdefault(source_path, sha256(source_path))
            if actual != artifact.get("sha256"):
                errors.append(f"{label}: hash mismatch {artifact_id!r}")


def cmd_doctor(args: argparse.Namespace) -> int:
    errors: list[str] = []
    warnings: list[str] = []
    local_hash_cache: dict[Path, str] = {}
    errors.extend(attacks.validate_catalogue(ROOT))

    required = [
        ROOT / "AGENTS.md",
        ROOT / "README.md",
        ROOT / "OPERATIONS.md",
        ROOT / "WORKFLOW.md",
        ROOT / "MANIFEST.yaml",
        OPERATIONS / "POLICY.yaml",
        INTAKE / "INDEX.yaml",
        ISSUES / "MASTER_ISSUES.md",
        ISSUES / "joins.yaml",
        ISSUES / "NEXT_ID",
        FIXES / "INDEX.yaml",
        ROOT / "anatomy" / "ANATOMY.md",
        ROOT / "anatomy" / "PIN.yaml",
        ROOT / "releases" / "CURRENT.yaml",
        CAMPAIGNS / "INDEX.yaml",
    ]
    for path in required:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")

    try:
        policy = load_yaml(OPERATIONS / "POLICY.yaml") or {}
        validate_schema_instance(
            "operations-policy.schema.json",
            policy,
            "operations/POLICY.yaml",
            errors,
        )
        manifest = load_yaml(ROOT / "MANIFEST.yaml") or {}
        manifest_operations = manifest.get("operations", {})
        for operation, record in policy.get("operations", {}).items():
            runbook = ROOT / str(record.get("runbook", ""))
            if not runbook.is_file():
                errors.append(f"operation {operation}: missing runbook {record.get('runbook')}")
            if manifest_operations.get(operation) != record.get("runbook"):
                errors.append(f"operation {operation}: MANIFEST/POLICY runbook mismatch")
    except Exception as exc:
        errors.append(f"operations policy: {exc}")

    try:
        base, metadata, tokens = render_base()
        if len(tokens) != len(metadata):
            errors.append("issue entry/token cardinality mismatch")
        entry_files = sorted((ISSUES / "entries").glob("M-*.md"))
        entry_ids = {parse_entry(path)[0].get("id") for path in entry_files}
        if entry_ids != set(tokens):
            errors.append("issue entry files and layout tokens are not a bijection")
        for issue_id, entry in metadata.items():
            validate_schema_instance(
                "issue-entry.schema.json",
                entry,
                f"issues/entries/{pad_issue(issue_id)}.md",
                errors,
            )
            if entry.get("workflow_state") not in ISSUE_STATES:
                errors.append(
                    f"{issue_id}: unknown issue state {entry.get('workflow_state')!r}"
                )
            migrated = entry.get("migration_body_sha256") is not None
            if migrated and entry.get("migration_review") != "complete":
                errors.append(f"{issue_id}: migration metadata review is incomplete")
            if not migrated and entry.get("migration_review") != "not-applicable":
                errors.append(f"{issue_id}: new issue has invalid migration metadata")
        master = render_master()
        master_path = ISSUES / "MASTER_ISSUES.md"
        if master_path.exists() and master_path.read_text(encoding="utf-8") != master:
            errors.append("issues/MASTER_ISSUES.md is stale")
        legacy = ROOT / "archive" / "register-v1" / "PHORVEX_MASTER_ISSUES.md"
        if legacy.is_file():
            legacy_layout, legacy_entries, legacy_order = split_legacy_register(
                legacy.read_text(encoding="utf-8")
            )
            current_layout = (ISSUES / "layout.md").read_text(encoding="utf-8")
            if not current_layout.startswith(legacy_layout):
                errors.append("migrated issue layout prefix differs from the base register")
            if tokens[: len(legacy_order)] != legacy_order:
                errors.append("migrated issue token order differs from the base register")
            for issue_id, legacy_body in legacy_entries.items():
                expected = hashlib.sha256(legacy_body.encode("utf-8")).hexdigest()
                if metadata[issue_id].get("migration_body_sha256") != expected:
                    errors.append(f"{issue_id}: migrated-body provenance hash mismatch")
        next_id = int((ISSUES / "NEXT_ID").read_text(encoding="utf-8").strip())
        maximum = max(int(issue_id.split("-")[1]) for issue_id in metadata)
        if next_id <= maximum:
            errors.append(
                f"issues/NEXT_ID={next_id} must be greater than maximum M-{maximum}"
            )
    except Exception as exc:
        errors.append(f"issue render: {exc}")

    try:
        index = load_yaml(FIXES / "INDEX.yaml") or {}
        fixes = index.get("fixes", {})
        if index != synchronized_index(index):
            errors.append("fixes/INDEX.yaml projections are stale")
        stale_issue_links = sync_issue_fix_links(index, check=True)
        if stale_issue_links:
            errors.append(
                "issue-to-fix links are stale: " + ", ".join(stale_issue_links)
            )
        for fix_id, record in fixes.items():
            status_path = FIXES / fix_id / "STATUS.yaml"
            if not status_path.is_file():
                errors.append(f"{fix_id}: missing STATUS.yaml")
                continue
            status = load_yaml(status_path) or {}
            validate_schema_instance(
                "fix-status.schema.json",
                status,
                f"fixes/{fix_id}/STATUS.yaml",
                errors,
            )
            if status.get("fix_id") != fix_id:
                errors.append(f"{fix_id}: status fix_id mismatch")
            if status.get("state") not in ALLOWED_STATES:
                errors.append(f"{fix_id}: unknown state {status.get('state')!r}")
            required_roles = {
                "human_owner",
                "proposer",
                "implementer",
                "skeptic",
                "live_verifier",
                "coordinator",
            }
            roles = status.get("roles", {})
            missing_roles = sorted(
                role for role in required_roles if not roles.get(role)
            )
            if missing_roles:
                errors.append(f"{fix_id}: missing role assignments {missing_roles}")
            if status.get("profile") != "legacy-migrated":
                for failure in gates.prerequisites(ROOT, status_path.parent, status, status.get("state")):
                    errors.append(f"{fix_id}: {failure}")
                for key in status.get("checks", {}):
                    if key not in gates.CHECK_ROLES:
                        errors.append(f"{fix_id}: unknown check {key}")
                    elif status["checks"][key].get("result") in {"PASS", "NOT_REQUIRED"}:
                        for failure in gates.check_errors(ROOT, status_path.parent, status, key):
                            errors.append(f"{fix_id}: {failure}")
            implementation = status.get("implementation", {})
            if not isinstance(implementation.get("stacked_on"), list):
                errors.append(f"{fix_id}: implementation.stacked_on must be a list")
            if not isinstance(status.get("verification", {}).get("required"), list):
                errors.append(f"{fix_id}: verification.required must be a list")
            action = status.get("next_action", {}).get("action")
            if not action:
                errors.append(f"{fix_id}: no next action")
            if record.get("state") != status.get("state"):
                errors.append(f"{fix_id}: index/status state mismatch")
            for dep in record.get("dependencies", []) + record.get("stacked_on", []):
                if dep not in fixes:
                    errors.append(f"{fix_id}: unknown dependency {dep}")
            if status.get("state") == "PR_READY" and status.get("verification", {}).get("p3") != "PASS":
                errors.append(f"{fix_id}: PR_READY without P3 PASS")
            if status.get("state") == "PR_READY" and not (
                FIXES / fix_id / "evidence" / "p3" / "verdict.md"
            ).is_file():
                errors.append(f"{fix_id}: PR_READY without evidence/p3/verdict.md")
            if status.get("state") == "PR_READY" and (FIXES / fix_id / "06-verdict.md").is_file():
                if status.get("profile") == "legacy-migrated":
                    warnings.append(
                        f"{fix_id}: legacy 06-verdict.md is P3-only; it is not final closure"
                    )
                else:
                    errors.append(f"{fix_id}: PR_READY cycle has a premature final 06-verdict.md")
            manifest_path = FIXES / fix_id / "evidence" / "manifest.yaml"
            if not manifest_path.is_file():
                errors.append(f"{fix_id}: missing evidence/manifest.yaml")
            else:
                manifest = load_yaml(manifest_path) or {}
                validate_schema_instance("evidence-manifest.schema.json", manifest,
                                         f"fixes/{fix_id}/evidence/manifest.yaml", errors)
                if manifest.get("fix_id") != fix_id:
                    errors.append(f"{fix_id}: evidence manifest fix_id mismatch")
                seen_artifacts: set[str] = set()
                for artifact in manifest.get("artifacts", []):
                    artifact_id = artifact.get("id")
                    if not artifact_id or artifact_id in seen_artifacts:
                        errors.append(f"{fix_id}: duplicate/empty evidence artifact id {artifact_id!r}")
                    seen_artifacts.add(artifact_id)
                    if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
                        errors.append(f"{fix_id}: invalid evidence SHA-256 {artifact_id!r}")
                    if not isinstance(artifact.get("bytes"), int) or artifact.get("bytes") < 0:
                        errors.append(f"{fix_id}: invalid evidence byte count {artifact_id!r}")
                    retention = artifact.get("retention")
                    if retention == "local-original":
                        source_value = artifact.get("local_source")
                        if not source_value:
                            errors.append(
                                f"{fix_id}: local-original artifact lacks local_source "
                                f"{artifact.get('path')}"
                            )
                            continue
                        source_path = Path(str(source_value))
                        if not source_path.is_file():
                            warnings.append(
                                f"{fix_id}: local-original evidence unavailable "
                                f"{artifact.get('path')}"
                            )
                            continue
                        if source_path.stat().st_size != artifact.get("bytes"):
                            errors.append(
                                f"{fix_id}: local-original size mismatch {artifact.get('path')}"
                            )
                        if args.deep_evidence:
                            actual = local_hash_cache.setdefault(source_path, sha256(source_path))
                            if actual != artifact.get("sha256"):
                                errors.append(
                                    f"{fix_id}: local-original hash mismatch {artifact.get('path')}"
                                )
                        continue
                    if retention == "artifact-store":
                        continue
                    if retention != "git":
                        errors.append(
                            f"{fix_id}: unknown evidence retention {retention!r}"
                        )
                        continue
                    artifact_path = FIXES / fix_id / str(artifact.get("path", ""))
                    if not artifact_path.is_file():
                        errors.append(f"{fix_id}: missing evidence artifact {artifact.get('path')}")
                        continue
                    if artifact_path.stat().st_size != artifact.get("bytes"):
                        errors.append(f"{fix_id}: evidence size mismatch {artifact.get('path')}")
                    if sha256(artifact_path) != artifact.get("sha256"):
                        errors.append(f"{fix_id}: evidence hash mismatch {artifact.get('path')}")
            if status.get("profile") == "legacy-migrated" and not (FIXES / fix_id / "verify.sh").is_file():
                warnings.append(f"{fix_id}: legacy record lacks verify.sh")
    except Exception as exc:
        errors.append(f"fix index: {exc}")

    try:
        _, issue_metadata, _ = render_base()
        fix_index = (load_yaml(FIXES / "INDEX.yaml") or {}).get("fixes", {})
        for issue_id, entry in issue_metadata.items():
            linked = [fix_index[fix_id] for fix_id in entry.get("fixes", []) if fix_id in fix_index]
            linked_states = {record.get("state") for record in linked}
            issue_state = entry.get("workflow_state")
            if issue_state == "CLOSED" and linked_states & {"REOPENED", "INVALIDATED"}:
                errors.append(
                    f"{issue_id}: CLOSED while a linked fix is reopened/invalidated"
                )
            if issue_state == "MAIN_PENDING_DEPLOY" and linked and not (
                linked_states
                & {
                    "MERGED",
                    "DEPLOYED",
                    "LIVE_VERIFIED",
                    "SYNCHRONIZED",
                    "CLOSED",
                }
            ):
                warnings.append(
                    f"{issue_id}: main-pending state is ahead of all linked fix records"
                )
            if issue_state == "DEPLOYED_PENDING_L3" and linked and not (
                linked_states
                & {"DEPLOYED", "LIVE_VERIFIED", "SYNCHRONIZED", "CLOSED"}
            ):
                warnings.append(
                    f"{issue_id}: deployed state is ahead of all linked fix records"
                )
    except Exception as exc:
        errors.append(f"issue/fix state synchronization: {exc}")

    try:
        for path in sorted((ISSUES / "entries").glob("M-*.md")):
            metadata, _ = parse_entry(path)
            for transition in metadata.get("transitions", []) or []:
                source_state = transition.get("from")
                target_state = transition.get("to")
                allowed = target_state in ISSUE_TRANSITIONS.get(source_state, set())
                if not allowed and not transition.get("forced"):
                    errors.append(
                        f"{metadata.get('id')}: invalid recorded issue transition "
                        f"{source_state} -> {target_state}"
                    )
        for status_path in sorted(FIXES.glob("*/STATUS.yaml")):
            if status_path.parent.name == "_template":
                continue
            status = load_yaml(status_path) or {}
            for transition in status.get("transitions", []) or []:
                source_state = transition.get("from")
                target_state = transition.get("to")
                allowed = target_state in TRANSITIONS.get(source_state, set())
                if not allowed and not transition.get("forced"):
                    errors.append(
                        f"{status.get('fix_id')}: invalid recorded fix transition "
                        f"{source_state} -> {target_state}"
                    )
    except Exception as exc:
        errors.append(f"recorded transitions: {exc}")

    try:
        intake_index_path = INTAKE / "INDEX.yaml"
        intake_index = load_yaml(intake_index_path) or {}
        expected_intake_index = synchronized_intake_index(intake_index)
        if intake_index != expected_intake_index:
            errors.append("intake/INDEX.yaml projection is stale")
        for intake_id, record in expected_intake_index.get("intakes", {}).items():
            status_path = INTAKE / intake_id / "STATUS.yaml"
            status = load_yaml(status_path) or {}
            validate_schema_instance(
                "intake-status.schema.json",
                status,
                f"intake/{intake_id}/STATUS.yaml",
                errors,
            )
            if status.get("intake_id") != intake_id:
                errors.append(f"{intake_id}: intake_id/status directory mismatch")
            if status.get("state") not in INTAKE_STATES:
                errors.append(f"{intake_id}: unknown intake state {status.get('state')!r}")
            if not status.get("next_action", {}).get("action"):
                errors.append(f"{intake_id}: missing next action")
            for transition in status.get("transitions", []):
                source_state = transition.get("from")
                target_state = transition.get("to")
                allowed = target_state in INTAKE_TRANSITIONS.get(source_state, set())
                promoted = target_state == "FILED" and source_state in {
                    "DEDUP_REVIEW",
                    "NEEDS_DEDUP_RULING",
                }
                if not allowed and not promoted and not transition.get("forced"):
                    errors.append(
                        f"{intake_id}: invalid recorded transition "
                        f"{source_state} -> {target_state}"
                    )
            promotion = status.get("promotion", {})
            if status.get("state") == "FILED":
                issue_id = promotion.get("issue_id")
                issue_path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
                if not issue_id or not issue_path.is_file():
                    errors.append(f"{intake_id}: FILED without canonical issue")
                elif parse_entry(issue_path)[0].get("intake_id") != intake_id:
                    errors.append(f"{intake_id}: promoted issue backlink mismatch")
            if status.get("state") == "DUPLICATE":
                issue_id = status.get("dedup", {}).get("issue_id")
                if not issue_id or not (
                    ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
                ).is_file():
                    errors.append(f"{intake_id}: DUPLICATE without existing issue")
            validate_typed_evidence(
                INTAKE / intake_id / "evidence" / "manifest.yaml",
                record_root=INTAKE / intake_id,
                expected_kind="intake",
                expected_id=intake_id,
                errors=errors,
                warnings=warnings,
                deep=args.deep_evidence,
                hash_cache=local_hash_cache,
            )
    except Exception as exc:
        errors.append(f"intake index: {exc}")

    try:
        campaign_index_path = CAMPAIGNS / "INDEX.yaml"
        campaign_index = load_yaml(campaign_index_path) or {}
        expected_campaign_index = synchronized_campaign_index(campaign_index)
        if campaign_index != expected_campaign_index:
            errors.append("campaigns/INDEX.yaml projection is stale")
        for campaign_id, record in expected_campaign_index.get("campaigns", {}).items():
            campaign_dir = CAMPAIGNS / campaign_id
            status = load_yaml(campaign_dir / "STATUS.yaml") or {}
            if record.get("profile") == "legacy-migrated":
                if not status.get("migration", {}).get("historical"):
                    errors.append(f"{campaign_id}: legacy profile lacks historical marker")
                continue
            validate_schema_instance(
                "campaign-status.schema.json",
                status,
                f"campaigns/{campaign_id}/STATUS.yaml",
                errors,
            )
            if status.get("campaign_id") != campaign_id:
                errors.append(f"{campaign_id}: campaign_id/status directory mismatch")
            required_campaign_files = [
                campaign_dir / "CAMPAIGN.md",
                campaign_dir / "hypotheses.yaml",
                campaign_dir / "verdict.md",
            ]
            for required_path in required_campaign_files:
                if not required_path.is_file():
                    errors.append(
                        f"{campaign_id}: missing {required_path.relative_to(campaign_dir)}"
                    )
            if status.get("state") == "CLOSED":
                if status.get("safety", {}).get("cleanup") != "PASS":
                    errors.append(f"{campaign_id}: CLOSED without cleanup PASS")
                if status.get("safety", {}).get("unresolved"):
                    errors.append(f"{campaign_id}: CLOSED with unresolved safety items")
            for round_record in status.get("rounds", []):
                round_id = round_record.get("id")
                round_dir = campaign_dir / "rounds" / str(round_id)
                validate_typed_evidence(
                    round_dir / "evidence" / "manifest.yaml",
                    record_root=round_dir,
                    expected_kind="campaign",
                    expected_id=campaign_id,
                    errors=errors,
                    warnings=warnings,
                    deep=args.deep_evidence,
                    hash_cache=local_hash_cache,
                )
    except Exception as exc:
        errors.append(f"campaign index: {exc}")

    try:
        for status_path in sorted(RELEASES.glob("*/STATUS.yaml")):
            if status_path.parent.name == "_template":
                continue
            sync_id = status_path.parent.name
            if not re.fullmatch(
                r"(?:MAIN|DEPLOY)-\d{8}-\d{6}-[a-f0-9]{7,40}", sync_id
            ):
                continue
            status = load_yaml(status_path) or {}
            validate_schema_instance(
                "release-sync.schema.json",
                status,
                f"releases/{sync_id}/STATUS.yaml",
                errors,
            )
            if status.get("sync_id") != sync_id:
                errors.append(f"{sync_id}: sync_id/status directory mismatch")
            validate_typed_evidence(
                status_path.parent / "evidence" / "manifest.yaml",
                record_root=status_path.parent,
                expected_kind="release",
                expected_id=sync_id,
                errors=errors,
                warnings=warnings,
                deep=args.deep_evidence,
                hash_cache=local_hash_cache,
            )
        current = load_yaml(RELEASES / "CURRENT.yaml") or {}
        sync_record = current.get("deployed", {}).get("sync_record")
        if sync_record and not (ROOT / str(sync_record)).is_file():
            errors.append("CURRENT.yaml deployed.sync_record is missing")
        repo = ROOT.parent
        observed_main = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "origin/main"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if observed_main.returncode == 0:
            local_main = observed_main.stdout.strip()
            recorded_main = str(
                current.get("code_repository", {}).get("origin_main_sha", "")
            )
            if recorded_main and local_main != recorded_main:
                warnings.append(
                    f"origin/main advanced to {local_main[:12]}; sync-main is required"
                )
    except Exception as exc:
        errors.append(f"release records: {exc}")

    legacy_manifest_path = ROOT / "artifacts" / "legacy-manifest.yaml"
    if legacy_manifest_path.is_file():
        legacy_manifest = load_yaml(legacy_manifest_path) or {}
        seen_logical: set[str] = set()
        unavailable_local = 0
        for artifact in legacy_manifest.get("artifacts", []):
            logical = artifact.get("logical_path")
            if not logical or logical in seen_logical:
                errors.append(f"legacy manifest duplicate/empty logical path: {logical!r}")
            seen_logical.add(logical)
            if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
                errors.append(f"legacy manifest invalid SHA-256: {logical}")
            if not isinstance(artifact.get("bytes"), int) or artifact.get("bytes") < 0:
                errors.append(f"legacy manifest invalid byte count: {logical}")
            source_value = artifact.get("local_source")
            if not source_value:
                errors.append(f"legacy manifest entry lacks local_source: {logical}")
                continue
            source_path = Path(str(source_value))
            if not source_path.is_file():
                unavailable_local += 1
                continue
            if source_path.stat().st_size != artifact.get("bytes"):
                errors.append(f"legacy manifest size mismatch: {logical}")
            if args.deep_evidence:
                actual = local_hash_cache.setdefault(source_path, sha256(source_path))
                if actual != artifact.get("sha256"):
                    errors.append(f"legacy manifest hash mismatch: {logical}")
        if unavailable_local:
            warnings.append(
                f"{unavailable_local} local-original artifact(s) are unavailable in this clone"
            )

        campaign_prefix = (
            "campaigns/2026-08-25-live-validation/round-1/evidence/"
        )
        expected_campaign = {
            artifact["logical_path"][len(campaign_prefix) :]: artifact["sha256"]
            for artifact in legacy_manifest.get("artifacts", [])
            if artifact.get("logical_path", "").startswith(campaign_prefix)
        }
        campaign_manifest_path = (
            ROOT
            / "campaigns"
            / "2026-08-25-live-validation"
            / "round-1"
            / "evidence"
            / "manifest.yaml"
        )
        if expected_campaign:
            if not campaign_manifest_path.is_file():
                errors.append("historical campaign evidence manifest is missing")
            else:
                campaign_manifest = load_yaml(campaign_manifest_path) or {}
                campaign_evidence_root = campaign_manifest_path.parent
                for artifact in campaign_manifest.get("artifacts", []):
                    if artifact.get("retention") != "git":
                        continue
                    artifact_path = (
                        campaign_evidence_root / str(artifact.get("path", ""))
                    ).resolve()
                    if (
                        campaign_evidence_root.resolve() not in artifact_path.parents
                        or not artifact_path.is_file()
                    ):
                        errors.append(
                            f"campaign evidence missing/outside root: {artifact.get('path')}"
                        )
                        continue
                    if artifact_path.stat().st_size != artifact.get("bytes"):
                        errors.append(
                            f"campaign evidence size mismatch: {artifact.get('path')}"
                        )
                    if sha256(artifact_path) != artifact.get("sha256"):
                        errors.append(
                            f"campaign evidence hash mismatch: {artifact.get('path')}"
                        )
                actual_campaign = {
                    artifact.get("path"): artifact.get("sha256")
                    for artifact in campaign_manifest.get("artifacts", [])
                    if artifact.get("retention") == "local-original"
                }
                if actual_campaign != expected_campaign:
                    errors.append(
                        "campaign local-original manifest does not match global legacy manifest"
                    )

    pin_path = ROOT / "anatomy" / "PIN.yaml"
    source_pin = ROOT / "anatomy" / "pipeline" / "SOURCE_PIN.json"
    if pin_path.is_file() and source_pin.is_file():
        pin = load_yaml(pin_path)
        source = json.loads(source_pin.read_text(encoding="utf-8"))
        if not pins_match(str(source.get("commit", "")), str(pin["anatomy"]["source_commit"])):
            errors.append("anatomy PIN.yaml and pipeline/SOURCE_PIN.json disagree")
        joins_doc = load_yaml(ISSUES / "joins.yaml") or {}
        if not pins_match(
            str(pin["anatomy"]["source_commit"]),
            str(joins_doc.get("anatomy_pin", "")),
        ):
            errors.append("issues/joins.yaml and anatomy/PIN.yaml disagree")
        incomplete_legacy_joins = [
            issue_id
            for issue_id, join in joins_doc.get("joins", {}).items()
            if join.get("migration_source") == "legacy-v2-projection"
            and join.get("review") != "complete"
        ]
        if incomplete_legacy_joins:
            warnings.append(
                f"{len(incomplete_legacy_joins)} historical anatomy join(s) need semantic review"
            )
        pending_new_joins = [
            issue_id
            for issue_id, join in joins_doc.get("joins", {}).items()
            if join.get("source") == "workflow-v2-filing"
            and join.get("review") != "complete"
        ]
        if pending_new_joins:
            warnings.append(
                f"{len(pending_new_joins)} newly filed issue(s) await anatomy join review"
            )

        current_path = ROOT / "releases" / "CURRENT.yaml"
        if current_path.is_file():
            current = load_yaml(current_path)
            deployed = str(current.get("deployed", {}).get("embedded_git_sha", ""))
            anatomy_source = str(pin["anatomy"]["source_commit"])
            current_claim = bool(
                current.get("anatomy", {}).get("current_for_deployed_release")
            )
            current_match = pins_match(deployed, anatomy_source)
            if current_claim and not current_match:
                errors.append(
                    "CURRENT.yaml claims anatomy is current but deployed/anatomy pins differ"
                )
            elif not current_match:
                warnings.append(
                    "anatomy is stale relative to the observed deployed source; release sync required"
                )

    for path in ROOT.rglob("*"):
        if path.is_file() and path.stat().st_size > 50 * 1024 * 1024:
            errors.append(f"oversized tracked candidate: {path.relative_to(ROOT)}")

    print(f"doctor: {len(errors)} error(s), {len(warnings)} warning(s)")
    for warning in warnings:
        print(f"WARN: {warning}")
    for error in errors:
        print(f"FAIL: {error}")
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    attacks.register(sub, globals())

    doctor = sub.add_parser("doctor", help="validate workflow integrity")
    doctor.add_argument(
        "--deep-evidence",
        action="store_true",
        help="also SHA-256 local-original evidence when it is available",
    )
    doctor.set_defaults(func=cmd_doctor)

    guide = sub.add_parser("guide", help="show the bounded runbook for an operation")
    guide.add_argument(
        "operation",
        choices=["fix", "intake", "issue", "sync", "campaign", "audit", "triage"],
    )
    guide.add_argument("--show", action="store_true", help="also print the runbook")
    guide.set_defaults(func=cmd_guide)

    brief = sub.add_parser("brief", help="show bounded context for an issue/fix")
    brief.add_argument("identifier")
    brief.add_argument("--agent", help="emit a bounded, blind-safe role packet")
    brief.set_defaults(func=cmd_brief)

    intake = sub.add_parser(
        "new-intake",
        aliases=["report-bug"],
        help="create a non-canonical reported finding",
    )
    intake.add_argument("title")
    intake.add_argument("--kind", choices=sorted(INTAKE_KINDS), default="BUG")
    intake.add_argument("--reporter", required=True)
    intake.add_argument("--approval-ref")
    intake.add_argument("--id", dest="intake_id")
    intake.add_argument("--claim")
    intake.add_argument("--report-file")
    intake.add_argument("--source-main-sha")
    intake.add_argument("--source-release")
    intake.add_argument("--deployed-image")
    intake.add_argument("--deployed-digest")
    intake.add_argument("--deployed-git-sha")
    intake.add_argument("--environment")
    intake.add_argument("--investigator")
    intake.add_argument("--coordinator")
    intake.set_defaults(func=cmd_new_intake)

    intake_transition = sub.add_parser(
        "intake-transition", help="perform a validated intake-state transition"
    )
    intake_transition.add_argument("intake_id")
    intake_transition.add_argument("target")
    intake_transition.add_argument("--by", required=True)
    intake_transition.add_argument("--next-owner", required=True)
    intake_transition.add_argument("--next-action", required=True)
    intake_transition.add_argument("--artifact")
    intake_transition.add_argument("--note")
    intake_transition.add_argument("--approval-ref")
    intake_transition.add_argument(
        "--verification-result",
        choices=["PASS", "FAIL", "UNAVAILABLE", "NON_DISCRIMINATING", "BLOCKED"],
    )
    intake_transition.add_argument(
        "--positive-control", choices=["PASS", "NOT_REQUIRED", "FAIL", "UNAVAILABLE"]
    )
    intake_transition.add_argument("--force", action="store_true")
    intake_transition.set_defaults(func=cmd_intake_transition)

    dedup = sub.add_parser(
        "dedup-intake", help="rank and record possible duplicate issues"
    )
    dedup.add_argument("intake_id")
    dedup.add_argument("--limit", type=int, default=10)
    dedup.add_argument("--record", action="store_true")
    dedup.add_argument(
        "--determination", choices=["NEW", "DUPLICATE", "AMBIGUOUS"]
    )
    dedup.add_argument("--issue")
    dedup.add_argument("--human-ruling-ref")
    dedup.set_defaults(func=cmd_dedup_intake)

    issue = sub.add_parser("new-issue", help="file a new canonical M-issue")
    issue.add_argument("title")
    issue.add_argument("--severity", required=True)
    issue.add_argument("--anatomy-tag", required=True)
    issue.add_argument("--kind", choices=sorted(INTAKE_KINDS), default="BUG")
    issue.add_argument("--approval-ref", required=True)
    issue.add_argument("--intake-id")
    issue.add_argument("--claim")
    issue.add_argument("--evidence")
    issue.add_argument("--required-correction")
    issue.add_argument("--repo")
    issue.add_argument("--source-ref", default="origin/main")
    issue.set_defaults(func=cmd_new_issue)

    issue_transition = sub.add_parser(
        "issue-transition", help="perform a validated issue-state transition"
    )
    issue_transition.add_argument("issue_id")
    issue_transition.add_argument("target")
    issue_transition.add_argument("--by", required=True)
    issue_transition.add_argument("--source", required=True)
    issue_transition.add_argument("--artifact")
    issue_transition.add_argument("--note")
    issue_transition.add_argument("--approval-ref")
    issue_transition.add_argument("--force", action="store_true")
    issue_transition.set_defaults(func=cmd_issue_transition)

    promote = sub.add_parser(
        "promote-intake", help="promote a verified new intake to an M-issue"
    )
    promote.add_argument("intake_id")
    promote.add_argument("--severity", required=True)
    promote.add_argument("--anatomy-tag", required=True)
    promote.add_argument("--approval-ref", required=True)
    promote.add_argument("--human-ruling-ref")
    promote.add_argument("--by", required=True)
    promote.add_argument("--claim")
    promote.add_argument("--evidence")
    promote.add_argument("--required-correction")
    promote.add_argument("--start-fix")
    promote.add_argument("--fix-title")
    promote.add_argument("--repo")
    promote.add_argument("--source-ref", default="origin/main")
    promote.set_defaults(func=cmd_promote_intake)

    seal = sub.add_parser("seal", help="seal a skeptic blind derivation")
    seal.add_argument("fix_id")
    seal.add_argument("--by", required=True)
    seal.add_argument("--expect-revision", type=int, required=True)
    seal.add_argument("--force", action="store_true")
    seal.add_argument("--approval-ref")
    seal.set_defaults(func=cmd_seal)

    new = sub.add_parser("new-fix", help="create a fix from the template")
    new.add_argument("fix_id")
    new.add_argument("--issue", action="append", default=[])
    new.add_argument("--title")
    new.add_argument("--follow-up-to")
    new.set_defaults(func=cmd_new_fix)

    transition = sub.add_parser("transition", help="perform a validated fix-state transition")
    transition.add_argument("fix_id")
    transition.add_argument("target")
    transition.add_argument("--by", required=True)
    transition.add_argument("--expect-revision", type=int, required=True)
    transition.add_argument("--next-owner", required=True)
    transition.add_argument("--next-action", required=True)
    transition.add_argument("--artifact")
    transition.add_argument("--note")
    transition.add_argument("--approval-ref")
    transition.add_argument("--force", action="store_true")
    transition.set_defaults(func=cmd_transition)

    configure = sub.add_parser("configure", help="revision-checked role/pin/plan updates")
    configure.add_argument("fix_id")
    configure.add_argument("--file", required=True, help="YAML object with changed input fields")
    configure.add_argument("--by", required=True)
    configure.add_argument("--expect-revision", required=True, type=int)
    configure.add_argument("--approval-ref")
    configure.set_defaults(func=cmd_configure)

    start = sub.add_parser("start", help="record standing scope through reviewed PR delivery for an existing fix")
    start.add_argument("fix_id")
    start.add_argument("--by", required=True)
    start.add_argument("--expect-revision", required=True, type=int)
    start.set_defaults(func=cmd_start)

    check = sub.add_parser("record-check", help="sign and hash a retained fix artifact")
    check.add_argument("fix_id")
    check.add_argument("check", choices=sorted(gates.CHECK_ROLES))
    check.add_argument("--by", required=True)
    check.add_argument("--artifact", required=True, help="path relative to the fix")
    check.add_argument("--result", choices=["PASS", "FAIL", "UNAVAILABLE", "NON_DISCRIMINATING", "NOT_REQUIRED"], default="PASS")
    check.add_argument("--command", required=True, help="exact reproduction/review command")
    check.add_argument("--inputs", action="append", help="Complete dependency file/directory; reviewer must approve before reuse")
    check.add_argument("--approval-ref")
    check.add_argument("--rationale")
    check.add_argument("--expect-revision", required=True, type=int)
    check.set_defaults(func=cmd_record_check)

    for name, handler in [('submit-review', cmd_submit_review), ('review-verdict', cmd_review_verdict)]:
        batch = sub.add_parser(name, help='Atomic role handoff: record evidence, validate gates and notify peer')
        batch.add_argument('fix_id')
        batch.add_argument('--file', required=True, help='Role-specific YAML evidence package')
        batch.add_argument('--by', required=True)
        batch.add_argument('--expect-revision', type=int, required=True)
        batch.add_argument('--no-notify', action='store_true', help='Explicit foreground handoff; otherwise bus notification is automatic')
        if name == 'review-verdict': batch.add_argument('--result', choices=['PASS', 'FAIL'], required=True)
        batch.set_defaults(func=handler)
    delta = sub.add_parser('review-delta', help='Changes since last passing independent review; never grants reuse automatically')
    delta.add_argument('fix_id'); delta.add_argument('--agent', required=True); delta.set_defaults(func=cmd_review_delta)
    notify = sub.add_parser('handoff-notify', help='Retry a committed handoff notification without repeating checks')
    notify.add_argument('fix_id'); notify.add_argument('--by', required=True); notify.set_defaults(func=cmd_handoff_notify)
    local = sub.add_parser('preflight', help='Plan/run selected local CI checks, with matching tool versions')
    local.add_argument('fix_id', nargs='?'); local.add_argument('--base'); local.add_argument('--head')
    local.add_argument('--run', action='store_true'); local.add_argument('--output')
    local.add_argument('--verbose', action='store_true', help='Show full commands and changed paths instead of bounded plan')
    local.add_argument('--python'); local.add_argument('--helm'); local.add_argument('--timeout', type=int, default=600)
    local.set_defaults(func=cmd_preflight)

    render = sub.add_parser("render-issues", help="render canonical master register")
    render.add_argument("--check", action="store_true")
    render.set_defaults(func=cmd_render_issues)

    rehash = sub.add_parser("rehash-issue", help="accept an intentional issue-body edit")
    rehash.add_argument("issue_id")
    rehash.set_defaults(func=cmd_rehash_issue)

    sync = sub.add_parser("sync-index", help="sync fix-index projections from STATUS.yaml")
    sync.add_argument("--check", action="store_true")
    sync.set_defaults(func=cmd_sync_index)

    sync_main = sub.add_parser(
        "sync-main", help="scan or publish a reviewed origin/main reconciliation"
    )
    sync_main_mode = sync_main.add_mutually_exclusive_group(required=True)
    sync_main_mode.add_argument("--check", action="store_true")
    sync_main_mode.add_argument("--publish", action="store_true")
    sync_main.add_argument("--repo")
    sync_main.add_argument("--source-ref", default="origin/main")
    sync_main.add_argument("--issue", action="append", default=[])
    sync_main.add_argument("--ignore-issue", action="append", default=[])
    sync_main.add_argument("--unattributed-reviewed", action="store_true")
    sync_main.add_argument("--approval-ref")
    sync_main.add_argument("--by", default="release-synchronizer")
    sync_main.set_defaults(func=cmd_sync_main)

    release = sub.add_parser(
        "release-sync", help="observe or finalize a deployed release transaction"
    )
    release_mode = release.add_mutually_exclusive_group(required=True)
    release_mode.add_argument("--check", action="store_true")
    release_mode.add_argument("--publish", action="store_true")
    release_mode.add_argument("--finalize", action="store_true")
    release.add_argument("--record")
    release.add_argument("--repo")
    release.add_argument("--image")
    release.add_argument("--digest")
    release.add_argument("--git-sha")
    release.add_argument("--release-commit")
    release.add_argument("--source-release")
    release.add_argument("--observed-at")
    release.add_argument("--observed-by")
    release.add_argument("--environment")
    release.add_argument("--issue", action="append", default=[])
    release.add_argument("--fix", action="append", default=[])
    release.add_argument("--pass-issue", action="append", default=[])
    release.add_argument("--fail-issue", action="append", default=[])
    release.add_argument("--defer-issue", action="append", default=[])
    release.add_argument("--approval-ref")
    release.add_argument("--by", default="release-synchronizer")
    release.set_defaults(func=cmd_release_sync)

    campaign = sub.add_parser(
        "new-campaign", help="create an explicitly approved live campaign"
    )
    campaign.add_argument("question")
    campaign.add_argument("--id", dest="campaign_id")
    campaign.add_argument("--owner", default="human-owner")
    campaign.add_argument("--approval-ref", required=True)
    campaign.add_argument("--environment", required=True)
    campaign.add_argument(
        "--permission", choices=sorted(CAMPAIGN_PERMISSIONS), default="read-only"
    )
    campaign.add_argument("--duration-ceiling", required=True)
    campaign.add_argument("--cost-ceiling", required=True)
    campaign.add_argument("--source-release")
    campaign.add_argument("--fix", action="append", default=[])
    campaign.add_argument("--image")
    campaign.add_argument("--digest")
    campaign.add_argument("--git-sha")
    campaign.add_argument("--stop-condition", action="append", default=[])
    campaign.add_argument("--campaign-lead", required=True)
    campaign.add_argument("--independent-reviewer")
    campaign.add_argument("--coordinator", required=True)
    campaign.set_defaults(func=cmd_new_campaign)

    campaign_transition = sub.add_parser(
        "campaign-transition", help="perform a validated campaign-state transition"
    )
    campaign_transition.add_argument("campaign_id")
    campaign_transition.add_argument("target")
    campaign_transition.add_argument("--by", required=True)
    campaign_transition.add_argument("--next-owner", required=True)
    campaign_transition.add_argument("--next-action", required=True)
    campaign_transition.add_argument("--artifact")
    campaign_transition.add_argument("--note")
    campaign_transition.add_argument("--approval-ref")
    campaign_transition.add_argument("--phase-approval-ref")
    campaign_transition.add_argument("--image")
    campaign_transition.add_argument("--digest")
    campaign_transition.add_argument("--git-sha")
    campaign_transition.add_argument(
        "--positive-control", choices=["PASS", "FAIL", "UNAVAILABLE"]
    )
    campaign_transition.add_argument(
        "--cleanup", choices=["PASS", "FAIL", "pending"]
    )
    campaign_transition.add_argument(
        "--verdict",
        choices=["PASS", "FAIL", "UNAVAILABLE", "NON_DISCRIMINATING"],
    )
    campaign_transition.add_argument("--reviewer")
    campaign_transition.add_argument("--round-state", action="append", default=[])
    campaign_transition.add_argument("--finding", action="append", default=[])
    campaign_transition.add_argument("--force", action="store_true")
    campaign_transition.set_defaults(func=cmd_campaign_transition)

    campaign_round = sub.add_parser(
        "new-campaign-round", help="add a planned round to a v2 campaign"
    )
    campaign_round.add_argument("campaign_id")
    campaign_round.add_argument("round_id")
    campaign_round.set_defaults(func=cmd_new_campaign_round)

    anatomy = sub.add_parser("anatomy-refresh", help="audit anatomy at an exact source ref")
    anatomy.add_argument("--source-ref", required=True)
    anatomy.add_argument("--repo")
    anatomy_mode = anatomy.add_mutually_exclusive_group()
    anatomy_mode.add_argument("--check", action="store_true", help="audit without publishing (default)")
    anatomy_mode.add_argument("--publish", action="store_true", help="publish only after the suite passes")
    anatomy.set_defaults(func=cmd_anatomy_refresh)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
