#!/usr/bin/env python3
"""Operator for the versioned Phorvex workflow directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
ISSUES = ROOT / "issues"
FIXES = ROOT / "fixes"
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
LEGACY_ENTRY_START = re.compile(r"^### (M-\d+) ·", re.MULTILINE)
LEGACY_BOUNDARY = re.compile(
    r"^(?:### M-\d+ ·|## |### (?!M-\d+ ·))", re.MULTILINE
)


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
    base, metadata, tokens = render_base()
    joins_doc = load_yaml(ISSUES / "joins.yaml") or {}
    joins: dict[str, dict[str, Any]] = joins_doc.get("joins", {})
    unknown = sorted(set(joins) - set(tokens))
    if unknown:
        raise ValueError(f"joins reference unknown issues: {unknown}")

    out: list[str] = []
    for line in base.splitlines(keepends=True):
        out.append(line)
        match = re.match(r"^### (M-\d+) ·", line)
        if not match:
            continue
        issue_id = match.group(1)
        state = metadata[issue_id].get("workflow_state", "UNKNOWN")
        fix_ids = metadata[issue_id].get("fixes", [])
        fix_text = ", ".join(f"`{fix_id}`" for fix_id in fix_ids) if fix_ids else "none"
        out.append(f"\n> **WORKFLOW** · `{state}` · fixes: {fix_text}\n")
        if issue_id in joins:
            out.append(str(joins[issue_id]["rendered"]).rstrip() + "\n")
    rendered = "".join(out)
    states = Counter(str(metadata[i].get("workflow_state", "UNKNOWN")) for i in tokens)
    state_text = ", ".join(f"{k}={v}" for k, v in sorted(states.items()))
    pin = joins_doc.get("anatomy_pin", "unknown")
    banner = (
        "\n"
        "> **Generated canonical view.** Source: `issues/entries/` + "
        "`issues/joins.yaml`. Do not edit this file.\n"
        f"> Entries: {len(tokens)} · joins: {len(joins)} · anatomy pin: `{pin}` · "
        f"states: {state_text}.\n"
    )
    first_newline = rendered.find("\n")
    return rendered[: first_newline + 1] + banner + rendered[first_newline + 1 :]


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


def cmd_sync_index(args: argparse.Namespace) -> int:
    path = FIXES / "INDEX.yaml"
    current = load_yaml(path)
    expected = synchronized_index(current)
    stale_links = sync_issue_fix_links(expected, check=True)
    if args.check:
        if current != expected or stale_links:
            if current != expected:
                print("FAIL: fixes/INDEX.yaml is stale", file=sys.stderr)
            if stale_links:
                print(
                    "FAIL: issue-to-fix links are stale: " + ", ".join(stale_links),
                    file=sys.stderr,
                )
            return 1
        print("fix index: PASS")
        return 0
    write_yaml(path, expected)
    sync_issue_fix_links(expected, check=False)
    write_text(ISSUES / "MASTER_ISSUES.md", render_master())
    print(f"wrote {path}")
    return 0


def cmd_render_issues(args: argparse.Namespace) -> int:
    target = ISSUES / "MASTER_ISSUES.md"
    rendered = render_master()
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != rendered:
            print(f"FAIL: {target} is stale", file=sys.stderr)
            return 1
        print("issues render: PASS")
        return 0
    write_text(target, rendered)
    print(f"wrote {target}")
    return 0


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
    metadata["updated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    write_entry(path, metadata, body)
    print(f"rehashed {args.issue_id}: {digest}")
    return 0


def cmd_brief(args: argparse.Namespace) -> int:
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
        print(f"  branch: {status.get('implementation', {}).get('branch')}")
        print(f"  stacked_on: {status.get('implementation', {}).get('stacked_on', [])}")
        next_action = status.get("next_action", {})
        print(f"  next_owner: {next_action.get('owner')}")
        print(f"  next_action: {next_action.get('action')}")
    return 0


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
    existing = status.get("blind_derivation", {}).get("status")
    if existing == "sealed" and not args.force:
        print("FAIL: blind derivation already sealed; pass --force only for a recorded amendment", file=sys.stderr)
        return 1
    digest = sha256(blind_path)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    seal_path.write_text(f"{digest}  {blind_path.name}\nsealed_at: {now}\n", encoding="utf-8")
    status["blind_derivation"] = {"status": "sealed", "sha256": digest, "sealed_at": now}
    status["updated_at"] = now
    write_yaml(status_path, status)
    print(f"sealed {args.fix_id}: {digest}")
    return 0


def cmd_new_fix(args: argparse.Namespace) -> int:
    try:
        validate_fix_id(args.fix_id)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    target = FIXES / args.fix_id
    if target.exists():
        print(f"FAIL: {target} already exists", file=sys.stderr)
        return 1
    for issue_id in args.issue:
        if not re.fullmatch(r"M-\d+", issue_id):
            print(f"FAIL: invalid issue id {issue_id!r}", file=sys.stderr)
            return 1
        issue_path = ISSUES / "entries" / f"{pad_issue(issue_id)}.md"
        if not issue_path.is_file():
            print(f"FAIL: unknown issue {issue_id}", file=sys.stderr)
            return 1
    index_path = FIXES / "INDEX.yaml"
    index = load_yaml(index_path)
    owners: dict[str, list[str]] = {}
    for fix_id, record in index["fixes"].items():
        for issue_id in record.get("issues", []):
            owners.setdefault(issue_id, []).append(fix_id)
    duplicates = {issue: owners[issue] for issue in args.issue if issue in owners}
    if duplicates:
        valid_follow_up = args.follow_up_to and all(
            args.follow_up_to in issue_owners for issue_owners in duplicates.values()
        )
        if not valid_follow_up:
            print(
                "FAIL: issue already owned; pass --follow-up-to with an owning fix: "
                + ", ".join(f"{issue}={fixes}" for issue, fixes in duplicates.items()),
                file=sys.stderr,
            )
            return 1
    shutil.copytree(FIXES / "_template", target)
    status_path = target / "STATUS.yaml"
    status = load_yaml(status_path)
    status["fix_id"] = args.fix_id
    status["issues"] = args.issue
    status["title"] = args.title or "UNSET — complete 00-intake.md"
    if args.follow_up_to:
        status["follow_up_to"] = args.follow_up_to
    status["updated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    write_yaml(status_path, status)
    evidence_manifest_path = target / "evidence" / "manifest.yaml"
    evidence_manifest = load_yaml(evidence_manifest_path)
    evidence_manifest["fix_id"] = args.fix_id
    write_yaml(evidence_manifest_path, evidence_manifest)
    index["fixes"][args.fix_id] = {
        "directory": f"fixes/{args.fix_id}",
        "aliases": [],
        "issues": args.issue,
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
    print(f"created {target.relative_to(ROOT)}")
    return 0


def transition_prerequisites(fix_dir: Path, status: dict[str, Any], target: str) -> list[str]:
    missing: list[str] = []
    if target == "PR_READY":
        if status.get("verification", {}).get("p3") != "PASS":
            missing.append("verification.p3 must be PASS")
        if not status.get("implementation", {}).get("head_sha"):
            missing.append("implementation.head_sha")
    if target == "IN_PR":
        pull_request = status.get("pull_request", {})
        if not pull_request.get("url"):
            missing.append("pull_request.url")
        head = status.get("implementation", {}).get("head_sha")
        reviewed = pull_request.get("reviewed_head")
        if head != reviewed and pull_request.get("patch_equivalence") != "PASS":
            missing.append(
                "reviewed_head must equal implementation.head_sha or patch_equivalence must be PASS"
            )
    if target == "MERGED" and not status.get("pull_request", {}).get("merge_sha"):
        missing.append("pull_request.merge_sha")
    if target == "DEPLOYED":
        deployment = status.get("deployment", {})
        if not deployment.get("image"):
            missing.append("deployment.image")
        if not deployment.get("git_sha"):
            missing.append("deployment.git_sha")
    if target == "LIVE_VERIFIED":
        verification = status.get("verification", {})
        for level in ("l3", "l4"):
            if level.upper() not in verification.get("required", []):
                continue
            if verification.get(level) != "PASS":
                missing.append(f"verification.{level} must be PASS")
    if target == "SYNCHRONIZED":
        synchronization = status.get("synchronization", {})
        for key, value in synchronization.items():
            normalized = str(value).lower()
            if any(word in normalized for word in ("pending", "missing", "stale", "gap")):
                missing.append(f"synchronization.{key}={value!r}")
    if target == "CLOSED" and not (fix_dir / "06-verdict.md").is_file():
        missing.append("06-verdict.md")
    return missing


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
    current = status.get("state")
    allowed = args.target in TRANSITIONS.get(current, set())
    if not allowed and not args.force:
        print(f"FAIL: transition {current} -> {args.target} is not allowed", file=sys.stderr)
        return 1
    if (args.target in HUMAN_GATED_STATES or args.force) and not args.approval_ref:
        print("FAIL: this transition requires --approval-ref", file=sys.stderr)
        return 1
    if not args.force:
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
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
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
    status["next_action"] = {"owner": args.next_owner, "action": args.next_action}
    status["updated_at"] = now
    write_yaml(status_path, status)
    index_path = FIXES / "INDEX.yaml"
    index = synchronized_index(load_yaml(index_path))
    write_yaml(index_path, index)
    sync_issue_fix_links(index, check=False)
    write_text(ISSUES / "MASTER_ISSUES.md", render_master())
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
            pin["commit"] = target
            tag = subprocess.run(
                ["git", "-C", str(source), "describe", "--tags", "--exact-match", target],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            pin["release"] = tag.stdout.strip() if tag.returncode == 0 else args.source_ref
            pin["frozen_at"] = "release-sync"
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

            if args.check and changed:
                print(
                    "FAIL: generated anatomy differs from committed outputs",
                    file=sys.stderr,
                )
                return 1
            if args.publish:
                for rel in comparisons:
                    src, dst = workflow / rel, ROOT / rel
                    if src.is_file():
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        temp_dst = dst.with_suffix(dst.suffix + ".tmp")
                        shutil.copy2(src, temp_dst)
                        temp_dst.replace(dst)
                anatomy_pin_path = ROOT / "anatomy" / "PIN.yaml"
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
                current["anatomy"] = {
                    "source_commit": target,
                    "current_for_deployed_release": True,
                    "refresh_status": "PASS",
                }
                write_yaml(current_path, current)
                print("published validated anatomy outputs and pin")
        except subprocess.CalledProcessError as exc:
            print(exc.stdout or str(exc), file=sys.stderr)
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


def cmd_doctor(args: argparse.Namespace) -> int:
    errors: list[str] = []
    warnings: list[str] = []
    local_hash_cache: dict[Path, str] = {}

    required = [
        ROOT / "AGENTS.md",
        ROOT / "README.md",
        ROOT / "WORKFLOW.md",
        ROOT / "MANIFEST.yaml",
        ISSUES / "MASTER_ISSUES.md",
        ISSUES / "joins.yaml",
        FIXES / "INDEX.yaml",
        ROOT / "anatomy" / "ANATOMY.md",
        ROOT / "anatomy" / "PIN.yaml",
        ROOT / "releases" / "CURRENT.yaml",
    ]
    for path in required:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")

    try:
        base, metadata, tokens = render_base()
        if len(tokens) != len(metadata):
            errors.append("issue entry/token cardinality mismatch")
        for issue_id, entry in metadata.items():
            if entry.get("workflow_state") not in ISSUE_STATES:
                errors.append(
                    f"{issue_id}: unknown issue state {entry.get('workflow_state')!r}"
                )
            if entry.get("migration_review") != "complete":
                errors.append(f"{issue_id}: migration metadata review is incomplete")
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
            if current_layout != legacy_layout or tokens != legacy_order:
                errors.append("issue layout/order differs from the migrated base register")
            for issue_id, legacy_body in legacy_entries.items():
                expected = hashlib.sha256(legacy_body.encode("utf-8")).hexdigest()
                if metadata[issue_id].get("migration_body_sha256") != expected:
                    errors.append(f"{issue_id}: migrated-body provenance hash mismatch")
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
        if not str(source.get("commit", "")).startswith(str(pin["anatomy"]["source_commit"])):
            errors.append("anatomy PIN.yaml and pipeline/SOURCE_PIN.json disagree")
        joins_doc = load_yaml(ISSUES / "joins.yaml") or {}
        if not str(pin["anatomy"]["source_commit"]).startswith(
            str(joins_doc.get("anatomy_pin", ""))
        ):
            errors.append("issues/joins.yaml and anatomy/PIN.yaml disagree")
        incomplete_joins = [
            issue_id
            for issue_id, join in joins_doc.get("joins", {}).items()
            if join.get("review") != "complete"
        ]
        if incomplete_joins:
            errors.append(
                f"{len(incomplete_joins)} anatomy join(s) lack completed migration review"
            )

        current_path = ROOT / "releases" / "CURRENT.yaml"
        if current_path.is_file():
            current = load_yaml(current_path)
            deployed = str(current.get("deployed", {}).get("embedded_git_sha", ""))
            anatomy_source = str(pin["anatomy"]["source_commit"])
            current_claim = bool(
                current.get("anatomy", {}).get("current_for_deployed_release")
            )
            pins_match = bool(deployed) and (
                deployed.startswith(anatomy_source) or anatomy_source.startswith(deployed)
            )
            if current_claim and not pins_match:
                errors.append(
                    "CURRENT.yaml claims anatomy is current but deployed/anatomy pins differ"
                )
            elif not pins_match:
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

    doctor = sub.add_parser("doctor", help="validate workflow integrity")
    doctor.add_argument(
        "--deep-evidence",
        action="store_true",
        help="also SHA-256 local-original evidence when it is available",
    )
    doctor.set_defaults(func=cmd_doctor)

    brief = sub.add_parser("brief", help="show bounded context for an issue/fix")
    brief.add_argument("identifier")
    brief.set_defaults(func=cmd_brief)

    seal = sub.add_parser("seal", help="seal a skeptic blind derivation")
    seal.add_argument("fix_id")
    seal.add_argument("--force", action="store_true")
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
    transition.add_argument("--next-owner", required=True)
    transition.add_argument("--next-action", required=True)
    transition.add_argument("--artifact")
    transition.add_argument("--note")
    transition.add_argument("--approval-ref")
    transition.add_argument("--force", action="store_true")
    transition.set_defaults(func=cmd_transition)

    render = sub.add_parser("render-issues", help="render canonical master register")
    render.add_argument("--check", action="store_true")
    render.set_defaults(func=cmd_render_issues)

    rehash = sub.add_parser("rehash-issue", help="accept an intentional issue-body edit")
    rehash.add_argument("issue_id")
    rehash.set_defaults(func=cmd_rehash_issue)

    sync = sub.add_parser("sync-index", help="sync fix-index projections from STATUS.yaml")
    sync.add_argument("--check", action="store_true")
    sync.set_defaults(func=cmd_sync_index)

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
