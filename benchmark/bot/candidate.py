#!/usr/bin/env python3
"""Apply an LLM-proposed brain change on a throwaway candidate branch.

This is the deterministic, security-critical core of the benchmark bot's
"LLM rewrites brain source" path. A planner (see planner.py) turns a prompt
into a unified diff; this module decides whether that diff is allowed and, if
so, lands it as one commit on a disposable branch with a disposable, non-release
tag that build-image.sh can build. It never edits the working repository, never
touches main, never merges and never pushes.

What a candidate may change: only `*.go` files under `phorvex/`, excluding
`phorvex/tools/` (release and test tooling) and `_test.go` files (so a candidate
cannot weaken the tests). Everything else -- the Dockerfiles, charts, go.mod,
go.sum, deploy/, benchmark/ -- is off limits here, and build-image.sh enforces
the same boundary again (Dockerfile drift check, `-mod=readonly`). Files may be
added or modified; deletion is refused unless --allow-delete is given.

The LLM proposes; a human disposes. The output is a branch and a tag, nothing
more. Promotion to a real release stays a separate, human decision outside the
harness.

Usage:
  candidate.py --src-repo REPO --run-dir D --run-id ID \
    [--base-tag TAG] --base-commit SHA --diff DIFF_FILE [--prompt-file P] \
    [--planner NAME] [--model NAME] [--allow-delete] [--out D/CANDIDATE.json]

Exit codes: 2 bad arguments; 3 base ref problem; 4 the diff does not apply;
5 the diff touches something out of scope; 6 the diff is empty; 7 git failure.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "phorvex-bench/candidate/v1"
# A candidate tag must not look like a release tag (ticket Part 3 field 16), so
# release tooling ignores it and it is never confused with a shipped version.
RELEASE_NAMESPACE = re.compile(r"^(manager|brain|sensor|actuator|console|attacks)-v")
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}
# The candidate commit is a throwaway, so its identity is informational; it is
# deliberately not the operator's, and it carries no author-assistant trailer.
BOT_IDENTITY = ("phorvex-benchmark-bot", "benchmark-bot@phorvex.invalid")


class CandidateError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def in_scope(path):
    """True iff a candidate diff may add or modify this repo-relative path."""
    parts = path.split("/")
    return (
        parts[0] == "phorvex"
        and len(parts) > 1
        and parts[1] != "tools"
        and path.endswith(".go")
        and not path.endswith("_test.go")
    )


class Git:
    def __init__(self, cwd):
        self.cwd = str(cwd)

    def __call__(self, *args, check=True, _input=None):
        env = {**os.environ, **GIT_ENV}
        result = subprocess.run(
            ["git", "-C", self.cwd, *args],
            text=True, capture_output=True, input=_input, env=env,
        )
        if check and result.returncode != 0:
            raise CandidateError(7, f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result


def resolve_scope_dir(run_dir, src_repo):
    """Validate --run-dir is outside the working repo and does not contain it."""
    work = Path(subprocess.run(
        ["git", "-C", str(src_repo), "rev-parse", "--show-toplevel"],
        text=True, capture_output=True, env={**os.environ, **GIT_ENV},
    ).stdout.strip() or "")
    if not work.is_dir():
        raise CandidateError(2, f"--src-repo is not a Git repository: {src_repo}")
    work = work.resolve()
    d = Path(run_dir)
    if not d.is_absolute() or not d.is_dir():
        raise CandidateError(2, "--run-dir must be an existing absolute directory")
    d = d.resolve()
    if d == Path("/"):
        raise CandidateError(2, "--run-dir must not be /")
    if work == d or work in d.parents:
        raise CandidateError(2, "--run-dir must be outside the working repository")
    if d in work.parents:
        raise CandidateError(2, "--run-dir must not contain the working repository")
    return work, d


def make_candidate(args):
    work_repo, run_dir = resolve_scope_dir(args.run_dir, args.src_repo)

    if not re.fullmatch(r"[0-9a-f]{6,40}", args.run_id):
        raise CandidateError(2, "--run-id must be 6-40 lowercase hex digits")
    if not re.fullmatch(r"[0-9a-f]{40}", args.base_commit):
        raise CandidateError(2, "--base-commit must be a full 40-character lowercase SHA")

    diff_text = Path(args.diff).read_text()
    if not diff_text.strip():
        raise CandidateError(6, "the proposed diff is empty")

    clone = run_dir / "candidate-src"
    if clone.exists() or clone.is_symlink():
        raise CandidateError(2, f"{clone} already exists")

    # Read-only on the working repo. --shared borrows its objects instead of
    # copying them (disk is tight on the jump host); the candidate's own commit
    # and tag are written into the clone, never back into the working repo.
    subprocess.run(
        ["git", "-C", str(work_repo), "clone", "--quiet", "--shared", "--", str(work_repo), str(clone)],
        check=True, capture_output=True, env={**os.environ, **GIT_ENV},
    )
    try:
        return _build_candidate(args, Git(clone), clone, diff_text)
    except CandidateError:
        # A failed candidate leaves nothing behind, so a retry in the same run
        # directory is clean. A successful one is kept for build-image.sh.
        shutil.rmtree(clone, ignore_errors=True)
        raise


def _build_candidate(args, git, clone, diff_text):

    # With a tag, the base must resolve to exactly --base-commit through it.
    # Without one (a deployed commit need not be tagged), the commit must exist.
    if args.base_tag:
        tagged = git("rev-parse", "--verify", "--quiet", f"refs/tags/{args.base_tag}^{{commit}}", check=False)
        if tagged.returncode != 0 or tagged.stdout.strip() != args.base_commit:
            raise CandidateError(3, f"tag {args.base_tag} does not resolve to --base-commit {args.base_commit}")
    elif git("cat-file", "-e", f"{args.base_commit}^{{commit}}", check=False).returncode != 0:
        raise CandidateError(3, f"--base-commit {args.base_commit} is not in the source repository")

    branch = f"bench-candidate/{args.run_id}"
    git("checkout", "--quiet", "--detach", args.base_commit)
    git("switch", "--quiet", "-c", branch)

    # Validate the diff applies before changing anything, then stage it.
    check = git("apply", "--check", "--whitespace=nowarn", str(args.diff), check=False)
    if check.returncode != 0:
        raise CandidateError(4, f"the proposed diff does not apply to {args.base_tag or args.base_commit[:12]}: {check.stderr.strip()}")
    git("apply", "--index", "--whitespace=nowarn", str(args.diff))

    changed = []
    for line in git("diff", "--cached", "--name-status").stdout.splitlines():
        status, _, path = line.partition("\t")
        path = path.strip()
        status = status.strip()
        offenders = []
        if status.startswith("R") or status.startswith("C"):
            offenders.append(f"{status} {path} (rename/copy not allowed)")
        elif status == "D" and not args.allow_delete:
            offenders.append(f"D {path} (deletion not allowed; pass --allow-delete)")
        elif status in ("A", "M", "D") and not in_scope(path):
            offenders.append(f"{status} {path} (out of scope)")
        if offenders:
            raise CandidateError(5, "the proposed diff touches files it may not: " + "; ".join(offenders))
        changed.append({"status": status, "path": path})
    if not changed:
        raise CandidateError(6, "the proposed diff makes no change")

    # gofmt the changed Go files when gofmt is available, so a formatting-only
    # slip does not fail the later go build; the build remains the real gate.
    gofmt = shutil.which("gofmt")
    if gofmt:
        go_files = [c["path"] for c in changed if c["status"] in ("A", "M") and c["path"].endswith(".go")]
        if go_files:
            subprocess.run([gofmt, "-w", *go_files], cwd=str(clone), check=False, capture_output=True)
            git("add", "--", *go_files)

    message = f"bench(candidate {args.run_id}): {args.summary or 'LLM-proposed brain change'}\n"
    git("-c", f"user.name={BOT_IDENTITY[0]}", "-c", f"user.email={BOT_IDENTITY[1]}",
        "commit", "--quiet", "--no-verify", "-m", message)
    candidate_commit = git("rev-parse", "HEAD").stdout.strip()

    tag = f"bench-{args.run_id}"
    if RELEASE_NAMESPACE.match(tag):
        raise CandidateError(2, f"internal: candidate tag {tag} is in the release namespace")
    git("-c", f"user.name={BOT_IDENTITY[0]}", "-c", f"user.email={BOT_IDENTITY[1]}",
        "tag", "-a", "-m", f"benchmark candidate {args.run_id}", tag, candidate_commit)

    prompt_text = Path(args.prompt_file).read_text() if args.prompt_file else None
    record = {
        "schema": SCHEMA,
        "runId": args.run_id,
        "baseTag": args.base_tag,
        "baseCommit": args.base_commit,
        "candidateBranch": branch,
        "candidateTag": tag,
        "candidateCommit": candidate_commit,
        "repo": str(clone),
        "changedPaths": changed,
        "planner": args.planner,
        "model": args.model,
        "promptSha256": sha256_text(prompt_text) if prompt_text is not None else None,
        "diffSha256": sha256_text(diff_text),
        "createdAt": utc_now(),
        "guardrails": {
            "scope": "phorvex/**/*.go, excluding phorvex/tools/ and _test.go",
            "base": "detached clone of the working repo",
            "allowDelete": bool(args.allow_delete),
            "noMerge": True,
            "noPush": True,
            "worksOnWorkingRepo": False,
        },
    }
    if args.out:
        out = Path(args.out)
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_text(json.dumps(record, indent=2) + "\n")
        tmp.replace(out)
    return record


def parse_args(argv):
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--src-repo", required=True)
    p.add_argument("--run-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--base-tag")
    p.add_argument("--base-commit", required=True)
    p.add_argument("--diff", required=True)
    p.add_argument("--prompt-file")
    p.add_argument("--summary", default="")
    p.add_argument("--planner", default="unknown")
    p.add_argument("--model", default="unknown")
    p.add_argument("--allow-delete", action="store_true")
    p.add_argument("--out")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        record = make_candidate(args)
    except CandidateError as error:
        print(f"candidate: {error}", file=sys.stderr)
        return error.code
    print(record["candidateTag"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
