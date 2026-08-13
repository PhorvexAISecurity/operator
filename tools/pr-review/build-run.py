#!/usr/bin/env python3
"""Build a runnable pr-regression-review workflow script for one PR.

Why a build step instead of passing args?  `args` is NOT delivered to a workflow started via
`scriptPath` (verified: a payload arrives as undefined and every value falls back to its default).
And the review agents must NOT fetch the diff themselves — workflow subagents inherit the calling
session's cwd, so a bare `gh pr diff` / `git diff` silently reviews whatever repo that happens to
be.  Both failure modes cost a full run before being caught.  So the caller resolves the target and
bakes it into the script.

    ./build-run.py 8 --repo R --workdir /path/to/checkout -o /tmp/run8.js       # one PR
    ./build-run.py 7 8 9 --repo R --workdir /path/to/checkout -o /tmp/batch.js   # review together
    # then:  Workflow({scriptPath: "/tmp/batch.js"})

Reviewing several PRs in one pass is the point: a change can be individually correct and still be
unsafe to merge alone. PR #8 was exactly that — it needed #7 to land first, which no single-PR
review could have known.
"""
import argparse, json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
TEMPLATE = HERE / "pr-regression-review.template.js"


def sh(*cmd: str) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return r.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pr", nargs="+", help="one or more PR numbers to review TOGETHER")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workdir", required=True, help="absolute path to the checkout under review")
    ap.add_argument("-o", "--out", default="/tmp/pr-review-run.js")
    a = ap.parse_args()

    wd = pathlib.Path(a.workdir).resolve()
    if not (wd / ".git").exists():
        sys.exit(f"{wd} is not a git checkout")

    changes, files, blocks = [], [], []
    for n in a.pr:
        d = sh("gh", "pr", "diff", n, "--repo", a.repo)
        m = json.loads(sh("gh", "pr", "view", n, "--repo", a.repo, "--json", "title,files"))
        f = [x["path"] for x in m["files"]]
        if not d.strip() or not f:
            sys.exit(f"PR #{n} produced an empty diff — refusing to build a review that would read as 'clean'")
        changes.append({"pr": n, "title": m["title"], "files": f})
        files += f
        blocks.append(f"===== PR #{n}: {m['title']} =====\n{d}")
        print(f"  PR #{n}: {m['title'][:64]} ({len(f)} files, {len(d)} chars)")

    files = sorted(set(files))
    diff = "\n\n".join(blocks)
    # Files touched by more than one PR are the obvious interaction surface; hand them to the
    # reviewers explicitly rather than hoping a lens rediscovers the overlap.
    seen, overlap = {}, []
    for c in changes:
        for f in c["files"]:
            seen.setdefault(f, []).append(c["pr"])
    overlap = {f: prs for f, prs in seen.items() if len(prs) > 1}

    target = json.dumps(
        {"repo": a.repo, "pr": ",".join(a.pr), "prs": a.pr, "changes": changes,
         "overlap": overlap, "workdir": str(wd), "files": files, "diff": diff}, indent=2
    )
    tpl = TEMPLATE.read_text()
    old = """const REPO = args?.repo ?? 'PhorvexSecurity/operator'
const PR = String(args?.pr ?? '')
const WD = args?.workdir ?? '.'"""
    new = (
        "// ---- TARGET (injected by build-run.py; `args` is NOT delivered via scriptPath) ----\n"
        f"const TARGET = {target}\n"
        "// ---------------------------------------------------------------------------------\n"
        "const REPO = TARGET.repo\nconst PR = String(TARGET.pr)\nconst WD = TARGET.workdir"
    )
    if old not in tpl:
        sys.exit("template shape changed — update build-run.py")
    out = tpl.replace(old, new, 1).replace(
        "const DIFF = args?.diff ?? ''\nconst FILES = args?.files ?? []",
        "const DIFF = TARGET.diff\nconst FILES = TARGET.files",
    )
    pathlib.Path(a.out).write_text(out)
    print(f"\nwrote {a.out}\n  {len(a.pr)} PR(s), {len(files)} distinct files, {len(diff)} diff chars")
    if overlap:
        print(f"  files touched by >1 PR: {', '.join(list(overlap)[:4])}")
    print(f'\nnow run:  Workflow({{scriptPath: "{a.out}"}})')


if __name__ == "__main__":
    main()
