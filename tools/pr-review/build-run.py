#!/usr/bin/env python3
"""Build a runnable pr-regression-review workflow script for one PR.

Why a build step instead of passing args?  `args` is NOT delivered to a workflow started via
`scriptPath` (verified: a payload arrives as undefined and every value falls back to its default).
And the review agents must NOT fetch the diff themselves — workflow subagents inherit the calling
session's cwd, so a bare `gh pr diff` / `git diff` silently reviews whatever repo that happens to
be.  Both failure modes cost a full run before being caught.  So the caller resolves the target and
bakes it into the script.

    ./build-run.py 8 --repo PhorvexSecurity/operator --workdir /path/to/checkout -o /tmp/run8.js
    # then:  Workflow({scriptPath: "/tmp/run8.js"})
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
    ap.add_argument("pr")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workdir", required=True, help="absolute path to the checkout under review")
    ap.add_argument("-o", "--out", default="/tmp/pr-review-run.js")
    a = ap.parse_args()

    wd = pathlib.Path(a.workdir).resolve()
    if not (wd / ".git").exists():
        sys.exit(f"{wd} is not a git checkout")

    diff = sh("gh", "pr", "diff", a.pr, "--repo", a.repo)
    meta = json.loads(sh("gh", "pr", "view", a.pr, "--repo", a.repo, "--json", "title,files"))
    files = [f["path"] for f in meta["files"]]
    if not diff.strip() or not files:
        sys.exit(f"PR #{a.pr} produced an empty diff — refusing to build a review that would read as 'clean'")

    target = json.dumps(
        {"repo": a.repo, "pr": a.pr, "workdir": str(wd), "files": files, "diff": diff}, indent=2
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
    print(f"wrote {a.out}\n  PR #{a.pr}: {meta['title'][:70]}\n  {len(files)} files, {len(diff)} diff chars")
    print(f'\nnow run:  Workflow({{scriptPath: "{a.out}"}})')


if __name__ == "__main__":
    main()
