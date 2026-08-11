#!/usr/bin/env python3
"""Turn a run-<stamp>.json into the Markdown that lands on the pull request.

The comment has to answer three things without anyone opening the report: did it pass,
what broke, and where is the evidence. Everything else belongs in the dashboard.

    python3 summary.py runs/run-<stamp>.json --url https://ci-report.phorvex.ai/pr-42/...

Emits Markdown on stdout. `--marker` prints an HTML comment the workflow uses to find and
update its previous comment instead of posting a new one on every push.
"""

import argparse
import json
import sys
from pathlib import Path

VERDICT = {
    "PASS": ("✅", "All contracts held."),
    "WARN": ("⚠️", "No contract was violated, but something is worth a look."),
    "FAIL": ("❌", "A critical or major contract was violated."),
}

MARKER = "<!-- phorvex-e2e-report -->"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_json")
    ap.add_argument("--url", default=None, help="published report URL")
    ap.add_argument("--marker", action="store_true", help="prepend the update marker")
    ap.add_argument("--title", default="Phorvex End-to-End")
    a = ap.parse_args()

    doc = json.loads(Path(a.run_json).read_text(encoding="utf-8"))
    verdict = doc.get("verdict", "?")
    icon, blurb = VERDICT.get(verdict, ("❓", ""))
    tally = doc.get("tally", {})
    counts = doc.get("counts", {})
    checks = doc.get("checks", [])
    target = (doc.get("target") or {}).get("name") or "—"

    out = []
    if a.marker:
        out.append(MARKER)
    out.append(f"## {icon} {a.title} — **{verdict}**")
    out.append("")
    out.append(blurb)
    out.append("")

    # The headline numbers. `skip` is shown as prominently as `pass` on purpose: a board of
    # 30 passes and 20 skips is not the same claim as 50 passes, and hiding the skips is
    # how a green badge starts meaning nothing.
    out.append(f"| Passed | Failed | Warned | Skipped | Mode | Target | Decisions |")
    out.append("|---:|---:|---:|---:|:--|:--|---:|")
    out.append(
        f"| {tally.get('pass', 0)} | {tally.get('fail', 0)} | {tally.get('warn', 0)} "
        f"| {tally.get('skip', 0)} | `{doc.get('mode', '?')}` | `{target}` "
        f"| {counts.get('records', 0)} |"
    )
    out.append("")

    bad = [c for c in checks if c["status"] == "fail"]
    warned = [c for c in checks if c["status"] == "warn"]
    if bad:
        out.append("### Failed checks")
        out.append("")
        out.append("| id | severity | check | what went wrong |")
        out.append("|:--|:--|:--|:--|")
        for c in bad:
            out.append(f"| `{c['id']}` | {c.get('severity', '?')} | {c['title']} "
                       f"| {c['summary']} |")
        out.append("")
    if warned:
        out.append("<details><summary>Warnings (" + str(len(warned)) + ")</summary>")
        out.append("")
        for c in warned:
            out.append(f"- `{c['id']}` **{c['title']}** — {c['summary']}")
        out.append("")
        out.append("</details>")
        out.append("")

    # A skipped check is a hole in coverage, so it is reported — folded, because on a
    # read-only run most of the actuation catalogue is legitimately unreachable.
    skipped = [c for c in checks if c["status"] == "skip"]
    if skipped:
        out.append("<details><summary>Not evaluated (" + str(len(skipped)) +
                   ") — these prove nothing either way</summary>")
        out.append("")
        for c in skipped:
            out.append(f"- `{c['id']}` **{c['title']}** — {c['summary']}")
        out.append("")
        out.append("</details>")
        out.append("")

    gt = doc.get("groundTruth") or []
    if gt:
        out.append("<details><summary>Cluster ground truth (" + str(len(gt)) +
                   ") — verified with kubectl, not with what Phorvex reported</summary>")
        out.append("")
        out.append("| verdict | action | pod | detail |")
        out.append("|:--|:--|:--|:--|")
        for g in gt:
            out.append(f"| {g['verdict']} | `{g['action']}` | `{g['pod']}` | {g['detail']} |")
        out.append("")
        out.append("</details>")
        out.append("")

    if a.url:
        out.append(f"📊 **[Full dashboard →]({a.url})**  ")
        out.append("Every decision, its six stages, and each field next to its legal range "
                   "and the function that produced it.")
        out.append("")

    pf = doc.get("preflight", {}).get("version", {})
    out.append(
        f"<sub>console `{pf.get('console', '?')}` · operator `{pf.get('operator', '?')}` · "
        f"transport `{doc.get('transport', '?')}` · run `{doc.get('runId', '?')}`</sub>"
    )

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
