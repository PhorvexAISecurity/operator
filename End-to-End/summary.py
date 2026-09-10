#!/usr/bin/env python3
"""Turn a run-<stamp>.json into the Markdown that lands on the pull request.

The comment has to answer three things without anyone opening the report: did it pass,
what broke, and where is the evidence. Everything else belongs in the dashboard.

    python3 summary.py runs/run-<stamp>.json --url https://ci-report.phorvex.ai/pr-42/...

Emits Markdown on stdout. `--marker` prints an HTML comment the workflow uses to find and
update its previous comment instead of posting a new one on every push.
"""

import argparse
import contextlib
import html
import io
import json
import sys
from pathlib import Path

VERDICT = {
    "PASS": ("✅", "All contracts held."),
    "WARN": ("⚠️", "No contract was violated, but something is worth a look."),
    "FAIL": ("❌", "A critical or major contract was violated."),
}

MARKER = "<!-- phorvex-e2e-report -->"


def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_json", nargs='?', default='')
    ap.add_argument("--expect-run-id", default=None)
    ap.add_argument("--expect-source-commit", default=None)
    ap.add_argument("--exit-code", default=None)
    ap.add_argument("--url", default=None, help="published report URL")
    ap.add_argument("--marker", action="store_true", help="prepend the update marker")
    ap.add_argument("--title", default="Phorvex End-to-End")
    a = ap.parse_args()

    unavailable = False
    try:
        if not a.run_json or not Path(a.run_json).is_file():
            raise ValueError('No report file was produced for this attempt')
        doc = json.loads(Path(a.run_json).read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or doc.get('schema') != 'phorvex.e2e/1':
            raise ValueError('Invalid report schema')
        for key, expected in (('runId', a.expect_run_id), ('sourceCommit', a.expect_source_commit)):
            if expected and doc.get(key) != expected:
                raise ValueError('Report does not match this attempt and source commit')
        if (doc.get('verdict') not in ('PASS', 'WARN', 'FAIL', 'ABORTED') or
                not isinstance(doc.get('checks'), list) or not isinstance(doc.get('tally'), dict)):
            raise ValueError('Incomplete run report')
        for check in doc['checks']:
            if (not isinstance(check, dict) or
                    not {'id', 'title', 'summary', 'status'}.issubset(check) or
                    check['status'] not in ('pass', 'fail', 'warn', 'skip')):
                raise ValueError('Malformed check record')
        for key in ('abort', 'counts', 'preflight', 'baselineReasons', 'target'):
            if key in ('counts', 'preflight') and key in doc and doc[key] is None:
                raise ValueError('Malformed report object')
            if doc.get(key) is not None and not isinstance(doc[key], dict):
                raise ValueError('Malformed report object')
            if doc.get(key) is None:
                doc[key] = {}
        if not isinstance((doc.get('preflight') or {}).get('version', {}), dict):
            raise ValueError('Malformed version record')
        for key in ('baselined', 'newFailures', 'staleBaseline', 'groundTruth'):
            if doc.get(key) is not None and not isinstance(doc[key], list):
                raise ValueError('Malformed report list')
            if key != 'groundTruth' and any(not isinstance(x, str) for x in doc.get(key) or []):
                raise ValueError('Malformed check identifier')
        if not isinstance((doc.get('abort') or {}).get('cleanupErrors', []), list):
            raise ValueError('Malformed cleanup record')
        for record in doc.get('groundTruth') or []:
            if not isinstance(record, dict) or not {'verdict', 'action', 'pod', 'detail'}.issubset(record):
                raise ValueError('Malformed ground truth record')
    except (OSError, ValueError, TypeError) as error:
        unavailable = True
        doc = {'verdict': 'ABORTED', 'runId': a.expect_run_id or 'unknown',
               'sourceCommit': a.expect_source_commit or 'unknown',
               'abort': {'stage': 'report unavailable', 'error': str(error)[:500]}}
    if (a.exit_code is not None and doc.get('verdict') != 'ABORTED' and
            (a.exit_code not in ('0', '1') or
             (a.exit_code == '1' and doc.get('verdict') != 'FAIL') or
             ('exitCode' in doc and str(doc['exitCode']) != a.exit_code))):
        unavailable = True
        doc['verdict'] = 'ABORTED'
        doc['abort'] = {'stage': 'process / report completion',
                        'error': 'Pipeline did not complete consistently with this report; see the current job log'}
        a.url = None
    if doc.get('verdict') == 'ABORTED':
        unavailable = unavailable or a.exit_code == '0'
        escape = lambda value: html.escape(str(value))[:2500].replace('\n', ' ')
        if a.marker:
            print(MARKER)
        print(f"## ❌ {escape(a.title)} — ABORTED\n")
        print('This run did not complete. Unexecuted checks prove nothing; an abort is not baselinable.\n')
        print(f"Run: <code>{escape(doc.get('runId'))}</code> · source: <code>{escape(doc.get('sourceCommit'))}</code>\n")
        abort = doc.get('abort') or {}
        print(f"Stage: <code>{escape(abort.get('stage', 'unknown'))}</code>\n")
        print(f"Primary error: <code>{escape(abort.get('error', 'Unavailable; see this attempt’s job log'))}</code>\n")
        for error in abort.get('cleanupErrors', []):
            print(f"Cleanup unresolved: <code>{escape(error)}</code>\n")
        if doc.get('injection'):
            print(f"Injection/cleanup record: <code>{escape(json.dumps(doc['injection']))}</code>\n")
        print(f"Not evaluated: {doc.get('tally', {}).get('skip', 'unknown')} checks.\n")
        if unavailable:
            print(f"Pipeline exit: <code>{escape(a.exit_code)}</code>. See this attempt's Actions job log for the primary failure.\n")
        elif a.url:
            print(f"[Current attempt report]({a.url})\n")
        else:
            print('No published dashboard is available; use the current Actions artifacts/job log.\n')
        return 1 if unavailable else 0
    verdict = doc.get("verdict", "?")
    icon, blurb = VERDICT.get(verdict, ("❓", ""))
    tally = doc.get("tally", {})
    counts = doc.get("counts", {})
    checks = doc.get("checks", [])
    target = (doc.get("target") or {}).get("name") or "—"
    baselined = doc.get("baselined") or []
    new_failures = doc.get("newFailures") or []
    reasons = doc.get("baselineReasons") or {}
    stale = doc.get("staleBaseline") or []

    out = []
    if a.marker:
        out.append(MARKER)
    out.append(f"## {icon} {a.title} — **{verdict}**")
    out.append("")
    out.append(blurb)
    out.append("")

    # A red report next to a green check is exactly the kind of thing that erodes trust in
    # a gate, so it is explained at the top rather than left to be discovered.
    if baselined and not new_failures:
        out.append(f"> **No new regressions.** All {len(baselined)} failing check(s) are "
                   f"known and recorded in `End-to-End/baseline.json`, so this does not "
                   f"block the merge. The report still reports them as failures.")
        out.append("")
    elif new_failures:
        out.append(f"> **{len(new_failures)} new failure(s) not in the baseline:** "
                   + ", ".join(f"`{i}`" for i in new_failures) + ". This blocks the merge.")
        out.append("")
    if stale:
        out.append(f"> ⚠️ `{'`, `'.join(stale)}` now **passes** but is still listed in "
                   f"`baseline.json`. Delete the entry — a baseline that outlives its cause "
                   f"is a permanent blind spot.")
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
        out.append("| id | severity | known? | check | what went wrong |")
        out.append("|:--|:--|:--|:--|:--|")
        for c in bad:
            mark = "baseline" if c["id"] in baselined else "**new**"
            out.append(f"| `{c['id']}` | {c.get('severity', '?')} | {mark} | {c['title']} "
                       f"| {c['summary']} |")
        out.append("")
        if reasons:
            out.append("<details><summary>Why the known failures are accepted</summary>")
            out.append("")
            for cid, why in reasons.items():
                out.append(f"- **`{cid}`** — {why}")
            out.append("")
            out.append("</details>")
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
    else:
        out.append('No published dashboard is available; use the current Actions artifacts/job log.\n')

    pf = doc.get("preflight", {}).get("version", {})
    out.append(
        f"<sub>console `{pf.get('console', '?')}` · operator `{pf.get('operator', '?')}` · "
        f"transport `{doc.get('transport', '?')}` · run `{doc.get('runId', '?')}`</sub>"
    )

    sys.stdout.write("\n".join(out) + "\n")


def main():
    # Render into memory first: a future malformed-field or template error must
    # never truncate a PR comment into an empty/partial success-shaped message.
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            rc = _main()
    except SystemExit:
        sys.stdout.write(buffer.getvalue())  # argparse --help keeps its normal behavior
        raise
    except Exception as error:
        def argument(flag):
            try:
                return html.escape(sys.argv[sys.argv.index(flag) + 1])[:200]
            except (ValueError, IndexError):
                return 'unknown'
        print(MARKER + '\n## ❌ Phorvex End-to-End — ABORTED\n')
        print(f"Run: <code>{argument('--expect-run-id')}</code> · source: <code>{argument('--expect-source-commit')}</code>\n")
        print(f'Summary unavailable ({type(error).__name__}); inspect this attempt’s artifacts/job log. No success is asserted.')
        return 1
    sys.stdout.write(buffer.getvalue())
    return rc


if __name__ == "__main__":
    sys.exit(main() or 0)
