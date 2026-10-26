#!/usr/bin/env python3
"""Build the LiteLLM-defense benchmark reports from the two collected runs.

Reads data/defended.json and data/undefended.json (written by benchmark.sh) and writes:
  report.html             — the attacker dwell-time contrast and the brain's decision
  report.csv              — one curated row per mode, with the full decision record
  report-parameters.csv   — every scalar parameter of each decision (long format)

Stdlib only. Run:  python3 deploy/benchmarks/litellm-defense/report.py
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"

# Curated columns: the headline, then the brain/decision parameters the user asked for.
# Each is (column, list-of-keys-to-search-for anywhere in the decision record).
PARAMS = [
    ("action", ["action"]),
    ("selected", ["selected"]),
    ("feasible", ["feasible"]),
    ("actuated", ["actuated"]),
    ("threatPosture", ["threatPosture"]),
    ("eventEvidence", ["eventEvidence"]),
    ("threatLevel", ["threatLevel"]),
    ("trustVerdict", ["trustVerdict"]),
    ("assetValue", ["assetValue"]),
    ("blastRadius", ["blastRadius"]),
    ("blindCost", ["blindCost"]),
    ("cost", ["cost"]),
    ("coverageValue", ["coverageValue"]),
    ("killSwitch", ["killSwitch"]),
    ("dispatchOutcome", ["dispatchOutcome"]),
    ("dispatchReason", ["dispatchReason"]),
    ("noopReason", ["noopReason"]),
    ("flowRegime", ["flowRegime"]),
    ("stage", ["stage", "stageName"]),
    ("pHold", ["pHold", "PHold"]),
    ("preemptMargin", ["preemptMargin", "PreemptMargin"]),
    ("projNextStageSec", ["projectedNextStageSec", "ProjectedNextStageSec", "projNextSec"]),
    ("infectionFrontier", ["infectionFrontier", "InfectionFrontier", "frontier"]),
    ("brainImage", ["brainImage"]),
    ("gitSHA", ["gitSHA"]),
]


def find(node, keys):
    """First value for any of `keys` anywhere in the nested record (depth-first)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in keys and not isinstance(v, (dict, list)):
                    return v
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def flatten(node, prefix=""):
    """Every scalar in the record, as dotted key -> value."""
    out = {}
    if isinstance(node, dict):
        for k, v in node.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = node
    return out


def parse_ts(s):
    if not s:
        return None
    s = s.rstrip("Z")
    if "." in s:  # trim nanoseconds to microseconds for fromisoformat
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def load(mode):
    p = DATA / f"{mode}.json"
    if not p.exists():
        sys.exit(f"missing {p}; run benchmark.sh first")
    return json.loads(p.read_text())


def dwell(run):
    fired, rotated = parse_ts(run.get("firedAt")), parse_ts(run.get("rotatedAt"))
    if fired and rotated:
        return round((rotated - fired).total_seconds(), 1), True
    return None, False


def main():
    runs = {m: load(m) for m in ("defended", "undefended")}
    dwells = {m: dwell(r) for m, r in runs.items()}

    # report.csv — one curated row per mode.
    with (HERE / "report.csv").open("w", newline="") as f:
        cols = ["mode", "defense", "firedAt", "rotatedAt", "dwellSeconds", "contained",
                "attackId", "targetPod"] + [c for c, _ in PARAMS] + ["decisionJson"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for mode, run in runs.items():
            d = run.get("decision") or {}
            sec, contained = dwells[mode]
            row = {"mode": mode, "defense": run.get("defense"), "firedAt": run.get("firedAt"),
                   "rotatedAt": run.get("rotatedAt"), "dwellSeconds": sec, "contained": contained,
                   "attackId": run.get("attackId"), "targetPod": run.get("targetPod"),
                   "decisionJson": json.dumps(d, separators=(",", ":"))}
            for col, keys in PARAMS:
                row[col] = find(d, keys)
            w.writerow(row)

    # report-parameters.csv — every scalar of each decision, long format.
    with (HERE / "report-parameters.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mode", "parameter", "value"])
        for mode, run in runs.items():
            for k, v in sorted(flatten(run.get("decision") or {}).items()):
                w.writerow([mode, k, v])

    (HERE / "report.html").write_text(render(runs, dwells))
    print("wrote report.html, report.csv, report-parameters.csv in", HERE)


def render(runs, dwells):
    def cell(v):
        return html.escape("" if v is None else str(v))

    d_sec, d_ok = dwells["defended"]
    u_sec, u_ok = dwells["undefended"]
    headline = (
        f"operator-refactored contained the foothold in <b>{d_sec}s</b>"
        if d_ok else "operator-refactored did not contain the foothold in the window"
    )
    contrast = (
        "the same attack, with actuation off, was never contained (the attacker dwells)."
        if not u_ok else f"with actuation off it still took {u_sec}s."
    )

    # Curated side-by-side.
    rows = []
    for col, keys in PARAMS:
        dv = find(runs["defended"].get("decision") or {}, keys)
        uv = find(runs["undefended"].get("decision") or {}, keys)
        rows.append(f"<tr><th>{col}</th><td>{cell(dv)}</td><td>{cell(uv)}</td></tr>")
    curated = "\n".join(rows)

    def summary(mode):
        r = runs[mode]
        sec, ok = dwells[mode]
        return (f"<tr><th>{mode}</th><td>{cell(r.get('defense'))}</td>"
                f"<td>{'yes' if ok else 'no'}</td><td>{cell(sec)}</td>"
                f"<td>{cell(r.get('attackId'))}</td><td>{cell(r.get('targetPod'))}</td></tr>")

    def full(mode):
        flat = flatten(runs[mode].get("decision") or {})
        body = "\n".join(f"<tr><th>{html.escape(k)}</th><td>{cell(v)}</td></tr>"
                         for k, v in sorted(flat.items())) or "<tr><td>(no decision captured)</td></tr>"
        return f"<details><summary>{mode}: every decision parameter ({len(flat)})</summary><table class=kv>{body}</table></details>"

    return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>LiteLLM defense benchmark</title>
<style>
:root{{--bg:#0b0e14;--fg:#e6e6e6;--muted:#9aa4b2;--line:#222a38;--accent:#28c;--ok:#2faa5d;--bad:#d9534f;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#fff;--fg:#14181f;--muted:#5a6572;--line:#e3e7ee;--accent:#15c;--ok:#1a7a40;--bad:#b23;}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:16px}}
.wrap{{max-width:980px;margin:0 auto}} h1{{font-size:22px;margin:.3em 0}} h2{{font-size:16px;color:var(--muted);margin:1.6em 0 .5em;font-weight:600}}
.head{{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:12px 0;background:linear-gradient(180deg,transparent, #ffffff06)}}
.big{{font-size:19px}} .muted{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;margin:.4em 0;font-size:14px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600}} td{{font-variant-numeric:tabular-nums;word-break:break-word}}
table.cmp td:nth-child(2){{color:var(--ok)}} table.cmp td:nth-child(3){{color:var(--bad)}}
details{{border:1px solid var(--line);border-radius:10px;margin:.5em 0;padding:.2em .8em}} summary{{cursor:pointer;padding:.5em 0;color:var(--muted)}}
table.kv th{{width:42%;font-weight:400;color:var(--muted)}} code{{color:var(--accent)}}
.foot{{color:var(--muted);font-size:12px;margin-top:2em}}
</style>
<div class=wrap>
<h1>LiteLLM defense benchmark</h1>
<div class=head><div class=big>{headline}</div><div class=muted>Compared with the same foothold undefended, {contrast}</div></div>

<h2>Attacker dwell time</h2>
<table class=cmp><tr><th>mode</th><th>defense</th><th>contained</th><th>dwell (s)</th><th>attack id</th><th>target pod</th></tr>
{summary('defended')}
{summary('undefended')}
</table>
<p class=muted>Dwell time is from the foothold firing to the actuator rotating the target pod away.
Undefended runs with the operator's actuation off (kill switch engaged): the brain still
evaluates the trusted signal, but nothing acts, so the attacker is never contained within the window.</p>

<h2>The brain's decision, side by side</h2>
<table class=cmp><tr><th>parameter</th><th>defended</th><th>undefended</th></tr>
{curated}
</table>

<h2>Every parameter (brain + decision record)</h2>
{full('defended')}
{full('undefended')}

<p class=foot>Generated by <code>deploy/benchmarks/litellm-defense/report.py</code>.
The attack is the product's own catalogue foothold — a synthetic, trusted SecurityEvent —
fired through the console API. CSVs: <code>report.csv</code>, <code>report-parameters.csv</code>.</p>
</div></html>"""


if __name__ == "__main__":
    main()
