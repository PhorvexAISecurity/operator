#!/usr/bin/env python3
"""Build the LiteLLM/vLLM defense benchmark reports from the collected attacks.

Reads data/results.jsonl (one JSON record per attack, written by benchmark.sh) and writes:
  report.html             — per-workload, per-mode dwell-time contrast and every brain decision
  report.csv              — one curated row per attack, with the full decision record
  report-parameters.csv   — every scalar parameter of each attack's decision (long format)

Stdlib only. Run:  python3 deploy/benchmarks/litellm-defense/report.py
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import json
import pathlib
import statistics
import sys

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"
RESULTS = DATA / "results.jsonl"

# Curated columns: the brain/decision parameters the user asked for. Each is
# (column, list-of-keys-to-search-for anywhere in the decision record).
PARAMS = [
    ("action", ["action"]),
    ("selected", ["selected"]),
    ("feasible", ["feasible"]),
    ("actuated", ["actuated"]),
    ("dispatchOutcome", ["dispatchOutcome"]),
    ("dispatchReason", ["dispatchReason", "dryRunCause", "actuationBrakeCause"]),
    ("infeasibleWhy", ["infeasibleWhy"]),
    ("why", ["why"]),
    ("stage", ["stage", "stageName"]),
    ("nextStage", ["nextStage"]),
    ("pHold", ["pHold", "PHold"]),
    ("hazard", ["hazard"]),
    ("assetValue", ["asset", "assetValue"]),
    ("blastRadius", ["blast", "blastRadius"]),
    ("cost", ["cost"]),
    ("perDollar", ["perDollar"]),
    ("coverageValue", ["coverageValue"]),
    ("lambda", ["lambda"]),
    ("dryRun", ["dryRun"]),
    ("killSwitch", ["killSwitch"]),
    ("r6Would", ["r6Would"]),
    ("r6Note", ["r6Note"]),
    ("engine", ["engine"]),
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
    if "." in s:  # normalise any fractional precision to microseconds for fromisoformat
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6].ljust(6, '0')}"
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def dwell(rec):
    fired, rotated = parse_ts(rec.get("firedAt")), parse_ts(rec.get("rotatedAt"))
    if fired and rotated:
        return round((rotated - fired).total_seconds(), 1), True
    return None, False


def load():
    if not RESULTS.exists():
        sys.exit(f"missing {RESULTS}; run benchmark.sh first")
    recs = []
    for line in RESULTS.read_text().splitlines():
        line = line.strip()
        if line:
            r = json.loads(line)
            r["_dwell"], r["_contained"] = dwell(r)
            recs.append(r)
    if not recs:
        sys.exit(f"{RESULTS} is empty; run benchmark.sh first")
    return recs


def groups(recs):
    """(target, mode) -> list of records, in a stable order."""
    g = {}
    for r in recs:
        g.setdefault((r["target"], r["mode"]), []).append(r)
    for v in g.values():
        v.sort(key=lambda r: r.get("attempt", 0))
    return g


def main():
    recs = load()

    # report.csv — one curated row per attack.
    with (HERE / "report.csv").open("w", newline="") as f:
        cols = ["target", "mode", "defense", "attempt", "firedAt", "rotatedAt", "dwellSeconds",
                "contained", "mechanism", "attackId", "targetPod"] + [c for c, _ in PARAMS] + ["decisionJson"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in recs:
            d = r.get("decision") or {}
            row = {"target": r["target"], "mode": r["mode"], "defense": r.get("defense"),
                   "attempt": r.get("attempt"), "firedAt": r.get("firedAt"),
                   "rotatedAt": r.get("rotatedAt"), "dwellSeconds": r["_dwell"],
                   "contained": r["_contained"], "mechanism": r.get("mechanism"),
                   "attackId": r.get("attackId"), "targetPod": r.get("targetPod"),
                   "decisionJson": json.dumps(d, separators=(",", ":"))}
            for col, keys in PARAMS:
                row[col] = find(d, keys)
            w.writerow(row)

    # report-parameters.csv — every scalar of each attack's decision, long format.
    with (HERE / "report-parameters.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "mode", "attempt", "parameter", "value"])
        for r in recs:
            for k, v in sorted(flatten(r.get("decision") or {}).items()):
                w.writerow([r["target"], r["mode"], r.get("attempt"), k, v])

    (HERE / "report.html").write_text(render(recs))
    print("wrote report.html, report.csv, report-parameters.csv in", HERE)


def summarise(rs):
    """contained count, and mean/min/max dwell over the contained attacks."""
    n = len(rs)
    contained = [r for r in rs if r["_contained"]]
    dwells = [r["_dwell"] for r in contained]
    mean = round(statistics.mean(dwells), 1) if dwells else None
    return n, len(contained), mean, (min(dwells) if dwells else None), (max(dwells) if dwells else None)


def render(recs):
    def cell(v):
        return html.escape("" if v is None else str(v))

    g = groups(recs)
    targets = sorted({t for t, _ in g})

    # Headline: defended dwell on the proxy, the first workload we can show a number for.
    head_bits = []
    for t in targets:
        n, c, mean, lo, hi = summarise(g.get((t, "defended"), []))
        if mean is not None:
            head_bits.append(f"<b>{t}</b> contained in ~<b>{mean}s</b> ({c}/{n})")
    headline = "operator-refactored " + ("; ".join(head_bits) if head_bits
               else "did not contain the footholds in the window")

    # Per-workload summary: defended vs undefended, side by side.
    srows = []
    for t in targets:
        for mode in ("defended", "undefended"):
            n, c, mean, lo, hi = summarise(g.get((t, mode), []))
            if n == 0:
                continue
            rng = "" if mean is None else f"{lo}–{hi}"
            srows.append(f"<tr><th>{cell(t)}</th><td>{mode}</td><td>{c}/{n}</td>"
                         f"<td>{cell(mean)}</td><td>{cell(rng)}</td></tr>")
    summary = "\n".join(srows)

    # Per-attack detail across every workload, mode and attempt.
    arows = []
    for t in targets:
        for mode in ("defended", "undefended"):
            for r in g.get((t, mode), []):
                d = r.get("decision") or {}
                arows.append(
                    f"<tr><th>{cell(t)}</th><td>{mode}</td><td>{cell(r.get('attempt'))}</td>"
                    f"<td class={'ok' if r['_contained'] else 'bad'}>{'yes' if r['_contained'] else 'no'}</td>"
                    f"<td>{cell(r['_dwell'])}</td>"
                    f"<td>{cell(find(d, ['action']))}</td>"
                    f"<td>{cell(r.get('mechanism'))}</td>"
                    f"<td>{cell(find(d, ['dispatchOutcome']))}</td>"
                    f"<td>{cell(find(d, ['cost']))}</td>"
                    f"<td>{cell(find(d, ['why']))}</td>"
                    f"<td class=pod>{cell(r.get('targetPod'))}</td></tr>")
    attacks = "\n".join(arows)

    # Full decision parameters, one collapsible block per attack that recorded a decision.
    details = []
    for t in targets:
        for mode in ("defended", "undefended"):
            for r in g.get((t, mode), []):
                flat = flatten(r.get("decision") or {})
                if not flat:
                    continue
                body = "\n".join(f"<tr><th>{html.escape(k)}</th><td>{cell(v)}</td></tr>"
                                 for k, v in sorted(flat.items()))
                details.append(
                    f"<details><summary>{cell(t)} · {mode} · attack #{cell(r.get('attempt'))} "
                    f"— {len(flat)} parameters</summary><table class=kv>{body}</table></details>")
    decisions = "\n".join(details) or "<p class=muted>(no decision records captured)</p>"

    return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>LiteLLM vLLM defense benchmark</title>
<style>
:root{{--bg:#0b0e14;--fg:#e6e6e6;--muted:#9aa4b2;--line:#222a38;--accent:#28c;--ok:#2faa5d;--bad:#d9534f;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#fff;--fg:#14181f;--muted:#5a6572;--line:#e3e7ee;--accent:#15c;--ok:#1a7a40;--bad:#b23;}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:16px}}
.wrap{{max-width:1040px;margin:0 auto}} h1{{font-size:22px;margin:.3em 0}} h2{{font-size:16px;color:var(--muted);margin:1.6em 0 .5em;font-weight:600}}
.head{{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:12px 0;background:linear-gradient(180deg,transparent,#ffffff06)}}
.big{{font-size:19px}} .muted{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;margin:.4em 0;font-size:14px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600}} td{{font-variant-numeric:tabular-nums;word-break:break-word}}
td.ok{{color:var(--ok);font-weight:600}} td.bad{{color:var(--bad);font-weight:600}} td.pod{{font-size:12px;color:var(--muted)}}
details{{border:1px solid var(--line);border-radius:10px;margin:.5em 0;padding:.2em .8em}} summary{{cursor:pointer;padding:.5em 0;color:var(--muted)}}
table.kv th{{width:42%;font-weight:400;color:var(--muted)}} code{{color:var(--accent)}}
.foot{{color:var(--muted);font-size:12px;margin-top:2em}}
</style>
<div class=wrap>
<h1>LiteLLM / vLLM defense benchmark</h1>
<div class=head><div class=big>{headline}</div>
<div class=muted>Each workload is attacked several times with and without the operator acting.
Dwell time is from the foothold firing to the actuator rotating the target pod away.</div></div>

<h2>Containment by workload</h2>
<table><tr><th>workload</th><th>mode</th><th>contained</th><th>mean dwell (s)</th><th>range (s)</th></tr>
{summary}
</table>
<p class=muted>Undefended runs with the operator's actuation disabled (kill switch engaged):
nothing rotates the target, so the attacker is never contained within the observation window.</p>

<h2>Every attack</h2>
<table><tr><th>workload</th><th>mode</th><th>#</th><th>contained</th><th>dwell (s)</th>
<th>action</th><th>via</th><th>dispatch</th><th>cost</th><th>why</th><th>target pod</th></tr>
{attacks}
</table>

<h2>The brain's decision, per attack</h2>
{decisions}

<p class=foot>Generated by <code>deploy/benchmarks/litellm-defense/report.py</code>.
The attack is the product's own catalogue foothold — a synthetic, trusted SecurityEvent —
admitted by the operator's own creator-identity policy. CSVs: <code>report.csv</code>,
<code>report-parameters.csv</code>.</p>
</div></html>"""


if __name__ == "__main__":
    main()
