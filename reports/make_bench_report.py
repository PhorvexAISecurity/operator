#!/usr/bin/env python3
"""Turn a benchmark JSONL (serial or parallel run) into reports/<mode>.csv and
reports/<mode>.html (a Gantt-style timeline + a result table). Pure transform.
Usage: make_bench_report.py <in.jsonl> <mode> <out_dir>"""
import csv
import datetime as dt
import html
import json
import sys

IN, MODE, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
E = html.escape

rows, summary = [], {}
for line in open(IN):
    line = line.strip()
    if not line:
        continue
    o = json.loads(line)
    (summary.update(o) if o.get("summary") else rows.append(o))
rows.sort(key=lambda r: (r.get("startOffsetSec", 0), r.get("ns", "")))

# ---- CSV ----
cols = ["mode", "ns", "attack", "route", "budget", "startOffsetSec", "endOffsetSec",
        "durationSec", "firedResultId", "status", "outcomeClass", "outcome",
        "phorvexAction", "actuated", "fireVerdict", "hasLiveRecord"]
with open(f"{OUT}/{MODE}.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)


def verdict(r):
    o, oc = (r.get("outcome") or ""), (r.get("outcomeClass") or "")
    if o == "DEFENDED":
        return "DEFENDED", "#0ca30c"
    if o == "PROTECTION_REVALIDATED":
        return "PROTECTED", "#2a78d6"
    if o == "LANDED":
        return "LANDED", "#d03b3b"
    if "NOT_LANDED" in oc:
        return "not landed", "#898781"
    if not r.get("hasLiveRecord"):
        return "fired (no live record)", "#898781"
    if oc:
        return "inconclusive", "#eda100"
    return "fired", "#898781"


wall = summary.get("wallClockSec", max((r.get("endOffsetSec", 0) for r in rows), default=0))
maxend = max((r.get("endOffsetSec", 0) for r in rows), default=1) or 1
now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ---- timeline bars ----
bars = []
for r in rows:
    lab, col = verdict(r)
    left = 100.0 * r.get("startOffsetSec", 0) / maxend
    width = max(1.2, 100.0 * r.get("durationSec", 0) / maxend)
    bars.append(
        f'<div class=lane><div class=lname>{E(r["ns"])}<span>{E(r["attack"])}</span></div>'
        f'<div class=track><div class=bar style="left:{left:.1f}%;width:{width:.1f}%;background:{col}" '
        f'title="{E(r["ns"])}/{E(r["attack"])} {r.get("startOffsetSec")}–{r.get("endOffsetSec")}s">'
        f'<span>{r.get("durationSec")}s</span></div></div>'
        f'<div class=lv style="color:{col}">{E(lab)}</div></div>'
    )

trows = "".join(
    f'<tr><td>{E(r["ns"])}</td><td>{E(r["attack"])}</td>'
    f'<td class=n>{r.get("startOffsetSec")}</td><td class=n>{r.get("endOffsetSec")}</td>'
    f'<td class=n>{r.get("durationSec")}</td>'
    f'<td><span class=pill style="background:{verdict(r)[1]}">{E(verdict(r)[0])}</span></td>'
    f'<td>{E(str(r.get("phorvexAction") or "—"))}</td><td class=n>{E(str(r.get("actuated")))}</td>'
    f'<td class=sub>{E(str(r.get("firedResultId") or ""))}</td></tr>'
    for r in rows
)

title = f"{'Parallel' if MODE=='parallel' else 'Serial'} live-attack benchmark"
other = "serial" if MODE == "parallel" else "parallel"
css = """
:root{--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--sub:#52514e;--muted:#898781;--line:#e1e0d9}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--sub:#c3c2b7;--muted:#898781;--line:#2c2c2a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:30px 16px 70px}
h1{font-size:23px;margin:0 0 2px}.lede{color:var(--sub);margin:0 0 18px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 22px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 16px;min-width:150px}
.kpi .v{font-size:26px;font-weight:650}.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:15px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.lane{display:grid;grid-template-columns:170px 1fr 150px;gap:10px;align-items:center;margin:5px 0}
.lname{font-size:12.5px;font-weight:600}.lname span{display:block;color:var(--muted);font-weight:400;font-size:11.5px}
.track{position:relative;height:22px;background:var(--surface);border:1px solid var(--line);border-radius:6px}
.bar{position:absolute;top:2px;height:16px;border-radius:4px;min-width:3px}
.bar span{position:absolute;right:4px;top:-1px;font-size:10.5px;color:#fff;line-height:16px}
.lv{font-size:12px;font-weight:600}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin:4px 0 0 180px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.n{text-align:right;font-variant-numeric:tabular-nums}.sub{color:var(--muted);font-size:11px}
.pill{color:#fff;border-radius:999px;padding:2px 9px;font-size:11.5px;font-weight:600;white-space:nowrap}
footer{color:var(--muted);font-size:12px;margin-top:26px}a{color:#2a78d6}
"""
timeline = "".join(bars)
html_doc = f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{E(title)}</title>
<meta name=description content="Wall-clock timeline and outcomes for the {E(MODE)} live-attack benchmark run.">
<style>{css}</style></head><body><div class=wrap>
<h1>{E(title)}</h1>
<p class=lede>One armed Live attack per app, fired {'all at once (across apps)' if MODE=='parallel' else 'one at a time, in order'} through the Console on <code>phorvex-dev-eks</code>. Generated {now}. Companion: <a href="{other}.html">{other}.html</a>.</p>
<div class=kpis>
<div class=kpi><div class=v>{wall:.0f}s</div><div class=l>Total wall-clock</div></div>
<div class=kpi><div class=v>{len(rows)}</div><div class=l>Attacks fired</div></div>
<div class=kpi><div class=v>{sum(1 for r in rows if verdict(r)[0] in ('DEFENDED','PROTECTED'))}</div><div class=l>Defended / protected</div></div>
<div class=kpi><div class=v>{max((r.get('durationSec',0) for r in rows),default=0):.0f}s</div><div class=l>Longest single attack</div></div>
</div>
<h2>Execution timeline (bar = when each attack ran, within the {wall:.0f}s window)</h2>
{timeline}
<div class=axis><span>0s</span><span>{maxend/2:.0f}s</span><span>{maxend:.0f}s</span></div>
<h2>Per-attack results</h2>
<table><thead><tr><th>App</th><th>Attack</th><th>Start</th><th>End</th><th>Dur</th><th>Verdict</th><th>Actuator</th><th>Actuated</th><th>Run id</th></tr></thead>
<tbody>{trows}</tbody></table>
<footer>Offsets are seconds from the start of this run. In parallel mode the bars overlap (attacks on different apps run at once; the Console serializes same-app runs); in serial mode they are back-to-back. Verdicts: DEFENDED = brain action contained a real landing; PROTECTED = prior protection revalidated; LANDED = attack succeeded uncontained; "fired (no live record)" = the workload foothold route records a manager disposition, not a behavioural live result. Raw rows: {E(MODE)}.csv.</footer>
</div></body></html>"""
open(f"{OUT}/{MODE}.html", "w").write(html_doc)
print(f"wrote {OUT}/{MODE}.html and {OUT}/{MODE}.csv from {len(rows)} attacks; wall={wall}s")
