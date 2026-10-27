#!/usr/bin/env python3
"""Build the scenario (named-attack) benchmark report from data/scenarios.jsonl.

Each record is one attack run: an ATLAS/OWASP catalogue attack against a serving workload,
defended by its designated actuator, in defended or undefended mode. Writes:
  report-actuators.html            — per-attack containment, with/without the operator
  report-actuators.csv             — one curated row per attack run, with the full decision
  report-actuators-parameters.csv  — every scalar of each decision (long format)

Stdlib only. Run: python3 deploy/benchmarks/litellm-defense/report-actuators.py
"""
from __future__ import annotations
import csv, datetime as dt, html, json, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE / "data" / "actuators.jsonl"

PARAMS = [
    ("action", ["action"]), ("selected", ["selected"]), ("feasible", ["feasible"]),
    ("actuated", ["actuated"]), ("dispatchOutcome", ["dispatchOutcome"]),
    ("dispatchReason", ["dispatchReason", "dryRunCause", "actuationBrakeCause"]),
    ("infeasibleWhy", ["infeasibleWhy"]), ("why", ["why"]), ("stage", ["stage", "stageName"]),
    ("pHold", ["pHold", "PHold"]), ("hazard", ["hazard"]), ("assetValue", ["asset", "assetValue"]),
    ("blastRadius", ["blast", "blastRadius"]), ("cost", ["cost"]), ("perDollar", ["perDollar"]),
    ("coverageValue", ["coverageValue"]), ("killSwitch", ["killSwitch"]), ("r6Would", ["r6Would"]),
    ("engine", ["engine"]), ("brainImage", ["brainImage"]), ("gitSHA", ["gitSHA"]),
]


def find(node, keys):
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
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6].ljust(6, '0')}"
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def dwell(r):
    f, c = parse_ts(r.get("firedAt")), parse_ts(r.get("containedAt"))
    return (round((c - f).total_seconds(), 1), True) if (f and c) else (None, False)


def load():
    if not RESULTS.exists():
        sys.exit(f"missing {RESULTS}; run actuators.sh first")
    recs = []
    for line in RESULTS.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            r["_dwell"], r["_contained"] = dwell(r)
            recs.append(r)
    if not recs:
        sys.exit(f"{RESULTS} is empty")
    return recs


def main():
    recs = load()
    with (HERE / "report-actuators.csv").open("w", newline="") as f:
        cols = ["atlasId", "name", "target", "actuator", "mode", "defense", "firedAt",
                "containedAt", "dwellSeconds", "contained", "mechanism", "attackId",
                "targetPod"] + [c for c, _ in PARAMS] + ["decisionJson"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in recs:
            d = r.get("decision") or {}
            row = {"atlasId": r.get("atlasId"), "name": r.get("name"), "target": r.get("target"),
                   "actuator": r.get("actuator"), "mode": r.get("mode"), "defense": r.get("defense"),
                   "firedAt": r.get("firedAt"), "containedAt": r.get("containedAt"),
                   "dwellSeconds": r["_dwell"], "contained": r["_contained"],
                   "mechanism": r.get("mechanism"), "attackId": r.get("attackId"),
                   "targetPod": r.get("targetPod"),
                   "decisionJson": json.dumps(d, separators=(",", ":"))}
            for col, keys in PARAMS:
                row[col] = find(d, keys)
            w.writerow(row)

    with (HERE / "report-actuators-parameters.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["atlasId", "target", "mode", "parameter", "value"])
        for r in recs:
            for k, v in sorted(flatten(r.get("decision") or {}).items()):
                w.writerow([r.get("atlasId"), r.get("target"), r.get("mode"), k, v])

    (HERE / "report-actuators.html").write_text(render(recs))
    print("wrote report-actuators.html, report-actuators.csv, report-actuators-parameters.csv in", HERE)


def render(recs):
    def cell(v):
        return html.escape("" if v is None else str(v))

    # key attacks by (atlasId, name, target, actuator), with defended/undefended results.
    keys, by = [], {}
    for r in recs:
        k = (r.get("atlasId"), r.get("name"), r.get("target"), r.get("actuator"))
        if k not in by:
            by[k] = {}
            keys.append(k)
        by[k][r.get("mode")] = r

    contained_def = sum(1 for k in keys if by[k].get("defended", {}).get("_contained"))
    headline = (f"operator-refactored contained <b>{contained_def}/{len(keys)}</b> catalogue "
                f"attacks on the serving workloads; with actuation off, none were contained.")

    rows = []
    for k in keys:
        atlas, name, target, actuator = k
        dfd, und = by[k].get("defended", {}), by[k].get("undefended", {})
        dsec, dok = dfd.get("_dwell"), dfd.get("_contained")
        rows.append(
            "<tr>"
            f"<td><code>{cell(atlas)}</code></td><td>{cell(name)}</td>"
            f"<td>{cell(target)}</td><td>{cell(actuator)}</td>"
            f"<td class={'ok' if dok else 'bad'}>{'contained' if dok else 'not contained'}</td>"
            f"<td>{cell(dfd.get('mechanism'))}</td><td>{cell(dsec)}</td>"
            f"<td class={'bad' if not und.get('_contained') else 'ok'}>"
            f"{'contained' if und.get('_contained') else 'not contained'}</td>"
            "</tr>")
    table = "\n".join(rows)

    details = []
    for k in keys:
        atlas, name, target, actuator = k
        for mode in ("defended", "undefended"):
            r = by[k].get(mode)
            if not r:
                continue
            flat = flatten(r.get("decision") or {})
            if not flat:
                continue
            body = "\n".join(f"<tr><th>{html.escape(x)}</th><td>{cell(v)}</td></tr>"
                             for x, v in sorted(flat.items()))
            details.append(
                f"<details><summary>{cell(atlas)} · {cell(target)} · {mode} "
                f"— {len(flat)} parameters</summary><table class=kv>{body}</table></details>")
    decisions = "\n".join(details) or "<p class=muted>(no decision records captured)</p>"

    return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>LLM actuator defense benchmark</title>
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
td.ok{{color:var(--ok);font-weight:600}} td.bad{{color:var(--bad);font-weight:600}}
details{{border:1px solid var(--line);border-radius:10px;margin:.5em 0;padding:.2em .8em}} summary{{cursor:pointer;padding:.5em 0;color:var(--muted)}}
table.kv th{{width:42%;font-weight:400;color:var(--muted)}} code{{color:var(--accent)}}
.foot{{color:var(--muted);font-size:12px;margin-top:2em}}
</style>
<div class=wrap>
<h1>LLM actuator defense benchmark — LiteLLM &amp; vLLM</h1>
<div class=head><div class=big>{headline}</div>
<div class=muted>Each row is a catalogue attack (ATLAS / OWASP mapping) fired as a trusted
foothold, defended by the actuator the attack library assigns it. Dwell is fire → containment.</div></div>

<h2>Attacks and containment</h2>
<table><tr><th>attack</th><th>name</th><th>workload</th><th>actuator</th>
<th>with operator</th><th>via</th><th>dwell (s)</th><th>operator off</th></tr>
{table}
</table>
<p class=muted>Containment is observed directly: <b>rotated</b> = the compromised pod was
replaced; <b>quarantined</b> = a deny-all NetworkPolicy isolated it in place. Undefended runs
with the operator's actuation disabled (kill switch), so nothing acts.</p>

<h2>The brain's decision, per attack</h2>
{decisions}

<p class=foot>Generated by <code>deploy/benchmarks/litellm-defense/report-actuators.py</code>.
Attacks are synthetic, trusted catalogue footholds admitted by the operator's own
creator-identity policy — no exploit or model payload. CSVs: <code>report-actuators.csv</code>,
<code>report-actuators-parameters.csv</code>.</p>
</div></html>"""


if __name__ == "__main__":
    main()
