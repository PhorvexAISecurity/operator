#!/usr/bin/env python3
"""Render reports/<mode>.csv and reports/<mode>.html from a benchmark JSONL that
carries the full exact result record per attack. HTML = KPIs + execution timeline
+ per-attack brain pipeline (fire -> attack executed -> SecurityEvent -> decision
-> actuation -> post-action check -> verdict) + results table, matching the
test_coverage detail. Usage: make_bench_report.py <in.jsonl> <mode> <out_dir>"""
import csv, datetime as dt, html, json, sys

IN, MODE, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
E = html.escape

import re


def parse_reason(reason):
    """Pull the one-step objective math out of the decision reason string."""
    out = {}
    if not reason:
        return out
    for key, pat in (("strictGain", r"strict gain (-?[\d.]+)"), ("fullValue_S", r"fullValue=(-?[\d.]+)"),
                     ("ECost", r"ECost=(-?[\d.]+)"), ("lambda", r"lambda\w*=(-?[\d.]+)"),
                     ("hazard", r"hazard=(-?[\d.]+)"), ("pHold", r"pHold=(-?[\d.]+)")):
        m = re.search(pat, reason)
        if m:
            out[key] = m.group(1)
    m = re.search(r"stage=([^\s]+)", reason)
    if m:
        out["stage"] = m.group(1)
    return out


def brain_params(rec):
    de = (rec or {}).get("decisionEvidence") or {}
    parsed = parse_reason(de.get("reason"))
    econ = {k: rec.get(k) for k in ("lambda", "lambdaAvailable", "pHold", "coveredFacts", "perDollar",
            "economicsVersion", "economicsAvailable", "disruptionAversion", "uptimeBefore", "uptimeDip",
            "uptimeAfter") if rec and rec.get(k) is not None}
    return parsed, de, econ, (rec or {}).get("cost") or {}
rows, summary = [], {}
for line in open(IN):
    line = line.strip()
    if not line:
        continue
    o = json.loads(line)
    (summary.update(o) if o.get("summary") else rows.append(o))
rows.sort(key=lambda r: (r.get("startOffsetSec", 0), r.get("ns", "")))

CSV_COLS = ["mode", "ns", "attack", "route", "expectedActuator", "budget", "startOffsetSec",
            "endOffsetSec", "durationSec", "firedResultId", "status", "outcomeClass", "outcome",
            "phorvexAction", "actuated", "decisionAction", "fireVerdict", "hasLiveRecord",
            "strictGain", "fullValue_S", "ECost", "lambda", "hazard", "pHold", "stage",
            "valueAtRisk", "savings", "feasible", "killSwitch", "trustVerdict", "mutationKind",
            "dispatchOutcome", "decisionId", "tickId", "brainImage", "gitSha", "candidatesEvaluated"]
with open(f"{OUT}/{MODE}.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=CSV_COLS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        rec = r.get("record") or {}
        parsed, de, econ, cost = brain_params(rec)
        row = dict(r)
        row.update(parsed)
        row.setdefault("lambda", econ.get("lambda"))
        row.setdefault("pHold", econ.get("pHold"))
        row.update({"valueAtRisk": cost.get("valueAtRisk"), "savings": cost.get("savings"),
                    "feasible": de.get("feasible"), "killSwitch": de.get("killSwitch"),
                    "trustVerdict": de.get("trustVerdict"), "mutationKind": de.get("mutationKind"),
                    "dispatchOutcome": de.get("dispatchOutcome"), "decisionId": de.get("decisionId"),
                    "tickId": de.get("tickId"), "brainImage": de.get("brainImage"), "gitSha": de.get("gitSha"),
                    "candidatesEvaluated": len(de.get("actionStatus") or [])})
        w.writerow(row)

CH = {"ok": "#0ca30c", "fail": "#d03b3b", "partial": "#eda100", "skip": "#898781", "na": "#898781"}


def probe_of(rec):
    for k, v in (rec or {}).items():
        if k.endswith("Probe") and isinstance(v, dict):
            return k, v
    return "", {}


def verdict(r):
    rec = r.get("record") or {}
    o, oc = (rec.get("outcome") or ""), (rec.get("outcomeClass") or "")
    fv = (r.get("fireVerdict") or "")
    if o == "DEFENDED":
        return "DEFENDED", "#0ca30c"
    if o == "PROTECTION_REVALIDATED":
        return "PROTECTED", "#2a78d6"
    if o == "LANDED":
        return "LANDED", "#d03b3b"
    if "scope" in fv or fv in ("setup-failed", "profile-failed", "failed"):
        return "rejected / did not fire", "#d03b3b"
    if "NOT_LANDED" in oc:
        return "attack did not land", "#898781"
    if oc == "effect-only" or "unverified" in oc or oc.endswith("UNKNOWN") or "unsupported" in oc or r.get("status") == "partial":
        return "mechanism / inconclusive", "#eda100"
    if not r.get("hasLiveRecord"):
        return "fired (no live record)", "#898781"
    return "fired", "#898781"


def attack_actuated(rec):
    _, p = probe_of(rec)
    de = (rec or {}).get("decisionEvidence") or {}
    if (rec or {}).get("actuated") or p.get("actuated") or p.get("dispatchPath") == "SELECTED_ACTUATED":
        return True
    return bool(de.get("actuated") and de.get("correlation") == "exact-event-uid")


def stages(r):
    rec, out = r.get("record") or {}, []
    fv = r.get("fireVerdict") or ""
    if not rec:
        if "scope" in fv or fv in ("setup-failed", "profile-failed", "failed"):
            out.append(("Fire", "fail", f"Console rejected before firing: {fv}"))
        else:
            out.append(("Fire", "ok", f"Accepted ({fv or 'ok'})"))
            out.append(("Live verdict", "skip", "Workload foothold route records a manager disposition, not a behavioural live record."))
        return out
    pk, p = probe_of(rec)
    stim, de, eff = rec.get("stimulusEvidence") or {}, rec.get("decisionEvidence") or {}, rec.get("effectEvidence") or {}
    out.append(("Fire & preflight", "ok", f"POST {r['route']} → result {rec.get('id')}"))
    landed = {"voiceMemoryProbe": ("firstContextObserved", "cross-call context planted/seen"),
              "voiceOutputProbe": ("firstAssistantDisclosure", "model disclosed the marker"),
              "voiceAgencyProbe": ("firstModelCallback", "model made the refund callback"),
              "voiceMCPProbe": ("firstDescriptorFetched", "poisoned descriptor fetched"),
              "litellmLiveProbe": ("initialAcceptedWork", "owned trial credential got real work")}
    if pk in landed:
        fld, desc = landed[pk]
        ok = bool(p.get(fld))
        out.append(("Attack executed", "ok" if ok else "skip", desc if ok else f"did not land ({fld}=false)"))
    elif pk == "endpointLeaseProbe":
        out.append(("Attack executed", "ok", f"stolen A → HTTP {p.get('postAStatus')}, legit B → HTTP {p.get('postBStatus')}"))
    elif stim:
        out.append(("Attack executed", "partial" if not stim.get("behavioralExecuted") else "ok",
                    ("synthetic signal only. " if not stim.get("behavioralExecuted") else "") + (stim.get("limitation") or "")[:160]))
    else:
        out.append(("Attack executed", "partial", "see probe"))
    ev = stim.get("eventName") or p.get("eventName") or ""
    out.append(("SecurityEvent", "ok" if ev else "skip", f"{ev} rule={stim.get('eventRule','—')}" if ev else "no event (only after a real landing / qualifying input)"))
    act = attack_actuated(rec)
    exact = act or de.get("correlation") == "exact-event-uid" or bool(p.get("selectedDecisionID") or p.get("selectionDecisionID"))
    sel = (de.get("action") or p.get("selectedAction") or "") if exact else ""
    if sel:
        out.append(("Brain decision", "ok" if sel not in ("noop", "") else "skip", f"selected {sel}" + (f" · {(de.get('reason') or '')[:120]}" if de.get("reason") else "")))
    else:
        out.append(("Brain decision", "skip", "no exact decision bound to this attack"))
    if act:
        det = []
        if de.get("dispatchOutcome"):
            det.append(f"dispatch {de['dispatchOutcome']} ({de.get('mutationKind')})")
        if p.get("dispatchPath"):
            det.append(p["dispatchPath"])
        out.append(("Actuation", "ok", "; ".join(det) or f"actuated {rec.get('phorvexAction') or de.get('action') or ''}"))
    else:
        out.append(("Actuation", "skip", "nothing actuated for this attack"))
    if eff:
        out.append(("Post-action check", "ok" if eff.get("observed") else "fail", f"{eff.get('kind')}: observed={eff.get('observed')}"))
    elif pk == "litellmLiveProbe" and p.get("accepted"):
        out.append(("Post-action check", "ok" if p.get("replayBlockedBeforeUpstream") else "fail",
                    f"replay blocked={p.get('replayBlockedBeforeUpstream')}; benign kept={p.get('benignContinuity')}"))
    elif pk == "endpointLeaseProbe":
        out.append(("Post-action check", "ok" if p.get("protectionRevalidated") else "fail", f"every Pod effective={p.get('everyServingPodEffective')}"))
    elif pk == "voiceMemoryProbe" and rec.get("outcome") in ("DEFENDED", "LANDED"):
        out.append(("Post-action check", "ok" if not p.get("repeatPoisonObserved") else "fail", f"repeat poison={p.get('repeatPoisonObserved')}; benign kept={p.get('repeatBenignObserved')}"))
    else:
        out.append(("Post-action check", "skip", "not reached"))
    lab, col = verdict(r)
    out.append(("Verdict", "ok" if col in ("#0ca30c", "#2a78d6") else ("fail" if col == "#d03b3b" else "partial"), lab))
    return out


wall = summary.get("wallClockSec", max((r.get("endOffsetSec", 0) for r in rows), default=0))
maxend = max((r.get("endOffsetSec", 0) for r in rows), default=1) or 1
now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

bars = "".join(
    f'<div class=lane><div class=lname>{E(r["ns"])}<span>{E(r["attack"])}</span></div>'
    f'<div class=track><div class=bar style="left:{100.0*r.get("startOffsetSec",0)/maxend:.1f}%;'
    f'width:{max(0.8,100.0*r.get("durationSec",0)/maxend):.1f}%;background:{verdict(r)[1]}" '
    f'title="{E(r["ns"])}/{E(r["attack"])} {r.get("startOffsetSec")}-{r.get("endOffsetSec")}s"></div></div>'
    f'<div class=lv style="color:{verdict(r)[1]}">{E(verdict(r)[0])}</div></div>' for r in rows)

trows = "".join(
    f'<tr><td>{E(r["ns"])}</td><td><a href="#{E(r["ns"]+"-"+r["attack"])}">{E(r["attack"])}</a></td>'
    f'<td class=n>{r.get("startOffsetSec")}</td><td class=n>{r.get("durationSec")}</td>'
    f'<td><span class=pill style="background:{verdict(r)[1]}">{E(verdict(r)[0])}</span></td>'
    f'<td class=sub>{E(str(r.get("expectedActuator") or "—"))}</td>'
    f'<td>{E(str((r.get("record") or {}).get("phorvexAction") or r.get("decisionAction") or "—"))}</td>'
    f'<td class=n>{E(str(r.get("actuated")))}</td></tr>' for r in rows)

def kv_grid(pairs):
    cells = "".join(f'<div class=kv><span class=k>{E(k)}</span><span class=val>{E(str(v))}</span></div>'
                    for k, v in pairs if v is not None and v != "")
    return f'<div class=grid>{cells}</div>' if cells else ""


def brain_block(r):
    rec = r.get("record") or {}
    if not rec:
        return '<div class=brain><div class=bt>Brain parameters</div><p class=none>No live record for this route; no brain decision was recorded.</p></div>'
    parsed, de, econ, cost = brain_params(rec)
    obj = kv_grid([
        ("strict gain", parsed.get("strictGain")), ("fullValue S", parsed.get("fullValue_S")),
        ("ECost", parsed.get("ECost")), ("lambda", parsed.get("lambda") or econ.get("lambda")),
        ("hazard", parsed.get("hazard")), ("pHold", parsed.get("pHold") or econ.get("pHold")),
        ("stage", parsed.get("stage")), ("covered facts", econ.get("coveredFacts")),
        ("value at risk", cost.get("valueAtRisk")), ("savings", cost.get("savings")),
        ("economics", econ.get("economicsVersion")),
        ("uptime before/dip/after", (f"{rec.get('uptimeBefore')}/{rec.get('uptimeDip')}/{rec.get('uptimeAfter')}" if rec.get('uptimeBefore') is not None else None)),
    ])
    _, pr = probe_of(rec)
    ident = kv_grid([
        ("decision action", de.get("action") or pr.get("selectedAction")),
        ("probe decisionId", pr.get("selectedDecisionID") or pr.get("selectionDecisionID")),
        ("dispatch path", pr.get("dispatchPath")), ("event UID", de.get("eventUid") or pr.get("eventUID")),
        ("selected", de.get("selected")), ("feasible", de.get("feasible")),
        ("actuated", de.get("actuated")), ("kill switch", de.get("killSwitch")), ("trust", de.get("trustVerdict")),
        ("mutation", de.get("mutationKind")), ("dispatch", (f"{de.get('dispatchOutcome')} ({de.get('dispatchReason')})" if de.get("dispatchOutcome") else None)),
        ("event rule", de.get("eventRule")), ("decisionId", de.get("decisionId")), ("tickId", de.get("tickId")),
        ("policyUid", de.get("policyUid")), ("brain image", de.get("brainImage")), ("git sha", de.get("gitSha")),
    ])
    cands = de.get("actionStatus") or []
    ct = ""
    if cands:
        def cc(st):
            return {"selected": "#0ca30c", "candidate": "#2a78d6", "eligible": "#2a78d6"}.get(st, "#898781")
        crows = "".join(f'<tr><td>{E(c.get("action",""))}</td>'
                        f'<td><span class=cst style="color:{cc(c.get("status"))}">{E(str(c.get("status")))}</span></td>'
                        f'<td class=sub>{E(str(c.get("reason") or c.get("exclusionKind") or ""))}</td></tr>' for c in cands)
        ct = (f'<div class=ctitle>Admissible-set evaluation — {len(cands)} candidates (the Runtime Math Gate)</div>'
              f'<table class=cand><thead><tr><th>Action</th><th>Status</th><th>Reason / exclusion</th></tr></thead><tbody>{crows}</tbody></table>')
    raw = de.get("reason")
    rawline = f'<div class=raw>objective: <code>{E(raw)}</code></div>' if raw else ""
    return (f'<div class=brain><div class=bt>Brain parameters — one-step objective J = S − βₙCNorm − β_fCFlow (here S − λ·ECost)</div>'
            f'{rawline}{obj}'
            f'<div class=bt2>Decision identity &amp; dispatch</div>{ident}{ct}</div>')


def build_card(r):
    sts = "".join(f'<li><span class=dot style="background:{CH[st]}"></span><div><b>{E(n)}</b><span class=sd>{E(d)}</span></div></li>'
                  for n, st, d in stages(r))
    return (f'<section class=card id="{E(r["ns"]+"-"+r["attack"])}"><div class=ch><h3>{E(r["attack"])}</h3>'
            f'<span class=ns>{E(r["ns"])}</span><span class=pill style="background:{verdict(r)[1]}">{E(verdict(r)[0])}</span></div>'
            f'<div class=meta>expected <code>{E(str(r.get("expectedActuator") or "—"))}</code> · ran {r.get("startOffsetSec")}–{r.get("endOffsetSec")}s ({r.get("durationSec")}s) · run <code>{E(str(r.get("firedResultId") or "—"))}</code></div>'
            f'<ol class=pipe>{sts}</ol>{brain_block(r)}</section>')


cards = "".join(build_card(r) for r in rows)

title = f"{'Parallel' if MODE=='parallel' else 'Serial'} live-attack benchmark"
other = "serial" if MODE == "parallel" else "parallel"
defended = sum(1 for r in rows if verdict(r)[0] in ("DEFENDED", "PROTECTED"))
css = """
:root{--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--sub:#52514e;--muted:#898781;--line:#e1e0d9}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--sub:#c3c2b7;--muted:#898781;--line:#2c2c2a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:30px 16px 70px}h1{font-size:23px;margin:0 0 2px}.lede{color:var(--sub);margin:0 0 16px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 20px}.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 16px;min-width:140px}
.kpi .v{font-size:25px;font-weight:650}.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:15px;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.lane{display:grid;grid-template-columns:165px 1fr 150px;gap:10px;align-items:center;margin:4px 0}
.lname{font-size:12px;font-weight:600}.lname span{display:block;color:var(--muted);font-weight:400;font-size:11px}
.track{position:relative;height:18px;background:var(--surface);border:1px solid var(--line);border-radius:5px}
.bar{position:absolute;top:2px;height:12px;border-radius:3px;min-width:2px}.lv{font-size:11.5px;font-weight:600}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin:4px 0 0 175px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:6px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);font-size:12.5px;vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}tr:last-child td{border-bottom:0}
.n{text-align:right;font-variant-numeric:tabular-nums}.sub{color:var(--muted)}a{color:#2a78d6;text-decoration:none}a:hover{text-decoration:underline}
.pill{color:#fff;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600;white-space:nowrap}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 12px;scroll-margin-top:12px}
.ch{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.ch h3{margin:0;font-size:15px;flex:1;min-width:180px}
.ns{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 7px;font-size:11px;color:var(--sub)}
.meta{color:var(--muted);font-size:11.5px;margin:7px 0}code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:11px;font-family:ui-monospace,monospace}
.pipe{list-style:none;margin:0;padding:0;border-left:2px solid var(--line);margin-left:5px}.pipe li{position:relative;padding:4px 0 4px 20px}
.dot{position:absolute;left:-7px;top:9px;width:11px;height:11px;border-radius:50%;border:2px solid var(--surface)}
.pipe b{display:block;font-size:12.5px}.sd{display:block;color:var(--sub);font-size:12px}.brain{margin-top:10px;border-top:1px dashed var(--line);padding-top:9px}.bt,.bt2{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:600;margin:2px 0 6px}.bt2{margin-top:10px}.raw{font-size:11.5px;color:var(--sub);margin-bottom:7px}.raw code{font-size:11px;white-space:normal}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:5px}.kv{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:4px 8px}.kv .k{display:block;font-size:10.5px;color:var(--muted)}.kv .val{font-size:12.5px;font-variant-numeric:tabular-nums;word-break:break-all}.ctitle{font-size:11px;color:var(--muted);margin:10px 0 4px;font-weight:600}.cand{margin-top:0}.cand td,.cand th{padding:4px 8px;font-size:11.5px}.cst{font-weight:600}.none{color:var(--muted);font-size:12px}footer{color:var(--muted);font-size:12px;margin-top:24px}
"""
doc = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{E(title)}</title><meta name=description content="All armed live attacks fired per app in {E(MODE)} mode, with the full brain pipeline and wall-clock timing.">
<style>{css}</style></head><body><div class=wrap>
<h1>{E(title)}</h1><p class=lede>All {len(rows)} armed Live attacks fired through the Console on <code>phorvex-dev-eks</code>, {'apps concurrently (same-app runs serialized)' if MODE=='parallel' else 'one at a time, in order'}. Generated {now}. Companion: <a href="{other}.html">{other}.html</a>.</p>
<div class=kpis>
<div class=kpi><div class=v>{wall:.0f}s</div><div class=l>Total wall-clock</div></div>
<div class=kpi><div class=v>{len(rows)}</div><div class=l>Attacks fired</div></div>
<div class=kpi><div class=v>{defended}</div><div class=l>Defended / protected</div></div>
<div class=kpi><div class=v>{len(set(r['ns'] for r in rows))}</div><div class=l>Apps</div></div>
</div>
<h2>Execution timeline</h2>{bars}<div class=axis><span>0s</span><span>{maxend/2:.0f}s</span><span>{maxend:.0f}s</span></div>
<h2>Summary</h2><table><thead><tr><th>App</th><th>Attack</th><th>Start</th><th>Dur</th><th>Verdict</th><th>Expected actuator</th><th>Actuator fired</th><th>Actuated</th></tr></thead><tbody>{trows}</tbody></table>
<h2>Per-attack brain pipeline</h2>{cards}
<footer>Offsets are seconds from the start of this run. DEFENDED = brain action contained a real landing; PROTECTED = prior protection revalidated; mechanism/inconclusive = effect or steered action seen but the attack oracle did not confirm; attack did not land = target never produced the forbidden behaviour; rejected = Console refused before firing; fired (no live record) = workload foothold disposition. Raw rows: {E(MODE)}.csv.</footer>
</div></body></html>"""
open(f"{OUT}/{MODE}.html", "w").write(doc)
print(f"wrote {OUT}/{MODE}.html + {MODE}.csv from {len(rows)} attacks; wall={wall}s defended={defended}")
