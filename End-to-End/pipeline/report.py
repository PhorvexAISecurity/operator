"""Render one run document into a self-contained dashboard.

No build step, no libraries, no network: the output opens from a double-click and carries
its own data. The layout is an instrument readout rather than a document — a verdict band,
a six-segment signal path that shows WHICH stage broke, a checks ledger, and a trace
explorer where every engine value sits next to the function that produced it.
"""

import html
import json
from datetime import datetime

from trace import STAGE_LABEL, STAGE_ORDER

STATUS_FA = {"pass": "قبول", "fail": "ردّ", "warn": "هشدار", "skip": "اجرا نشد"}
SEV_FA = {"critical": "بحرانی", "major": "مهم", "minor": "جزئی"}
STAGE_OF_CHECK = ["preflight", "ingest", "physics", "context", "brain", "feasibility", "actuator"]
CHECK_STAGE_LABEL = dict(STAGE_LABEL, preflight="۰ · پیش‌پرواز")
VERDICT_FA = {"PASS": "قبول", "FAIL": "ردّ", "WARN": "با هشدار"}

CSS = """
:root{
  --paper:#F4F7F8; --panel:#FFFFFF; --sunk:#EDF2F4; --rail:#E4EBEE;
  --ink:#0E1A1F; --ink-2:#33454D; --mute:#6A7C85;
  --rule:#D8E2E6; --rule-2:#E9EFF1;
  --brand:#0B7A88; --brand-wash:#E2F1F3;
  --pass:#1B6B48; --pass-wash:#E3F1EA;
  --fail:#A2352C; --fail-wash:#F9E8E6;
  --warn:#8E5A0C; --warn-wash:#F7EEDF;
  --skip:#6A7C85; --skip-wash:#ECF0F2;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Tahoma,"Noto Sans Arabic",sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,"Cascadia Mono","Roboto Mono",monospace;
  --shadow:0 1px 2px rgba(14,26,31,.05), 0 10px 28px -18px rgba(14,26,31,.22);
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --paper:#0A1015; --panel:#111A20; --sunk:#0D151A; --rail:#16222A;
    --ink:#E7EEF2; --ink-2:#B3C2CA; --mute:#7E8F99;
    --rule:#1E2C34; --rule-2:#172329;
    --brand:#3BC4D4; --brand-wash:#0E2B31;
    --pass:#4FC98D; --pass-wash:#0F2A20;
    --fail:#E8635E; --fail-wash:#2C1614;
    --warn:#E0A24A; --warn-wash:#2A2113;
    --skip:#7E8F99; --skip-wash:#151F25;
    --shadow:0 1px 2px rgba(0,0,0,.45), 0 12px 32px -20px rgba(0,0,0,.7);
  }
}
:root[data-theme="dark"]{
  --paper:#0A1015; --panel:#111A20; --sunk:#0D151A; --rail:#16222A;
  --ink:#E7EEF2; --ink-2:#B3C2CA; --mute:#7E8F99;
  --rule:#1E2C34; --rule-2:#172329;
  --brand:#3BC4D4; --brand-wash:#0E2B31;
  --pass:#4FC98D; --pass-wash:#0F2A20;
  --fail:#E8635E; --fail-wash:#2C1614;
  --warn:#E0A24A; --warn-wash:#2A2113;
  --skip:#7E8F99; --skip-wash:#151F25;
  --shadow:0 1px 2px rgba(0,0,0,.45), 0 12px 32px -20px rgba(0,0,0,.7);
}
*{box-sizing:border-box}
body{margin:0; background:var(--paper); color:var(--ink); font-family:var(--sans);
     line-height:1.75; font-size:16px; -webkit-font-smoothing:antialiased}
.wrap{max-width:1180px; margin:0 auto; padding:34px 22px 80px;
      display:flex; flex-direction:column; gap:34px}
.ltr{direction:ltr; unicode-bidi:isolate; display:inline-block}
code,.m{font-family:var(--mono); direction:ltr; unicode-bidi:isolate;
        font-variant-numeric:tabular-nums}
code{background:var(--sunk); border:1px solid var(--rule-2); border-radius:5px;
     padding:1px 6px; font-size:.85em; color:var(--ink)}
svg{direction:ltr}
h1,h2,h3{margin:0; text-wrap:balance}

/* ── verdict band ────────────────────────────────────────────────── */
.band{background:var(--panel); border:1px solid var(--rule); border-radius:14px;
      box-shadow:var(--shadow); overflow:hidden}
.band .top{display:flex; flex-wrap:wrap; align-items:center; gap:20px 30px;
           padding:22px 26px; border-bottom:1px solid var(--rule-2)}
.vlabel{font-size:.72rem; letter-spacing:.16em; color:var(--mute);
        text-transform:uppercase; margin:0 0 2px}
.vword{font-size:2.5rem; font-weight:800; line-height:1.05; letter-spacing:-.02em}
.vword.pass{color:var(--pass)} .vword.fail{color:var(--fail)} .vword.warn{color:var(--warn)}
.tally{display:flex; gap:9px; flex-wrap:wrap; margin-inline-start:auto}
.tile{min-width:78px; padding:9px 14px; border-radius:10px; border:1px solid var(--rule);
      background:var(--sunk); text-align:center}
.tile b{display:block; font-family:var(--mono); font-variant-numeric:tabular-nums;
        font-size:1.45rem; font-weight:700; line-height:1.2}
.tile span{font-size:.74rem; color:var(--mute)}
.tile.pass b{color:var(--pass)} .tile.fail b{color:var(--fail)}
.tile.warn b{color:var(--warn)} .tile.skip b{color:var(--skip)}
.meta{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
      gap:1px; background:var(--rule-2)}
.meta div{background:var(--panel); padding:12px 18px}
.meta dt{font-size:.72rem; color:var(--mute); margin:0 0 3px}
.meta dd{margin:0; font-size:.92rem; font-family:var(--mono); direction:ltr;
         unicode-bidi:isolate; color:var(--ink); overflow-wrap:anywhere}

/* ── signal path ─────────────────────────────────────────────────── */
.path{display:flex; gap:0; overflow-x:auto; border:1px solid var(--rule);
      border-radius:12px; background:var(--panel); box-shadow:var(--shadow)}
.seg{flex:1 1 0; min-width:132px; padding:14px 15px; border-inline-end:1px solid var(--rule-2);
     position:relative}
.seg:last-child{border-inline-end:0}
.seg::before{content:""; position:absolute; inset-inline:0; top:0; height:3px; background:var(--skip)}
.seg.pass::before{background:var(--pass)} .seg.fail::before{background:var(--fail)}
.seg.warn::before{background:var(--warn)}
.seg h3{font-size:.9rem; font-weight:700; margin-bottom:5px}
.seg p{margin:0; font-size:.76rem; color:var(--mute); font-family:var(--mono); direction:ltr;
       unicode-bidi:isolate}

/* ── section shell ───────────────────────────────────────────────── */
.sec{display:flex; flex-direction:column; gap:14px}
.shead{display:flex; align-items:baseline; gap:12px; flex-wrap:wrap;
       border-bottom:2px solid var(--rule); padding-bottom:9px}
.shead h2{font-size:1.22rem; font-weight:700}
.shead .sub{font-size:.78rem; color:var(--mute); font-family:var(--mono);
            direction:ltr; unicode-bidi:isolate}
.filters{display:flex; gap:7px; flex-wrap:wrap; margin-inline-start:auto}
.filters button{font:inherit; font-size:.79rem; padding:4px 12px; border-radius:99px; cursor:pointer;
                border:1px solid var(--rule); background:var(--panel); color:var(--ink-2)}
.filters button[aria-pressed="true"]{background:var(--brand-wash); border-color:var(--brand);
                                     color:var(--brand); font-weight:700}

/* ── checks ledger ───────────────────────────────────────────────── */
.grp{border:1px solid var(--rule); border-radius:12px; background:var(--panel);
     box-shadow:var(--shadow); overflow:hidden}
.grp > h3{padding:11px 17px; font-size:.92rem; background:var(--sunk);
          border-bottom:1px solid var(--rule-2); font-weight:700}
.chk{border-top:1px solid var(--rule-2); border-inline-start:4px solid var(--skip)}
.chk:first-of-type{border-top:0}
.chk.pass{border-inline-start-color:var(--pass)} .chk.fail{border-inline-start-color:var(--fail)}
.chk.warn{border-inline-start-color:var(--warn)}
.chk > summary{padding:11px 17px; cursor:pointer; display:flex; gap:11px;
               align-items:baseline; flex-wrap:wrap; list-style:none}
.chk > summary::-webkit-details-marker{display:none}
.chk > summary::before{content:"▸"; color:var(--mute); font-size:.8rem;
                       transition:transform .15s; display:inline-block}
.chk[open] > summary::before{transform:rotate(-90deg)}
.chk:hover > summary{background:var(--sunk)}
.cid{font-family:var(--mono); font-size:.76rem; color:var(--mute); min-width:38px}
.ctitle{font-weight:650; font-size:.95rem}
.csum{color:var(--ink-2); font-size:.88rem; margin-inline-start:auto; text-align:start}
.pill{font-size:.71rem; font-weight:700; padding:2px 9px; border-radius:99px; white-space:nowrap}
.pill.pass{background:var(--pass-wash); color:var(--pass)}
.pill.fail{background:var(--fail-wash); color:var(--fail)}
.pill.warn{background:var(--warn-wash); color:var(--warn)}
.pill.skip{background:var(--skip-wash); color:var(--skip)}
.cbody{padding:2px 17px 15px 17px; display:flex; flex-direction:column; gap:9px;
       border-top:1px dashed var(--rule-2); margin-top:2px}
.cbody p{margin:0; font-size:.9rem; color:var(--ink-2)}
.cbody .lbl{font-size:.72rem; color:var(--mute); letter-spacing:.05em}
.ev{margin:0; padding:10px 13px; background:var(--sunk); border:1px solid var(--rule-2);
    border-radius:8px; font-family:var(--mono); direction:ltr; unicode-bidi:isolate;
    font-size:.79rem; line-height:1.85; white-space:pre-wrap; overflow-x:auto; color:var(--ink-2)}

/* ── traces ──────────────────────────────────────────────────────── */
.trace{border:1px solid var(--rule); border-radius:12px; background:var(--panel);
       box-shadow:var(--shadow); overflow:hidden}
.trace > summary{padding:12px 17px; cursor:pointer; display:flex; gap:12px; flex-wrap:wrap;
                 align-items:baseline; list-style:none}
.trace > summary::-webkit-details-marker{display:none}
.trace:hover > summary{background:var(--sunk)}
.tpod{font-family:var(--mono); direction:ltr; unicode-bidi:isolate; font-size:.87rem;
      font-weight:650; color:var(--ink)}
.tmeta{font-size:.79rem; color:var(--mute); font-family:var(--mono); direction:ltr;
       unicode-bidi:isolate; margin-inline-start:auto}
.stage{border-top:1px solid var(--rule-2)}
.stage > h4{margin:0; padding:9px 17px; font-size:.83rem; font-weight:700; color:var(--brand);
            background:var(--sunk)}
.tblwrap{overflow-x:auto}
table{border-collapse:collapse; width:100%; min-width:660px}
th{background:var(--panel); font-size:.71rem; letter-spacing:.04em; color:var(--mute);
   text-align:start; padding:8px 15px; border-bottom:1px solid var(--rule-2); font-weight:700}
td{padding:8px 15px; border-top:1px solid var(--rule-2); font-size:.87rem;
   color:var(--ink-2); vertical-align:top}
td.k{font-family:var(--mono); direction:ltr; unicode-bidi:isolate; color:var(--ink); font-size:.81rem}
td.v{font-family:var(--mono); direction:ltr; unicode-bidi:isolate; font-weight:650;
     color:var(--ink); font-variant-numeric:tabular-nums; white-space:nowrap}
td.v.absent{color:var(--mute); font-weight:400}
td.src{font-family:var(--mono); direction:ltr; unicode-bidi:isolate; font-size:.74rem; color:var(--mute)}
td.why{max-width:34ch; font-size:.83rem}
tr:hover td{background:var(--sunk)}
.reasonrow td{background:var(--brand-wash)}

/* ── ground truth ────────────────────────────────────────────────── */
.gt{display:flex; flex-direction:column; gap:10px}
.gtrow{border:1px solid var(--rule); border-inline-start:4px solid var(--skip); border-radius:10px;
       background:var(--panel); padding:13px 16px; box-shadow:var(--shadow)}
.gtrow.confirmed{border-inline-start-color:var(--pass)}
.gtrow.contradicted{border-inline-start-color:var(--fail)}
.gtrow h4{margin:0 0 5px; font-size:.92rem}
.gtrow p{margin:0; font-size:.87rem; color:var(--ink-2)}
.gtrow .ev{margin-top:8px}

.empty{padding:26px; text-align:center; color:var(--mute); font-size:.9rem;
       border:1px dashed var(--rule); border-radius:12px}
footer{border-top:1px solid var(--rule); padding-top:18px; font-size:.79rem; color:var(--mute);
       display:flex; flex-wrap:wrap; gap:7px 22px}
:focus-visible{outline:2px solid var(--brand); outline-offset:3px; border-radius:5px}
@media (prefers-reduced-motion: reduce){*{transition:none !important}}
"""

JS = """
(function(){
  var btns = document.querySelectorAll('#filters button');
  function apply(want){
    btns.forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.f === want)); });
    document.querySelectorAll('.chk').forEach(function(c){
      c.style.display = (want === 'all' || c.dataset.status === want) ? '' : 'none';
    });
    document.querySelectorAll('.grp').forEach(function(g){
      var any = Array.prototype.some.call(g.querySelectorAll('.chk'),
        function(c){ return c.style.display !== 'none'; });
      g.style.display = any ? '' : 'none';
    });
  }
  btns.forEach(function(b){ b.addEventListener('click', function(){ apply(b.dataset.f); }); });
  apply('all');
})();
"""


def esc(x):
    return html.escape(str(x), quote=True)


def fmt(v, present):
    if not present or v is None:
        return "—", True
    if isinstance(v, bool):
        return ("بله" if v else "خیر"), False
    if isinstance(v, float):
        s = f"{v:.4f}".rstrip("0").rstrip(".")
        return (s or "0"), False
    if isinstance(v, list):
        return (", ".join(str(x) for x in v) if v else "—"), (not v)
    s = str(v)
    return (s if s.strip() else "—"), (not s.strip())


def worst(statuses):
    for s in ("fail", "warn", "pass"):
        if s in statuses:
            return s
    return "skip"


def _band(doc):
    v = doc["verdict"].lower()
    t = doc["tally"]
    pf = doc.get("preflight", {}).get("version", {}) or {}
    tgt = doc.get("target") or {}
    meta = [
        ("حالت اجرا", doc["mode"]),
        ("هدف", tgt.get("name", "—")),
        ("نیم‌اسپیس", tgt.get("namespace", "—")),
        ("کنسول / اپراتور", f"{pf.get('console','?')} / {pf.get('operator','?')}"),
        ("رکوردهای تصمیم", doc["counts"]["records"]),
        ("اقدام‌های اجراشده", doc["counts"]["actuated"]),
        ("MaxMovesPerTick", doc.get("policy", {}).get("maxMovesPerTick") or "—"),
        ("ترابری", doc["transport"]),
        ("شروع", doc["startedAt"][:19].replace("T", " ")),
        ("پایان", doc["finishedAt"][:19].replace("T", " ")),
    ]
    tiles = "".join(
        f'<div class="tile {k}"><b>{t[k]}</b><span>{esc(STATUS_FA[k])}</span></div>'
        for k in ("pass", "fail", "warn", "skip"))
    cells = "".join(f"<div><dt>{esc(a)}</dt><dd>{esc(b)}</dd></div>" for a, b in meta)
    return f"""<section class="band">
  <div class="top">
    <div><p class="vlabel">verdict</p><div class="vword {v}">{esc(VERDICT_FA.get(doc['verdict'], doc['verdict']))}</div></div>
    <div class="tally">{tiles}</div>
  </div>
  <dl class="meta">{cells}</dl>
</section>"""


def _path(doc):
    by = {}
    for c in doc["checks"]:
        by.setdefault(c["stage"], []).append(c["status"])
    segs = []
    for st in STAGE_OF_CHECK:
        sts = by.get(st, [])
        w = worst(sts) if sts else "skip"
        counts = {k: sts.count(k) for k in ("pass", "fail", "warn", "skip")}
        line = " ".join(f"{k[0].upper()}{counts[k]}" for k in ("pass", "fail", "warn", "skip") if counts[k])
        segs.append(f'<div class="seg {w}"><h3>{esc(CHECK_STAGE_LABEL[st])}</h3>'
                    f'<p>{esc(line or "—")}</p></div>')
    return ('<section class="sec"><div class="shead"><h2>مسیر سیگنال</h2>'
            '<span class="sub">worst status per stage</span></div>'
            f'<div class="path">{"".join(segs)}</div></section>')


def _checks(doc):
    by = {}
    for c in doc["checks"]:
        by.setdefault(c["stage"], []).append(c)
    groups = []
    for st in STAGE_OF_CHECK:
        if st not in by:
            continue
        rows = []
        for c in by[st]:
            ev = ""
            if c.get("evidence"):
                ev = ('<p class="lbl">شواهد</p><pre class="ev">'
                      + esc("\n".join(str(e) for e in c["evidence"])) + "</pre>")
            rows.append(f"""<details class="chk {c['status']}" data-status="{c['status']}">
  <summary><span class="cid">{esc(c['id'])}</span>
    <span class="ctitle">{esc(c['title'])}</span>
    <span class="pill {c['status']}">{esc(STATUS_FA[c['status']])}</span>
    <span class="csum">{esc(c['summary'])}</span></summary>
  <div class="cbody">
    <div><p class="lbl">قبول‌شدنش چه چیزی را ثابت می‌کند · شدت {esc(SEV_FA.get(c['severity'], c['severity']))}</p>
    <p>{esc(c['proves'])}</p></div>{ev}
  </div>
</details>""")
        groups.append(f'<div class="grp"><h3>{esc(CHECK_STAGE_LABEL[st])}</h3>{"".join(rows)}</div>')
    filt = "".join(f'<button data-f="{k}">{esc(v)}</button>'
                   for k, v in [("all", "همه"), ("fail", "ردّ"), ("warn", "هشدار"),
                                ("pass", "قبول"), ("skip", "اجرا نشد")])
    return f"""<section class="sec">
  <div class="shead"><h2>چک‌ها</h2><span class="sub">{len(doc['checks'])} checks</span>
    <div class="filters" id="filters">{filt}</div></div>
  {"".join(groups)}
</section>"""


def _traces(doc):
    traces = doc.get("traces", [])
    if not traces:
        return ('<section class="sec"><div class="shead"><h2>ردّ تصمیم‌ها</h2></div>'
                '<div class="empty">هیچ رکورد تصمیمی ضبط نشد.</div></section>')
    # Decisions that did something come first; they are what a reader opens the report for.
    ordered = sorted(traces, key=lambda t: (not t["actuated"], not t["selected"], t["time"]))
    # Every acted/selected trace is rendered. The no-action tail is overwhelmingly repeated
    # noop ticks on the same pods, so it is sampled one-per-pod: the full set stays in the
    # JSON, and the count of what was left out is printed rather than silently dropped.
    shown, seen_pods, omitted = [], set(), 0
    for tr in ordered:
        if tr["actuated"] or tr["selected"]:
            shown.append(tr)
            continue
        key = (tr["namespace"], tr["pod"])
        if key in seen_pods:
            omitted += 1
            continue
        seen_pods.add(key)
        shown.append(tr)
    blocks = []
    for tr in shown:
        stages = []
        for s in tr["stages"]:
            rows = []
            for f in s["fields"]:
                val, absent = fmt(f["value"], f["present"])
                cls = "v absent" if absent else "v"
                rows.append(
                    f'<tr><td class="k">{esc(f["key"])}</td>'
                    f'<td>{esc(f["label"])}</td>'
                    f'<td class="{cls}">{esc(val)}</td>'
                    f'<td class="k">{esc(f["range"])}</td>'
                    f'<td class="src">{esc(f["source"])}</td>'
                    f'<td class="why">{esc(f["why"])}</td></tr>')
            stages.append(f"""<div class="stage"><h4>{esc(s['label'])}</h4><div class="tblwrap"><table>
  <thead><tr><th>فیلد</th><th>یعنی چه</th><th>مقدار</th><th>بازه</th><th>تولیدکننده</th><th>چرا مهم است</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table></div></div>""")
        attr = ""
        if tr["attribution"]:
            ar = "".join(
                f'<tr><td class="k">{esc(a.get("key", a.get("fact", "")))}</td>'
                f'<td class="v">{esc(fmt(a.get("weight", a.get("value")), True)[0])}</td>'
                f'<td>{esc(a.get("kind", a.get("note", "")))}</td></tr>'
                for a in tr["attribution"])
            attr = ('<div class="stage"><h4>انتساب — کدام حقیقت‌ها چقدر سهم داشتند</h4>'
                    '<div class="tblwrap"><table><thead><tr><th>کلید</th><th>وزن</th><th>نوع</th></tr></thead>'
                    f"<tbody>{ar}</tbody></table></div></div>")
        state = ("اجرا شد" if tr["actuated"] else
                 "انتخاب شد" if tr["selected"] else "بدون اقدام")
        pill = "pass" if tr["actuated"] else ("warn" if tr["selected"] else "skip")
        blocks.append(f"""<details class="trace">
  <summary><span class="tpod">{esc(tr['namespace'])}/{esc(tr['pod'])}</span>
    <span class="pill {pill}">{esc(state)}</span>
    <code>{esc(tr['action'])}</code>
    <span class="tmeta">{esc(tr['time'][:19].replace('T', ' '))}</span></summary>
  {''.join(stages)}{attr}
</details>""")
    more = ("" if not omitted else
            f'<p class="empty">{omitted} تیکِ تکراریِ بدون اقدام روی همین پادها نمایش داده نشد '
            f'— همه‌شان در فایل JSON همین اجرا هستند.</p>')
    return f"""<section class="sec">
  <div class="shead"><h2>ردّ تصمیم‌ها</h2>
    <span class="sub">{len(shown)} of {len(ordered)} decisions · every value with its source</span></div>
  {''.join(blocks)}{more}
</section>"""


def _ground(doc):
    gt = doc.get("groundTruth") or []
    if not gt:
        body = ('<div class="empty">در این اجرا اقدامی روی کلاستر انجام نشد، '
                'پس چیزی برای راستی‌آزمایی مستقل وجود نداشت.</div>')
    else:
        rows = []
        for g in gt:
            rows.append(f"""<div class="gtrow {esc(g['verdict'])}">
  <h4><code>{esc(g['action'])}</code> روی <span class="ltr">{esc(g['namespace'])}/{esc(g['pod'])}</span>
      — {esc({'confirmed': 'تأیید شد', 'contradicted': 'رد شد', 'unverifiable': 'قابل تأیید نبود'}[g['verdict']])}</h4>
  <p>{esc(g['detail'])}</p>
  <p class="lbl" style="margin-top:6px">انتظار: {esc(g['expected'])}</p>
  {f'<pre class="ev">{esc(g["evidence"])}</pre>' if g.get("evidence") else ''}
</div>""")
        body = f'<div class="gt">{"".join(rows)}</div>'
    return ('<section class="sec"><div class="shead"><h2>راستی‌آزمایی مستقل</h2>'
            '<span class="sub">kubectl / workload logs — never Phorvex&#39;s own report</span></div>'
            + body + "</section>")


def render(doc, standalone=True):
    title = f"Phorvex E2E — {doc['verdict']} — {doc['startedAt'][:19]}"
    body = f"""<div class="wrap">
  <header>
    <p class="vlabel">Phorvex · End-to-End</p>
    <h1 style="font-size:1.7rem;font-weight:800;margin-bottom:6px">گزارش تست پایان‌به‌پایان</h1>
    <p style="margin:0;color:var(--ink-2);max-width:72ch">
      یک اجرا از اولین مرحله (ورود سیگنال) تا آخرین مرحله (دستی که به کلاستر می‌خورد).
      هر مقداری که موتور تولید کرده اینجا هست، کنار تابعی که آن را ساخته و دلیلی که به آن نیاز داریم.
    </p>
  </header>
  {_band(doc)}
  {_path(doc)}
  {_checks(doc)}
  {_ground(doc)}
  {_traces(doc)}
  <footer>
    <span>schema {esc(doc['schema'])}</span>
    <span>{esc(doc['counts']['records'])} decision records</span>
    <span>ساخته‌شده در {esc(datetime.now().strftime('%Y-%m-%d %H:%M'))}</span>
  </footer>
</div>
<script>{JS}</script>"""
    head = f"<title>{esc(title)}</title>\n<style>{CSS}</style>"
    if not standalone:
        return head + "\n" + body
    return (f'<!doctype html>\n<html lang="fa" dir="rtl">\n<head>\n'
            f'<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f"{head}\n</head>\n<body>\n{body}\n</body>\n</html>\n")


def render_json(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2)
