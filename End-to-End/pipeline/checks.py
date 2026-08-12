"""The assertion catalogue.

Every check states three things: what it inspects, what a pass *proves*, and how it can
fail. A check that cannot be evaluated returns SKIP with the reason — it never returns
PASS for something it did not actually look at, because a green board built on unrun
checks is worse than a red one.

Severity is about consequence, not confidence:
  critical — a contract violation; the system did something it says it never does
  major    — a value or explanation the dashboard would show that is wrong or impossible
  minor    — a smell worth reporting that does not by itself invalidate a run
"""

import math

from trace import all_numeric_fields, is_finite_number

PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"

_REGISTRY = []


def check(cid, stage, title, proves, severity="major"):
    def deco(fn):
        _REGISTRY.append({
            "id": cid, "stage": stage, "title": title,
            "proves": proves, "severity": severity, "fn": fn,
        })
        return fn
    return deco


def registry():
    return list(_REGISTRY)


def result(status, summary, evidence=None):
    return {"status": status, "summary": summary, "evidence": evidence or []}


def _num(rec, key, default=0.0):
    v = rec.get(key, default)
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else default


def _in_range(v, lo, hi):
    return is_finite_number(v) and lo - 1e-9 <= v <= hi + 1e-9


def _bounded(ctx, key, lo, hi, optional=False):
    """Shared body for the many [lo,hi] field checks."""
    bad, seen = [], 0
    for r in ctx.records:
        if key not in r:
            if optional:
                continue
            bad.append(f"{r.get('pod')} @ {r.get('time')}: field missing")
            continue
        seen += 1
        v = r[key]
        if not _in_range(v, lo, hi):
            bad.append(f"{r.get('pod')} @ {r.get('time')}: {key}={v!r}")
    if seen == 0:
        return result(SKIP, f"هیچ رکوردی فیلد {key} را نداشت")
    if bad:
        return result(FAIL, f"{len(bad)} رکورد از {seen} رکورد خارج از بازه‌ی [{lo}, {hi}]", bad[:10])
    return result(PASS, f"هر {seen} رکورد داخل [{lo}, {hi}]")


# ─────────────────────────── 0 · preflight ───────────────────────────

@check("P01", "preflight", "کنسول و اپراتور در دسترس‌اند",
       "نقطه‌ی ورودِ خودِ تست سالم است؛ بقیه‌ی نتایج بی‌معنا می‌شد اگر نبود", "critical")
def p01(ctx):
    h = ctx.preflight.get("health") or {}
    v = ctx.preflight.get("version") or {}
    if not h.get("ok"):
        return result(FAIL, "«/api/health» ok=true برنگرداند", [repr(h)[:300]])
    return result(PASS, f"کنسول {v.get('console','?')} · اپراتور {v.get('operator','?')}",
                  [f"image={v.get('operatorImage','?')}"])


@check("P02", "preflight", "نسخه‌ی کنسول و اپراتور یکی است",
       "داشبورد و موتور از یک بیلد می‌آیند، پس فیلدی که تست انتظارش را دارد واقعاً وجود دارد", "minor")
def p02(ctx):
    v = ctx.preflight.get("version") or {}
    c, o = v.get("console"), v.get("operator")
    if not c or not o:
        return result(SKIP, "نسخه گزارش نشد")
    if c != o:
        return result(WARN, f"ناهماهنگی نسخه: کنسول {c} در برابر اپراتور {o}")
    return result(PASS, f"هر دو روی {c}")


@check("P03", "preflight", "حلقه‌ی تیک زنده است",
       "اپراتور واقعاً دارد تصمیم می‌گیرد؛ رکوردها بایگانی نیستند", "critical")
def p03(ctx):
    if not ctx.records:
        return result(FAIL, "هیچ رکورد تصمیمی در پنجره‌ی ضبط نیامد")
    fresh = ctx.freshest_age_sec
    if fresh is None:
        return result(WARN, "زمان رکوردها قابل تفسیر نبود")
    if fresh > ctx.stale_after_sec:
        return result(FAIL, f"تازه‌ترین رکورد {fresh:.0f} ثانیه قدیمی است (آستانه {ctx.stale_after_sec}s)")
    return result(PASS, f"{len(ctx.records)} رکورد، تازه‌ترین {fresh:.1f} ثانیه پیش")


@check("P04", "preflight", "پادهای هدف در کلاستر آماده‌اند",
       "حمله به چیزی می‌خورد که واقعاً سرویس می‌دهد", "critical")
def p04(ctx):
    if not ctx.baseline_pods:
        return result(SKIP, "پایه‌ی kubectl گرفته نشد (حالت observe بدون هدف)")
    ready = [p for p, m in ctx.baseline_pods.items() if m["phase"] == "Running"]
    if not ready:
        return result(FAIL, "هیچ پاد Running در نیم‌اسپیس هدف نیست",
                      [f"{p}: {m['phase']}" for p, m in ctx.baseline_pods.items()][:10])
    return result(PASS, f"{len(ready)} پاد Running",
                  [f"{p} uid={m['uid'][:8]} owner={m['owner']}" for p, m in ctx.baseline_pods.items()][:10])


@check("P05", "preflight", "هیچ کنترلری در حال crash نیست",
       "اپراتوری که مدام ری‌استارت می‌شود تصمیم می‌گیرد ولی دستش به کلاستر نمی‌رسد — "
       "و چون اپراتور دیگری همچنان لاگ می‌نویسد، داشبورد سالم به‌نظر می‌رسد", "critical")
def p05(ctx):
    if not ctx.controller_pods:
        return result(SKIP, "وضعیت پادهای کنترلر خوانده نشد")
    bad = [f"{p}: {m['phase']} · restarts={m['restarts']}" for p, m in ctx.controller_pods.items()
           if m["phase"] != "Running" or m["restarts"] > ctx.max_restarts]
    if bad:
        return result(FAIL, f"{len(bad)} کنترلر ناسالم", bad)
    return result(PASS, f"{len(ctx.controller_pods)} کنترلر سالم",
                  [f"{p}: {m['phase']} · restarts={m['restarts']}" for p, m in ctx.controller_pods.items()])


# ─────────────────────────── 1 · ingest ───────────────────────────

@check("I01", "ingest", "هر رکورد هویت کامل دارد",
       "ورود، پاد را واقعاً دیده — رکورد بی‌نام‌ونشان یعنی snapshot ناقص بوده", "critical")
def i01(ctx):
    bad = [f"@{r.get('time')}: {k} خالی"
           for r in ctx.records for k in ("tenant", "namespace", "pod")
           if not str(r.get(k, "")).strip()]
    if bad:
        return result(FAIL, f"{len(bad)} فیلد هویتی خالی", bad[:10])
    return result(PASS, f"هر {len(ctx.records)} رکورد tenant/namespace/pod دارد")


@check("I02", "ingest", "زمان تیک‌ها رو به جلوست",
       "فایل حسابرسی در حال نوشته‌شدن است و رکوردها پشت‌هم‌اند، نه درهم", "minor")
def i02(ctx):
    ts = [ctx.parse_time(r.get("time")) for r in ctx.records]
    ts = [t for t in ts if t is not None]
    if len(ts) < 2:
        return result(SKIP, "کمتر از دو رکورد زمان‌دار")
    back = sum(1 for a, b in zip(ts, ts[1:]) if b < a - 0.001)
    if back:
        return result(WARN, f"{back} پرش به عقب در ترتیب جریان")
    return result(PASS, f"{len(ts)} مهر زمانی، بدون پرش به عقب")


@check("I03", "ingest", "هدف در جریان تصمیم دیده می‌شود",
       "ورود این نیم‌اسپیس را پوشش می‌دهد؛ سکوتِ بعدی یعنی «تصمیم گرفت کاری نکند»، نه «ندید»", "critical")
def i03(ctx):
    if not ctx.target:
        return result(SKIP, "بدون هدف اجرا شد")
    ns = ctx.target["namespace"]
    hit = [r for r in ctx.records if r.get("namespace") == ns]
    if not hit:
        return result(FAIL, f"هیچ تصمیمی برای نیم‌اسپیس {ns} در پنجره نیامد",
                      sorted({r.get("namespace", "") for r in ctx.records})[:12])
    pods = sorted({r.get("pod") for r in hit})
    return result(PASS, f"{len(hit)} تصمیم روی {len(pods)} پاد در {ns}", pods[:8])


# ─────────────────────────── 2 · physics ───────────────────────────

@check("PH01", "physics", "residual همیشه متناهی و در [0,1] است",
       "همان کلاس باگی که NaN را تا بهینه‌ساز می‌برد و انتخاب را بی‌صدا به noop می‌انداخت", "critical")
def ph01(ctx):
    return _bounded(ctx, "residual", 0.0, 1.0)


@check("PH02", "physics", "هیچ عدد نامتناهی در هیچ فیلدی نیست",
       "جاروی سراسری NaN/Inf روی کل رکورد، نه فقط فیلدهایی که انتظارش را داریم", "critical")
def ph02(ctx):
    bad = []
    for r in ctx.records:
        for k, v in all_numeric_fields(r):
            if not math.isfinite(v):
                bad.append(f"{r.get('pod')} @ {r.get('time')}: {k}={v}")
    if bad:
        return result(FAIL, f"{len(bad)} مقدار نامتناهی", bad[:10])
    n = sum(len(all_numeric_fields(r)) for r in ctx.records)
    return result(PASS, f"{n} مقدار عددی در {len(ctx.records)} رکورد، همه متناهی")


@check("PH03", "physics", "residual بالا بدون رویداد امنیتی، تصمیم را نمی‌سازد",
       "فیزیک فقط گزارش می‌دهد؛ اهمیت‌دادن کار زمینه است", "minor")
def ph03(ctx):
    odd = [f"{r.get('pod')}: residual={r.get('residual')} ولی threatPosture=0 و انتخاب شد"
           for r in ctx.records
           if r.get("selected") and _num(r, "residual") > 0.5 and _num(r, "threatPosture") == 0]
    if odd:
        return result(WARN, f"{len(odd)} انتخاب فقط بر پایه‌ی فیزیک", odd[:6])
    return result(PASS, "هیچ انتخابی صرفاً از ناهنجاری فیزیکی نیامد")


# ─────────────────────────── 3 · context ───────────────────────────

@check("C01", "context", "assetValue متناهی و نامنفی است", "ارزش دارایی قابل استفاده است", "major")
def c01(ctx):
    return _bounded(ctx, "assetValue", 0.0, 1e6)


@check("C02", "context", "blastRadius در [0,1] است",
       "امتیاز گراف نرمال‌شده است؛ خارج از بازه یعنی نرمال‌سازی شکسته", "major")
def c02(ctx):
    return _bounded(ctx, "blastRadius", 0.0, 1.0)


@check("C03", "context", "سیگنال‌های زمینه در [0,1] هستند",
       "threatPosture / exposure / sloHeadroom / belief همه بی‌بعد و کران‌دارند", "major")
def c03(ctx):
    parts, worst = [], PASS
    for k in ("threatPosture", "exposure", "sloHeadroom", "belief"):
        r = _bounded(ctx, k, 0.0, 1.0)
        parts.append(f"{k}: {r['summary']}")
        if r["status"] == FAIL:
            worst = FAIL
    return result(worst, "چهار سیگنال بررسی شد", parts)


@check("C04", "context", "phase یکی از فازهای شناخته‌شده است",
       "فاز مستقیم وارد ویژگی‌های RLS می‌شود؛ فاز ناشناخته یعنی هزینه‌ی چرخش غلط", "major")
def c04(ctx):
    known = set(ctx.inv["known_phases"])
    bad = [f"{r.get('pod')}: phase={r.get('phase')!r}" for r in ctx.records
           if r.get("phase") and r["phase"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} فاز ناشناخته", bad[:8])
    return result(PASS, f"همه در {sorted(known)}")


@check("C05", "context", "stage یکی از ۹ مرحله‌ی تعریف‌شده است",
       "شامل زنجیره‌ی موازی AI؛ مرحله‌ی ناشناخته یعنی طبقه‌بندی رویداد شکسته", "major")
def c05(ctx):
    known = set(ctx.inv["known_stages"])
    bad = [f"{r.get('pod')}: stage={r.get('stage')!r}" for r in ctx.records
           if r.get("stage") and r["stage"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} مرحله‌ی ناشناخته", bad[:8])
    seen = sorted({r.get("stage") for r in ctx.records if r.get("stage")})
    return result(PASS, f"مراحل دیده‌شده: {', '.join(seen) or '—'}")


@check("C06", "context", "nextStage جانشین قانونی stage است",
       "یا جانشین خطی، یا جهش به lateral از فشار همسایه، یا نقشه‌ی AI — نه هر چیز دیگری", "major")
def c06(ctx):
    generic = ["recon", "exploit", "persist", "lateral", "impact"]
    ai_map = {"gpu-side-channel": "model-theft", "model-theft": "impact",
              "llm-jacking": "impact", "prompt-inject-persist": "lateral"}
    bad, seen = [], 0
    for r in ctx.records:
        s, n = r.get("stage"), r.get("nextStage")
        if not s or not n:
            continue
        seen += 1
        if s in ai_map:
            ok = n == ai_map[s]
        elif s in generic:
            i = generic.index(s)
            linear = generic[min(i + 1, len(generic) - 1)]
            ok = n in (linear, "lateral")  # lateral jump is legal under neighbour pressure
        else:
            ok = False
        if not ok:
            bad.append(f"{r.get('pod')}: {s} → {n}")
    if seen == 0:
        return result(SKIP, "هیچ رکوردی هر دو فیلد را نداشت")
    if bad:
        return result(FAIL, f"{len(bad)} گذارِ غیرقانونی", bad[:8])
    return result(PASS, f"هر {seen} گذار قانونی است")


@check("C07", "context", "hazard و pHold و preemptMargin در [0,1] هستند",
       "هر سه احتمال‌اند؛ خارج از بازه یعنی وایبول یا پسین بتا شکسته", "major")
def c07(ctx):
    parts, worst = [], PASS
    for k in ("stageHazard", "pHold", "preemptMargin"):
        r = _bounded(ctx, k, 0.0, 1.0, optional=True)
        parts.append(f"{k}: {r['summary']}")
        if r["status"] == FAIL:
            worst = FAIL
    return result(worst, "سه احتمال بررسی شد", parts)


@check("C08", "context", "حاشیه‌ی مرحله‌ی بعد با خطر جهش سازگار است",
       "این عدد مدت زمان نیست، یک حاشیه‌ی علامت‌دار است: منفی یعنی «از موعد گذشته» "
       "(hazard.go:327). هر دو از یک وایبول می‌آیند، پس یک رابطه‌ی دقیق بینشان برقرار است "
       "که با هم دررفتنشان را می‌گیرد", "major")
def c08(ctx):
    # margin = median − exposure, and hazard = weibullCDF(exposure). At exposure = median,
    # hazard = 1 − exp(−(−ln 0.5)) = 0.5 exactly — independent of scale and of the stage.
    # So margin < 0 ⟺ hazard > 0.5 is an exact identity, not a tuned threshold. The band
    # around 0.5 absorbs the audit's 4-decimal rounding.
    band = 0.001
    have = [r for r in ctx.records if is_finite_number(r.get("projectedNextStageSec"))]
    if not have:
        return result(SKIP, "فیلد در هیچ رکوردی نبود")
    bad = []
    for r in have:
        m, h = r["projectedNextStageSec"], _num(r, "stageHazard")
        if abs(h - 0.5) <= band:
            continue  # exactly at the median; either sign is legal
        if (m < 0) != (h > 0.5):
            bad.append(f"{r.get('namespace')}/{r.get('pod')}: margin={m:.0f}s با hazard={h:.4f} "
                       f"نمی‌خواند (margin<0 باید دقیقاً معادل hazard>0.5 باشد)")
    if bad:
        return result(FAIL, f"{len(bad)} ناسازگاری بین حاشیه و خطر جهش", bad[:8])
    overdue = sum(1 for r in have if r["projectedNextStageSec"] < 0)
    return result(PASS, f"هر {len(have)} رکورد اتحاد را برقرار می‌کند "
                        f"({overdue} تا از موعد گذشته و hazard هر کدام > ۰٫۵)")


# ─────────────────────────── 4 · brain ───────────────────────────

@check("B01", "brain", "اتحاد خالص برقرار است: net = risk − λ×cost",
       "قلب تصمیم؛ اگر این نخواند، عددی که داشبورد نشان می‌دهد از جای دیگری آمده", "critical")
def b01(ctx):
    tol = ctx.inv["net_identity_tolerance"]
    bad, seen = [], 0
    for r in ctx.records:
        if not all(is_finite_number(r.get(k)) for k in ("risk", "cost", "net")):
            continue
        seen += 1
        expect = _num(r, "risk") - _num(r, "lambda") * _num(r, "cost")
        if abs(expect - _num(r, "net")) > tol:
            bad.append(f"{r.get('pod')}: risk={r['risk']} λ={_num(r,'lambda')} "
                       f"cost={r['cost']} → انتظار {expect:.4f} ولی net={r['net']}")
    if seen == 0:
        return result(SKIP, "هیچ رکوردی هر سه عدد را نداشت")
    if bad:
        return result(FAIL, f"{len(bad)} نقض از {seen}", bad[:8])
    return result(PASS, f"هر {seen} رکورد در تلورانس ±{tol}")


@check("B02", "brain", "موتور تصمیم شناخته‌شده است", "رکورد از همان موتوری آمده که مستند شده", "minor")
def b02(ctx):
    known = set(ctx.inv["known_engines"])
    bad = [f"{r.get('pod')}: engine={r.get('engine')!r}" for r in ctx.records
           if r.get("engine") and r["engine"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} موتور ناشناخته", bad[:6])
    seen = sorted({r.get("engine") for r in ctx.records if r.get("engine")})
    return result(PASS, f"موتور: {', '.join(seen) or '—'}")


@check("B03", "brain", "اقدام‌ها از فهرست ۱۷ اقدام تعریف‌شده‌اند",
       "اقدام خارج از فهرست یعنی چیزی صادر شده که هیچ handlerی ندارد", "critical")
def b03(ctx):
    known = set(ctx.inv["known_actions"])
    bad = [f"{r.get('pod')}: action={r.get('action')!r}" for r in ctx.records
           if r.get("action") and r["action"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} اقدام ناشناخته", bad[:8])
    seen = sorted({r.get("action") for r in ctx.records if r.get("action")})
    return result(PASS, f"اقدام‌های دیده‌شده: {', '.join(seen) or '—'}")


@check("B04", "brain", "λ متناهی و نامنفی است", "قیمت سایه از حل دوگانه سالم بیرون آمده", "major")
def b04(ctx):
    return _bounded(ctx, "lambda", 0.0, 1e6, optional=True)


@check("B05", "brain", "هر تصمیم انتخاب‌شده امکان‌پذیر هم هست",
       "نقض قرارداد: مغز هرگز نباید حرکتی را انتخاب کند که دروازه‌ی ایمنی ردش کرده", "critical")
def b05(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy','')!r}"
           for r in ctx.records if r.get("selected") and not r.get("feasible")]
    if bad:
        return result(FAIL, f"{len(bad)} تصمیمِ انتخاب‌شده‌ی ناممکن", bad[:8])
    sel = sum(1 for r in ctx.records if r.get("selected"))
    return result(PASS, f"{sel} انتخاب، همه امکان‌پذیر")


@check("B06", "brain", "هر تصمیم یک «چرایی» ناتهی دارد",
       "چیزی که داشبورد نشان می‌دهد باید از خود تصمیم آمده باشد، نه از یک متن ثابت", "major")
def b06(ctx):
    empty = [f"{r.get('pod')} action={r.get('action')}" for r in ctx.records
             if not str(r.get("reason", "")).strip()]
    if empty:
        return result(FAIL, f"{len(empty)} تصمیم بدون چرایی", empty[:8])
    # A reason that never varies is a hardcoded string, not an explanation.
    uniq = {r.get("reason") for r in ctx.records}
    if len(ctx.records) >= 8 and len(uniq) == 1:
        return result(WARN, "همه‌ی رکوردها یک متن یکسان دارند — احتمالاً ثابت است", list(uniq)[:1])
    return result(PASS, f"{len(uniq)} متن متمایز در {len(ctx.records)} رکورد")


@check("B07", "brain", "سقف MaxMovesPerTick رعایت شده",
       "بودجه‌ی هر تیک یک سقف سخت است؛ شکستنش یعنی حلقه‌ی حریصانه زودتر متوقف نشده", "critical")
def b07(ctx):
    if ctx.max_moves_per_tick is None:
        return result(SKIP, "سقف سیاست خوانده نشد")
    per = {}
    for r in ctx.records:
        if r.get("selected"):
            per.setdefault((r.get("tenant"), r.get("time")), []).append(r.get("pod"))
    bad = [f"tenant={t} @ {ts}: {len(p)} انتخاب ({', '.join(p[:4])})"
           for (t, ts), p in per.items() if len(p) > ctx.max_moves_per_tick]
    if bad:
        return result(FAIL, f"{len(bad)} تیک از سقف {ctx.max_moves_per_tick} عبور کرد", bad[:6])
    return result(PASS, f"{len(per)} تیکِ دارای انتخاب، همه ≤ {ctx.max_moves_per_tick}")


@check("B08", "brain", "هر دارایی در هر تیک حداکثر یک اقدام می‌گیرد",
       "قید افراز در حلقه‌ی حریصانه؛ دو اقدام روی یک پاد یعنی selectedAsset کار نکرده", "critical")
def b08(ctx):
    per = {}
    for r in ctx.records:
        if r.get("selected"):
            per.setdefault((r.get("time"), r.get("namespace"), r.get("pod")), []).append(r.get("action"))
    bad = [f"{ns}/{pod} @ {t}: {acts}" for (t, ns, pod), acts in per.items() if len(acts) > 1]
    if bad:
        return result(FAIL, f"{len(bad)} دارایی با بیش از یک اقدام", bad[:6])
    return result(PASS, f"{len(per)} جفت (تیک، دارایی)، همه یکتا")


@check("B09", "brain", "پادافکن R6 برای هر تصمیم ثبت شده",
       "مقایسه‌ی سه‌طرفه‌ی داشبورد از همین می‌آید؛ نبودش یعنی مقایسه ساختگی است", "minor")
def b09(ctx):
    known = set(ctx.inv["known_actions"])
    missing = [f"{r.get('pod')}" for r in ctx.records if not r.get("r6Counterfactual")]
    bad = [f"{r.get('pod')}: {r.get('r6Counterfactual')!r}" for r in ctx.records
           if r.get("r6Counterfactual") and r["r6Counterfactual"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} پادافکن نامعتبر", bad[:6])
    if missing:
        return result(WARN, f"{len(missing)} رکورد بدون پادافکن", missing[:6])
    return result(PASS, f"هر {len(ctx.records)} رکورد پادافکن دارد")


@check("B10", "brain", "سهم‌های انتساب متناهی‌اند",
       "جدول انتساب مستقیم روی داشبورد می‌رود؛ NaN آنجا نامرئی است", "major")
def b10(ctx):
    bad, n = [], 0
    for r in ctx.records:
        for i, t in enumerate(r.get("attribution") or []):
            for k, v in t.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    n += 1
                    if not math.isfinite(v):
                        bad.append(f"{r.get('pod')}: attribution[{i}].{k}={v}")
    if bad:
        return result(FAIL, f"{len(bad)} سهم نامتناهی", bad[:8])
    return result(PASS if n else SKIP, f"{n} سهم عددی، همه متناهی" if n else "هیچ رکوردی انتساب نداشت")


# ─────────────────────────── 5 · feasibility ───────────────────────────

@check("F01", "feasibility", "هر ردّ امکان‌سنجی قانونِ نام‌برده دارد",
       "«ناممکن» بدون دلیل، قابل بازبینی نیست", "major")
def f01(ctx):
    prefixes = ctx.inv["law_reason_prefixes"]
    bad, unknown, matched, n = [], [], {}, 0
    for r in ctx.records:
        if r.get("feasible") is not False:
            continue
        n += 1
        why = str(r.get("infeasibleWhy", "")).strip()
        if not why:
            bad.append(f"{r.get('pod')} action={r.get('action')}")
            continue
        law = next((l for l, pres in prefixes.items() if any(why.startswith(p) or p in why for p in pres)), None)
        if law:
            matched[law] = matched.get(law, 0) + 1
        else:
            unknown.append(f"{r.get('pod')}: {why[:90]}")
    if bad:
        return result(FAIL, f"{len(bad)} ردّ بدون دلیل", bad[:8])
    if unknown:
        return result(FAIL, f"{len(unknown)} دلیل که به هیچ قانون شناخته‌شده‌ای نگاشت نشد", unknown[:6])
    return result(PASS if n else SKIP,
                  f"{n} ردّ، همه به قانون نگاشت شدند" if n else "در این پنجره هیچ ردّی رخ نداد",
                  [f"{k}: {v}" for k, v in sorted(matched.items())])


@check("F02", "feasibility", "هیچ اقدامِ ناممکنی اجرا نشده",
       "دروازه در مرز صدور هم اجرا می‌شود؛ عبور از آن یعنی fail-closed شکسته", "critical")
def f02(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy')!r}"
           for r in ctx.records if r.get("actuated") and r.get("feasible") is False]
    if bad:
        return result(FAIL, f"{len(bad)} اجرای ناممکن", bad)
    return result(PASS, "هیچ اقدام ردشده‌ای به اجرا نرسید")


@check("F03", "feasibility", "روی پاد stateful هیچ rotate صادر نشده",
       "قانون stateful-integrity؛ راستی‌آزمایی با kubectl، نه با ادعای خود رکورد", "critical")
def f03(ctx):
    if not ctx.stateful_by_pod:
        return result(SKIP, "وضعیت stateful پادها از kubectl خوانده نشد")
    bad = []
    for r in ctx.records:
        if r.get("action") != "rotate" or not (r.get("selected") or r.get("actuated")):
            continue
        st = ctx.stateful_by_pod.get((r.get("namespace"), r.get("pod")))
        if st is True:
            bad.append(f"{r.get('namespace')}/{r.get('pod')} rotate روی پاد stateful "
                       f"(selected={r.get('selected')}, actuated={r.get('actuated')})")
    if bad:
        return result(FAIL, f"{len(bad)} نقض یکپارچگی state", bad)
    n = sum(1 for v in ctx.stateful_by_pod.values() if v)
    if n == 0:
        # Passing on an empty set is the "green board built on nothing" failure mode.
        return result(SKIP, "هیچ پاد statefulی در نیم‌اسپیس هدف نیست — چیزی برای آزمودن نبود")
    return result(PASS, f"{n} پاد stateful بررسی شد، هیچ rotate صادر نشد")


# ─────────────────────────── 6 · actuator ───────────────────────────

@check("A01", "actuator", "اجرا فقط پس از انتخاب و امکان‌پذیری رخ داده",
       "زنجیره‌ی مجوز کامل است: انتخاب → امکان‌پذیر → غیر dryRun → اجرا", "critical")
def a01(ctx):
    bad = []
    for r in ctx.records:
        if not r.get("actuated"):
            continue
        if not r.get("selected"):
            bad.append(f"{r.get('pod')}: اجرا شد ولی انتخاب نشده بود")
        if r.get("dryRun"):
            bad.append(f"{r.get('pod')}: اجرا شد با وجود dryRun")
    if bad:
        return result(FAIL, f"{len(bad)} نقض زنجیره‌ی مجوز", bad[:8])
    n = sum(1 for r in ctx.records if r.get("actuated"))
    return result(PASS, f"{n} اجرا، همه با مجوز کامل" if n else "در این پنجره اجرایی رخ نداد")


@check("A02", "actuator", "هر اجرا اثر انگشت قابل بازبینی دارد",
       "handler و اشیای لمس‌شده؛ اجرای بی‌ردّ همان چیزی است که «فیک» به‌نظر می‌رسد", "major")
def a02(ctx):
    acted = [r for r in ctx.records if r.get("actuated")]
    if not acted:
        return result(SKIP, "در این پنجره اجرایی رخ نداد")
    phoenix = set(ctx.inv["phoenix_actions"])
    bad = []
    for r in acted:
        if r.get("action") in phoenix:
            continue  # Phoenix path emits an AMTD CR; A03 verifies it in the cluster
        if not r.get("handler") and not r.get("objectsTouched"):
            bad.append(f"{r.get('pod')} action={r.get('action')}: نه handler، نه شیء لمس‌شده")
    if bad:
        return result(FAIL, f"{len(bad)} اجرای بدون اثر انگشت", bad)
    return result(PASS, f"هر {len(acted)} اجرا اثر انگشت دارد",
                  [f"{r.get('pod')} → {r.get('handler') or r.get('action')} "
                   f"{r.get('objectsTouched') or ''}" for r in acted][:8])


@check("A03", "actuator", "کلاستر تغییرِ ادعاشده را تأیید می‌کند",
       "زمین حقیقتِ مستقل: UID پاد، مالکیت AMTD، یا لاگ خودِ سرویس — نه گزارش خود Phorvex", "critical")
def a03(ctx):
    if not ctx.ground_truth:
        return result(SKIP, "راستی‌آزمایی مستقل اجرا نشد (اجرایی رخ نداد یا حالت observe بود)")
    fails = [g for g in ctx.ground_truth if g["verdict"] == "contradicted"]
    unknown = [g for g in ctx.ground_truth if g["verdict"] == "unverifiable"]
    ev = [f"{g['action']} روی {g['pod']}: {g['detail']}" for g in ctx.ground_truth]
    if fails:
        return result(FAIL, f"{len(fails)} ادعا با کلاستر نمی‌خواند", ev)
    if unknown and len(unknown) == len(ctx.ground_truth):
        return result(WARN, "هیچ ادعایی مستقل قابل تأیید نبود", ev)
    return result(PASS, f"{len(ctx.ground_truth) - len(unknown)} ادعا مستقل تأیید شد", ev)


@check("A04", "actuator", "در حالت dryRun هیچ اجرایی رخ نداده",
       "قرارداد dryRun؛ شکستنش یعنی یک اجرای غیرمنتظره روی کلاستر واقعی", "critical")
def a04(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')}"
           for r in ctx.records if r.get("dryRun") and r.get("actuated")]
    if bad:
        return result(FAIL, f"{len(bad)} اجرا در dryRun", bad)
    n = sum(1 for r in ctx.records if r.get("dryRun"))
    return result(PASS, f"{n} تصمیم dryRun، هیچ‌کدام اجرا نشد" if n else "هیچ تصمیم dryRunی در پنجره نبود")


@check("A06", "actuator", "نبودِ اقدام با وضعیت واقعیِ نویسنده‌ی حسابرسی می‌خواند",
       "«انتخاب شد ولی اجرا نشد» دو علت کاملاً متفاوت دارد: کلید توقفِ عمدی، یا actuator خراب. "
       "این چک آن دو را با متریکِ خودِ اپراتور از هم جدا می‌کند به‌جای اینکه از روی نبودِ اقدام حدس بزند",
       "critical")
def a06(ctx):
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    live = [r for r in ctx.records
            if r.get("selected") and r.get("feasible") and not r.get("dryRun")
            and r.get("action") != "noop"]
    acted = [r for r in live if r.get("actuated")]

    if ks is None:
        if not live:
            return result(SKIP, "نه متریکی خوانده شد نه حرکت زنده‌ای بود")
        if acted:
            return result(PASS, f"{len(acted)} از {len(live)} حرکتِ زنده اجرا شد")
        return result(WARN,
                      f"{len(live)} حرکت انتخاب شد و هیچ‌کدام اجرا نشد، ولی وضعیت کلید توقف خوانده نشد",
                      ["بدون متریکِ نویسنده نمی‌شود گفت این سرکوبِ عمدی است یا خرابی — "
                       "audit_writer.metrics_url را تنظیم کنید"])

    if ks >= 1:
        ev = [f"phorvex_kill_switch_engaged = {ks:g} → این اپراتور عمداً فقط تصمیم می‌گیرد",
              f"{len(live)} حرکت انتخاب شد، {len(acted)} اجرا — مطابق انتظار"]
        if acted:
            return result(FAIL, "کلید توقف فعال است ولی اقدام اجرا شده — سرکوب کار نکرده",
                          ev + [f"{r.get('namespace')}/{r.get('pod')} → {r.get('action')}" for r in acted])
        return result(PASS, "کلید توقف فعال است، پس نبودِ اقدام درست است — actuator خراب نیست", ev)

    if not live:
        return result(SKIP, "کلید توقف خاموش است ولی در این پنجره حرکت زنده‌ای نبود")
    if acted:
        return result(PASS, f"کلید توقف خاموش، {len(acted)} از {len(live)} حرکت اجرا شد")
    by_action = {}
    for r in live:
        by_action[r.get("action")] = by_action.get(r.get("action"), 0) + 1
    return result(FAIL,
                  f"کلید توقف خاموش است ولی هیچ‌کدام از {len(live)} حرکت اجرا نشد",
                  [f"{a}: {n} بار انتخاب، صفر اجرا" for a, n in sorted(by_action.items())]
                  + ["actuator این اپراتور یا وجود ندارد یا این نوع اقدام را پشتیبانی نمی‌کند "
                     "(مسیر Phoenix فقط rotate/quarantine را می‌شناسد)"])


@check("A07", "actuator", "منبع داشبورد مشخص است: آینه‌ی تصمیم یا اپراتورِ اقدام‌کننده",
       "اگر جریانی که داشبورد نشان می‌دهد از یک اپراتورِ kill-switched بیاید، بیننده «تصمیم» را "
       "«اقدام» می‌خواند — ریشه‌ی این برداشت که «actuatorها فیک‌اند»", "major")
def a07(ctx):
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    if ks is None:
        return result(SKIP, "متریک نویسنده‌ی حسابرسی خوانده نشد")
    stamped = sum(1 for r in ctx.records if r.get("killSwitch"))
    if ks < 1:
        return result(PASS, "نویسنده‌ی این حسابرسی اپراتورِ اقدام‌کننده است")
    if stamped == len(ctx.records) and ctx.records:
        return result(PASS, f"آینه‌ی تصمیم است و هر {stamped} رکورد killSwitch=true دارد")
    return result(FAIL,
                  f"آینه‌ی تصمیم است ولی فقط {stamped} از {len(ctx.records)} رکورد آن را ثبت کرده",
                  ["رکوردی با selected=true، dryRun=false، actuated=false و بدون killSwitch "
                   "از یک actuator خراب قابل تفکیک نیست",
                   "رفع در مخزن انجام شد (model/types.go · audit/log.go · runner/manager.go) "
                   "ولی تا بیلد و استقرار مجدد اثر نمی‌کند"])


@check("A05", "actuator", "حمله واکنشی تولید کرد",
       "پایان‌به‌پایانِ واقعی: سیگنال وارد شد و در همان پنجره اقدامی بیرون آمد", "major")
def a05(ctx):
    if not ctx.attack_fired:
        return result(SKIP, "حالت observe — حمله‌ای شلیک نشد")
    ns = ctx.target["namespace"]
    after = [r for r in ctx.post_records if r.get("namespace") == ns]
    acted = [r for r in after if r.get("actuated")]
    selected = [r for r in after if r.get("selected")]
    posture = [r for r in after if _num(r, "threatPosture") > 0]
    ev = [f"پس از شلیک: {len(after)} تصمیم، {len(posture)} با تهدید>0، "
          f"{len(selected)} انتخاب، {len(acted)} اجرا"]
    if acted:
        return result(PASS, f"{len(acted)} اقدام روی {ns}",
                      ev + [f"{r.get('pod')} → {r.get('action')} ({r.get('handler') or 'phoenix'})" for r in acted])
    if selected:
        return result(WARN, "اقدام انتخاب شد ولی اجرا نشد — سیاست را در حالت dryRun بررسی کنید", ev)
    if posture:
        return result(WARN, "تهدید دیده شد ولی هیچ حرکتی صرف نکرد (ممکن است تصمیم درست باشد)", ev)
    return result(FAIL, f"سیگنال حمله در {ns} به هیچ تغییری در تصمیم منجر نشد", ev)
