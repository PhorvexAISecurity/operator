"""Turn one audit record into a five-stage trace.

An `audit.Record` is already a complete end-to-end trace of one decision: it carries the
physics residual, the context signals, the kill-chain assessment, the brain's cost/gain
terms, the feasibility verdict, and what the actuator actually touched. This module does
not compute anything — it groups those fields into the stages they came from and attaches,
for every field, the source that produced it. That provenance is what lets the dashboard
answer "why" instead of only "what".

Adding a field here is the only change needed for it to appear in the dashboard.
"""

import math

# (key, Persian label, range/unit, producing function, why it matters)
FIELDS = {
    "ingest": [
        ("tenant",    "تنانت",            "رشته",   "ingest/kube.go:77 CollectSnapshot", "کدام سیاست بر این پاد حاکم است"),
        ("namespace", "نیم‌اسپیس",         "رشته",   "ingest/kube.go:77 CollectSnapshot", "محل پاد در کلاستر"),
        ("pod",       "پاد",              "رشته",   "ingest/kube.go:77 CollectSnapshot", "دارایی تحت بررسی"),
        ("node",      "نود",              "رشته",   "ingest/kube.go:186 collectNodes",   "برای نرخ دلاری و امکان‌سنجی سخت‌افزاری"),
        ("time",      "زمان تیک",          "RFC3339", "runner/manager.go tick",           "اثبات اینکه رکورد تازه است، نه بایگانی"),
    ],
    "physics": [
        ("residual",  "ناهنجاری فیزیکی",   "0 … 1",  "physics/littleslaw.go:31 Residual", "ترکیب ۰٫۷×بیشترین + ۰٫۳×میانگین چهار سنجه؛ صفر یعنی «داده نداریم» نه «امن است»"),
    ],
    "context": [
        ("assetValue",   "ارزش دارایی",      "≥ 0",   "ctxprov/sensed.go:24 Context",       "لیبل‌ها + سکرت‌ها + شعاع انفجار، ضرب‌در مرز آلودگی"),
        ("blastRadius",  "شعاع انفجار",      "0 … 1", "graph/reachability.go:251 reachScore", "دسترسی میرا تا ۳ گام، نرمال‌شده به بدترین پادِ کلاستر"),
        ("threatPosture", "وضعیت تهدید",     "0 … 1", "ctxprov/sensed.go:24 Context",       "شدت رویدادها، میراشده با سن رویداد"),
        ("exposure",     "فشار در معرض بودن", "0 … 1", "ctxprov/sensed.go:24 Context",       "زمان از آخرین جابه‌جایی نسبت به کف پیش‌دستانه"),
        ("sloHeadroom",  "حاشیه‌ی SLO",      "0 … 1", "ctxprov/sensed.go:24 Context",       "۱ یعنی آزادی کامل برای اقدام"),
        ("belief",       "باور نگه‌داشتن",    "0 … 1", "killchain/hazard.go:236 Assess",     "همان pHold؛ احتمال اینکه مهاجم هنوز جای پا دارد"),
        ("phase",        "فاز بار کاری",     "متنی",  "ctxprov/sensed.go:24 Context",       "تعیین‌کننده‌ی هزینه‌ی چرخش در RLS"),
        ("stage",        "مرحله‌ی مهاجم",    "متنی",  "killchain/hazard.go:236 Assess",     "recon → exploit → persist → lateral → impact"),
        ("nextStage",    "مرحله‌ی بعدی",     "متنی",  "killchain/hazard.go:44 successorOf",  "با فشار همسایه می‌تواند از مراحل میانی بپرد"),
        ("stageHazard",  "خطر جهش",         "0 … 1", "killchain/hazard.go:156 weibullCDF",  "وایبول با شکل ۲ — نرخ خطر با ماندن خطی بالا می‌رود"),
        ("pHold",        "P(نگه‌داشتن)",     "0 … 1", "killchain/hazard.go:236 Assess",     "پسین بتا × میرایی بازیابی ۳۰ ثانیه‌ای"),
        ("preemptMargin", "حاشیه‌ی پیش‌دستی", "0 … 1", "killchain/hazard.go:309",           "احتمال بقا: آیا تا اجرای اقدام هنوز جلوتریم"),
        ("projectedNextStageSec", "حاشیه تا مرحله‌ی بعد", "ثانیه، علامت‌دار", "killchain/hazard.go:330 projectedNextStageSec", "میانه‌ی زمان جهش منهای سنِ مرحله. مثبت = هنوز فرصت داریم؛ منفی = از موعد گذشته و مدل می‌گوید باید قبلاً جهیده باشد"),
    ],
    "brain": [
        ("engine",        "موتور تصمیم",     "متنی",  "decision/coverage.go:79 Name",       "p1-coverage یعنی حریصانه‌ی زیرمُدولار"),
        ("lambda",        "λ قیمت سایه",     "≥ 0",   "cost/dual.go:54 Step",              "خودتنظیم با فشار بودجه؛ دستی ست نمی‌شود"),
        ("risk",          "پوشش (منفعت)",    "≥ 0",   "decision/coverage.go:381",          "وزن حقیقت‌های شناساییِ باطل‌شده توسط این حرکت"),
        ("cost",          "ECost",           "≥ 0",   "cost/p1cost.go:49 ECost",           "0.4×C_norm + 0.6×C_flow — بی‌بعد"),
        ("net",           "خالص",            "حقیقی", "decision/coverage.go:378",          "risk − λ×cost؛ همین یک تفریق تصمیم را می‌سازد"),
        ("perDollar",     "پوشش به ازای هزینه", "≥ 0", "decision/coverage.go:355",         "معیار مقایسه‌ی کاندیداها"),
        ("coveredWeight", "وزن پوشش‌داده‌شده", "≥ 0",  "decision/coverage.go:256",          "سهم تازه‌ای که این حرکت اضافه می‌کند"),
        ("coveredFacts",  "تعداد حقیقت‌ها",   "عدد",   "decision/coverage.go:256",          "چند حقیقت مستقل باطل می‌شود"),
        ("proactiveRate", "نرخ پیش‌دستانه",   "≥ 0",   "decision/coverage.go:366",          "perDollar − λ؛ صفر یعنی «هنوز وقتش نیست»"),
        ("action",        "اقدام انتخابی",    "متنی",  "decision/coverage.go:159 Decide",   "خروجی حلقه‌ی حریصانه"),
        ("selected",      "انتخاب شد",       "بولی",  "decision/coverage.go:246",          "درون سقف MaxMovesPerTick قرار گرفت"),
        ("reason",        "چرایی",           "متنی",  "decision/coverage.go:500 coverageReason", "توضیح تولیدشده از همان اعداد بالا"),
        ("r6Counterfactual", "R6 چه می‌کرد",  "متنی",  "decision/engine.go:234",           "تایمر کور رقیب"),
        ("counterfactualNote", "تفاوت با R6", "متنی",  "decision/coverage.go:477",         "چرا انتخاب ما با آن فرق دارد"),
        ("blindCost",     "هزینه‌ی تایمر کور", "≥ 0",  "decision/coverage.go",              "هزینه‌ای که R6 این چرخه می‌پردازد"),
    ],
    "feasibility": [
        ("feasible",      "امکان‌پذیر",       "بولی",  "feasibility/constraint.go:58 Evaluate", "دروازه دو بار اجرا می‌شود: ساخت مجموعه و مرز صدور"),
        ("infeasibleWhy", "قانون بازدارنده",  "متنی",  "feasibility/constraint.go:46 checkLaw", "اولین قانونی که جلو را گرفت؛ panic هم «ناممکن» است"),
    ],
    "actuator": [
        ("actuated",       "اجرا شد",        "بولی",  "runner/manager.go:584 actuate",       "دست واقعاً به کلاستر خورد"),
        ("dryRun",         "حالت آزمایشی",   "بولی",  "PhorvexPolicy.dryRun",                "در dryRun هرگز actuated نمی‌شود"),
        ("killSwitch",     "کلید توقف سراسری", "بولی", "runner/manager.go:543 killEngaged",   "دروازه‌ای جدا از dryRun: اقدام را سرکوب می‌کند ولی dryRun را false می‌گذارد. بدون این فیلد، یک آینه‌ی تصمیم از یک actuator خراب قابل تفکیک نیست"),
        ("handler",        "اجراکننده",      "متنی",  "actuator/handler.go Registry",        "کدام از ۱۶ handler ثبت‌شده کار را کرد"),
        ("objectsTouched", "اشیای لمس‌شده",  "لیست",  "actuator/handler.go:54",              "اثر انگشت قابل بازبینی روی کلاستر"),
        ("mutationKind",   "نوع تغییر",      "متنی",  "actuator/handler.go:57",              "برگشت‌پذیر / برگشت‌ناپذیر / رو به جلو"),
        ("rollbackRef",    "مرجع بازگشت",    "متنی",  "actuator/handler.go:55",              "چطور می‌شود برگرداند"),
    ],
}

STAGE_ORDER = ["ingest", "physics", "context", "brain", "feasibility", "actuator"]
STAGE_LABEL = {
    "ingest": "۱ · ورود",
    "physics": "۲ · فیزیک",
    "context": "۳ · زمینه",
    "brain": "۴ · مغز",
    "feasibility": "۵ · امکان‌سنجی",
    "actuator": "۶ · اقدام",
}


def is_finite_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def trace_of(rec):
    """Group one record's fields into stages, keeping absence distinguishable from zero."""
    stages = []
    for name in STAGE_ORDER:
        fields = []
        for key, label, rng, src, why in FIELDS[name]:
            present = key in rec
            fields.append({
                "key": key, "label": label, "range": rng, "source": src, "why": why,
                "value": rec.get(key), "present": present,
            })
        stages.append({"stage": name, "label": STAGE_LABEL[name], "fields": fields})
    return {
        "id": f"{rec.get('time','')}|{rec.get('namespace','')}/{rec.get('pod','')}|{rec.get('action','')}",
        "time": rec.get("time", ""),
        "tenant": rec.get("tenant", ""),
        "namespace": rec.get("namespace", ""),
        "pod": rec.get("pod", ""),
        "action": rec.get("action", ""),
        "selected": bool(rec.get("selected")),
        "actuated": bool(rec.get("actuated")),
        "feasible": bool(rec.get("feasible")),
        "attribution": rec.get("attribution") or [],
        "stages": stages,
        "raw": rec,
    }


def all_numeric_fields(rec):
    """Every numeric leaf, for the global non-finite sweep."""
    out = []
    for k, v in rec.items():
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            out.append((k, v))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        if isinstance(iv, (int, float)) and not isinstance(iv, bool):
                            out.append((f"{k}[{i}].{ik}", iv))
    return out
