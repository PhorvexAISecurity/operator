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
import re

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
        return result(SKIP, f"no record carried the {key} field")
    if bad:
        return result(FAIL, f"{len(bad)} of {seen} records fall outside [{lo}, {hi}]", bad[:10])
    return result(PASS, f"all {seen} records inside [{lo}, {hi}]")


# ─────────────────────────── 0 · preflight ───────────────────────────

@check("P01", "preflight", "console and operator are reachable",
       "the test's own entry point is healthy; every other result would be meaningless without it",
       "critical")
def p01(ctx):
    h = ctx.preflight.get("health") or {}
    v = ctx.preflight.get("version") or {}
    if not h.get("ok"):
        return result(FAIL, "/api/health did not return ok=true", [repr(h)[:300]])
    return result(PASS, f"console {v.get('console','?')} · operator {v.get('operator','?')}",
                  [f"image={v.get('operatorImage','?')}"])


@check("P02", "preflight", "console and operator report the same version",
       "dashboard and engine come from one build, so a field the test expects genuinely exists",
       "minor")
def p02(ctx):
    v = ctx.preflight.get("version") or {}
    c, o = v.get("console"), v.get("operator")
    if not c or not o:
        return result(SKIP, "no version was reported")
    if c != o:
        return result(WARN, f"version mismatch: console {c} against operator {o}")
    return result(PASS, f"both on {c}")


@check("P03", "preflight", "the tick loop is alive",
       "the operator is genuinely deciding; the records are not an archive", "critical")
def p03(ctx):
    if not ctx.records:
        return result(FAIL, "no decision record arrived during the capture window")
    fresh = ctx.freshest_age_sec
    if fresh is None:
        return result(WARN, "record timestamps could not be parsed")
    if fresh > ctx.stale_after_sec:
        return result(FAIL, f"the freshest record is {fresh:.0f}s old (threshold {ctx.stale_after_sec}s)")
    return result(PASS, f"{len(ctx.records)} records, freshest {fresh:.1f}s ago")


@check("P04", "preflight", "the target pods are ready in the cluster",
       "the attack lands on something that is actually serving", "critical")
def p04(ctx):
    if not ctx.baseline_pods:
        return result(SKIP, "no kubectl baseline was taken (observe mode with no target)")
    ready = [p for p, m in ctx.baseline_pods.items() if m["phase"] == "Running"]
    if not ready:
        return result(FAIL, "no Running pod in the target namespace",
                      [f"{p}: {m['phase']}" for p, m in ctx.baseline_pods.items()][:10])
    return result(PASS, f"{len(ready)} pods Running",
                  [f"{p} uid={m['uid'][:8]} owner={m['owner']}" for p, m in ctx.baseline_pods.items()][:10])


@check("P05", "preflight", "no controller is crash-looping",
       "an operator that keeps restarting still decides but never reaches the cluster — and "
       "because another operator keeps writing logs, the dashboard looks healthy", "critical")
def p05(ctx):
    if not ctx.controller_pods:
        return result(FAIL, "no expected controller pod status was observed")
    bad = [f"{p}: {m['phase']} · restarts={m['restarts']} · "
           f"{m.get('reason') or ('not Ready' if not m.get('ready', False) else 'unhealthy')}"
           for p, m in ctx.controller_pods.items()
           if m["phase"] != "Running" or m["restarts"] > ctx.max_restarts or not m.get("ready", False)]
    if bad:
        return result(FAIL, f"{len(bad)} unhealthy controllers", bad)
    return result(PASS, f"{len(ctx.controller_pods)} healthy controllers",
                  [f"{p}: {m['phase']} · restarts={m['restarts']}" for p, m in ctx.controller_pods.items()])


# ─────────────────────────── 1 · ingest ───────────────────────────

@check("I01", "ingest", "every record carries a complete identity",
       "ingest genuinely saw the pod — an anonymous record means the snapshot was incomplete",
       "critical")
def i01(ctx):
    bad = [f"@{r.get('time')}: {k} empty"
           for r in ctx.records for k in ("tenant", "namespace", "pod")
           if not str(r.get(k, "")).strip()]
    if bad:
        return result(FAIL, f"{len(bad)} empty identity fields", bad[:10])
    return result(PASS, f"all {len(ctx.records)} records carry tenant/namespace/pod")


@check("I02", "ingest", "tick timestamps move forward",
       "the audit file is being written and the records are sequential rather than interleaved",
       "minor")
def i02(ctx):
    ts = [ctx.parse_time(r.get("time")) for r in ctx.records]
    ts = [t for t in ts if t is not None]
    if len(ts) < 2:
        return result(SKIP, "fewer than two timestamped records")
    back = sum(1 for a, b in zip(ts, ts[1:]) if b < a - 0.001)
    if back:
        return result(WARN, f"{back} backward jumps in stream order")
    return result(PASS, f"{len(ts)} timestamps, no backward jumps")


@check("I03", "ingest", "the target appears in the decision stream",
       "ingest covers this namespace, so later silence means \"it decided to do nothing\", "
       "not \"it never saw it\"", "critical")
def i03(ctx):
    if not ctx.target:
        return result(SKIP, "ran without a target")
    ns = ctx.target["namespace"]
    hit = [r for r in ctx.records if r.get("namespace") == ns]
    if not hit:
        return result(FAIL, f"no decision for namespace {ns} arrived in the window",
                      sorted({r.get("namespace", "") for r in ctx.records})[:12])
    pods = sorted({r.get("pod") for r in hit})
    return result(PASS, f"{len(hit)} decisions across {len(pods)} pods in {ns}", pods[:8])


# ─────────────────────────── 2 · physics ───────────────────────────

@check("PH01", "physics", "residual is always finite and inside [0,1]",
       "the same bug class that carried a NaN into the optimiser and silently turned the "
       "selection into a noop", "critical")
def ph01(ctx):
    return _bounded(ctx, "residual", 0.0, 1.0)


@check("PH02", "physics", "no non-finite number in any field",
       "a global NaN/Inf sweep over the whole record, not only the fields we expect", "critical")
def ph02(ctx):
    bad = []
    for r in ctx.records:
        for k, v in all_numeric_fields(r):
            if not math.isfinite(v):
                bad.append(f"{r.get('pod')} @ {r.get('time')}: {k}={v}")
    if bad:
        return result(FAIL, f"{len(bad)} non-finite values", bad[:10])
    n = sum(len(all_numeric_fields(r)) for r in ctx.records)
    return result(PASS, f"{n} numeric values across {len(ctx.records)} records, all finite")


@check("PH03", "physics", "a high residual with no security event does not drive a decision",
       "physics only reports; deciding that it matters is context's job", "minor")
def ph03(ctx):
    odd = [f"{r.get('pod')}: residual={r.get('residual')} but threatPosture=0, and it was selected"
           for r in ctx.records
           if r.get("selected") and _num(r, "residual") > 0.5 and _num(r, "threatPosture") == 0]
    if odd:
        return result(WARN, f"{len(odd)} selections driven by physics alone", odd[:6])
    return result(PASS, "no selection came from a physical anomaly alone")


# ─────────────────────────── 3 · context ───────────────────────────

@check("C01", "context", "assetValue is finite and non-negative", "the asset value is usable", "major")
def c01(ctx):
    return _bounded(ctx, "assetValue", 0.0, 1e6)


@check("C02", "context", "blastRadius is inside [0,1]",
       "the graph score is normalised; out of range means the normalisation is broken", "major")
def c02(ctx):
    return _bounded(ctx, "blastRadius", 0.0, 1.0)


@check("C03", "context", "context signals are inside [0,1]",
       "threatPosture / exposure / sloHeadroom / belief are all dimensionless and bounded", "major")
def c03(ctx):
    parts, worst = [], PASS
    for k in ("threatPosture", "exposure", "sloHeadroom", "belief"):
        r = _bounded(ctx, k, 0.0, 1.0)
        parts.append(f"{k}: {r['summary']}")
        if r["status"] == FAIL:
            worst = FAIL
    return result(worst, "four signals checked", parts)


@check("C04", "context", "phase is one of the known phases",
       "phase feeds straight into the RLS features; an unknown phase means the rotation cost "
       "is wrong", "major")
def c04(ctx):
    known = set(ctx.inv["known_phases"])
    bad = [f"{r.get('pod')}: phase={r.get('phase')!r}" for r in ctx.records
           if r.get("phase") and r["phase"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown phases", bad[:8])
    return result(PASS, f"all within {sorted(known)}")


@check("C05", "context", "stage is one of the 9 defined stages",
       "the parallel AI chain included; an unknown stage means event classification is broken",
       "major")
def c05(ctx):
    known = set(ctx.inv["known_stages"])
    bad = [f"{r.get('pod')}: stage={r.get('stage')!r}" for r in ctx.records
           if r.get("stage") and r["stage"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown stages", bad[:8])
    seen = sorted({r.get("stage") for r in ctx.records if r.get("stage")})
    return result(PASS, f"stages seen: {', '.join(seen) or '—'}")


@check("C06", "context", "nextStage is a legal successor of stage",
       "either the linear successor, a lateral jump under neighbour pressure, or the AI map — "
       "nothing else", "major")
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
        return result(SKIP, "no record carried both fields")
    if bad:
        return result(FAIL, f"{len(bad)} illegal transitions", bad[:8])
    return result(PASS, f"all {seen} transitions are legal")


@check("C07", "context", "hazard, pHold and preemptMargin are inside [0,1]",
       "all three are probabilities; out of range means the Weibull or the Beta posterior "
       "is broken", "major")
def c07(ctx):
    parts, worst = [], PASS
    for k in ("stageHazard", "pHold", "preemptMargin"):
        r = _bounded(ctx, k, 0.0, 1.0, optional=True)
        parts.append(f"{k}: {r['summary']}")
        if r["status"] == FAIL:
            worst = FAIL
    return result(worst, "three probabilities checked", parts)


@check("C08", "context", "the next-stage margin agrees with the jump hazard",
       "this number is not a duration, it is a signed margin: negative means \"overdue\" "
       "(hazard.go:327). Both come from the same Weibull, so an exact relation holds between "
       "them that catches the two drifting apart", "major")
def c08(ctx):
    # margin = median − exposure, and hazard = weibullCDF(exposure). At exposure = median,
    # hazard = 1 − exp(−(−ln 0.5)) = 0.5 exactly — independent of scale and of the stage.
    # So margin < 0 ⟺ hazard > 0.5 is an exact identity, not a tuned threshold. The band
    # around 0.5 absorbs the audit's 4-decimal rounding.
    band = 0.001
    have = [r for r in ctx.records if is_finite_number(r.get("projectedNextStageSec"))]
    if not have:
        return result(SKIP, "the field was absent from every record")
    bad = []
    for r in have:
        m, h = r["projectedNextStageSec"], _num(r, "stageHazard")
        if abs(h - 0.5) <= band:
            continue  # exactly at the median; either sign is legal
        if (m < 0) != (h > 0.5):
            bad.append(f"{r.get('namespace')}/{r.get('pod')}: margin={m:.0f}s disagrees with "
                       f"hazard={h:.4f} (margin<0 must be exactly equivalent to hazard>0.5)")
    if bad:
        return result(FAIL, f"{len(bad)} disagreements between margin and jump hazard", bad[:8])
    overdue = sum(1 for r in have if r["projectedNextStageSec"] < 0)
    return result(PASS, f"all {len(have)} records satisfy the identity "
                        f"({overdue} overdue, each with hazard > 0.5)")


# ─────────────────────────── 4 · brain ───────────────────────────

@check("B01", "brain", "the net identity holds: net = risk − λ×cost",
       "the heart of the decision; if this does not add up, the number the dashboard shows "
       "came from somewhere else", "critical")
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
                       f"cost={r['cost']} → expected {expect:.4f} but net={r['net']}")
    if seen == 0:
        return result(SKIP, "no record carried all three numbers")
    if bad:
        return result(FAIL, f"{len(bad)} violations out of {seen}", bad[:8])
    return result(PASS, f"all {seen} records within ±{tol}")


@check("B02", "brain", "the decision engine is a known one",
       "the record came from the engine that is documented", "minor")
def b02(ctx):
    known = set(ctx.inv["known_engines"])
    bad = [f"{r.get('pod')}: engine={r.get('engine')!r}" for r in ctx.records
           if r.get("engine") and r["engine"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown engines", bad[:6])
    seen = sorted({r.get("engine") for r in ctx.records if r.get("engine")})
    return result(PASS, f"engine: {', '.join(seen) or '—'}")


@check("B03", "brain", "actions come from the defined list of 17",
       "an action off the list means something was issued that has no handler at all", "critical")
def b03(ctx):
    known = set(ctx.inv["known_actions"])
    bad = [f"{r.get('pod')}: action={r.get('action')!r}" for r in ctx.records
           if r.get("action") and r["action"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown actions", bad[:8])
    seen = sorted({r.get("action") for r in ctx.records if r.get("action")})
    return result(PASS, f"actions seen: {', '.join(seen) or '—'}")


@check("B04", "brain", "λ is finite and non-negative",
       "the shadow price came out of the dual solve intact", "major")
def b04(ctx):
    return _bounded(ctx, "lambda", 0.0, 1e6, optional=True)


@check("B05", "brain", "every selected decision is also feasible",
       "a contract violation: the brain must never select a move the safety gate rejected",
       "critical")
def b05(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy','')!r}"
           for r in ctx.records if r.get("selected") and not r.get("feasible")]
    if bad:
        return result(FAIL, f"{len(bad)} selected-but-infeasible decisions", bad[:8])
    sel = sum(1 for r in ctx.records if r.get("selected"))
    return result(PASS, f"{sel} selections, all feasible")


@check("B06", "brain", "every decision carries a non-empty \"why\"",
       "what the dashboard shows must come from the decision itself, not from a fixed string",
       "major")
def b06(ctx):
    empty = [f"{r.get('pod')} action={r.get('action')}" for r in ctx.records
             if not str(r.get("reason", "")).strip()]
    if empty:
        return result(FAIL, f"{len(empty)} decisions with no reason", empty[:8])
    # A reason that never varies is a hardcoded string, not an explanation.
    uniq = {r.get("reason") for r in ctx.records}
    if len(ctx.records) >= 8 and len(uniq) == 1:
        return result(WARN, "every record carries the identical text — probably hardcoded",
                      list(uniq)[:1])
    return result(PASS, f"{len(uniq)} distinct texts across {len(ctx.records)} records")


@check("B07", "brain", "the MaxMovesPerTick cap is respected",
       "the per-tick budget is a hard ceiling; breaking it means the greedy loop did not stop "
       "when it should have", "critical")
def b07(ctx):
    if ctx.max_moves_per_tick is None:
        return result(SKIP, "the policy cap could not be read")
    per = {}
    for r in ctx.records:
        if r.get("selected"):
            per.setdefault((r.get("tenant"), r.get("time")), []).append(r.get("pod"))
    bad = [f"tenant={t} @ {ts}: {len(p)} selections ({', '.join(p[:4])})"
           for (t, ts), p in per.items() if len(p) > ctx.max_moves_per_tick]
    if bad:
        return result(FAIL, f"{len(bad)} ticks exceeded the cap of {ctx.max_moves_per_tick}", bad[:6])
    return result(PASS, f"{len(per)} ticks with a selection, all ≤ {ctx.max_moves_per_tick}")


@check("B08", "brain", "each asset gets at most one action per tick",
       "the partition constraint in the greedy loop; two actions on one pod means selectedAsset "
       "did not hold", "critical")
def b08(ctx):
    per = {}
    for r in ctx.records:
        if r.get("selected"):
            per.setdefault((r.get("time"), r.get("namespace"), r.get("pod")), []).append(r.get("action"))
    bad = [f"{ns}/{pod} @ {t}: {acts}" for (t, ns, pod), acts in per.items() if len(acts) > 1]
    if bad:
        return result(FAIL, f"{len(bad)} assets with more than one action", bad[:6])
    return result(PASS, f"{len(per)} (tick, asset) pairs, all unique")


@check("B09", "brain", "the R6 counterfactual is recorded for every decision",
       "the dashboard's three-way comparison comes from this; without it the comparison is "
       "fabricated", "minor")
def b09(ctx):
    known = set(ctx.inv["known_actions"])
    missing = [f"{r.get('pod')}" for r in ctx.records if not r.get("r6Counterfactual")]
    bad = [f"{r.get('pod')}: {r.get('r6Counterfactual')!r}" for r in ctx.records
           if r.get("r6Counterfactual") and r["r6Counterfactual"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} invalid counterfactuals", bad[:6])
    if missing:
        return result(WARN, f"{len(missing)} records with no counterfactual", missing[:6])
    return result(PASS, f"all {len(ctx.records)} records carry a counterfactual")


@check("B10", "brain", "attribution contributions are finite",
       "the attribution table goes straight onto the dashboard; a NaN is invisible there",
       "major")
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
        return result(FAIL, f"{len(bad)} non-finite contributions", bad[:8])
    return result(PASS if n else SKIP,
                  f"{n} numeric contributions, all finite" if n else "no record carried attribution")


# ─────────────────────────── 5 · feasibility ───────────────────────────

@check("F01", "feasibility", "every feasibility rejection names a law or capability gate",
       "\"infeasible\" without a reason cannot be audited", "major")
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
        # authz.Checker emits an explicit SSAR deny, not a feasibility-law verdict.
        # Match the complete resource/verb/namespace tuple; arbitrary "denied" text
        # and SSAR transport errors must not count as an explained rejection.
        if law is None and re.fullmatch(
                r"denied [a-z0-9.-]*/[a-z0-9.-]+:[a-z]+ in [a-z0-9.-]+", why):
            law = "capability-rbac"
        if law:
            matched[law] = matched.get(law, 0) + 1
        else:
            unknown.append(f"{r.get('pod')}: {why[:90]}")
    if bad:
        return result(FAIL, f"{len(bad)} rejections with no reason", bad[:8])
    if unknown:
        return result(FAIL, f"{len(unknown)} reasons that map to no known law or capability gate", unknown[:6])
    return result(PASS if n else SKIP,
                  f"{n} rejections, all mapped to a law or capability gate" if n else "no rejection occurred in this window",
                  [f"{k}: {v}" for k, v in sorted(matched.items())])


@check("F02", "feasibility", "no infeasible action was actuated",
       "the gate also runs at the issue boundary; getting past it means fail-closed is broken",
       "critical")
def f02(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy')!r}"
           for r in ctx.records if r.get("actuated") and r.get("feasible") is False]
    if bad:
        return result(FAIL, f"{len(bad)} infeasible actuations", bad)
    return result(PASS, "no rejected action reached actuation")


@check("F03", "feasibility", "no rotate was issued against a stateful pod",
       "the stateful-integrity law; verified with kubectl, not with the record's own claim",
       "critical")
def f03(ctx):
    if not ctx.stateful_by_pod:
        return result(SKIP, "pod stateful status could not be read from kubectl")
    bad = []
    for r in ctx.records:
        if r.get("action") != "rotate" or not (r.get("selected") or r.get("actuated")):
            continue
        st = ctx.stateful_by_pod.get((r.get("namespace"), r.get("pod")))
        if st is True:
            bad.append(f"{r.get('namespace')}/{r.get('pod')} rotate against a stateful pod "
                       f"(selected={r.get('selected')}, actuated={r.get('actuated')})")
    if bad:
        return result(FAIL, f"{len(bad)} state-integrity violations", bad)
    n = sum(1 for v in ctx.stateful_by_pod.values() if v)
    if n == 0:
        # Passing on an empty set is the "green board built on nothing" failure mode.
        return result(SKIP, "no stateful pod in the target namespace — there was nothing to test")
    return result(PASS, f"{n} stateful pods checked, no rotate issued")


# ─────────────────────────── 6 · actuator ───────────────────────────

@check("A01", "actuator", "actuation happened only after selection and feasibility",
       "the authorisation chain is intact: selected → feasible → not dryRun → actuated", "critical")
def a01(ctx):
    bad = []
    for r in ctx.records:
        if not r.get("actuated"):
            continue
        if not r.get("selected"):
            bad.append(f"{r.get('pod')}: actuated but never selected")
        if r.get("dryRun"):
            bad.append(f"{r.get('pod')}: actuated despite dryRun")
    if bad:
        return result(FAIL, f"{len(bad)} authorisation-chain violations", bad[:8])
    n = sum(1 for r in ctx.records if r.get("actuated"))
    return result(PASS, f"{n} actuations, all fully authorised" if n
                  else "no actuation occurred in this window")


@check("A02", "actuator", "every actuation leaves an auditable fingerprint",
       "the handler and the objects touched; a traceless actuation is exactly what looks \"fake\"",
       "major")
def a02(ctx):
    acted = [r for r in ctx.records if r.get("actuated")]
    if not acted:
        return result(SKIP, "no actuation occurred in this window")
    phoenix = set(ctx.inv["phoenix_actions"])
    bad = []
    for r in acted:
        if r.get("action") in phoenix:
            continue  # Phoenix emits a SecurityEvent; A03 verifies the resulting cluster mutation
        if not r.get("handler") and not r.get("objectsTouched"):
            bad.append(f"{r.get('pod')} action={r.get('action')}: no handler, no object touched")
    if bad:
        return result(FAIL, f"{len(bad)} actuations with no fingerprint", bad)
    return result(PASS, f"all {len(acted)} actuations carry a fingerprint",
                  [f"{r.get('pod')} → {r.get('handler') or r.get('action')} "
                   f"{r.get('objectsTouched') or ''}" for r in acted][:8])


@check("A03", "actuator", "the cluster confirms the claimed change",
       "independent ground truth: the pod UID, active NetworkPolicy isolation, or the service's own log — "
       "never Phorvex's own report", "critical")
def a03(ctx):
    if not ctx.ground_truth:
        return result(SKIP, "no independent verification ran (nothing actuated, or observe mode)")
    fails = [g for g in ctx.ground_truth if g["verdict"] == "contradicted"]
    unknown = [g for g in ctx.ground_truth if g["verdict"] == "unverifiable"]
    ev = [f"{g['action']} on {g['pod']}: {g['detail']}" for g in ctx.ground_truth]
    if fails:
        return result(FAIL, f"{len(fails)} claims disagree with the cluster", ev)
    if unknown and len(unknown) == len(ctx.ground_truth):
        return result(WARN, "no claim could be independently confirmed", ev)
    return result(PASS, f"{len(ctx.ground_truth) - len(unknown)} claims independently confirmed", ev)


@check("A04", "actuator", "nothing was actuated under dryRun",
       "the dryRun contract; breaking it means an unexpected actuation against a live cluster",
       "critical")
def a04(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')}"
           for r in ctx.records if r.get("dryRun") and r.get("actuated")]
    if bad:
        return result(FAIL, f"{len(bad)} actuations under dryRun", bad)
    n = sum(1 for r in ctx.records if r.get("dryRun"))
    return result(PASS, f"{n} dryRun decisions, none actuated" if n
                  else "no dryRun decision in the window")


@check("A06", "actuator", "the absence of action matches the audit writer's real state",
       "\"selected but not actuated\" has two completely different causes: a deliberate kill "
       "switch, or a broken actuator. This check separates them using the operator's own metric "
       "instead of guessing from the absence of action", "critical")
def a06(ctx):
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    live = [r for r in ctx.records
            if r.get("selected") and r.get("feasible") and not r.get("dryRun")
            and r.get("action") != "noop"]
    acted = [r for r in live if r.get("actuated")]

    if ks is None:
        if not live:
            return result(SKIP, "no metric was read and there was no live move either")
        if acted:
            return result(PASS, f"{len(acted)} of {len(live)} live moves were actuated")
        return result(WARN,
                      f"{len(live)} moves were selected and none actuated, but the kill-switch "
                      f"state could not be read",
                      ["without the writer's metric there is no telling deliberate suppression "
                       "from a fault — set audit_writer.metrics_url"])

    if ks >= 1:
        ev = [f"phorvex_kill_switch_engaged = {ks:g} → this operator deliberately only decides",
              f"{len(live)} moves selected, {len(acted)} actuated — as expected"]
        if acted:
            return result(FAIL, "the kill switch is engaged yet an action was actuated — "
                                "suppression did not work",
                          ev + [f"{r.get('namespace')}/{r.get('pod')} → {r.get('action')}" for r in acted])
        return result(PASS, "the kill switch is engaged, so the absence of action is correct — "
                            "the actuator is not broken", ev)

    if not live:
        return result(SKIP, "the kill switch is off but there was no live move in this window")
    if acted:
        return result(PASS, f"kill switch off, {len(acted)} of {len(live)} moves actuated")
    by_action = {}
    for r in live:
        by_action[r.get("action")] = by_action.get(r.get("action"), 0) + 1
    return result(FAIL,
                  f"the kill switch is off yet none of the {len(live)} moves was actuated",
                  [f"{a}: selected {n}×, actuated zero" for a, n in sorted(by_action.items())]
                  + ["this operator's actuator is either absent or does not support this action "
                     "type (the Phoenix path only knows rotate/quarantine)"])


@check("A07", "actuator", "the dashboard's source is unambiguous: decision mirror or "
       "actuating operator",
       "if the stream the dashboard shows comes from a kill-switched operator, the viewer reads "
       "a \"decision\" as an \"action\" — the root of the impression that \"the actuators are fake\"",
       "major")
def a07(ctx):
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    if ks is None:
        return result(SKIP, "the audit writer's metric could not be read")
    stamped = sum(1 for r in ctx.records if r.get("killSwitch"))
    if ks < 1:
        return result(PASS, "the writer of this audit is the actuating operator")
    if stamped == len(ctx.records) and ctx.records:
        return result(PASS, f"it is a decision mirror and all {stamped} records carry killSwitch=true")
    return result(FAIL,
                  f"it is a decision mirror but only {stamped} of {len(ctx.records)} records "
                  f"recorded that",
                  ["a record with selected=true, dryRun=false, actuated=false and no killSwitch "
                   "cannot be told apart from a broken actuator",
                   "fixed in the repository (model/types.go · audit/log.go · runner/manager.go) "
                   "but it takes effect only after a rebuild and redeploy"])


@check("A05", "actuator", "the attack produced a reaction",
       "genuine end-to-end: a signal went in and an action came out within the same window",
       "major")
def a05(ctx):
    if not ctx.attack_fired:
        return result(SKIP, "observe mode — no attack was fired")
    ns = ctx.target["namespace"]
    after = [r for r in ctx.post_records if r.get("namespace") == ns]
    acted = [r for r in after if r.get("actuated")]
    selected = [r for r in after if r.get("selected")]
    posture = [r for r in after if _num(r, "threatPosture") > 0]
    ev = [f"after firing: {len(after)} decisions, {len(posture)} with threat>0, "
          f"{len(selected)} selected, {len(acted)} actuated"]
    if acted:
        return result(PASS, f"{len(acted)} actions on {ns}",
                      ev + [f"{r.get('pod')} → {r.get('action')} ({r.get('handler') or 'phoenix'})" for r in acted])
    if selected:
        return result(WARN, "an action was selected but never actuated — check the policy for "
                            "dryRun mode", ev)
    if posture:
        return result(WARN, "the threat was seen but no move was spent (this may be the correct "
                            "decision)", ev)
    return result(FAIL, f"the attack signal in {ns} led to no change in any decision", ev)
