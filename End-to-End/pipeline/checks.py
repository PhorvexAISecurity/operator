"""The assertion catalogue.

Every check states three things: what it inspects, what a pass *proves*, and how it can
fail. A check that cannot be evaluated returns SKIP with the reason — it never returns
PASS for something it did not actually look at, because a green board built on unrun
checks is worse than a red one.

Severity is about consequence, not confidence:
  critical — a contract violation; the system did something it says it never does
  major    — a value or explanation the dashboard would show that is wrong or impossible
  minor    — a smell worth reporting that does not by itself invalidate a run

Two things every result now carries, because status alone was hiding them:

  coverage — how much of what the check claims it actually saw. `full`, `partial` (some
             records or components were unavailable), `none` (nothing was observable) or
             `not-applicable` (the situation the check is about did not arise). A PASS at
             `partial` coverage is a smaller claim than a PASS at `full`, and the run
             verdict and the PR comment both read this field.
  inputs   — the record fields and cluster observations the verdict rests on. The full
             table, with each field's producer and what its absence means, is CHECKS.md.

An absent number is never read as zero. `residual` missing is "we did not observe it",
which is a different fact from "we observed 0.0", and the check that turned the first into
the second is the reason a NaN could ride through the optimiser unremarked.
"""

import math
import re

import attribution as attribution_mod
from trace import all_numeric_fields, is_finite_number

PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"

# Coverage is orthogonal to status: a check can pass over half its intended inputs.
FULL, PARTIAL, NONE, NOT_APPLICABLE = "full", "partial", "none", "not-applicable"

_REGISTRY = []


def check(cid, stage, title, proves, severity="major", inputs=()):
    def deco(fn):
        _REGISTRY.append({
            "id": cid, "stage": stage, "title": title,
            "proves": proves, "severity": severity, "inputs": list(inputs), "fn": fn,
        })
        return fn
    return deco


def registry():
    return list(_REGISTRY)


def result(status, summary, evidence=None, coverage=None):
    if coverage is None:
        coverage = NONE if status == SKIP else FULL
    return {"status": status, "summary": summary, "evidence": evidence or [],
            "coverage": coverage}


def _ctx(ctx, name, default=None):
    """Checks are called with whatever the run assembled; absent context is not zero."""
    return getattr(ctx, name, default)


def _scope_note(ctx):
    """Every check that counts 'all decisions' has to say which decisions it could see."""
    scope = _ctx(ctx, "scope")
    if scope is None or getattr(scope, "is_global", True):
        return ""
    return f" (capture scope: {scope.describe()})"


def _scope_coverage(ctx, coverage=FULL):
    scope = _ctx(ctx, "scope")
    if scope is not None and not getattr(scope, "is_global", True) and coverage == FULL:
        return PARTIAL
    return coverage


def _present(rec, key):
    """Presence, not truthiness: 0.0 is an observation and absence is not."""
    return key in rec


def _finite(rec, key):
    return is_finite_number(rec.get(key))


def _in_range(v, lo, hi):
    return is_finite_number(v) and lo - 1e-9 <= v <= hi + 1e-9


def _bounded(ctx, key, lo, hi, optional=False):
    """Shared body for the many [lo,hi] field checks.

    `optional=True` names a field the producer emits with `omitempty`, so its absence is a
    real "not applicable to this record". For a field the schema always writes, absence on
    *some* records is a defect and still fails; absence on *every* record means the field
    is not in this schema at all, which is unavailable coverage rather than a silent pass.
    """
    bad, missing, seen = [], 0, 0
    for r in ctx.records:
        if not _present(r, key):
            missing += 1
            if not optional:
                bad.append(f"{r.get('namespace')}/{r.get('pod')} @ {r.get('time')}: {key} missing")
            continue
        seen += 1
        v = r[key]
        if not _in_range(v, lo, hi):
            bad.append(f"{r.get('namespace')}/{r.get('pod')} @ {r.get('time')}: {key}={v!r}")
    if seen == 0:
        return result(SKIP, f"no record carried the {key} field — unavailable, not zero",
                      coverage=NONE)
    if bad:
        return result(FAIL, f"{len(bad)} of {len(ctx.records)} records fall outside [{lo}, {hi}] "
                            f"or do not carry {key}", bad[:10])
    if missing:
        return result(PASS, f"{seen} of {len(ctx.records)} records carried {key}, all inside "
                            f"[{lo}, {hi}]; {missing} did not carry it",
                      coverage=PARTIAL)
    return result(PASS, f"all {seen} records inside [{lo}, {hi}]")


def _composite(parts):
    """Roll several sub-results into one without losing an unavailable component.

    The old version took the worst of {FAIL, PASS} and treated SKIP as nothing, so a
    composite whose every component was absent reported PASS. Absence of all the inputs is
    the one thing this must never call a pass.
    """
    statuses = [p["status"] for _, p in parts]
    lines = [f"{name}: {p['summary']}" for name, p in parts]
    evaluated = [s for s in statuses if s != SKIP]
    if FAIL in statuses:
        return result(FAIL, f"{statuses.count(FAIL)} of {len(parts)} components violate their "
                            f"range", lines,
                      coverage=PARTIAL if SKIP in statuses else FULL)
    if not evaluated:
        return result(SKIP, f"none of the {len(parts)} components was present in any record",
                      lines, coverage=NONE)
    if SKIP in statuses or any(p["coverage"] == PARTIAL for _, p in parts):
        return result(PASS, f"{len(evaluated)} of {len(parts)} components checked; the rest "
                            f"were not observed", lines, coverage=PARTIAL)
    return result(PASS, f"all {len(parts)} components checked", lines)


# ─────────────────────────── 0 · preflight ───────────────────────────

@check("P01", "preflight", "console and operator are reachable",
       "the test's own entry point is healthy; every other result would be meaningless without it",
       "critical", inputs=["console /api/health", "console /api/version"])
def p01(ctx):
    h = ctx.preflight.get("health") or {}
    v = ctx.preflight.get("version") or {}
    if not h.get("ok"):
        return result(FAIL, "/api/health did not return ok=true", [repr(h)[:300]])
    return result(PASS, f"console {v.get('console','?')} · operator {v.get('operator','?')}",
                  [f"image={v.get('operatorImage','?')}"])


@check("P02", "preflight", "console and operator report the same version",
       "dashboard and engine come from one build, so a field the test expects genuinely exists",
       "minor", inputs=["console /api/version"])
def p02(ctx):
    v = ctx.preflight.get("version") or {}
    c, o = v.get("console"), v.get("operator")
    if not c or not o:
        return result(SKIP, "no version was reported")
    if c != o:
        return result(WARN, f"version mismatch: console {c} against operator {o}")
    return result(PASS, f"both on {c}")


@check("P03", "preflight", "the tick loop is alive",
       "the operator is genuinely deciding; the records are not an archive", "critical",
       inputs=["record.time", "capture completeness"])
def p03(ctx):
    capture = _ctx(ctx, "capture_complete", True)
    if not ctx.records:
        return result(FAIL, "no decision record arrived during the capture window"
                            + _scope_note(ctx), coverage=NONE)
    fresh = ctx.freshest_age_sec
    if fresh is None:
        return result(WARN, "record timestamps could not be parsed", coverage=NONE)
    if fresh > ctx.stale_after_sec:
        return result(FAIL, f"the freshest record is {fresh:.0f}s old (threshold {ctx.stale_after_sec}s)")
    if not capture:
        return result(WARN, f"{len(ctx.records)} records, freshest {fresh:.1f}s ago, but the "
                            f"capture window was not observed completely",
                      [_ctx(ctx, "capture_reason", "")], coverage=PARTIAL)
    return result(PASS, f"{len(ctx.records)} records, freshest {fresh:.1f}s ago" + _scope_note(ctx),
                  coverage=_scope_coverage(ctx))


@check("P04", "preflight", "the target pods are Ready in the cluster",
       "the attack lands on something that is actually serving — Running is scheduling, Ready is "
       "the readiness probe passing", "critical",
       inputs=["pod .status.phase", "pod .status.conditions[Ready]", "pod .metadata.deletionTimestamp"])
def p04(ctx):
    if not ctx.baseline_pods:
        return result(SKIP, "no kubectl baseline was taken (observe mode with no target)",
                      coverage=NOT_APPLICABLE)
    pods = ctx.baseline_pods
    unknown = [p for p, m in pods.items() if m.get("ready") is None]
    ready = [p for p, m in pods.items()
             if m.get("phase") == "Running" and m.get("ready") is True and not m.get("terminating")]
    detail = [f"{p}: phase={m.get('phase')} ready={m.get('ready')} "
              f"terminating={m.get('terminating')} uid={(m.get('uid') or '')[:8]} "
              f"owner={m.get('ownerKind')}/{(m.get('ownerUID') or '')[:8]}"
              for p, m in pods.items()]
    if not ready:
        return result(FAIL, "no Running and Ready pod in the target namespace", detail[:10])
    if unknown:
        return result(PASS, f"{len(ready)} pods Running and Ready; {len(unknown)} reported no "
                            f"Ready condition at all", detail[:10], coverage=PARTIAL)
    return result(PASS, f"{len(ready)} of {len(pods)} pods Running and Ready", detail[:10])


@check("P05", "preflight", "no controller is crash-looping",
       "an operator that keeps restarting still decides but never reaches the cluster — and "
       "because another operator keeps writing logs, the dashboard looks healthy", "critical",
       inputs=["Deployment/ReplicaSet/Pod inventory", "containerStatuses[].restartCount",
               "pod .status.conditions[Ready]"])
def p05(ctx):
    read = _ctx(ctx, "controller_observation")
    if read is not None and not read.usable:
        return result(FAIL, "the controller inventory could not be read, so controller health "
                            "is unknown", [read.describe()], coverage=NONE)
    if not ctx.controller_pods:
        return result(FAIL, "no expected controller pod status was observed", coverage=NONE)
    bad = [f"{p}: {m['phase']} · restarts={m['restarts']} · "
           f"{m.get('reason') or ('not Ready' if not m.get('ready', False) else 'unhealthy')}"
           for p, m in ctx.controller_pods.items()
           if m["phase"] != "Running" or m["restarts"] > ctx.max_restarts or not m.get("ready", False)]
    if bad:
        return result(FAIL, f"{len(bad)} unhealthy controllers", bad)
    coverage = FULL if read is None or read.ok else PARTIAL
    return result(PASS, f"{len(ctx.controller_pods)} healthy controllers",
                  [f"{p}: {m['phase']} · restarts={m['restarts']}" for p, m in ctx.controller_pods.items()],
                  coverage=coverage)


# ─────────────────────────── 1 · ingest ───────────────────────────

@check("I01", "ingest", "every record carries a complete identity",
       "ingest genuinely saw the pod — an anonymous record means the snapshot was incomplete",
       "critical", inputs=["record.tenant", "record.namespace", "record.pod"])
def i01(ctx):
    bad = [f"@{r.get('time')}: {k} empty"
           for r in ctx.records for k in ("tenant", "namespace", "pod")
           if not str(r.get(k, "")).strip()]
    if bad:
        return result(FAIL, f"{len(bad)} empty identity fields", bad[:10])
    if not ctx.records:
        return result(SKIP, "no record was captured", coverage=NONE)
    return result(PASS, f"all {len(ctx.records)} records carry tenant/namespace/pod" + _scope_note(ctx),
                  coverage=_scope_coverage(ctx))


@check("I02", "ingest", "tick timestamps move forward",
       "the audit file is being written and the records are sequential rather than interleaved",
       "minor", inputs=["record.time"])
def i02(ctx):
    ts = [ctx.parse_time(r.get("time")) for r in ctx.records]
    ts = [t for t in ts if t is not None]
    if len(ts) < 2:
        return result(SKIP, "fewer than two timestamped records", coverage=NONE)
    back = sum(1 for a, b in zip(ts, ts[1:]) if b < a - 0.001)
    if back:
        return result(WARN, f"{back} backward jumps in stream order")
    return result(PASS, f"{len(ts)} timestamps, no backward jumps")


@check("I03", "ingest", "the target appears in the decision stream",
       "ingest covers this namespace, so later silence means \"it decided to do nothing\", "
       "not \"it never saw it\"", "critical",
       inputs=["record.namespace", "target.namespace"])
def i03(ctx):
    if not ctx.target:
        return result(SKIP, "ran without a target", coverage=NOT_APPLICABLE)
    ns = ctx.target["namespace"]
    hit = [r for r in ctx.records if r.get("namespace") == ns]
    if not hit:
        return result(FAIL, f"no decision for namespace {ns} arrived in the window",
                      sorted({r.get("namespace", "") for r in ctx.records})[:12], coverage=NONE)
    pods = sorted({r.get("pod") for r in hit})
    return result(PASS, f"{len(hit)} decisions across {len(pods)} pods in {ns}", pods[:8])


# ─────────────────────────── 2 · physics ───────────────────────────

@check("PH01", "physics", "residual is always finite and inside [0,1]",
       "the same bug class that carried a NaN into the optimiser and silently turned the "
       "selection into a noop", "critical", inputs=["record.residual"])
def ph01(ctx):
    return _bounded(ctx, "residual", 0.0, 1.0)


@check("PH02", "physics", "no non-finite number anywhere in the record",
       "a NaN/Inf sweep over every numeric leaf at every depth, including the nested "
       "decisionTrace and pHoldInputs objects where the optimiser's own inputs live",
       "critical", inputs=["every numeric leaf of the record, recursively"])
def ph02(ctx):
    bad = []
    for r in ctx.records:
        for k, v in all_numeric_fields(r):
            if not math.isfinite(v):
                bad.append(f"{r.get('namespace')}/{r.get('pod')} @ {r.get('time')}: {k}={v}")
    if bad:
        return result(FAIL, f"{len(bad)} non-finite values", bad[:10])
    n = sum(len(all_numeric_fields(r)) for r in ctx.records)
    if not n:
        return result(SKIP, "no record carried a numeric value", coverage=NONE)
    return result(PASS, f"{n} numeric values across {len(ctx.records)} records, all finite"
                        + _scope_note(ctx), coverage=_scope_coverage(ctx))


@check("PH03", "physics", "a high residual with no security event does not drive a decision",
       "physics only reports; deciding that it matters is context's job", "minor",
       inputs=["record.residual", "record.threatPosture", "record.selected"])
def ph03(ctx):
    # Both fields are required by the schema. A record missing one is not evidence that its
    # value was zero, so it is excluded from the population and reported as reduced coverage.
    usable = [r for r in ctx.records if _finite(r, "residual") and _finite(r, "threatPosture")]
    if not usable:
        return result(SKIP, "no record carried both residual and threatPosture", coverage=NONE)
    odd = [f"{r.get('namespace')}/{r.get('pod')}: residual={r['residual']} but threatPosture=0, "
           f"and it was selected"
           for r in usable
           if r.get("selected") and r["residual"] > 0.5 and r["threatPosture"] == 0]
    if odd:
        return result(WARN, f"{len(odd)} selections driven by physics alone", odd[:6])
    coverage = PARTIAL if len(usable) < len(ctx.records) else FULL
    return result(PASS, f"no selection among {len(usable)} evaluable records came from a "
                        f"physical anomaly alone", coverage=_scope_coverage(ctx, coverage))


# ─────────────────────────── 3 · context ───────────────────────────

@check("C01", "context", "assetValue is finite and non-negative", "the asset value is usable",
       "major", inputs=["record.assetValue"])
def c01(ctx):
    return _bounded(ctx, "assetValue", 0.0, 1e6)


@check("C02", "context", "blastRadius is inside [0,1]",
       "the graph score is normalised; out of range means the normalisation is broken", "major",
       inputs=["record.blastRadius"])
def c02(ctx):
    return _bounded(ctx, "blastRadius", 0.0, 1.0)


@check("C03", "context", "context signals are inside [0,1]",
       "threatPosture / exposure / sloHeadroom are dimensionless and bounded. `belief` was "
       "retired to `pHold` in phorvex.audit.v2 (audit/contract.go) and is checked by C07; "
       "a composite whose components are all absent reports SKIP, never PASS", "major",
       inputs=["record.threatPosture", "record.exposure", "record.sloHeadroom"])
def c03(ctx):
    return _composite([(k, _bounded(ctx, k, 0.0, 1.0))
                       for k in ("threatPosture", "exposure", "sloHeadroom")])


@check("C04", "context", "phase is one of the known phases",
       "phase feeds straight into the RLS features; an unknown phase means the rotation cost "
       "is wrong", "major", inputs=["record.phase", "invariants.known_phases"])
def c04(ctx):
    known = set(ctx.inv["known_phases"])
    bad = [f"{r.get('pod')}: phase={r.get('phase')!r}" for r in ctx.records
           if r.get("phase") and r["phase"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown phases", bad[:8])
    seen = sum(1 for r in ctx.records if r.get("phase"))
    if not seen:
        return result(SKIP, "no record carried a phase", coverage=NONE)
    return result(PASS, f"all {seen} within {sorted(known)}",
                  coverage=PARTIAL if seen < len(ctx.records) else FULL)


@check("C05", "context", "stage is one of the 9 defined stages",
       "the parallel AI chain included; an unknown stage means event classification is broken",
       "major", inputs=["record.stage", "invariants.known_stages"])
def c05(ctx):
    known = set(ctx.inv["known_stages"])
    bad = [f"{r.get('pod')}: stage={r.get('stage')!r}" for r in ctx.records
           if r.get("stage") and r["stage"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown stages", bad[:8])
    seen = sorted({r.get("stage") for r in ctx.records if r.get("stage")})
    if not seen:
        return result(SKIP, "no record carried a stage", coverage=NONE)
    return result(PASS, f"stages seen: {', '.join(seen)}")


@check("C06", "context", "nextStage is a legal successor of stage",
       "either the linear successor, a lateral jump under neighbour pressure, or the AI map — "
       "nothing else", "major", inputs=["record.stage", "record.nextStage"])
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
        return result(SKIP, "no record carried both fields", coverage=NONE)
    if bad:
        return result(FAIL, f"{len(bad)} illegal transitions", bad[:8])
    return result(PASS, f"all {seen} transitions are legal",
                  coverage=PARTIAL if seen < len(ctx.records) else FULL)


@check("C07", "context", "hazard, pHold and preemptMargin are inside [0,1]",
       "all three are probabilities; out of range means the Weibull or the Beta posterior "
       "is broken. All three are omitempty, so an all-absent composite is SKIP", "major",
       inputs=["record.stageHazard", "record.pHold", "record.preemptMargin"])
def c07(ctx):
    return _composite([(k, _bounded(ctx, k, 0.0, 1.0, optional=True))
                       for k in ("stageHazard", "pHold", "preemptMargin")])


@check("C08", "context", "the next-stage margin agrees with the jump hazard",
       "this number is not a duration, it is a signed margin: negative means \"overdue\" "
       "(hazard.go:521 projectedNextStageSec). Both come from the same Weibull and the same "
       "dwell clock, so an exact relation holds between them that catches the two drifting "
       "apart", "major", inputs=["record.projectedNextStageSec", "record.stageHazard"])
def c08(ctx):
    # margin = median − dwell, and hazard = weibullCDF(dwell). At dwell = median,
    # hazard = 1 − exp(−(−ln 0.5)) = 0.5 exactly — independent of scale and of the stage
    # (killchain/hazard.go:415 and :487 share the same dwellSec). So margin < 0 ⟺
    # hazard > 0.5 is an exact identity, not a tuned threshold. The band around 0.5
    # absorbs the audit's 4-decimal rounding.
    band = 0.001
    # Both fields are omitempty. A record with a margin but no hazard cannot be evaluated —
    # reading the absent hazard as 0.0 would have asserted the identity against a value the
    # operator never produced.
    have = [r for r in ctx.records
            if _finite(r, "projectedNextStageSec") and _finite(r, "stageHazard")]
    partial = [r for r in ctx.records
               if _finite(r, "projectedNextStageSec") and not _finite(r, "stageHazard")]
    if not have:
        return result(SKIP, "no record carried both the margin and the jump hazard",
                      coverage=NONE)
    bad = []
    for r in have:
        m, h = r["projectedNextStageSec"], r["stageHazard"]
        if abs(h - 0.5) <= band:
            continue  # exactly at the median; either sign is legal
        if (m < 0) != (h > 0.5):
            bad.append(f"{r.get('namespace')}/{r.get('pod')}: margin={m:.0f}s disagrees with "
                       f"hazard={h:.4f} (margin<0 must be exactly equivalent to hazard>0.5)")
    if bad:
        return result(FAIL, f"{len(bad)} disagreements between margin and jump hazard", bad[:8])
    overdue = sum(1 for r in have if r["projectedNextStageSec"] < 0)
    return result(PASS, f"all {len(have)} records satisfy the identity "
                        f"({overdue} overdue, each with hazard > 0.5)"
                  + (f"; {len(partial)} carried no hazard and were not evaluated" if partial else ""),
                  coverage=PARTIAL if partial else FULL)


# ─────────────────────────── 4 · brain ───────────────────────────

# phorvex.audit.v2 renamed the P1 gain term from `risk` to `coverageValue`
# (audit/contract.go:36) and audit/log.go rejects a v2 record that still carries `risk`.
# Reading the retired name meant B01 skipped on every single run against the deployed
# operator: it was checking the engine's central identity against a field that cannot exist.
GAIN_FIELD_BY_ENGINE = {"p1-coverage": "coverageValue"}


@check("B01", "brain", "the net identity holds: net = gain − λ×cost",
       "the heart of the decision; if this does not add up, the number the dashboard shows "
       "came from somewhere else. Under p1-coverage the gain term is coverageValue "
       "(decision/coverage.go:662 net := cov - lambda*ecost)", "critical",
       inputs=["record.engine", "record.coverageValue", "record.cost", "record.net",
               "record.lambda"])
def b01(ctx):
    tol = ctx.inv["net_identity_tolerance"]
    bad, unknown_engine, seen = [], set(), 0
    for r in ctx.records:
        engine = r.get("engine")
        gain_field = GAIN_FIELD_BY_ENGINE.get(engine)
        if gain_field is None:
            # Another engine may define its own gain term; asserting this one's identity
            # against it would be an invented contract.
            unknown_engine.add(engine or "<absent>")
            continue
        if not all(_finite(r, k) for k in (gain_field, "cost", "net")):
            continue
        seen += 1
        # lambda is omitempty and its zero value genuinely means "no budget pressure",
        # which is the one absence the identity may read as 0.
        lam = r["lambda"] if _finite(r, "lambda") else 0.0
        expect = r[gain_field] - lam * r["cost"]
        if abs(expect - r["net"]) > tol:
            bad.append(f"{r.get('namespace')}/{r.get('pod')}: {gain_field}={r[gain_field]} "
                       f"λ={lam} cost={r['cost']} → expected {expect:.4f} but net={r['net']}")
    if seen == 0:
        return result(SKIP, "no record carried a known engine's gain, cost and net together"
                            + (f" (engines seen: {', '.join(sorted(unknown_engine))})"
                               if unknown_engine else ""), coverage=NONE)
    if bad:
        return result(FAIL, f"{len(bad)} violations out of {seen}", bad[:8])
    if unknown_engine:
        return result(PASS, f"all {seen} p1-coverage records within ±{tol}; "
                            f"{len(unknown_engine)} other engine(s) define their own gain term",
                      sorted(unknown_engine), coverage=PARTIAL)
    return result(PASS, f"all {seen} records within ±{tol}")


@check("B02", "brain", "the decision engine is a known one",
       "the record came from the engine that is documented", "minor",
       inputs=["record.engine", "invariants.known_engines"])
def b02(ctx):
    known = set(ctx.inv["known_engines"])
    bad = [f"{r.get('pod')}: engine={r.get('engine')!r}" for r in ctx.records
           if r.get("engine") and r["engine"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown engines", bad[:6])
    seen = sorted({r.get("engine") for r in ctx.records if r.get("engine")})
    if not seen:
        return result(SKIP, "no record named an engine", coverage=NONE)
    return result(PASS, f"engine: {', '.join(seen)}")


@check("B03", "brain", "actions come from the defined list of 17",
       "an action off the list means something was issued that has no handler at all", "critical",
       inputs=["record.action", "invariants.known_actions"])
def b03(ctx):
    known = set(ctx.inv["known_actions"])
    bad = [f"{r.get('pod')}: action={r.get('action')!r}" for r in ctx.records
           if r.get("action") and r["action"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} unknown actions", bad[:8])
    seen = sorted({r.get("action") for r in ctx.records if r.get("action")})
    if not seen:
        return result(SKIP, "no record named an action", coverage=NONE)
    return result(PASS, f"actions seen: {', '.join(seen)}")


@check("B04", "brain", "λ is finite and non-negative",
       "the shadow price came out of the dual solve intact", "major", inputs=["record.lambda"])
def b04(ctx):
    return _bounded(ctx, "lambda", 0.0, 1e6, optional=True)


@check("B05", "brain", "no decision is recorded as selected while recorded infeasible",
       "a contract violation as the record states it: the brain must never select a move the "
       "safety gate rejected. This reads the record's own two fields — it does not re-run the "
       "feasibility laws", "critical", inputs=["record.selected", "record.feasible"])
def b05(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy','')!r}"
           for r in ctx.records if r.get("selected") and not r.get("feasible")]
    if bad:
        return result(FAIL, f"{len(bad)} selected-but-infeasible decisions", bad[:8])
    sel = sum(1 for r in ctx.records if r.get("selected"))
    if not sel:
        return result(SKIP, "no decision was selected in this window", coverage=NOT_APPLICABLE)
    return result(PASS, f"{sel} selections, all recorded feasible")


@check("B06", "brain", "every decision carries a non-empty \"why\"",
       "what the dashboard shows must come from the decision itself, not from a fixed string",
       "major", inputs=["record.reason"])
def b06(ctx):
    if not ctx.records:
        return result(SKIP, "no record was captured", coverage=NONE)
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


@check("B07", "brain", "the MaxMovesPerTick cap is respected for the policy that owns it",
       "the per-tick budget is a hard ceiling on ONE PhorvexPolicy's own assets. Grouping by "
       "tenant alone attributed selections from namespaces this run never read a policy for; "
       "the budget is only checked where the owning policy was actually observed", "critical",
       inputs=["PhorvexPolicy .metadata.uid", "PhorvexPolicy spec.budget.maxMovesPerTick",
               "record.namespace", "record.time", "record.selected"])
def b07(ctx):
    policy = _ctx(ctx, "policy")
    read = _ctx(ctx, "policy_observation")
    if ctx.max_moves_per_tick is None or not policy or not policy.get("uid"):
        return result(SKIP, "no single owning PhorvexPolicy identity was observed, so no "
                            "owner-wide budget can be established"
                            + (f": {read.describe()}" if read is not None and not read.ok else ""),
                      coverage=NONE)
    owned = policy["namespace"]
    per, outside = {}, 0
    for r in ctx.records:
        if not r.get("selected"):
            continue
        if r.get("namespace") != owned:
            # Governed by a policy whose budget this run never read.
            outside += 1
            continue
        per.setdefault((r.get("namespace"), r.get("time")), []).append(r.get("pod"))
    bad = [f"{ns} @ {ts}: {len(p)} selections ({', '.join(str(x) for x in p[:4])})"
           for (ns, ts), p in per.items() if len(p) > ctx.max_moves_per_tick]
    evidence = [f"policy {policy.get('name')} uid={(policy.get('uid') or '')[:8]} "
                f"namespace={owned} maxMovesPerTick={ctx.max_moves_per_tick}"
                f"{'' if policy.get('budgetDeclared') else ' (operator default; the CR omits it)'}"]
    if bad:
        return result(FAIL, f"{len(bad)} ticks exceeded the cap of {ctx.max_moves_per_tick}",
                      evidence + bad[:6])
    if not per:
        return result(SKIP, f"no selection occurred under policy {policy.get('name')} in this "
                            f"window", evidence, coverage=NOT_APPLICABLE)
    return result(PASS, f"{len(per)} ticks with a selection under {policy.get('name')}, "
                        f"all ≤ {ctx.max_moves_per_tick}"
                  + (f"; {outside} selections outside its namespace were not attributed to it"
                     if outside else ""),
                  evidence, coverage=PARTIAL if outside else FULL)


@check("B08", "brain", "each asset gets at most one action per tick",
       "the partition constraint in the greedy loop; two actions on one pod means selectedAsset "
       "did not hold", "critical",
       inputs=["record.time", "record.namespace", "record.pod", "record.selected"])
def b08(ctx):
    per = {}
    for r in ctx.records:
        if r.get("selected"):
            per.setdefault((r.get("time"), r.get("namespace"), r.get("pod")), []).append(r.get("action"))
    bad = [f"{ns}/{pod} @ {t}: {acts}" for (t, ns, pod), acts in per.items() if len(acts) > 1]
    if bad:
        return result(FAIL, f"{len(bad)} assets with more than one action", bad[:6])
    if not per:
        return result(SKIP, "no decision was selected in this window", coverage=NOT_APPLICABLE)
    return result(PASS, f"{len(per)} (tick, asset) pairs, all unique" + _scope_note(ctx),
                  coverage=_scope_coverage(ctx))


@check("B09", "brain", "the R6 counterfactual is recorded for every decision",
       "the dashboard's three-way comparison comes from this; without it the comparison is "
       "fabricated", "minor",
       inputs=["record.r6Counterfactual", "invariants.known_actions"])
def b09(ctx):
    known = set(ctx.inv["known_actions"])
    missing = [f"{r.get('pod')}" for r in ctx.records if not r.get("r6Counterfactual")]
    bad = [f"{r.get('pod')}: {r.get('r6Counterfactual')!r}" for r in ctx.records
           if r.get("r6Counterfactual") and r["r6Counterfactual"] not in known]
    if bad:
        return result(FAIL, f"{len(bad)} invalid counterfactuals", bad[:6])
    if not ctx.records:
        return result(SKIP, "no record was captured", coverage=NONE)
    if missing:
        return result(WARN, f"{len(missing)} records with no counterfactual", missing[:6],
                      coverage=PARTIAL)
    return result(PASS, f"all {len(ctx.records)} records carry a counterfactual")


@check("B10", "brain", "attribution contributions are finite",
       "the attribution table goes straight onto the dashboard; a NaN is invisible there",
       "major", inputs=["record.attribution[].*"])
def b10(ctx):
    bad, n = [], 0
    for r in ctx.records:
        for i, t in enumerate(r.get("attribution") or []):
            if not isinstance(t, dict):
                bad.append(f"{r.get('pod')}: attribution[{i}] is not an object")
                continue
            for k, v in t.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    n += 1
                    if not math.isfinite(v):
                        bad.append(f"{r.get('pod')}: attribution[{i}].{k}={v}")
    if bad:
        return result(FAIL, f"{len(bad)} non-finite or malformed contributions", bad[:8])
    return result(PASS if n else SKIP,
                  f"{n} numeric contributions, all finite" if n else "no record carried attribution",
                  coverage=FULL if n else NONE)


# ─────────────────────────── 5 · feasibility ───────────────────────────

@check("F01", "feasibility", "every feasibility rejection names a law or capability gate",
       "\"infeasible\" without a reason cannot be audited", "major",
       inputs=["record.feasible", "record.infeasibleWhy", "invariants.law_reason_prefixes"])
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
                  [f"{k}: {v}" for k, v in sorted(matched.items())],
                  coverage=FULL if n else NOT_APPLICABLE)


@check("F02", "feasibility", "no infeasible action was actuated",
       "the gate also runs at the issue boundary; getting past it means fail-closed is broken",
       "critical", inputs=["record.actuated", "record.feasible"])
def f02(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')} why={r.get('infeasibleWhy')!r}"
           for r in ctx.records if r.get("actuated") and r.get("feasible") is False]
    if bad:
        return result(FAIL, f"{len(bad)} infeasible actuations", bad)
    n = sum(1 for r in ctx.records if r.get("actuated"))
    if not n:
        return result(SKIP, "no actuation occurred in this window", coverage=NOT_APPLICABLE)
    return result(PASS, f"none of {n} actuations was recorded infeasible")


@check("F03", "feasibility", "no rotate was issued against a stateful pod",
       "the stateful-integrity law; verified with kubectl, not with the record's own claim",
       "critical", inputs=["pod ownerReferences[0].kind", "pod spec.volumes[].persistentVolumeClaim",
                           "record.action", "record.selected", "record.actuated"])
def f03(ctx):
    if not ctx.stateful_by_pod:
        return result(SKIP, "pod stateful status could not be read from kubectl", coverage=NONE)
    bad, unknown = [], []
    for r in ctx.records:
        if r.get("action") != "rotate" or not (r.get("selected") or r.get("actuated")):
            continue
        key = (r.get("namespace"), r.get("pod"))
        st = ctx.stateful_by_pod.get(key)
        if st is True:
            bad.append(f"{r.get('namespace')}/{r.get('pod')} rotate against a stateful pod "
                       f"(selected={r.get('selected')}, actuated={r.get('actuated')})")
        elif st is None:
            # Not "it is stateless": we did not observe it. Saying so is the whole point.
            unknown.append(f"{r.get('namespace')}/{r.get('pod')}: stateful status unobserved")
    if bad:
        return result(FAIL, f"{len(bad)} state-integrity violations", bad)
    n = sum(1 for v in ctx.stateful_by_pod.values() if v)
    if n == 0:
        # Passing on an empty set is the "green board built on nothing" failure mode.
        return result(SKIP, "no stateful pod was observed in the target namespace — there was "
                            "nothing to test", coverage=NOT_APPLICABLE)
    if unknown:
        return result(WARN, f"{n} stateful pods checked, but {len(unknown)} rotate targets had "
                            f"no observed stateful status", unknown[:6], coverage=PARTIAL)
    return result(PASS, f"{n} stateful pods checked, no rotate issued")


# ─────────────────────────── 6 · actuator ───────────────────────────

@check("A01", "actuator", "the record's own authorisation chain is intact",
       "as the record states it: selected → feasible → not dryRun → actuated. This is a "
       "consistency check on the audit record, not an independent observation of the "
       "actuator", "critical",
       inputs=["record.actuated", "record.selected", "record.dryRun"])
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
    if not n:
        return result(SKIP, "no actuation occurred in this window", coverage=NOT_APPLICABLE)
    return result(PASS, f"{n} actuations, all consistently recorded")


@check("A02", "actuator", "every actuation leaves an auditable fingerprint",
       "the handler and the objects touched, as recorded; a traceless actuation is exactly "
       "what looks \"fake\". The fingerprint is the record's claim — A03 is what checks the "
       "cluster", "major",
       inputs=["record.handler", "record.objectsTouched", "invariants.phoenix_actions"])
def a02(ctx):
    acted = [r for r in ctx.records if r.get("actuated")]
    if not acted:
        return result(SKIP, "no actuation occurred in this window", coverage=NOT_APPLICABLE)
    phoenix = set(ctx.inv["phoenix_actions"])
    bad, delegated = [], 0
    for r in acted:
        if r.get("action") in phoenix:
            delegated += 1
            continue  # Phoenix emits a SecurityEvent; A03 verifies the resulting cluster mutation
        if not r.get("handler") and not r.get("objectsTouched"):
            bad.append(f"{r.get('pod')} action={r.get('action')}: no handler, no object touched")
    if bad:
        return result(FAIL, f"{len(bad)} actuations with no fingerprint", bad)
    return result(PASS, f"all {len(acted)} actuations carry a fingerprint"
                  + (f" ({delegated} delegated to Phoenix and checked by A03)" if delegated else ""),
                  [f"{r.get('pod')} → {r.get('handler') or r.get('action')} "
                   f"{r.get('objectsTouched') or ''}" for r in acted][:8],
                  coverage=PARTIAL if delegated else FULL)


@check("A03", "actuator", "the cluster confirms the claimed change",
       "independent ground truth: the Pod UID and a Ready same-owner successor, an active "
       "deny-all NetworkPolicy selecting that exact UID, or the service's own log — never "
       "Phorvex's own report. A claim nobody could observe is unverifiable, and a mix of "
       "confirmed and unverifiable is not a pass", "critical",
       inputs=["groundTruth[].verdict", "groundTruth[].attribution"])
def a03(ctx):
    if not ctx.ground_truth:
        return result(SKIP, "no independent verification ran (nothing actuated, or observe mode)",
                      coverage=NOT_APPLICABLE)
    fails = [g for g in ctx.ground_truth if g["verdict"] == "contradicted"]
    unknown = [g for g in ctx.ground_truth if g["verdict"] == "unverifiable"]
    confirmed = [g for g in ctx.ground_truth if g["verdict"] == "confirmed"]
    ev = [f"{g['action']} on {g['namespace']}/{g['pod']}: {g['verdict']} — {g['detail']}"
          + (f" [attribution: {g.get('attribution')}]" if g.get("attribution") else "")
          for g in ctx.ground_truth]
    if fails:
        return result(FAIL, f"{len(fails)} claims disagree with the cluster", ev)
    if not confirmed:
        return result(WARN, f"none of the {len(unknown)} claims could be independently "
                            f"confirmed", ev, coverage=NONE)
    if unknown:
        return result(WARN, f"{len(confirmed)} of {len(ctx.ground_truth)} claims confirmed; "
                            f"{len(unknown)} could not be observed", ev, coverage=PARTIAL)
    attributed = sum(1 for g in confirmed if g.get("attribution") == "correlated")
    return result(PASS, f"all {len(confirmed)} claims independently confirmed"
                  + (f"; {len(confirmed) - attributed} observed effects could not be attributed "
                     f"to the injected action" if attributed < len(confirmed) else ""),
                  ev, coverage=PARTIAL if attributed < len(confirmed) else FULL)


@check("A04", "actuator", "nothing was actuated under dryRun",
       "the dryRun contract; breaking it means an unexpected actuation against a live cluster",
       "critical", inputs=["record.dryRun", "record.actuated"])
def a04(ctx):
    bad = [f"{r.get('namespace')}/{r.get('pod')} action={r.get('action')}"
           for r in ctx.records if r.get("dryRun") and r.get("actuated")]
    if bad:
        return result(FAIL, f"{len(bad)} actuations under dryRun", bad)
    n = sum(1 for r in ctx.records if r.get("dryRun"))
    if not n:
        return result(SKIP, "no dryRun decision in the window", coverage=NOT_APPLICABLE)
    return result(PASS, f"{n} dryRun decisions, none actuated")


@check("A06", "actuator", "the absence of action matches the audit writer's real state",
       "\"selected but not actuated\" has two completely different causes: a deliberate kill "
       "switch, or a broken actuator. This check separates them using the operator's own metric "
       "instead of guessing from the absence of action", "critical",
       inputs=["metric phorvex_kill_switch_engaged", "record.selected", "record.feasible",
               "record.dryRun", "record.actuated"])
def a06(ctx):
    read = _ctx(ctx, "metrics_observation")
    ks = (ctx.writer_metrics or {}).get("phorvex_kill_switch_engaged")
    live = [r for r in ctx.records
            if r.get("selected") and r.get("feasible") and not r.get("dryRun")
            and r.get("action") != "noop"]
    acted = [r for r in live if r.get("actuated")]
    # A failed scrape and a successful scrape with no such gauge are different facts.
    why_absent = (read.describe() if read is not None and not read.usable
                  else "the writer exposed no phorvex_kill_switch_engaged gauge")

    if ks is None:
        if not live:
            return result(SKIP, f"no kill-switch state was read and there was no live move "
                                f"either ({why_absent})", coverage=NONE)
        if acted:
            return result(PASS, f"{len(acted)} of {len(live)} live moves were actuated, so the "
                                f"actuator is demonstrably working", [why_absent],
                          coverage=PARTIAL)
        return result(WARN,
                      f"{len(live)} moves were selected and none actuated, but the kill-switch "
                      f"state could not be read",
                      [why_absent,
                       "without the writer's metric there is no telling deliberate suppression "
                       "from a fault — set audit_writer.metrics_url"], coverage=NONE)

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
        return result(SKIP, "the kill switch is off but there was no live move in this window",
                      coverage=NOT_APPLICABLE)
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
       "major", inputs=["metric phorvex_kill_switch_engaged", "record.killSwitch"])
def a07(ctx):
    read = _ctx(ctx, "metrics_observation")
    ks = (ctx.writer_metrics or {}).get("phorvex_kill_switch_engaged")
    if ks is None:
        return result(SKIP, "the audit writer's kill-switch state could not be read"
                      + (f": {read.describe()}" if read is not None and not read.usable else ""),
                      coverage=NONE)
    if not ctx.records:
        return result(SKIP, "no record was captured, so the stream's source cannot be judged",
                      coverage=NONE)
    stamped = sum(1 for r in ctx.records if r.get("killSwitch"))
    if ks < 1:
        return result(PASS, "the writer of this audit is the actuating operator")
    if stamped == len(ctx.records):
        return result(PASS, f"it is a decision mirror and all {stamped} records carry "
                            f"killSwitch=true" + _scope_note(ctx),
                      coverage=_scope_coverage(ctx))
    return result(FAIL,
                  f"it is a decision mirror but only {stamped} of {len(ctx.records)} records "
                  f"recorded that",
                  ["a record with selected=true, dryRun=false, actuated=false and no killSwitch "
                   "cannot be told apart from a broken actuator",
                   "fixed in the repository (model/types.go · audit/log.go · runner/manager.go) "
                   "but it takes effect only after a rebuild and redeploy"])


@check("A05", "actuator", "the reaction is attributable to the signal we injected",
       "genuine end-to-end causality: a decision bound to THIS event UID and THIS target Pod "
       "UID inside the window. An actuation that merely happened in the same namespace "
       "afterwards is a coincidence the operator produces on its own schedule, so it is "
       "reported as unattributed — never as a defended attack", "major",
       inputs=["injection eventUID/targetUID", "record eventUID/podUID (feature-detected)",
               "record.time", "record.namespace", "record.actuated", "record.selected"])
def a05(ctx):
    if not ctx.attack_fired:
        return result(SKIP, "observe mode — no attack was fired", coverage=NOT_APPLICABLE)
    ns = ctx.target["namespace"]
    after = [r for r in ctx.post_records if r.get("namespace") == ns]
    acted = [r for r in after if r.get("actuated")]
    selected = [r for r in after if r.get("selected")]
    posture = [r for r in after if _finite(r, "threatPosture") and r["threatPosture"] > 0]
    ev = [f"after firing: {len(after)} decisions in {ns}, {len(posture)} with threat>0, "
          f"{len(selected)} selected, {len(acted)} actuated"]

    correlator = _ctx(ctx, "correlator")
    if correlator is None:
        return result(WARN, "no injection identity was recorded, so nothing in this window can "
                            "be attributed to the fired signal", ev, coverage=NONE)
    ev.append(f"correlation support: {correlator.support} — {correlator.describe()}")

    # No reaction at all is a genuine negative result and stays a failure: the signal either
    # never reached ingest or the operator stopped ticking.
    if not after:
        return result(FAIL, f"the attack signal in {ns} led to no change in any decision", ev)

    if not correlator.supported:
        named = correlator.named(after)
        if named:
            ev.append(f"{len(named)} decisions name the injected event "
                      f"{correlator.injection.get('eventName')}, but a name is not a UID-bound "
                      f"causal identity")
        if correlator.support == attribution_mod.OUTPUT_ONLY:
            # phoenix.eventUID identifies what the actuator emitted. Reading it as the cause
            # would attribute every rotation in the window to whatever we happened to inject.
            ev.append("phoenix.eventUID identifies the SecurityEvent this operator EMITTED, "
                      "not the detector event that caused the decision; the two are "
                      "different objects and must not be equated")
        return result(WARN,
                      f"{len(acted)} actuations and {len(selected)} selections followed the "
                      f"injection in {ns}, but this audit schema cannot bind any of them to the "
                      f"event we created", ev, coverage=NONE)

    correlated = correlator.correlated(after)
    if not correlated:
        return result(WARN,
                      f"{len(after)} decisions followed the injection in {ns}, none of them "
                      f"bound to the injected event and target",
                      ev + [correlator.classify(r)[1] for r in after[:4]], coverage=FULL)
    correlated_acted = [r for r in correlated if r.get("actuated")]
    correlated_selected = [r for r in correlated if r.get("selected")]
    ev.append(f"{len(correlated)} decisions bound to the injected event, "
              f"{len(correlated_selected)} selected, {len(correlated_acted)} actuated")
    if correlated_acted:
        return result(PASS, f"{len(correlated_acted)} actions attributable to the injected event",
                      ev + [f"{r.get('pod')} → {r.get('action')} ({r.get('handler') or 'phoenix'})"
                            for r in correlated_acted])
    if correlated_selected:
        return result(WARN, "a move bound to the injected event was selected but never actuated "
                            "— check the policy for dryRun mode", ev)
    return result(WARN, "the injected event was seen by the engine but no move was spent (this "
                        "may be the correct decision)", ev)
