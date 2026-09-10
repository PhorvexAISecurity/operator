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

# (key, label, range/unit, producing function, why it matters)
FIELDS = {
    "ingest": [
        ("tenant",    "Tenant",     "string",  "ingest/kube.go:77 CollectSnapshot", "which policy governs this pod"),
        ("namespace", "Namespace",  "string",  "ingest/kube.go:77 CollectSnapshot", "where the pod sits in the cluster"),
        ("pod",       "Pod",        "string",  "ingest/kube.go:77 CollectSnapshot", "the asset under assessment"),
        ("node",      "Node",       "string",  "ingest/kube.go:186 collectNodes",   "for the dollar rate and hardware feasibility"),
        ("time",      "Tick time",  "RFC3339", "runner/manager.go tick",            "proof the record is fresh rather than archived"),
    ],
    "physics": [
        ("residual",  "Physical anomaly", "0 … 1", "physics/littleslaw.go:31 Residual", "0.7×max + 0.3×mean of four gauges; zero means \"no data\", not \"safe\""),
    ],
    "context": [
        ("assetValue",    "Asset value",        "≥ 0",   "ctxprov/sensed.go:24 Context",         "labels + secrets + blast radius, scaled by the contamination boundary"),
        ("blastRadius",   "Blast radius",       "0 … 1", "graph/reachability.go:251 reachScore", "decayed reachability out to 3 hops, normalised to the cluster's worst pod"),
        ("threatPosture", "Threat posture",     "0 … 1", "ctxprov/sensed.go:24 Context",         "event severity, decayed by event age"),
        ("exposure",      "Exposure pressure",  "0 … 1", "ctxprov/sensed.go:24 Context",         "time since the last move, relative to the proactive floor"),
        ("sloHeadroom",   "SLO headroom",       "0 … 1", "ctxprov/sensed.go:24 Context",         "1 means full freedom to act"),
        ("phase",         "Workload phase",     "text",  "ctxprov/sensed.go:24 Context",         "sets the rotation cost inside RLS"),
        ("stage",         "Attacker stage",     "text",  "killchain/hazard.go:236 Assess",       "recon → exploit → persist → lateral → impact"),
        ("nextStage",     "Next stage",         "text",  "killchain/hazard.go:44 successorOf",   "can skip intermediate stages under neighbour pressure"),
        ("stageHazard",   "Jump hazard",        "0 … 1", "killchain/hazard.go:156 weibullCDF",   "Weibull with shape 2 — the hazard rate climbs linearly with dwell"),
        ("pHold",         "P(hold)",            "0 … 1", "killchain/hazard.go:236 Assess",       "Beta posterior × 30-second recovery decay"),
        ("preemptMargin", "Pre-emption margin", "0 … 1", "killchain/hazard.go:309",              "survival probability: are we still ahead by the time the action lands"),
        ("projectedNextStageSec", "Margin to next stage", "seconds, signed", "killchain/hazard.go:330 projectedNextStageSec", "median jump time minus stage age. Positive = there is still time; negative = overdue, and the model says the jump should already have happened"),
    ],
    "brain": [
        ("engine",        "Decision engine",    "text", "decision/coverage.go:79 Name",             "p1-coverage means submodular greedy"),
        ("lambda",        "λ shadow price",     "≥ 0",  "cost/dual.go:54 Step",                    "self-tuning under budget pressure; never set by hand"),
        # `risk` was retired in phorvex.audit.v2 (audit/contract.go:36 renames it to
        # coverageValue; audit/log.go rejects a v2 record that still carries it). Reading the
        # old name meant the net identity had nothing to check and skipped on every run.
        ("coverageValue", "Coverage (gain)",    "≥ 0",  "decision/coverage.go:670 CoverageValue",  "weight of the recon facts this move invalidates"),
        ("threatRisk",    "Legacy threat risk", "≥ 0",  "audit/contract.go:36 (legacy P0 read shim)", "only present on translated pre-v2 records; the P1 gain term is coverageValue"),
        ("cost",          "ECost",              "≥ 0",  "cost/p1cost.go:49 ECost",                 "0.4×C_norm + 0.6×C_flow — dimensionless"),
        ("net",           "Net",                "real", "decision/coverage.go:662",                "coverageValue − λ×cost; this single subtraction is the decision"),
        ("perDollar",     "Coverage per cost",  "≥ 0",  "decision/coverage.go:355",                "the yardstick candidates are ranked on"),
        ("coveredWeight", "Covered weight",     "≥ 0",  "decision/coverage.go:256",                "the fresh share this move adds"),
        ("coveredFacts",  "Fact count",         "count", "decision/coverage.go:256",               "how many independent facts get invalidated"),
        ("proactiveRate", "Proactive rate",     "≥ 0",  "decision/coverage.go:366",                "perDollar − λ; zero means \"not yet worth it\""),
        ("action",        "Selected action",    "text", "decision/coverage.go:159 Decide",         "output of the greedy loop"),
        ("selected",      "Selected",           "bool", "decision/coverage.go:246",                "landed inside the MaxMovesPerTick cap"),
        ("reason",        "Why",                "text", "decision/coverage.go:500 coverageReason", "explanation generated from the very numbers above"),
        ("r6Counterfactual",   "What R6 would do", "text", "decision/engine.go:234",               "the blind-timer rival"),
        ("counterfactualNote", "Difference from R6", "text", "decision/coverage.go:477",           "why our choice differs from it"),
        ("blindCost",     "Blind-timer cost",   "≥ 0",  "decision/coverage.go",                    "what R6 pays this cycle"),
    ],
    "feasibility": [
        ("feasible",      "Feasible",      "bool", "feasibility/constraint.go:58 Evaluate", "the gate runs twice: set construction and the issue boundary"),
        ("infeasibleWhy", "Blocking law",  "text", "feasibility/constraint.go:46 checkLaw", "the first law that blocked it; a panic counts as \"infeasible\" too"),
    ],
    "actuator": [
        ("actuated",       "Actuated",            "bool", "runner/manager.go:584 actuate",     "a hand actually touched the cluster"),
        ("dryRun",         "Dry run",             "bool", "PhorvexPolicy.dryRun",              "under dryRun it is never actuated"),
        ("killSwitch",     "Global kill switch",  "bool", "runner/manager.go:543 killEngaged", "a gate separate from dryRun: it suppresses the action but leaves dryRun false. Without this field a decision mirror cannot be told apart from a broken actuator"),
        ("handler",        "Handler",             "text", "actuator/handler.go Registry",      "which of the 16 registered handlers did the work"),
        ("objectsTouched", "Objects touched",     "list", "actuator/handler.go:54",            "the auditable fingerprint left on the cluster"),
        ("mutationKind",   "Mutation kind",       "text", "actuator/handler.go:57",            "reversible / irreversible / roll-forward"),
        ("rollbackRef",    "Rollback ref",        "text", "actuator/handler.go:55",            "how it can be undone"),
    ],
}

STAGE_ORDER = ["ingest", "physics", "context", "brain", "feasibility", "actuator"]
STAGE_LABEL = {
    "ingest": "1 · Ingest",
    "physics": "2 · Physics",
    "context": "3 · Context",
    "brain": "4 · Brain",
    "feasibility": "5 · Feasibility",
    "actuator": "6 · Actuator",
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


MAX_SWEEP_DEPTH = 12  # deep enough for decisionTrace; bounded so a cyclic-looking doc ends


def all_numeric_fields(rec, prefix="", depth=0):
    """Every numeric leaf at any depth, for the global non-finite sweep.

    The old sweep read top-level numbers and one level of list-of-objects, which is not
    where the interesting numbers live: `decisionTrace` and `pHoldInputs` are nested
    objects, so a NaN carried into the optimiser through a trace input was invisible to the
    check whose entire purpose is to catch exactly that. Booleans stay excluded — they are
    ints in Python and finiteness says nothing about them.
    """
    out = []
    if depth > MAX_SWEEP_DEPTH:
        return out
    if isinstance(rec, dict):
        items = rec.items()
    elif isinstance(rec, (list, tuple)):
        items = ((str(i), v) for i, v in enumerate(rec))
    else:
        return out
    for key, value in items:
        path = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out.append((path, value))
        elif isinstance(value, (dict, list, tuple)):
            out.extend(all_numeric_fields(value, path, depth + 1))
    return out
