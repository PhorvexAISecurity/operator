#!/usr/bin/env python3
"""Security Gain validation analysis for verification-loop study episodes.

Reads the per-episode report.json files written by run_study.py (one or more study
directories, any scenario) and produces:

  candidates.csv  one row per (episode, candidate action) in that episode's real decision state
  summary.json    per scenario: per-action outcomes for every instantiated attacker capability,
                  the fact-invalidation matrix, ranking, regret and time horizons
  summary.md      the same as readable tables

Predicted values come from the unchanged brain's decision trace. Measured values come only
from probes and the brain's re-observation after the branch, in the same episode. A measured
column is filled only for the action that episode actually executed; every other value is left
blank and its companion *_status column says why. Nothing unavailable is written as zero.
Standard library only.
"""
import argparse
import csv
import json
import math
import os
from datetime import datetime

MARKER = "verification-loop-synthetic-downstream"
TOKEN = "pod-bound-token"
NOOP = "noop"
# Each attacker capability a scenario instantiates, the probe that measures it and the fact
# kind the brain mints for it. Kinds without an instantiated capability are unmeasured.
CAPABILITIES = {
    "lease": {"kind": "endpointLeaseReuse", "label": "stolen lease credential A reaches the protected downstream"},
    "token": {"kind": "podBoundKubeAPIAuthPotential", "label": "stolen Pod-bound bearer authenticates at the API server"},
}
SCENARIOS = {
    "lease": {"id": "elr-stolen-inference-credential-envtest-v1", "caps": ["lease"], "replicas": 1},
    "token": {"id": "rotate-stolen-pod-bound-token-envtest-v1", "caps": ["token"], "replicas": 2},
    "combined": {"id": "combined-stolen-lease-and-token-envtest-v1", "caps": ["lease", "token"], "replicas": 2},
}
ACTION_ORDER = ("endpoint-lease-revoke", "rotate", "endpoint-rotate", NOOP)
END_TAIL_S = 3.0  # a capability is usable at the end if any probe in the final 3 s succeeded
HORIZONS = ((0.0, 5.0), (5.0, 10.0), (10.0, 15.0), (15.0, 20.0), (20.0, None))
EVIDENCE = ("MEASURED in a private envtest API server with the unchanged brain, native actuator and shipped "
            "Python admission boundary; synthetic downstream; TEST_INJECTED attack events; no kubelet or containers")
Z = 1.959963984540054

COLUMNS = [
    "scenario_id", "snapshot_id", "episode", "arm", "executed_in_episode", "asset_id", "action_id",
    "feasible", "blocking_gate", "selectable", "selected_by_brain",
    "predicted_security_gain", "predicted_marginal_gain", "predicted_net_gain",
    "asset_value", "attacker_hold_estimate", "urgency", "dispersion_multiplier", "provenance",
    "predicted_cover_keys", "predicted_fact_weights", "predicted_weight_on_measured_capabilities", "instantiated_capabilities",
    "confirmed_invalidated_keys", "confirmed_invalidated_keys_status",
    "false_invalidated_keys", "uncredited_removals", "unmeasured_cleared_keys", "exact_keys_cleared", "kinds_reminted_on_new_identity",
    "post_branch_fact_keys", "post_branch_selected_action", "post_branch_target",
    "remaining_attacker_capabilities", "remaining_attacker_capabilities_status",
    "attack_landed_before_decision",
    "attack_success_no_action", "attack_success_no_action_status",
    "attack_success_with_action", "attack_success_with_action_status", "capability_outcomes",
    "time_to_capability_removal_s",
    "time_to_reacquire_s", "time_to_reacquire_status",
    "effect_duration_s", "effect_duration_status",
    "estimated_risk_reduction", "estimated_risk_reduction_status",
    "expected_disruption_cost", "measured_disruption", "measured_disruption_status",
    "expected_avoided_loss", "expected_avoided_loss_status",
    "evidence_quality",
]


def ts(s):
    if not s or s.startswith("0001-"):
        return None
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    return datetime.fromisoformat(s).timestamp()


def val(x):
    """Trace numbers are {present, value}; absent is None, never zero."""
    if isinstance(x, dict):
        return x.get("value") if x.get("present") else None
    return x


def wilson(k, n):
    if n == 0:
        return None
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    h = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


def newcombe(k1, n1, k2, n2):
    """Difference p1 - p2 with Newcombe's hybrid score interval (method 10)."""
    a, b = wilson(k1, n1), wilson(k2, n2)
    if a is None or b is None:
        return None
    (p1, l1, u1), (p2, l2, u2) = a, b
    d = p1 - p2
    return (d, d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2), d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2))


def outcome(p):
    """'success' = the capability worked (lease: the protected downstream operation ran; token:
    the API server authenticated the bearer); 'denied' = the exact refusal with zero downstream
    effect; anything else is indeterminate and never counted either way."""
    body = p.get("body") if isinstance(p.get("body"), dict) else {}
    if p.get("error"):
        return "indeterminate"
    if p.get("capability") == TOKEN:
        if p.get("status") == 201 and body.get("authenticated") is True:
            return "success"
        if p.get("status") == 401 and body.get("error") == "unauthorized":
            return "denied"
        return "indeterminate"
    if p.get("status") == 200 and body.get("marker") == MARKER and p.get("after_calls") == p.get("before_calls", -2) + 1:
        return "success"
    if p.get("status") == 401 and body.get("error") == "unauthorized" and p.get("after_calls") == p.get("before_calls"):
        return "denied"
    return "indeterminate"


def kendall_tau_b(x, y):
    n = len(x)
    conc = disc = tx = ty = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx, dy = x[i] - x[j], y[i] - y[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                tx += 1
            elif dy == 0:
                ty += 1
            elif dx * dy > 0:
                conc += 1
            else:
                disc += 1
    den = math.sqrt((conc + disc + tx) * (conc + disc + ty))
    return None if den == 0 else (conc - disc) / den


def ranks(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    r = [0.0] * len(v)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def spearman(x, y):
    rx, ry = ranks(x), ranks(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    sxy = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    sx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    sy = math.sqrt(sum((b - my) ** 2 for b in ry))
    return None if sx == 0 or sy == 0 else sxy / (sx * sy)


def trace_of(decisions):
    for d in decisions or []:
        if d.get("Trace"):
            return d, d["Trace"]
    return None, None


def kind(key):
    return key.split("|")[2] if key.count("|") >= 2 else key


def mean(v):
    v = [x for x in v if x is not None]
    return sum(v) / len(v) if v else None


def median(v):
    v = sorted(x for x in v if x is not None)
    if not v:
        return None
    m = len(v) // 2
    return v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2


def fmt(x, digits=4):
    if x is None:
        return ""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (int, float)):
        return ("%." + str(digits) + "f") % x
    return str(x)


def executed_action(r, arm):
    if r.get("study_action"):
        return r["study_action"]
    if r.get("counterfactual_action"):
        return r["counterfactual_action"]
    return "endpoint-lease-revoke" if arm == "intervention" else NOOP


def capability_stats(series):
    """series: [(seconds after the branch point, outcome)] for one capability."""
    det = [(t, o) for t, o in series if t is not None and o != "indeterminate"]
    if not det:
        return None
    k = sum(o == "success" for _, o in det)
    end = max(t for t, _ in det)
    usable = any(o == "success" for t, o in det if t >= end - END_TAIL_S)
    last_success = max((t for t, o in det if o == "success"), default=None)
    removal = None
    if not usable:
        after = [t for t, o in det if o == "denied" and (last_success is None or t > last_success)]
        removal = max(0.0, min(after)) if after else None
    return {"k": k, "n": len(det), "usable_at_end": usable, "succeeded_after_branch": k > 0,
            "last_success_s": last_success, "removal_s": removal, "window_end_s": end,
            "series": det}


def load_episode(path, meta):
    with open(os.path.join(path, "report.json")) as f:
        r = json.load(f)
    arm = r.get("arm") or meta.get("arm") or "intervention"
    scenario = r.get("scenario") or meta.get("scenario") or "lease"
    d, t = trace_of(r.get("decisions"))
    if t is None:
        return {"dir": meta["dir"], "arm": arm, "scenario": scenario, "verdict": r.get("verdict"), "error": r.get("error") or "no decision trace"}
    _, pt = trace_of(r.get("post_decisions"))
    probes = r.get("probes") or []
    t0 = ts(r.get("dispatch_finished_at"))
    if t0 is None:
        hold = [ts(p["at"]) for p in probes if p["name"].endswith("study-hold")]
        t0 = min(hold) if hold else None

    def rel(p):
        return ts(p["at"]) - t0 if t0 is not None else None

    series = {
        "lease": [(rel(p), outcome(p)) for p in probes if not p.get("capability") and p["name"].startswith("A-")
                  and p["name"] != "A-selected-but-dispatch-withheld"],
        "token": [(rel(p), outcome(p)) for p in probes if p.get("capability") == TOKEN and p["name"] != "attack-baseline-T"],
    }
    pre = {"lease": [outcome(p) for p in probes if p["name"] == "attack-baseline-A"],
           "token": [outcome(p) for p in probes if p["name"] == "attack-baseline-T"]}
    legit = [(rel(p), outcome(p), p.get("latency_ms"), p.get("replica") or "") for p in probes if p["name"].startswith("B-")]
    pre_b = [p.get("latency_ms") for p in probes if p["name"] in ("clean-B", "attack-baseline-B") and outcome(p) == "success"]
    facts = {f["factKey"]: {"w": f.get("finalWeight"), "attributed": bool(f.get("steeredBy"))} for f in t.get("facts") or []}
    post = None if pt is None else {f["factKey"]: {"w": f.get("finalWeight"), "attributed": bool(f.get("steeredBy"))} for f in pt.get("facts") or []}
    status = {s["action"]: s for s in t.get("actionStatus") or []}
    cands = []
    for c in t.get("candidates") or []:
        st = status.get(c["action"], {})
        feasible = val(c.get("feasible"))
        excl = c.get("existingExclusionReason") or ""
        cands.append({
            "action": c["action"], "feasible": feasible, "selected": bool(c.get("selected")),
            "blocking_gate": excl or (st.get("reason") if st.get("status") in ("infeasible", "excluded") else "") or "",
            "selectable": bool(feasible) and not excl,
            "status_reason": st.get("reason", ""), "cover": c.get("coverKeys") or [],
            "gross": val(c.get("grossFullValue")), "marginal": val(c.get("marginalCoverage")), "net": val(c.get("netGain")),
            "provenance": val(c.get("provenance")), "expected_cost": val(c.get("expectedCost")),
        })
    dispatch = r.get("dispatch") or {}
    caps = SCENARIOS.get(scenario, SCENARIOS["lease"])["caps"]
    return {
        "dir": meta["dir"], "arm": arm, "scenario": scenario, "caps": caps, "verdict": r.get("verdict"), "error": r.get("error") or "",
        "executed_action": executed_action(r, arm), "decision_id": t.get("decisionID"),
        "asset": "%s/%s" % (t.get("assetNamespace"), t.get("assetName")), "asset_uid": t.get("assetUID"),
        "selected": t.get("selectedAction"), "asset_value": d.get("AssetValue"),
        "p_hold": val((t.get("inputs") or {}).get("pHold")), "urgency": val((t.get("inputs") or {}).get("stageUrgency")),
        "dispersion": val((t.get("inputs") or {}).get("dispersionMult")),
        "facts": facts, "post": post, "candidates": cands,
        "dispatch_emitted": dispatch.get("Emitted"), "dispatch_note": dispatch.get("Note") or "",
        "pre": pre, "pre_b_latency": pre_b, "legit": legit,
        "stats": {c: capability_stats(series[c]) for c in caps},
        "post_target": r.get("post_target") or "", "post_error": r.get("post_observation_error") or "",
        "post_selected": None if pt is None else pt.get("selectedAction"),
    }


def invalidation(e):
    """Per instantiated capability: is the attack-attributed fact still minted after the branch,
    and is the capability still usable? Structural (unattributed) kinds are reported separately:
    they have no instantiated capability here, and a replacement Pod re-mints them under a new key."""
    if e["post"] is None:
        return None
    post_attr = {kind(k) for k, f in e["post"].items() if f["attributed"]}
    post_kinds = {kind(k) for k in e["post"]}
    out = {"true": [], "false": [], "uncredited": [], "persisting": [], "per_cap": {},
           "keys_cleared": sorted(set(e["facts"]) - set(e["post"])), "reminted": [], "unmeasured_cleared": []}
    measured = {CAPABILITIES[c]["kind"] for c in e["caps"]}
    for c in e["caps"]:
        k, s = CAPABILITIES[c]["kind"], e["stats"].get(c)
        if s is None:
            out["per_cap"][c] = "unavailable"
            continue
        removed, attributed = not s["usable_at_end"], k in post_attr
        cls = ("persisting" if not removed else "uncredited") if attributed else ("true" if removed else "false")
        out[cls].append(k)
        out["per_cap"][c] = cls
    for key in sorted(e["facts"]):
        k = kind(key)
        if k in measured:
            continue
        if k in post_kinds:
            if key not in e["post"]:
                out["reminted"].append(k)
        else:
            out["unmeasured_cleared"].append(k)
    return out


def legit_disruption(e):
    obs = [(o, lat) for _, o, lat, _ in e["legit"]]
    ok = sorted(lat for o, lat in obs if o == "success")
    p95 = ok[min(len(ok) - 1, int(math.ceil(0.95 * len(ok))) - 1)] if ok else None
    base = sorted(e["pre_b_latency"])
    return {"failures": sum(o != "success" for o, _ in obs), "samples": len(obs), "p95_ms": p95,
            "pre_ms": base[len(base) // 2] if base else None}


def usable_fraction(e):
    vals = [e["stats"][c]["usable_at_end"] for c in e["caps"] if e["stats"].get(c)]
    return sum(vals) / len(vals) if vals else None


def disruption_status(e, action):
    if action == "rotate":
        if SCENARIOS[e["scenario"]]["replicas"] == 1:
            return None, ("UNAVAILABLE: envtest has no kubelet, so eviction does not stop the serving process; "
                          "production single-replica rotate is an outage (the brain's availability gate)")
        d = legit_disruption(e)
        return ("surviving_replica_legit_failures=%d/%d;legit_p95_ms=%s" % (d["failures"], d["samples"], fmt(d["p95_ms"], 1)),
                "PARTIAL: the surviving replica is measured; the evicted Pod's capacity loss and in-flight requests are not (no kubelet)")
    d = legit_disruption(e)
    return ("legit_failures=%d/%d;legit_p95_ms=%s;legit_pre_median_ms=%s" % (d["failures"], d["samples"], fmt(d["p95_ms"], 1), fmt(d["pre_ms"], 1)),
            "MEASURED: legitimate credential-B probes on every serving replica (local, single worker)")


def episode_rows(e, baseline):
    rows = []
    inval = invalidation(e)
    scen = SCENARIOS[e["scenario"]]
    cands = list(e["candidates"])
    if not any(c["action"] == NOOP for c in cands):
        cands.append({"action": NOOP, "feasible": True, "selectable": True, "selected": e["selected"] == NOOP, "blocking_gate": "", "cover": [],
                      "gross": 0.0, "marginal": 0.0, "net": 0.0, "provenance": None, "expected_cost": 0.0, "status_reason": "withhold every action"})
    measured_kinds = {CAPABILITIES[c]["kind"] for c in e["caps"]}
    pre = "1" if all(e["pre"][c] and all(o == "success" for o in e["pre"][c]) for c in e["caps"]) else "0"
    for c in cands:
        executed = c["action"] == e["executed_action"]
        row = {k: "" for k in COLUMNS}
        row.update({
            "scenario_id": scen["id"], "snapshot_id": e["decision_id"], "episode": e["dir"], "arm": e["arm"],
            "executed_in_episode": "yes" if executed else "no",
            "asset_id": "%s uid=%s" % (e["asset"], e["asset_uid"]), "action_id": c["action"],
            "feasible": {True: "true", False: "false"}.get(c["feasible"], "unknown"),
            "blocking_gate": c["blocking_gate"] or ("none" if c["feasible"] else c["status_reason"] or "unknown"),
            "selectable": "true" if c["selectable"] else "false",
            "selected_by_brain": "yes" if c["selected"] else "no",
            "predicted_security_gain": fmt(c["gross"]), "predicted_marginal_gain": fmt(c["marginal"]), "predicted_net_gain": fmt(c["net"]),
            "asset_value": fmt(e["asset_value"]), "attacker_hold_estimate": fmt(e["p_hold"]), "urgency": fmt(e["urgency"]),
            "dispersion_multiplier": fmt(e["dispersion"]), "provenance": fmt(c["provenance"]) if c["action"] != NOOP else "not-applicable",
            "predicted_cover_keys": ";".join(c["cover"]),
            "predicted_fact_weights": ";".join("%s=%s" % (k, fmt((e["facts"].get(k) or {}).get("w"))) for k in c["cover"]),
            "predicted_weight_on_measured_capabilities": fmt(sum((e["facts"].get(k) or {}).get("w") or 0 for k in c["cover"] if kind(k) in measured_kinds)),
            "instantiated_capabilities": ";".join(e["caps"]),
            "attack_landed_before_decision": pre,
            "expected_disruption_cost": fmt(c["expected_cost"]),
            "expected_avoided_loss_status": "UNAVAILABLE: synthetic downstream has no defensible consequence value",
            "evidence_quality": EVIDENCE,
        })
        if not executed:
            why = "UNAVAILABLE: not executed in this episode (see %s-scenario episodes that executed %s)" % (e["scenario"], c["action"])
            for col in ("confirmed_invalidated_keys_status", "remaining_attacker_capabilities_status", "attack_success_no_action_status",
                        "attack_success_with_action_status", "time_to_reacquire_status", "effect_duration_status",
                        "estimated_risk_reduction_status", "measured_disruption_status"):
                row[col] = why
            rows.append(row)
            continue
        if e["post"] is not None:
            row["post_branch_fact_keys"] = ";".join("%s=%s%s" % (k, fmt(f["w"]), "*" if f["attributed"] else "") for k, f in sorted(e["post"].items()))
        row["post_branch_selected_action"] = e["post_selected"] or ""
        row["post_branch_target"] = e["post_target"]
        if inval is None:
            row["confirmed_invalidated_keys_status"] = "UNAVAILABLE: post-branch observation failed: " + e["post_error"]
        else:
            row["confirmed_invalidated_keys"] = ";".join(inval["true"])
            row["false_invalidated_keys"] = ";".join(inval["false"])
            row["uncredited_removals"] = ";".join(inval["uncredited"])
            row["unmeasured_cleared_keys"] = ";".join(inval["unmeasured_cleared"])
            row["exact_keys_cleared"] = ";".join(inval["keys_cleared"])
            row["kinds_reminted_on_new_identity"] = ";".join(inval["reminted"])
            row["confirmed_invalidated_keys_status"] = ("MEASURED for the attack-attributed kinds %s; structural kinds have no instantiated "
                                                        "capability here and are listed as unmeasured" % ",".join(sorted(measured_kinds)))
        remaining = []
        for cap in e["caps"]:
            s = e["stats"].get(cap)
            if s and s["usable_at_end"]:
                remaining.append("%s (measured usable at end of window)" % CAPABILITIES[cap]["label"])
        if "lease" in e["caps"]:
            remaining.append("credential-B lease: legitimate, mounted in the pod Secret volume; theft by an in-pod attacker NOT TESTED")
        if "token" in e["caps"]:
            remaining.append("tokens for other Pods of the same ServiceAccount: only obtainable with access to those Pods; NOT TESTED")
        if e["post"] is not None:
            structural = sorted({kind(k) for k, f in e["post"].items() if not f["attributed"]} - measured_kinds)
            if structural:
                remaining.append("brain still mints structural " + ",".join(structural) + " (capabilities not instantiated; NOT MEASURED)")
        row["remaining_attacker_capabilities"] = " | ".join(remaining)
        row["remaining_attacker_capabilities_status"] = "PARTIAL: only the instantiated capabilities (%s) are measured" % ",".join(e["caps"])
        frac = usable_fraction(e)
        if baseline and baseline.get("p") is not None:
            row["attack_success_no_action"] = fmt(baseline["p"])
            row["attack_success_no_action_status"] = ("MEASURED: baseline arm, same scenario and initial state, %d episodes; fraction of "
                                                      "instantiated capabilities usable at the end of the window" % baseline["n"])
        else:
            row["attack_success_no_action_status"] = "UNAVAILABLE: no baseline episodes for this scenario"
        if frac is not None:
            row["attack_success_with_action"] = fmt(frac)
            row["attack_success_with_action_status"] = "MEASURED: fraction of instantiated capabilities usable in the final %.0f s of the window" % END_TAIL_S
        else:
            row["attack_success_with_action_status"] = "UNAVAILABLE: no determinate attack probes"
        outcomes, removals, censor = [], [], []
        for cap in e["caps"]:
            s = e["stats"].get(cap)
            if not s:
                outcomes.append("%s: UNAVAILABLE" % cap)
                continue
            outcomes.append("%s: %d/%d succeeded after the branch; %s" % (
                cap, s["k"], s["n"], "usable at end" if s["usable_at_end"] else "removed at +%.1f s" % s["removal_s"]))
            if not s["usable_at_end"]:
                removals.append("%s=%.2f" % (cap, s["removal_s"]))
                censor.append(s["window_end_s"] - s["removal_s"])
        row["capability_outcomes"] = " | ".join(outcomes)
        row["time_to_capability_removal_s"] = ";".join(removals)
        removed_all = len(censor) == len(e["caps"])
        if censor:
            bound = min(censor)
            row["time_to_reacquire_s"] = row["effect_duration_s"] = fmt(bound)
            prefix = "CENSORED" if removed_all else "PARTIAL"
            row["time_to_reacquire_status"] = "%s: no reacquisition of a removed capability within the window (value is the lower bound)%s" % (
                prefix, "" if removed_all else "; other instantiated capabilities were never removed")
            row["effect_duration_status"] = "%s: the removal still held at the end of the window (value is the lower bound)" % prefix
        else:
            row["time_to_reacquire_status"] = "NOT APPLICABLE: no instantiated capability was removed"
            row["effect_duration_status"] = "NOT APPLICABLE: no removal observed"
        if baseline and baseline.get("p") is not None and frac is not None:
            row["estimated_risk_reduction"] = fmt(baseline["p"] - frac)
            row["estimated_risk_reduction_status"] = ("ESTIMATE from measured outcomes: baseline usable fraction minus this episode's, "
                                                      "at the end of the window (capabilities weighted equally)")
        else:
            row["estimated_risk_reduction_status"] = "UNAVAILABLE: missing baseline or episode probes"
        value, status = disruption_status(e, c["action"])
        row["measured_disruption"] = value or ""
        row["measured_disruption_status"] = status
        rows.append(row)
    return rows


def summarize_scenario(scenario, episodes):
    caps = SCENARIOS[scenario]["caps"]
    by_action = {}
    for e in episodes:
        by_action.setdefault(e["executed_action"], []).append(e)
    base_eps = by_action.get(NOOP, [])
    base_cap = {}
    for c in caps:
        ok = [e for e in base_eps if e["stats"].get(c)]
        base_cap[c] = (sum(e["stats"][c]["usable_at_end"] for e in ok), len(ok))
    base_frac = mean([usable_fraction(e) for e in base_eps])
    baseline = {"p": base_frac, "n": len(base_eps), "per_capability": {c: {"k": k, "n": n} for c, (k, n) in base_cap.items()}}
    actions = {}
    for act in sorted(by_action, key=lambda a: ACTION_ORDER.index(a) if a in ACTION_ORDER else 99):
        es = by_action[act]
        cands = [c for e in es for c in e["candidates"] if c["action"] == act]
        gross = [c["gross"] for c in cands if c["gross"] is not None]
        per_cap = {}
        for c in caps:
            ok = [e for e in es if e["stats"].get(c)]
            k_end = sum(e["stats"][c]["usable_at_end"] for e in ok)
            k_any = sum(e["stats"][c]["succeeded_after_branch"] for e in ok)
            rr = newcombe(base_cap[c][0], base_cap[c][1], k_end, len(ok)) if base_cap[c][1] and ok else None
            removal = [e["stats"][c]["removal_s"] for e in ok if not e["stats"][c]["usable_at_end"]]
            inv = [invalidation(e) for e in es]
            horizon = []
            for lo, hi in HORIZONS:
                obs = [o for e in ok for t, o in e["stats"][c]["series"] if t >= lo and (hi is None or t < hi)]
                horizon.append({"from_s": lo, "to_s": hi, "success": sum(o == "success" for o in obs), "n": len(obs)})
            per_cap[c] = {
                "usable_at_end": {"k": k_end, "n": len(ok), "wilson": wilson(k_end, len(ok))},
                "succeeded_after_branch": {"k": k_any, "n": len(ok), "wilson": wilson(k_any, len(ok))},
                "risk_reduction_end": {"estimate": rr[0], "newcombe95": [rr[1], rr[2]]} if rr else None,
                "removal_s": {"n": len(removal), "min": min(removal) if removal else None, "median": median(removal), "max": max(removal) if removal else None},
                "reacquisition": "censored" if removal and len(removal) == len(ok) else ("not-applicable" if not removal else "partial"),
                "min_censoring_window_s": min((e["stats"][c]["window_end_s"] - e["stats"][c]["removal_s"] for e in ok if not e["stats"][c]["usable_at_end"]), default=None),
                "invalidation": {cls: sum(1 for i in inv if i and i["per_cap"].get(c) == cls) for cls in ("true", "false", "uncredited", "persisting")},
                "time_horizons": horizon,
            }
        dis = [legit_disruption(e) for e in es]
        rr_total = sum(per_cap[c]["risk_reduction_end"]["estimate"] for c in caps if per_cap[c]["risk_reduction_end"]) if all(per_cap[c]["risk_reduction_end"] for c in caps) else None
        inv = [invalidation(e) for e in es]
        actions[act] = {
            "episodes": len(es), "arms": sorted({e["arm"] for e in es}), "verdicts": sorted({e["verdict"] for e in es}),
            "dispatch_emitted": sorted({str(e.get("dispatch_emitted")) for e in es}),
            "dispatch_notes": sorted({e.get("dispatch_note", "")[:160] for e in es}),
            "feasible_in_decision_state": sorted({str(c["feasible"]) for c in cands}) or ["True"],
            "selectable": all(c["selectable"] for c in cands) if cands else True,
            "blocking_gate": sorted({c["blocking_gate"] for c in cands if c["blocking_gate"]}),
            "predicted_security_gain": {"mean": mean(gross), "min": min(gross) if gross else None, "max": max(gross) if gross else None} if act != NOOP else {"mean": 0.0, "min": 0.0, "max": 0.0},
            "predicted_weight_on_measured_capabilities": mean([sum((e["facts"].get(k) or {}).get("w") or 0 for k in c["cover"] if kind(k) in {CAPABILITIES[x]["kind"] for x in caps})
                                                               for e in es for c in e["candidates"] if c["action"] == act]) if act != NOOP else 0.0,
            "per_capability": per_cap,
            "measured_risk_reduction_total": rr_total,
            "unmeasured_kinds_cleared": sorted({k for i in inv if i for k in i["unmeasured_cleared"]}),
            "kinds_reminted_on_new_identity": sorted({k for i in inv if i for k in i["reminted"]}),
            "post_selected_actions": sorted({str(e["post_selected"]) for e in es}),
            "post_targets": sorted({e["post_target"].split(" uid=")[0] for e in es}),
            "post_errors": sorted({e["post_error"] for e in es if e["post_error"]}),
            "legit_failures": sum(d["failures"] for d in dis), "legit_samples": sum(d["samples"] for d in dis),
            "legit_p95_ms_max": max((d["p95_ms"] for d in dis if d["p95_ms"] is not None), default=None),
            "disruption_representative": not (act == "rotate" and SCENARIOS[scenario]["replicas"] == 1),
            "inputs": {"p_hold": [min(e["p_hold"] for e in es), max(e["p_hold"] for e in es)],
                       "urgency": [min(e["urgency"] for e in es), max(e["urgency"] for e in es)]},
        }
    order = [a for a in actions if actions[a]["measured_risk_reduction_total"] is not None]
    pred = [actions[a]["predicted_security_gain"]["mean"] for a in order]
    meas = [actions[a]["measured_risk_reduction_total"] for a in order]
    selectable = [a for a in order if actions[a]["selectable"]]
    pairs = []
    for i in range(len(order)):
        for j in range(i + 1, len(order)):
            if pred[i] == pred[j]:
                continue
            hi, lo = (order[i], order[j]) if pred[i] > pred[j] else (order[j], order[i])
            m_hi, m_lo = actions[hi]["measured_risk_reduction_total"], actions[lo]["measured_risk_reduction_total"]
            verdict = "agree" if m_hi > m_lo else ("tie-in-outcome" if m_hi == m_lo else "reversal")
            pairs.append({"predicted_higher": hi, "predicted_lower": lo, "measured_rr_higher": m_hi, "measured_rr_lower": m_lo,
                          "both_selectable": hi in selectable and lo in selectable, "verdict": verdict})
    selected = sorted({e["selected"] for e in episodes if e.get("selected")})
    sel_action = selected[0] if len(selected) == 1 else None
    def best(candidates):
        if not candidates:
            return None, None
        top = max(actions[a]["measured_risk_reduction_total"] for a in candidates)
        return "/".join(a for a in candidates if actions[a]["measured_risk_reduction_total"] == top), top

    best_sel, best_sel_rr = best(selectable)
    best_all, best_all_rr = best(order)
    sel_rr = actions[sel_action]["measured_risk_reduction_total"] if sel_action in actions else None

    def sub(a, b):
        return None if a is None or b is None else a - b

    fpred = [actions[a]["predicted_security_gain"]["mean"] for a in selectable]
    fmeas = [actions[a]["measured_risk_reduction_total"] for a in selectable]
    return {
        "scenario": scenario, "scenario_id": SCENARIOS[scenario]["id"], "capabilities": caps, "episodes": len(episodes),
        "baseline": baseline, "actions": actions,
        "ranking": {
            "actions": order, "predicted_security_gain": pred, "measured_risk_reduction_total": meas,
            "kendall_tau_b": kendall_tau_b(pred, meas) if len(order) > 1 else None,
            "spearman": spearman(pred, meas) if len(order) > 1 else None,
            "selectable_only": {"actions": selectable, "kendall_tau_b": kendall_tau_b(fpred, fmeas) if len(selectable) > 1 else None,
                                "spearman": spearman(fpred, fmeas) if len(selectable) > 1 else None},
            "sufficient_data": False,
            "note": "One scenario, %d actions; rank coefficients over so few points are descriptive only. Statistical rank agreement: NOT VALIDATED." % len(order),
            "pairs": pairs,
        },
        "regret": {"selected": selected, "best_selectable_tested": best_sel, "best_tested_including_gated": best_all,
                   "regret_vs_best_selectable": sub(best_sel_rr, sel_rr),
                   "gate_regret_vs_best_tested": sub(best_all_rr, sel_rr)},
    }


def ci(w):
    return "" if not w else "%.3f [%.3f, %.3f]" % w


def markdown_scenario(s):
    caps = s["capabilities"]
    out = ["## Scenario `%s` (%d episodes)" % (s["scenario_id"], s["episodes"]), ""]
    out.append("Instantiated attacker capabilities: " + "; ".join("**%s**: %s" % (c, CAPABILITIES[c]["label"]) for c in caps) + ".")
    b = s["baseline"]["per_capability"]
    out.append("Baseline (no action): " + "; ".join("%s usable at end in %d/%d episodes" % (c, b[c]["k"], b[c]["n"]) for c in caps) + ".")
    out += ["", "| action | selectable in state | predicted SG (gross) | predicted weight on measured capabilities | brain selected | " +
            " | ".join("%s usable at end (Wilson 95%%) | %s removal time s (min/median/max) | %s risk reduction (Newcombe 95%%)" % (c, c, c) for c in caps) +
            " | legitimate failures |", "|---|---|---|---|---|" + "---|---|---|" * len(caps) + "---|"]
    selected = s["regret"]["selected"]
    for a, x in s["actions"].items():
        cells = []
        for c in caps:
            p = x["per_capability"][c]
            r = p["removal_s"]
            rr = p["risk_reduction_end"]
            cells += ["%d/%d = %s" % (p["usable_at_end"]["k"], p["usable_at_end"]["n"], ci(p["usable_at_end"]["wilson"])),
                      "—" if not r["n"] else "%s / %s / %s" % (fmt(r["min"], 1), fmt(r["median"], 1), fmt(r["max"], 1)),
                      "%.3f [%.3f, %.3f]" % (rr["estimate"], rr["newcombe95"][0], rr["newcombe95"][1]) if rr else "UNAVAILABLE"]
        gate = ("yes" if x["selectable"] else "no") + ((" (" + "; ".join(x["blocking_gate"]) + ")") if x["blocking_gate"] else "")
        legit = ("%d/%d" % (x["legit_failures"], x["legit_samples"])) if x["disruption_representative"] else "UNAVAILABLE (no kubelet)"
        out.append("| %s | %s | %s | %s | %s | %s | %s |" % (a, gate, fmt(x["predicted_security_gain"]["mean"]), fmt(x["predicted_weight_on_measured_capabilities"]),
                                                       "yes" if a in selected else "no", " | ".join(cells), legit))
    out += ["", "Fact invalidation vs capability (attack-attributed facts, brain re-observation after the branch):", "",
            "| action | target observed after | " + " | ".join("%s: true / false / uncredited / persisting" % c for c in caps) +
            " | structural kinds re-minted on a new identity | brain selects after |", "|---|---|" + "---|" * len(caps) + "---|---|"]
    for a, x in s["actions"].items():
        inv = [x["per_capability"][c]["invalidation"] for c in caps]
        out.append("| %s | %s | %s | %s | %s |" % (a, "; ".join(x["post_targets"]),
                   " | ".join("%d / %d / %d / %d" % (i["true"], i["false"], i["uncredited"], i["persisting"]) for i in inv),
                   ", ".join(x["kinds_reminted_on_new_identity"]) or "—", ", ".join(x["post_selected_actions"])))
    for c in caps:
        h0 = next(iter(s["actions"].values()))["per_capability"][c]["time_horizons"]
        out += ["", "Time horizon, %s (successes / determinate probes after the branch point):" % c, "",
                "| action | " + " | ".join("%g–%s s" % (h["from_s"], "" if h["to_s"] is None else "%g" % h["to_s"]) for h in h0) + " |",
                "|---|" + "---|" * len(h0)]
        for a, x in s["actions"].items():
            out.append("| %s | %s |" % (a, " | ".join("%d/%d" % (h["success"], h["n"]) if h["n"] else "—" for h in x["per_capability"][c]["time_horizons"])))
    r, g = s["ranking"], s["regret"]
    out += ["", "Ranking: %s; predicted SG %s; measured risk reduction (sum over capabilities, end of window) %s." % (
        ", ".join(r["actions"]), [round(v, 4) for v in r["predicted_security_gain"]], [round(v, 3) for v in r["measured_risk_reduction_total"]]),
        "Kendall τ-b = %s, Spearman ρ = %s (all tested); selectable only (%s): τ-b = %s, ρ = %s. %s" % (
            fmt(r["kendall_tau_b"], 3), fmt(r["spearman"], 3), ", ".join(r["selectable_only"]["actions"]),
            fmt(r["selectable_only"]["kendall_tau_b"], 3), fmt(r["selectable_only"]["spearman"], 3), r["note"]), "",
        "| predicted higher | predicted lower | both selectable | measured RR (higher / lower) | verdict |", "|---|---|---|---|---|"]
    for p in r["pairs"]:
        out.append("| %s | %s | %s | %.3f / %.3f | %s |" % (p["predicted_higher"], p["predicted_lower"], "yes" if p["both_selectable"] else "no",
                                                         p["measured_rr_higher"], p["measured_rr_lower"], p["verdict"]))
    out += ["", "Regret: brain selected %s. Best selectable tested action: %s (regret %s). Best tested action including gated ones: %s (gate regret %s)." % (
        ", ".join(g["selected"]), g["best_selectable_tested"], fmt(g["regret_vs_best_selectable"], 3),
        g["best_tested_including_gated"], fmt(g["gate_regret_vs_best_tested"], 3)), ""]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("study", nargs="+", help="run_study.py output directories")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    episodes = []
    for study in a.study:
        with open(os.path.join(study, "study-manifest.json")) as f:
            manifest = json.load(f)
        for meta in manifest["episodes"]:
            meta = dict(meta, scenario=meta.get("scenario") or manifest.get("scenario") or "lease")
            path = os.path.join(study, meta["dir"])
            if not os.path.exists(os.path.join(path, "report.json")):
                episodes.append({"dir": meta["dir"], "arm": meta["arm"], "scenario": meta["scenario"], "verdict": meta.get("verdict"), "error": "no report.json"})
                continue
            episodes.append(load_episode(path, meta))
    usable = [e for e in episodes if "candidates" in e]
    scenarios = [sc for sc in SCENARIOS if any(e["scenario"] == sc for e in usable)]
    summary = {"episodes_total": len(episodes), "episodes_usable": len(usable),
               "unusable": [{"dir": e["dir"], "verdict": e.get("verdict"), "error": e.get("error")} for e in episodes if "candidates" not in e],
               "scenarios": {sc: summarize_scenario(sc, [e for e in usable if e["scenario"] == sc]) for sc in scenarios}}
    os.makedirs(a.out, exist_ok=True)
    rows = []
    for e in usable:
        rows += episode_rows(e, summary["scenarios"][e["scenario"]]["baseline"])
    with open(os.path.join(a.out, "candidates.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)
    md = ["# Security Gain validation — measured outcomes", "",
          "Episodes: %d usable of %d. Generated by analyze.py; see REPORT.md for interpretation." % (len(usable), len(episodes)), ""]
    for sc in scenarios:
        md += markdown_scenario(summary["scenarios"][sc])
    if summary["unusable"]:
        md += ["## Episodes without a usable decision", ""] + ["- %s (%s): %s" % (u["dir"], u["verdict"], u["error"]) for u in summary["unusable"]]
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("episodes=%d usable=%d rows=%d scenarios=%s" % (len(episodes), len(usable), len(rows), ",".join(scenarios)))


if __name__ == "__main__":
    main()
