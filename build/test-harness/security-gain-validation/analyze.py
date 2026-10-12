#!/usr/bin/env python3
"""Security Gain validation analysis for verification-loop study episodes.

Reads the per-episode report.json files written by run_study.py and produces:

  candidates.csv  one row per (episode, candidate action) in that episode's real decision state
  summary.json    per-action outcomes, fact-invalidation matrix, ranking, regret, time horizons
  summary.md      the same as readable tables

Predicted values come from the unchanged brain's decision trace. Measured values come only
from probes and post-branch brain re-observation in the same episode. A measured column is
filled only for the action that episode actually executed; every other value is left blank
and its companion *_status column says why. Nothing unavailable is written as zero.
Standard library only.
"""
import argparse
import csv
import json
import math
import os
from datetime import datetime

MARKER = "verification-loop-synthetic-downstream"
SCENARIO = "elr-stolen-inference-credential-envtest-v1"
# The only attacker capability this fixture instantiates: credential A admitted downstream.
MEASURED_KIND = "endpointLeaseReuse"
NOOP = "noop"
ARM_ACTION = {"intervention": "endpoint-lease-revoke", "baseline": NOOP, "cf-rotate": "rotate", "cf-endpoint-rotate": "endpoint-rotate"}
HORIZONS = ((0.0, 5.0), (5.0, 10.0), (10.0, 20.0), (20.0, None))
EVIDENCE = ("MEASURED in a private envtest API server with the unchanged brain, native actuator and shipped "
            "Python admission boundary; synthetic downstream; TEST_INJECTED attack event; no kubelet or containers")
Z = 1.959963984540054

COLUMNS = [
    "scenario_id", "snapshot_id", "episode", "arm", "executed_in_episode", "asset_id", "action_id",
    "feasible", "blocking_gate", "selected_by_brain",
    "predicted_security_gain", "predicted_marginal_gain", "predicted_net_gain",
    "asset_value", "attacker_hold_estimate", "urgency", "dispersion_multiplier", "provenance",
    "predicted_cover_keys", "predicted_fact_weights", "predicted_weight_on_measured_capability",
    "confirmed_invalidated_keys", "confirmed_invalidated_keys_status",
    "false_invalidated_keys", "unmeasured_cleared_keys", "exact_keys_cleared", "kinds_reminted_on_new_identity",
    "post_branch_fact_keys", "post_branch_selected_action", "post_branch_target",
    "remaining_attacker_capabilities", "remaining_attacker_capabilities_status",
    "attack_landed_before_decision",
    "attack_success_no_action", "attack_success_no_action_status",
    "attack_success_with_action", "attack_success_with_action_status", "attack_probes_with_action",
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
    """'success' = the protected downstream operation ran; 'denied' = exact admission refusal with
    zero downstream effect; anything else is indeterminate and never counted either way."""
    body = p.get("body") if isinstance(p.get("body"), dict) else {}
    if p.get("error"):
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


def load_episode(path, meta):
    with open(os.path.join(path, "report.json")) as f:
        r = json.load(f)
    arm = r.get("arm") or meta.get("arm") or "intervention"
    d, t = trace_of(r.get("decisions"))
    if t is None:
        return {"dir": meta["dir"], "arm": arm, "verdict": r.get("verdict"), "error": r.get("error") or "no decision trace"}
    _, pt = trace_of(r.get("post_decisions"))
    probes = r.get("probes") or []
    if arm == "intervention":
        a_names, b_names = ("A-after-native", "A-hold"), ("B-after-native", "B-hold")
        t0 = ts(r.get("dispatch_finished_at"))
    else:
        a_names, b_names = ("A-study-hold",), ("B-study-hold",)
        t0 = ts(r.get("dispatch_finished_at")) if arm != "baseline" else None
        if t0 is None:
            hold = [ts(p["at"]) for p in probes if p["name"] == "A-study-hold"]
            t0 = min(hold) if hold else None

    def series(names):
        return [(ts(p["at"]) - t0 if t0 is not None else None, outcome(p), p.get("latency_ms")) for p in probes if p["name"] in names]

    pre_a = [outcome(p) for p in probes if p["name"] == "attack-baseline-A"]
    pre_b_lat = [p.get("latency_ms") for p in probes if p["name"] in ("clean-B", "attack-baseline-B") and outcome(p) == "success"]
    facts = {f["factKey"]: f for f in t.get("facts") or []}
    status = {s["action"]: s for s in t.get("actionStatus") or []}
    cands = []
    for c in t.get("candidates") or []:
        st = status.get(c["action"], {})
        cands.append({
            "action": c["action"], "feasible": val(c.get("feasible")), "selected": bool(c.get("selected")),
            "blocking_gate": c.get("existingExclusionReason") or (st.get("reason") if st.get("status") in ("infeasible", "excluded") else "") or "",
            "status_reason": st.get("reason", ""), "cover": c.get("coverKeys") or [],
            "gross": val(c.get("grossFullValue")), "marginal": val(c.get("marginalCoverage")), "net": val(c.get("netGain")),
            "provenance": val(c.get("provenance")), "expected_cost": val(c.get("expectedCost")),
        })
    dispatch = r.get("dispatch") or {}
    return {
        "dir": meta["dir"], "arm": arm, "verdict": r.get("verdict"), "error": r.get("error") or "",
        "executed_action": ARM_ACTION.get(arm), "decision_id": t.get("decisionID"), "tick_id": t.get("tickID"),
        "asset": "%s/%s" % (t.get("assetNamespace"), t.get("assetName")), "asset_uid": t.get("assetUID"),
        "selected": t.get("selectedAction"), "asset_value": d.get("AssetValue"),
        "p_hold": val((t.get("inputs") or {}).get("pHold")), "urgency": val((t.get("inputs") or {}).get("stageUrgency")),
        "dispersion": val((t.get("inputs") or {}).get("dispersionMult")),
        "facts": {k: f.get("finalWeight") for k, f in facts.items()},
        "candidates": cands,
        "dispatch_emitted": dispatch.get("Emitted"), "dispatch_handler": dispatch.get("Handler"), "dispatch_note": dispatch.get("Note") or "",
        "pre_a": pre_a, "pre_b_latency": pre_b_lat,
        "a": series(a_names), "b": series(b_names),
        "a_after_replacement": [outcome(p) for p in probes if p["name"] == "A-after-replacement"],
        "b_after_replacement": [outcome(p) for p in probes if p["name"] == "B-after-replacement"],
        "hold_s": (r.get("hold_elapsed_ms") or 0) / 1000.0,
        "post_target": r.get("post_target") or "",
        "post_error": r.get("post_observation_error") or "",
        "post_facts": None if pt is None else sorted(f["factKey"] for f in pt.get("facts") or []),
        "post_weights": None if pt is None else {f["factKey"]: f.get("finalWeight") for f in pt.get("facts") or []},
        "post_selected": None if pt is None else pt.get("selectedAction"),
    }


def kind(key):
    return key.rsplit("|", 1)[-1]


def capability_removed(e):
    """Was credential A's downstream capability removed for the whole post-action window?"""
    obs = [o for _, o, _ in e["a"] if o != "indeterminate"] + [o for o in e["a_after_replacement"] if o != "indeterminate"]
    if not obs:
        return None
    return all(o == "denied" for o in obs)


def invalidation(e):
    """Compare each pre-decision fact with the brain's post-branch view and the measured capability.

    Exact keys name the pod, so a replacement pod clears every old key. Whether the brain still
    believes in the capability is judged by fact kind on the observed workload: a kind that is
    re-minted on the replacement persists; one that is not was invalidated in the brain's view."""
    if e["post_facts"] is None:
        return None
    post_kinds = {kind(k) for k in e["post_facts"]}
    removed = capability_removed(e)
    out = {"cleared": [], "true": [], "false": [], "unmeasured": [], "persisting": [],
           "keys_cleared": sorted(set(e["facts"]) - set(e["post_facts"])), "reminted": []}
    for key in sorted(e["facts"]):
        k = kind(key)
        if k in post_kinds:
            out["persisting"].append(k)
            if key not in e["post_facts"]:
                out["reminted"].append(k)
            continue
        out["cleared"].append(k)
        if k != MEASURED_KIND:
            out["unmeasured"].append(k)
        elif removed:
            out["true"].append(k)
        else:
            out["false"].append(k)
    return out


def a_rate(e):
    obs = [o for _, o, _ in e["a"] if o != "indeterminate"]
    return (sum(o == "success" for o in obs), len(obs))


def interrupted(e):
    k, n = a_rate(e)
    return None if n == 0 else k == 0


def disruption(e):
    obs = [(o, lat) for _, o, lat in e["b"]]
    ok = [lat for o, lat in obs if o == "success"]
    fail = sum(o != "success" for o, _ in obs)
    lat = sorted(ok)
    p95 = lat[min(len(lat) - 1, int(math.ceil(0.95 * len(lat))) - 1)] if lat else None
    base = sorted(e["pre_b_latency"])
    return {"legit_failures": fail, "legit_samples": len(obs), "legit_p95_ms": p95,
            "legit_pre_ms": base[len(base) // 2] if base else None}


def episode_rows(e, baseline):
    rows = []
    inval = invalidation(e)
    removed = capability_removed(e)
    succ, n = a_rate(e)
    pre = "1" if e["pre_a"] and all(o == "success" for o in e["pre_a"]) else ("0" if e["pre_a"] else "")
    cands = list(e["candidates"])
    if not any(c["action"] == NOOP for c in cands):
        cands.append({"action": NOOP, "feasible": True, "selected": e["selected"] == NOOP, "blocking_gate": "", "cover": [],
                      "gross": 0.0, "marginal": 0.0, "net": 0.0, "provenance": None, "expected_cost": 0.0, "status_reason": "withhold every action"})
    for c in cands:
        executed = c["action"] == e["executed_action"]
        row = {k: "" for k in COLUMNS}
        row.update({
            "scenario_id": SCENARIO, "snapshot_id": e["decision_id"], "episode": e["dir"], "arm": e["arm"],
            "executed_in_episode": "yes" if executed else "no",
            "asset_id": "%s uid=%s" % (e["asset"], e["asset_uid"]), "action_id": c["action"],
            "feasible": {True: "true", False: "false"}.get(c["feasible"], "unknown"),
            "blocking_gate": c["blocking_gate"] or ("none" if c["feasible"] else c["status_reason"] or "unknown"),
            "selected_by_brain": "yes" if c["selected"] else "no",
            "predicted_security_gain": fmt(c["gross"]), "predicted_marginal_gain": fmt(c["marginal"]), "predicted_net_gain": fmt(c["net"]),
            "asset_value": fmt(e["asset_value"]), "attacker_hold_estimate": fmt(e["p_hold"]), "urgency": fmt(e["urgency"]),
            "dispersion_multiplier": fmt(e["dispersion"]), "provenance": fmt(c["provenance"]) if c["action"] != NOOP else "not-applicable",
            "predicted_cover_keys": ";".join(c["cover"]),
            "predicted_fact_weights": ";".join("%s=%s" % (k, fmt(e["facts"].get(k))) for k in c["cover"]),
            "predicted_weight_on_measured_capability": fmt(sum(e["facts"].get(k, 0) for k in c["cover"] if kind(k) == MEASURED_KIND)),
            "attack_landed_before_decision": pre,
            "expected_disruption_cost": fmt(c["expected_cost"]),
            "expected_avoided_loss_status": "UNAVAILABLE: synthetic downstream has no defensible consequence value",
            "evidence_quality": EVIDENCE,
        })
        if not executed:
            why = "UNAVAILABLE: not executed in this episode (measured in arm %s episodes)" % next((a for a, x in ARM_ACTION.items() if x == c["action"]), "none")
            for col in ("confirmed_invalidated_keys_status", "remaining_attacker_capabilities_status", "attack_success_no_action_status",
                        "attack_success_with_action_status", "time_to_reacquire_status", "effect_duration_status",
                        "estimated_risk_reduction_status", "measured_disruption_status"):
                row[col] = why
            rows.append(row)
            continue
        row["post_branch_fact_keys"] = ";".join("%s=%s" % (k, fmt(e["post_weights"].get(k))) for k in e["post_facts"]) if e["post_facts"] is not None else ""
        row["post_branch_selected_action"] = e["post_selected"] or ""
        row["post_branch_target"] = e["post_target"]
        if inval is None:
            row["confirmed_invalidated_keys_status"] = "UNAVAILABLE: post-branch observation failed: " + e["post_error"]
        else:
            row["confirmed_invalidated_keys"] = ";".join(inval["true"])
            row["false_invalidated_keys"] = ";".join(inval["false"])
            row["unmeasured_cleared_keys"] = ";".join(inval["unmeasured"])
            row["exact_keys_cleared"] = ";".join(inval["keys_cleared"])
            row["kinds_reminted_on_new_identity"] = ";".join(inval["reminted"])
            row["confirmed_invalidated_keys_status"] = ("MEASURED for %s (credential A probes); other cleared kinds have no instantiated "
                                                        "capability in this fixture and are listed as unmeasured" % MEASURED_KIND)
        remaining = []
        if removed is False:
            remaining.append("credential-A downstream admission (measured usable)")
        remaining.append("credential-B lease: legitimate, mounted in the pod Secret volume; theft by an in-pod attacker NOT TESTED")
        if inval is not None and inval["persisting"]:
            remaining.append("brain still mints: " + ",".join(sorted(set(inval["persisting"]) - {MEASURED_KIND})) + " (capabilities not instantiated; NOT MEASURED)")
        row["remaining_attacker_capabilities"] = " | ".join(remaining)
        row["remaining_attacker_capabilities_status"] = "PARTIAL: only credential A is measured"
        if baseline:
            row["attack_success_no_action"] = fmt(baseline["p"])
            row["attack_success_no_action_status"] = "MEASURED: baseline arm, same initial state, %d episodes, episode-level" % baseline["n"]
        else:
            row["attack_success_no_action_status"] = "UNAVAILABLE: no baseline episodes"
        if n:
            row["attack_success_with_action"] = fmt(succ / n)
            row["attack_probes_with_action"] = "%d/%d" % (succ, n)
            row["attack_success_with_action_status"] = "MEASURED: fraction of credential-A probes reaching the protected downstream over %.1fs" % e["hold_s"]
        else:
            row["attack_success_with_action_status"] = "UNAVAILABLE: no determinate attack probes"
        if removed:
            row["time_to_reacquire_s"] = fmt(e["hold_s"])
            row["time_to_reacquire_status"] = "CENSORED: no reacquisition within the observed window (value is the lower bound)"
            row["effect_duration_s"] = fmt(e["hold_s"])
            row["effect_duration_status"] = "CENSORED: effect still holding at end of window (value is the lower bound)"
        elif removed is False:
            row["time_to_reacquire_status"] = "NOT APPLICABLE: capability was never removed"
            row["effect_duration_status"] = "NOT APPLICABLE: no interruption observed"
        else:
            row["time_to_reacquire_status"] = row["effect_duration_status"] = "UNAVAILABLE: no determinate attack probes"
        if baseline and n:
            row["estimated_risk_reduction"] = fmt(baseline["p"] - (0.0 if interrupted(e) else 1.0))
            row["estimated_risk_reduction_status"] = "ESTIMATE from measured outcomes: baseline-arm success probability minus this episode's (attack reached downstream at least once = 1)"
        else:
            row["estimated_risk_reduction_status"] = "UNAVAILABLE: missing baseline or episode probes"
        dis = disruption(e)
        if c["action"] == "rotate":
            row["measured_disruption_status"] = ("UNAVAILABLE: envtest has no kubelet, so eviction does not stop the serving process; "
                                                 "production single-replica rotate is an outage (the brain's availability gate)")
        else:
            row["measured_disruption"] = "legit_failures=%d/%d;legit_p95_ms=%s;legit_pre_median_ms=%s" % (
                dis["legit_failures"], dis["legit_samples"], fmt(dis["legit_p95_ms"], 1), fmt(dis["legit_pre_ms"], 1))
            row["measured_disruption_status"] = "MEASURED: legitimate credential-B probes (local, single worker)"
        rows.append(row)
    return rows


def fmt(x, digits=4):
    if x is None:
        return ""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (int, float)):
        return ("%." + str(digits) + "f") % x
    return str(x)


def summarize(episodes):
    by_arm = {}
    for e in episodes:
        by_arm.setdefault(e["arm"], []).append(e)
    base = [e for e in by_arm.get("baseline", []) if interrupted(e) is not None]
    base_k = sum(not interrupted(e) for e in base)
    baseline = {"p": base_k / len(base), "k": base_k, "n": len(base)} if base else None
    actions = {}
    for arm, es in sorted(by_arm.items()):
        act = ARM_ACTION[arm]
        es_ok = [e for e in es if interrupted(e) is not None]
        k_ep = sum(not interrupted(e) for e in es_ok)
        k_pr = sum(a_rate(e)[0] for e in es_ok)
        n_pr = sum(a_rate(e)[1] for e in es_ok)
        inv = [invalidation(e) for e in es]
        cands = [c for e in es for c in e["candidates"] if c["action"] == act]
        gross = [c["gross"] for c in cands if c["gross"] is not None]
        feas = sorted({str(c["feasible"]) for c in cands}) or ["True"]
        horizon = []
        for lo, hi in HORIZONS:
            obs = [o for e in es_ok for t, o, _ in e["a"] if t is not None and t >= lo and (hi is None or t < hi) and o != "indeterminate"]
            k = sum(o == "success" for o in obs)
            horizon.append({"from_s": lo, "to_s": hi, "success": k, "n": len(obs), "wilson": wilson(k, len(obs))})
        dis = [disruption(e) for e in es_ok]
        rr = newcombe(baseline["k"], baseline["n"], k_ep, len(es_ok)) if baseline and es_ok else None
        actions[act] = {
            "arm": arm, "episodes": len(es), "episodes_with_probes": len(es_ok),
            "verdicts": sorted({e["verdict"] for e in es}),
            "dispatch_emitted": sorted({str(e.get("dispatch_emitted")) for e in es}),
            "dispatch_notes": sorted({e.get("dispatch_note", "")[:160] for e in es}),
            "feasible_in_decision_state": feas,
            "blocking_gate": sorted({c["blocking_gate"] for c in cands if c["blocking_gate"]}),
            "predicted_security_gain": {"mean": mean(gross), "min": min(gross) if gross else None, "max": max(gross) if gross else None} if act != NOOP else {"mean": 0.0, "min": 0.0, "max": 0.0},
            "predicted_weight_on_measured_capability": mean([sum(e["facts"].get(k, 0) for k in c["cover"] if kind(k) == MEASURED_KIND) for e in es for c in e["candidates"] if c["action"] == act]) if act != NOOP else 0.0,
            "attack_reached_downstream_episode": {"k": k_ep, "n": len(es_ok), "wilson": wilson(k_ep, len(es_ok))},
            "attack_probe_success": {"k": k_pr, "n": n_pr, "wilson": wilson(k_pr, n_pr), "note": "probes cluster within episodes; treat as descriptive"},
            "risk_reduction_vs_baseline": {"estimate": rr[0], "newcombe95": [rr[1], rr[2]]} if rr else None,
            "time_horizons": horizon,
            "fact_invalidation": {
                "post_observed": sum(i is not None for i in inv),
                "measured_kind_cleared_and_capability_removed": sum(bool(i and MEASURED_KIND in i["true"]) for i in inv),
                "measured_kind_cleared_but_capability_usable": sum(bool(i and MEASURED_KIND in i["false"]) for i in inv),
                "measured_kind_persisting": sum(bool(i and MEASURED_KIND in i["persisting"]) for i in inv),
                "unmeasured_kinds_cleared": sorted({k for i in inv if i for k in i["unmeasured"]}),
                "kinds_reminted_on_new_identity": sorted({k for i in inv if i for k in i["reminted"]}),
                "post_weights_by_kind": {k: mean([w for e in es if e.get("post_weights") for key, w in e["post_weights"].items() if kind(key) == k])
                                         for k in sorted({kind(key) for e in es if e.get("post_weights") for key in e["post_weights"]})},
                "pre_weights_by_kind": {k: mean([w for e in es for key, w in e["facts"].items() if kind(key) == k])
                                        for k in sorted({kind(key) for e in es for key in e["facts"]})},
                "post_selected_actions": sorted({str(e["post_selected"]) for e in es}),
                "post_targets": sorted({e["post_target"].split(" uid=")[0] for e in es}),
                "post_errors": sorted({e["post_error"] for e in es if e["post_error"]}),
            },
            "after_replacement_attack": [o for e in es for o in e["a_after_replacement"]],
            "legit_failures": sum(d["legit_failures"] for d in dis), "legit_samples": sum(d["legit_samples"] for d in dis),
            "disruption_representative": act != "rotate",
            "legit_p95_ms_max": max((d["legit_p95_ms"] for d in dis if d["legit_p95_ms"] is not None), default=None),
            "reacquisition": "censored" if es_ok and all(interrupted(e) for e in es_ok) else ("not-applicable" if es_ok else "unavailable"),
            "min_censoring_window_s": min((e["hold_s"] for e in es_ok), default=None),
        }
    order = [a for a in ("endpoint-lease-revoke", "rotate", "endpoint-rotate", NOOP) if a in actions and actions[a]["risk_reduction_vs_baseline"]]
    pred = [actions[a]["predicted_security_gain"]["mean"] for a in order]
    meas = [actions[a]["risk_reduction_vs_baseline"]["estimate"] for a in order]
    feasible = [a for a in order if a == NOOP or "True" in actions[a]["feasible_in_decision_state"]]
    fpred = [actions[a]["predicted_security_gain"]["mean"] for a in feasible]
    fmeas = [actions[a]["risk_reduction_vs_baseline"]["estimate"] for a in feasible]
    pairs = []
    for i in range(len(order)):
        for j in range(i + 1, len(order)):
            a, b = order[i], order[j]
            if pred[i] == pred[j]:
                continue
            hi, lo = (a, b) if pred[i] > pred[j] else (b, a)
            ci_hi = actions[hi]["risk_reduction_vs_baseline"]["newcombe95"]
            ci_lo = actions[lo]["risk_reduction_vs_baseline"]["newcombe95"]
            m_hi, m_lo = actions[hi]["risk_reduction_vs_baseline"]["estimate"], actions[lo]["risk_reduction_vs_baseline"]["estimate"]
            verdict = "agree" if m_hi > m_lo else ("tie-in-outcome" if m_hi == m_lo else "reversal")
            if verdict == "reversal" and not ci_hi[1] < ci_lo[0]:
                verdict = "reversal-not-significant"
            pairs.append({"predicted_higher": hi, "predicted_lower": lo, "measured_rr_higher": m_hi, "measured_rr_lower": m_lo,
                          "both_feasible": hi in feasible and lo in feasible, "verdict": verdict})
    selected = sorted({e["selected"] for e in episodes if e.get("selected")})
    best = max(feasible, key=lambda a: actions[a]["risk_reduction_vs_baseline"]["estimate"]) if feasible else None
    regret = None
    if best and len(selected) == 1 and selected[0] in actions and actions[selected[0]]["risk_reduction_vs_baseline"]:
        regret = actions[best]["risk_reduction_vs_baseline"]["estimate"] - actions[selected[0]]["risk_reduction_vs_baseline"]["estimate"]
    return {
        "scenario_id": SCENARIO, "measured_capability": MEASURED_KIND, "baseline": baseline, "actions": actions,
        "ranking": {
            "actions": order, "predicted_security_gain": pred, "measured_risk_reduction": meas,
            "kendall_tau_b": kendall_tau_b(pred, meas) if len(order) > 1 else None,
            "spearman": spearman(pred, meas) if len(order) > 1 else None,
            "sufficient_data": False,
            "note": "One scenario and %d actions; a rank coefficient over so few points is descriptive only. Statistical rank agreement: NOT VALIDATED." % len(order),
            "feasible_only": {"actions": feasible, "predicted_security_gain": fpred, "measured_risk_reduction": fmeas,
                              "kendall_tau_b": kendall_tau_b(fpred, fmeas) if len(feasible) > 1 else None,
                              "spearman": spearman(fpred, fmeas) if len(feasible) > 1 else None},
            "pairs": pairs,
        },
        "regret": {"selected": selected, "best_tested_feasible": best, "feasible_tested": feasible, "regret_risk_reduction": regret},
    }


def mean(v):
    v = [x for x in v if x is not None]
    return sum(v) / len(v) if v else None


def ci(w):
    return "" if not w else "%.3f [%.3f, %.3f]" % w


def markdown(s, episodes):
    out = ["# Security Gain validation — %s" % s["scenario_id"], ""]
    b = s["baseline"]
    out.append("Episodes: %d (%s). Baseline (no action) attack reached the protected downstream in %d/%d episodes."
               % (len(episodes), ", ".join("%s=%d" % (a, s["actions"][x]["episodes"]) for x, a in [(v, k) for k, v in ARM_ACTION.items()] if x in s["actions"]),
                  b["k"] if b else 0, b["n"] if b else 0))
    out += ["", "## Outcomes by action (measured capability: credential A → downstream)", "",
            "| action | feasible in state | predicted SG (gross) | predicted weight on measured capability | attack reached downstream (episodes, Wilson 95%) | attack probe success (Wilson 95%) | risk reduction vs baseline (Newcombe 95%) | legit failures | reacquisition |",
            "|---|---|---|---|---|---|---|---|---|"]
    for a, x in s["actions"].items():
        rr = x["risk_reduction_vs_baseline"]
        out.append("| %s | %s%s | %s | %s | %s | %s | %s | %s | %s |" % (
            a, "/".join(x["feasible_in_decision_state"]), (" (" + "; ".join(x["blocking_gate"]) + ")") if x["blocking_gate"] else "",
            fmt(x["predicted_security_gain"]["mean"]), fmt(x["predicted_weight_on_measured_capability"]),
            "%d/%d = %s" % (x["attack_reached_downstream_episode"]["k"], x["attack_reached_downstream_episode"]["n"], ci(x["attack_reached_downstream_episode"]["wilson"])),
            "%d/%d = %s" % (x["attack_probe_success"]["k"], x["attack_probe_success"]["n"], ci(x["attack_probe_success"]["wilson"])),
            "%.3f [%.3f, %.3f]" % (rr["estimate"], rr["newcombe95"][0], rr["newcombe95"][1]) if rr else "UNAVAILABLE",
            ("%d/%d" % (x["legit_failures"], x["legit_samples"])) if x["disruption_representative"] else "UNAVAILABLE (no kubelet: eviction does not stop serving)",
            ("censored ≥ %.1fs" % x["min_censoring_window_s"]) if x["reacquisition"] == "censored" else x["reacquisition"]))
    out += ["", "## Fact invalidation vs capability (post-branch brain re-observation)", "",
            "| action | post observed | target observed after | %s cleared + capability removed | cleared but A still usable (false invalidation) | %s persisting | other kinds cleared (unmeasured) | kinds re-minted on a new identity | brain selects after |" % (MEASURED_KIND, MEASURED_KIND),
            "|---|---|---|---|---|---|---|---|---|"]
    for a, x in s["actions"].items():
        f = x["fact_invalidation"]
        out.append("| %s | %d/%d | %s | %d | %d | %d | %s | %s | %s |" % (a, f["post_observed"], x["episodes"], "; ".join(f["post_targets"]),
                   f["measured_kind_cleared_and_capability_removed"], f["measured_kind_cleared_but_capability_usable"],
                   f["measured_kind_persisting"], ", ".join(f["unmeasured_kinds_cleared"]) or "—",
                   ", ".join(f["kinds_reminted_on_new_identity"]) or "—", ", ".join(f["post_selected_actions"])))
    out += ["", "## Fact weights before the decision and after the branch (mean by kind)", "",
            "| action | " + " | ".join(sorted(next(iter(s["actions"].values()))["fact_invalidation"]["pre_weights_by_kind"])) + " |",
            "|---|" + "---|" * len(next(iter(s["actions"].values()))["fact_invalidation"]["pre_weights_by_kind"])]
    kinds = sorted(next(iter(s["actions"].values()))["fact_invalidation"]["pre_weights_by_kind"])
    first = next(iter(s["actions"].values()))["fact_invalidation"]["pre_weights_by_kind"]
    out.append("| (before, all arms) | " + " | ".join(fmt(first.get(k)) for k in kinds) + " |")
    for a, x in s["actions"].items():
        pw = x["fact_invalidation"]["post_weights_by_kind"]
        out.append("| %s (after) | %s |" % (a, " | ".join(fmt(pw.get(k)) if pw.get(k) is not None else "absent" for k in kinds)))
    out += ["", "## Time horizon (credential-A probe success after the branch point)", "", "| action | " + " | ".join(
        "%g–%s s" % (h["from_s"], "" if h["to_s"] is None else "%g" % h["to_s"]) for h in next(iter(s["actions"].values()))["time_horizons"]) + " |",
        "|---|" + "---|" * len(HORIZONS)]
    for a, x in s["actions"].items():
        out.append("| %s | %s |" % (a, " | ".join("%d/%d" % (h["success"], h["n"]) if h["n"] else "—" for h in x["time_horizons"])))
    r = s["ranking"]
    out += ["", "## Ranking", "",
            "Order: %s; predicted SG %s; measured risk reduction %s." % (", ".join(r["actions"]), [round(v, 4) for v in r["predicted_security_gain"]], [round(v, 3) for v in r["measured_risk_reduction"]]),
            "Kendall τ-b = %s; Spearman ρ = %s. %s" % (fmt(r["kendall_tau_b"], 3), fmt(r["spearman"], 3), r["note"]), "",
            "Feasible candidates only (%s): Kendall τ-b = %s; Spearman ρ = %s." % (", ".join(r["feasible_only"]["actions"]),
                                                                            fmt(r["feasible_only"]["kendall_tau_b"], 3), fmt(r["feasible_only"]["spearman"], 3)), "",
            "| predicted higher | predicted lower | both feasible | measured RR (higher / lower) | verdict |", "|---|---|---|---|---|"]
    for p in r["pairs"]:
        out.append("| %s | %s | %s | %.3f / %.3f | %s |" % (p["predicted_higher"], p["predicted_lower"], "yes" if p["both_feasible"] else "no",
                                                       p["measured_rr_higher"], p["measured_rr_lower"], p["verdict"]))
    g = s["regret"]
    out += ["", "Regret: brain selected %s; best tested feasible action %s (feasible tested: %s); regret in risk-reduction units = %s." % (
        ", ".join(g["selected"]), g["best_tested_feasible"], ", ".join(g["feasible_tested"]), fmt(g["regret_risk_reduction"], 3))]
    bad = [e for e in episodes if e.get("error") and e.get("verdict") not in ("STUDY_ARM_RECORDED", "LOCAL_RUNTIME_DEFENDED")]
    if bad:
        out += ["", "## Episodes with errors", ""] + ["- %s (%s): %s" % (e["dir"], e.get("verdict"), e["error"]) for e in bad]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("study", help="run_study.py output directory")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(os.path.join(a.study, "study-manifest.json")) as f:
        manifest = json.load(f)
    episodes = []
    for meta in manifest["episodes"]:
        path = os.path.join(a.study, meta["dir"])
        if not os.path.exists(os.path.join(path, "report.json")):
            episodes.append({"dir": meta["dir"], "arm": meta["arm"], "verdict": meta.get("verdict"), "error": "no report.json"})
            continue
        episodes.append(load_episode(path, meta))
    usable = [e for e in episodes if "candidates" in e]
    s = summarize(usable)
    s["episodes_total"], s["episodes_usable"] = len(episodes), len(usable)
    s["unusable"] = [{"dir": e["dir"], "verdict": e.get("verdict"), "error": e.get("error")} for e in episodes if "candidates" not in e]
    os.makedirs(a.out, exist_ok=True)
    rows = []
    for e in usable:
        rows += episode_rows(e, s["baseline"])
    with open(os.path.join(a.out, "candidates.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(s, f, indent=2, default=str)
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(markdown(s, episodes))
    print("episodes=%d usable=%d rows=%d" % (len(episodes), len(usable), len(rows)))


if __name__ == "__main__":
    main()
