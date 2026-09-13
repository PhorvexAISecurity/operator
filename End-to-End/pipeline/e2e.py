#!/usr/bin/env python3
"""End-to-End pipeline for Phorvex.

Drives the system from its first stage (a signal entering ingest) to its last (a hand
touching the cluster), captures every intermediate value the engine produced, asserts the
contracts each stage is supposed to hold, verifies the actuator's claims against the
cluster itself, and writes one self-contained dashboard.

    python3 pipeline/e2e.py --mode observe
    python3 pipeline/e2e.py --mode attack --target litellm

`observe` only reads. `attack` fires a real attack against a namespace that the console
has explicitly armed, then clears it again — it changes a live cluster, so it is never
the default and always prints what it is about to do.
"""

import argparse
import calendar
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import checks as checks_mod                      # noqa: E402
from attribution import Correlator               # noqa: E402
from groundtruth import verify                   # noqa: E402
from notify import Notifier                      # noqa: E402
from report import render                        # noqa: E402
from trace import trace_of                       # noqa: E402
from transport import (Cluster, Console, Metrics, Transport, TransportError,  # noqa: E402
                       capture_limits, capture_scope)
from detector import DetectorSignal             # noqa: E402
from run_output import Cleanup, RunOutput, SCHEMA, error_text  # noqa: E402

ROOT = HERE.parent


class Ctx:
    """Everything the checks are allowed to look at.

    Observations travel alongside the values they produced. A check that reads
    `writer_metrics` can also read `metrics_observation` and tell "the gauge is absent"
    apart from "the scrape failed" — the distinction A06 exists to make.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.inv = cfg["invariants"]
        self.records = []
        self.pre_records = []
        self.post_records = []
        self.preflight = {}
        self.target = None
        self.baseline_pods = {}
        self.baseline_namespace = None
        self.stateful_by_pod = {}
        self.ground_truth = []
        self.attack_fired = False
        self.attack_started_at = None
        self.max_moves_per_tick = None
        self.policy = None
        self.policy_observation = None
        self.policy_mode = None
        self.policy_dryrun = None
        self.controller_pods = {}
        self.controller_observation = None
        self.writer_metrics = {}
        self.metrics_observation = None
        self.scope = None
        self.clock_skew_sec = 0.0
        self.capture_complete = True
        self.capture_reason = ""
        self.captures = {}
        self.correlator = None
        self.stale_after_sec = 180
        self.max_restarts = int(cfg.get("invariants", {}).get("max_controller_restarts", 10))

    @staticmethod
    def parse_time(s):
        if not s:
            return None
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z?", str(s))
        if not m:
            return None
        base = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
        return base + (float("0." + m.group(2)) if m.group(2) else 0.0)

    @property
    def freshest_age_sec(self):
        ts = [self.parse_time(r.get("time")) for r in self.records]
        ts = [t for t in ts if t is not None]
        return None if not ts else max(0.0, time.time() - max(ts))


def log(msg, indent=0):
    print(f"{'  ' * indent}{msg}", flush=True)


def record_key(r):
    """Identity of a decision for deduplication.

    Two decisions can legitimately share a tick timestamp, a pod name and an action while
    belonging to different tenants or namespaces — a pod name is not unique across a
    cluster. Dropping the second one silenced a real owner's decision, so every identity
    field the record carries is part of the key.
    """
    return (r.get("time"), r.get("tenant"), r.get("namespace"), r.get("pod"),
            r.get("action"), r.get("selected"), r.get("actuated"))


def dedupe(records):
    """The SSE endpoint replays the audit file, so a re-read yields repeats."""
    seen, out = set(), []
    for r in records:
        k = record_key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


DEFAULT_MAX_MOVES_PER_TICK = 3  # api/v1alpha1/defaults.go:20 — used when the CR omits it


def read_policy(cluster, namespace):
    """Live PhorvexPolicy identity, budget and mode.

    The budget is a per-owner ceiling, so the owner's identity travels with it: without a
    policy UID there is nobody to hold the budget against, and B07 says so instead of
    attributing every tenant's selections to whichever policy `items[0]` happened to be.

    An unset spec.budget.maxMovesPerTick means the operator applies its own default, so the
    pipeline uses that same constant rather than skipping the check and pretending it has
    no opinion. The result records which of the two it was.
    """
    read = cluster.phorvex_policy(namespace)
    if not read.usable or not read.value:
        return None, read
    policy = dict(read.value)
    if policy.get("maxMovesPerTick") is None:
        policy["maxMovesPerTick"] = DEFAULT_MAX_MOVES_PER_TICK
    return policy, read


def run(cfg, mode, target_name, out_dir, stream_override=None, notifier=None, run_label=None,
        report_url=None, baseline=None, output=None):
    output = output or RunOutput(out_dir, mode, target_name, label=run_label)
    cleanup = Cleanup()
    try:
        with cleanup:
            doc, rc = _run(cfg, mode, target_name, out_dir, stream_override, notifier, run_label,
                           report_url, baseline, cleanup, output)
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        doc, rc = output.abort(error, cleanup.errors), 2
    try:
        doc['exitCode'] = rc
        doc = output.write(doc, render)
    except Exception as error:
        # CI's summary has a separate missing-artifact fallback. Never turn a disk
        # or renderer failure into success or replace the primary abort diagnostic.
        log('report write failed: ' + error_text(error))
        if doc.get('abort'):
            log('primary error: ' + doc['abort']['error'])
            doc['abort']['reportErrors'] = [error_text(error)]
        else:
            output.stage = 'report writing'
            doc = output.abort(error, cleanup.errors)
        if notifier:
            notifier.stage(6, 'fail', 'report write failed; see this attempt job log')
        return doc, 2
    if doc.get('status') == 'aborted':
        log(f"E2E ABORTED [{doc['abort']['stage']}]: {doc['abort']['error']}")
        for error in doc['abort']['cleanupErrors']:
            log('cleanup unresolved: ' + error)
        if notifier:
            notifier.stage(6, 'fail', 'run aborted; see current attempt artifacts')
        return doc, 2
    if notifier:
        notifier.stage(6, 'ok', f'run-{output.run_id}.html')
        notifier.finish(doc['verdict'], doc['tally'],
                        report_url.replace('{stamp}', output.run_id) if report_url else None,
                        failures=[r['id'] for r in doc['checks'] if r['status'] == 'fail'],
                        extra=(["already known: " + ', '.join(doc['baselined'])] if doc['baselined'] else [])
                        + (["stale baseline (delete): " + ', '.join(doc['staleBaseline'])] if doc['staleBaseline'] else []))
    return doc, rc


def _run(cfg, mode, target_name, out_dir, stream_override, notifier, run_label,
         report_url, baseline, cleanup, output):
    ctx = Ctx(cfg)
    t = Transport(cfg["transport"])
    console = Console(t, cfg["console"])
    cluster = Cluster(t)
    metrics = Metrics(t, cfg.get("audit_writer"))
    cap = cfg["capture"]
    limits = capture_limits(cap)
    started = output.started
    n = notifier or Notifier(enabled=False)
    log(f"● transport: {t.describe()}   mode: {mode}")
    n.start(mode, target_name, t.describe(), ctx_lines=[run_label] if run_label else [])

    # ── 0 · preflight ────────────────────────────────────────────────────────
    log("\n[0/6] preflight")
    output.stage = 'preflight'
    n.running(0)
    ctx.preflight["health"], ctx.preflight["version"] = console.wait_preflight()
    ctx.controller_observation = cluster.controller_pods(
        cfg.get("operator_namespace", "phorvex-system"), cfg.get("controller_deployments"))
    ctx.controller_pods = ctx.controller_observation.value or {}
    ctx.preflight["controllers"] = ctx.controller_pods
    ctx.preflight["controllerRead"] = ctx.controller_observation.to_json()
    ctx.metrics_observation = metrics.scrape()
    ctx.writer_metrics = ctx.metrics_observation.value_or({})
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    ctx.preflight["auditWriter"] = {"metricsUrl": metrics.describe(), "killSwitchEngaged": ks,
                                    "read": ctx.metrics_observation.to_json()}
    if ks is not None:
        log(f"audit writer: kill switch = {'engaged (decide only, no action)' if ks else 'off'}", 1)
    elif not ctx.metrics_observation.usable:
        log("audit writer: metrics " + ctx.metrics_observation.describe(), 1)
    for name, meta in ctx.controller_pods.items():
        log(f"{name}: {meta['phase']} · restarts={meta['restarts']}", 1)
    log(f"console {ctx.preflight['version'].get('console')} · "
        f"operator {ctx.preflight['version'].get('operator')}", 1)

    if target_name:
        ctx.target = next((x for x in cfg["targets"] if x["name"] == target_name), None)
        if not ctx.target:
            raise SystemExit(f"unknown target: {target_name} "
                             f"(available: {', '.join(x['name'] for x in cfg['targets'])})")
        ns = ctx.target["namespace"]
        ctx.baseline_namespace = ns
        baseline_read = cluster.pod_uids(ns)
        # An unreadable baseline is not an empty namespace. Continuing with `{}` here is
        # what let a later "the pod is not in the inventory" read as a successful rotation.
        if not baseline_read.usable:
            raise TransportError("the target pod baseline could not be captured, so no later "
                                 "observation could be compared against it: "
                                 + baseline_read.describe())
        ctx.baseline_pods = baseline_read.value
        ctx.preflight["baselineRead"] = baseline_read.to_json()
        ctx.policy, ctx.policy_observation = read_policy(cluster, ns)
        if ctx.policy:
            ctx.max_moves_per_tick = ctx.policy["maxMovesPerTick"]
            ctx.policy_mode, ctx.policy_dryrun = ctx.policy.get("mode"), ctx.policy.get("dryRun")
        for pod in ctx.baseline_pods:
            st = cluster.pod_is_stateful(ns, pod)
            if st.usable:
                ctx.stateful_by_pod[(ns, pod)] = st.value
        log(f"target {ctx.target['name']} · {len(ctx.baseline_pods)} pods · "
            f"stateful={sum(1 for v in ctx.stateful_by_pod.values() if v)} · "
            f"maxMovesPerTick={ctx.max_moves_per_tick} · mode={ctx.policy_mode} "
            f"· dryRun={ctx.policy_dryrun}", 1)
        if not ctx.policy:
            log("no single governing PhorvexPolicy was observed: "
                + ctx.policy_observation.describe(), 1)

    # What this run's captures claim to cover, decided once and recorded next to the
    # counters. A scoped run must not be read as a cluster-wide observation.
    ctx.scope = capture_scope(cap, ctx.target)
    ctx.clock_skew_sec = float(cap.get("clock_skew_tolerance_sec", 2))
    log(f"capture scope: {ctx.scope.describe()} · limits {limits.to_json()}", 1)

    # A stage is only green here if preflight found a live system: an unreachable console or
    # a controller that is not Running makes every later stage meaningless, and the board
    # must say so at [0/6] rather than let it surface as an empty capture at [1/6].
    controller_health = checks_mod.p05(ctx)
    n.stage(0, "fail" if (controller_health["status"] != checks_mod.PASS
                          or not ctx.preflight["version"].get("operator")) else "ok",
            f"console {ctx.preflight['version'].get('console', '?')} · "
            f"operator {ctx.preflight['version'].get('operator', '?')} · "
            + controller_health["summary"])

    # ── 1 · baseline capture ─────────────────────────────────────────────────
    secs = stream_override or cap["stream_seconds"]
    output.stage = 'baseline capture'
    log(f"\n[1/6] baseline capture ({secs}s of the decision stream)")
    n.running(1, f"{secs}s")
    pre = console.stream_decisions(secs, limits, ctx.scope)
    ctx.captures["baseline"] = pre
    output.captures["baseline"] = pre.to_json()
    ctx.pre_records = dedupe(pre.records)
    log(f"{len(ctx.pre_records)} unique records · {pre.describe()}", 1)
    if not pre.complete:
        log(f"baseline capture incomplete: {pre.reason}", 1)
    # No records at all is a failed capture, not an empty one — every check downstream would
    # skip, and a board of skips reads as a pass.
    n.stage(1, "ok" if (ctx.pre_records and pre.complete) else "fail",
            f"{len(ctx.pre_records)} records · {pre.describe()}")

    # ── 2 · fire ─────────────────────────────────────────────────────────────
    attack_response = None
    detector = None
    captured_post = None
    attack_started_at = None
    legacy_clear = None
    if mode == "attack":
        output.stage = 'injection / live capture'
        if not ctx.target:
            raise SystemExit("attack mode requires --target")
        a = ctx.target["attack"]
        n.running(2, ctx.target["name"])
        if ctx.target.get("detector"):
            detector = DetectorSignal(t, ctx.target, run_id=output.run_id)
            output.injection = {'kind': 'SecurityEvent', 'name': detector.name,
                                'identity': detector.identity, 'targetNamespace': detector.namespace,
                                'runId': output.run_id,
                                'createAttempted': False, 'createResponseValidated': False,
                                'cleanup': 'not-needed'}

            def clear_detector():
                needed = detector.attempted
                try:
                    detector.clear()
                except Exception:
                    output.injection['cleanup'] = 'failed'
                    raise
                output.injection['cleanup'] = 'delete-request-acknowledged' if needed else 'not-needed'

            cleanup.callback(clear_detector)

        def fire_when_stream_ready():
            nonlocal attack_response, attack_started_at, legacy_clear
            attack_started_at = time.time()
            if detector:
                log(f"\n[2/6] firing authenticated E2E signal as {detector.identity}")
                try:
                    attack_response = detector.fire()
                    output.injection['createResponseValidated'] = True
                finally:
                    output.injection['createAttempted'] = detector.attempted
                    # Whatever the API server assigned, kept verbatim: this is the only
                    # identity any later record can be bound to.
                    output.injection.update(detector.injection_identity())
            else:
                # A console signal returns no event identity at all, so nothing downstream
                # can bind a reaction to it. That is recorded here rather than glossed over.
                output.injection = {'kind': 'console-signal', 'targetNamespace': ctx.target['namespace'],
                                    'eventUID': None, 'eventName': None, 'targetUID': None,
                                    'runId': output.run_id,
                                    'createAttempted': True, 'cleanup': 'not-configured'}
                log(f"\n[2/6] firing a real attack → POST {a['path']} {json.dumps(a['body'])}")
                # Also clear legacy console signals on exceptions after POST.
                if ctx.target.get("clear"):
                    cl = ctx.target["clear"]
                    cleared = False

                    def clear_once():
                        nonlocal cleared
                        if not cleared:
                            output.injection['cleanup'] = 'failed'
                            result = console.post_json(cl["path"], cl["body"])
                            if not isinstance(result, dict) or result.get('ok') is not True:
                                raise TransportError('console cleanup did not acknowledge success')
                            cleared = True
                            output.injection['cleanup'] = 'clear-response-acknowledged'
                            return result

                    legacy_clear = clear_once
                    cleanup.callback(clear_once)
                attack_response = console.post_json(a["path"], a["body"])
            ctx.attack_fired = True

        log("\n[2/6] opening audit stream before injection (waiting for readiness heartbeat)")
        live = console.stream_decisions(
            cap["post_attack_seconds"] + cap["settle_seconds"], limits, ctx.scope,
            on_connected=fire_when_stream_ready)
        ctx.captures["live"] = live
        output.captures["live"] = live.to_json()
        captured_post = live.records
        log(str(attack_response)[:300], 1)
        # The console answers 200-with-error for an unarmed namespace and 503 when no
        # attackable pod is left, so "did it fire" is a field, not an HTTP code.
        fired = bool(attack_response.get("ok"))
        n.stage(2, "ok" if fired else "fail",
                (f"{attack_response.get('pod', '?')} → {attack_response.get('expect', '?')}"
                 if fired else str(attack_response.get("error") or attack_response)[:80]))
    else:
        log("\n[2/6] fire — skipped (observe mode; the cluster is left untouched)")
        n.stage(2, "skip", "observe mode")

    # ── 3 · post capture ─────────────────────────────────────────────────────
    win = cap["post_attack_seconds"] if mode == "attack" else 0
    output.stage = 'post-attack capture'
    if win:
        log(f"\n[3/6] post-attack capture ({win}s)")
        n.running(3, f"{win}s")
        post = captured_post
        # The "already seen it" key has to carry namespace and tenant too: two namespaces
        # can produce a decision for the same pod name, action and tick, and dropping the
        # second one deletes another owner's evidence.
        pre_keys = {record_key(r) for r in ctx.pre_records}
        # Record timestamps come from the operator's clock and `attack_started_at` from
        # ours, so comparing them assumes the two agree. They agree to within NTP, not
        # exactly, and the audit stamps whole records — so the tolerance is declared and
        # recorded rather than left as an invisible strictly-greater-than. It only widens
        # which records are *considered*: what makes one attributable is A05's identity
        # binding, not its position in the window.
        skew = ctx.clock_skew_sec
        ctx.post_records = [r for r in dedupe(post)
                            if record_key(r) not in pre_keys
                            and (ctx.parse_time(r.get("time")) or 0) >= attack_started_at - skew]
        log(f"{len(ctx.post_records)} fresh records after firing · "
            f"{ctx.captures['live'].describe()}", 1)
        if not ctx.captures["live"].complete:
            log(f"live capture incomplete: {ctx.captures['live'].reason}", 1)
        # An attack that produced no new decision at all is a finding: either the signal
        # never reached ingest or the operator stopped ticking. Warn rather than fail —
        # the check catalogue at [5/6] is what decides the run.
        n.stage(3, "ok" if (ctx.post_records and ctx.captures["live"].complete) else "warn",
                f"{len(ctx.post_records)} fresh records")
    else:
        log("\n[3/6] post-attack capture — skipped")
        n.stage(3, "skip", "nothing fired")

    ctx.records = dedupe(ctx.pre_records + ctx.post_records)
    ctx.attack_started_at = attack_started_at
    ctx.capture_complete = all(c.complete for c in ctx.captures.values())
    ctx.capture_reason = "; ".join(f"{k}: {c.reason}" for k, c in ctx.captures.items()
                                  if not c.complete)
    # What this run's records are capable of proving about cause, feature-detected from the
    # records themselves rather than assumed from the schema we hope is deployed.
    ctx.correlator = Correlator(output.injection or {}, ctx.records) if ctx.attack_fired else None

    # ── 4 · ground truth ─────────────────────────────────────────────────────
    log("\n[4/6] independent verification against the cluster")
    output.stage = 'ground truth'
    acted = [r for r in ctx.records if r.get("actuated")]
    if acted:
        n.running(4, f"{len(acted)} actions")
        ctx.ground_truth = verify(
            cluster, acted, ctx.baseline_pods,
            namespace=ctx.baseline_namespace,
            # Without an injection, the run's own start bounds the log evidence: nothing
            # written before the pipeline began can answer for what it observed.
            action_started_at=attack_started_at or started.timestamp(),
            log_patterns=ctx.inv.get("action_log_evidence"),
            attribution_of=(ctx.correlator.classify if ctx.correlator else None),
            clock_skew_sec=ctx.clock_skew_sec)
        for g in ctx.ground_truth:
            log(f"{g['verdict']:14s} {g['action']:16s} {g['namespace']}/{g['pod']}: "
                f"{g['detail']} [attribution: {g['attribution']}]", 1)
        # groundtruth.py returns `unverifiable` for the actions it cannot independently
        # confirm. That is not a failure — it is the module refusing to vouch for something
        # it did not look at — so it is counted separately from a real contradiction.
        gt = {}
        for g in ctx.ground_truth:
            gt[g["verdict"]] = gt.get(g["verdict"], 0) + 1
        bad = sum(v for k, v in gt.items() if k not in ("confirmed", "unverifiable"))
        n.stage(4, "fail" if bad else ("warn" if gt.get("unverifiable") else "ok"),
                " · ".join(f"{k}={v}" for k, v in sorted(gt.items())))
    else:
        log("nothing was actuated in the window — there is nothing to verify", 1)
        n.stage(4, "skip", "nothing actuated")

    # ── 5 · checks ───────────────────────────────────────────────────────────
    log("\n[5/6] running the checks")
    n.running(5)
    results = []
    output.stage = 'checks'
    output.results = results
    for c in checks_mod.registry():
        try:
            r = c["fn"](ctx)
        except Exception as e:                        # a broken check is a finding, not a crash
            r = checks_mod.result(checks_mod.FAIL, f"the check itself errored: {type(e).__name__}: {e}")
        results.append({**{k: v for k, v in c.items() if k != "fn"}, **r})
        mark = {"pass": "✔", "fail": "✘", "warn": "!", "skip": "–"}[r["status"]]
        log(f"{mark} {c['id']:5s} {c['title']}  —  {r['summary']}", 1)

    tally = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "warn", "skip")}
    coverage_tally = {c: sum(1 for r in results if r.get("coverage") == c)
                      for c in ("full", "partial", "none", "not-applicable")}
    # Severity-aware roll-up: a failing MINOR check is a real finding but must not read as a
    # broken system, and a passing board built on skips must not read as full coverage.
    hard = [r for r in results if r["status"] == "fail" and r["severity"] in ("critical", "major")]
    soft = [r for r in results if (r["status"] == "fail" and r["severity"] == "minor")
            or r["status"] == "warn"]
    # A critical contract that could not be observed at all is not a passing contract. It is
    # separated from `not-applicable` on purpose: "no actuation happened, so there was
    # nothing to verify" is a legitimate PASS; "the cluster would not tell us" is not.
    unobserved = [r for r in results
                  if r["severity"] == "critical" and r.get("coverage") == "none"]
    incomplete = [] if ctx.capture_complete else [ctx.capture_reason]
    verdict = ("FAIL" if hard else
               "WARN" if (soft or unobserved or incomplete) else "PASS")
    for r in unobserved:
        log(f"! {r['id']} is critical and could not be observed — {r['summary']}", 1)
    if incomplete:
        log(f"! the capture window was not fully observed — {ctx.capture_reason}", 1)

    # The verdict above stays honest: a contract violation is a FAIL whether or not anyone
    # wrote it down. The baseline only separates "already broken" from "broken by this
    # change", because that is the question a pull-request gate is actually asking.
    known = dict((baseline or {}).get("checks") or {})
    baselined = [r["id"] for r in hard if r["id"] in known]
    new_failures = [r["id"] for r in hard if r["id"] not in known]
    # A baselined check that PASSES means the entry outlived its cause. Left alone it
    # becomes a permanent hole in the gate, so it is reported loudly rather than silently
    # tolerated.
    stale = [r["id"] for r in results if r["status"] == "pass" and r["id"] in known]
    for cid in baselined:
        log(f"↷ {cid} is already known — {known[cid].get('reason', '')[:110]}", 1)
    for cid in stale:
        log(f"! {cid} no longer fails — remove its entry from baseline.json", 1)

    n.stage(5, "fail" if new_failures else ("warn" if (soft or hard) else "ok"),
            f"✔{tally['pass']} ✘{tally['fail']} !{tally['warn']} –{tally['skip']}"
            + (f" ({len(baselined)} known)" if baselined else ""))

    # ── 6 · clear + report ───────────────────────────────────────────────────
    n.running(6)
    output.stage = 'cleanup'
    cleanup.close()
    if cleanup.errors:
        raise TransportError('attack cleanup failed; see cleanupErrors')
    log("\n[6/6] registered cleanup complete")

    traces = [trace_of(r) for r in ctx.records]

    run_doc = {
        "schema": SCHEMA,
        "startedAt": started.isoformat(),
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "transport": t.describe(),
        "target": ctx.target,
        "verdict": verdict,
        "tally": tally,
        # Coverage sits next to the tally because they answer different questions: the tally
        # says how many contracts held, coverage says how many were actually examined.
        "coverage": dict(coverage_tally,
                         criticalUnobserved=[r["id"] for r in unobserved]),
        "capture": {"scope": ctx.scope.to_json(), "limits": limits.to_json(),
                    "complete": ctx.capture_complete, "reason": ctx.capture_reason,
                    "clockSkewToleranceSec": ctx.clock_skew_sec,
                    "windows": {k: c.to_json() for k, c in ctx.captures.items()}},
        "attribution": ctx.correlator.to_json() if ctx.correlator else None,
        # What the gate acted on, recorded next to the verdict so a green CI run next to a
        # red report is self-explaining rather than suspicious.
        "baselined": baselined,
        "newFailures": new_failures,
        "staleBaseline": stale,
        "baselineReasons": {k: v.get("reason") for k, v in known.items() if k in baselined},
        "preflight": ctx.preflight,
        "attackResponse": attack_response,
        "attackStartedAtEpoch": attack_started_at,
        "injection": output.injection,
        "policy": {"maxMovesPerTick": ctx.max_moves_per_tick,
                   "mode": ctx.policy_mode, "dryRun": ctx.policy_dryrun,
                   "uid": (ctx.policy or {}).get("uid"), "name": (ctx.policy or {}).get("name"),
                   "namespace": (ctx.policy or {}).get("namespace"),
                   "budgetDeclared": (ctx.policy or {}).get("budgetDeclared"),
                   "read": ctx.policy_observation.to_json() if ctx.policy_observation else None},
        "baselineNamespace": ctx.baseline_namespace,
        "baselinePods": ctx.baseline_pods,
        "controllerPods": ctx.controller_pods,
        "statefulPods": [f"{ns}/{p}" for (ns, p), v in ctx.stateful_by_pod.items() if v],
        "counts": {"records": len(ctx.records), "pre": len(ctx.pre_records),
                   "post": len(ctx.post_records), "actuated": len(acted)},
        "checks": results,
        "groundTruth": ctx.ground_truth,
        "traces": traces,
    }

    output.stage = 'report'
    stamp = output.run_id
    run_doc["runId"] = stamp

    log(f"\n══ verdict: {verdict}  "
        f"(✔{tally['pass']}  ✘{tally['fail']}  !{tally['warn']}  –{tally['skip']})")
    if baselined:
        log(f"   {len(baselined)} known failures: {', '.join(baselined)}")
    if new_failures:
        log(f"   {len(new_failures)} new failures: {', '.join(new_failures)}")

    # Exit non-zero only for a hard failure nobody has accounted for. With no baseline
    # loaded this is exactly the old behaviour: every hard failure is a new one.
    return run_doc, 1 if new_failures else 0


def main():
    ap = argparse.ArgumentParser(description="Phorvex End-to-End pipeline")
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--mode", choices=["observe", "attack"], default="observe")
    ap.add_argument("--target", default=None)
    ap.add_argument("--out", default=str(ROOT / "runs"))
    ap.add_argument("--run-id", default=None, help="unique attempt ID (CI run/attempt/job)")
    ap.add_argument("--source-commit", default=None, help="full harness source commit, not deployed version")
    ap.add_argument("--stream-seconds", type=int, default=None)
    ap.add_argument("--list-targets", action="store_true")
    ap.add_argument("--telegram", action="store_true",
                    help="report each stage to Telegram (needs TELEGRAM_BOT_TOKEN + "
                         "TELEGRAM_CHAT_ID; silently inert without them)")
    ap.add_argument("--run-label", default=None,
                    help="one line of context for the Telegram board, e.g. 'PR #42 · abc1234'")
    ap.add_argument("--report-url", default=None,
                    help="URL template for the published report; {stamp} is replaced with "
                         "the run id, e.g. https://ci-report.phorvex.ai/pr-42/run-{stamp}.html")
    ap.add_argument("--baseline", default=None,
                    help="known-failure file (see baseline.json). Failures listed there are "
                         "still reported as failures, but do not set a non-zero exit code — "
                         "so CI gates on NEW regressions rather than on absolute state.")
    a = ap.parse_args()

    if a.list_targets:
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
        for tg in cfg["targets"]:
            print(f"{tg['name']:20s} ns={tg['namespace']:18s} kind={tg['kind']}")
        return 0
    if a.mode == "attack" and not a.target:
        ap.error("--mode attack requires --target (list them with --list-targets)")

    n = Notifier(enabled=a.telegram, log=lambda m: log(m, 1))
    if a.telegram and not n.enabled:
        log("warning: --telegram was passed but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID are unset "
            "— notifications are off")
    try:
        output = RunOutput(a.out, a.mode, a.target, a.run_id, a.source_commit, a.run_label)
    except ValueError as error:
        ap.error(str(error))
    try:
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
        baseline = None
        if a.baseline:
            # Baseline/config errors are fatal and reported, never ignored.
            baseline = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
            log(f"● baseline: {a.baseline} ({len(baseline.get('checks') or {})} known checks)")
        _, rc = run(cfg, a.mode, a.target, Path(a.out), a.stream_seconds,
                    notifier=n, run_label=a.run_label, report_url=a.report_url,
                    baseline=baseline, output=output)
        return rc
    except Exception as error:
        log('E2E initialization aborted: ' + error_text(error))
        try:
            output.write(output.abort(error), render)
        except Exception as write_error:
            log('report write failed: ' + error_text(write_error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
