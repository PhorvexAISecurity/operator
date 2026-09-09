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
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import checks as checks_mod                      # noqa: E402
from groundtruth import verify                   # noqa: E402
from notify import Notifier                      # noqa: E402
from report import render                        # noqa: E402
from trace import trace_of                       # noqa: E402
from transport import Cluster, Console, Metrics, Transport, TransportError  # noqa: E402
from detector import DetectorSignal             # noqa: E402

ROOT = HERE.parent


class Ctx:
    """Everything the checks are allowed to look at."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.inv = cfg["invariants"]
        self.records = []
        self.pre_records = []
        self.post_records = []
        self.preflight = {}
        self.target = None
        self.baseline_pods = {}
        self.stateful_by_pod = {}
        self.ground_truth = []
        self.attack_fired = False
        self.max_moves_per_tick = None
        self.policy_mode = None
        self.policy_dryrun = None
        self.controller_pods = {}
        self.writer_metrics = {}
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


def dedupe(records):
    """The SSE endpoint replays the audit file, so a re-read yields repeats."""
    seen, out = set(), []
    for r in records:
        k = (r.get("time"), r.get("namespace"), r.get("pod"), r.get("action"), r.get("selected"))
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


DEFAULT_MAX_MOVES_PER_TICK = 3  # api/v1alpha1/defaults.go:20 — used when the CR omits it


def read_policy(cluster, namespace):
    """Live PhorvexPolicy budget and mode.

    The field is spec.budget.maxMovesPerTick; an unset value means the operator applies its
    own default, so the pipeline falls back to that same constant rather than skipping the
    budget check and pretending it has no opinion.
    """
    rc, out, _ = cluster.kubectl(
        f"-n {namespace} get phorvexpolicy -o jsonpath="
        "'{.items[0].spec.budget.maxMovesPerTick}|{.items[0].spec.mode}|{.items[0].spec.dryRun}'")
    if rc != 0:
        return None, None, None
    budget, _, rest = out.strip().strip("'").partition("|")
    mode, _, dry = rest.partition("|")
    b = int(budget) if budget.strip().isdigit() else DEFAULT_MAX_MOVES_PER_TICK
    return b, (mode.strip() or None), (dry.strip() or None)


def run(cfg, mode, target_name, out_dir, stream_override=None, notifier=None, run_label=None,
        report_url=None, baseline=None):
    with ExitStack() as cleanup:
        return _run(cfg, mode, target_name, out_dir, stream_override, notifier, run_label,
                    report_url, baseline, cleanup)


def _run(cfg, mode, target_name, out_dir, stream_override, notifier, run_label,
         report_url, baseline, cleanup):
    ctx = Ctx(cfg)
    t = Transport(cfg["transport"])
    console = Console(t, cfg["console"])
    cluster = Cluster(t)
    metrics = Metrics(t, cfg.get("audit_writer"))
    cap = cfg["capture"]
    started = datetime.now(timezone.utc)
    n = notifier or Notifier(enabled=False)
    log(f"● transport: {t.describe()}   mode: {mode}")
    n.start(mode, target_name, t.describe(), ctx_lines=[run_label] if run_label else [])

    # ── 0 · preflight ────────────────────────────────────────────────────────
    log("\n[0/6] preflight")
    n.running(0)
    ctx.preflight["health"], ctx.preflight["version"] = console.wait_preflight()
    ctx.controller_pods = cluster.controller_pods(
        cfg.get("operator_namespace", "phorvex-system"), cfg.get("controller_deployments"))
    ctx.preflight["controllers"] = ctx.controller_pods
    ctx.writer_metrics = metrics.scrape()
    ks = ctx.writer_metrics.get("phorvex_kill_switch_engaged")
    ctx.preflight["auditWriter"] = {"metricsUrl": metrics.describe(), "killSwitchEngaged": ks}
    if ks is not None:
        log(f"audit writer: kill switch = {'engaged (decide only, no action)' if ks else 'off'}", 1)
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
        ctx.baseline_pods = cluster.pod_uids(ns)
        ctx.max_moves_per_tick, ctx.policy_mode, ctx.policy_dryrun = read_policy(cluster, ns)
        for pod in ctx.baseline_pods:
            st = cluster.pod_is_stateful(ns, pod)
            if st is not None:
                ctx.stateful_by_pod[(ns, pod)] = st
        log(f"target {ctx.target['name']} · {len(ctx.baseline_pods)} pods · "
            f"stateful={sum(1 for v in ctx.stateful_by_pod.values() if v)} · "
            f"maxMovesPerTick={ctx.max_moves_per_tick} · mode={ctx.policy_mode} "
            f"· dryRun={ctx.policy_dryrun}", 1)

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
    log(f"\n[1/6] baseline capture ({secs}s of the decision stream)")
    n.running(1, f"{secs}s")
    pre, malformed = console.stream_decisions(secs, cap["max_bytes"])
    ctx.pre_records = dedupe(pre)
    log(f"{len(ctx.pre_records)} unique records"
        f"{f' ({malformed} malformed lines from the cut)' if malformed else ''}", 1)
    # No records at all is a failed capture, not an empty one — every check downstream would
    # skip, and a board of skips reads as a pass.
    n.stage(1, "ok" if ctx.pre_records else "fail",
            f"{len(ctx.pre_records)} records"
            + (f" · {malformed} malformed" if malformed else ""))

    # ── 2 · fire ─────────────────────────────────────────────────────────────
    attack_response = None
    detector = None
    captured_post = None
    attack_started_at = None
    legacy_clear = None
    if mode == "attack":
        if not ctx.target:
            raise SystemExit("attack mode requires --target")
        a = ctx.target["attack"]
        n.running(2, ctx.target["name"])
        if ctx.target.get("detector"):
            detector = DetectorSignal(t, ctx.target)
            cleanup.callback(detector.clear)

        def fire_when_stream_ready():
            nonlocal attack_response, attack_started_at, legacy_clear
            attack_started_at = time.time()
            if detector:
                log(f"\n[2/6] firing authenticated E2E signal as {detector.identity}")
                attack_response = detector.fire()
            else:
                log(f"\n[2/6] firing a real attack → POST {a['path']} {json.dumps(a['body'])}")
                # Also clear legacy console signals on exceptions after POST.
                if ctx.target.get("clear"):
                    cl = ctx.target["clear"]
                    cleared = False

                    def clear_once():
                        nonlocal cleared
                        if not cleared:
                            result = console.post_json(cl["path"], cl["body"])
                            cleared = True
                            return result

                    legacy_clear = clear_once
                    cleanup.callback(clear_once)
                attack_response = console.post_json(a["path"], a["body"])
            ctx.attack_fired = True

        log("\n[2/6] opening audit stream before injection (waiting for readiness heartbeat)")
        captured_post, _ = console.stream_decisions(
            cap["post_attack_seconds"] + cap["settle_seconds"], cap["max_bytes"],
            on_connected=fire_when_stream_ready)
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
    if win:
        log(f"\n[3/6] post-attack capture ({win}s)")
        n.running(3, f"{win}s")
        post = captured_post
        pre_keys = {(r.get("time"), r.get("pod"), r.get("action")) for r in ctx.pre_records}
        ctx.post_records = [r for r in dedupe(post)
                            if (r.get("time"), r.get("pod"), r.get("action")) not in pre_keys
                            and (ctx.parse_time(r.get("time")) or 0) >= attack_started_at]
        log(f"{len(ctx.post_records)} fresh records after firing", 1)
        # An attack that produced no new decision at all is a finding: either the signal
        # never reached ingest or the operator stopped ticking. Warn rather than fail —
        # the check catalogue at [5/6] is what decides the run.
        n.stage(3, "ok" if ctx.post_records else "warn",
                f"{len(ctx.post_records)} fresh records")
    else:
        log("\n[3/6] post-attack capture — skipped")
        n.stage(3, "skip", "nothing fired")

    ctx.records = dedupe(ctx.pre_records + ctx.post_records)

    # ── 4 · ground truth ─────────────────────────────────────────────────────
    log("\n[4/6] independent verification against the cluster")
    acted = [r for r in ctx.records if r.get("actuated")]
    if acted:
        n.running(4, f"{len(acted)} actions")
        ctx.ground_truth = verify(cluster, acted, ctx.baseline_pods)
        for g in ctx.ground_truth:
            log(f"{g['verdict']:14s} {g['action']:16s} {g['pod']}: {g['detail']}", 1)
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
    for c in checks_mod.registry():
        try:
            r = c["fn"](ctx)
        except Exception as e:                        # a broken check is a finding, not a crash
            r = checks_mod.result(checks_mod.FAIL, f"the check itself errored: {type(e).__name__}: {e}")
        results.append({**{k: v for k, v in c.items() if k != "fn"}, **r})
        mark = {"pass": "✔", "fail": "✘", "warn": "!", "skip": "–"}[r["status"]]
        log(f"{mark} {c['id']:5s} {c['title']}  —  {r['summary']}", 1)

    tally = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "warn", "skip")}
    # Severity-aware roll-up: a failing MINOR check is a real finding but must not read as a
    # broken system, and a passing board built on skips must not read as full coverage.
    hard = [r for r in results if r["status"] == "fail" and r["severity"] in ("critical", "major")]
    soft = [r for r in results if (r["status"] == "fail" and r["severity"] == "minor")
            or r["status"] == "warn"]
    verdict = "FAIL" if hard else ("WARN" if soft else "PASS")

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
    if detector:
        log(f"\n[6/6] clearing dedicated E2E event {detector.name}")
        detector.clear()
    elif ctx.attack_fired and ctx.target.get("clear"):
        cl = ctx.target["clear"]
        log(f"\n[6/6] clearing the attack signal → POST {cl['path']} {json.dumps(cl['body'])}")
        log(str(legacy_clear())[:250], 1)
    else:
        log("\n[6/6] clear — not needed")

    traces = [trace_of(r) for r in ctx.records]

    run_doc = {
        "schema": "phorvex.e2e/1",
        "startedAt": started.isoformat(),
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "transport": t.describe(),
        "target": ctx.target,
        "verdict": verdict,
        "tally": tally,
        # What the gate acted on, recorded next to the verdict so a green CI run next to a
        # red report is self-explaining rather than suspicious.
        "baselined": baselined,
        "newFailures": new_failures,
        "staleBaseline": stale,
        "baselineReasons": {k: v.get("reason") for k, v in known.items() if k in baselined},
        "preflight": ctx.preflight,
        "attackResponse": attack_response,
        "attackStartedAtEpoch": attack_started_at,
        "policy": {"maxMovesPerTick": ctx.max_moves_per_tick,
                   "mode": ctx.policy_mode, "dryRun": ctx.policy_dryrun},
        "baselinePods": ctx.baseline_pods,
        "controllerPods": ctx.controller_pods,
        "statefulPods": [f"{ns}/{p}" for (ns, p), v in ctx.stateful_by_pod.items() if v],
        "counts": {"records": len(ctx.records), "pre": len(ctx.pre_records),
                   "post": len(ctx.post_records), "actuated": len(acted)},
        "checks": results,
        "groundTruth": ctx.ground_truth,
        "traces": traces,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    run_doc["runId"] = stamp
    jpath = out_dir / f"run-{stamp}.json"
    hpath = out_dir / f"run-{stamp}.html"
    jpath.write_text(json.dumps(run_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    hpath.write_text(render(run_doc), encoding="utf-8")
    (out_dir / "latest.html").write_text(render(run_doc), encoding="utf-8")
    n.stage(6, "ok", hpath.name)

    log(f"\n══ verdict: {verdict}  "
        f"(✔{tally['pass']}  ✘{tally['fail']}  !{tally['warn']}  –{tally['skip']})")
    if baselined:
        log(f"   {len(baselined)} known failures: {', '.join(baselined)}")
    if new_failures:
        log(f"   {len(new_failures)} new failures: {', '.join(new_failures)}")
    log(f"   {jpath}")
    log(f"   {hpath}")

    # CI passes a URL template so the channel links the published report, not a path on a
    # runner that is about to be destroyed.
    url = report_url.replace("{stamp}", stamp) if report_url else None
    extra = []
    if baselined:
        extra.append(f"already known: {', '.join(baselined)}")
    if stale:
        extra.append(f"stale baseline (delete): {', '.join(stale)}")
    n.finish(verdict, tally, url,
             failures=[r["id"] for r in results if r["status"] == "fail"], extra=extra)

    # Exit non-zero only for a hard failure nobody has accounted for. With no baseline
    # loaded this is exactly the old behaviour: every hard failure is a new one.
    return run_doc, 1 if new_failures else 0


def main():
    ap = argparse.ArgumentParser(description="Phorvex End-to-End pipeline")
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--mode", choices=["observe", "attack"], default="observe")
    ap.add_argument("--target", default=None)
    ap.add_argument("--out", default=str(ROOT / "runs"))
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

    cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    if a.list_targets:
        for tg in cfg["targets"]:
            print(f"{tg['name']:20s} ns={tg['namespace']:18s} kind={tg['kind']}")
        return 0
    if a.mode == "attack" and not a.target:
        ap.error("--mode attack requires --target (list them with --list-targets)")

    baseline = None
    if a.baseline:
        # A missing or malformed baseline is fatal rather than ignored: silently falling
        # back to "no known failures" would turn a typo in a CI path into a red build that
        # looks like a real regression.
        baseline = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
        n_known = len((baseline.get("checks") or {}))
        log(f"● baseline: {a.baseline} ({n_known} known checks)")

    n = Notifier(enabled=a.telegram, log=lambda m: log(m, 1))
    if a.telegram and not n.enabled:
        log("warning: --telegram was passed but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID are unset "
            "— notifications are off")
    try:
        _, rc = run(cfg, a.mode, a.target, Path(a.out), a.stream_seconds,
                    notifier=n, run_label=a.run_label, report_url=a.report_url,
                    baseline=baseline)
        return rc
    except TransportError as e:
        log(f"transport error: {e}")
        # A transport failure kills the run before any stage reports, so the board would
        # sit on "pending" forever. Say what happened instead of leaving it hanging.
        n.alert(f"❌ <b>Phorvex E2E</b> — transport error\n<code>{e}</code>"
                + (f"\n{a.run_label}" if a.run_label else ""))
        return 2


if __name__ == "__main__":
    sys.exit(main())
