#!/usr/bin/env python3
"""Full live-attack benchmark over ONE shared Console port-forward.
serial  = all attacks one at a time, in order.
parallel= apps run concurrently; attacks within one app stay serial (Console 409s
          same-app concurrency). Captures the full exact result record per attack.
Usage: benchmark_runner.py <serial|parallel> <out.jsonl>"""
import json, socket, subprocess, sys, time, urllib.error, urllib.request
import concurrent.futures as cf
from collections import OrderedDict

MODE, OUT = sys.argv[1], sys.argv[2]
NS_CONSOLE, PORT = "phorvex-system", 18210
PF = None
TERMINAL = ("done", "partial", "failed")

# The full armed set (one line per attack). budgets bound polling; terminal breaks early.
ATTACKS = [
    ("vllm", "kvcache", "/api/vllm/attack", 240),
    ("vllm", "poison", "/api/vllm/attack", 240),
    ("vllm", "endpoint-rotate", "/api/vllm/attack", 240),
    ("vllm", "model-shard-replace", "/api/vllm/attack", 240),
    ("vllm", "warm-swap", "/api/vllm/attack", 240),
    ("vllm", "request-drain", "/api/vllm/attack", 300),
    ("vllm", "guardrail-rotate", "/api/vllm/attack", 660),
    ("vllm", "endpoint-lease-revoke", "/api/vllm/attack", 660),
    ("vllm", "foothold", "/api/workload/attack", 90),
    ("voice", "ai2-agent-memory-contamination", "/api/voice/live/fire", 300),
    ("voice", "ai2-mcp-tool-poisoning", "/api/voice/mcp/live/fire", 300),
    ("voice", "ai2-agent-excessive-agency", "/api/voice/agency/live/fire", 300),
    ("voice", "ai2-system-prompt-leakage", "/api/voice/output/live/fire", 300),
    ("voice", "foothold", "/api/workload/attack", 90),
    ("litellm", "ai2-unbounded-consumption", "/api/litellm/live/fire", 360),
    ("litellm", "ai2-query-extraction", "/api/litellm/live/fire", 360),
    ("litellm", "foothold", "/api/workload/attack", 90),
    ("mcp", "foothold", "/api/workload/attack", 90),
    ("nats", "foothold", "/api/workload/attack", 90),
    ("document-store", "foothold", "/api/workload/attack", 90),
]
EXPECTED = {"kvcache": "kv-reset", "poison": "adapter-rotate", "endpoint-rotate": "endpoint-rotate",
            "model-shard-replace": "model-shard-replace", "warm-swap": "warm-swap", "request-drain": "request-drain",
            "guardrail-rotate": "guardrail-rotate", "endpoint-lease-revoke": "endpoint-lease-revoke",
            "ai2-agent-memory-contamination": "voice-memory-note-revoke", "ai2-mcp-tool-poisoning": "voice-mcp-tool-pin",
            "ai2-agent-excessive-agency": "voice-refund-pair-deny", "ai2-system-prompt-leakage": "voice-output-policy-activate",
            "ai2-unbounded-consumption": "litellm-client-revoke", "ai2-query-extraction": "litellm-client-revoke"}


def token():
    return subprocess.run(["kubectl", "create", "token", "phorvex-phorvex-console-e2e", "-n", NS_CONSOLE,
                           "--audience", "phorvex-console", "--duration", "180m"], check=True,
                          capture_output=True, text=True).stdout.strip()


def port_up():
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", PORT), 2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def ensure_pf():
    """(Re)start the Console port-forward if the local port is not connectable."""
    global PF
    try:
        with socket.create_connection(("127.0.0.1", PORT), 2):
            return True
    except OSError:
        pass
    if PF is not None:
        try:
            PF.terminate()
        except Exception:
            pass
    PF = subprocess.Popen(["kubectl", "-n", NS_CONSOLE, "port-forward", "deploy/phorvex-phorvex-console",
                           f"{PORT}:8090"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return port_up()


def http(method, path, tok, body=None, timeout=60):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + tok, "X-Phorvex-Lens": "operator",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        ensure_pf()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except Exception:
            return 0, {}


def expected_for(ns, attack):
    if attack == "foothold":
        return "quarantine" if ns == "nats" else "rotate"
    return EXPECTED.get(attack, "")


def fire(item, tok, run_start):
    ns, attack, route, budget = item
    body = {"namespace": ns, "action": "foothold"} if route.endswith("/workload/attack") else \
        ({"action": attack} if route.endswith("/vllm/attack") else {"scenario": attack})
    t0 = time.time()
    code, resp = http("POST", route, tok, body)
    aid, rec = resp.get("attackId", ""), {}
    if aid:
        deadline = t0 + budget
        while time.time() < deadline:
            time.sleep(15)
            _, page = http("GET", f"/api/attack-results?includeObservations=true&id={aid}", tok)
            r = next((x for x in (page.get("attacks") or []) if x.get("id") == aid), None)
            if r:
                rec = r
                if r.get("status") in TERMINAL:
                    break
    t1 = time.time()
    de = (rec.get("decisionEvidence") or {}) if rec else {}
    return {"mode": MODE, "ns": ns, "attack": attack, "route": route, "budget": budget,
            "expectedActuator": expected_for(ns, attack),
            "startOffsetSec": round(t0 - run_start, 2), "endOffsetSec": round(t1 - run_start, 2),
            "durationSec": round(t1 - t0, 2), "fireStatus": code, "firedResultId": aid,
            "status": rec.get("status") if rec else None, "outcomeClass": rec.get("outcomeClass") if rec else None,
            "outcome": rec.get("outcome") if rec else None, "phorvexAction": rec.get("phorvexAction") if rec else None,
            "actuated": rec.get("actuated") if rec else None,
            "decisionAction": de.get("action"), "decisionReason": (de.get("reason") or "")[:240],
            "fireVerdict": resp.get("verdict") or ("ok" if resp.get("ok") else resp.get("error", "")),
            "hasLiveRecord": bool(rec), "record": rec}


def main():
    if not ensure_pf():
        raise SystemExit("console port-forward did not come up")
    try:
        tok = token()
        run_start = time.time()
        if MODE == "serial":
            results = [fire(it, tok, run_start) for it in ATTACKS]
        else:
            groups = OrderedDict()
            for it in ATTACKS:
                groups.setdefault(it[0], []).append(it)

            def run_group(items):
                return [fire(it, tok, run_start) for it in items]
            results = []
            with cf.ThreadPoolExecutor(max_workers=len(groups)) as ex:
                for f in cf.as_completed([ex.submit(run_group, v) for v in groups.values()]):
                    results.extend(f.result())
        wall = round(time.time() - run_start, 2)
    finally:
        if PF is not None:
            PF.terminate()
    results.sort(key=lambda r: r["startOffsetSec"])
    with open(OUT, "w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
        fh.write(json.dumps({"mode": MODE, "summary": True, "wallClockSec": wall, "attacks": len(results)}) + "\n")
    print(f"{MODE} done: wall={wall}s attacks={len(results)} -> {OUT}")


if __name__ == "__main__":
    main()
