#!/usr/bin/env python3
"""Serial/parallel live-attack benchmark over ONE shared Console port-forward, so
parallel fires actually run concurrently (independent per-fire port-forwards collide).
Usage: benchmark_runner.py <serial|parallel> <out.jsonl>"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import concurrent.futures as cf

MODE, OUT = sys.argv[1], sys.argv[2]
NS_CONSOLE = "phorvex-system"
PORT = 18200
TERMINAL = ("done", "partial", "failed")

ATTACKS = [
    ("vllm", "kvcache", "/api/vllm/attack", 240),
    ("voice", "ai2-agent-memory-contamination", "/api/voice/live/fire", 300),
    ("litellm", "ai2-query-extraction", "/api/litellm/live/fire", 300),
    ("crm", "foothold", "/api/workload/attack", 60),
    ("mcp", "foothold", "/api/workload/attack", 90),
    ("nats", "foothold", "/api/workload/attack", 90),
]


def token():
    return subprocess.run(["kubectl", "create", "token", "phorvex-phorvex-console-e2e",
                           "-n", NS_CONSOLE, "--audience", "phorvex-console", "--duration", "90m"],
                          check=True, capture_output=True, text=True).stdout.strip()


def port_up():
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", PORT), 2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def http(method, path, tok, body=None, timeout=60):
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}", method=method,
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
        return 0, {}


def fire(item, tok, run_start):
    ns, attack, route, budget = item
    body = {"namespace": ns, "action": "foothold"} if route.endswith("/workload/attack") else \
        ({"action": attack} if route.endswith("/vllm/attack") else {"scenario": attack})
    t0 = time.time()
    code, resp = http("POST", route, tok, body)
    aid = resp.get("attackId", "")
    rec = {}
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
    return {
        "mode": MODE, "ns": ns, "attack": attack, "route": route, "budget": budget,
        "startOffsetSec": round(t0 - run_start, 2), "endOffsetSec": round(t1 - run_start, 2),
        "durationSec": round(t1 - t0, 2), "fireStatus": code, "firedResultId": aid,
        "status": rec.get("status"), "outcomeClass": rec.get("outcomeClass"),
        "outcome": rec.get("outcome"), "phorvexAction": rec.get("phorvexAction"),
        "actuated": rec.get("actuated"),
        "fireVerdict": resp.get("verdict") or ("ok" if resp.get("ok") else resp.get("error", "")),
        "hasLiveRecord": rec != {},
    }


def main():
    pf = subprocess.Popen(["kubectl", "-n", NS_CONSOLE, "port-forward",
                           "deploy/phorvex-phorvex-console", f"{PORT}:8090"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not port_up():
            raise SystemExit("console port-forward did not come up")
        tok = token()
        run_start = time.time()
        if MODE == "serial":
            results = [fire(it, tok, run_start) for it in ATTACKS]
        else:
            with cf.ThreadPoolExecutor(max_workers=len(ATTACKS)) as ex:
                results = [f.result() for f in cf.as_completed(
                    [ex.submit(fire, it, tok, run_start) for it in ATTACKS])]
        wall = round(time.time() - run_start, 2)
    finally:
        pf.terminate()
    results.sort(key=lambda r: r["startOffsetSec"])
    with open(OUT, "w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
        fh.write(json.dumps({"mode": MODE, "summary": True, "wallClockSec": wall, "attacks": len(results)}) + "\n")
    print(f"{MODE} done: wall={wall}s attacks={len(results)} -> {OUT}")


if __name__ == "__main__":
    main()
