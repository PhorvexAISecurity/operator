#!/usr/bin/env python3
"""Foreground staging console driver. No live operation runs without fire/cleanup.

Rotate is a proactive-hygiene class: replacing the exact Pod clears a simulated
pod-resident foothold. This does not establish natural detection or exploit blocking.
The console provisions, signals, observes real brain actuation, and tears down.
"""
import argparse
import contextlib
import json
import os
import re
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NAMESPACE = "phorvex-staging"
CONTEXT = "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"
GATEWAY = "phorvex-gw"
AUDIENCE = "phorvex-staging-console"
SERVICE_ACCOUNT = "staging-phorvex-console-e2e"
SERVICE = "staging-phorvex-console"
CASES = {
    "newstack:voice-rotate": "rotate: proactive hygiene; pod-resident marker cleared by replacement",
    "newstack:litellm-rotate": "rotate: proactive hygiene; pod-resident marker cleared by replacement",
    "newstack:crm-refund-revoke": "cross-record refund lands, then real deny-guard revocation; legitimate refund control",
}
COMPONENTS = ("staging-phorvex", "staging-brain", "staging-sensor", "staging-actuator", SERVICE, "staging-attacks")
CAVEAT = "Rotate = proactive-hygiene class: clears a simulated pod-resident foothold by replacing the Pod; no natural-detection or exploit-prevention claim."


def kubectl(*args, timeout=30):
    remote = shlex.join(["kubectl", "--context=" + CONTEXT, "-n", NAMESPACE, *args])
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", GATEWAY, remote],
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or "kubectl failed")
    return p.stdout


def kube_json(*args):
    return json.loads(kubectl(*args, "-o", "json"))


def deployment_gates(doc):
    deployments = {d["metadata"]["name"]: d for d in doc.get("items", [])}
    issues = []
    for name in COMPONENTS:
        d = deployments.get(name)
        if not d:
            issues.append(name + " is absent (merge/release/Argo deployment pending)")
            continue
        s = d.get("status", {})
        desired = d.get("spec", {}).get("replicas", 1)
        if (desired != 1 or s.get("readyReplicas", 0) != desired or s.get("updatedReplicas", 0) != desired
                or s.get("observedGeneration", 0) < d["metadata"].get("generation", 1)):
            issues.append(name + " has not completed its one-replica rollout")
    for name in ("staging-phorvex", "staging-sensor", "staging-actuator"):
        if name not in deployments:
            continue
        c = deployments[name]["spec"]["template"]["spec"]["containers"][0]
        args = c.get("args", [])
        env = {v["name"]: v.get("value") for v in c.get("env", [])}
        if "--policy-namespaces=phorvex-staging" not in args:
            issues.append(name + " lacks the exact staging policy scope")
        if "--trusted-detectors=phorvex-staging/staging-attacks" not in args:
            issues.append(name + " lacks the staging attacks detector trust")
        if env.get("PHORVEX_INJECTOR_IDENTITY") != "phorvex-staging/staging-attacks":
            issues.append(name + " has the wrong injector identity")
        if env.get("PHORVEX_CRM_REFUND_NAMESPACE") != NAMESPACE:
            issues.append(name + " lacks the explicit staging refund authority")
        if name != "staging-sensor" and env.get("PHORVEX_ACTUATOR") != "native":
            issues.append(name + " lacks native enactment")
        if name == "staging-phorvex" and "--global-kill-switch=true" in args:
            issues.append("manager global kill switch is enabled")
    for name in (SERVICE, "staging-attacks"):
        if name not in deployments:
            continue
        env = {v["name"]: v.get("value") for v in deployments[name]["spec"]["template"]["spec"]["containers"][0].get("env", [])}
        if env.get("PHORVEX_NEWSTACK_LOOPS_ENABLED") != "true":
            issues.append(name + " lacks the staging loop opt-in")
    return issues


def snapshot():
    return kube_json("get", "deployments")


def print_json(value):
    print(json.dumps(value, indent=2, sort_keys=True), flush=True)


@contextlib.contextmanager
def console_connection(token):
    # SSH and kubectl port-forward are children owned by this invocation, with a
    # bounded startup and explicit termination. Nothing is detached or left running.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        local_port = probe.getsockname()[1]
    remote_port = local_port
    remote = shlex.join(["timeout", "--signal=TERM", "--kill-after=5s", "720s",
                         "kubectl", "--context=" + CONTEXT, "-n", NAMESPACE, "port-forward", "service/" + SERVICE, f"{remote_port}:80", "--address=127.0.0.1"])
    cmd = ["ssh", "-tt", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ExitOnForwardFailure=yes",
           "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", GATEWAY, remote]
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as child:
        try:
            base = f"http://127.0.0.1:{local_port}"
            deadline = time.monotonic() + 25
            while True:
                if child.poll() is not None:
                    raise RuntimeError("console tunnel failed: " + child.stderr.read().strip())
                try:
                    with urllib.request.urlopen(base + "/api/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("console tunnel did not become healthy within 25s")
                    time.sleep(0.25)
            yield base, token
        finally:
            # A remote PTY makes Ctrl-C/HUP reach the remote command. timeout is
            # an independent upper bound even if the SSH connection is lost.
            if child.poll() is None:
                try:
                    child.stdin.write("\x03")
                    child.stdin.flush()
                    child.wait(timeout=5)
                except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)


def api(connection, route, payload=None, timeout=35):
    base, token = connection
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(base + route, data=data,
                                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read(32768).decode(errors="replace")
        raise RuntimeError(f"console HTTP {exc.code}: {body}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("console returned an invalid response")
    return result


def token_for(args, mint=False):
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        token = os.environ.get("PHVX_NEWSTACK_TOKEN", "").strip()
    if not token and mint:
        # This TokenRequest is only reached for explicit fire/cleanup after the
        # read-only deployment gates. The token is short-lived and never saved.
        token = kubectl("create", "token", SERVICE_ACCOUNT, "--audience=" + AUDIENCE, "--duration=10m").strip()
    return token


def exact_run(doc, case_id):
    if (doc.get("schema") != "newstack-run-v1" or doc.get("caseId") != case_id
            or doc.get("namespace") != NAMESPACE or not re.fullmatch(r"ns-[0-9a-f]{32}", str(doc.get("runId", "")))):
        raise RuntimeError("console response lacks the exact run identity/schema")
    return doc


def cleanup_complete(doc):
    return doc.get("cleanupComplete") is True and doc.get("postflightClean") is not False


def validate_catalog(doc, case_id):
    if (doc.get("schema") != "newstack-catalog-v1" or doc.get("namespace") != NAMESPACE
            or doc.get("enabled") is not True or doc.get("fireEndpoint") != "/api/newstack/fire"
            or not any(item.get("id") == case_id for item in doc.get("items", []))):
        raise RuntimeError("console catalogue schema, staging opt-in or fixed case is unavailable")


def emit_result(result, args):
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print_json(result)


def cleanup_deployment_gates(doc):
    # Recovery does not depend on the brain/sensor/actuator being healthy.
    issues = []
    for name in (SERVICE, "staging-attacks"):
        deployment = next((d for d in doc.get("items", []) if d["metadata"]["name"] == name), None)
        if not deployment or deployment.get("status", {}).get("readyReplicas", 0) < 1:
            issues.append(name + " is unavailable for console cleanup")
    return issues


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", help="existing short-lived console bearer token; check never mints a token")
    parser.add_argument("--output", type=Path, help="save full console evidence JSON locally")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="offline case catalogue")
    sub.add_parser("targets", help="read-only staging fixture/stack inventory")
    check = sub.add_parser("check", help="read-only deployment preflight; optional console admission check with existing token")
    check.add_argument("case", nargs="?", choices=CASES, default="newstack:voice-rotate")
    fire = sub.add_parser("fire", help="provision -> console fire -> real brain verdict -> teardown -> postflight")
    fire.add_argument("case", choices=CASES)
    cleanup = sub.add_parser("cleanup", help="console reconciles only owned interrupted fixture runs")
    cleanup.add_argument("case", nargs="?", choices=CASES)
    args = parser.parse_args(argv)
    if args.command == "list":
        emit_result({"namespace": NAMESPACE, "cases": CASES, "caveat": CAVEAT}, args)
        return 0
    before = snapshot()
    if args.command == "targets":
        fixtures = kube_json("get", "pods,services,configmaps,phorvexpolicies,poddisruptionbudgets", "-l", "phorvex.ai/newstack-run")
        emit_result({"namespace": NAMESPACE, "deployments": [{"name": d["metadata"]["name"], "status": d.get("status", {})} for d in before.get("items", [])],
                     "fixtures": fixtures, "caveat": CAVEAT}, args)
        return 0
    issues = cleanup_deployment_gates(before) if args.command == "cleanup" else deployment_gates(before)
    if args.command == "check":
        result = {"namespace": NAMESPACE, "caseId": args.case, "deploymentReady": not issues, "issues": issues, "caveat": CAVEAT}
        token = token_for(args)
        if not issues and token:
            try:
                with console_connection(token) as connection:
                    validate_catalog(api(connection, "/api/newstack/catalog"), args.case)
                    result["console"] = api(connection, "/api/newstack/check?" + urllib.parse.urlencode({"caseId": args.case}))
                    if result["console"].get("ok") is not True:
                        issues.append("console admission check failed")
            except Exception as exc:
                issues.append(str(exc))
        elif not token:
            result["console"] = "Not queried: supply --token-file or PHVX_NEWSTACK_TOKEN for a read-only authenticated check. fire/cleanup mint a short-lived token."
        emit_result(result, args)
        return 2 if issues else 0
    if issues:
        emit_result({"verdict": "BLOCKED_ON_DEPLOY", "issues": issues, "caveat": CAVEAT}, args)
        return 2
    result = {"verdict": "ERROR", "caseId": args.case, "namespace": NAMESPACE, "caveat": CAVEAT}
    cleanup_errors = []
    try:
        with console_connection(token_for(args, mint=True)) as connection:
            if args.command == "cleanup":
                case_ids = [args.case] if args.case else []
                if not case_ids:
                    locks = kube_json("get", "configmaps", "--field-selector=metadata.name=phorvex-newstack-loop-lock").get("items", [])
                    case_ids = [locks[0].get("data", {}).get("caseId")] if locks else list(CASES)
                    if any(case_id not in CASES for case_id in case_ids):
                        raise RuntimeError("shared lane has an unknown case; refusing cleanup")
                responses = []
                result = {"cleanup": responses, "verdict": "CLEANUP_REQUIRED", "caveat": CAVEAT}
                for case_id in case_ids:
                    responses.append(api(connection, "/api/newstack/cleanup", {"caseId": case_id}, timeout=125))
                result["verdict"] = "CLEAN" if all(cleanup_complete(response) for response in responses) else "CLEANUP_REQUIRED"
            else:
                print(CAVEAT, file=sys.stderr, flush=True)
                dispatched = False
                try:
                    validate_catalog(api(connection, "/api/newstack/catalog"), args.case)
                    admission = api(connection, "/api/newstack/check?" + urllib.parse.urlencode({"caseId": args.case}))
                    if admission.get("ok") is not True:
                        result = {"verdict": "BLOCKED", "admission": admission, "caseId": args.case}
                    else:
                        dispatched = True
                        result = exact_run(api(connection, "/api/newstack/fire", {"caseId": args.case}, timeout=360), args.case)
                except (Exception, KeyboardInterrupt) as exc:
                    result["clientError"] = str(exc) or "interrupted"
                finally:
                    if dispatched:
                        try:
                            response = api(connection, "/api/newstack/cleanup", {"caseId": args.case}, timeout=125)
                            result["cleanupReconcile"] = response
                            if not cleanup_complete(response):
                                cleanup_errors.append(response)
                        except (Exception, KeyboardInterrupt) as exc:
                            cleanup_errors.append(str(exc) or "cleanup interrupted")
    except (Exception, KeyboardInterrupt) as exc:
        result["clientError"] = str(exc) or "interrupted"
    try:
        after = snapshot()
        post_issues = cleanup_deployment_gates(after) if args.command == "cleanup" else deployment_gates(after)
    except (Exception, KeyboardInterrupt) as exc:
        post_issues = [str(exc) or "postflight interrupted"]
    result["clientPostflightIssues"] = post_issues
    result["clientCleanupErrors"] = cleanup_errors
    result["caveat"] = CAVEAT
    emit_result(result, args)
    if cleanup_errors or post_issues or result.get("clientError"):
        return 2
    if args.command == "cleanup":
        return 0 if result.get("verdict") == "CLEAN" else 2
    # Only the exact console result can supply DEFENDED; the client also gates
    # its exit code on complete teardown and postflight.
    return 0 if result.get("verdict") == "DEFENDED" and result.get("cleanupComplete") is True and result.get("postflightClean") is True else 1


def interrupted(signum, _frame):
    raise KeyboardInterrupt("signal " + str(signum))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print_json({"verdict": "ERROR", "error": str(exc), "caveat": CAVEAT})
        sys.exit(2)
