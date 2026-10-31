"""Watch a pinned stage fixture, or issue one explicitly labelled calibration.

Run from the repository root: python -m benchmark.stage.observe --help.
Watch collection is read-only. The separate `rotate` command performs one
UID-preconditioned Pod deletion against an isolated dryRun study fixture.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .evidence import EvidenceError, Journal, MAX_EVENT_BYTES, Reducer, STREAMS, SCOPE_SCHEMA, validate_scope, stage_namespace
from .normalize import atomic_json


class Kube:
    def __init__(self, context):
        if not context:
            raise EvidenceError("explicit Kubernetes context required")
        self.prefix = ["kubectl", "--context", context]

    def get(self, path):
        result = subprocess.run(self.prefix + ["get", "--raw", path, "--request-timeout=20s"],
                                capture_output=True, timeout=25)
        if result.returncode:
            raise EvidenceError("Kubernetes read failed: " + result.stderr.decode(errors="replace")[-600:])
        if len(result.stdout) > MAX_EVENT_BYTES:
            raise EvidenceError("Kubernetes response exceeds observation bound")
        return json.loads(result.stdout)

    def watch(self, path, resource_version, seconds):
        separator = "&" if "?" in path else "?"
        query = urllib.parse.urlencode({"watch": "true", "allowWatchBookmarks": "true", "resourceVersion": resource_version,
                                        "timeoutSeconds": str(seconds + 60)})
        # Do not let kubectl's get printer retry or relist a closed watch. Raw
        # watch termination is a gap and requires a new collection session.
        return subprocess.Popen(self.prefix + ["get", "--raw", path + separator + query, "--request-timeout=0"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def delete_uid(self, namespace, name, uid):
        # Kubectl proxy preserves the caller's configured authentication without
        # copying credentials. A real HTTP DELETE carries the UID precondition;
        # a same-name replacement can never be deleted by a stale calibration.
        proxy = subprocess.Popen(self.prefix + ["proxy", "--address=127.0.0.1", "--port=0", "--accept-hosts=^127\\.0\\.0\\.1$"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([proxy.stdout], [], [], 10)[0]:
                raise EvidenceError("Kubernetes local proxy did not become ready")
            line = proxy.stdout.readline(1000).decode()
            match = re.search(r"127\.0\.0\.1:(\d+)", line)
            if not match:
                raise EvidenceError("unexpected local proxy address")
            url = "http://127.0.0.1:" + match.group(1) + "/api/v1/namespaces/" + namespace + "/pods/" + name
            body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "gracePeriodSeconds": 30}
            request = urllib.request.Request(url, data=json.dumps(body).encode(), method="DELETE", headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=20) as response:
                    raw = response.read(MAX_EVENT_BYTES + 1)
                    status = response.status
            except urllib.error.HTTPError as error:
                raw, status = error.read(MAX_EVENT_BYTES + 1), error.code
            if len(raw) > MAX_EVENT_BYTES:
                raise EvidenceError("delete receipt exceeds bound")
            receipt = json.loads(raw)
            returned_uid = receipt.get("metadata", {}).get("uid") or receipt.get("details", {}).get("uid")
            acknowledged = 200 <= status < 300 and returned_uid == uid
            return {"http_status": status, "acknowledged": acknowledged, "returned_uid": returned_uid,
                    "response_kind": receipt.get("kind"), "reason": receipt.get("reason"),
                    "resource_version": receipt.get("metadata", {}).get("resourceVersion"),
                    "deletion_timestamp": receipt.get("metadata", {}).get("deletionTimestamp")}
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()


def resource_paths(scope):
    ns = scope["namespace"]
    labels = ",".join(k + "=" + v for k, v in sorted(scope["selector"].items()))
    def query(path, **kwargs):
        return path + "?" + urllib.parse.urlencode(kwargs)
    return {
        "deployment": query("/apis/apps/v1/namespaces/" + ns + "/deployments", fieldSelector="metadata.name=" + scope["deployment_name"]),
        "replicasets": query("/apis/apps/v1/namespaces/" + ns + "/replicasets", labelSelector=labels),
        "pods": query("/api/v1/namespaces/" + ns + "/pods", labelSelector=labels),
        "service": query("/api/v1/namespaces/" + ns + "/services", fieldSelector="metadata.name=" + scope["service_name"]),
        "endpointslices": query("/apis/discovery.k8s.io/v1/namespaces/" + ns + "/endpointslices", labelSelector="kubernetes.io/service-name=" + scope["service_name"]),
        "policy": query("/apis/phorvex.ai/v1alpha1/namespaces/" + ns + "/phorvexpolicies", fieldSelector="metadata.name=" + scope["policy_name"]),
    }


def discover(kube, namespace, policy_name, deployment_name, service_name, source, image_digest):
    if not stage_namespace(namespace):
        raise EvidenceError("stage namespace required before querying Kubernetes")
    policy = kube.get("/apis/phorvex.ai/v1alpha1/namespaces/" + namespace + "/phorvexpolicies/" + policy_name)
    deployment = kube.get("/apis/apps/v1/namespaces/" + namespace + "/deployments/" + deployment_name)
    service = kube.get("/api/v1/namespaces/" + namespace + "/services/" + service_name)
    scope = {"schema": SCOPE_SCHEMA, "repository": "PhorvexSecurity/operator-refactored", "source_revision": source,
             "image_digest": image_digest, "context": kube.prefix[-1], "namespace": namespace, "policy_name": policy_name,
             "policy_uid": policy["metadata"]["uid"], "deployment_name": deployment_name,
             "workload_uid": deployment["metadata"]["uid"], "service_name": service_name, "service_uid": service["metadata"]["uid"],
             "selector": deployment["spec"]["selector"]["matchLabels"],
             "measurement": "watch-observed-service-ready-backends", "mode": "isolated-calibration"}
    return validate_scope(scope)


def collect(journal, seconds, stop=None):
    if not 1 <= seconds <= 366 * 86400:
        raise EvidenceError("one collection session must be 1 second..366 days; restarts remain explicit gaps")
    stop = stop or threading.Event()
    kube = Kube(journal.scope["context"])
    session = uuid.uuid4().hex
    journal.append("session", {"id": session, "clock": "collector-serialized-observation-utc", "checkpoint_seconds": 10})
    paths, processes, threads, errors = resource_paths(journal.scope), [], [], []
    api_activity = {}
    def watch(stream, process):
        try:
            while not stop.is_set():
                raw = process.stdout.readline(MAX_EVENT_BYTES + 1)
                if not raw:
                    if not stop.is_set():
                        raise EvidenceError("WATCH_DISCONNECTED:" + stream)
                    break
                if len(raw) > MAX_EVENT_BYTES:
                    raise EvidenceError("WATCH_EVENT_TOO_LARGE:" + stream)
                event = json.loads(raw)
                if event.get("type") == "ERROR":
                    raise EvidenceError("WATCH_API_ERROR:" + stream + ":" + str(event.get("object", {}).get("code")))
                rv = event.get("object", {}).get("metadata", {}).get("resourceVersion")
                if not rv:
                    raise EvidenceError("WATCH_RESOURCE_VERSION_MISSING:" + stream)
                journal.append("watch", {"session": session, "stream": stream, "resource_version": rv,
                                          "type": event["type"], "object": event["object"]})
                api_activity[stream] = time.monotonic()
        except BaseException as exc:
            errors.append(str(exc))
            stop.set()
            try:
                journal.append("gap", {"session": session, "reason": str(exc)})
            except BaseException:
                pass  # No successful append means no later watermark/coverage.
    try:
        for stream, path in paths.items():
            initial = kube.get(path)
            rv = initial.get("metadata", {}).get("resourceVersion")
            if not rv:
                raise EvidenceError("LIST_RESOURCE_VERSION_MISSING:" + stream)
            journal.append("list", {"session": session, "stream": stream, "resource_version": rv, "items": initial["items"]})
            api_activity[stream] = time.monotonic()
            process = kube.watch(path, rv, seconds)
            processes.append(process)
            thread = threading.Thread(target=watch, args=(stream, process), daemon=True)
            threads.append(thread)
            thread.start()
        deadline = time.monotonic() + seconds
        next_checkpoint = time.monotonic()
        while not stop.wait(1) and time.monotonic() < deadline:
            if time.monotonic() >= next_checkpoint:
                journal.append("checkpoint", {"session": session, "watch_processes_alive": all(p.poll() is None for p in processes)})
                next_checkpoint = time.monotonic() + 10
            if any(p.poll() is not None for p in processes):
                raise EvidenceError("WATCH_PROCESS_EXITED")
            if any(time.monotonic() - last > 180 for last in api_activity.values()):
                raise EvidenceError("WATCH_API_WATERMARK_STALE: no event/bookmark for 180 seconds")
    except BaseException as exc:
        errors.append(str(exc))
        journal.append("gap", {"session": session, "reason": str(exc)})
        raise
    finally:
        stop.set()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for thread in threads:
            thread.join(timeout=5)
        journal.append("stopped", {"session": session, "reason": errors[0] if errors else "COLLECTION_SESSION_ENDED"})
    if errors:
        raise EvidenceError(errors[0])


def calibration(journal, pod_name, reservation, deadline_seconds, kube=None):
    if not 1 <= deadline_seconds <= 600:
        raise EvidenceError("bounded calibration deadline required")
    reducer = Reducer(journal.scope)
    last_record = None
    for event in journal.records():
        reducer.apply(event)
        last_record = event
    if last_record is None or last_record["kind"] in ("gap", "stopped") or time.time() - last_record["at"] > 15:
        raise EvidenceError("a live observer must be recording before calibration")
    if len(reducer.watermarks) != len(STREAMS) or time.time() - min(reducer.watermarks.values()) > 180:
        raise EvidenceError("API watch watermarks are stale; calibration cannot proceed")
    kube = kube or Kube(journal.scope["context"])
    # Refresh all scope objects independently before touching a Pod. This does
    # not rewrite observer history or bridge any observation gap.
    fresh = Reducer(journal.scope)
    now = time.time()
    fresh.apply({"at": now, "kind": "session", "data": {"id": "preflight"}})
    for stream, path in resource_paths(journal.scope).items():
        initial = kube.get(path)
        fresh.apply({"at": time.time(), "kind": "list", "data": {"session": "preflight", "stream": stream, "items": initial["items"]}})
    if fresh.coverage_from is None or len(fresh.ready) < fresh.replicas:
        raise EvidenceError("calibration requires a fully ready isolated fixture")
    pods = [p for p in fresh.last_view["pods"].values() if p["metadata"]["name"] == pod_name]
    if len(pods) != 1:
        raise EvidenceError("calibration Pod name is absent or ambiguous")
    pod_uid = pods[0]["metadata"]["uid"]
    intent = {"id": "calibration-" + uuid.uuid4().hex, "origin": "controlled-stage-calibration", "action": "rotate",
              "pod_name": pod_name, "pod_uid": pod_uid, "workload_uid": journal.scope["workload_uid"],
              "policy_uid": journal.scope["policy_uid"], "reservation": reservation, "deadline": time.time() + deadline_seconds}
    # Validate against the actual observer state, not just the fresh preflight.
    reducer.at = time.time()
    reducer._intent(intent)
    journal.append("intent", intent)
    try:
        receipt = kube.delete_uid(journal.scope["namespace"], pod_name, pod_uid)
    except BaseException as exc:
        receipt = {"acknowledged": False, "reason": type(exc).__name__}
        journal.append("receipt", {**receipt, "id": intent["id"], "pod_uid": pod_uid, "operation": "uid-preconditioned-delete"})
        raise
    receipt.update(id=intent["id"], pod_uid=pod_uid, operation="uid-preconditioned-delete")
    journal.append("receipt", receipt)
    if receipt["acknowledged"] is not True:
        raise EvidenceError("UID-preconditioned deletion was not acknowledged; retained failed receipt")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discover_parser = commands.add_parser("discover", help="read exact fixture UIDs into a pinned scope file")
    for name in ("context", "namespace", "policy", "deployment", "service", "source", "image-digest", "output"):
        discover_parser.add_argument("--" + name, required=True)
    watch_parser = commands.add_parser("watch", help="read-only bounded collection; retain each restart as a gap")
    watch_parser.add_argument("--scope", required=True)
    watch_parser.add_argument("--journal", required=True)
    watch_parser.add_argument("--seconds", type=int, required=True)
    watch_parser.add_argument("--max-bytes", type=int, help="immutable journal capacity on creation; default 256 MiB, range 1 MiB..2 GiB")
    rotate_parser = commands.add_parser("rotate", help="perform ONE explicit UID-preconditioned stage calibration deletion")
    rotate_parser.add_argument("--journal", required=True)
    rotate_parser.add_argument("--pod", required=True)
    rotate_parser.add_argument("--reservation", type=float, required=True)
    rotate_parser.add_argument("--deadline-seconds", type=int, required=True)
    status_parser = commands.add_parser("status", help="inspect journal provenance and current observation gaps")
    status_parser.add_argument("--journal", required=True)
    args = parser.parse_args()
    if args.command == "discover":
        scope = discover(Kube(args.context), args.namespace, args.policy, args.deployment, args.service, args.source, args.image_digest)
        atomic_json(args.output, scope)
        print(json.dumps(scope))
    elif args.command == "watch":
        if args.max_bytes is not None and not 1 << 20 <= args.max_bytes <= 2 << 30:
            raise EvidenceError("journal capacity must be 1 MiB..2 GiB")
        journal = Journal(args.journal, json.loads(Path(args.scope).read_text()), max_bytes=args.max_bytes)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        collect(journal, args.seconds, stop)
    elif args.command == "rotate":
        print(json.dumps(calibration(Journal(args.journal), args.pod, args.reservation, args.deadline_seconds)))
    else:
        journal = Journal(args.journal)
        reducer = Reducer(journal.scope)
        for event in journal.records():
            reducer.apply(event)
        print(json.dumps(reducer.snapshot(reducer.at), sort_keys=True))


if __name__ == "__main__":
    main()
