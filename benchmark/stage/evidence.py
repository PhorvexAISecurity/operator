"""Durable, read-only endpoint-watch evidence and an isolated calibration reducer.

The clock is the observer's receive clock. These intervals describe observed
Service backend readiness, not application availability or server event time.
Only an explicitly isolated dryRun fixture permits a complete calibration ledger.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

SCHEMA = "phorvex-stage.observation.v1"
SCOPE_SCHEMA = "phorvex-stage.scope.v1"
STREAMS = ("deployment", "replicasets", "pods", "service", "endpointslices", "policy")
MAX_EVENT_BYTES = 4 << 20
MAX_JOURNAL_BYTES = 256 << 20


class EvidenceError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def stage_namespace(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value)) and any(
        part in ("stage", "staging") for part in value.split("-"))


def validate_scope(scope):
    required = {"schema", "repository", "source_revision", "image_digest", "context", "namespace",
                "policy_name", "policy_uid", "deployment_name", "workload_uid", "service_name", "service_uid",
                "selector", "measurement", "mode"}
    if set(scope) != required:
        raise EvidenceError("scope fields differ: " + str(sorted(set(scope) ^ required)))
    if scope["schema"] != SCOPE_SCHEMA or scope["repository"] != "PhorvexSecurity/operator-refactored":
        raise EvidenceError("operator-refactored scope required")
    if not stage_namespace(scope["namespace"]):
        raise EvidenceError("stage namespace required")
    if not re.fullmatch(r"[0-9a-f]{40}", scope["source_revision"]):
        raise EvidenceError("full source revision required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", scope["image_digest"]):
        raise EvidenceError("running brain image digest required")
    for key in ("context", "policy_name", "policy_uid", "deployment_name", "workload_uid", "service_name", "service_uid"):
        if not isinstance(scope[key], str) or not scope[key] or len(scope[key]) > 300:
            raise EvidenceError("invalid scope " + key)
    if not isinstance(scope["selector"], dict) or not scope["selector"] or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in scope["selector"].items()):
        raise EvidenceError("explicit exact label selector required")
    if scope["measurement"] != "watch-observed-service-ready-backends" or scope["mode"] != "isolated-calibration":
        raise EvidenceError("only isolated calibration readiness measurement is supported")
    return scope


class Journal:
    """Append-only hash chain. A failed fsync/transaction never advances coverage.

    SQLite serializes the observer and optional calibration command. History is
    bounded by refusing new writes; it is never silently evicted into completeness.
    """
    def __init__(self, path, scope=None, max_bytes=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        os.chmod(self.path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, at REAL NOT NULL, body TEXT NOT NULL, hash TEXT NOT NULL)")
        self.db.commit()
        capacity = self.db.execute("SELECT value FROM meta WHERE key='max_bytes'").fetchone()
        self.max_bytes = int(capacity[0]) if capacity else (MAX_JOURNAL_BYTES if max_bytes is None else max_bytes)
        if max_bytes is not None and max_bytes != self.max_bytes:
            raise EvidenceError("journal capacity is immutable; archive and create a new explicit observation segment")
        if not capacity:
            self.db.execute("INSERT INTO meta VALUES ('max_bytes',?)", (str(self.max_bytes),))
            self.db.commit()
        found = self.db.execute("SELECT value FROM meta WHERE key='scope'").fetchone()
        if found:
            self.scope = validate_scope(json.loads(found[0]))
            if scope is not None and canonical(scope) != canonical(self.scope):
                raise EvidenceError("journal belongs to a different source/scope")
        elif scope is not None:
            self.scope = validate_scope(copy.deepcopy(scope))
            self.db.execute("INSERT INTO meta VALUES ('scope',?)", (canonical(self.scope),))
            self.db.commit()
        else:
            raise EvidenceError("new journal requires a verified scope")

    def append(self, kind, data, at=None):
        if at is not None and (not isinstance(at, (int, float)) or not math.isfinite(at) or at < 0):
            raise EvidenceError("invalid observation clock")
        body = canonical({"schema": SCHEMA, "kind": kind, "data": data})
        if len(body.encode()) > MAX_EVENT_BYTES:
            raise EvidenceError("event exceeds bounded journal input")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                # Allocate implicit observation time only after every writer is
                # serialized. Receive threads may otherwise acquire the DB in
                # the opposite order of timestamps assigned outside the lock.
                at = float(time.time() if at is None else at)
                size = self.db.execute("SELECT COALESCE(SUM(length(body)+128),0) FROM events").fetchone()[0]
                if size + len(body) + 128 > self.max_bytes:
                    raise EvidenceError("journal capacity exhausted; capture stopped, history not evicted")
                old = self.db.execute("SELECT seq,at,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                if old and at < old[1]:
                    raise EvidenceError("observation clock regressed; capture stopped")
                if kind == "intent":
                    # Serialize the one-open-move check with durable intent.
                    # Two simultaneous calibration clients cannot both act.
                    reducer = Reducer(self.scope)
                    for event in self.records():
                        reducer.apply(event)
                    reducer.at = at
                    reducer._intent(data)
                seq = old[0] + 1 if old else 1
                prev = old[2] if old else digest(self.scope)
                h = digest([prev, seq, at, json.loads(body)])
                self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (seq, at, body, h))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        return seq

    def records(self):
        previous = digest(self.scope)
        expected = 1
        last_at = -1
        for seq, at, body, h in self.db.execute("SELECT seq,at,body,hash FROM events ORDER BY seq"):
            event = json.loads(body)
            if seq != expected or at < last_at or h != digest([previous, seq, at, event]):
                raise EvidenceError("journal hash chain or clock is invalid")
            yield {"seq": seq, "at": at, "hash": h, **event}
            expected += 1
            previous, last_at = h, at

    def close(self):
        self.db.close()


def owner(obj, kind):
    refs = [r for r in obj.get("metadata", {}).get("ownerReferences", []) if r.get("controller") and r.get("kind") == kind]
    return refs[0] if len(refs) == 1 else None


class Reducer:
    """Deterministic as-of reducer; never reads a later receipt into an earlier tick."""
    def __init__(self, scope):
        self.scope = validate_scope(copy.deepcopy(scope))
        self.objects = {s: {} for s in STREAMS}
        self.watermarks = {}
        self.coverage_from = None
        self.reasons = ["WATCH_NOT_STARTED"]
        self.session = None
        self.at = 0
        self.seq = 0
        self.chain = None
        self.moves = {}
        self.known_pods = None
        self.ready = set()
        self.replicas = None
        self.class_name = "unknown"
        self.generation = None
        self.policy_generation = None
        self.last_view = None
        self.known_lineage = {}

    def gap(self, reason):
        self.coverage_from = None
        self.reasons = sorted(set(self.reasons + [reason]))
        for move in self.moves.values():
            if move["state"] == "open":
                move["state"] = "censored"
                move["reason"] = reason
                move["observed_at"] = self.at

    def apply(self, event):
        at, kind, data = event["at"], event["kind"], event["data"]
        if at < self.at:
            raise EvidenceError("reducer clock regressed")
        self.at, self.seq, self.chain = at, event.get("seq"), event.get("hash")
        if kind == "session":
            self.gap("WATCH_SESSION_STARTED")
            self.session = data["id"]
            self.objects = {s: {} for s in STREAMS}
            self.watermarks = {}
            self.known_pods = None
            self.generation = None
            self.known_lineage = {}
        elif kind in ("gap", "stopped"):
            self.gap(data.get("reason", "WATCH_STOPPED"))
            self.watermarks = {}
        elif kind in ("list", "watch"):
            stream = data["stream"]
            if stream not in STREAMS or data.get("session") != self.session:
                raise EvidenceError("stream/session mismatch")
            if kind == "list":
                self.objects[stream] = {o["metadata"]["uid"]: o for o in data["items"]}
            elif data["type"] in ("ADDED", "MODIFIED"):
                obj = data["object"]
                self.objects[stream][obj["metadata"]["uid"]] = obj
            elif data["type"] == "DELETED":
                self.objects[stream].pop(data["object"]["metadata"]["uid"], None)
            elif data["type"] != "BOOKMARK":
                self.gap("WATCH_EVENT_UNSUPPORTED")
                return
            self.watermarks[stream] = at
            self._evaluate()
        elif kind == "intent":
            self._intent(data)
        elif kind == "receipt":
            self._receipt(data)
        elif kind == "checkpoint":
            # Checkpoints attest only a live observer process, not a new API watermark.
            self._evaluate()
        else:
            raise EvidenceError("unknown journal record kind: " + kind)

    def _single(self, stream, name, uid):
        xs = [x for x in self.objects[stream].values() if x["metadata"].get("name") == name]
        if len(xs) != 1 or xs[0]["metadata"].get("uid") != uid:
            raise EvidenceError(stream.upper() + "_IDENTITY_CHANGED_OR_MISSING")
        return xs[0]

    def _view(self):
        s = self.scope
        if set(self.watermarks) != set(STREAMS):
            raise EvidenceError("WATCH_INITIALIZATION_INCOMPLETE")
        for items in self.objects.values():
            if any(x["metadata"].get("namespace") != s["namespace"] for x in items.values()):
                raise EvidenceError("CROSS_NAMESPACE_OBJECT")
        deployment = self._single("deployment", s["deployment_name"], s["workload_uid"])
        service = self._single("service", s["service_name"], s["service_uid"])
        policy = self._single("policy", s["policy_name"], s["policy_uid"])
        if policy.get("spec", {}).get("mode", "dryRun") != "dryRun":
            raise EvidenceError("ISOLATED_CALIBRATION_POLICY_IS_NOT_DRY_RUN")
        if policy["spec"].get("selector", {}).get("matchLabels") != s["selector"] or policy["spec"]["selector"].get("matchExpressions"):
            raise EvidenceError("POLICY_SELECTOR_CHANGED")
        if policy["spec"].get("budget", {}).get("maxMovesPerTick", 1) != 1:
            raise EvidenceError("ONLY_B_ONE_SUPPORTED")
        if deployment["spec"].get("selector", {}).get("matchLabels") != s["selector"] or service["spec"].get("selector") != s["selector"]:
            raise EvidenceError("WORKLOAD_OR_SERVICE_SELECTOR_CHANGED")
        generation = deployment["metadata"].get("generation")
        if self.generation is not None and generation != self.generation:
            raise EvidenceError("UNRELATED_WORKLOAD_ROLLOUT")
        n = deployment["spec"].get("replicas")
        if type(n) is not int or n < 2:
            raise EvidenceError("SPEC_REPLICAS_UNAVAILABLE_OR_SINGLETON")
        rss = {uid for uid, r in self.objects["replicasets"].items()
               if (owner(r, "Deployment") or {}).get("uid") == s["workload_uid"]}
        pods = {}
        for uid, p in self.objects["pods"].items():
            labels = p["metadata"].get("labels", {})
            if all(labels.get(k) == v for k, v in s["selector"].items()):
                if (owner(p, "ReplicaSet") or {}).get("uid") not in rss:
                    raise EvidenceError("POD_CONTROLLER_LINEAGE_UNKNOWN")
                pods[uid] = p
                self.known_lineage[uid] = p
        ready = set()
        for es in self.objects["endpointslices"].values():
            if es["metadata"].get("labels", {}).get("kubernetes.io/service-name") != s["service_name"]:
                raise EvidenceError("ENDPOINT_SERVICE_LABEL_MISMATCH")
            if not any(r.get("kind") == "Service" and r.get("uid") == s["service_uid"] for r in es["metadata"].get("ownerReferences", [])):
                raise EvidenceError("ENDPOINT_SERVICE_UID_MISMATCH")
            for ep in es.get("endpoints", []):
                ref = ep.get("targetRef", {})
                # Pod deletion may arrive before EndpointSlice removal. Retain
                # the already observed UID lineage; never resolve by name.
                known_pod = pods.get(ref.get("uid")) or self.known_lineage.get(ref.get("uid"))
                if ref.get("kind") != "Pod" or ref.get("namespace", s["namespace"]) != s["namespace"] or known_pod is None or (owner(known_pod, "ReplicaSet") or {}).get("uid") not in rss:
                    raise EvidenceError("ENDPOINT_POD_LINEAGE_UNKNOWN")
                conditions = ep.get("conditions", {})
                if type(conditions.get("ready")) is not bool:
                    raise EvidenceError("ENDPOINT_READINESS_UNKNOWN")
                if conditions["ready"] and conditions.get("serving", True) and not conditions.get("terminating", False):
                    ready.add(ref["uid"])
        containers = deployment["spec"].get("template", {}).get("spec", {}).get("containers", [])
        volumes = deployment["spec"].get("template", {}).get("spec", {}).get("volumes", [])
        gpu = any(any("gpu" in k for k in c.get("resources", {}).get(part, {})) for c in containers for part in ("requests", "limits"))
        cls = "gpu" if gpu else "stateful" if any("persistentVolumeClaim" in v for v in volumes) else "stateless"
        return {"pods": pods, "ready": ready, "replicas": n, "class": cls, "generation": generation,
                "policy_generation": policy["metadata"].get("generation")}

    def _evaluate(self):
        try:
            view = self._view()
        except EvidenceError as exc:
            self.gap(str(exc))
            return
        current = set(view["pods"])
        active = [m for m in self.moves.values() if m["state"] == "open"]
        if active and not (active[0]["before_pods"] - {active[0]["pod_uid"]}) <= view["ready"]:
            self.gap("UNRELATED_BASELINE_ENDPOINT_LOSS_DURING_ROTATION")
            active = []
        if self.known_pods is not None and current != self.known_pods:
            added, removed = current - self.known_pods, self.known_pods - current
            cleanup = {m["pod_uid"] for m in self.moves.values() if m["state"] == "settled"}
            if not added and removed <= cleanup:
                pass  # Late deletion of a proven completed move's old Pod.
            elif len(active) != 1:
                self.gap("UNATTRIBUTED_POD_MEMBERSHIP_CHANGE")
            else:
                move = active[0]
                other_old = move["before_pods"] - {move["pod_uid"]}
                replacements = current - move["before_pods"]
                if not other_old <= current or len(replacements) > 1 or removed - {move["pod_uid"]}:
                    self.gap("CONCURRENT_OR_AMBIGUOUS_ROTATION")
                elif replacements:
                    move["replacement_uid"] = next(iter(replacements))
        self.known_pods = current
        self.ready = set(view["ready"])
        self.replicas, self.class_name, self.generation = view["replicas"], view["class"], view["generation"]
        self.policy_generation = view["policy_generation"]
        self.last_view = view
        active = [m for m in self.moves.values() if m["state"] == "open"]
        deficit = max(0, self.replicas - len(self.ready))
        cleanup = {m["pod_uid"] for m in self.moves.values() if m["state"] == "settled"}
        uncertain = {uid for uid, pod in view["pods"].items() if uid not in self.ready or pod["metadata"].get("deletionTimestamp")}
        if not active and uncertain - cleanup:
            self.gap("UNATTRIBUTED_PENDING_OR_TERMINATING_POD")
            return
        if deficit and len(active) != 1:
            self.gap("UNATTRIBUTED_READY_ENDPOINT_DEFICIT")
            return
        if active:
            move = active[0]
            if deficit > 1:
                self.gap("MULTIPLE_ENDPOINT_DEFICIT_DURING_SINGLE_ROTATION")
                return
            if deficit and move["loss_start"] is None:
                move["loss_start"] = self.at
            if not deficit and move["loss_start"] is not None:
                move["intervals"].append({"endpoint_uid": self.scope["service_uid"] + ":" + move["pod_uid"],
                                          "start": move["loss_start"], "end": self.at})
                move["loss_start"] = None
            replacement = move.get("replacement_uid")
            if replacement in self.ready and move["pod_uid"] not in self.ready and move.get("ack_at") is not None and deficit == 0:
                move["state"] = "settled"
                move["observed_at"] = self.at
                move["duration"] = self.at - move["intent_at"]
                move["revision"] += 1
            elif self.at > move["deadline"]:
                move["overdue"] = True
        if self.coverage_from is None and not active and deficit == 0:
            self.coverage_from = self.at
            self.reasons = []

    def _intent(self, data):
        if self.coverage_from is None or self.last_view is None:
            raise EvidenceError("calibration requires initialized complete observation")
        if self.ready != set(self.last_view["pods"]) or len(self.ready) != self.replicas or any(
                p["metadata"].get("deletionTimestamp") for p in self.last_view["pods"].values()):
            raise EvidenceError("calibration requires exactly the desired stable ready Pods")
        if any(m["state"] == "open" for m in self.moves.values()):
            raise EvidenceError("a calibration move is already open")
        if data.get("id") in self.moves or data.get("action") != "rotate" or data.get("origin") != "controlled-stage-calibration":
            raise EvidenceError("invalid/duplicate calibration intent")
        if data.get("workload_uid") != self.scope["workload_uid"] or data.get("policy_uid") != self.scope["policy_uid"]:
            raise EvidenceError("calibration scope mismatch")
        pod = self.last_view["pods"].get(data.get("pod_uid"))
        if not pod or pod["metadata"]["name"] != data.get("pod_name") or data["pod_uid"] not in self.ready:
            raise EvidenceError("calibration target is not an exactly identified ready endpoint")
        reservation = data.get("reservation")
        deadline = data.get("deadline")
        if not isinstance(reservation, (float, int)) or not math.isfinite(reservation) or reservation < 0:
            raise EvidenceError("explicit study reservation required")
        if not isinstance(deadline, (float, int)) or not self.at < deadline <= self.at + 600:
            raise EvidenceError("calibration deadline must be within 600 seconds")
        self.moves[data["id"]] = {**data, "state": "open", "intent_at": self.at, "observed_at": self.at,
                                   "revision": 0, "before_pods": set(self.last_view["pods"]),
                                   "ack_at": None, "loss_start": None, "intervals": [], "overdue": False,
                                   "duration": None}

    def _receipt(self, data):
        move = self.moves.get(data.get("id"))
        if not move or data.get("pod_uid") != move["pod_uid"] or data.get("operation") != "uid-preconditioned-delete":
            raise EvidenceError("calibration receipt identity mismatch")
        if move.get("ack_at") is not None:
            raise EvidenceError("duplicate calibration acknowledgement")
        if data.get("acknowledged") is not True:
            self.gap("CALIBRATION_DELETE_NOT_ACKNOWLEDGED")
            return
        move["ack_at"] = self.at
        move["receipt_sha256"] = digest(data)
        self._evaluate()

    def snapshot(self, at, sealed_until=None, require_sealed=False):
        if at < self.at:
            raise EvidenceError("snapshot precedes applied evidence")
        result = {"at": at, "source_revision": self.scope["source_revision"], "policy_uid": self.scope["policy_uid"],
                  "policy_generation": self.policy_generation,
                  "workload_uid": self.scope["workload_uid"], "spec_replicas": self.replicas,
                  "class": self.class_name, "ready_pod_uids": sorted(self.ready),
                  "complete_from": self.coverage_from, "watermark": min(self.watermarks.values()) if len(self.watermarks) == len(STREAMS) else None,
                  "measurement": self.scope["measurement"], "mode": self.scope["mode"], "authoritative": False,
                  "reasons": list(self.reasons), "moves": [], "samples": [], "journal_seq": self.seq, "journal_hash": self.chain}
        # A later bookmark can retrospectively seal a continuous watch segment;
        # it supplies no future object state to this as-of reducer.
        if sealed_until is not None or require_sealed:
            result["watermark"] = sealed_until
        if result["watermark"] is None or at > result["watermark"]:
            result["reasons"].append("API_WATCH_WATERMARK_BEHIND_TICK")
            result["complete_from"] = None
        for move in self.moves.values():
            if move["state"] == "censored" or move.get("ack_at") is None:
                if move["state"] == "open":
                    result["complete_from"] = None
                    result["reasons"].append("MOVE_ACKNOWLEDGEMENT_MISSING")
                result["samples"].append({"id": move["id"], "workload_uid": self.scope["workload_uid"], "action": "rotate",
                                           "at": move["observed_at"], "duration": None, "censored": True,
                                           "overdue": move["overdue"], "suspect": True})
                continue
            intervals = copy.deepcopy(move["intervals"])
            if move["loss_start"] is not None:
                intervals.append({"endpoint_uid": self.scope["service_uid"] + ":" + move["pod_uid"], "start": move["loss_start"], "end": at})
            result["moves"].append({"id": move["id"], "revision": move["revision"], "workload_uid": self.scope["workload_uid"],
                                     "policy_uid": self.scope["policy_uid"], "action": "rotate", "containment": False,
                                     "state": move["state"], "observed_at": at if move["state"] == "open" else move["observed_at"],
                                     "attributed": True, "measured": True, "intervals": intervals,
                                     "reservation": move["reservation"] if move["state"] == "open" else None, "overdue": move["overdue"]})
            if move["state"] == "settled":
                result["samples"].append({"id": move["id"], "workload_uid": self.scope["workload_uid"], "action": "rotate",
                                           "at": move["observed_at"], "duration": move["duration"], "censored": False,
                                           "overdue": move["overdue"], "suspect": False})
        return result


def sealed_sessions(records):
    """API watermarks seal observation time, independently of object state.

    A disconnected session ends at its last common API watermark, never its
    later process checkpoint. Restarts cannot bridge a missing observation.
    """
    seals, session, marks = {}, None, {}
    for event in records:
        if event["kind"] == "session":
            session, marks = event["data"]["id"], {}
        elif event["kind"] in ("list", "watch") and event["data"].get("session") == session:
            marks[event["data"]["stream"]] = event["at"]
            if set(marks) == set(STREAMS):
                seals[session] = min(marks.values())
        elif event["kind"] in ("gap", "stopped"):
            session, marks = None, {}
    return seals
