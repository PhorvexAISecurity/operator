"""Exact-target adapter inventory producer. No Kubernetes operation runs on import."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import posixpath
import re
import signal
import ssl
import threading
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager

EVENTS = "/apis/amtd.r6security.com/v1beta1/securityevents"
RULE = "phorvex.attack.adapter"
SOURCE = "adapter-inventory-detector"
NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
ADAPTER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")  # ingest.validAdapterName
MAX_BODY = 65536
HTTP_DEADLINE_SECONDS = 10
HTTP_SOCKET_TIMEOUT_SECONDS = 2
BODY_DEADLINE_SECONDS = 8
ROUTES = ("phorvex.ai/kv-reset-path", "phorvex.ai/health-path", "phorvex.ai/models-path",
          "phorvex.ai/lora-unload-path", "phorvex.ai/lora-load-path", "phorvex.ai/drain-path",
          "phorvex.ai/guardrail-path", "phorvex.ai/kv-invalidate-path")


class Inconclusive(RuntimeError):
    """Identity, inventory, or dispatch was ambiguous; no guess is permitted."""


class DispatchUncertain(Inconclusive):
    """A mutating API request may have landed. Stop this process."""


@dataclass(frozen=True)
class Config:
    namespace: str
    service: str
    port: int
    container: str
    expected: frozenset[str]
    instance: str
    service_account: str
    lock_uid: str
    poll_seconds: int = 15

    def __post_init__(self):
        if not all(NAME.fullmatch(x) and len(x) <= 63 for x in (self.namespace, self.service, self.container, self.instance, self.service_account)):
            raise Inconclusive("invalid fixed target or detector identity")
        if not 1 <= self.port <= 65535 or not 5 <= self.poll_seconds <= 300:
            raise Inconclusive("invalid fixed port or poll period")
        if any(not ADAPTER.fullmatch(x) for x in self.expected):
            raise Inconclusive("invalid expected adapter identifier")
        try:
            if str(uuid.UUID(self.lock_uid)) != self.lock_uid:
                raise ValueError("noncanonical UID")
        except ValueError as exc:
            raise Inconclusive("operator-precreated lock UID invalid") from exc

    @classmethod
    def from_env(cls):
        names = ("TARGET_NAMESPACE", "TARGET_SERVICE", "MODELS_PORT", "ENGINE_CONTAINER", "DETECTOR_INSTANCE", "SERVICE_ACCOUNT_NAME", "LOCK_UID")
        values = [os.environ[x] for x in names]
        expected = os.environ.get("EXPECTED_ADAPTERS", "")
        ids = expected.split(",") if expected else []
        if any(not x or x.strip() != x for x in ids) or len(ids) != len(set(ids)):
            raise Inconclusive("expected adapter configuration is ambiguous")
        return cls(values[0], values[1], int(values[2]), values[3], frozenset(ids), values[4], values[5], values[6], int(os.environ.get("POLL_SECONDS", "15")))


@dataclass(frozen=True)
class Target:
    service_uid: str
    service_rv: str
    slice_uid: str
    slice_rv: str
    pod_name: str
    pod_uid: str
    pod_rv: str
    pod_ip: str
    container_id: str
    image_id: str
    restart_count: int


def _one(rows, reason):
    if not isinstance(rows, list) or len(rows) != 1:
        raise Inconclusive(reason)
    return rows[0]


def _identified(obj):
    if not isinstance(obj, dict):
        raise Inconclusive("resource is not a JSON object")
    m = obj.get("metadata", {})
    if not m.get("uid") or not m.get("resourceVersion") or m.get("deletionTimestamp"):
        raise Inconclusive("resource identity unavailable")
    return m


def target_snapshot(api, cfg: Config) -> Target:
    service = api.get("service", cfg.namespace, cfg.service)
    sm = _identified(service)
    selector = service.get("spec", {}).get("selector")
    if selector != {"phorvex.ai/role": "leader"}:
        raise Inconclusive("Service selector differs from fixed leader contract")
    ports = service["spec"].get("ports", [])
    port = _one([p for p in ports if p.get("port") == cfg.port and p.get("protocol", "TCP") == "TCP"], "models Service port ambiguous")
    if port.get("targetPort", cfg.port) != cfg.port:
        raise Inconclusive("models Service targetPort differs")
    pod = _one(api.list("pods", cfg.namespace, "phorvex.ai/role=leader").get("items"), "leader Pod population ambiguous")
    pm = _identified(pod)
    if pm.get("labels", {}).get("phorvex.ai/role") != "leader":
        raise Inconclusive("leader Pod label differs")
    if pm.get("namespace") != cfg.namespace or pod.get("status", {}).get("phase") != "Running":
        raise Inconclusive("leader Pod is not running in target namespace")
    annotations = pm.get("annotations", {})
    declared_port = annotations.get("phorvex.ai/serving-port", "8000")
    if declared_port != str(cfg.port) or annotations.get("phorvex.ai/models-path", "/v1/models") != "/v1/models":
        raise Inconclusive("models GET differs from manager effective Pod route")
    for key in ROUTES:
        if key in annotations:
            route = annotations[key]
            if (not isinstance(route, str) or not route.startswith("/") or route.startswith("//")
                    or any(c in route for c in "\\?#%@") or any(ord(c) < 32 or ord(c) == 127 for c in route)
                    or posixpath.normpath(route) != route):
                raise Inconclusive("serving route annotation malformed")
    if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod["status"].get("conditions", [])):
        raise Inconclusive("leader Pod Ready condition absent")
    containers = [c for c in pod["spec"].get("containers", []) if c.get("name") == cfg.container]
    container = _one(containers, "engine container absent or duplicated")
    if not any(p.get("containerPort") == cfg.port and p.get("protocol", "TCP") == "TCP" for p in container.get("ports", [])):
        raise Inconclusive("engine models port is not declared")
    status = _one([s for s in pod["status"].get("containerStatuses", []) if s.get("name") == cfg.container], "engine status absent or duplicated")
    if not status.get("ready") or not status.get("containerID") or not status.get("imageID"):
        raise Inconclusive("engine container incarnation is not Ready")
    ip = pod["status"].get("podIP", "")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise Inconclusive("Pod IP is invalid") from exc
    slices = api.list("endpointslices", cfg.namespace, "kubernetes.io/service-name=" + cfg.service).get("items")
    slice_obj = _one(slices, "models EndpointSlice population ambiguous")
    em = _identified(slice_obj)
    if em.get("labels", {}).get("kubernetes.io/service-name") != cfg.service:
        raise Inconclusive("EndpointSlice Service label differs")
    if not any(o.get("kind") == "Service" and o.get("name") == cfg.service and o.get("uid") == sm["uid"] and o.get("controller") is True for o in em.get("ownerReferences", [])):
        raise Inconclusive("EndpointSlice Service UID owner differs")
    ep_port = _one(slice_obj.get("ports"), "EndpointSlice port population ambiguous")
    if ep_port.get("port") != cfg.port or ep_port.get("protocol", "TCP") != "TCP":
        raise Inconclusive("EndpointSlice models port differs")
    ep = _one(slice_obj.get("endpoints"), "EndpointSlice target population ambiguous")
    ref = ep.get("targetRef", {})
    if (ref.get("kind"), ref.get("namespace", cfg.namespace), ref.get("name"), ref.get("uid")) != ("Pod", cfg.namespace, pm["name"], pm["uid"]):
        raise Inconclusive("EndpointSlice target Pod identity differs")
    if ep.get("conditions", {}).get("ready") is not True or ep.get("conditions", {}).get("terminating") is True or ep.get("addresses") != [ip]:
        raise Inconclusive("EndpointSlice target is not exact Ready Pod IP")
    if slice_obj.get("addressType") != ("IPv4" if address.version == 4 else "IPv6"):
        raise Inconclusive("EndpointSlice address family differs")
    return Target(sm["uid"], sm["resourceVersion"], em["uid"], em["resourceVersion"], pm["name"], pm["uid"], pm["resourceVersion"], ip,
                  status["containerID"], status["imageID"], status.get("restartCount", 0))


def unexpected_adapter(raw: bytes, expected: frozenset[str]) -> str | None:
    if len(raw) > MAX_BODY:
        raise Inconclusive("models response exceeds bound")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_non_json_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Inconclusive("models response is not JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("data"), list) or not value["data"]:
        raise Inconclusive("models response population unsupported")
    if any(key.casefold() == "data" and key != "data" for key in value):
        raise Inconclusive("models response has ambiguous data key")
    seen, bases, adapters = set(), set(), set()
    for row in value["data"]:
        if not isinstance(row, dict) or not _model_id(row.get("id")) or row["id"] in seen:
            raise Inconclusive("models response has invalid or duplicate ID")
        if any(key.casefold() in ("id", "parent") and key not in ("id", "parent") for key in row):
            raise Inconclusive("models response has ambiguous ID or parent key")
        seen.add(row["id"])
        parent = row.get("parent")
        if parent is None or parent == "":
            bases.add(row["id"])
        elif _model_id(parent):
            adapters.add((row["id"], parent))
        else:
            raise Inconclusive("models response has unsupported parent")
    if not bases or any(parent not in bases for _, parent in adapters):
        raise Inconclusive("base model or adapter parent is ambiguous")
    unexpected = sorted(name for name, _ in adapters if name not in expected)
    if len(unexpected) > 1:
        raise Inconclusive("multiple unexpected adapters are ambiguous")
    if unexpected and not ADAPTER.fullmatch(unexpected[0]):
        raise Inconclusive("unexpected adapter is not a bindable name")
    return unexpected[0] if unexpected else None


def _model_id(value):
    return (isinstance(value, str) and 0 < len(value) <= 1024 and value == value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Inconclusive("models response has duplicate JSON key")
        result[key] = value
    return result


def _non_json_constant(value):
    raise Inconclusive("non-JSON numeric constant in response")


@contextmanager
def _http_deadline(seconds=HTTP_DEADLINE_SECONDS):
    # All transport dispatch is synchronous on the process main thread. The
    # timer bounds headers and a slow-drip body, not merely one socket read.
    if threading.current_thread() is not threading.main_thread() or signal.getitimer(signal.ITIMER_REAL)[0] != 0:
        raise Inconclusive("HTTP deadline authority unavailable")
    old_handler = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise TimeoutError("HTTP absolute deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def _bounded_body(response, clock=time.monotonic):
    deadline = clock() + BODY_DEADLINE_SECONDS
    result = bytearray()
    while True:
        if clock() >= deadline:
            raise TimeoutError("HTTP body deadline exceeded")
        chunk = response.read1(min(8192, MAX_BODY + 1 - len(result)))
        if clock() >= deadline:
            raise TimeoutError("HTTP body deadline exceeded")
        if not isinstance(chunk, bytes):
            raise Inconclusive("HTTP body is not bytes")
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > MAX_BODY:
            raise Inconclusive("HTTP body exceeds size bound")


def _incident_key(cfg: Config, pod_uid: str, adapter: str) -> str:
    return "|".join((cfg.instance, cfg.namespace, pod_uid, adapter))


def event_name(key: str) -> str:
    return "adapter-inv-" + hashlib.sha256(key.encode()).hexdigest()[:24]


def lock_name(cfg: Config) -> str:
    return "adapter-inv-lock-" + hashlib.sha256((cfg.namespace + "|" + cfg.instance).encode()).hexdigest()[:24]


def lock_body(cfg: Config, target: Target, adapter: str, existing: dict, phase: str, event_uid: str = "") -> dict:
    if (phase not in ("CLAIMED", "BOUND") or phase == "BOUND" and (not isinstance(event_uid, str) or not event_uid)
            or phase == "CLAIMED" and event_uid):
        raise Inconclusive("detector intent lock phase invalid")
    key = _incident_key(cfg, target.pod_uid, adapter)
    data = {"phase": phase, "incidentDigest": hashlib.sha256(key.encode()).hexdigest(),
            "podName": target.pod_name, "podUID": target.pod_uid,
            "adapter": adapter, "eventName": event_name(key)}
    if event_uid:
        data["eventUID"] = event_uid
    return {"apiVersion": "v1", "kind": "ConfigMap", "immutable": phase == "BOUND",
            "metadata": {"name": lock_name(cfg), "namespace": cfg.namespace,
                         "uid": existing["metadata"]["uid"], "resourceVersion": existing["metadata"]["resourceVersion"],
                         "labels": {"phorvex.ai/adapter-detector": cfg.instance}},
            "data": data}


def _own_lock(lock: dict, cfg: Config) -> tuple[str, dict | None]:
    m = _identified(lock)
    data = lock.get("data", {})
    if (lock.get("apiVersion") != "v1" or lock.get("kind") != "ConfigMap"
            or lock.get("binaryData") or m.get("uid") != cfg.lock_uid or m.get("name") != lock_name(cfg) or m.get("namespace") != cfg.namespace
            or m.get("labels", {}).get("phorvex.ai/adapter-detector") != cfg.instance
            or m.get("ownerReferences") or not isinstance(data, dict)):
        raise Inconclusive("detector intent lock ownership differs")
    if not data and (lock.get("immutable") is None or lock.get("immutable") is False):
        return "UNCLAIMED", None  # Operator-precreated, single-use lock.
    phase = data.get("phase")
    if phase not in ("CLAIMED", "BOUND") or lock.get("immutable") is not (phase == "BOUND"):
        raise Inconclusive("detector intent lock phase/immutability differs")
    adapter, pod_uid, pod_name = data.get("adapter", ""), data.get("podUID", ""), data.get("podName", "")
    if not ADAPTER.fullmatch(adapter) or not pod_uid or not NAME.fullmatch(pod_name):
        raise Inconclusive("detector intent lock identity absent")
    event_uid = data.get("eventUID", "")
    expected = lock_body(cfg, Target("", "", "", "", pod_name, pod_uid, "", "", "", "", 0), adapter, lock, phase, event_uid)
    if data != expected["data"]:
        raise Inconclusive("detector intent lock incident differs")
    return phase, data


def event_body(cfg: Config, target: Target, adapter: str) -> dict:
    key = _incident_key(cfg, target.pod_uid, adapter)
    return {"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
            "metadata": {"name": event_name(key),
                         "labels": {"phorvex.ai/adapter-detector": cfg.instance},
                         "annotations": {"phorvex.ai/adapter-name": adapter, "phorvex.ai/target-pod-uid": target.pod_uid,
                                         "phorvex.ai/detector-instance": cfg.instance,
                                         "phorvex.ai/detector-attempt": hashlib.sha256(key.encode()).hexdigest()}},
            "spec": {"rule": {"source": SOURCE, "type": RULE, "threatLevel": "high"},
                     "targets": [cfg.namespace + "/" + target.pod_name], "anomalyScore": "1.0000",
                     "description": "one unexpected adapter in exact owned serving inventory"}}


def _event_age(event: dict, now: float) -> float:
    from datetime import datetime
    stamp = event["metadata"].get("creationTimestamp", "")
    try:
        created = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise Inconclusive("event has no usable API creation time") from exc
    age = now - created
    if age < 0:
        raise Inconclusive("event creation time is in the future")
    return age


def _own_event(event: dict, cfg: Config) -> tuple[str, str, str]:
    m = _identified(event)
    if m.get("labels", {}).get("phorvex.ai/adapter-detector") != cfg.instance or m.get("annotations", {}).get("phorvex.ai/detector-instance") != cfg.instance:
        raise Inconclusive("event instance ownership differs")
    creator = "system:serviceaccount:" + cfg.namespace + ":" + cfg.service_account
    if m.get("annotations", {}).get("phorvex.ai/creator-identity") != creator:
        raise Inconclusive("event authenticated creator differs or is absent")
    if event.get("spec", {}).get("rule", {}).get("type") != RULE or event["spec"]["rule"].get("source") != SOURCE:
        raise Inconclusive("event rule identity differs")
    target = _one(event["spec"].get("targets"), "event target population ambiguous")
    adapter = m["annotations"].get("phorvex.ai/adapter-name", "")
    pod_uid = m["annotations"].get("phorvex.ai/target-pod-uid", "")
    if not ADAPTER.fullmatch(adapter) or not pod_uid or "/" not in target:
        raise Inconclusive("event adapter or Pod identity absent")
    namespace, pod_name = target.split("/", 1)
    key = _incident_key(cfg, pod_uid, adapter)
    if namespace != cfg.namespace or not NAME.fullmatch(pod_name) or m["name"] != event_name(key) or m["annotations"].get("phorvex.ai/detector-attempt") != hashlib.sha256(key.encode()).hexdigest():
        raise Inconclusive("event attempt identity differs")
    expected = event_body(cfg, Target("", "", "", "", pod_name, pod_uid, "", "", "", "", 0), adapter)
    if event.get("spec") != expected["spec"]:
        raise Inconclusive("event exact producer spec differs")
    return target, pod_uid, adapter


def _create_verified(api, cfg: Config, body: dict, wall_clock) -> dict:
    name = body["metadata"]["name"]
    known = api.get_event(name)
    if known is not None:
        raise Inconclusive("event name occupied before this single POST")
    try:
        response = api.create_event(body)
    except Conflict as exc:
        raise DispatchUncertain("event create name conflict; no adoption or retry") from exc
    except DispatchUncertain:
        raise
    except Exception as exc:
        # The dispatch may have succeeded. A fresh process can reconcile by
        # deterministic name; this process must not send a second POST.
        raise DispatchUncertain("event create outcome ambiguous; no retry") from exc
    response_meta = response.get("metadata", {}) if isinstance(response, dict) else {}
    emitted_uid = response_meta.get("uid", "")
    if response_meta.get("name") != name or not isinstance(emitted_uid, str) or not emitted_uid:
        raise DispatchUncertain("event create response has no exact API UID; no adoption")
    try:
        created = api.get_event(name)
    except Exception as exc:
        raise DispatchUncertain("event create readback ambiguous; no retry") from exc
    if created is None or created["metadata"].get("name") != name or created["metadata"].get("uid") != emitted_uid:
        raise DispatchUncertain("event create/readback identity ambiguous; no retry")
    target, uid, adapter = _own_event(created, cfg)
    if target != body["spec"]["targets"][0] or uid != body["metadata"]["annotations"]["phorvex.ai/target-pod-uid"] or adapter != body["metadata"]["annotations"]["phorvex.ai/adapter-name"]:
        raise Inconclusive("event create/readback contract differs")
    if _event_age(created, wall_clock()) >= 900:
        raise DispatchUncertain("event API time outside manager evidence horizon; UID not bound")
    return created


def _claim_lock_verified(api, cfg: Config, initial: dict, body: dict) -> dict:
    if _own_lock(initial, cfg)[0] != "UNCLAIMED":
        raise Inconclusive("detector intent lock already claimed")
    try:
        api.update_lock(body)
    except Exception as exc:
        # An update timeout/conflict may have committed the intent. Stop even if
        # subsequent GET sees the claim; only this exact successful CAS continues.
        try:
            observed = api.get_lock()
            if observed is not None and observed.get("metadata", {}).get("uid") == initial["metadata"]["uid"]:
                if _own_lock(observed, cfg) == ("CLAIMED", body["data"]):
                    raise DispatchUncertain("detector intent lock CAS recorded after uncertainty; no event POST") from exc
        except DispatchUncertain:
            raise
        except Exception:
            pass
        raise DispatchUncertain("detector intent lock CAS unconfirmed; no event POST") from exc
    try:
        lock = api.get_lock()
    except Exception as exc:
        raise DispatchUncertain("detector intent lock CAS readback ambiguous; no event POST") from exc
    if lock is None or not lock.get("metadata", {}).get("uid"):
        raise DispatchUncertain("detector intent lock CAS readback absent; no event POST")
    if lock["metadata"]["uid"] != initial["metadata"]["uid"] or _own_lock(lock, cfg) != ("CLAIMED", body["data"]):
        raise DispatchUncertain("detector intent lock CAS readback differs; no event POST")
    return lock


def _bind_lock_verified(api, cfg: Config, claimed: dict, event_uid: str) -> dict:
    phase, intent = _own_lock(claimed, cfg)
    if phase != "CLAIMED" or not event_uid:
        raise Inconclusive("detector intent lock is not claimable for UID binding")
    target = Target("", "", "", "", intent["podName"], intent["podUID"], "", "", "", "", 0)
    body = lock_body(cfg, target, intent["adapter"], claimed, "BOUND", event_uid)
    try:
        api.update_lock(body)
    except Exception as exc:
        try:
            api.get_lock()  # exact-name diagnostic read; never adopt on uncertainty
        except Exception:
            pass
        raise DispatchUncertain("event UID lock binding CAS ambiguous; terminal review required") from exc
    try:
        bound = api.get_lock()
    except Exception as exc:
        raise DispatchUncertain("event UID lock binding readback ambiguous") from exc
    if (bound is None or bound.get("metadata", {}).get("uid") != claimed["metadata"]["uid"]
            or _own_lock(bound, cfg) != ("BOUND", body["data"])):
        raise DispatchUncertain("event UID lock binding readback differs")
    return bound


class Conflict(Exception):
    pass


def run_once(api, cfg: Config, wall_clock) -> dict:
    if not callable(wall_clock):
        raise Inconclusive("fresh wall clock callable required")
    before = target_snapshot(api, cfg)
    raw = api.models(before.pod_ip, cfg.port)
    adapter = unexpected_adapter(raw, cfg.expected)
    after = target_snapshot(api, cfg)
    if before != after:
        raise Inconclusive("target or route changed during models observation")
    events = api.list_events(cfg.instance)
    if not isinstance(events, list) or len(events) > 1:
        raise Inconclusive("owned event population ambiguous")
    lock = api.get_lock()
    if lock is None:
        raise Inconclusive("operator-precreated detector intent lock absent")
    phase, intent = _own_lock(lock, cfg)
    if phase == "UNCLAIMED":
        if events:
            raise Inconclusive("owned event has no claimed detector intent lock")
        if adapter is None:
            return {"status": "clean", "podUID": before.pod_uid, "event": None}
        body = event_body(cfg, before, adapter)
        claimed = _claim_lock_verified(api, cfg, lock, lock_body(cfg, before, adapter, lock, "CLAIMED"))
        created = _create_verified(api, cfg, body, wall_clock)
        _bind_lock_verified(api, cfg, claimed, created["metadata"]["uid"])
        return {"status": "created", "podUID": before.pod_uid, "event": created["metadata"]["uid"]}
    if phase == "CLAIMED":
        raise Inconclusive("detector intent CLAIMED without terminal UID binding; review required")
    if not events:
        raise Inconclusive("durable detector intent exists without event; terminal review required")
    if events:
        event = events[0]
        target_name, uid, name = _own_event(event, cfg)
        if event["metadata"]["uid"] != intent["eventUID"]:
            raise Inconclusive("event UID differs from immutable detector intent")
        if (event["metadata"]["name"], target_name, uid, name) != (intent["eventName"], cfg.namespace + "/" + intent["podName"], intent["podUID"], intent["adapter"]):
            raise Inconclusive("event differs from durable detector intent")
        age = _event_age(event, wall_clock())
        if age >= 900:
            raise Inconclusive("incident event expired; protected operation review required")
        if (target_name, uid) != (cfg.namespace + "/" + before.pod_name, before.pod_uid):
            raise Inconclusive("target Pod changed; protected operation review required")
        if adapter is None:
            return {"status": "cleared-await-terminal", "podUID": before.pod_uid, "event": event["metadata"]["uid"]}
        if name != adapter:
            raise Inconclusive("unexpected adapter changed; protected operation review required")
        return {"status": "retained", "podUID": before.pod_uid, "event": event["metadata"]["uid"]}
    raise AssertionError("unreachable detector incident state")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise Inconclusive("HTTP redirect refused")


class ClusterAPI:
    """Single-dispatch, fixed-path in-cluster transport. No proxy or HTTP retries."""
    def __init__(self, cfg: Config):
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = int(os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
        if not 1 <= port <= 65535 or not host or "/" in host:
            raise Inconclusive("Kubernetes API origin invalid")
        self.origin = "https://" + ("[" + host + "]" if ":" in host else host) + ":" + str(port)
        self.token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        self.kube_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        self.models_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.cfg = cfg

    def _request(self, method, path, body=None, missing=False):
        if not path.startswith("/") or "?" in path and not path.startswith(("/api/v1/", "/apis/")):
            raise Inconclusive("Kubernetes request path invalid")
        raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Authorization": "Bearer " + self.token_path.read_text().strip(), "Accept": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + path, data=raw, method=method, headers=headers)
        try:
            with _http_deadline():
                with self.kube_opener.open(request, timeout=HTTP_SOCKET_TIMEOUT_SECONDS) as response:
                    if response.status not in (200, 201, 202):
                        raise Inconclusive("Kubernetes response status unsupported")
                    payload = _bounded_body(response)
                    return json.loads(payload, object_pairs_hook=_unique_object, parse_constant=_non_json_constant)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and missing:
                return None
            if exc.code == 409 and method == "POST":
                raise Conflict() from None
            raise Inconclusive("Kubernetes HTTP " + str(exc.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if method in ("POST", "PUT"):
                raise DispatchUncertain("mutating Kubernetes request outcome ambiguous") from exc
            raise Inconclusive("Kubernetes transport failed") from exc

    def get(self, kind, namespace, name, allow_missing=False):
        resources = {"service": "services", "pod": "pods"}
        if kind not in resources or not NAME.fullmatch(name) or namespace != self.cfg.namespace:
            raise Inconclusive("unsupported Kubernetes GET")
        return self._request("GET", "/api/v1/namespaces/" + namespace + "/" + resources[kind] + "/" + name, missing=allow_missing)

    def list(self, kind, namespace, selector):
        if namespace != self.cfg.namespace or (kind, selector) not in (("pods", "phorvex.ai/role=leader"), ("endpointslices", "kubernetes.io/service-name=" + self.cfg.service)):
            raise Inconclusive("unsupported Kubernetes LIST")
        base = "/api/v1/" if kind == "pods" else "/apis/discovery.k8s.io/v1/"
        return self._request("GET", base + "namespaces/" + namespace + "/" + kind + "?labelSelector=" + urllib.parse.quote(selector, safe=""))

    def models(self, ip: str, port: int) -> bytes:
        address = ipaddress.ip_address(ip)
        if port != self.cfg.port:
            raise Inconclusive("models port differs from fixed config")
        url = "http://" + ("[" + str(address) + "]" if address.version == 6 else str(address)) + ":" + str(port) + "/v1/models"
        req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with _http_deadline():
                with self.models_opener.open(req, timeout=HTTP_SOCKET_TIMEOUT_SECONDS) as response:
                    if response.status != 200 or not response.headers.get("Content-Type", "").startswith("application/json"):
                        raise Inconclusive("models HTTP status or type unsupported")
                    return _bounded_body(response)
        except urllib.error.HTTPError as exc:
            raise Inconclusive("models HTTP " + str(exc.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Inconclusive("models transport failed") from exc

    def list_events(self, instance: str):
        if instance != self.cfg.instance:
            raise Inconclusive("event instance differs")
        value = self._request("GET", EVENTS + "?labelSelector=" + urllib.parse.quote("phorvex.ai/adapter-detector=" + instance, safe=""))
        return value.get("items")

    def get_event(self, name: str):
        if not NAME.fullmatch(name):
            raise Inconclusive("event name invalid")
        return self._request("GET", EVENTS + "/" + name, missing=True)

    def get_lock(self):
        return self._request("GET", "/api/v1/namespaces/" + self.cfg.namespace + "/configmaps/" + lock_name(self.cfg), missing=True)

    def update_lock(self, body: dict):
        return self._request("PUT", "/api/v1/namespaces/" + self.cfg.namespace + "/configmaps/" + lock_name(self.cfg), body)

    def create_event(self, body: dict):
        return self._request("POST", EVENTS, body)

def main():
    cfg = Config.from_env()
    api = ClusterAPI(cfg)
    while True:
        try:
            result = run_once(api, cfg, time.time)
            print("adapter detector: " + result["status"], flush=True)
        except Inconclusive as exc:
            print("adapter detector: inconclusive " + str(exc), flush=True)
            if isinstance(exc, DispatchUncertain):
                raise SystemExit(3)
        except Exception as exc:
            print("adapter detector: unexpected " + type(exc).__name__, flush=True)
        time.sleep(cfg.poll_seconds)


if __name__ == "__main__":
    main()
