"""Durable proxy coordinator for the Phorvex operation-bound drain v11 contract."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Awaitable, Callable

import httpx

SCHEMA = "phorvex.drain.v1"
CAPABILITY = "operation-bound-quiescence-v1"
MAX_U64 = 18446744073709551615
MAX_SAFE_JSON_INTEGER = 9007199254740991
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
TERMINAL = {"QUIESCENT", "CANCELLED", "FAILED", "STALE", "OPENED"}
CANCEL_GRACE_SECONDS = 30


class DrainError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def strict_loads(data: bytes, *, max_bytes: int) -> object:
    if len(data) > max_bytes:
        raise DrainError(413, "body_too_large")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite {value}")))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise DrainError(400, "invalid_json") from exc


def canonical_bytes(value: object) -> bytes:
    def check(item):
        if item is None or isinstance(item, (str, bool)):
            return
        if type(item) is int:
            if not 0 <= item <= MAX_SAFE_JSON_INTEGER:
                raise ValueError("JSON integer is outside the interoperable range")
            return
        if isinstance(item, list):
            for child in item:
                check(child)
            return
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError("canonical JSON object keys must be strings")
            for child in item.values():
                check(child)
            return
        raise ValueError("unsupported canonical JSON value")

    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def domain_digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode() + b"\0" + canonical_bytes(value)).hexdigest()


def u64(value: object, name: str, *, positive: bool = False) -> int:
    if not isinstance(value, str) or not DECIMAL.fullmatch(value):
        raise DrainError(400, f"invalid_{name}")
    parsed = int(value)
    if parsed > MAX_U64 or (positive and parsed == 0):
        raise DrainError(400, f"invalid_{name}")
    return parsed


def exact_object(value: object, fields: set[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise DrainError(400, f"invalid_{name}")
    return value


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def deadline_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z")


def cancellation_grace_deadline(deadline: str) -> str:
    return deadline_text(parse_deadline(deadline, require_future=False)
                         + timedelta(seconds=CANCEL_GRACE_SECONDS))


def parse_deadline(value: object, *, require_future: bool = True) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DrainError(400, "invalid_deadline")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DrainError(400, "invalid_deadline") from exc
    now = datetime.now(timezone.utc)
    if require_future and (result <= now or (result - now).total_seconds() > 600):
        raise DrainError(400, "invalid_deadline")
    return result


def validate_create(value: object, *, require_future: bool = True) -> dict:
    required = {
        "schema", "operation_id", "operation_generation", "attempt",
        "owner", "expected_incarnation_digest", "deadline", "mode",
    }
    allowed = required | {"supersedes"}
    if not isinstance(value, dict) or set(value) not in (required, allowed):
        raise DrainError(400, "invalid_fields")
    if value["schema"] != SCHEMA or value["mode"] != "abort-and-quiesce":
        raise DrainError(400, "invalid_schema_or_mode")
    if not isinstance(value["operation_id"], str) or not HEX32.fullmatch(value["operation_id"]):
        raise DrainError(400, "invalid_operation_id")
    u64(value["operation_generation"], "operation_generation", positive=True)
    if type(value["attempt"]) is not int or value["attempt"] not in (1, 2):
        raise DrainError(400, "invalid_attempt")
    owner = exact_object(value["owner"], {
        "tenant", "namespace_uid", "policy_uid", "pod_uid", "service_uid",
    }, "owner")
    for key, item in owner.items():
        if not isinstance(item, str) or not item or len(item.encode()) > 256:
            raise DrainError(400, f"invalid_owner_{key}")
    if not isinstance(value["expected_incarnation_digest"], str) or not HEX64.fullmatch(
            value["expected_incarnation_digest"]):
        raise DrainError(400, "invalid_incarnation")
    parse_deadline(value["deadline"], require_future=require_future)
    if "supersedes" in value:
        sup = exact_object(value["supersedes"], {
            "operation_generation", "operation_id", "revision",
        }, "supersedes")
        u64(sup["operation_generation"], "supersedes_generation", positive=True)
        u64(sup["revision"], "supersedes_revision", positive=True)
        if not isinstance(sup["operation_id"], str) or not HEX32.fullmatch(sup["operation_id"]):
            raise DrainError(400, "invalid_supersedes_operation_id")
    if (value["attempt"] == 1) != ("supersedes" not in value):
        raise DrainError(400, "invalid_attempt_supersession")
    return value


class Ledger:
    """Crash-safe single-Pod ledger; initialization is a separate init step."""
    def __init__(self, directory: Path, pod_uid: str):
        self.directory = directory
        self.origin_path = directory / "origin.json"
        self.ledger_path = directory / "ledger.json"
        self._lock = threading.RLock()
        try:
            names = {path.name for path in directory.iterdir()}
        except OSError as exc:
            raise RuntimeError("drain ledger directory is unavailable") from exc
        if names != {"origin.json", "ledger.json"}:
            raise RuntimeError("drain ledger has missing files or transaction residue")
        try:
            origin = strict_loads(self.origin_path.read_bytes(), max_bytes=4096)
            data = strict_loads(self.ledger_path.read_bytes(), max_bytes=1 << 20)
        except (OSError, DrainError) as exc:
            raise RuntimeError("drain ledger is missing or malformed") from exc
        exact_object(origin, {"schema", "pod_uid", "ledger_id"}, "origin")
        if origin["schema"] != SCHEMA or origin["pod_uid"] != pod_uid:
            raise RuntimeError("drain origin does not match this Pod")
        if not isinstance(origin["ledger_id"], str) or not HEX32.fullmatch(origin["ledger_id"]):
            raise RuntimeError("invalid drain ledger ID")
        exact_object(data, {
            "schema", "pod_uid", "ledger_id", "generation_high_water",
            "admission", "current", "history",
        }, "ledger")
        if (data["schema"] != SCHEMA or data["pod_uid"] != pod_uid
                or data["ledger_id"] != origin["ledger_id"]):
            raise RuntimeError("drain sentinel and ledger disagree")
        u64(data["generation_high_water"], "generation_high_water")
        if data["admission"] not in ("OPEN", "CLOSED"):
            raise RuntimeError("invalid persisted admission")
        if not isinstance(data["history"], list) or len(data["history"]) > 64:
            raise RuntimeError("invalid drain history")
        try:
            canonical_bytes(origin)
            canonical_bytes(data)
            records = list(data["history"])
            if data["current"] is not None:
                records.append(data["current"])
            record_fields = {
                "schema", "operation_id", "operation_generation", "attempt",
                "owner_digest", "backend_incarnation_digest", "revision", "state",
                "admission", "admission_generation", "engine_boot_id",
                "virtual_engine_ids",
                "engine_snapshot", "terminal_dispositions", "proxy_snapshot",
                "observations", "deadline", "cancellation_grace_deadline",
                "transition_reason", "cancel_boundary_revision",
                "last_transition", "canonical_create",
            }
            valid_states = {
                "CLOSING_ADMISSION", "DRAINING", "QUIESCENT",
                "CANCEL_REQUESTED", "CANCELLED", "REOPENING", "OPENED",
                "FAILED", "STALE",
            }
            for record in records:
                exact_object(record, record_fields, "record")
                if (record["schema"] != SCHEMA
                        or record["state"] not in valid_states
                        or record["admission"] not in ("OPEN", "CLOSED")
                        or not HEX32.fullmatch(record["operation_id"])
                        or not HEX32.fullmatch(record["engine_boot_id"])
                        or not HEX64.fullmatch(record["owner_digest"])
                        or not HEX64.fullmatch(record["backend_incarnation_digest"])
                        or record["virtual_engine_ids"] != [0]
                        or not isinstance(record["observations"], list)
                        or len(record["observations"]) > 2):
                    raise ValueError("invalid persisted operation")
                u64(record["operation_generation"], "operation_generation", positive=True)
                u64(record["revision"], "revision", positive=True)
                u64(record["admission_generation"], "admission_generation")
                create = validate_create(record["canonical_create"], require_future=False)
                if (record["schema"] != create["schema"]
                        or record["operation_id"] != create["operation_id"]
                        or record["operation_generation"] != create["operation_generation"]
                        or record["attempt"] != create["attempt"]
                        or record["deadline"] != create["deadline"]
                        or record["backend_incarnation_digest"]
                        != create["expected_incarnation_digest"]
                        or record["owner_digest"]
                        != domain_digest("phorvex-drain-owner-v1", create["owner"])):
                    raise ValueError("persisted operation changed its canonical create binding")
                if (record["cancellation_grace_deadline"]
                        != cancellation_grace_deadline(record["deadline"])
                        or record["transition_reason"] not in (
                            "none", "deadline-expired", "operator-requested")
                        or not isinstance(record["cancel_boundary_revision"], str)):
                    raise ValueError("persisted cancellation boundary is invalid")
                boundary = u64(record["cancel_boundary_revision"],
                               "cancel_boundary_revision")
                if ((record["transition_reason"] == "none") != (boundary == 0)):
                    raise ValueError("persisted cancellation reason/boundary disagree")
                if record["state"] in ("CANCEL_REQUESTED", "CANCELLED") and boundary == 0:
                    raise ValueError("persisted cancellation state lacks its boundary")
        except (DrainError, ValueError, TypeError) as exc:
            raise RuntimeError("invalid persisted drain operation") from exc
        self.data = data

    @property
    def ledger_id(self):
        return self.data["ledger_id"]

    def write(self):
        raw = canonical_bytes(self.data) + b"\n"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        temporary.chmod(0o600)
        temporary.replace(self.ledger_path)
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


@dataclass
class EngineHTTPClient:
    base_url: str
    token: str
    source: str

    async def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=2.0), trust_env=False,
                follow_redirects=False) as client:
            response = await client.request(
                method, self.base_url + path,
                headers={"Authorization": f"Bearer {self.token}",
                         "Content-Type": "application/json"},
                content=None if body is None else canonical_bytes(body))
        if response.status_code != 200:
            raise DrainError(502, "engine_control_refused")
        if response.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            raise DrainError(502, "engine_content_type")
        value = strict_loads(response.content, max_bytes=32768)
        if not isinstance(value, dict):
            raise DrainError(502, "engine_response")
        return value

    async def capability(self):
        return await self._call("GET", "/phorvex/drain/capability")

    async def begin(self, operation_id, operation_generation):
        return await self._call("POST", "/phorvex/drain/begin", {
            "operation_id": operation_id,
            "operation_generation": operation_generation,
        })

    async def observe(self, operation_id, operation_generation, nonce):
        return await self._call("POST", "/phorvex/drain/observe", {
            "operation_id": operation_id,
            "operation_generation": operation_generation,
            "observation_nonce": nonce,
        })

    async def reopen(self, operation_id, operation_generation):
        return await self._call("POST", "/phorvex/drain/reopen", {
            "operation_id": operation_id,
            "operation_generation": operation_generation,
        })


class Coordinator:
    def __init__(self, ledger: Ledger, engine: EngineHTTPClient, *, pod_uid: str,
                 proxy_source: str, model_digest: str,
                 snapshot_proxy: Callable[[], Awaitable[dict]],
                 terminate_proxy: Callable[[], Awaitable[dict]]):
        self.ledger = ledger
        self.engine = engine
        self.pod_uid = pod_uid
        self.proxy_source = proxy_source
        self.model_digest = model_digest
        self.snapshot_proxy = snapshot_proxy
        self.terminate_proxy = terminate_proxy
        self.proxy_boot_id = os.urandom(16).hex()
        self.admission_open = False
        self._lock = asyncio.Lock()
        current = self.ledger.data["current"]
        if current is not None and current.get("state") != "OPENED":
            current["state"] = "STALE"
            current["revision"] = str(u64(current["revision"], "revision") + 1)
            current["last_transition"] = now_text()
            self.ledger.data["admission"] = "CLOSED"
            self.ledger.write()

    async def initialize(self):
        async with self._lock:
            capability = await self._engine_capability()
            current = self.ledger.data["current"]
            if current is None and capability["admission"] == "OPEN":
                self.admission_open = True
                self.ledger.data["admission"] = "OPEN"
                self.ledger.write()
            else:
                self.admission_open = False
                self.ledger.data["admission"] = "CLOSED"
                self.ledger.write()

    async def _engine_capability(self):
        value = await self.engine.capability()
        required = {
            "request_id", "action", "supported", "engine_boot_id", "admission",
            "admission_generation", "operation_id", "operation_generation",
            "observation_nonce", "observation_sequence", "virtual_engine_ids",
            "snapshot", "queues", "terminal_dispositions", "error",
        }
        exact_object(value, required, "engine_capability")
        if (value["action"] != "capability" or value["supported"] is not True
                or value["error"] is not None or value["virtual_engine_ids"] != [0]
                or not isinstance(value["engine_boot_id"], str)
                or not HEX32.fullmatch(value["engine_boot_id"])):
            raise DrainError(503, "unsupported_engine")
        u64(value["admission_generation"], "admission_generation")
        u64(value["observation_sequence"], "observation_sequence")
        return value

    def _incarnation(self, engine_capability):
        fields = {
            "schema": SCHEMA, "pod_uid": self.pod_uid,
            "ledger_id": self.ledger.ledger_id,
            "proxy_boot_id": self.proxy_boot_id,
            "engine_boot_id": engine_capability["engine_boot_id"],
            "proxy_source": self.proxy_source,
            "engine_source": self.engine.source,
            "engine_mode": "v0-frontend-multiprocessing",
            "virtual_engine_ids": [0], "model_digest": self.model_digest,
        }
        return domain_digest("phorvex-drain-incarnation-v1", fields)

    async def capability(self):
        async with self._lock:
            engine = await self._engine_capability()
            current = self.ledger.data["current"]
            if (current is not None and current["state"] not in ("OPENED", "STALE")
                    and engine["engine_boot_id"] != current["engine_boot_id"]):
                current["state"] = "STALE"
                current["revision"] = str(
                    u64(current["revision"], "revision", positive=True) + 1)
                current["last_transition"] = now_text()
                self.admission_open = False
                self.ledger.data["admission"] = "CLOSED"
                self.ledger.write()
            high = u64(self.ledger.data["generation_high_water"], "generation_high_water")
            body = {
                "schema": SCHEMA, "capability": CAPABILITY,
                "pod_uid": self.pod_uid, "ledger_id": self.ledger.ledger_id,
                "proxy_boot_id": self.proxy_boot_id,
                "engine_boot_id": engine["engine_boot_id"],
                "incarnation_digest": self._incarnation(engine),
                "proxy_source": self.proxy_source, "engine_source": self.engine.source,
                "engine_mode": "v0-frontend-multiprocessing",
                "virtual_engine_ids": [0],
                "generation_high_water": str(high),
                "admission": "OPEN" if self.admission_open else "CLOSED",
            }
            # A STALE current operation keeps admission closed but advertises
            # the one exact next generation needed for authenticated attempt-2
            # supersession. Other active states remain non-creatable.
            if (high < MAX_U64 and
                    (self.ledger.data["current"] is None or
                     self.ledger.data["current"].get("state") == "STALE")):
                body["next_operation_generation"] = str(high + 1)
            return body

    def admit_generation(self):
        if not self.admission_open:
            raise DrainError(503, "admission_closed")

    def _find(self, generation: str, operation_id: str):
        current = self.ledger.data["current"]
        if current and (current["operation_generation"], current["operation_id"]) == (
                generation, operation_id):
            return current
        for record in self.ledger.data["history"]:
            if (record["operation_generation"], record["operation_id"]) == (
                    generation, operation_id):
                return record
        return None

    def _status(self, record, query_nonce=None):
        body = {key: value for key, value in record.items() if key != "canonical_create"}
        body["query_nonce"] = query_nonce
        body["receipt_sha256"] = domain_digest("phorvex-drain-status-v1", body)
        return body

    async def create(self, payload):
        payload = validate_create(payload)
        async with self._lock:
            generation = u64(payload["operation_generation"], "operation_generation", positive=True)
            existing = self._find(payload["operation_generation"], payload["operation_id"])
            if existing:
                if existing["canonical_create"] != payload:
                    raise DrainError(409, "generation_conflict")
                return 200, self._status(existing)
            high = u64(self.ledger.data["generation_high_water"], "generation_high_water")
            if generation <= high:
                retained_generation = any(
                    item is not None
                    and item.get("operation_generation") == payload["operation_generation"]
                    for item in ([self.ledger.data["current"]]
                                 + self.ledger.data["history"]))
                if retained_generation:
                    raise DrainError(409, "generation_conflict")
                raise DrainError(410, "expired_generation")
            if generation != high + 1:
                raise DrainError(409, "generation_gap")
            current = self.ledger.data["current"]
            supersedes = payload.get("supersedes")
            if current is not None:
                if (current.get("state") != "STALE" or supersedes is None
                        or supersedes != {
                            "operation_generation": current["operation_generation"],
                            "operation_id": current["operation_id"],
                            "revision": current["revision"],
                        }
                        or domain_digest("phorvex-drain-owner-v1", payload["owner"])
                        != current["owner_digest"]):
                    raise DrainError(409, "operation_in_progress")
            elif supersedes is not None:
                raise DrainError(409, "invalid_supersession")

            history = self.ledger.data["history"]
            while len(history) + (1 if current is not None else 0) >= 64:
                cutoff = datetime.now(timezone.utc).timestamp() - 86400
                eligible = next((index for index, item in enumerate(history)
                                 if item.get("state") == "OPENED"
                                 and datetime.fromisoformat(
                                     item["last_transition"].replace("Z", "+00:00")
                                 ).timestamp() <= cutoff), None)
                if eligible is None:
                    raise DrainError(503, "ledger_capacity")
                history.pop(eligible)
            engine_capability = await self._engine_capability()
            incarnation = self._incarnation(engine_capability)
            if payload["expected_incarnation_digest"] != incarnation:
                raise DrainError(409, "incarnation_mismatch")
            self.admission_open = False
            owner_digest = domain_digest("phorvex-drain-owner-v1", payload["owner"])
            record = {
                "schema": SCHEMA,
                "operation_id": payload["operation_id"],
                "operation_generation": payload["operation_generation"],
                "attempt": payload["attempt"], "owner_digest": owner_digest,
                "backend_incarnation_digest": incarnation,
                "revision": "1", "state": "CLOSING_ADMISSION",
                "admission": "CLOSED", "admission_generation": str(high),
                "engine_boot_id": engine_capability["engine_boot_id"],
                "virtual_engine_ids": [0],
                "engine_snapshot": {}, "terminal_dispositions": {},
                "proxy_snapshot": {}, "observations": [],
                "deadline": payload["deadline"],
                "cancellation_grace_deadline": cancellation_grace_deadline(payload["deadline"]),
                "transition_reason": "none", "cancel_boundary_revision": "0",
                "last_transition": now_text(),
                "canonical_create": payload,
            }
            if current is not None:
                history.append(current)
            self.ledger.data.update({
                "generation_high_water": str(generation), "admission": "CLOSED",
                "current": record,
            })
            self.ledger.write()
            try:
                # Snapshot while the public gate is already closed, but do not
                # cancel relay tasks until BeginDrain has taken the engine-owned
                # scheduler snapshot on the common ordered input stream.
                proxy_snapshot = await self.snapshot_proxy()
                engine = await self.engine.begin(payload["operation_id"],
                                                 payload["operation_generation"])
                self._validate_engine(engine, record, action="begin")
                proxy_terminal = await self.terminate_proxy()
            except BaseException:
                record["state"] = "FAILED"
                record["revision"] = str(
                    u64(record["revision"], "revision", positive=True) + 1)
                record["last_transition"] = now_text()
                self.ledger.write()
                raise
            record.update({
                "state": "DRAINING", "revision": "2",
                "admission_generation": engine["admission_generation"],
                "engine_snapshot": engine["snapshot"],
                "terminal_dispositions": engine["terminal_dispositions"],
                "proxy_snapshot": {
                    "before_engine_begin": proxy_snapshot,
                    "after_engine_begin": proxy_terminal,
                },
                "last_transition": now_text(),
            })
            self.ledger.write()
            return 201, self._status(record)

    def _validate_engine(self, value, record, *, action, nonce=None):
        fields = {
            "request_id", "action", "supported", "engine_boot_id", "admission",
            "admission_generation", "operation_id", "operation_generation",
            "observation_nonce", "observation_sequence", "virtual_engine_ids",
            "snapshot", "queues", "terminal_dispositions", "error",
        }
        if (isinstance(value, dict)
                and value.get("engine_boot_id") != record["engine_boot_id"]):
            record["state"] = "STALE"
            record["revision"] = str(
                u64(record["revision"], "revision", positive=True) + 1)
            record["last_transition"] = now_text()
            self.admission_open = False
            self.ledger.data["admission"] = "CLOSED"
            self.ledger.write()
            raise DrainError(409, "engine_incarnation_changed")
        if (not isinstance(value, dict) or set(value) != fields
                or value.get("action") != action
                or value.get("supported") is not True or value.get("error") is not None
                or value.get("engine_boot_id") != record["engine_boot_id"]
                or value.get("operation_id") != record["operation_id"]
                or value.get("operation_generation") != record["operation_generation"]
                or value.get("admission_generation")
                != record["operation_generation"]
                or (action in ("begin", "observe")
                    and value.get("admission") != "CLOSED")
                or (action == "reopen" and value.get("admission") != "OPEN")
                or value.get("virtual_engine_ids") != [0]
                or (nonce is not None and value.get("observation_nonce") != nonce)
                or (action in ("observe", "reopen")
                    and (value.get("snapshot") != record["engine_snapshot"]
                         or value.get("terminal_dispositions")
                         != record["terminal_dispositions"]))):
            raise DrainError(502, "engine_evidence_mismatch")
        u64(value.get("admission_generation"), "admission_generation")
        u64(value.get("observation_sequence"), "observation_sequence")
        for key in ("snapshot", "queues", "terminal_dispositions"):
            if not isinstance(value.get(key), dict):
                raise DrainError(502, "engine_evidence_mismatch")

    @staticmethod
    def _zero_queues(queues):
        return all(not values[name]
                   for values in queues.values()
                   for name in ("waiting", "running", "swapped", "cached"))

    async def status(self, generation, operation_id, nonce):
        u64(generation, "operation_generation", positive=True)
        if not HEX32.fullmatch(operation_id):
            raise DrainError(400, "invalid_operation_id")
        if not isinstance(nonce, str) or not HEX32.fullmatch(nonce):
            raise DrainError(400, "invalid_observation_nonce")
        async with self._lock:
            record = self._find(generation, operation_id)
            if record is None:
                high = u64(self.ledger.data["generation_high_water"], "generation_high_water")
                raise DrainError(410 if int(generation) <= high else 404,
                                 "expired_generation" if int(generation) <= high else "unknown_operation")
            if (record is self.ledger.data["current"]
                    and record["state"] in ("QUIESCENT", "CANCELLED", "REOPENING")):
                # A terminal quiescence receipt is useful only while the exact
                # engine operation and boot remain current. This fresh engine
                # control read closes the same-Pod/same-container process-
                # restart gap before the operator can retire or restore a
                # Kubernetes route.
                engine = await self._engine_capability()
                if engine["engine_boot_id"] != record["engine_boot_id"]:
                    record["state"] = "STALE"
                    record["revision"] = str(
                        u64(record["revision"], "revision", positive=True) + 1)
                    record["last_transition"] = now_text()
                    self.admission_open = False
                    self.ledger.data["admission"] = "CLOSED"
                    self.ledger.write()
                    return self._status(record, nonce)
                operation_matches = (
                    engine["operation_id"] == record["operation_id"]
                    and engine["operation_generation"]
                    == record["operation_generation"]
                    and engine["admission_generation"]
                    == record["admission_generation"])
                if record["state"] == "REOPENING":
                    if (engine["admission"] == "OPEN"
                            and engine["operation_id"] is None
                            and engine["operation_generation"] is None
                            and engine["admission_generation"]
                            == record["admission_generation"]):
                        record["state"] = "OPENED"
                        record["admission"] = "OPEN"
                        record["revision"] = str(
                            u64(record["revision"], "revision", positive=True) + 1)
                        record["last_transition"] = now_text()
                        self.ledger.data["history"].append(record)
                        self.ledger.data["current"] = None
                        self.ledger.data["admission"] = "OPEN"
                        self.ledger.write()
                        self.admission_open = True
                        return self._status(record, nonce)
                    # The engine's ordered capability response definitively
                    # followed the attempted reopen but did not observe it.
                    # Preserve a closed failure instead of replaying reopen.
                    record["state"] = "FAILED"
                    record["revision"] = str(
                        u64(record["revision"], "revision", positive=True) + 1)
                    record["last_transition"] = now_text()
                    self.admission_open = False
                    self.ledger.data["admission"] = "CLOSED"
                    self.ledger.write()
                    return self._status(record, nonce)
                if engine["admission"] != "CLOSED" or not operation_matches:
                    record["state"] = "FAILED"
                    record["revision"] = str(
                        u64(record["revision"], "revision", positive=True) + 1)
                    record["last_transition"] = now_text()
                    self.admission_open = False
                    self.ledger.data["admission"] = "CLOSED"
                    self.ledger.write()
                    return self._status(record, nonce)
            if record["state"] in TERMINAL:
                return self._status(record, nonce)
            deadline = datetime.fromisoformat(record["deadline"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now >= deadline and record["state"] != "CANCEL_REQUESTED":
                # The normal work deadline never grants completion. It closes
                # the abort worker at a durable cancellation boundary while
                # preserving both admission gates as CLOSED. Only the same
                # fresh two-observation engine proof may reach CANCELLED.
                prior_revision = u64(record["revision"], "revision", positive=True)
                record["state"] = "CANCEL_REQUESTED"
                record["revision"] = str(prior_revision + 1)
                record["transition_reason"] = "deadline-expired"
                record["cancel_boundary_revision"] = str(prior_revision)
                record["last_transition"] = now_text()
                self.ledger.write()
            grace = datetime.fromisoformat(
                record["cancellation_grace_deadline"].replace("Z", "+00:00"))
            if now >= grace:
                record["state"] = "FAILED"
                record["revision"] = str(
                    u64(record["revision"], "revision", positive=True) + 1)
                record["last_transition"] = now_text()
                self.ledger.write()
                return self._status(record, nonce)
            engine = await self.engine.observe(operation_id, generation, nonce)
            self._validate_engine(engine, record, action="observe", nonce=nonce)
            prior = record["observations"][-1:] if record["observations"] else []
            sequence = u64(engine["observation_sequence"], "observation_sequence", positive=True)
            if prior and sequence <= u64(prior[0]["sequence"], "observation_sequence", positive=True):
                raise DrainError(502, "nonmonotonic_observation")
            observation = {
                "nonce": nonce, "sequence": str(sequence),
                "queues": engine["queues"],
                "hash": domain_digest("phorvex-drain-observation-v1", engine),
            }
            record["observations"] = (record["observations"] + [observation])[-2:]
            if (len(record["observations"]) == 2
                    and len({item["nonce"] for item in record["observations"]}) == 2
                    and all(self._zero_queues(item["queues"])
                            for item in record["observations"])
                    and all(value in ("aborted", "completed-before-abort")
                            for value in record["terminal_dispositions"].values())
                    and set(record["terminal_dispositions"]) == {
                        request_id for queues in record["engine_snapshot"].values()
                        for name in ("waiting", "running", "swapped", "cached")
                        for request_id in queues[name]
                    }):
                record["state"] = ("CANCELLED" if record["state"] == "CANCEL_REQUESTED"
                                   else "QUIESCENT")
            record["revision"] = str(u64(record["revision"], "revision", positive=True) + 1)
            record["last_transition"] = now_text()
            self.ledger.write()
            return self._status(record, nonce)

    async def cancel(self, generation, operation_id, owner_digest, incarnation, revision):
        u64(generation, "operation_generation", positive=True)
        expected = u64(revision, "revision", positive=True)
        if (not HEX32.fullmatch(operation_id)
                or not HEX64.fullmatch(owner_digest)
                or not HEX64.fullmatch(incarnation)):
            raise DrainError(400, "invalid_binding")
        async with self._lock:
            record = self._find(generation, operation_id)
            if record is None or record is not self.ledger.data["current"]:
                raise DrainError(404, "unknown_operation")
            if (record["owner_digest"] != owner_digest
                    or record["backend_incarnation_digest"] != incarnation):
                raise DrainError(409, "binding_mismatch")
            boundary = u64(record["cancel_boundary_revision"],
                           "cancel_boundary_revision")
            if record["state"] in ("CANCEL_REQUESTED", "CANCELLED", "FAILED"):
                if boundary == expected and boundary != 0:
                    return self._status(record)
                raise DrainError(409, "revision_conflict")
            if record["state"] not in ("CLOSING_ADMISSION", "DRAINING"):
                raise DrainError(409, "invalid_cancel_state")
            if u64(record["revision"], "revision", positive=True) != expected:
                raise DrainError(409, "revision_conflict")
            record["state"] = "CANCEL_REQUESTED"
            record["revision"] = str(expected + 1)
            record["transition_reason"] = "operator-requested"
            record["cancel_boundary_revision"] = str(expected)
            record["last_transition"] = now_text()
            self.ledger.write()
            return self._status(record)

    async def _intent(self, generation, operation_id, owner_digest, incarnation,
                      revision, state):
        u64(generation, "operation_generation", positive=True)
        u64(revision, "revision", positive=True)
        if (not HEX32.fullmatch(operation_id)
                or not HEX64.fullmatch(owner_digest)
                or not HEX64.fullmatch(incarnation)):
            raise DrainError(400, "invalid_binding")
        async with self._lock:
            record = self._find(generation, operation_id)
            if record is None or record is not self.ledger.data["current"]:
                raise DrainError(404, "unknown_operation")
            if record["state"] not in ("CLOSING_ADMISSION", "DRAINING",
                                       "CANCEL_REQUESTED"):
                raise DrainError(409, "invalid_cancel_state")
            if (record["owner_digest"] != owner_digest
                    or record["backend_incarnation_digest"] != incarnation):
                raise DrainError(409, "binding_mismatch")
            if record["revision"] != revision:
                raise DrainError(409, "revision_conflict")
            record["state"] = state
            record["revision"] = str(int(revision) + 1)
            record["last_transition"] = now_text()
            self.ledger.write()
            return self._status(record)

    async def reopen(self, generation, operation_id, owner_digest, incarnation, revision):
        u64(generation, "operation_generation", positive=True)
        u64(revision, "revision", positive=True)
        if (not HEX32.fullmatch(operation_id)
                or not HEX64.fullmatch(owner_digest)
                or not HEX64.fullmatch(incarnation)):
            raise DrainError(400, "invalid_binding")
        async with self._lock:
            record = self._find(generation, operation_id)
            if record is None or record is not self.ledger.data["current"]:
                raise DrainError(404, "unknown_operation")
            if (record["owner_digest"] != owner_digest
                    or record["backend_incarnation_digest"] != incarnation
                    or record["revision"] != revision):
                raise DrainError(409, "binding_or_revision_conflict")
            if record["state"] not in ("QUIESCENT", "CANCELLED"):
                raise DrainError(409, "not_quiescent")
            record["state"] = "REOPENING"
            record["revision"] = str(int(revision) + 1)
            record["last_transition"] = now_text()
            self.ledger.write()
            engine = await self.engine.reopen(operation_id, generation)
            self._validate_engine(engine, record, action="reopen")
            if engine["admission"] != "OPEN":
                raise DrainError(502, "engine_did_not_reopen")
            record["state"] = "OPENED"
            record["admission"] = "OPEN"
            record["revision"] = str(int(record["revision"]) + 1)
            record["last_transition"] = now_text()
            self.ledger.data["history"].append(record)
            self.ledger.data["current"] = None
            self.ledger.data["admission"] = "OPEN"
            self.ledger.write()
            self.admission_open = True
            return self._status(record)


def initialize_ledger(directory: Path, pod_uid: str, ledger_id: str):
    if not pod_uid or not HEX32.fullmatch(ledger_id):
        raise RuntimeError("invalid drain origin")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise RuntimeError("refusing to initialize nonempty drain directory")
    origin = {"schema": SCHEMA, "pod_uid": pod_uid, "ledger_id": ledger_id}
    ledger = {
        "schema": SCHEMA, "pod_uid": pod_uid, "ledger_id": ledger_id,
        "generation_high_water": "0", "admission": "OPEN",
        "current": None, "history": [],
    }
    for name, value in (("origin.json", origin), ("ledger.json", ledger)):
        path = directory / name
        with path.open("xb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
