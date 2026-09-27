"""Optional durable caller admission for the public vLLM proxy listener.

The named Kubernetes ConfigMap is the effective policy on every request. The
immutable Secret and its projected bytes provide only credential material; no
local file or previous successful read can authorize a caller on API failure.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Awaitable, Callable

import httpx


POLICY_NAME = "phorvex-endpoint-lease-policy"
SECRET_NAME = "phorvex-endpoint-lease-keys"
SECRET_KEYS = frozenset(("client-a", "client-b", "seed"))
STATE_KEYS = frozenset(("version", "revision", "serviceUID", "proxySourceSHA256",
                        "secretUID", "seedSHA256", "allowedClientHMACs",
                        "revokedClientHMACs", "lastOperationID"))
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OPERATION_ID = re.compile(r"[0-9a-f]{32,64}\Z")
MAX_STATE = 16 * 1024
MAX_API = 64 * 1024
MAX_REVISION = (1 << 53) - 1
SA_ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class AuthorityUnavailable(Exception):
    """A trusted current policy, source, or Secret could not be established."""


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AuthorityUnavailable("duplicate JSON key")
        value[key] = item
    return value


def _json(raw: bytes):
    if len(raw) > MAX_API:
        raise AuthorityUnavailable("API document exceeds bound")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AuthorityUnavailable("invalid API JSON") from exc


def source_sha256(proxy: bytes, boundary: bytes, lease: bytes,
                  drain: bytes, drain_init: bytes) -> str:
    return hashlib.sha256(b"\0".join((proxy, boundary, lease, drain,
                                       drain_init))).hexdigest()


def parse_state(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_STATE:
        raise AuthorityUnavailable("policy size differs")
    value = _json(raw)
    if not isinstance(value, dict) or set(value) != STATE_KEYS or canonical(value) != raw:
        raise AuthorityUnavailable("noncanonical policy")
    if type(value["version"]) is not int or value["version"] != 1 or \
            type(value["revision"]) is not int or not 0 <= value["revision"] <= MAX_REVISION:
        raise AuthorityUnavailable("policy version or revision differs")
    if not all(isinstance(value[key], str) and UID.fullmatch(value[key])
               for key in ("serviceUID", "secretUID")) or \
            not all(isinstance(value[key], str) and SHA.fullmatch(value[key])
                    for key in ("proxySourceSHA256", "seedSHA256")):
        raise AuthorityUnavailable("policy identity differs")
    allowed, revoked = value["allowedClientHMACs"], value["revokedClientHMACs"]
    if not all(isinstance(rows, list) and all(isinstance(x, str) and SHA.fullmatch(x)
                                              for x in rows) and rows == sorted(set(rows))
               for rows in (allowed, revoked)) or \
            not allowed or len(allowed) + len(revoked) != 2 or \
            set(allowed) & set(revoked):
        raise AuthorityUnavailable("policy roster differs")
    operation = value["lastOperationID"]
    if not isinstance(operation, str) or \
            (value["revision"] == 0 and (operation or revoked)) or \
            (value["revision"] > 0 and not OPERATION_ID.fullmatch(operation)):
        raise AuthorityUnavailable("policy operation differs")
    return value


def _metadata(value: dict, kind: str, name: str, uid: str) -> None:
    if not isinstance(value, dict) or value.get("kind") != kind or \
            not isinstance(value.get("metadata"), dict):
        raise AuthorityUnavailable("Kubernetes object shape differs")
    meta = value["metadata"]
    if meta.get("namespace") != "vllm" or meta.get("name") != name or \
            meta.get("uid") != uid or meta.get("deletionTimestamp"):
        raise AuthorityUnavailable("Kubernetes object identity differs")


def _secret_bytes(value: dict, uid: str) -> dict[str, bytes]:
    _metadata(value, "Secret", SECRET_NAME, uid)
    if value.get("immutable") is not True or not isinstance(value.get("data"), dict) or \
            set(value["data"]) != SECRET_KEYS or value.get("stringData"):
        raise AuthorityUnavailable("Secret shape differs")
    result = {}
    for key in SECRET_KEYS:
        encoded = value["data"][key]
        if not isinstance(encoded, str):
            raise AuthorityUnavailable("Secret encoding differs")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise AuthorityUnavailable("Secret encoding differs") from exc
        if base64.b64encode(raw).decode("ascii") != encoded or \
                not 32 <= len(raw) <= 256 or \
                (key != "seed" and any(byte < 33 or byte > 126 for byte in raw)):
            raise AuthorityUnavailable("Secret credential shape differs")
        result[key] = raw
    if len(set(result.values())) != len(SECRET_KEYS):
        raise AuthorityUnavailable("Secret credentials collide")
    return result


def _mounted_secret(directory: Path) -> dict[str, bytes]:
    """Pin one Kubernetes projection generation for all three key reads."""
    root = directory.resolve(strict=True)
    anchor = root / "..data"
    generation = anchor.resolve(strict=True)
    if generation.parent != root or not generation.name.startswith(".."):
        raise AuthorityUnavailable("Secret projection changed")
    result = {}
    for key in SECRET_KEYS:
        descriptor = os.open(generation / key, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 256:
                raise AuthorityUnavailable("Secret projection is invalid")
            result[key] = os.read(descriptor, 257)
        finally:
            os.close(descriptor)
    if anchor.resolve(strict=True) != generation:
        raise AuthorityUnavailable("Secret projection changed during read")
    return result


class KubernetesReader:
    """Bounded exact-name API reads with projected service-account authority."""

    def __init__(self, base_url: str | None = None, token_file: Path | None = None,
                 ca_file: Path | None = None):
        self.base_url = base_url or "https://kubernetes.default.svc:443"
        self.token_file = token_file or SA_ROOT / "token"
        self.ca_file = ca_file or SA_ROOT / "ca.crt"

    async def __call__(self, kind: str) -> dict:
        if kind == "policy":
            path = f"/api/v1/namespaces/vllm/configmaps/{POLICY_NAME}"
        elif kind == "secret":
            path = f"/api/v1/namespaces/vllm/secrets/{SECRET_NAME}"
        else:
            raise AuthorityUnavailable("unknown API resource")
        token = self.token_file.read_bytes()
        if not 1 <= len(token) <= 16 * 1024 or b"\n" in token.strip():
            raise AuthorityUnavailable("service-account token differs")
        context = ssl.create_default_context(cafile=str(self.ca_file))
        async with httpx.AsyncClient(verify=context, trust_env=False,
                                     follow_redirects=False,
                                     timeout=httpx.Timeout(2.0, connect=1.0)) as client:
            async with client.stream("GET", self.base_url + path,
                                     headers={"Authorization": "Bearer " + token.decode().strip(),
                                              "Accept": "application/json"}) as response:
                if response.status_code != 200 or \
                        not response.headers.get("content-type", "").startswith("application/json"):
                    raise AuthorityUnavailable("named Kubernetes API read failed")
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_API:
                        raise AuthorityUnavailable("named Kubernetes API response exceeds bound")
                    chunks.append(chunk)
        value = _json(b"".join(chunks))
        if not isinstance(value, dict):
            raise AuthorityUnavailable("named Kubernetes API shape differs")
        return value


@dataclass(frozen=True)
class Identity:
    pod_uid: str
    service_uid: str
    policy_configmap_uid: str
    secret_uid: str
    source_sha256: str
    source_actual_sha256: str
    secret_dir: Path


@dataclass(frozen=True)
class Snapshot:
    rule: dict
    state_sha256: str
    client_hmacs: frozenset[str]
    seed: bytes


@dataclass(frozen=True)
class Admission:
    status: int
    revision: int = -1
    client_hmac: str = ""


class EndpointLease:
    def __init__(self, identity: Identity,
                 read_api: Callable[[str], Awaitable[dict]] | None = None):
        self.identity = identity
        self.read_api = read_api or KubernetesReader()
        self._lock = asyncio.Lock()
        self._max_revision = -1
        self._max_state_sha256 = ""
        self._inflight: dict[tuple[int, str], int] = {}

    async def _current(self) -> Snapshot:
        ident = self.identity
        if not all(UID.fullmatch(value) for value in (
                ident.pod_uid, ident.service_uid, ident.policy_configmap_uid,
                ident.secret_uid)) or \
                not SHA.fullmatch(ident.source_sha256) or \
                ident.source_actual_sha256 != ident.source_sha256:
            raise AuthorityUnavailable("proxy source or UID differs")
        policy = await self.read_api("policy")
        _metadata(policy, "ConfigMap", POLICY_NAME, ident.policy_configmap_uid)
        if not isinstance(policy.get("data"), dict) or set(policy["data"]) != {"state.json"} or \
                policy.get("binaryData") or not isinstance(policy["data"]["state.json"], str):
            raise AuthorityUnavailable("policy ConfigMap shape differs")
        raw = policy["data"]["state.json"].encode("utf-8")
        rule = parse_state(raw)
        if (rule["serviceUID"] != ident.service_uid or
                rule["secretUID"] != ident.secret_uid or
                rule["proxySourceSHA256"] != ident.source_sha256):
            raise AuthorityUnavailable("policy binding differs")
        secret = _secret_bytes(await self.read_api("secret"), ident.secret_uid)
        if _mounted_secret(ident.secret_dir) != secret or \
                hashlib.sha256(secret["seed"]).hexdigest() != rule["seedSHA256"]:
            raise AuthorityUnavailable("Secret authority differs")
        ids = frozenset(hmac.new(secret["seed"], secret[key], hashlib.sha256).hexdigest()
                        for key in ("client-a", "client-b"))
        if len(ids) != 2 or ids != set(rule["allowedClientHMACs"] + rule["revokedClientHMACs"]):
            raise AuthorityUnavailable("policy roster does not match Secret")
        state_sha = hashlib.sha256(raw).hexdigest()
        if rule["revision"] < self._max_revision or \
                (rule["revision"] == self._max_revision and
                 state_sha != self._max_state_sha256):
            raise AuthorityUnavailable("policy revision replayed or drifted")
        self._max_revision = rule["revision"]
        self._max_state_sha256 = state_sha
        return Snapshot(rule, state_sha, ids, secret["seed"])

    async def _maybe_current(self) -> Snapshot | None:
        try:
            async with asyncio.timeout(5):
                return await self._current()
        except Exception:
            # A malformed API object or mounted projection is unavailable
            # authority. Cancellation still propagates (it is BaseException).
            return None

    async def ready(self) -> bool:
        async with self._lock:
            return await self._maybe_current() is not None

    async def admit(self, authorization: list[bytes]) -> Admission:
        if len(authorization) != 1 or not authorization[0].startswith(b"Bearer "):
            return Admission(401)
        bearer = authorization[0][7:]
        if not 32 <= len(bearer) <= 256 or any(byte < 33 or byte > 126 for byte in bearer):
            return Admission(401)
        async with self._lock:
            snapshot = await self._maybe_current()
            if snapshot is None:
                return Admission(503)
            client_id = hmac.new(snapshot.seed, bearer, hashlib.sha256).hexdigest()
            if not any(hmac.compare_digest(client_id, value)
                       for value in snapshot.rule["allowedClientHMACs"]):
                return Admission(401)
            key = snapshot.rule["revision"], client_id
            current = self._inflight.get(key, 0)
            if current >= MAX_REVISION:
                return Admission(503)
            self._inflight[key] = current + 1
            return Admission(200, *key)

    async def finish(self, admission: Admission) -> None:
        if admission.status != 200:
            return
        async with self._lock:
            key = admission.revision, admission.client_hmac
            count = self._inflight.get(key, 0)
            if count <= 1:
                self._inflight.pop(key, None)
            else:
                self._inflight[key] = count - 1

    async def status(self, revoked: str, retained: str) -> dict | None:
        if not SHA.fullmatch(revoked) or not SHA.fullmatch(retained) or revoked == retained:
            return None
        async with self._lock:
            snapshot = await self._maybe_current()
            if snapshot is None or revoked not in snapshot.client_hmacs or \
                    retained not in snapshot.client_hmacs:
                return None
            rule = snapshot.rule
            old_inflight = sum(count for (rev, _), count in self._inflight.items()
                               if rev < rule["revision"])
            if old_inflight > MAX_REVISION:
                return None
            return {"version": 1, "ready": True,
                    "podUID": self.identity.pod_uid,
                    "serviceUID": rule["serviceUID"],
                    "policyConfigMapUID": self.identity.policy_configmap_uid,
                    "secretUID": rule["secretUID"],
                    "proxySourceSHA256": rule["proxySourceSHA256"],
                    "seedSHA256": rule["seedSHA256"],
                    "stateSHA256": snapshot.state_sha256,
                    "revision": rule["revision"],
                    "lastOperationID": rule["lastOperationID"],
                    "revokedClientHMAC": revoked,
                    "retainedClientHMAC": retained,
                    "revokedClientAllowed": revoked in rule["allowedClientHMACs"],
                    "retainedClientAllowed": retained in rule["allowedClientHMACs"],
                    "oldRevisionInFlight": old_inflight}
