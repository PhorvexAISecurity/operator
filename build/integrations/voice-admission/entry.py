"""Separately attested ASGI admission boundary around the unchanged Voice app."""

import asyncio
import base64
import contextvars
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import time
import uuid
from urllib.parse import parse_qsl

from twilio.request_validator import RequestValidator
from starlette.websockets import WebSocketDisconnect

from policy import Authority, KubernetesReader, PolicyUnavailable, MAX_VALUE_BYTES, canonical, digest, environment_pins, load_profile

POLL_SECONDS = 0.25
FIRST_FRAME_SECONDS = 240
MAX_FRAME_BYTES = 65536
MAX_SESSIONS = 128
MAX_RETAINED_SESSIONS = 256
MAX_COUNTER = 1_000_000_000
RECEIPT_DIR = Path("/var/lib/phorvex-voice-memory/admission")
STATE_TOKEN = Path("/etc/phorvex/voice-memory-state-token/token")
CURRENT_SESSION = contextvars.ContextVar("voice_admission_session", default=None)
RUN = re.compile(r"[a-z0-9]{8,24}\Z")


def now_ms():
    return time.time_ns() // 1_000_000


class FormValues(dict):
    """The official validator reads all values, including duplicate fields."""
    def getall(self, name):
        return self[name]


def header(scope, name):
    values = [value for key, value in scope.get("headers", []) if key.lower() == name]
    if len(values) != 1 or len(values[0]) > 2048:
        return ""
    try:
        return values[0].decode("ascii")
    except UnicodeError:
        return ""


def route(scope, path):
    return (scope.get("path") == path and scope.get("raw_path", path.encode()) == path.encode() and
            not scope.get("query_string", b"") and not scope.get("root_path", ""))


def signature_valid(scope, validator, profile, body=None):
    signature = header(scope, b"x-twilio-signature")
    if not signature:
        return False
    try:
        if scope["type"] == "websocket" and route(scope, "/ws"):
            return validator.validate(profile["websocketSigningURLs"][0], {}, signature)
        if scope["type"] == "http" and scope.get("method") == "POST" and route(scope, "/"):
            content_type = header(scope, b"content-type").split(";", 1)[0].strip().lower()
            if content_type != "application/x-www-form-urlencoded" or body is None:
                return False
            values = FormValues()
            for key, value in parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                                        encoding="utf-8", errors="strict", max_num_fields=256):
                values.setdefault(key, []).append(value)
            return validator.validate(profile["webhookSigningURL"], values, signature)
    except (ValueError, TypeError, UnicodeError):
        pass
    return False


@dataclass
class Session:
    pins: object
    rule: dict
    rule_sha: str
    authenticated: bool
    directory: Path
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    connected: int = field(default_factory=now_ms)
    run_sha: str = field(default_factory=lambda: digest(b""))
    call_sha: str = ""
    stream_sid: str = ""
    active: bool = False
    received: int = 0
    sent: int = 0
    sent_bytes: int = 0
    disconnect_delivered: bool = False
    completed: bool = False
    disconnected: int = 0
    stage: str = "pending"
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    provider: dict = field(default_factory=lambda: {"sttFrames": 0, "modelTextFrames": 0, "modelCompletions": 0,
                                                   "ttsAudioFrames": 0, "ttsAudioBytes": 0,
                                                   "sttTextSHA256": "", "modelTextSHA256": ""})
    exposure: dict | None = None
    submit: object = None
    live_observe: object = None

    def identities(self):
        return {"version": 1, "sessionID": self.session_id, "runSHA256": self.run_sha, "callSIDHash": self.call_sha,
                "podUID": self.pins.pod_uid, "deploymentUID": self.pins.deployment_uid,
                "admissionSourceSHA256": self.pins.source_sha, "legacyBundleSHA256": self.pins.legacy_sha,
                "authProfileSHA256": self.pins.profile_sha}

    def write(self, prefix, value):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or (self.directory.stat().st_mode & 0o077):
            raise PolicyUnavailable("admission-receipt-unavailable")
        raw = canonical(value)
        if len(raw) > (MAX_VALUE_BYTES * 2 if prefix == "admission-exposure-" else MAX_VALUE_BYTES):
            raise PolicyUnavailable("admission-receipt-unavailable")
        temporary = self.directory / ("." + prefix + self.session_id + ".tmp")
        path = self.directory / (prefix + self.session_id + ".json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)

    def retain(self):
        self.submit(self, "admission-session-", self.receipt())
        self.maybe_freeze()

    def receipt(self):
        return self.identities() | {
            "admissionRuleSHA256": self.rule_sha, "admissionRevision": self.rule["revision"],
            "authenticated": self.authenticated, "connectedAtUnixMs": self.connected, "observedAtUnixMs": now_ms(),
            "disconnectedAtUnixMs": self.disconnected, "stage": self.stage,
            "receivedAudioFrames": self.received, "sentAudioFrames": self.sent, "sentAudioBytes": self.sent_bytes,
            "disconnectDelivered": self.disconnect_delivered, "delegateCompleted": self.completed}

    def retain_provider(self):
        self.submit(self, "admission-provider-", self.provider_receipt())
        self.maybe_freeze()

    def provider_receipt(self):
        return self.identities() | {"observedAtUnixMs": now_ms()} | self.provider

    def maybe_freeze(self):
        if (self.exposure is None and self.run_sha != digest(b"") and not self.authenticated and self.active and not self.completed and
                not self.stop.is_set() and self.stage == "pipeline-observed" and not self.disconnected and
                self.live_observe() and self.rule["revision"] == 0 and
                self.received > 0 and self.sent > 0 and self.sent_bytes > 0 and
                all(self.provider[key] > 0 for key in ("sttFrames", "modelTextFrames", "modelCompletions",
                                                      "ttsAudioFrames", "ttsAudioBytes"))):
            pair = {"session": self.receipt(), "provider": self.provider_receipt()}
            self.exposure = pair
            # One atomic pair commit; readers cannot observe half-written hashes.
            self.submit(self, "admission-exposure-", pair)


def instrument_bot(bot):
    """Append a passive installed Pipecat observer; original pipeline stays intact."""
    from pipecat.observers.base_observer import BaseObserver
    from pipecat.frames.frames import TranscriptionFrame, LLMTextFrame, LLMFullResponseEndFrame, TTSAudioRawFrame
    original = bot.PipelineTask

    class ProviderObserver(BaseObserver):
        def __init__(self, session):
            super().__init__()
            self.session = session

        async def on_push_frame(self, data):
            session, source, frame = self.session, data.source, data.frame
            if session.completed:
                return
            values = session.provider
            changed = False
            if isinstance(source, bot.DeepgramSTTService) and type(frame) is TranscriptionFrame:
                if isinstance(frame.text, str) and 0 < len(frame.text.encode()) <= MAX_FRAME_BYTES:
                    values["sttFrames"] += 1
                    values["sttTextSHA256"] = digest(frame.text.encode())
                    changed = True
            elif isinstance(source, bot.OpenAILLMService):
                if type(frame) is LLMTextFrame and isinstance(frame.text, str) and 0 < len(frame.text.encode()) <= MAX_FRAME_BYTES:
                    values["modelTextFrames"] += 1
                    values["modelTextSHA256"] = digest(frame.text.encode())
                    changed = True
                elif type(frame) is LLMFullResponseEndFrame:
                    values["modelCompletions"] += 1
                    changed = True
            elif isinstance(source, bot.ElevenLabsTTSService) and type(frame) is TTSAudioRawFrame and frame.audio:
                values["ttsAudioFrames"] += 1
                values["ttsAudioBytes"] += len(frame.audio)
                changed = True
            if changed:
                if any(value > MAX_COUNTER for value in values.values() if isinstance(value, int)):
                    session.stop.set()
                    return
                session.retain_provider()

    class ObservedPipelineTask(original):
        def __init__(self, *args, **kwargs):
            session = CURRENT_SESSION.get()
            if session is not None:
                kwargs["observers"] = list(kwargs.get("observers") or []) + [ProviderObserver(session)]
            super().__init__(*args, **kwargs)

    bot.PipelineTask = ObservedPipelineTask
    return original


class AdmissionApp:
    def __init__(self, delegate, authority, profile, token, *, directory=RECEIPT_DIR, state_token=STATE_TOKEN):
        self.delegate, self.authority, self.profile = delegate, authority, profile
        self.validator = RequestValidator(token)
        self.directory, self.state_token = directory, state_token
        self.sessions = {}
        self.lock = asyncio.Lock()
        self.refresh_lock = asyncio.Lock()
        self.healthy = False
        self.rule = self.sha = self.rv = None
        self.poll_task = None
        self.shutdown = asyncio.Event()
        self.disconnects = self.completions = 0
        self.pending_writes = {}
        self.write_event = asyncio.Event()
        self.writer_task = None
        self.receipt_error = False
        self.write_busy = False
        self.retained = {}
        self.storage_full = False
        if self.directory.exists():
            # Bound even restart discovery. Existing exposure groups are retained
            # until explicit run-owned cleanup; only closed non-exposure groups
            # are eligible for automatic pruning.
            for index, path in enumerate(self.directory.iterdir()):
                if index >= MAX_RETAINED_SESSIONS * 4:
                    self.storage_full = True
                    break
                match = re.fullmatch(r"admission-(session|provider|exposure)-([0-9a-f-]{36})\.json", path.name)
                if match:
                    kind, identity = match.groups()
                    item = self.retained.setdefault(identity, {"session": None, "protected": False})
                    item["protected"] |= kind == "exposure"
            self.storage_full |= len(self.retained) >= MAX_RETAINED_SESSIONS

    def submit(self, session, prefix, value):
        if session.run_sha == digest(b""):
            return  # ordinary production sessions create no persistent fixtures
        self.retained.setdefault(session.session_id, {"session": session, "protected": False})
        if prefix == "admission-exposure-":
            self.retained[session.session_id]["protected"] = True
        # Canonical bytes freeze the snapshot. Per-path coalescing bounds work to
        # three tiny pending objects per session, independent of frame rate.
        self.pending_writes[(prefix, session.session_id)] = (session, prefix, json.loads(canonical(value)))
        self.write_event.set()

    async def writer(self):
        while not self.shutdown.is_set() or self.pending_writes:
            await self.write_event.wait()
            await asyncio.sleep(0.02)
            work, self.pending_writes = self.pending_writes, {}
            self.write_event.clear()
            self.write_busy = True
            for session, prefix, value in work.values():
                try:
                    await asyncio.to_thread(session.write, prefix, value)
                except Exception:
                    async with self.lock:
                        self.receipt_error = True
                        self.healthy = False
                        for current in self.sessions.values():
                            if not current.authenticated:
                                current.stop.set()
            self.write_busy = False
            if len(self.retained) > MAX_RETAINED_SESSIONS // 2:
                removable = [identity for identity, item in self.retained.items() if not item["protected"] and
                             (item["session"] is None or item["session"].completed)]
                removable = removable[:max(0, len(self.retained) - MAX_RETAINED_SESSIONS // 2)]
                for identity in removable:
                    for key in list(self.pending_writes):
                        if key[1] == identity:
                            del self.pending_writes[key]
                def prune():
                    for identity in removable:
                        for prefix in ("admission-session-", "admission-provider-"):
                            (self.directory / (prefix + identity + ".json")).unlink(missing_ok=True)
                try:
                    await asyncio.to_thread(prune)
                    for identity in removable:
                        self.retained.pop(identity, None)
                except OSError:
                    self.receipt_error = True

    async def refresh(self):
        async with self.refresh_lock:
            try:
                rule, sha, rv = await asyncio.to_thread(self.authority.read)
            except PolicyUnavailable:
                async with self.lock:
                    self.healthy = False
                    for session in self.sessions.values():
                        if not session.authenticated:
                            session.stop.set()
                raise
            async with self.lock:
                self.rule, self.sha, self.rv, self.healthy = rule, sha, rv, not self.receipt_error
                if rule["revision"] == 1:
                    for session in self.sessions.values():
                        if not session.authenticated:
                            session.stop.set()
            return rule, sha, rv

    async def reclaim_owned_cleanup(self):
        if self.write_busy:
            return
        candidates = [identity for identity, item in self.retained.items() if item["session"] is None or item["session"].completed]
        def absent():
            return [identity for identity in candidates if not any((self.directory / (prefix + identity + ".json")).exists()
                for prefix in ("admission-session-", "admission-provider-", "admission-exposure-"))]
        for identity in await asyncio.to_thread(absent):
            if not self.write_busy and not any(key[1] == identity for key in self.pending_writes):
                self.retained.pop(identity, None)

    async def poll(self):
        while not self.shutdown.is_set():
            try:
                await self.refresh()
            except PolicyUnavailable:
                pass
            try:
                await asyncio.wait_for(self.shutdown.wait(), POLL_SECONDS)
            except asyncio.TimeoutError:
                pass

    def ensure_poll(self):
        if self.poll_task is None:
            self.poll_task = asyncio.create_task(self.poll())
        if self.writer_task is None:
            self.writer_task = asyncio.create_task(self.writer())

    async def response(self, send, status, body):
        raw = canonical(body)
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": raw})

    async def state(self, scope, send):
        try:
            token = self.state_token.read_bytes()
            require_token = 32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token)
            supplied = header(scope, b"authorization").encode("ascii")
            if not require_token:
                return await self.response(send, 503, {"error": "admission-state-unavailable"})
            if not hmac.compare_digest(supplied, b"Bearer " + token):
                return await self.response(send, 401, {"error": "unauthorized"})
            await self.refresh()
            if self.receipt_error:
                raise PolicyUnavailable("admission-receipt-unavailable")
        except (OSError, PolicyUnavailable):
            return await self.response(send, 503, {"error": "admission-policy-unavailable"})
        async with self.lock:
            unsigned = [s for s in self.sessions.values() if not s.authenticated and not s.completed]
            pending = sum(not s.active for s in unsigned)
            active = sum(s.active for s in unsigned)
            enforcing = self.rule["revision"] == 1
            body = {"version": 1, "podUID": self.authority.pins.pod_uid, "deploymentUID": self.authority.pins.deployment_uid,
                    "policyCMUID": self.authority.pins.policy_cm_uid, "policyResourceVersion": self.rv,
                    "ruleSHA256": self.sha, "revision": self.rule["revision"], "mode": self.rule["mode"],
                    "operationId": self.rule["operationId"], "admissionSourceSHA256": self.authority.pins.source_sha,
                    "legacyBundleSHA256": self.authority.pins.legacy_sha, "authProfileSHA256": self.authority.pins.profile_sha,
                    "observedAtUnixMs": now_ms(), "pendingUnsigned": pending, "activeUnsigned": active,
                    "activeSigned": sum(s.authenticated and s.active and not s.completed for s in self.sessions.values()),
                    "transitionPending": enforcing and bool(unsigned), "settled": enforcing and not unsigned,
                    "disconnectsDelivered": self.disconnects, "delegatesCompleted": self.completions}
        return await self.response(send, 200, body)

    async def evidence(self, scope, send):
        try:
            token = self.state_token.read_bytes()
            if not (32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token)):
                return await self.response(send, 503, {"error": "admission-state-unavailable"})
            if not hmac.compare_digest(header(scope, b"authorization").encode(), b"Bearer " + token):
                return await self.response(send, 401, {"error": "unauthorized"})
            raw = scope.get("query_string", b"").decode("ascii")
            if not raw.startswith("sessionID="):
                raise ValueError()
            session_id = raw[len("sessionID="):]
            if str(uuid.UUID(session_id)) != session_id or raw != "sessionID=" + session_id:
                raise ValueError()
            if not (scope.get("method") == "GET" and scope.get("raw_path") == b"/v1/voice-session-admission/evidence"):
                raise ValueError()
            path = self.directory / ("admission-exposure-" + session_id + ".json")
            def read_pair():
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as receipt:
                    return receipt.read(MAX_VALUE_BYTES * 2 + 1)
            body = await asyncio.to_thread(read_pair)
            if not body or len(body) > MAX_VALUE_BYTES * 2 or self.receipt_error:
                raise ValueError()
            pair = json.loads(body)
            if set(pair) != {"session", "provider"} or canonical(pair) != body:
                raise ValueError()
            for value in pair.values():
                if value["sessionID"] != session_id or len(canonical(value)) > MAX_VALUE_BYTES:
                    raise ValueError()
            return await self.response(send, 200, pair)
        except FileNotFoundError:
            return await self.response(send, 404, {"error": "admission-exposure-unavailable"})
        except (ValueError, OSError, KeyError, UnicodeError):
            return await self.response(send, 400, {"error": "unsupported-request"})

    async def session_state(self, scope, send):
        try:
            token = self.state_token.read_bytes()
            if not (32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token)):
                return await self.response(send, 503, {"error": "admission-state-unavailable"})
            if not hmac.compare_digest(header(scope, b"authorization").encode(), b"Bearer " + token):
                return await self.response(send, 401, {"error": "unauthorized"})
            raw = scope.get("query_string", b"").decode("ascii")
            session_id = raw.removeprefix("sessionID=")
            if raw != "sessionID=" + str(uuid.UUID(session_id)) or scope.get("method") != "GET" or \
                    scope.get("raw_path") != b"/v1/voice-session-admission/session":
                raise ValueError()
            async with self.lock:
                session = self.sessions.get(session_id) or self.retained.get(session_id, {}).get("session")
                body = session.receipt() if session else None
            if body is None:
                path = self.directory / ("admission-session-" + session_id + ".json")
                def read():
                    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as receipt:
                        return receipt.read(MAX_VALUE_BYTES + 1)
                data = await asyncio.to_thread(read)
                if not data or len(data) > MAX_VALUE_BYTES:
                    raise ValueError()
                body = json.loads(data)
                if canonical(body) != data or body["sessionID"] != session_id:
                    raise ValueError()
            return await self.response(send, 200, body)
        except FileNotFoundError:
            return await self.response(send, 404, {"error": "admission-session-unavailable"})
        except (OSError, ValueError, UnicodeError, KeyError):
            return await self.response(send, 400, {"error": "unsupported-request"})

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            async def lifespan_send(message):
                if message["type"] == "lifespan.startup.complete":
                    try:
                        await self.refresh()
                    except PolicyUnavailable:
                        return await send({"type": "lifespan.startup.failed", "message": "admission-policy-unavailable"})
                    self.ensure_poll()
                elif message["type"] == "lifespan.shutdown.complete":
                    self.shutdown.set()
                    self.write_event.set()
                    if self.poll_task:
                        await self.poll_task
                    if self.writer_task:
                        await self.writer_task
                await send(message)
            return await self.delegate(scope, receive, lifespan_send)
        self.ensure_poll()
        if scope["type"] == "websocket":
            if not route(scope, "/ws"):
                return await send({"type": "websocket.close", "code": 1008})
            return await self.websocket(scope, receive, send)
        if scope["type"] != "http":
            return await self.delegate(scope, receive, send)
        if scope.get("path") == "/v1/voice-session-admission/evidence":
            return await self.evidence(scope, send)
        if scope.get("path") == "/v1/voice-session-admission/session":
            return await self.session_state(scope, send)
        if scope.get("path") == "/v1/voice-session-admission/state":
            if scope.get("method") != "GET" or not route(scope, "/v1/voice-session-admission/state"):
                return await self.response(send, 400, {"error": "unsupported-request"})
            return await self.state(scope, send)
        if scope.get("path") == "/healthz":
            try:
                await self.refresh()
                if not self.healthy:
                    raise PolicyUnavailable("admission-receipt-unavailable")
            except PolicyUnavailable:
                return await self.response(send, 503, {"error": "admission-policy-unavailable"})
        if scope.get("method") == "POST" and scope.get("path") == "/":
            if not route(scope, "/"):
                return await self.response(send, 403, {"error": "admission-rejected"})
            body = bytearray()
            while True:
                message = await asyncio.wait_for(receive(), FIRST_FRAME_SECONDS)
                if message["type"] != "http.request":
                    return await self.response(send, 400, {"error": "unsupported-request"})
                body.extend(message.get("body", b""))
                if len(body) > MAX_FRAME_BYTES:
                    return await self.response(send, 413, {"error": "request-too-large"})
                if not message.get("more_body"):
                    break
            try:
                await self.refresh()
            except PolicyUnavailable:
                return await self.response(send, 503, {"error": "admission-policy-unavailable"})
            if self.rule["revision"] == 1 and not signature_valid(scope, self.validator, self.profile, bytes(body)):
                return await self.response(send, 403, {"error": "admission-rejected"})
            consumed = False
            async def replay():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()
            return await self.delegate(scope, replay, send)
        return await self.delegate(scope, receive, send)

    async def websocket(self, scope, receive, send):
        signed = signature_valid(scope, self.validator, self.profile)
        # Enforce is a validated one-way transition. Once observed, unsigned
        # denial needs no API request, UUID, registry entry or persistent work.
        if self.rule and self.rule["revision"] == 1 and not signed:
            return await send({"type": "websocket.close", "code": 1008})
        try:
            rule, sha, _ = await self.refresh()
        except PolicyUnavailable:
            return await send({"type": "websocket.close", "code": 1011})
        pending_run = header(scope, b"x-phorvex-admission-run")
        if pending_run:
            await self.reclaim_owned_cleanup()
        async with self.lock:
            if (not self.healthy or (self.rule["revision"] == 1 and not signed) or len(self.sessions) >= MAX_SESSIONS or
                    (pending_run and (not RUN.fullmatch(pending_run) or self.storage_full or
                                      len(self.retained) >= MAX_RETAINED_SESSIONS))):
                rejected = True
            else:
                rejected = False
                session = Session(self.authority.pins, rule, sha, signed, self.directory)
                session.submit = self.submit
                session.live_observe = lambda: self.healthy and self.rule["revision"] == 0
                session.run_sha = digest(pending_run.encode())
                self.sessions[session.session_id] = session
                session.retain()
        if rejected:
            return await send({"type": "websocket.close", "code": 1008})

        async def disconnect():
            async with self.lock:
                if not session.disconnect_delivered:
                    session.disconnect_delivered = True
                    self.disconnects = min(MAX_COUNTER, self.disconnects + 1)
                    session.retain()
            return {"type": "websocket.disconnect", "code": 1008}

        async def guarded_receive():
            if session.stop.is_set():
                return await disconnect()
            incoming = asyncio.create_task(receive())
            stopped = asyncio.create_task(session.stop.wait())
            try:
                timeout = None if session.active else max(0, FIRST_FRAME_SECONDS - (now_ms() - session.connected) / 1000)
                done, _ = await asyncio.wait((incoming, stopped), timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
                if session.stop.is_set() or incoming not in done:
                    session.stop.set()
                    return await disconnect()
                message = incoming.result()
            finally:
                for task in (incoming, stopped):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(incoming, stopped, return_exceptions=True)
            if message["type"] == "websocket.disconnect":
                return await disconnect()
            if message["type"] != "websocket.receive":
                return message
            text = message.get("text")
            if not isinstance(text, str) or len(text.encode()) > MAX_FRAME_BYTES:
                session.stop.set()
                return await disconnect()
            try:
                value = json.loads(text)
            except (ValueError, TypeError):
                session.stop.set()
                return await disconnect()
            if not isinstance(value, dict):
                session.stop.set()
                return await disconnect()
            if value.get("event") == "start":
                try:
                    await self.refresh()  # second authoritative gate immediately before delegation
                except PolicyUnavailable:
                    return await disconnect()
                async with self.lock:
                    if session.stop.is_set() or not self.healthy or (self.rule["revision"] == 1 and not signed) or session.active:
                        session.stop.set()
                        denied = True
                    else:
                        denied = False
                        start = value.get("start", {})
                        if not isinstance(start, dict):
                            session.stop.set()
                            start = {}
                        custom = start.get("customParameters", {})
                        if not isinstance(custom, dict):
                            session.stop.set()
                            custom = {}
                        run = custom.get("admissionRunId", "") if isinstance(custom, dict) else ""
                        sid = start.get("callSid", "")
                        stream = start.get("streamSid", "")
                        if (session.stop.is_set() or not isinstance(run, str) or (run and not RUN.fullmatch(run)) or
                                (pending_run and run != pending_run) or
                                (run and session.session_id not in self.retained and
                                 (self.storage_full or len(self.retained) >= MAX_RETAINED_SESSIONS)) or
                                not isinstance(sid, str) or not 1 <= len(sid) <= 128 or
                                not isinstance(stream, str) or not 1 <= len(stream) <= 128):
                            session.stop.set()
                            denied = True
                        else:
                            session.active = not session.stop.is_set()
                            session.run_sha, session.call_sha = digest(run.encode()), digest(sid.encode())
                            session.stream_sid = stream
                            session.retain()
                if denied:
                    return await disconnect()
            elif value.get("event") == "media":
                try:
                    if not session.active or value.get("streamSid") != session.stream_sid or \
                            not base64.b64decode(value["media"]["payload"], validate=True):
                        raise ValueError()
                except (ValueError, TypeError, KeyError):
                    session.stop.set()
                    return await disconnect()
                session.received = min(MAX_COUNTER, session.received + 1)
                session.retain()
            return message

        closed = False
        async def guarded_send(message):
            nonlocal closed
            async with self.lock:
                if session.stop.is_set() or (not signed and self.rule["revision"] == 1):
                    return  # suppress every unsigned outbound message after the atomic barrier
            audio = b""
            if message["type"] == "websocket.send" and message.get("text"):
                try:
                    value = json.loads(message["text"])
                    if not isinstance(value, dict):
                        raise ValueError()
                    if value.get("event") == "media":
                        audio = base64.b64decode(value["media"]["payload"], validate=True)
                except (ValueError, TypeError, KeyError):
                    session.stop.set()
                    return
            async def deliver():
                if not session.stop.is_set():
                    await send(message)
                    return True
                return False
            # Never hold the global registry lock across network backpressure.
            sending = asyncio.create_task(deliver())
            stopped = asyncio.create_task(session.stop.wait())
            try:
                done, _ = await asyncio.wait((sending, stopped), return_when=asyncio.FIRST_COMPLETED)
                delivered = sending in done and sending.result()
            finally:
                for task in (sending, stopped):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(sending, stopped, return_exceptions=True)
            if not delivered:
                return
            async with self.lock:
                if message["type"] == "websocket.close":
                    closed = True
                if audio:
                    session.sent = min(MAX_COUNTER, session.sent + 1)
                    session.sent_bytes = min(MAX_COUNTER, session.sent_bytes + len(audio))
                    session.stage = "pipeline-observed"
                    session.retain()

        context = CURRENT_SESSION.set(session)
        completed = False
        try:
            await self.delegate(scope, guarded_receive, guarded_send)
            completed = True
        except WebSocketDisconnect:
            completed = True  # legacy receive_text exits normally on injected disconnect
        except RuntimeError as error:
            if not (not session.active and session.stop.is_set() and session.disconnect_delivered and
                    str(error) == 'Expected ASGI message "websocket.connect", but got \'websocket.disconnect\''):
                raise
            # A transition can win before the delegate receives ASGI connect.
            # Starlette then rejects the injected disconnect in its connect state.
            completed = True
        finally:
            CURRENT_SESSION.reset(context)
            async with self.lock:
                session.completed, session.disconnected, session.stage = completed, now_ms(), "closed"
                if completed:
                    self.completions = min(MAX_COUNTER, self.completions + 1)
                session.retain()
                self.sessions.pop(session.session_id, None)
            if not closed:
                try:
                    await send({"type": "websocket.close", "code": 1000 if signed else 1008})
                except RuntimeError:
                    pass  # ASGI server has already closed the disconnected socket.


def create_application():
    import sys
    from importlib import metadata
    if metadata.version("twilio") != "9.8.4" or metadata.version("pipecat-ai") != "0.0.94":
        raise PolicyUnavailable("admission-dependency-unreviewed")
    pins = environment_pins()
    token = os.environ["TWILIO_AUTH_TOKEN"]
    profile = load_profile((Path("/opt/voice-admission") / "auth-profile.json").read_bytes(), pins, token)
    authority = Authority(pins, KubernetesReader())
    authority.read()  # fail before importing the delegated provider application
    sys.path.insert(0, "/app")
    import bot
    instrument_bot(bot)
    return AdmissionApp(bot.app, authority, profile, token)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_application(), host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
