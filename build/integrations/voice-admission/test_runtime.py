import asyncio
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import Response
from starlette.websockets import WebSocketDisconnect
from twilio.request_validator import RequestValidator

from entry import AdmissionApp, CURRENT_SESSION, FormValues, signature_valid
from policy import Authority, Pins, canonical, digest, load_profile


TOKEN = "owner-test-token-is-private-and-local"
STATE = b"s" * 48


def fixture():
    ids = [f"00000000-0000-4000-8000-{index:012d}" for index in range(1, 6)]
    profile = {"version": 1, "deploymentUID": ids[1], "publicHost": "voicebot.phorvex.ai",
               "websocketSigningURLs": ["wss://voicebot.phorvex.ai/ws"],
               "webhookSigningURL": "https://voicebot.phorvex.ai/", "twilioSecretName": "voice-secrets",
               "authTokenSHA256": digest(TOKEN.encode())}
    pins = Pins(*ids, "a" * 64, "b" * 64, digest(canonical(profile)))
    rule = {"version": 1, "deploymentUID": pins.deployment_uid, "securityPolicyUID": pins.security_policy_uid,
            "wrapperCMUID": pins.wrapper_cm_uid, "admissionSourceSHA256": pins.source_sha,
            "legacyBundleSHA256": pins.legacy_sha, "authProfileSHA256": pins.profile_sha,
            "revision": 0, "mode": "observe", "operationId": ""}
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "voice-session-admission-policy",
           "namespace": "voice", "uid": pins.policy_cm_uid, "resourceVersion": "10", "ownerReferences": [
               {"apiVersion": "apps/v1", "kind": "Deployment", "name": "voice-bot", "uid": pins.deployment_uid,
                "controller": True}]}, "data": {"rule.json": canonical(rule).decode()}}
    return pins, profile, obj


class Socket:
    def __init__(self, app, *, signed=False, run="admission123", send_hook=None):
        self.incoming, self.outgoing = asyncio.Queue(), asyncio.Queue()
        self.sent, self.accepted = [], asyncio.Event()
        headers = [(b"x-phorvex-admission-run", run.encode()), (b"host", b"untrusted.example")]
        if signed:
            headers.append((b"x-twilio-signature", RequestValidator(TOKEN).compute_signature(
                "wss://voicebot.phorvex.ai/ws", {}).encode()))
        scope = {"type": "websocket", "path": "/ws", "raw_path": b"/ws", "query_string": b"",
                 "scheme": "ws", "headers": headers}
        async def send(message):
            if send_hook:
                await send_hook(message)
            self.sent.append(copy.deepcopy(message))
            if message["type"] == "websocket.accept":
                self.accepted.set()
            await self.outgoing.put(message)
        self.task = asyncio.create_task(app(scope, self.incoming.get, send))
        self.incoming.put_nowait({"type": "websocket.connect"})
        self.run = run

    async def start(self):
        await asyncio.wait_for(self.accepted.wait(), 1)
        for value in ({"event": "connected"}, {"event": "start", "start": {"streamSid": "MSlocal", "callSid": "CAlocal",
                      "customParameters": {"admissionRunId": self.run}}}):
            await self.incoming.put({"type": "websocket.receive", "text": json.dumps(value)})

    async def media(self):
        await self.incoming.put({"type": "websocket.receive", "text": json.dumps({"event": "media", "streamSid": "MSlocal", "media": {
            "payload": base64.b64encode(b"audio").decode()}})})

    async def close(self):
        if not self.task.done():
            await self.incoming.put({"type": "websocket.disconnect", "code": 1000})
        await asyncio.wait_for(self.task, 2)


class RuntimeFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pins, self.profile, self.obj = fixture()
        self.failed = False
        def read():
            if self.failed:
                raise OSError("private API failure")
            return copy.deepcopy(self.obj)
        self.authority = Authority(self.pins, read)
        self.state_path = Path(self.temp.name) / "state-token"
        self.state_path.write_bytes(STATE)
        self.started, self.stopped, self.ticks = [], [], {}
        self.body = None
        delegate = FastAPI()

        @delegate.post("/")
        async def webhook(request: Request):
            self.body = await request.body()
            return Response(self.body, media_type="application/octet-stream")

        @delegate.websocket("/ws")
        async def websocket(ws: WebSocket):
            await ws.accept()
            try:
                for _ in range(2):
                    await ws.receive_text()
                session = CURRENT_SESSION.get()
                self.started.append(session.session_id)
                self.ticks[session.session_id] = 0
                async def producer():
                    try:
                        while True:
                            self.ticks[session.session_id] += 1
                            await ws.send_text(json.dumps({"event": "media", "media": {"payload": "YXVkaW8="}}))
                            await asyncio.sleep(0.005)
                    finally:
                        self.stopped.append(session.session_id)
                producing = asyncio.create_task(producer())
                try:
                    while True:
                        await ws.receive_text()
                finally:
                    producing.cancel()
                    await asyncio.gather(producing, return_exceptions=True)
            except WebSocketDisconnect:
                pass

        self.app = AdmissionApp(delegate, self.authority, self.profile, TOKEN,
                                directory=Path(self.temp.name) / "admission", state_token=self.state_path)
        self.sockets = []

    async def asyncTearDown(self):
        for socket in self.sockets:
            await socket.close()
        self.app.shutdown.set()
        self.app.write_event.set()
        await asyncio.gather(*(task for task in (self.app.poll_task, self.app.writer_task) if task), return_exceptions=True)

    async def socket(self, **kwargs):
        socket = Socket(self.app, **kwargs)
        self.sockets.append(socket)
        return socket

    def enforce(self):
        rule = json.loads(self.obj["data"]["rule.json"])
        rule.update(revision=1, mode="require-twilio-signature", operationId="c" * 64)
        self.obj["metadata"]["resourceVersion"] = "11"
        self.obj["data"]["rule.json"] = canonical(rule).decode()

    async def http(self, path, method="GET", body=b"", headers=None, query=b""):
        incoming = asyncio.Queue()
        await incoming.put({"type": "http.request", "body": body, "more_body": False})
        outgoing = []
        async def send(message):
            outgoing.append(message)
        await self.app({"type": "http", "path": path, "raw_path": path.encode(), "query_string": query,
                        "method": method, "headers": headers or []}, incoming.get, send)
        return outgoing[0]["status"], b"".join(message.get("body", b"") for message in outgoing)

    async def state(self):
        status, body = await self.http("/v1/voice-session-admission/state", headers=[(b"authorization", b"Bearer " + STATE)])
        return status, json.loads(body)

    async def until(self, predicate):
        async with asyncio.timeout(2):
            while not predicate():
                await asyncio.sleep(0.005)


class RuntimeTest(RuntimeFixture):
    async def test_active_delegate_runtime_error_propagates_without_completion_credit(self):
        async def failing(scope, receive, send):
            self.assertEqual((await receive())["type"], "websocket.connect")
            await send({"type": "websocket.accept"})
            await receive()  # connected
            await receive()  # admitted start
            self.assertEqual((await receive())["type"], "websocket.disconnect")
            raise RuntimeError("active-local-cleanup-failed")
        self.app.delegate = failing
        active = await self.socket()
        await active.start()
        await self.until(lambda: any(s.active for s in self.app.sessions.values()))
        session = next(iter(self.app.sessions.values()))
        self.enforce()
        await self.app.refresh()
        with self.assertRaisesRegex(RuntimeError, "active-local-cleanup-failed"):
            await asyncio.wait_for(active.task, 1)
        self.assertTrue(session.disconnect_delivered)
        self.assertFalse(session.completed)
        self.assertFalse(session.receipt()["delegateCompleted"])
        self.assertEqual(self.app.completions, 0)
        self.sockets.remove(active)

    async def test_transition_before_delegate_accept_closes_pending_without_initialization(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.app.delegate
        async def delayed(scope, receive, send):
            entered.set()
            await release.wait()
            await original(scope, receive, send)
        self.app.delegate = delayed
        pending = await self.socket(run="pending123")
        await asyncio.wait_for(entered.wait(), 1)
        self.assertEqual(len(self.app.sessions), 1)
        self.enforce()
        await self.app.refresh()
        release.set()
        await asyncio.wait_for(pending.task, 1)
        self.assertFalse(self.started)
        self.assertFalse(self.app.sessions)
        status, state = await self.state()
        self.assertEqual(status, 200)
        self.assertTrue(state["settled"])
        self.assertEqual(state["disconnectsDelivered"], 1)

    async def test_completed_retention_is_bounded_and_owned_cleanup_reclaims_protected_group(self):
        with patch("entry.MAX_RETAINED_SESSIONS", 8):
            active = await self.socket()
            await active.start()
            await active.media()
            await self.until(lambda: any(s.active and s.received and s.sent for s in self.app.sessions.values()))
            protected = next(iter(self.app.sessions.values()))
            protected.provider.update(sttFrames=1, modelTextFrames=1, modelCompletions=1, ttsAudioFrames=1,
                                      ttsAudioBytes=5, sttTextSHA256=digest(b"user"), modelTextSHA256=digest(b"model"))
            protected.retain_provider()
            await self.until(lambda: (self.app.directory / ("admission-exposure-" + protected.session_id + ".json")).exists())
            for _ in range(12):
                pending = await self.socket(run="completed123")
                await asyncio.wait_for(pending.accepted.wait(), 1)
                await pending.close()
                await self.until(lambda: not self.app.pending_writes and not self.app.write_busy)
            self.assertLessEqual(len(self.app.retained), 4)
            self.assertIn(protected.session_id, self.app.retained)
            self.assertTrue((self.app.directory / ("admission-exposure-" + protected.session_id + ".json")).exists())
            self.assertFalse(protected.completed)
            await active.close()
            await self.until(lambda: not self.app.pending_writes and not self.app.write_busy)
            for prefix in ("admission-session-", "admission-provider-", "admission-exposure-"):
                (self.app.directory / (prefix + protected.session_id + ".json")).unlink(missing_ok=True)
            await self.app.reclaim_owned_cleanup()
            self.assertNotIn(protected.session_id, self.app.retained)

    async def test_receipt_write_failure_cannot_credit_exposure_or_settled_state(self):
        socket = await self.socket()
        await socket.start()
        await self.until(lambda: any(s.active for s in self.app.sessions.values()))
        session = next(iter(self.app.sessions.values()))
        with patch.object(session, "write", side_effect=OSError("private disk failure")):
            session.retain()
            await self.until(lambda: self.app.receipt_error)
            await asyncio.wait_for(socket.task, 1)
        self.enforce()
        status, state = await self.state()
        self.assertEqual(status, 503)
        self.assertNotIn("settled", state)

    async def test_many_denied_handshakes_create_no_api_registry_or_disk_work(self):
        self.enforce()
        await self.app.refresh()
        self.app.ensure_poll()
        await asyncio.sleep(0.01)
        self.app.poll_task.cancel()
        await asyncio.gather(self.app.poll_task, return_exceptions=True)
        with patch.object(self.authority, "read", side_effect=AssertionError("denial called API")), \
                patch("entry.uuid.uuid4", side_effect=AssertionError("denial allocated session")):
            sockets = [await self.socket(run="denied1234") for _ in range(100)]
            await asyncio.gather(*(socket.task for socket in sockets))
        self.assertFalse(self.app.sessions)
        self.assertFalse(self.app.pending_writes)
        self.assertFalse(self.app.retained)
        self.assertFalse(self.started)
        self.assertFalse(self.app.directory.exists())
        signed = await self.socket(signed=True)
        await signed.start()
        await self.until(lambda: len(self.started) == 1)
        self.assertFalse(signed.task.done())

    async def test_exposure_pair_is_automatic_atomic_immutable_and_lifecycle_stays_current(self):
        socket = await self.socket()
        await socket.start()
        await socket.media()
        await self.until(lambda: any(s.active and s.received > 0 and s.sent > 0 for s in self.app.sessions.values()))
        session = next(s for s in self.app.sessions.values() if s.active)
        query = ("sessionID=" + session.session_id).encode()
        auth = [(b"authorization", b"Bearer " + STATE)]
        status, _ = await self.http("/v1/voice-session-admission/evidence", headers=auth, query=query)
        self.assertEqual(status, 404)
        session.provider.update(sttFrames=1, modelTextFrames=1, modelCompletions=1, ttsAudioFrames=1,
                                ttsAudioBytes=5, sttTextSHA256=digest(b"real user"), modelTextSHA256=digest(b"real model"))
        session.retain_provider()
        await self.until(lambda: (self.app.directory / ("admission-exposure-" + session.session_id + ".json")).exists())
        status, first = await self.http("/v1/voice-session-admission/evidence", headers=auth, query=query)
        self.assertEqual(status, 200)
        frozen = json.loads(first)
        self.assertEqual(frozen["session"]["stage"], "pipeline-observed")
        self.assertFalse(frozen["session"]["delegateCompleted"])
        session.provider["modelTextFrames"] += 1
        session.retain_provider()
        status, repeated = await self.http("/v1/voice-session-admission/evidence", headers=auth, query=query)
        self.assertEqual(first, repeated)
        self.enforce()
        await self.app.refresh()
        await asyncio.wait_for(socket.task, 1)
        status, current = await self.http("/v1/voice-session-admission/session", headers=auth, query=query)
        current = json.loads(current)
        self.assertTrue(current["disconnectDelivered"])
        self.assertTrue(current["delegateCompleted"])
        self.assertEqual(current["stage"], "closed")
        status, repeated = await self.http("/v1/voice-session-admission/evidence", headers=auth, query=query)
        self.assertEqual(first, repeated)


    async def test_pending_and_actual_producer_teardown_signed_session_survives(self):
        active = await self.socket()
        signed = await self.socket(signed=True)
        pending = await self.socket(run="pending123")
        await active.start()
        await signed.start()
        await self.until(lambda: len(self.started) == 2)
        unsigned_id = next(s.session_id for s in self.app.sessions.values() if s.active and not s.authenticated)
        signed_id = next(s.session_id for s in self.app.sessions.values() if s.active and s.authenticated)
        status, state = await self.state()
        self.assertEqual((status, state["pendingUnsigned"], state["activeUnsigned"]), (200, 1, 1))
        self.enforce()
        await self.app.refresh()
        await asyncio.wait_for(active.task, 1)
        await asyncio.wait_for(pending.task, 1)
        stopped_ticks = self.ticks[unsigned_id]
        signed_ticks = self.ticks[signed_id]
        await asyncio.sleep(0.03)
        self.assertIn(unsigned_id, self.stopped)
        self.assertEqual(self.ticks[unsigned_id], stopped_ticks)
        self.assertGreater(self.ticks[signed_id], signed_ticks)
        status, state = await self.state()
        self.assertEqual((status, state["pendingUnsigned"], state["activeUnsigned"], state["activeSigned"]), (200, 0, 0, 1))
        self.assertTrue(state["settled"])
        self.assertGreaterEqual(state["disconnectsDelivered"], 2)
        self.assertFalse(signed.task.done())
        rejected = await self.socket(run="rejected123")
        await asyncio.wait_for(rejected.task, 1)
        self.assertEqual(rejected.sent[0]["type"], "websocket.close")
        self.assertEqual(len(self.started), 2)

    async def test_backpressured_unsigned_send_cannot_stall_policy_or_signed_session(self):
        blocked = asyncio.Event()
        release = asyncio.Event()
        async def backpressure(message):
            if message["type"] == "websocket.send":
                blocked.set()
                await release.wait()
        active = await self.socket(send_hook=backpressure)
        signed = await self.socket(signed=True)
        pending = await self.socket(run="pending123")
        await active.start()
        await signed.start()
        await asyncio.wait_for(blocked.wait(), 1)
        self.enforce()
        await asyncio.wait_for(self.app.refresh(), 0.2)
        status, state = await asyncio.wait_for(self.state(), 0.2)
        self.assertEqual(status, 200)
        await asyncio.wait_for(pending.task, 1)
        await asyncio.wait_for(active.task, 1)
        self.assertFalse(signed.task.done())
        self.assertFalse(any(message["type"] == "websocket.send" for message in active.sent))
        release.set()

    async def test_second_start_gate_catches_transition_before_provider_initialization(self):
        pending = await self.socket()
        await asyncio.wait_for(pending.accepted.wait(), 1)
        self.enforce()
        # No explicit refresh: the start gate must read authoritative API itself.
        await pending.start()
        await asyncio.wait_for(pending.task, 1)
        self.assertFalse(self.started)

    async def test_read_failure_rejects_new_work_stops_unsigned_and_preserves_signed(self):
        active = await self.socket()
        signed = await self.socket(signed=True)
        await active.start()
        await signed.start()
        await self.until(lambda: len(self.started) == 2)
        self.failed = True
        status, state = await self.state()
        self.assertEqual(status, 503)
        self.assertNotIn("settled", state)
        await asyncio.wait_for(active.task, 1)
        self.assertFalse(signed.task.done())
        rejected = await self.socket(signed=True, run="newtrial12")
        await asyncio.wait_for(rejected.task, 1)
        self.assertEqual(rejected.sent[0]["code"], 1011)

    async def test_signed_webhook_duplicate_fields_verified_and_original_body_replayed(self):
        self.enforce()
        body = b"From=first&From=second&Blank=&Extra=new"
        params = FormValues(From=["first", "second"], Blank=[""], Extra=["new"])
        signature = RequestValidator(TOKEN).compute_signature("https://voicebot.phorvex.ai/", params).encode()
        headers = [(b"x-twilio-signature", signature), (b"content-type", b"application/x-www-form-urlencoded"),
                   (b"host", b"attacker.invalid"), (b"x-forwarded-host", b"attacker.invalid")]
        status, response = await self.http("/", "POST", body, headers)
        self.assertEqual((status, response, self.body), (200, body, body))
        status, _ = await self.http("/", "POST", b"From=first&Blank=&Extra=new", headers)
        self.assertEqual(status, 403)
        status, _ = await self.http("/", "POST", body, headers, query=b"x=1")
        self.assertEqual(status, 403)


class SignatureTest(unittest.TestCase):
    def test_canonical_authority_and_unsupported_request_shapes(self):
        pins, profile, _ = fixture()
        self.assertEqual(load_profile(canonical(profile), pins, TOKEN), profile)
        validator = RequestValidator(TOKEN)
        scope = {"type": "websocket", "path": "/ws", "raw_path": b"/ws", "query_string": b"", "headers": [
            (b"host", b"untrusted"), (b"x-twilio-signature", validator.compute_signature(profile["websocketSigningURLs"][0], {}).encode())]}
        self.assertTrue(signature_valid(scope, validator, profile))
        for change in ("query", "raw", "duplicate", "wrong-url"):
            bad = copy.deepcopy(scope)
            if change == "query":
                bad["query_string"] = b"secret=x"
            elif change == "raw":
                bad["raw_path"] = b"/%77s"
            elif change == "duplicate":
                bad["headers"].append(bad["headers"][1])
            else:
                bad["headers"][1] = (b"x-twilio-signature", validator.compute_signature("wss://untrusted/ws", {}).encode())
            self.assertFalse(signature_valid(bad, validator, profile), change)


if __name__ == "__main__":
    unittest.main()
