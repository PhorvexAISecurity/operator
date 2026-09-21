from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

import httpx
import websockets


SOURCE = Path(os.environ.get("LOADGEN_SOURCE", Path(__file__).with_name("loadgen.py")))
SPEC = importlib.util.spec_from_file_location("voice_loadgen_under_test", SOURCE)
loadgen = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = loadgen
SPEC.loader.exec_module(loadgen)


class FixedRandom:
    def random(self) -> float:
        return 0.5

    def choice(self, values):
        return values[0]

    def choices(self, values, **_kwargs):
        return [values[0]]

    def uniform(self, low: float, _high: float) -> float:
        return low


class VoiceFixture:
    def __init__(self, scenario: str, twiml_status: int = 200):
        self.scenario = scenario
        self.twiml_status = twiml_status
        self.ws_connections = 0
        self.saw_start = False
        self.saw_stop = False
        self.start_seen = asyncio.Event()
        self.http_server = None
        self.ws_server = None

    async def __aenter__(self):
        self.ws_server = await websockets.serve(self._ws, "127.0.0.1", 0)
        ws_port = self.ws_server.sockets[0].getsockname()[1]
        self.ws_url = f"ws://127.0.0.1:{ws_port}/ws"
        self.http_server = await asyncio.start_server(self._http, "127.0.0.1", 0)
        http_port = self.http_server.sockets[0].getsockname()[1]
        self.http_url = f"http://127.0.0.1:{http_port}"
        return self

    async def __aexit__(self, *_exc):
        self.http_server.close()
        await self.http_server.wait_closed()
        self.ws_server.close()
        await self.ws_server.wait_closed()

    async def _http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await asyncio.wait_for(reader.readline(), 2)
            content_length = 0
            while True:
                header = await asyncio.wait_for(reader.readline(), 2)
                if header in (b"\r\n", b"\n", b""):
                    break
                name, _, value = header.partition(b":")
                if name.lower() == b"content-length":
                    content_length = int(value.strip())
            if content_length:
                await asyncio.wait_for(reader.readexactly(content_length), 2)
            if self.twiml_status == 200:
                if self.scenario == "twiml-malformed":
                    body = b"<Response><Connect>"
                elif self.scenario == "twiml-wrong-host":
                    body = b'<Response><Connect><Stream url="ws://example.invalid/ws" /></Connect></Response>'
                elif self.scenario == "twiml-oversized":
                    body = b" " * (loadgen.VOICE_MAX_TWIML_BYTES + 1)
                elif self.scenario == "distinct-route":
                    body = b'<Response><Connect><Stream url="wss://voice.example.test/ws" /></Connect></Response>'
                else:
                    body = (
                        '<?xml version="1.0"?><Response><Connect><Stream url="'
                        + self.ws_url
                        + '" /></Connect></Response>'
                    ).encode()
            else:
                body = b"upstream unavailable"
            reason = b"OK" if self.twiml_status == 200 else b"Service Unavailable"
            writer.write(
                b"HTTP/1.1 "
                + str(self.twiml_status).encode()
                + b" "
                + reason
                + b"\r\nContent-Type: text/xml\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def _ws(self, ws):
        self.ws_connections += 1
        stream_sid = None
        sent_scenario_response = False
        async for raw in ws:
            msg = json.loads(raw)
            event = msg.get("event")
            if event == "start":
                self.saw_start = True
                stream_sid = msg["start"]["streamSid"]
                self.start_seen.set()
                if self.scenario == "malformed-json":
                    await ws.send("{")
                    sent_scenario_response = True
                elif self.scenario == "invalid-base64":
                    await ws.send(json.dumps({"event": "media", "streamSid": stream_sid, "media": {"payload": "***"}}))
                    sent_scenario_response = True
                elif self.scenario == "wrong-stream":
                    payload = base64.b64encode(b"valid-audio").decode()
                    await ws.send(
                        json.dumps({"event": "media", "streamSid": "MZ-wrong", "media": {"payload": payload}})
                    )
                    sent_scenario_response = True
                elif self.scenario == "oversized":
                    limit = getattr(loadgen, "VOICE_MAX_MEDIA_FRAME_BYTES", 64 * 1024)
                    payload = base64.b64encode(b"x" * (limit + 1)).decode()
                    await ws.send(
                        json.dumps({"event": "media", "streamSid": stream_sid, "media": {"payload": payload}})
                    )
                    sent_scenario_response = True
                elif self.scenario == "early-close":
                    await ws.close(code=1000, reason="fixture early close")
                    return
                elif self.scenario == "receiver-error":
                    await ws.close(code=1011, reason="fixture receiver error")
                    return
            elif event == "media" and self.scenario in {"valid", "distinct-route"} and not sent_scenario_response:
                payload = base64.b64encode(b"valid-audio").decode()
                await ws.send(json.dumps({"event": "media", "streamSid": stream_sid, "media": {"payload": payload}}))
                sent_scenario_response = True
            elif event == "stop":
                self.saw_stop = True
                return


def counter(name: str, **labels: str) -> float:
    key = (name, tuple(sorted(labels.items())))
    return loadgen.M._counters.get(key, 0.0)


def voice_attempts() -> float:
    return sum(v for (name, _labels), v in loadgen.M._counters.items() if name == "loadgen_voice_call_attempts_total")


class VoiceOracleIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loadgen.M = loadgen.Metrics()
        loadgen.ECHO = loadgen.EchoCorpus()
        loadgen.VOICE_USE_ECHO = False
        loadgen.FRAME_SECONDS = 0
        loadgen.silence_ulaw = lambda _seconds: bytes([loadgen.ULAW_SILENCE]) * loadgen.FRAME_SAMPLES

        async def no_think(_low, _high):
            return None

        async def one_frame_tts(_text, _rng):
            return b"\x7f" * loadgen.FRAME_SAMPLES

        loadgen.think = no_think
        loadgen.tts_ulaw = one_frame_tts

    async def run_scenario(self, scenario: str, twiml_status: int = 200):
        async with VoiceFixture(scenario, twiml_status) as fixture:
            loadgen.VOICE_URL = fixture.http_url
            loadgen.VOICE_WS_URL = fixture.ws_url
            if hasattr(loadgen, "VOICE_TWIML_STREAM_HOST"):
                loadgen.VOICE_TWIML_STREAM_HOST = (
                    "voice.example.test" if scenario == "distinct-route" else "127.0.0.1"
                )
            async with httpx.AsyncClient(timeout=5) as client:
                await asyncio.wait_for(loadgen.voice_session(loadgen.Ctx(client, FixedRandom())), 5)
            return fixture

    async def test_silent_peer_not_successful(self):
        fixture = await self.run_scenario("silent")
        self.assertTrue(fixture.saw_start)
        # This is the baseline discriminator: the old source increments voice/ok
        # after a send-only session; the repaired path must not.
        self.assertEqual(counter("loadgen_sessions_total", app="voice", outcome="ok"), 0)
        if hasattr(loadgen, "VOICE_OUTCOME_REASONS"):
            self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="missing-media"), 1)
            self.assertEqual(voice_attempts(), 1)

    async def test_valid_bidirectional_media_and_legitimate_stop(self):
        fixture = await self.run_scenario("valid")
        self.assertTrue(fixture.saw_start)
        self.assertTrue(fixture.saw_stop)
        self.assertEqual(
            counter("loadgen_voice_call_attempts_total", outcome="success", reason="bidirectional-media"), 1
        )
        self.assertEqual(counter("loadgen_sessions_total", app="voice", outcome="voice-bidirectional"), 1)
        self.assertEqual(counter("loadgen_voice_valid_media_frames_total"), 1)
        self.assertGreater(counter("loadgen_voice_valid_media_bytes_total"), 0)
        self.assertEqual(counter("loadgen_voice_calls_total", outcome="ok"), 0)
        self.assertEqual(counter("loadgen_sessions_total", app="voice", outcome="ok"), 0)
        self.assertEqual(voice_attempts(), 1)

    async def test_public_twiml_route_validates_while_client_uses_internal_endpoint(self):
        fixture = await self.run_scenario("distinct-route")
        self.assertEqual(fixture.ws_connections, 1)
        self.assertEqual(
            counter("loadgen_voice_call_attempts_total", outcome="success", reason="bidirectional-media"), 1
        )

    async def test_malformed_json_refused(self):
        await self.run_scenario("malformed-json")
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="invalid-json"), 1)
        self.assertEqual(voice_attempts(), 1)

    async def test_invalid_base64_refused(self):
        await self.run_scenario("invalid-base64")
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="invalid-media"), 1)
        self.assertEqual(voice_attempts(), 1)

    async def test_wrong_stream_refused(self):
        await self.run_scenario("wrong-stream")
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="wrong-stream"), 1)
        self.assertEqual(voice_attempts(), 1)

    async def test_clean_early_close_refused(self):
        await self.run_scenario("early-close")
        self.assertEqual(
            counter("loadgen_voice_call_attempts_total", outcome="failure", reason="early-close"),
            1,
            loadgen.M._counters,
        )
        self.assertEqual(voice_attempts(), 1)

    async def test_receiver_error_refused(self):
        await self.run_scenario("receiver-error")
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="ws-receive"), 1)
        self.assertEqual(voice_attempts(), 1)

    async def test_failed_twiml_never_opens_websocket(self):
        fixture = await self.run_scenario("valid", twiml_status=503)
        self.assertEqual(fixture.ws_connections, 0)
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="twiml-http"), 1)
        self.assertEqual(voice_attempts(), 1)

    async def test_malformed_twiml_never_opens_websocket(self):
        fixture = await self.run_scenario("twiml-malformed")
        self.assertEqual(fixture.ws_connections, 0)
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="twiml-invalid"), 1)

    async def test_unexpected_twiml_stream_never_opens_websocket(self):
        fixture = await self.run_scenario("twiml-wrong-host")
        self.assertEqual(fixture.ws_connections, 0)
        self.assertEqual(
            counter("loadgen_voice_call_attempts_total", outcome="failure", reason="twiml-stream-contract"),
            1,
        )

    async def test_oversized_twiml_never_opens_websocket(self):
        fixture = await self.run_scenario("twiml-oversized")
        self.assertEqual(fixture.ws_connections, 0)
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="twiml-too-large"), 1)

    async def test_oversized_media_refused_without_retention(self):
        await self.run_scenario("oversized")
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="receive-limit"), 1)
        self.assertEqual(counter("loadgen_voice_valid_media_bytes_total"), 0)
        self.assertEqual(voice_attempts(), 1)

    async def test_cancellation_records_one_attempt_and_propagates(self):
        async with VoiceFixture("silent") as fixture:
            loadgen.VOICE_URL = fixture.http_url
            loadgen.VOICE_WS_URL = fixture.ws_url
            if hasattr(loadgen, "VOICE_TWIML_STREAM_HOST"):
                loadgen.VOICE_TWIML_STREAM_HOST = "127.0.0.1"
            async with httpx.AsyncClient(timeout=5) as client:
                task = asyncio.create_task(loadgen.voice_session(loadgen.Ctx(client, FixedRandom())))
                await asyncio.wait_for(fixture.start_seen.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertEqual(counter("loadgen_voice_call_attempts_total", outcome="failure", reason="cancelled"), 1)
        self.assertEqual(voice_attempts(), 1)


if __name__ == "__main__":
    unittest.main()
