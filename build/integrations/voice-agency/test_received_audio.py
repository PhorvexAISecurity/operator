"""Actual local WebSocket producers exercise both reviewed audio drains."""

import ast
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web

import ws_probe


class ReceivedAudioProducerTests(unittest.IsolatedAsyncioTestCase):
    async def trial(self, embedded, frames):
        async def handler(request):
            socket = web.WebSocketResponse()
            await socket.prepare(request)
            async for incoming in socket:
                value = json.loads(incoming.data)
                if value.get("event") == "start":
                    stream = value["streamSid"]
                    for frame in frames:
                        if isinstance(frame, bytes):
                            await socket.send_bytes(frame)
                        elif isinstance(frame, str):
                            await socket.send_str(frame)
                        else:
                            frame = dict(frame)
                            if frame.get("streamSid") == "same":
                                frame["streamSid"] = stream
                            await socket.send_json(frame)
                if value.get("event") == "stop":
                    break
            await socket.close()
            return socket

        application = web.Application()
        application.router.add_get("/ws", handler)
        runner = web.AppRunner(application)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"ws://127.0.0.1:{port}/ws"
        original_sleep = asyncio.sleep

        async def bounded_test_sleep(delay):
            # Preserve time to drain the deliberately large bound fixtures.
            await original_sleep(0.1 if delay >= 1 else 0.001)

        with patch.object(asyncio, "sleep", bounded_test_sleep):
            if not embedded:
                return await ws_probe.run_probe(url, "agencya1", "benign")
            source = Path(__file__).resolve().parents[3] / "phorvex/internal/console/voice_agency_probe.py"
            parsed = ast.parse(source.read_text())
            nodes = [node for node in ast.walk(parsed) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name in ("received_audio", "session")]
            self.assertEqual(len(nodes), 2)
            namespace = {"asyncio": asyncio, "aiohttp": aiohttp, "base64": base64,
                         "hashlib": hashlib, "json": json, "production_ws_headers": lambda: {}, "phase": "benign", "confirmation": b"",
                         "confirmation_hash": hashlib.sha256(b"").hexdigest(), "sha": lambda s: hashlib.sha256(s.encode()).hexdigest(),
                         "canonical": lambda v: json.dumps(v, sort_keys=True, separators=(",", ":")).encode(),
                         "phase_baseline": lambda *args: (), "expected_refunds": [], "SESSION_SECONDS": 3, "FIRST_RESPONSE_SECONDS": 0.1,
                         "FINAL_RESPONSE_SECONDS": 0.1, "RESPONSE_QUIET_SECONDS": 0.02, "raw": b"\xff" * 160,
                         "stream": "MZ" + "A" * 32, "sid": "CA" + "A" * 32,
                         "account": "AC" + "A" * 32, "phones": ("+15550000001",), "run": "agencya1"}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
            original_connect = aiohttp.ClientSession.ws_connect

            def local_connect(client, target, **kwargs):
                self.assertEqual(target, "http://127.0.0.1:8080/ws")
                return original_connect(client, url, **kwargs)

            with patch.object(aiohttp.ClientSession, "ws_connect", local_connect):
                received, count, size, digest, _ = await namespace["session"]()
            return {"receivedFrames": received, "receivedAudioFrames": count,
                    "receivedAudioBytes": size, "receivedAudioSHA256": digest}

    async def test_actual_media_is_decoded_counted_and_hashed(self):
        chunks = (b"\x01\x02\x03", b"\x04\x05")
        frames = [{"event": "mark", "mark": {"name": "control"}}] + [
            {"event": "media", "streamSid": "same", "media": {"payload": base64.b64encode(chunk).decode()}}
            for chunk in chunks]
        for embedded in (False, True):
            with self.subTest(embedded=embedded):
                result = await self.trial(embedded, frames)
                self.assertEqual(result["receivedFrames"], 3)
                self.assertEqual(result["receivedAudioFrames"], 2)
                self.assertEqual(result["receivedAudioBytes"], 5)
                self.assertEqual(result["receivedAudioSHA256"], hashlib.sha256(b"".join(chunks)).hexdigest())

    async def test_actual_control_frame_does_not_credit_audio(self):
        for embedded in (False, True):
            result = await self.trial(embedded, [{"event": "mark", "mark": {"name": "done"}},
                                                {"event": "text", "text": "control text", "streamSid": "same",
                                                 "media": {"payload": "AQID"}}])
            self.assertEqual(result["receivedFrames"], 2)
            self.assertEqual(result["receivedAudioFrames"], 0)
            self.assertEqual(result["receivedAudioBytes"], 0)
            self.assertEqual(result["receivedAudioSHA256"], hashlib.sha256(b"").hexdigest())

    async def test_invalid_media_cannot_credit_audio(self):
        invalid = [
            {"event": "media", "streamSid": "other", "media": {"payload": "AQ=="}},
            {"event": "media", "streamSid": "same", "media": {"payload": ""}},
            {"event": "media", "streamSid": "same", "media": {"payload": "invalid!"}},
            {"event": "media", "streamSid": "same", "media": {"payload": 1}},
            {"event": "media", "streamSid": "same", "media": []},
            b"arbitrary binary is not Twilio media",
            "[]",
            "invalid JSON text",
        ]
        for embedded in (False, True):
            for frame in invalid:
                with self.subTest(embedded=embedded, frame=frame), self.assertRaises((ValueError, RuntimeError)):
                    await self.trial(embedded, [frame])

    async def test_actual_producer_cannot_exceed_audio_or_frame_bounds(self):
        audio = {"event": "media", "streamSid": "same",
                 "media": {"payload": base64.b64encode(b"\x01" * 32768).decode()}}
        for embedded in (False, True):
            for frames in ([audio] * 33, [{"event": "mark"}] * 1025):
                with self.subTest(embedded=embedded, frames=len(frames)), self.assertRaises((ValueError, RuntimeError)):
                    await self.trial(embedded, frames)


if __name__ == "__main__":
    unittest.main()
