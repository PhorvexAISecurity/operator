"""Official signature verification and actual local WebSocket audio producers."""
import ast
import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import aiohttp
from aiohttp import web
from twilio.request_validator import RequestValidator

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "phorvex/internal/console"
spec = importlib.util.spec_from_file_location("admission_probe", CONSOLE / "voice_admission_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
URL = "wss://voicebot.phorvex.ai/ws"
TOKEN = "synthetic-offline-test-token-000000"


def legacy_signer(name):
    path = CONSOLE / f"voice_{name}_probe.py"
    parsed = ast.parse(path.read_text())
    nodes = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "production_ws_headers"]
    if len(nodes) != 1:
        raise AssertionError("fixed production signer missing")
    namespace = {"os": os}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["production_ws_headers"]


class OfficialSignatures(unittest.IsolatedAsyncioTestCase):
    async def test_every_fixed_probe_passes_actual_production_verifier(self):
        accepted = []
        async def handler(request):
            valid = RequestValidator(TOKEN).validate(URL, {}, request.headers.get("X-Twilio-Signature", ""))
            if not valid:
                return web.Response(status=403)
            accepted.append(True)
            ws = web.WebSocketResponse(); await ws.prepare(request)
            await ws.send_json({"event": "mark", "mark": {"name": "control"}})
            await ws.send_json({"event": "media", "streamSid": "MZ-test", "media": {"payload": "AQID"}})
            await ws.close(); return ws
        app = web.Application(); app.router.add_get("/ws", handler)
        runner = web.AppRunner(app); await runner.setup(); self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        port = site._server.sockets[0].getsockname()[1]
        with patch.dict(os.environ, {"PUBLIC_HOST": "voicebot.phorvex.ai", "TWILIO_AUTH_TOKEN": TOKEN}):
            for signer in [legacy_signer(name) for name in ("memory", "agency", "mcp", "output")] + [probe.signing_headers]:
                async with aiohttp.ClientSession(trust_env=False) as client:
                    async with client.ws_connect(f"http://127.0.0.1:{port}/ws", headers=signer()) as ws:
                        audio = []
                        async for message in ws:
                            if message.type == aiohttp.WSMsgType.TEXT:
                                audio.append(probe.audio_bytes(json.loads(message.data), "MZ-test"))
                        self.assertEqual(audio, [b"", b"\x01\x02\x03"])
                    with self.assertRaises(aiohttp.WSServerHandshakeError) as failure:
                        async with client.ws_connect(f"http://127.0.0.1:{port}/ws"):
                            pass
                    self.assertEqual(failure.exception.status, 403)
        self.assertEqual(len(accepted), 5)

    def test_canonical_url_and_token_mismatch_fail(self):
        signers = [legacy_signer(name) for name in ("memory", "agency", "mcp", "output")] + [probe.signing_headers]
        with patch.dict(os.environ, {"PUBLIC_HOST": "voicebot.phorvex.ai", "TWILIO_AUTH_TOKEN": TOKEN}):
            for signer in signers:
                signature = signer()["X-Twilio-Signature"]
                self.assertFalse(RequestValidator(TOKEN).validate("wss://other.invalid/ws", {}, signature))
                self.assertFalse(RequestValidator(TOKEN).validate(URL + "?x=1", {}, signature))
                self.assertFalse(RequestValidator("different-test-token").validate(URL, {}, signature))
        for host, token in (("attacker.invalid", TOKEN), ("voicebot.phorvex.ai", "")):
            with patch.dict(os.environ, {"PUBLIC_HOST": host, "TWILIO_AUTH_TOKEN": token}):
                for signer in signers:
                    with self.assertRaises((RuntimeError, ValueError)):
                        signer()

    def test_control_frames_cannot_be_counted_as_audio(self):
        for frame in ({"event": "mark"}, {"event": "clear"}, {"event": "text", "media": {"payload": "AQID"}}, []):
            self.assertEqual(probe.audio_bytes(frame, "MZ-test"), b"")
        for payload in ("", "invalid!", 1):
            with self.assertRaises((ValueError, TypeError)):
                probe.audio_bytes({"event": "media", "streamSid": "MZ-test", "media": {"payload": payload}}, "MZ-test")
        with self.assertRaises(ValueError):
            probe.audio_bytes({"event": "media", "streamSid": "other", "media": {"payload": "AQID"}}, "MZ-test")

    def test_worker_source_is_bounded_and_compiles(self):
        compile(probe.WORKER, "fixed-admission-worker", "exec")
        self.assertLessEqual((CONSOLE / "voice_admission_probe.py").stat().st_size, 24 << 10)
        self.assertNotIn("TWILIO_AUTH_TOKEN", probe.canonical({"safe": True}).decode())


if __name__ == "__main__":
    unittest.main()
