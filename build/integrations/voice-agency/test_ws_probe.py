"""Offline transport-shape checks; no Voice workload or CRM connection."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("voice_agency_ws_probe", Path(__file__).with_name("ws_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeSocket:
    def __init__(self):
        self.sent = []

    async def send(self, raw):
        self.sent.append(json.loads(raw))

    async def recv(self):
        raise ConnectionError("offline fixture output ended")


class FakeConnect:
    def __init__(self, socket):
        self.socket = socket

    def __call__(self, url, **kwargs):
        if url != "ws://127.0.0.1:18080/ws" or kwargs.get("max_size") != 65536:
            raise AssertionError("transport was not bounded local Voice")
        return self

    async def __aenter__(self):
        return self.socket

    async def __aexit__(self, *_):
        return False


async def no_wait(_):
    await asyncio.get_running_loop().run_in_executor(None, lambda: None)


class VoiceAgencyWebSocketProbeTest(unittest.TestCase):
    def test_exact_media_start_and_no_prompt_injection(self):
        socket = FakeSocket()
        with patch.object(probe.asyncio, "sleep", no_wait):
            result = asyncio.run(probe.run_probe("ws://127.0.0.1:18080/ws", "agencya1", "attack",
                                                 connector=FakeConnect(socket)))
        self.assertEqual(result["phase"], "attack")
        self.assertEqual([x["event"] for x in socket.sent[:2]], ["connected", "start"])
        self.assertEqual(socket.sent[1]["start"]["customParameters"],
                         {"caller": probe.agency_phones("agencya1")[0], "agencyRunId": "agencya1"})
        self.assertEqual(socket.sent[1]["start"]["mediaFormat"],
                         {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1})
        self.assertEqual(len(socket.sent[1]["start"]["accountSid"]), 34)
        self.assertEqual(socket.sent[-1]["event"], "stop")
        media = [x for x in socket.sent if x["event"] == "media"]
        self.assertEqual(len(media), result["mediaFrames"])
        raw = b"".join(base64.b64decode(x["media"]["payload"]) for x in media)
        self.assertEqual(raw[:len(probe.clip("attack"))], probe.clip("attack"))
        self.assertTrue(all(len(base64.b64decode(x["media"]["payload"])) == 160 for x in media))
        self.assertNotIn("issue_refund", json.dumps(socket.sent))

    def test_refuses_remote_or_mutable_target(self):
        for url in ("ws://voice.example/ws", "ws://127.0.0.1:18080/other",
                    "wss://127.0.0.1:18080/ws", "ws://127.0.0.1:18080/ws?caller=other"):
            with self.assertRaises(ValueError):
                probe.checked_url(url)
        with self.assertRaises(ValueError):
            probe.identity("bad-id", "attack")


if __name__ == "__main__":
    unittest.main()
