#!/usr/bin/env python3
"""Real loopback HTTP controls for the sealed guardrail bridge; no cluster calls."""

import copy
from datetime import timedelta
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import bridge  # noqa: E402


def write_private(path, value):
    raw = value if isinstance(value, bytes) else bridge._wire(value)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


class BackendHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.calls.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        if self.server.behavior == "disconnect":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if self.server.behavior == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        response = b'{"id":"owned-local-result","choices":[{"message":{"content":"4"}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class Backend(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, behavior="ok"):
        super().__init__(("127.0.0.1", 0), BackendHandler)
        self.calls = []
        self.behavior = behavior
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)


class Fixture:
    def __init__(self, behavior="ok"):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.backend = Backend(behavior)
        self.canary = "CANARY-ABCDEFGHIJKLMNOPQRST"
        self.bodies = {slot: bridge.request_body("owned-model", self.canary, slot) for slot in bridge.SLOTS}
        now = bridge._now()
        self.manifest = {
            "schema": bridge.SCHEMA,
            "runNonce": "0123456789abcdef01234567",
            "runDir": str(self.dir),
            "createdAt": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(seconds=90)).isoformat().replace("+00:00", "Z"),
            "proxySourceSHA256": bridge.PROXY_SOURCE_SHA256,
            "fixture": {"namespace": "vllm", "podUID": "fixture-pod-uid-123", "proxyContainerID": "containerd://proxy-12345",
                        "bridgeContainerID": "containerd://bridge-12345", "proxyImageID": "image@sha256:proxy-12345",
                        "bridgeImageID": "image@sha256:bridge-12345"},
            "target": {"namespace": "vllm", "podName": "real-vllm-pod", "podUID": "target-pod-uid-456",
                       "podIP": "127.0.0.1", "containerID": "containerd://target-12345",
                       "imageID": "image@sha256:target-12345", "port": self.backend.server_port},
            "model": "owned-model", "canarySHA256": bridge._sha(self.canary.encode()),
            "requests": {slot: bridge._sha(body) for slot, body in self.bodies.items()},
        }
        self.manifest_sha = write_private(self.dir / "manifest.json", self.manifest)
        self.state = None
        self.server = None

    def attest(self, slot, phase, *, mutate=None, at=None):
        x = {"schema": bridge.SCHEMA, "manifestSHA256": self.manifest_sha, "slot": slot,
             "phase": phase, "observedAt": at or bridge._stamp(),
             "fixture": copy.deepcopy(self.manifest["fixture"]), "target": copy.deepcopy(self.manifest["target"]),
             "proxySourceSHA256": bridge.PROXY_SOURCE_SHA256}
        if mutate:
            mutate(x)
        return write_private(self.dir / f"attest-{slot}-{phase}.json", x)

    def start(self):
        self.state = bridge.BridgeState(self.dir, self.manifest_sha, self.manifest["fixture"]["podUID"], test_loopback=True)
        self.server = bridge.BridgeServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, slot="disclosure", *, body=None, path=bridge.FIXED_PATH, extra=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json", "X-Canary-Run": self.manifest["runNonce"], "X-Canary-Slot": slot}
        if extra:
            headers.update(extra)
        if host:
            headers["Host"] = host
        try:
            conn.request("POST", path, body=self.bodies.get(slot, b"") if body is None else body, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.state.close()
        self.backend.close()
        self.temp.cleanup()


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def tearDown(self):
        self.f.close()

    def test_real_http_forward_once_and_finalize_without_canary_in_evidence(self):
        self.f.attest("arithmetic", "before")
        self.f.start()
        status, response = self.f.request("arithmetic")
        self.assertEqual(status, 200)
        self.assertIn(b"owned-local-result", response)
        self.assertEqual(len(self.f.backend.calls), 1)
        call = self.f.backend.calls[0]
        self.assertEqual(call["path"], bridge.FIXED_PATH)
        self.assertEqual(call["body"], self.f.bodies["arithmetic"])
        self.assertNotIn("Authorization", call["headers"])
        self.assertNotIn("X-Canary-Run", call["headers"])
        self.assertIn("X-Canary-Request-ID", call["headers"])
        self.f.attest("arithmetic", "after")
        final = bridge.finalize(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], "arithmetic", test_loopback=True)
        self.assertEqual(final["status"], "ATTESTED_RESPONSE")
        self.assertEqual(final["httpStatus"], 200)
        self.assertNotIn(self.f.canary.encode(), (self.f.dir / "bridge-journal.jsonl").read_bytes())
        self.assertNotIn(self.f.canary.encode(), (self.f.dir / "final-arithmetic.json").read_bytes())
        with self.assertRaises(bridge.Refused):
            bridge.finalize(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], "arithmetic", test_loopback=True)

    def test_path_header_body_and_slot_refusals_never_reach_backend(self):
        self.f.attest("disclosure", "before")
        self.f.start()
        bad = [
            {"path": "/v1/models"},
            {"path": bridge.FIXED_PATH + "?url=http://elsewhere"},
            {"extra": {"Authorization": "Bearer owned-test"}},
            {"extra": {"X-Forwarded-Host": "example.invalid"}},
            {"host": "example.invalid"},
            {"body": self.f.bodies["say_ok"]},
            {"slot": "not-registered"},
        ]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs):
                status, _ = self.f.request(**kwargs)
                self.assertEqual(status, 409)
        self.assertEqual(self.f.backend.calls, [])
        self.assertEqual((self.f.dir / "bridge-journal.jsonl").read_bytes(), b"")

    def test_replayed_request_and_restarted_bridge_are_refused(self):
        self.f.attest("say_ok", "before")
        self.f.start()
        self.assertEqual(self.f.request("say_ok")[0], 200)
        self.assertEqual(self.f.request("say_ok")[0], 409)
        self.assertEqual(len(self.f.backend.calls), 1)
        with self.assertRaises(FileExistsError):
            bridge.BridgeState(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], test_loopback=True)

    def test_stale_or_mismatched_pre_attestation_refuses_before_intent(self):
        old = (bridge._now() - timedelta(seconds=20)).isoformat().replace("+00:00", "Z")
        self.f.attest("disclosure", "before", at=old)
        self.f.attest("arithmetic", "before", mutate=lambda x: x["target"].update(podUID="wrong-pod-uid-456"))
        self.f.start()
        self.assertEqual(self.f.request("disclosure")[0], 409)
        self.assertEqual(self.f.request("arithmetic")[0], 409)
        self.assertEqual(self.f.backend.calls, [])

    def test_post_target_drift_never_finalizes_positive(self):
        self.f.attest("say_ok", "before")
        self.f.start()
        self.assertEqual(self.f.request("say_ok")[0], 200)
        self.f.attest("say_ok", "after", mutate=lambda x: x["target"].update(containerID="containerd://replacement-12345"))
        with self.assertRaises(bridge.Refused):
            bridge.finalize(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], "say_ok", test_loopback=True)
        self.assertFalse((self.f.dir / "final-say_ok.json").exists())

    def test_redirect_is_not_followed_and_slot_is_nonreplayable(self):
        self.f.backend.behavior = "redirect"
        self.f.attest("disclosure", "before")
        self.f.start()
        self.assertEqual(self.f.request("disclosure")[0], 502)
        self.assertEqual(self.f.request("disclosure")[0], 409)
        self.assertEqual(len(self.f.backend.calls), 1)
        self.assertIn(b"UPSTREAM_REDIRECT", (self.f.dir / "bridge-journal.jsonl").read_bytes())

    def test_ambiguous_disconnect_retains_intent_without_retry(self):
        self.f.backend.behavior = "disconnect"
        self.f.attest("disclosure", "before")
        self.f.start()
        self.assertEqual(self.f.request("disclosure")[0], 502)
        self.assertEqual(self.f.request("disclosure")[0], 409)
        self.assertEqual(len(self.f.backend.calls), 1)
        self.f.attest("disclosure", "after")
        final = bridge.finalize(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], "disclosure", test_loopback=True)
        self.assertEqual(final["status"], "UNKNOWN_AFTER_DISPATCH")

    def test_manifest_source_loopback_duplicate_json_and_hardlink_fail_closed(self):
        self.assertRaises(bridge.Refused, bridge.load_manifest, self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"])
        self.f.manifest["proxySourceSHA256"] = "0" * 64
        (self.f.dir / "manifest.json").unlink()
        wrong_sha = write_private(self.f.dir / "manifest.json", self.f.manifest)
        self.assertRaises(bridge.Refused, bridge.load_manifest, self.f.dir, wrong_sha, self.f.manifest["fixture"]["podUID"], test_loopback=True)
        (self.f.dir / "manifest.json").unlink()
        dup = bridge._wire(self.f.manifest).rstrip(b"\n")[:-1] + b',"schema":"other"}'
        dup_sha = write_private(self.f.dir / "manifest.json", dup)
        self.assertRaises(bridge.Refused, bridge.load_manifest, self.f.dir, dup_sha, self.f.manifest["fixture"]["podUID"], test_loopback=True)
        os.link(self.f.dir / "manifest.json", self.f.dir / "manifest-link.json")
        self.assertRaises(bridge.Refused, bridge.load_manifest, self.f.dir, dup_sha, self.f.manifest["fixture"]["podUID"], test_loopback=True)

    def test_manifest_copied_to_another_private_run_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as other:
            copied = Path(other)
            digest = write_private(copied / "manifest.json", (self.f.dir / "manifest.json").read_bytes())
            self.assertEqual(digest, self.f.manifest_sha)
            with self.assertRaises(bridge.Refused):
                bridge.load_manifest(copied, digest, self.f.manifest["fixture"]["podUID"], test_loopback=True)

    def test_malformed_terminal_cannot_finalize_an_attested_response(self):
        self.f.attest("arithmetic", "before")
        self.f.start()
        self.assertEqual(self.f.request("arithmetic")[0], 200)
        self.f.attest("arithmetic", "after")
        journal = self.f.dir / "bridge-journal.jsonl"
        rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
        rows[-1]["responseSHA256"] = None
        journal.write_bytes(b"".join(bridge._wire(row) for row in rows))
        with self.assertRaises(bridge.Refused):
            bridge.finalize(self.f.dir, self.f.manifest_sha, self.f.manifest["fixture"]["podUID"], "arithmetic", test_loopback=True)

    def test_same_canary_but_changed_conversation_shape_rejected_even_if_rehashed(self):
        body = json.loads(self.f.bodies["disclosure"])
        body["messages"].append({"role": "user", "content": "unregistered"})
        altered = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.f.manifest["requests"]["disclosure"] = bridge._sha(altered)
        (self.f.dir / "manifest.json").unlink()
        self.f.manifest_sha = write_private(self.f.dir / "manifest.json", self.f.manifest)
        self.f.attest("disclosure", "before")
        self.f.start()
        self.assertEqual(self.f.request("disclosure", body=altered)[0], 409)
        self.assertEqual(self.f.backend.calls, [])


if __name__ == "__main__":
    unittest.main()
