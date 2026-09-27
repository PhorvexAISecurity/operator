import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SOURCE = Path(__file__).with_name("gateway.py")
spec = importlib.util.spec_from_file_location("litellm_live_gateway", SOURCE)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class Upstream(BaseHTTPRequestHandler):
    calls = 0
    master = "sk-real-master-only-in-process"

    def log_message(self, *_):
        pass

    def do_POST(self):
        type(self).calls += 1
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.headers.get("Authorization") != "Bearer " + self.master:
            self.reply(401, {"error": {"code": "invalid_api_key"}})
            return
        self.reply(200, {"object": "chat.completion", "id": "cmpl-real-upstream",
                         "choices": [{"message": {"role": "assistant", "content": "OK"}}],
                         "usage": {"total_tokens": 7}})

    def reply(self, status, value):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.attacker = "sk-test-owned-attacker-1234567890"
        self.control = "sk-test-owned-control-1234567890"
        self.attacker_sha = hashlib.sha256(self.attacker.encode()).hexdigest()
        self.control_sha = hashlib.sha256(self.control.encode()).hexdigest()
        self.clients = self.root / "clients.json"
        self.policy = self.root / "state.json"
        self.clients.write_text(json.dumps({"version": 1, "attackerSHA256": self.attacker_sha,
                                            "controlSHA256": self.control_sha,
                                            "modelAlias": "gpt-4o-mini"}))
        self.set_policy(False, 0, "")
        Upstream.calls = 0
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        self.g = gateway.Gateway(self.clients, self.policy, Upstream.master, "pod-uid",
                                 "cm-uid", hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                 "this-is-a-private-status-token-1234567890",
                                 upstream_port=self.upstream.server_address[1])
        bound = type("TestPublic", (gateway.PublicHandler,), {"gateway": self.g})
        self.public = ThreadingHTTPServer(("127.0.0.1", 0), bound)
        self.public_thread = threading.Thread(target=self.public.serve_forever, daemon=True)
        self.public_thread.start()
        self.addCleanup(self.public.server_close)
        self.addCleanup(self.public.shutdown)
        status_bound = type("TestStatus", (gateway.StatusHandler,), {"gateway": self.g})
        self.status_server = ThreadingHTTPServer(("127.0.0.1", 0), status_bound)
        self.status_thread = threading.Thread(target=self.status_server.serve_forever, daemon=True)
        self.status_thread.start()
        self.addCleanup(self.status_server.server_close)
        self.addCleanup(self.status_server.shutdown)

    def set_policy(self, active, revision, operation):
        temp = self.root / "next-state.json"
        temp.write_text(json.dumps({"version": 1, "active": active, "revision": revision,
                                    "operationId": operation, "clientSHA256": self.attacker_sha},
                                   separators=(",", ":"), sort_keys=True))
        temp.replace(self.policy)

    def post(self, bearer, model="gpt-4o-mini"):
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=5)
        try:
            body = json.dumps({"model": model, "messages": [{"role": "user", "content": "Say OK."}],
                               "max_tokens": 8, "stream": False}).encode()
            conn.request("POST", "/v1/chat/completions", body,
                         {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_original_work_revoke_repeat_and_benign_continuity(self):
        self.assertEqual(self.post(self.attacker)[0], 200)
        self.assertEqual(self.post(self.control)[0], 200)
        self.assertEqual(Upstream.calls, 2)
        before = self.g.status()
        self.assertEqual(before["counters"]["attacker"]["usageTokens"], 7)
        self.set_policy(True, 1, "selected-decision-operation")
        status, reply = self.post(self.attacker)
        self.assertEqual((status, reply["error"]["code"]), (429, "PHORVEX_CLIENT_REVOKED"))
        self.assertEqual(Upstream.calls, 2)  # No downstream work on replay.
        self.assertEqual(self.post(self.control)[0], 200)
        self.assertEqual(Upstream.calls, 3)
        after = self.g.status()
        self.assertTrue(after["ready"])
        self.assertEqual((after["active"], after["revision"], after["operationId"]),
                         (True, 1, "selected-decision-operation"))
        self.assertEqual(after["counters"]["attacker"]["deniedRequests"], 1)
        self.assertEqual(after["counters"]["control"]["upstreamCompletions"], 2)

    def test_invalid_bearer_stays_upstream_negative_not_defense(self):
        status, reply = self.post("sk-invalid-generated-1234567890")
        self.assertEqual(status, 401)
        self.assertEqual(reply["error"]["code"], "invalid_api_key")
        self.assertEqual(Upstream.calls, 1)
        self.assertEqual(self.g.status()["counters"]["attacker"]["deniedRequests"], 0)

    def test_existing_authorized_master_client_passes_through_real_upstream(self):
        status, reply = self.post(Upstream.master)
        self.assertEqual(status, 200)
        self.assertEqual(reply["id"], "cmpl-real-upstream")
        self.assertEqual(Upstream.calls, 1)
        self.assertEqual(self.g.status()["counters"]["attacker"]["forwardedRequests"], 0)

    def test_malformed_policy_fails_closed_without_forwarding(self):
        self.policy.write_text('{"version":1,"active":false,"active":true}')
        self.assertFalse(self.g.status()["ready"])
        self.assertEqual(self.post(self.attacker)[0], 503)
        self.assertEqual(Upstream.calls, 0)

    def test_source_and_client_authority_required(self):
        with self.assertRaisesRegex(ValueError, "source digest"):
            gateway.Gateway(self.clients, self.policy, Upstream.master, "pod", "cm", "0" * 64,
                            "this-is-a-private-status-token-1234567890")
        self.clients.write_text(json.dumps({"version": 1, "attackerSHA256": self.attacker_sha,
                                            "controlSHA256": self.attacker_sha,
                                            "modelAlias": "gpt-4o-mini"}))
        with self.assertRaisesRegex(ValueError, "owned-client authority"):
            gateway.Gateway(self.clients, self.policy, Upstream.master, "pod", "cm",
                            hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                            "this-is-a-private-status-token-1234567890")

    def test_status_requires_operator_only_token(self):
        for bearer, expected in (("", 401), ("wrong", 401),
                                 ("this-is-a-private-status-token-1234567890", 200)):
            conn = http.client.HTTPConnection("127.0.0.1", self.status_server.server_address[1], timeout=5)
            try:
                conn.request("GET", "/v1/admission/state",
                             headers={"Authorization": "Bearer " + bearer})
                response = conn.getresponse()
                self.assertEqual(response.status, expected)
                raw = response.read()
                if expected == 200:
                    value = json.loads(raw)
                    self.assertEqual((value["podUID"], value["configMapUID"], value["ready"]),
                                     ("pod-uid", "cm-uid", True))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
