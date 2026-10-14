"""Real gateway entrypoint smoke with synthetic local upstream and no live services."""

import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SOURCE = Path(__file__).resolve().parents[2] / "test-harness/fixtures/litellm-live/gateway_metrics.py"


class LocalModel(BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, *_):
        pass

    def do_POST(self):
        type(self).calls += 1
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != "Bearer sk-synthetic-master":
            self.send_error(401)
            return
        body = json.dumps({"object": "chat.completion", "id": "fixture-model",
                           "choices": [{"message": {"role": "assistant", "content": "OK"}}],
                           "usage": {"total_tokens": 3}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EntrypointTests(unittest.TestCase):
    def test_source_mounted_entrypoint_status_revoke_and_control(self):
        self.entrypoint_protocol(metrics_enabled=False)

    def test_opt_in_metrics_entrypoint_is_private_and_counts_terminal_requests(self):
        self.entrypoint_protocol(metrics_enabled=True)

    def test_preserved_legacy_source_entrypoint(self):
        self.entrypoint_protocol(metrics_enabled=False, source=SOURCE.with_name("gateway.py"))

    def entrypoint_protocol(self, metrics_enabled, source=SOURCE):
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        seed = b"synthetic-local-trial-seed-32-bytes-0001"
        nonce = "a" * 32

        def token(role):
            mac = hmac.new(seed, f"phorvex-litellm-live-v2:{nonce}:{role}".encode(),
                           hashlib.sha256).hexdigest()
            return f"sk-phx2-{role}-{nonce}-{mac}"

        old, control = token("a"), token("c")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "seed").write_bytes(seed)
            (root / "status-token").write_text("synthetic-private-status-token-32-bytes")
            (root / "clients.json").write_text(json.dumps({"version": 2,
                "seedSHA256": hashlib.sha256(seed).hexdigest(), "modelAlias": "gpt-4o-mini"},
                sort_keys=True, separators=(",", ":")))
            policy = root / "state.json"
            policy.write_text('{"entries":[],"revision":0,"version":2}')
            upstream = ThreadingHTTPServer(("127.0.0.1", 4000), LocalModel)
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            LocalModel.calls = 0
            env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                   "PHORVEX_LITELLM_STATUS_TOKEN_FILE": str(root / "status-token"),
                   "PHORVEX_LITELLM_CLIENTS_FILE": str(root / "clients.json"),
                   "PHORVEX_LITELLM_POLICY_FILE": str(policy),
                   "PHORVEX_LITELLM_TRIAL_SEED_FILE": str(root / "seed"),
                   "LITELLM_MASTER_KEY": "sk-synthetic-master", "POD_UID": "fixture-pod",
                   "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID": "fixture-policy-cm",
                   "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256": source_sha}
            if metrics_enabled:
                env.update({"PHORVEX_LITELLM_METRICS_ENABLED": "1", "POD_NAMESPACE": "litellm",
                            "POD_NAME": "litellm-runtime-fixture"})
            proc = subprocess.Popen([sys.executable, "-B", str(source)], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if proc.poll() is not None:
                        self.fail("gateway entrypoint exited before binding status and public ports")
                    try:
                        with socket.create_connection(("127.0.0.1", 4002), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("gateway entrypoint did not bind status listener")
                        time.sleep(0.05)

                def request(port, method, path, bearer, body=None):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                    try:
                        headers = {"Authorization": "Bearer " + bearer}
                        if body is not None:
                            headers["Content-Type"] = "application/json"
                        conn.request(method, path, body, headers)
                        response = conn.getresponse()
                        return response.status, response.read()
                    finally:
                        conn.close()

                path = "/v1/admission/state?clientSHA256=" + hashlib.sha256(old.encode()).hexdigest()
                self.assertEqual(request(4002, "GET", path, "wrong")[0], 401)
                status, raw = request(4002, "GET", path, "synthetic-private-status-token-32-bytes")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(raw)["podUID"], "fixture-pod")
                body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Say OK."}],
                                   "max_tokens": 8, "stream": False}).encode()
                self.assertEqual(request(4001, "POST", "/v1/chat/completions", old, body)[0], 200)
                self.assertEqual(request(4001, "POST", "/v1/chat/completions", control, body)[0], 200)
                self.assertEqual(LocalModel.calls, 2)
                next_state = {"version": 2, "revision": 1,
                              "entries": [{"active": True, "clientSHA256": hashlib.sha256(old.encode()).hexdigest(),
                                           "operationId": "synthetic-operation-1"}]}
                replacement = root / "next-state.json"
                replacement.write_text(json.dumps(next_state, sort_keys=True, separators=(",", ":")))
                replacement.replace(policy)
                denied_status, denied_body = request(4001, "POST", "/v1/chat/completions", old, body)
                self.assertEqual(denied_status, 429)
                self.assertEqual(json.loads(denied_body)["error"]["code"], "PHORVEX_CLIENT_REVOKED")
                self.assertEqual(request(4001, "POST", "/v1/chat/completions", control, body)[0], 200)
                self.assertEqual(LocalModel.calls, 3)
                if metrics_enabled:
                    deadline = time.monotonic() + 3
                    while True:
                        status, raw = request(4003, "GET", "/metrics", "")
                        self.assertEqual(status, 200)
                        counters = dict(re.findall(rb'^http_requests_total\{(.*)\} (\d+)$', raw, re.M))
                        if sum(int(value) for value in counters.values()) == 4:
                            break
                        if time.monotonic() >= deadline:
                            self.fail("terminal runtime accounting did not catch up")
                        time.sleep(.01)
                    self.assertIn(b'namespace="litellm",pod="litellm-runtime-fixture",target="litellm"', raw)
                    histograms = dict(re.findall(rb'^http_request_duration_seconds_count\{(.*)\} (\d+)$', raw, re.M))
                    self.assertEqual(counters, histograms)
                    self.assertEqual(sum(int(value) for value in counters.values()), 4)
                    self.assertEqual(request(4003, "GET", "/metrics?x=y", "")[0], 404)
                    self.assertEqual(request(4003, "GET", path, "synthetic-private-status-token-32-bytes")[0], 404)
                    self.assertEqual(request(4003, "POST", "/v1/chat/completions", old, body)[0], 501)
                    self.assertEqual(LocalModel.calls, 3)
                else:
                    with self.assertRaises(OSError):
                        socket.create_connection(("127.0.0.1", 4003), timeout=0.2)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    unittest.main()
