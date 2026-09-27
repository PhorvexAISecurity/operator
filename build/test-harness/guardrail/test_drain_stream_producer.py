"""Exercise the actual console SSE producer through the reviewed proxy, offline."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import drain_v11
import test_drain_v11
import test_guardrail_proxy as proxy_test


HERE = Path(__file__).resolve().parent
GO_SOURCE = HERE.parents[2] / "phorvex/internal/console/vllm_drain_worker.go"
NONCE = "1234567890abcdef1234567890abcdef"
REQUEST_ID = "cmpl-" + NONCE
SCHEDULER_ID = REQUEST_ID + "-0"
ADMIN = "local-admin-only"


def production_stream_script(port: int) -> str:
    source = GO_SOURCE.read_text()
    match = re.search(r"const drainStreamPython = `([^`]*)`", source)
    if match is None:
        raise AssertionError("actual console stream producer missing")
    script = match.group(1)
    target = re.compile(r'http\.client\.HTTPConnection\("(?:127\.0\.0\.1|vllm\.vllm\.svc\.cluster\.local)",8000,timeout=210\)')
    if len(target.findall(script)) != 1:
        raise AssertionError("stream producer destination changed or became ambiguous")
    return target.sub(f'http.client.HTTPConnection("127.0.0.1",{port},timeout=210)', script)


class BackendState:
    def __init__(self, mode: str):
        self.mode = mode
        self.abort = threading.Event()
        self.first = threading.Event()
        self.request_id = ""
        self.scheduler_id = ""
        self.calls = []


class FakeV11Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        state = self.server.state
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        state.calls.append((self.path, body))
        if self.path != "/v1/completions":
            self.send_error(404)
            return
        request = json.loads(body)
        if not request.get("stream"):
            raw = json.dumps({"choices": [{"finish_reason": "stop", "text": "Clouds form from water vapor."}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        state.request_id = self.headers.get("X-Request-Id", "")
        state.scheduler_id = "cmpl-" + state.request_id + "-0"
        if state.mode == "network-failure":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        frame_id = "wrong-id" if state.mode == "wrong-sse" else "cmpl-" + state.request_id
        self.wfile.write(b"data: " + json.dumps({"id": frame_id, "choices": [{"text": "1"}]}).encode() + b"\n\n")
        self.wfile.flush()
        state.first.set()
        if state.mode in ("wrong-sse", "early-complete"):
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            return
        state.abort.wait(5)
        self.close_connection = True

    def log_message(self, *_args):
        pass


class SchedulerEngine(test_drain_v11.FakeEngine):
    def __init__(self, backend: BackendState):
        super().__init__()
        self.backend = backend
        self.snapshot = {"0": {"waiting": [], "running": [], "swapped": [], "cached": []}}

    async def begin(self, operation_id, generation):
        if not self.backend.first.is_set() or self.backend.scheduler_id != SCHEDULER_ID:
            raise AssertionError("engine begin lacked the admitted owned scheduler ID")
        self.snapshot["0"]["running"] = [self.backend.scheduler_id]
        self.backend.abort.set()
        return await super().begin(operation_id, generation)


class ActualSSEProducerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def backend(self, mode):
        state = BackendState(mode)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeV11Backend)
        server.state = state
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return state, f"http://127.0.0.1:{server.server_port}"

    def launch(self, port):
        body = json.dumps({"model": "fixed-local-model", "prompt": "Write integers from 1 through 400, separated by spaces. Keep writing until 400. No introduction.",
                           "max_tokens": 1024, "temperature": 0, "stream": True, "n": 1}, separators=(",", ":")).encode()
        proc = subprocess.Popen([sys.executable, "-B", "-c", production_stream_script(port)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def close_process():
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
        self.addCleanup(close_process)
        proc.stdin.write(json.dumps({"body": base64.b64encode(body).decode(), "nonce": NONCE}).encode())
        proc.stdin.close()
        return proc

    def row(self, proc, timeout=8):
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            self.fail("actual console producer emitted no bounded projection")
        raw = proc.stdout.readline()
        self.assertLessEqual(len(raw), 1024)
        return json.loads(raw)

    def api(self, base, path, body=None):
        return proxy_test.request_json(base, path, body, {"Authorization": "Bearer " + ADMIN})

    def test_owned_stream_native_abort_and_reopen_benign(self):
        state, upstream = self.backend("wait-for-abort")
        engine = SchedulerEngine(state)
        ledger = Path(self.temp.name) / "ledger"
        drain_v11.initialize_ledger(ledger, "pod-uid", "a" * 32)
        config = proxy_test.guardrail.GuardrailConfig("pgv2", "observe", {"pgv1": 0.5, "pgv2": 0.5})
        runtime = proxy_test.guardrail.GuardrailRuntime(config)
        classifier = proxy_test.ScoreClassifier({})
        runtime.install_classifier("pgv1", classifier)
        runtime.install_classifier("pgv2", classifier)
        env = {"PHORVEX_DRAIN_V11": "1", "POD_UID": "pod-uid", "PHORVEX_PROXY_SOURCE": "proxy-source",
               "PHORVEX_ENGINE_SOURCE": "engine-source", "PHORVEX_MODEL_DIGEST": "model-digest",
               "PHORVEX_DRAIN_LEDGER_DIR": str(ledger)}
        with mock.patch.dict(os.environ, env), mock.patch.object(proxy_test.guardrail, "EngineHTTPClient", return_value=engine):
            app = proxy_test.guardrail.create_app(runtime=runtime, upstream=upstream, load_models=False,
                                                   upstream_api_key="backend-key", admin_api_key=ADMIN)
        with proxy_test.serve_app(app) as base:
            port = int(base.rsplit(":", 1)[1])
            proc = self.launch(port)
            first = self.row(proc)
            self.assertEqual((first["stage"], first["status"], first["id"]), ("first", 200, REQUEST_ID))
            self.assertEqual((state.request_id, state.scheduler_id), (NONCE, SCHEDULER_ID))
            status, cap = self.api(base, "/v1/drain/capability")
            self.assertEqual((status, cap["admission"]), (200, "OPEN"))
            payload = {"schema": drain_v11.SCHEMA, "operation_id": "1" * 32, "operation_generation": "1",
                       "attempt": 1, "owner": {"tenant": "test", "namespace_uid": "ns", "policy_uid": "policy",
                                              "pod_uid": "pod-uid", "service_uid": "service"},
                       "expected_incarnation_digest": cap["incarnation_digest"],
                       "deadline": (datetime.now(timezone.utc) + timedelta(minutes=3)).isoformat().replace("+00:00", "Z"),
                       "mode": "abort-and-quiesce"}
            status, created = self.api(base, "/v1/drain/operations", payload)
            self.assertEqual((status, created["state"]), (201, "DRAINING"))
            self.assertIn(SCHEDULER_ID, created["engine_snapshot"]["0"]["running"])
            self.assertEqual(created["terminal_dispositions"][SCHEDULER_ID], "aborted")
            self.assertGreaterEqual(created["proxy_snapshot"]["before_engine_begin"]["active"], 1)
            self.assertEqual(created["proxy_snapshot"]["after_engine_begin"]["remaining"], 0)
            final = self.row(proc)
            self.assertEqual(proc.wait(timeout=5), 0)
            self.assertEqual((final["stage"], final["status"], final["done"]), ("final", 200, False))
            self.assertGreaterEqual(final["frames"], 1)
            self.assertTrue(re.fullmatch("[0-9a-f]{64}", final["bodySHA256"]))
            for nonce in ("2" * 32, "3" * 32):
                status, observed = self.api(base, "/v1/drain/operations/1/" + "1" * 32 + "?observation_nonce=" + nonce)
                self.assertEqual(status, 200)
            self.assertEqual(observed["state"], "QUIESCENT")
            status, reopened = self.api(base, "/v1/drain/operations/1/" + "1" * 32 + "/reopen", {
                "owner_digest": observed["owner_digest"], "expected_incarnation_digest": observed["backend_incarnation_digest"],
                "expected_revision": observed["revision"]})
            self.assertEqual((status, reopened["state"], reopened["admission"]), (200, "OPENED", "OPEN"))
            status, benign = self.api(base, "/v1/completions", {"model": "fixed-local-model", "prompt": "Clouds are white.",
                                                                "max_tokens": 12, "temperature": 0, "stream": False, "n": 1})
            self.assertEqual((status, benign["choices"][0]["finish_reason"]), (200, "stop"))
            self.assertEqual(len(state.calls), 2)

    def test_wrong_frame_early_done_and_upstream_failure_cannot_prove_abort(self):
        for mode in ("wrong-sse", "early-complete", "network-failure"):
            with self.subTest(mode=mode):
                state, upstream = self.backend(mode)
                config = proxy_test.guardrail.GuardrailConfig("pgv2", "observe", {"pgv1": 0.5, "pgv2": 0.5})
                runtime = proxy_test.guardrail.GuardrailRuntime(config)
                classifier = proxy_test.ScoreClassifier({})
                runtime.install_classifier("pgv1", classifier)
                runtime.install_classifier("pgv2", classifier)
                app = proxy_test.guardrail.create_app(runtime=runtime, upstream=upstream, load_models=False,
                                                       upstream_api_key="backend-key", admin_api_key=ADMIN)
                with proxy_test.serve_app(app) as base:
                    proc = self.launch(int(base.rsplit(":", 1)[1]))
                    self.assertEqual(proc.wait(timeout=5), 0)
                    rows = [json.loads(line) for line in proc.stdout if line.strip()]
                    self.assertLessEqual(len(rows), 2)
                    self.assertEqual(len(state.calls), 1)
                    if mode == "early-complete":
                        self.assertEqual([row["stage"] for row in rows], ["first", "final"])
                        self.assertTrue(rows[-1]["done"])
                    else:
                        self.assertEqual([row["stage"] for row in rows], ["final"])
                        self.assertFalse(rows[-1]["done"])
