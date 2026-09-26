"""Synthetic handler tests: no Kubernetes, installed model, or live disclosure."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

import uvicorn

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guardrail_proxy as proxy
import output_policy as policy
import support_fixture


POD_UID = "11111111-1111-4111-8111-111111111111"
CM_UID = "22222222-2222-4222-8222-222222222222"
MARKER = "ownedSyntheticMarker_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _support_response():
    return {"schema": "phorvex.support-case-response.v1", "caseId": "CAT-001",
            "status": "delivered", "answer": "Case CAT-001 has been delivered.",
            "modelReceipt": {"completionId": "chatcmpl-test-1", "model": "real-model"},
            "diagnostics": {"internalAuditMarker": MARKER}}


def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def serve_app(app):
    port = _port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                          log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("test app did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def request(base, path, data=None, headers=None, method=None):
    req = urllib.request.Request(base + path, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as result:
            return result.status, result.read(), dict(result.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


class FakeSupport(BaseHTTPRequestHandler):
    response_body = _json(_support_response())
    response_type = "application/json"
    response_status = 200
    content_length = None
    delay = 0
    calls = 0

    def do_GET(self):
        if self.path != "/v1/support/state":
            self.send_error(404)
            return
        body = _json({"version": 1, "supportSourceSHA256": "a" * 64,
                      "completedModelCalls": self.calls, "model": "real-model"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).calls += 1
        request_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.delay:
            time.sleep(self.delay)
        body = self.response_body
        if request_body == b'{"caseId":"CAT-002"}' and self.response_body == _json(_support_response()):
            public = _support_response()
            public["caseId"] = "CAT-002"
            public["diagnostics"] = {}
            body = _json(public)
        self.send_response(self.response_status)
        self.send_header("Content-Type", self.response_type)
        self.send_header("Content-Length", str(len(body) if self.content_length is None else self.content_length))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def fake_support():
    FakeSupport.response_body = _json(_support_response())
    FakeSupport.response_type = "application/json"
    FakeSupport.response_status = 200
    FakeSupport.content_length = None
    FakeSupport.delay = 0
    FakeSupport.calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeSupport)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class OutputPolicyHandlerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy_dir = self.root / "policy"
        self.state_dir = self.root / "state"
        self.policy_dir.mkdir()
        self.state_dir.mkdir()
        (self.policy_dir / "rule.json").write_bytes(policy.canonical_rule(POD_UID))
        self.activate(False, 0, "")

    def activate(self, active, revision, operation_id):
        (self.policy_dir / "activation.json").write_bytes(_json({
            "version": 1, "ruleId": policy.RULE_ID, "configMapUID": CM_UID,
            "active": active, "revision": revision, "operationId": operation_id}))

    def app(self, url):
        return proxy.create_app(load_models=False, support_fixture_enabled=True,
                                support_fixture_url=url, output_policy_dir=self.policy_dir,
                                output_policy_state_dir=self.state_dir, pod_uid=POD_UID)

    def support(self, base, data=b'{"caseId":"CAT-001"}', headers=None):
        return request(base, "/v1/support/case", data,
                       {"Content-Type": "application/json", **(headers or {})})

    def test_inactive_baseline_then_active_removes_only_owned_field(self):
        with fake_support() as upstream, serve_app(self.app(upstream)) as base:
            status, raw, _ = self.support(base)
            self.assertEqual(status, 200)
            self.assertIn(MARKER.encode(), raw)
            self.activate(True, 1, "operation-one")
            status, raw, headers = self.support(base)
            self.assertEqual(status, 200)
            self.assertNotIn(MARKER.encode(), raw)
            value = json.loads(raw)
            self.assertEqual(value["answer"], _support_response()["answer"])
            self.assertEqual(value["status"], "delivered")
            self.assertEqual(value["modelReceipt"], _support_response()["modelReceipt"])
            self.assertEqual(value["diagnostics"], {})
            self.assertEqual(int(next(value for key, value in headers.items()
                                      if key.lower() == "content-length")), len(raw))
            code, raw, _ = request(base, "/v1/output-policy/state")
            self.assertEqual(code, 200)
            state = json.loads(raw)
            self.assertEqual((state["active"], state["revision"], state["operationId"]),
                             (True, 1, "operation-one"))
            self.assertEqual(state["configMapUID"], CM_UID)
            self.assertEqual(state["ruleSHA256"], hashlib.sha256(policy.canonical_rule(POD_UID)).hexdigest())
            self.assertEqual(state["supportSourceSHA256"], "a" * 64)
            self.assertEqual(state["proxySourceSHA256"], hashlib.sha256(
                (HERE / "guardrail_proxy.py").read_bytes() + b"\x00"
                + (HERE / "output_policy.py").read_bytes()).hexdigest())
            with mock.patch.object(Path, "read_bytes", return_value=b"changed-on-disk-after-start"):
                self.assertEqual(json.loads(request(base, "/v1/output-policy/state")[1])[
                    "proxySourceSHA256"], state["proxySourceSHA256"])
            code, safe_raw, _ = self.support(base, b'{"caseId":"CAT-002"}')
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(safe_raw)["diagnostics"], {})
            self.assertEqual(json.loads(safe_raw)["caseId"], "CAT-002")
            mutate_code, _, _ = request(base, "/v1/output-policy/state", b'{"active":false}',
                                        {"Content-Type": "application/json",
                                         "Authorization": "Bearer model-client-key"})
            self.assertEqual(mutate_code, 405)
            self.assertTrue(json.loads(request(base, "/v1/output-policy/state")[1])["active"])

    def test_missing_corrupt_and_replayed_policy_fail_closed_across_restart(self):
        with fake_support() as upstream:
            with serve_app(self.app(upstream)) as base:
                self.activate(True, 1, "operation-one")
                self.assertEqual(self.support(base)[0], 200)
                (self.policy_dir / "activation.json").unlink()
                code, body, _ = self.support(base)
                self.assertEqual(code, 503)
                self.assertNotIn(MARKER.encode(), body)
                self.activate(False, 0, "")
            with serve_app(self.app(upstream)) as restarted:
                code, body, _ = self.support(restarted)
                self.assertEqual(code, 503)
                self.assertNotIn(MARKER.encode(), body)
                self.activate(False, 2, "rollback-two")
                code, body, _ = self.support(restarted)
                self.assertEqual(code, 200)
                self.assertIn(MARKER.encode(), body)  # explicit higher-revision rollback

    def test_duplicate_schema_size_stream_and_upstream_error_are_typed(self):
        with fake_support() as upstream, serve_app(self.app(upstream)) as base:
            self.activate(True, 1, "operation-one")
            cases = [
                (b'{"schema":"phorvex.support-case-response.v1","schema":"x"}', None),
                (_json({**_support_response(), "extra": "x"}), None),
                (b"x" * (policy.MAX_RESPONSE_BYTES + 1), None),
                (_json(_support_response()), policy.MAX_RESPONSE_BYTES + 1),
                (_json(_support_response()), len(_json(_support_response())) + 10),
            ]
            for body, length in cases:
                with self.subTest(size=len(body), header=length):
                    FakeSupport.response_body = body
                    FakeSupport.content_length = length
                    code, raw, _ = self.support(base)
                    self.assertEqual(code, 502)
                    self.assertNotIn(MARKER.encode(), raw)
            FakeSupport.response_body = _json(_support_response())
            FakeSupport.content_length = None
            FakeSupport.response_type = "text/event-stream"
            self.assertEqual(self.support(base)[0], 502)
            FakeSupport.response_type = "application/json"
            before = FakeSupport.calls
            self.assertEqual(self.support(base, headers={"Accept": "text/event-stream"})[0], 400)
            self.assertEqual(self.support(base, data=b'{"caseId":"CAT-001","stream":true}')[0], 400)
            self.assertEqual(FakeSupport.calls, before)
            FakeSupport.response_status = 503
            self.assertEqual(self.support(base)[0], 502)

    def test_upstream_total_timeout_has_no_partial_response(self):
        with fake_support() as upstream, serve_app(self.app(upstream)) as base:
            self.activate(True, 1, "operation-one")
            FakeSupport.delay = 0.3
            with mock.patch.object(proxy, "SUPPORT_TIMEOUT_SECONDS", 0.1):
                code, raw, _ = self.support(base)
            self.assertEqual(code, 502)
            self.assertNotIn(MARKER.encode(), raw)

    def test_wrong_uid_rule_and_same_revision_drift_are_refused(self):
        reader = policy.PolicyReader(self.policy_dir, POD_UID, self.state_dir)
        reader.read()
        self.activate(True, 0, "operation-one")
        with self.assertRaises(policy.PolicyError):
            reader.read()
        self.activate(False, 0, "different-operation")
        with self.assertRaises(policy.PolicyError):
            reader.read()
        self.activate(False, 2, "")
        with self.assertRaises(policy.PolicyError):
            reader.read()
        (self.policy_dir / "rule.json").write_bytes(policy.canonical_rule(CM_UID))
        with self.assertRaises(policy.PolicyError):
            reader.read()

    def test_kubernetes_projected_generation_pair_and_duplicate_activation(self):
        mounted = self.root / "mounted"
        mounted.mkdir()
        first = mounted / "..2026_first"
        second = mounted / "..2026_second"
        first.mkdir()
        second.mkdir()
        for directory, revision, active, operation in (
                (first, 0, False, ""), (second, 1, True, "operation-one")):
            (directory / "rule.json").write_bytes(policy.canonical_rule(POD_UID))
            (directory / "activation.json").write_bytes(_json({
                "version": 1, "ruleId": policy.RULE_ID, "configMapUID": CM_UID,
                "active": active, "revision": revision, "operationId": operation}))
        (mounted / "..data").symlink_to(first.name)
        (mounted / "rule.json").symlink_to("..data/rule.json")
        (mounted / "activation.json").symlink_to("..data/activation.json")
        reader = policy.PolicyReader(mounted, POD_UID, self.state_dir)
        self.assertFalse(reader.read().active)
        (mounted / "..data_tmp").symlink_to(second.name)
        os.replace(mounted / "..data_tmp", mounted / "..data")
        self.assertTrue(reader.read().active)
        (second / "activation.json").write_bytes(
            b'{"version":1,"version":1,"ruleId":"support-internal-audit-marker-v1"}')
        with self.assertRaises(policy.PolicyError):
            reader.read()

    def test_disabled_proxy_loads_without_policy_module_and_route_does_not_forward(self):
        with tempfile.TemporaryDirectory() as isolated:
            source = Path(isolated) / "guardrail_proxy.py"
            source.write_bytes((HERE / "guardrail_proxy.py").read_bytes())
            command = [sys.executable, "-c",
                       "import importlib.util; s=importlib.util.spec_from_file_location('isolated',r'%s'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.app is not None" % source]
            result = subprocess.run(command, capture_output=True, text=True,
                                    env={**os.environ, "PHORVEX_SUPPORT_FIXTURE_ENABLED": "0"})
            self.assertEqual(result.returncode, 0, result.stderr)
        with fake_support() as upstream, serve_app(proxy.create_app(load_models=False,
                                                                     support_fixture_enabled=False,
                                                                     support_fixture_url=upstream)) as base:
            self.assertEqual(self.support(base)[0], 404)
            self.assertEqual(FakeSupport.calls, 0)


class FakeModel(BaseHTTPRequestHandler):
    calls = []
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).calls.append(body)
        case_id = "CAT-002" if b"CAT-002" in body else "CAT-001"
        payload = _json({"id": "chatcmpl-test-1", "model": "real-model",
                         "choices": [{"message": {"content": f"Case {case_id} has been delivered."}}]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_args):
        pass


class SyntheticSupportAppTest(unittest.TestCase):
    def test_marker_file_must_be_private_regular_and_model_url_guarded(self):
        with tempfile.TemporaryDirectory() as directory:
            marker_path = Path(directory) / "marker"
            marker_path.write_text(MARKER + "\n")
            marker_path.chmod(0o600)
            self.assertEqual(support_fixture.read_owned_marker(marker_path), MARKER)
            marker_path.chmod(0o644)
            with self.assertRaises(ValueError):
                support_fixture.read_owned_marker(marker_path)
            with mock.patch.dict(os.environ, {"SUPPORT_FIXTURE_MODEL_URL": "http://127.0.0.1:8001",
                                               "SUPPORT_FIXTURE_MODEL": "real-model",
                                               "SUPPORT_FIXTURE_MARKER_FILE": str(marker_path)}):
                with self.assertRaises(ValueError):
                    support_fixture.create_app()

    def test_owned_marker_is_serialized_only_after_real_model_completion(self):
        FakeModel.calls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeModel)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: thread.join(timeout=5))
        app = support_fixture.create_app(model_url=f"http://127.0.0.1:{server.server_port}",
                                         model="real-model", marker=MARKER)
        with serve_app(app) as base:
            bad_code, _, _ = request(base, "/v1/support/case", b'{"caseId":"other"}',
                                     {"Content-Type": "application/json"})
            self.assertEqual(bad_code, 400)
            code, raw, _ = request(base, "/v1/support/case", b'{"caseId":"CAT-001"}',
                                   {"Content-Type": "application/json"})
            self.assertEqual(code, 200)
            self.assertIn(MARKER.encode(), raw)
            receipt = json.loads(raw)["modelReceipt"]
            self.assertEqual(receipt, {"completionId": "chatcmpl-test-1", "model": "real-model"})
            state_code, state_raw, _ = request(base, "/v1/support/state")
            self.assertEqual(state_code, 200)
            self.assertEqual(json.loads(state_raw)["completedModelCalls"], 1)
            safe_code, safe_raw, _ = request(base, "/v1/support/case", b'{"caseId":"CAT-002"}',
                                             {"Content-Type": "application/json"})
            self.assertEqual(safe_code, 200)
            self.assertNotIn(MARKER.encode(), safe_raw)
            self.assertEqual(json.loads(safe_raw)["diagnostics"], {})
            self.assertIn("CAT-002", json.loads(safe_raw)["answer"])
        self.assertEqual(len(FakeModel.calls), 2)
        self.assertNotIn(MARKER.encode(), FakeModel.calls[0])
        self.assertNotIn(MARKER.encode(), FakeModel.calls[1])
        self.assertEqual(json.loads(FakeModel.calls[0])["messages"][0]["content"],
                         support_fixture.PROMPT)


if __name__ == "__main__":
    unittest.main()
