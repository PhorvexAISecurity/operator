import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uvicorn


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("m116_guardrail_proxy", HERE / "guardrail_proxy.py")
guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardrail)


class ScoreClassifier:
    """HF-pipeline-shaped score producer; final verdict remains production code."""

    def __init__(self, scores, default=0.0):
        self.scores = scores
        self.default = default

    def __call__(self, text):
        return [{"label": "INJECTION", "score": self.scores.get(text, self.default)}]


class CountingUpstream(BaseHTTPRequestHandler):
    calls = []
    lock = threading.Lock()
    stream_started = threading.Event()
    stream_release = threading.Event()
    reset_status = 200
    reset_body = b'{"success":true}'
    reset_authorization = None

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        with self.lock:
            self.calls.append((self.path, body))
            call_number = len(self.calls)
        if self.path == "/reset_prefix_cache":
            type(self).reset_authorization = self.headers.get("Authorization")
            response = type(self).reset_body
            self.send_response(type(self).reset_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return
        if self.path == "/v1/completions" and b"stream benign" in body:
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            self.stream_started.set()
            self.stream_release.wait(timeout=5)
            self.wfile.write(b"second")
            self.wfile.flush()
            return
        response = json.dumps({"upstream": True, "call": call_number}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def serve_app(app):
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("FastAPI test server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def request_json(base_url, path, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request_headers = dict(headers or {})
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url + path,
        data=data,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class GuardrailHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CountingUpstream.calls = []
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), CountingUpstream)
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.upstream_url = f"http://127.0.0.1:{cls.upstream.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.upstream_thread.join(timeout=5)

    def setUp(self):
        with CountingUpstream.lock:
            CountingUpstream.calls.clear()
        CountingUpstream.stream_started.clear()
        CountingUpstream.stream_release.clear()
        CountingUpstream.reset_status = 200
        CountingUpstream.reset_body = b'{"success":true}'
        CountingUpstream.reset_authorization = None

    def runtime(self, mode="enforce", threshold_pgv1=0.5, threshold_pgv2=0.5, scores=None):
        config = guardrail.GuardrailConfig(
            initial_variant="pgv2",
            mode=mode,
            thresholds={"pgv1": threshold_pgv1, "pgv2": threshold_pgv2},
        )
        runtime = guardrail.GuardrailRuntime(config)
        classifier = ScoreClassifier(scores or {})
        runtime.install_classifier("pgv1", classifier, "test-pgv1-revision")
        runtime.install_classifier("pgv2", classifier, "test-pgv2-revision")
        return runtime

    def app(self, runtime):
        return guardrail.create_app(runtime=runtime, upstream=self.upstream_url, load_models=False)

    def call_count(self):
        with CountingUpstream.lock:
            return len(CountingUpstream.calls)

    def test_default_config_is_enforce_with_half_thresholds(self):
        config = guardrail.load_config({})
        self.assertEqual(config.initial_variant, "pgv2")
        self.assertEqual(config.mode, "enforce")
        self.assertEqual(config.thresholds, {"pgv1": 0.5, "pgv2": 0.5})

    def test_invalid_startup_configuration_is_rejected(self):
        bad = (
            {"GUARDRAIL_MODE": "shadow"},
            {"GUARDRAIL_INITIAL_VARIANT": "unknown"},
            {"GUARDRAIL_THRESHOLD_PGV1": "nan"},
            {"GUARDRAIL_THRESHOLD_PGV2": "inf"},
            {"GUARDRAIL_THRESHOLD_PGV1": "-0.1"},
            {"GUARDRAIL_THRESHOLD_PGV2": "1.1"},
        )
        for environ in bad:
            with self.subTest(environ=environ), self.assertRaises(ValueError):
                guardrail.load_config(environ)

    def test_enforce_blocks_at_equality_and_forwards_benign_once(self):
        high = "instruction-shaped benign false positive"
        low = "ordinary benign"
        runtime = self.runtime(scores={high: 0.5, low: 0.1})
        with serve_app(self.app(runtime)) as base_url:
            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": high}],
            })
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["type"], "guardrail_blocked")
            self.assertEqual(self.call_count(), 0)

            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": low}],
            })
            self.assertEqual((status, body["upstream"]), (201, True))
            self.assertEqual(self.call_count(), 1)

    def test_observe_records_both_verdicts_and_forwards_exactly_once(self):
        secret_prompt = "PRIVATE-PROMPT-CONTENT"
        low = "ordinary benign"
        runtime = self.runtime(mode="observe", scores={secret_prompt: 0.9, low: 0.1})
        with serve_app(self.app(runtime)) as base_url, mock.patch("builtins.print") as printed:
            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": secret_prompt}],
            })
            self.assertEqual((status, body["call"]), (201, 1))
            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": low}],
            })
            self.assertEqual((status, body["call"]), (201, 2))

        self.assertEqual(self.call_count(), 2)
        rendered = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertNotIn(secret_prompt, rendered)
        verdicts = [json.loads(call.args[0]) for call in printed.call_args_list
                    if call.args and str(call.args[0]).startswith('{"event":"guardrail_verdict"')]
        self.assertEqual([item["would_block"] for item in verdicts], [True, False])
        self.assertEqual([item["outcome"] for item in verdicts], ["admitted_observe", "admitted_observe"])
        self.assertTrue(all(set(item) == {"event", "mode", "outcome", "score", "threshold", "variant", "would_block"}
                            for item in verdicts))

    def test_multiple_user_messages_use_one_conservative_snapshot(self):
        runtime = self.runtime(scores={"first": 0.1, "second": 0.8})
        with serve_app(self.app(runtime)) as base_url:
            status, _ = request_json(base_url, "/v1/chat/completions", {
                "messages": [
                    {"role": "system", "content": "ignored trusted system"},
                    {"role": "user", "content": "first"},
                    {"role": "assistant", "content": "ignored assistant"},
                    {"role": "user", "content": "second"},
                ],
            })
        self.assertEqual(status, 403)
        self.assertEqual(self.call_count(), 0)

    def test_below_threshold_stream_preserves_status_body_and_streaming(self):
        runtime = self.runtime(scores={"stream benign": 0.1})
        with serve_app(self.app(runtime)) as base_url:
            host_port = base_url.removeprefix("http://")
            host, port = host_port.split(":")
            connection = http.client.HTTPConnection(host, int(port), timeout=5)
            connection.request(
                "POST",
                "/v1/completions",
                body=json.dumps({"prompt": "stream benign"}),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 202)
            self.assertTrue(CountingUpstream.stream_started.wait(timeout=1))
            self.assertEqual(response.read(5), b"first")
            CountingUpstream.stream_release.set()
            self.assertEqual(response.read(), b"second")
            connection.close()
        self.assertEqual(self.call_count(), 1)

    def test_drain_aborts_counted_stream_and_next_request_still_works(self):
        runtime = self.runtime(scores={"stream benign": 0.1, "ordinary benign": 0.1})
        received = {}

        def stream_request(base_url):
            host_port = base_url.removeprefix("http://")
            host, port = host_port.split(":")
            connection = http.client.HTTPConnection(host, int(port), timeout=5)
            try:
                connection.request(
                    "POST",
                    "/v1/completions",
                    body=json.dumps({"prompt": "stream benign"}),
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                received["status"] = response.status
                received["first"] = response.read(5)
                received["rest"] = response.read()
            except Exception as exc:
                received["error"] = type(exc).__name__
            finally:
                connection.close()

        with serve_app(self.app(runtime)) as base_url:
            client_thread = threading.Thread(target=stream_request, args=(base_url,), daemon=True)
            client_thread.start()
            self.assertTrue(CountingUpstream.stream_started.wait(timeout=2))
            deadline = time.monotonic() + 2
            aborted = 0
            while aborted == 0 and time.monotonic() < deadline:
                status, body = request_json(base_url, "/v1/drain", {"abort_inflight": True})
                self.assertEqual(status, 200)
                aborted = body["aborted"]
                if aborted == 0:
                    time.sleep(0.01)
            CountingUpstream.stream_release.set()
            client_thread.join(timeout=5)
            self.assertEqual(aborted, 1)
            self.assertFalse(client_thread.is_alive())
            self.assertEqual(received.get("status"), 202)
            self.assertEqual(received.get("first"), b"first")
            self.assertNotEqual(received.get("rest"), b"second")

            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "ordinary benign"}],
            })
            self.assertEqual((status, body["upstream"]), (201, True))
        self.assertEqual(self.call_count(), 2)

    def test_kv_invalidate_propagates_authenticated_true_and_false(self):
        runtime = self.runtime()
        app = guardrail.create_app(
            runtime=runtime,
            upstream=self.upstream_url,
            load_models=False,
            upstream_api_key="reset-secret",
        )
        with serve_app(app) as base_url:
            headers = {"Authorization": "Bearer reset-secret"}
            status, body = request_json(base_url, "/v1/kv/invalidate", {"local": True}, headers)
            self.assertEqual((status, body), (200, {"success": True, "scope": "local-prefix-cache"}))
            self.assertEqual(CountingUpstream.reset_authorization, "Bearer reset-secret")

            CountingUpstream.reset_body = b'{"success":false}'
            status, body = request_json(base_url, "/v1/kv/invalidate", {"local": True}, headers)
            self.assertEqual((status, body), (200, {"success": False, "scope": "local-prefix-cache"}))

    def test_kv_invalidate_rejects_unconfirmed_upstream_responses(self):
        runtime = self.runtime()
        app = guardrail.create_app(
            runtime=runtime,
            upstream=self.upstream_url,
            load_models=False,
            upstream_api_key="reset-secret",
        )
        cases = (
            (200, b""),
            (204, b""),
            (200, b'{"success":true,"success":false}'),
            (200, b'{"success":true} trailing'),
            (200, b"x" * (guardrail.RESET_RESPONSE_MAX_BYTES + 1)),
        )
        with serve_app(app) as base_url:
            headers = {"Authorization": "Bearer reset-secret"}
            for upstream_status, upstream_body in cases:
                with self.subTest(status=upstream_status, body_len=len(upstream_body)):
                    CountingUpstream.reset_status = upstream_status
                    CountingUpstream.reset_body = upstream_body
                    status, body = request_json(base_url, "/v1/kv/invalidate", {"local": True}, headers)
                    self.assertEqual(status, 502)
                    self.assertFalse(body["success"])

    def test_kv_invalidate_requires_scope_and_upstream_credential(self):
        runtime = self.runtime()
        app = guardrail.create_app(runtime=runtime, upstream=self.upstream_url,
                                   load_models=False, upstream_api_key="")
        with serve_app(app) as base_url:
            status, _ = request_json(base_url, "/v1/kv/invalidate", {"local": True})
            self.assertEqual(status, 503)

        app = guardrail.create_app(runtime=runtime, upstream=self.upstream_url,
                                   load_models=False, upstream_api_key="reset-secret")
        with serve_app(app) as base_url:
            status, _ = request_json(base_url, "/v1/kv/invalidate", {"local": True})
            self.assertEqual(status, 401)
            status, _ = request_json(
                base_url, "/v1/kv/invalidate", {"local": False},
                {"Authorization": "Bearer reset-secret"})
            self.assertEqual(status, 400)
        self.assertEqual(self.call_count(), 0)

        app = guardrail.create_app(runtime=runtime, upstream=f"http://127.0.0.1:{_free_port()}",
                                   load_models=False, upstream_api_key="reset-secret")
        with serve_app(app) as base_url:
            status, body = request_json(
                base_url, "/v1/kv/invalidate", {"local": True},
                {"Authorization": "Bearer reset-secret"})
            self.assertEqual(status, 502)
            self.assertFalse(body["success"])

    def test_reload_changes_only_variant_and_preserves_effective_config(self):
        runtime = self.runtime(mode="observe", threshold_pgv1=0.8, threshold_pgv2=0.6)
        with serve_app(self.app(runtime)) as base_url:
            status, state = request_json(base_url, "/v1/guardrail/state")
            self.assertEqual(status, 200)
            self.assertEqual(state["models"]["pgv1"]["revision"], "test-pgv1-revision")
            status, body = request_json(base_url, "/v1/guardrail/reload", {"variant": "pgv1"})
            self.assertEqual((status, body), (200, {"active": "pgv1", "applied": True}))
            status, state = request_json(base_url, "/v1/guardrail/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["active"], "pgv1")
        self.assertEqual(state["mode"], "observe")
        self.assertEqual(state["thresholds"], {"pgv1": 0.8, "pgv2": 0.6})

    def test_invalid_score_fails_without_upstream_call(self):
        runtime = self.runtime(scores={"bad": float("nan")})
        with serve_app(self.app(runtime)) as base_url:
            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "bad"}],
            })
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "guardrail score unavailable")
        self.assertEqual(self.call_count(), 0)

    def test_upstream_connection_failure_does_not_claim_completed_forwarding_and_closes_client(self):
        runtime = self.runtime(scores={"ordinary benign": 0.1})
        unreachable = f"http://127.0.0.1:{_free_port()}"
        real_client = guardrail.httpx.AsyncClient
        instances = []

        class TrackingClient(real_client):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.closed_by_proxy = False
                instances.append(self)

            async def aclose(self):
                self.closed_by_proxy = True
                await super().aclose()

        app = guardrail.create_app(runtime=runtime, upstream=unreachable, load_models=False)
        with mock.patch.object(guardrail.httpx, "AsyncClient", TrackingClient), \
                serve_app(app) as base_url, mock.patch("builtins.print") as printed:
            status, body = request_json(base_url, "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "ordinary benign"}],
            })
        self.assertEqual((status, body["error"]), (502, "upstream unavailable"))
        self.assertEqual(len(instances), 1)
        self.assertTrue(instances[0].closed_by_proxy)
        rendered = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn('"outcome":"admitted_enforce"', rendered)
        self.assertNotIn("forwarded", rendered)
        self.assertNotIn("completed", rendered)


class TransformTest(unittest.TestCase):
    def deployment(self):
        return {
            "metadata": {"name": "vllm", "resourceVersion": "1"},
            "spec": {"template": {"metadata": {}, "spec": {
                "containers": [{
                    "name": "vllm",
                    "args": ["serve", "--port", "8000"],
                    "readinessProbe": {"httpGet": {"path": "/health", "port": 8000}},
                }],
                "volumes": [],
            }}},
        }

    def test_transform_renders_explicit_validated_guardrail_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            dst = Path(tmp) / "out.json"
            src.write_text(json.dumps(self.deployment()))
            env = dict(os.environ, GUARDRAIL_INITIAL_VARIANT="pgv1", GUARDRAIL_MODE="observe",
                       GUARDRAIL_THRESHOLD_PGV1="0.81", GUARDRAIL_THRESHOLD_PGV2="0.62",
                       VLLM_API_KEY_SECRET_NAME="vllm-reset-api", VLLM_API_KEY_SECRET_KEY="token")
            subprocess.run([os.environ.get("PYTHON", "python3"), str(HERE / "transform.py"), str(src), str(dst)],
                           env=env, check=True, capture_output=True, text=True)
            rendered = json.loads(dst.read_text())
        template = rendered["spec"]["template"]
        self.assertEqual(template["metadata"]["annotations"]["phorvex.ai/guardrail-variant"], "pgv1")
        sidecar = next(container for container in template["spec"]["containers"] if container["name"] == "guardrail")
        values = {item["name"]: item["value"] for item in sidecar["env"] if "value" in item}
        self.assertEqual(values["GUARDRAIL_MODE"], "observe")
        self.assertEqual(values["GUARDRAIL_THRESHOLD_PGV1"], "0.81")
        self.assertEqual(values["GUARDRAIL_THRESHOLD_PGV2"], "0.62")
        credential = next(item for item in sidecar["env"] if item["name"] == "VLLM_API_KEY")
        self.assertEqual(credential["valueFrom"]["secretKeyRef"], {"name": "vllm-reset-api", "key": "token"})
        vllm = next(container for container in template["spec"]["containers"] if container["name"] == "vllm")
        self.assertEqual(next(item for item in vllm["env"] if item["name"] == "VLLM_API_KEY"), credential)

    def test_transform_rejects_invalid_mode_and_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            dst = Path(tmp) / "out.json"
            src.write_text(json.dumps(self.deployment()))
            for setting in ({"GUARDRAIL_MODE": "silent"}, {"GUARDRAIL_THRESHOLD_PGV1": "nan"}):
                with self.subTest(setting=setting):
                    result = subprocess.run(
                        [os.environ.get("PYTHON", "python3"), str(HERE / "transform.py"), str(src), str(dst)],
                        env=dict(os.environ, **setting), capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_transform_requires_secret_backed_reset_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            dst = Path(tmp) / "out.json"
            src.write_text(json.dumps(self.deployment()))
            env = dict(os.environ)
            env.pop("VLLM_API_KEY_SECRET_NAME", None)
            env.pop("VLLM_API_KEY_SECRET_KEY", None)
            result = subprocess.run(
                [os.environ.get("PYTHON", "python3"), str(HERE / "transform.py"), str(src), str(dst)],
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(dst.exists())

    def test_deploy_rejects_invalid_config_before_mutation_or_stale_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assets = root / "assets"
            output = root / "output"
            fake_bin = root / "bin"
            assets.mkdir()
            output.mkdir()
            fake_bin.mkdir()
            (assets / "transform.py").write_bytes((HERE / "transform.py").read_bytes())
            (assets / "guardrail_proxy.py").write_text("not reached\n")
            stale = output / "vllm-deploy.new.json"
            stale.write_text('{"stale":true}\n')
            command_log = root / "kubectl.log"
            kubectl = fake_bin / "kubectl"
            kubectl.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$KUBECTL_LOG\"\n"
                "if [[ \"$1 $2\" == \"get deploy\" ]]; then printf '{\\\"read_only\\\":true}\\n'; fi\n"
            )
            kubectl.chmod(kubectl.stat().st_mode | stat.S_IXUSR)
            base_env = dict(
                os.environ,
                PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                KUBECTL_LOG=str(command_log),
                GUARDRAIL_ASSET_DIR=str(assets),
                GUARDRAIL_OUT_DIR=str(output),
            )
            for setting in ({"GUARDRAIL_MODE": "silent"}, {"GUARDRAIL_THRESHOLD_PGV1": "nan"}):
                with self.subTest(setting=setting):
                    command_log.write_text("")
                    stale.write_text('{"stale":true}\n')
                    result = subprocess.run(
                        ["bash", str(HERE / "guardrail-deploy.sh")],
                        env=dict(base_env, **setting), capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    commands = command_log.read_text().splitlines()
                    self.assertEqual(len(commands), 1)
                    self.assertTrue(commands[0].startswith("get deploy"), commands)
                    self.assertFalse(any(word in command for command in commands
                                         for word in ("create", "apply", "replace", "patch", "delete")))
                    self.assertEqual(stale.read_text(), '{"stale":true}\n')


if __name__ == "__main__":
    unittest.main()
