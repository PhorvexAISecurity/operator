"""Real FastAPI route/lifespan and loopback proxy checks for the dual listener."""
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import httpx


HERE = Path(__file__).resolve().parent
GUARDRAIL = HERE.parents[1] / "test-harness" / "guardrail"
sys.path.insert(0, str(GUARDRAIL))
import guardrail_proxy

spec = importlib.util.spec_from_file_location("dual_server_real", HERE / "dual_server.py")
dual = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dual)


@contextmanager
def upstream():
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond()
        def do_POST(self):
            self.respond()
        def respond(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            calls.append((self.command, self.path, self.headers.get("Authorization")))
            data = b'{"success":true}' if self.path == "/reset_prefix_cache" else b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


class RealAppTest(unittest.TestCase):
    def test_fastapi_lifespan_public_inference_and_control_separation(self):
        with upstream() as (url, calls):
            runtime = guardrail_proxy.GuardrailRuntime(guardrail_proxy.load_config({}))
            runtime.install_classifier("pgv1", lambda _: [{"label": "LABEL_0", "score": 0.99}])
            runtime.install_classifier("pgv2", lambda _: [{"label": "LABEL_0", "score": 0.99}])
            app = guardrail_proxy.create_app(runtime=runtime, upstream=url, load_models=False,
                                             upstream_api_key="u" * 32, admin_api_key="a" * 32)
            wrapped = dual.ServingBoundary(app, "u" * 32, "a" * 32)
            async def exercise():
                async with app.router.lifespan_context(app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped),
                                                 base_url="http://127.0.0.1:8000") as public:
                        state = await public.get("/v1/guardrail/state")
                        self.assertEqual(state.status_code, 200)
                        self.assertTrue(state.json()["ready"])
                        completion = await public.post("/v1/chat/completions", json={"messages": [
                            {"role": "user", "content": "ordinary hello"}]},
                            headers={"Authorization": "Bearer caller"})
                        self.assertEqual(completion.status_code, 200)
                        embeddings = await public.post("/v1/embeddings", json={"input": "hello"})
                        self.assertEqual(embeddings.status_code, 200)
                        self.assertEqual((await public.post("/reset_prefix_cache")).status_code, 404)
                        self.assertEqual((await public.post("/v1/guardrail/reload", json={"variant": "pgv1"})).status_code, 404)
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped),
                                                 base_url="https://127.0.0.1:8443") as private:
                        self.assertEqual((await private.post("/v1/guardrail/reload", json={"variant": "pgv1"})).status_code, 401)
                        changed = await private.post("/v1/guardrail/reload", json={"variant": "pgv1"},
                                                     headers={"Authorization": "Bearer " + "a" * 32})
                        self.assertEqual(changed.status_code, 200)
                        reset = await private.post("/reset_prefix_cache", content=b"",
                                                   headers={"Authorization": "Bearer " + "a" * 32})
                        self.assertEqual(reset.status_code, 200)
                self.assertEqual(runtime.snapshot()[0], "pgv1")
            asyncio.run(exercise())
            self.assertEqual(calls, [
                ("POST", "/v1/chat/completions", "Bearer " + "u" * 32),
                ("POST", "/v1/embeddings", "Bearer " + "u" * 32),
                ("POST", "/reset_prefix_cache", "Bearer " + "u" * 32),
            ])

    def test_real_uvicorn_http_tls_startup_and_shutdown(self):
        def available_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        public_port, admin_port = available_port(), available_port()
        while admin_port == public_port:
            admin_port = available_port()
        with tempfile.TemporaryDirectory() as private:
            cert, key = Path(private) / "cert.pem", Path(private) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
            def fake_load(runtime):
                for variant in ("pgv1", "pgv2"):
                    runtime.install_classifier(variant, lambda _: [{"label": "LABEL_0", "score": 0.99}])
            env={"VLLM_API_KEY": "u" * 32, "PHORVEX_GUARDRAIL_ADMIN_KEY": "a" * 32,
                 "PHORVEX_ADMIN_TLS_CERT_FILE": str(cert), "PHORVEX_ADMIN_TLS_KEY_FILE": str(key)}
            async def exercise():
                task=asyncio.create_task(dual.serve())
                try:
                    async with httpx.AsyncClient(verify=False, timeout=2) as client:
                        for _ in range(30):
                            try:
                                response=await client.get(f"http://127.0.0.1:{public_port}/v1/guardrail/state")
                                if response.status_code==200: break
                            except httpx.HTTPError:
                                pass
                            await asyncio.sleep(0.1)
                        else:
                            self.fail("public Uvicorn listener did not start")
                        refused=await client.post(f"http://127.0.0.1:{public_port}/reset_prefix_cache")
                        self.assertEqual(refused.status_code,404)
                        denied=await client.post(f"https://127.0.0.1:{admin_port}/v1/guardrail/reload",
                                                 json={"variant":"pgv1"})
                        self.assertEqual(denied.status_code,401)
                        accepted=await client.post(f"https://127.0.0.1:{admin_port}/v1/guardrail/reload",
                           json={"variant":"pgv1"},headers={"Authorization":"Bearer "+"a"*32})
                        self.assertEqual(accepted.status_code,200)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            with mock.patch.dict(os.environ,env), \
                 mock.patch.object(dual,"PUBLIC_PORT",public_port), \
                 mock.patch.object(dual,"ADMIN_PORT",admin_port), \
                 mock.patch.object(guardrail_proxy.GuardrailRuntime,"load_all",fake_load):
                asyncio.run(asyncio.wait_for(exercise(),timeout=15))


if __name__ == "__main__":
    unittest.main()
