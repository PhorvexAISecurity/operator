"""Synthetic lease controls through the real public/private ASGI boundary."""

import asyncio
import base64
import certifi
from contextlib import contextmanager
import copy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest

import httpx

import endpoint_lease as lease_module
from test_real_app import guardrail_proxy, upstream


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lease_dual_server", HERE / "dual_server.py")
dual = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dual)

POD = "44444444-4444-4444-8444-444444444444"
SERVICE = "11111111-1111-4111-8111-111111111111"
SECRET = "22222222-2222-4222-8222-222222222222"
POLICY = "33333333-3333-4333-8333-333333333333"
SOURCE = "c" * 64
SEED = b"s" * 48
A = b"a" * 48
B = b"b" * 48
ADMIN = "z" * 48
UPSTREAM = "u" * 48
A_ID = hmac.new(SEED, A, hashlib.sha256).hexdigest()
B_ID = hmac.new(SEED, B, hashlib.sha256).hexdigest()


def rule(revision=0, seed=SEED):
    a_id = hmac.new(seed, A, hashlib.sha256).hexdigest()
    b_id = hmac.new(seed, B, hashlib.sha256).hexdigest()
    return {"version": 1, "revision": revision, "serviceUID": SERVICE,
            "proxySourceSHA256": SOURCE, "secretUID": SECRET,
            "seedSHA256": hashlib.sha256(seed).hexdigest(),
            "allowedClientHMACs": sorted((a_id, b_id)) if revision == 0 else [b_id],
            "revokedClientHMACs": [] if revision == 0 else [a_id],
            "lastOperationID": "" if revision == 0 else "d" * 64}


class FakeKubernetes:
    def __init__(self, seed=SEED):
        self.seed = seed
        self.state = rule(seed=seed)
        self.secret_uid = SECRET
        self.fail = False
        self.calls = []

    async def __call__(self, kind):
        self.calls.append(kind)
        if self.fail:
            raise lease_module.AuthorityUnavailable("API unavailable")
        if kind == "policy":
            value = {"kind": "ConfigMap", "metadata": {"name": lease_module.POLICY_NAME,
                     "namespace": "vllm", "uid": POLICY},
                     "data": {"state.json": lease_module.canonical(self.state).decode()}}
        else:
            value = {"kind": "Secret", "immutable": True,
                     "metadata": {"name": lease_module.SECRET_NAME,
                                  "namespace": "vllm", "uid": self.secret_uid},
                     "data": {key: base64.b64encode(data).decode() for key, data in
                              (("client-a", A), ("client-b", B), ("seed", self.seed))}}
        return copy.deepcopy(value)


@contextmanager
def fixture(seed=SEED):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        generation = root / "..2026_09_27"
        generation.mkdir()
        for name, value in (("client-a", A), ("client-b", B), ("seed", seed)):
            (generation / name).write_bytes(value)
        (root / "..data").symlink_to(generation.name)
        api = FakeKubernetes(seed)
        identity = lease_module.Identity(POD, SERVICE, POLICY, SECRET,
                                         SOURCE, SOURCE, root)
        yield lease_module.EndpointLease(identity, api), api, root


def app_with_calls():
    calls = []
    async def app(scope, _receive, send):
        calls.append((scope["path"], list(scope["headers"])))
        body = b'{"model":"real-upstream","choices":[{"text":"public answer"}]}'
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})
    return app, calls


def status_url():
    return "/v1/endpoint-lease/state?revokedClientHMAC=" + A_ID + \
           "&retainedClientHMAC=" + B_ID


class EndpointLeaseTest(unittest.TestCase):
    def test_binary_seed_keeps_live_authority_and_caller_checks(self):
        seed = b"\x00\xff" * 16
        with fixture(seed) as (lease, api, _root):
            downstream, calls = app_with_calls()
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)

            async def exercise():
                self.assertTrue(await lease.ready())
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public:
                    self.assertEqual((await public.get("/health")).status_code, 200)
                    for bearer in (A, B):
                        self.assertEqual((await public.post("/v1/chat/completions", headers={
                            "Authorization": "Bearer " + bearer.decode()})).status_code, 200)
                    self.assertEqual((await public.post("/v1/chat/completions", headers={
                        "Authorization": "Bearer " + (b"x" * 48).decode()})).status_code, 401)
                    api.state = rule(1, seed)
                    self.assertEqual((await public.post("/v1/chat/completions", headers={
                        "Authorization": "Bearer " + A.decode()})).status_code, 401)
                    self.assertEqual((await public.post("/v1/chat/completions", headers={
                        "Authorization": "Bearer " + B.decode()})).status_code, 200)
                secret = await api("secret")
                secret["data"]["client-a"] = base64.b64encode(b"\x00" * 48).decode()
                with self.assertRaises(lease_module.AuthorityUnavailable):
                    lease_module._secret_bytes(secret, SECRET)
                secret["data"]["client-a"] = base64.b64encode(A).decode()
                secret["data"]["seed"] = base64.b64encode(seed[:31]).decode()
                with self.assertRaises(lease_module.AuthorityUnavailable):
                    lease_module._secret_bytes(secret, SECRET)
                secret["data"]["seed"] = base64.b64encode(seed * 9).decode()
                with self.assertRaises(lease_module.AuthorityUnavailable):
                    lease_module._secret_bytes(secret, SECRET)
                secret["data"]["seed"] = base64.b64encode(seed).decode() + "="
                with self.assertRaises(lease_module.AuthorityUnavailable):
                    lease_module._secret_bytes(secret, SECRET)

            asyncio.run(exercise())
            self.assertEqual(sum(path == "/v1/chat/completions" for path, _ in calls), 3)

    def test_canonical_wire_and_source_closure(self):
        before = lease_module.canonical(rule())
        after = lease_module.canonical(rule(1))
        self.assertEqual(lease_module.parse_state(before)["revision"], 0)
        self.assertEqual(lease_module.parse_state(after)["revision"], 1)
        real_decision = rule(1)
        real_decision["lastOperationID"] = "d" * 32
        self.assertEqual(lease_module.parse_state(lease_module.canonical(real_decision))
                         ["lastOperationID"], "d" * 32)
        self.assertEqual(lease_module.source_sha256(b"p", b"b", b"l", b"d", b"i"),
                         hashlib.sha256(b"p\0b\0l\0d\0i").hexdigest())
        for bad in (before + b"\n", before.replace(b'"revision":0', b'"revision":0.0'),
                    before.replace(b'"version":1', b'"version":1,"version":1'),
                    before.replace(b'"serviceUID"', b'"serviceUid"'),
                    b"{" + b"x" * (lease_module.MAX_STATE + 1) + b"}"):
            with self.assertRaises(lease_module.AuthorityUnavailable):
                lease_module.parse_state(bad)
        short_decision = rule(1)
        short_decision["lastOperationID"] = "d" * 31
        with self.assertRaises(lease_module.AuthorityUnavailable):
            lease_module.parse_state(lease_module.canonical(short_decision))
        null_roster = rule()
        null_roster["revokedClientHMACs"] = None
        with self.assertRaises(lease_module.AuthorityUnavailable):
            lease_module.parse_state(lease_module.canonical(null_roster))
        wire = {"version": 1, "revision": 0, "serviceUID": SERVICE,
                "proxySourceSHA256": SOURCE, "secretUID": SECRET,
                "seedSHA256": "e" * 64,
                "allowedClientHMACs": ["a" * 64, "b" * 64],
                "revokedClientHMACs": [], "lastOperationID": ""}
        self.assertEqual(hashlib.sha256(lease_module.canonical(wire)).hexdigest(),
                         "1288af043ecb5906a712aede455fcd74a361cc796bed852b9b08ade575c8568e")

    def test_real_guardrail_handler_keeps_public_answer_and_internal_key(self):
        with fixture() as (lease, api, _root), upstream() as (url, calls):
            runtime = guardrail_proxy.GuardrailRuntime(guardrail_proxy.load_config({}))
            runtime.install_classifier("pgv1", lambda _: [{"label": "LABEL_0", "score": 0.99}])
            runtime.install_classifier("pgv2", lambda _: [{"label": "LABEL_0", "score": 0.99}])
            app = guardrail_proxy.create_app(runtime=runtime, upstream=url, load_models=False,
                                              upstream_api_key=UPSTREAM, admin_api_key=ADMIN)
            boundary = dual.ServingBoundary(app, UPSTREAM, ADMIN, lease)
            async def exercise():
                async with app.router.lifespan_context(app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                                 base_url="http://127.0.0.1:8000") as public:
                        request = {"messages": [{"role": "user", "content": "ordinary hello"}]}
                        first = await public.post("/v1/chat/completions", json=request,
                                                  headers={"Authorization": "Bearer " + A.decode()})
                        self.assertEqual(first.status_code, 200)
                        self.assertEqual(first.json(), {"ok": True})
                        api.state = rule(1)
                        denied = await public.post("/v1/chat/completions", json=request,
                                                   headers={"Authorization": "Bearer " + A.decode()})
                        self.assertEqual((denied.status_code, denied.json()),
                                         (401, {"error": "unauthorized"}))
                        retained = await public.post("/v1/chat/completions", json=request,
                                                     headers={"Authorization": "Bearer " + B.decode()})
                        self.assertEqual((retained.status_code, retained.json()), (200, {"ok": True}))
            asyncio.run(exercise())
            self.assertEqual(calls, [("POST", "/v1/chat/completions", "Bearer " + UPSTREAM)] * 2)

    def test_public_revoke_restart_and_private_status(self):
        with fixture() as (lease, api, _root):
            downstream, calls = app_with_calls()
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)
            async def exercise():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public, \
                           httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="https://127.0.0.1:8443") as private:
                    initial = await public.post("/v1/chat/completions", content=b"{}",
                                                headers={"Authorization": "Bearer " + A.decode()})
                    self.assertEqual(initial.status_code, 200)
                    self.assertIn("choices", initial.json())
                    self.assertEqual((await public.get("/health")).status_code, 200)
                    api.state = rule(1)
                    denied = await public.post("/v1/chat/completions", content=b"{}",
                                               headers={"Authorization": "Bearer " + A.decode()})
                    self.assertEqual((denied.status_code, denied.json()),
                                     (401, {"error": "unauthorized"}))
                    retained = await public.post("/v1/chat/completions", content=b"{}",
                                                 headers={"Authorization": "Bearer " + B.decode()})
                    self.assertEqual(retained.status_code, 200)
                    self.assertEqual((await private.get(status_url(), headers={
                        "Authorization": "Bearer " + A.decode()})).status_code, 401)
                    state = await private.get(status_url(), headers={
                        "Authorization": "Bearer " + ADMIN})
                    self.assertEqual(state.status_code, 200)
                    self.assertEqual(state.headers["content-type"], "application/json")
                    body = state.json()
                    self.assertEqual(state.content, lease_module.canonical(body))
                    self.assertEqual(set(body), set(("version", "ready", "podUID", "serviceUID",
                                     "policyConfigMapUID", "secretUID", "proxySourceSHA256",
                                     "seedSHA256", "stateSHA256", "revision", "lastOperationID",
                                     "revokedClientHMAC", "retainedClientHMAC",
                                     "revokedClientAllowed", "retainedClientAllowed",
                                     "oldRevisionInFlight")))
                    self.assertEqual((body["revision"], body["revokedClientAllowed"],
                                      body["retainedClientAllowed"], body["oldRevisionInFlight"]),
                                     (1, False, True, 0))
                    self.assertNotIn(A.decode(), state.text)
                    self.assertNotIn(B.decode(), state.text)
                    self.assertNotIn(SEED.decode(), state.text)
                    self.assertEqual((await private.get(status_url() + "&other=x", headers={
                        "Authorization": "Bearer " + ADMIN})).status_code, 400)
                    restarted = dual.ServingBoundary(downstream, UPSTREAM, ADMIN,
                        lease_module.EndpointLease(lease.identity, api))
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted),
                                                 base_url="http://127.0.0.1:8000") as fresh:
                        self.assertEqual((await fresh.post("/v1/chat/completions", content=b"{}",
                            headers={"Authorization": "Bearer " + A.decode()})).status_code, 401)
                model_calls = [headers for path, headers in calls if path == "/v1/chat/completions"]
                self.assertEqual(len(model_calls), 2)
                for headers in model_calls:
                    auth = [v for k, v in headers if k.lower() == b"authorization"]
                    self.assertEqual(auth, [("Bearer " + UPSTREAM).encode()])
                self.assertGreaterEqual(api.calls.count("policy"), 5)
            asyncio.run(exercise())

    def test_api_secret_source_and_revision_uncertainty_never_forward(self):
        with fixture() as (lease, api, root):
            downstream, calls = app_with_calls()
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)
            async def exercise():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public:
                    def headers(value=B):
                        return {"Authorization": "Bearer " + value.decode()}
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 200)
                    api.fail = True
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 503)
                    self.assertEqual((await public.get("/health")).status_code, 503)
                    api.fail = False
                    api.secret_uid = "99999999-9999-4999-8999-999999999999"
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 503)
                    api.secret_uid = SECRET
                    (root / "..2026_09_27" / "seed").write_bytes(b"t" * 48)
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 503)
                    (root / "..2026_09_27" / "seed").write_bytes(SEED)
                    api.state = rule(1)
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 200)
                    api.state = rule()
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 503)
                    duplicate = [("Authorization", "Bearer " + B.decode()),
                                 ("Authorization", "Bearer " + B.decode())]
                    self.assertEqual((await public.post("/v1/chat/completions", headers=duplicate)).status_code, 401)
                    self.assertEqual((await public.post("/v1/chat/completions")).status_code, 401)
                    api.state = rule(1)
                    api.state["lastOperationID"] = "e" * 64
                    self.assertEqual((await public.post("/v1/chat/completions", headers=headers())).status_code, 503)
                self.assertEqual(len(calls), 2)
            asyncio.run(exercise())
        wrong = lease_module.Identity(POD, SERVICE, POLICY, SECRET, SOURCE, "f" * 64,
                                      Path("/unavailable"))
        self.assertFalse(asyncio.run(lease_module.EndpointLease(wrong, api).ready()))

    def test_every_public_model_route_requires_a_caller_and_private_a_cannot_reach_model(self):
        with fixture() as (lease, api, _root):
            api.state = rule(1)
            downstream, calls = app_with_calls()
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)
            async def exercise():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public, \
                           httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="https://127.0.0.1:8443") as private:
                    for method, path in sorted(dual.PUBLIC_MODEL):
                        denied = await public.request(method, path,
                            headers={"Authorization": "Bearer " + A.decode()})
                        self.assertEqual((denied.status_code, denied.json()),
                                         (401, {"error": "unauthorized"}), (method, path))
                        good = await public.request(method, path,
                            headers={"Authorization": "Bearer " + B.decode()})
                        self.assertEqual(good.status_code, 200, (method, path))
                    private_a = await private.post("/reset_prefix_cache",
                        headers={"Authorization": "Bearer " + A.decode()})
                    self.assertEqual(private_a.status_code, 401)
                self.assertEqual(len(calls), len(dual.PUBLIC_MODEL))
                for _, headers in calls:
                    self.assertEqual([v for k, v in headers if k.lower() == b"authorization"],
                                     [("Bearer " + UPSTREAM).encode()])
            asyncio.run(exercise())

    def test_stream_remains_in_flight_until_final_body_and_disconnect(self):
        with fixture() as (lease, api, _root):
            started, finish = asyncio.Event(), asyncio.Event()
            async def downstream(_scope, _receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"data: first\n\n", "more_body": True})
                started.set()
                await finish.wait()
                await send({"type": "http.response.body", "body": b"data: done\n\n"})
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)
            async def exercise(cancel):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public, \
                           httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="https://127.0.0.1:8443") as private:
                    task = asyncio.create_task(public.post("/v1/chat/completions",
                        headers={"Authorization": "Bearer " + A.decode()}))
                    await asyncio.wait_for(started.wait(), 2)
                    api.state = rule(1)
                    before = await private.get(status_url(), headers={"Authorization": "Bearer " + ADMIN})
                    self.assertEqual(before.json()["oldRevisionInFlight"], 1)
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        finish.set()
                        self.assertEqual((await task).status_code, 200)
                    after = await private.get(status_url(), headers={"Authorization": "Bearer " + ADMIN})
                    self.assertEqual(after.json()["oldRevisionInFlight"], 0)
            asyncio.run(exercise(False))

    def test_cancelled_stream_releases_old_revision_without_false_early_zero(self):
        with fixture() as (lease, api, _root):
            started, release = asyncio.Event(), asyncio.Event()
            async def downstream(_scope, _receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"data: admitted\n\n",
                            "more_body": True})
                started.set()
                await release.wait()
            boundary = dual.ServingBoundary(downstream, UPSTREAM, ADMIN, lease)
            async def exercise():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="http://127.0.0.1:8000") as public, \
                           httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary),
                                             base_url="https://127.0.0.1:8443") as private:
                    task = asyncio.create_task(public.post("/v1/chat/completions",
                        headers={"Authorization": "Bearer " + A.decode()}))
                    await asyncio.wait_for(started.wait(), 2)
                    api.state = rule(1)
                    state = await private.get(status_url(), headers={"Authorization": "Bearer " + ADMIN})
                    self.assertEqual(state.json()["oldRevisionInFlight"], 1)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    for _ in range(20):
                        state = await private.get(status_url(), headers={"Authorization": "Bearer " + ADMIN})
                        if state.json()["oldRevisionInFlight"] == 0:
                            break
                        await asyncio.sleep(0.01)
                    self.assertEqual(state.json()["oldRevisionInFlight"], 0)
            asyncio.run(exercise())

    def test_named_api_reader_is_bounded_and_uses_service_account_token(self):
        seen = []
        body = json.dumps({"kind": "ConfigMap", "metadata": {"name": lease_module.POLICY_NAME}}).encode()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                token = Path(directory) / "token"
                token.write_text("synthetic-service-account-token")
                reader = lease_module.KubernetesReader(
                    base_url=f"http://127.0.0.1:{server.server_port}", token_file=token,
                    ca_file=Path(certifi.where()))
                result = asyncio.run(reader("policy"))
                self.assertEqual(result["kind"], "ConfigMap")
                self.assertEqual(seen, [(f"/api/v1/namespaces/vllm/configmaps/{lease_module.POLICY_NAME}",
                                        "Bearer synthetic-service-account-token")])
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
