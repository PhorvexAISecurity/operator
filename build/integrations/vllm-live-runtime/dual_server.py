"""Two listeners for one guardrail runtime: public inference and private TLS control.

The public listener never exposes an upstream control route. Both listeners share
the same FastAPI app, classifier state, and drain coordinator in one process.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
import re
import threading
import time


PUBLIC_PORT = 8000
ADMIN_PORT = 8443
PUBLIC_MODEL = {
    ("GET", "/v1/models"),
    ("POST", "/v1/completions"),
    ("POST", "/v1/chat/completions"),
    ("POST", "/v1/embeddings"),
    ("POST", "/v1/rerank"),
    ("POST", "/v1/score"),
    ("POST", "/v1/audio/transcriptions"),
    ("POST", "/v1/audio/translations"),
    ("POST", "/tokenize"),
    ("POST", "/detokenize"),
    ("POST", "/pooling"),
    ("POST", "/rerank"),
    ("POST", "/score"),
}
PUBLIC_LOCAL = {("GET", "/v1/guardrail/state"), ("GET", "/health")}
ADMIN_MODEL = {
    ("GET", "/v1/models"), ("GET", "/health"),
    ("POST", "/reset_prefix_cache"),
    ("POST", "/v1/load_lora_adapter"),
    ("POST", "/v1/unload_lora_adapter"),
}
ADMIN_LOCAL = {
    ("GET", "/v1/guardrail/state"),
    ("POST", "/v1/guardrail/reload"),
    ("POST", "/v1/guardrail/classify"),
    ("POST", "/v1/kv/invalidate"),
    ("POST", "/v1/drain"),
    ("GET", "/v1/drain/capability"),
    ("POST", "/v1/drain/operations"),
    ("GET", "/v1/endpoint-lease/state"),
}
ADMIN_OPERATION = re.compile(
    r"/v1/drain/operations/[0-9]+/[0-9a-f]{32,64}(?:/(?:cancel|reopen))?\Z"
)
MAX_ADMIN_BODY = 65536


def _credential(name: str) -> str:
    value = os.environ.get(name, "")
    if not 32 <= len(value) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError(f"{name} is required as 32–256 printable non-space bytes")
    return value


async def _reply(send, status: int, code: bytes):
    body = b'{"error":"' + code + b'"}'
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def _json_reply(send, value: dict):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > 8192:
        await _reply(send, 503, b"lease_unavailable")
        return
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def _status_query(raw: bytes) -> tuple[str, str] | None:
    if len(raw) > 192:
        return None
    parts = raw.split(b"&")
    if len(parts) != 2:
        return None
    fields = {}
    for part in parts:
        key, sep, value = part.partition(b"=")
        if not sep or key not in (b"revokedClientHMAC", b"retainedClientHMAC") or \
                key in fields or not re.fullmatch(b"[0-9a-f]{64}", value):
            return None
        fields[key] = value.decode("ascii")
    if len(fields) != 2:
        return None
    return fields[b"revokedClientHMAC"], fields[b"retainedClientHMAC"]


class ServingBoundary:
    def __init__(self, app, upstream_key: str, admin_key: str, lease=None):
        if upstream_key == admin_key:
            raise ValueError("admin and upstream keys must differ")
        self.app, self.upstream_key, self.admin_key = app, upstream_key, admin_key
        self.lease = lease

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope.get("type") != "http":
            if scope.get("type") == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        server = scope.get("server")
        port = server[1] if isinstance(server, (tuple, list)) and len(server) == 2 else None
        method, path = scope.get("method"), scope.get("path")
        pair = method, path
        headers = list(scope.get("headers") or ())
        auth = [v for k, v in headers if k.lower() == b"authorization"]
        admission = None
        if port == PUBLIC_PORT:
            if pair not in PUBLIC_MODEL and pair not in PUBLIC_LOCAL:
                await _reply(send, 404, b"route_unavailable")
                return
            if self.lease is not None and pair == ("GET", "/health") and \
                    not await self.lease.ready():
                await _reply(send, 503, b"lease_unavailable")
                return
            if pair in PUBLIC_MODEL:
                if self.lease is not None:
                    admission = await self.lease.admit(auth)
                    if admission.status != 200:
                        await _reply(send, admission.status,
                                     b"unauthorized" if admission.status == 401
                                     else b"lease_unavailable")
                        return
                headers = [(k, v) for k, v in headers if k.lower() != b"authorization"]
                headers.append((b"authorization", ("Bearer " + self.upstream_key).encode()))
        elif port == ADMIN_PORT:
            operation = bool(ADMIN_OPERATION.fullmatch(path or "")) and method in ("GET", "POST")
            if pair not in ADMIN_MODEL and pair not in ADMIN_LOCAL and not operation:
                await _reply(send, 404, b"route_unavailable")
                return
            if len(auth) != 1 or not hmac.compare_digest(auth[0], ("Bearer " + self.admin_key).encode()):
                await _reply(send, 401, b"unauthorized")
                return
            if pair == ("GET", "/v1/endpoint-lease/state"):
                if self.lease is None:
                    await _reply(send, 404, b"route_unavailable")
                    return
                query = _status_query(scope.get("query_string", b""))
                if query is None:
                    await _reply(send, 400, b"invalid_request")
                    return
                value = await self.lease.status(*query)
                if value is None:
                    await _reply(send, 503, b"lease_unavailable")
                else:
                    await _json_reply(send, value)
                return
            if pair in ADMIN_MODEL:
                headers = [(k, v) for k, v in headers if k.lower() != b"authorization"]
                headers.append((b"authorization", ("Bearer " + self.upstream_key).encode()))
            # The app's named controls receive the operator's admin bearer.
            size = 0
            chunks = []
            deadline = time.monotonic() + 10
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    await _reply(send, 408, b"request_timeout")
                    return
                try:
                    event = await asyncio.wait_for(receive(), timeout=min(5, remaining))
                except asyncio.TimeoutError:
                    await _reply(send, 408, b"request_timeout")
                    return
                if event["type"] == "http.disconnect":
                    return
                if event["type"] != "http.request":
                    await _reply(send, 400, b"invalid_request")
                    return
                chunk = event.get("body", b"")
                size += len(chunk)
                if size > MAX_ADMIN_BODY:
                    await _reply(send, 413, b"request_too_large")
                    return
                chunks.append(chunk)
                if not event.get("more_body", False):
                    break
            body = b"".join(chunks)
            replayed = False
            disconnect = asyncio.Event()
            async def replay():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                await disconnect.wait()
                return {"type": "http.disconnect"}
            receive = replay
        else:
            await _reply(send, 404, b"listener_unavailable")
            return
        projected = dict(scope)
        projected["headers"] = headers
        try:
            await self.app(projected, receive, send)
        finally:
            if admission is not None:
                release = asyncio.create_task(self.lease.finish(admission))
                try:
                    await asyncio.shield(release)
                except asyncio.CancelledError:
                    await release
                    raise


async def serve():
    import uvicorn
    import guardrail_proxy
    from guardrail_proxy import GuardrailRuntime, create_app, load_config

    upstream, admin = _credential("VLLM_API_KEY"), _credential("PHORVEX_GUARDRAIL_ADMIN_KEY")
    cert = Path(os.environ["PHORVEX_ADMIN_TLS_CERT_FILE"])
    key = Path(os.environ["PHORVEX_ADMIN_TLS_KEY_FILE"])
    if not cert.is_file() or not key.is_file():
        raise ValueError("admin TLS certificate and key are required")
    runtime = GuardrailRuntime(load_config())
    lease_mode = os.environ.get("PHORVEX_ENDPOINT_LEASE_REQUIRED", "false")
    if lease_mode not in ("true", "false"):
        raise ValueError("PHORVEX_ENDPOINT_LEASE_REQUIRED must be true or false")
    lease = None
    if lease_mode == "true":
        from endpoint_lease import EndpointLease, Identity, source_sha256
        import endpoint_lease
        actual_source = source_sha256(Path(guardrail_proxy.__file__).read_bytes(),
                                      Path(__file__).read_bytes(),
                                      Path(endpoint_lease.__file__).read_bytes(),
                                      (Path(__file__).parent / "drain_v11.py").read_bytes(),
                                      (Path(__file__).parent / "drain_v11_init.py").read_bytes())
        lease = EndpointLease(Identity(
            pod_uid=os.environ.get("POD_UID", ""),
            service_uid=os.environ.get("PHORVEX_ENDPOINT_LEASE_SERVICE_UID", ""),
            policy_configmap_uid=os.environ.get("PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", ""),
            secret_uid=os.environ.get("PHORVEX_ENDPOINT_LEASE_SECRET_UID", ""),
            source_sha256=os.environ.get("PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", ""),
            source_actual_sha256=actual_source,
            secret_dir=Path(os.environ.get("PHORVEX_ENDPOINT_LEASE_SECRET_DIR", ""))))
    app = ServingBoundary(create_app(runtime=runtime, upstream_api_key=upstream,
                                     admin_api_key=admin, load_models=False), upstream, admin, lease)
    # Classifier loading is independent of the engine capability handshake.
    # Start both cold paths together; the public listener still waits for the
    # validated drain capability in FastAPI lifespan before it can bind.
    threading.Thread(target=runtime.load_all, daemon=True).start()
    public = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=PUBLIC_PORT,
                                           lifespan="on", proxy_headers=False, log_level="info"))
    private = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=ADMIN_PORT,
                                            lifespan="off", proxy_headers=False,
                                            ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="info"))
    await serve_pair(public, private)


async def serve_pair(public, private, *, shutdown_timeout=10.0):
    """Bind private control only after public lifespan proves engine capability."""
    public_task = asyncio.create_task(public.serve())
    tasks = [public_task]
    try:
        while not public.started:
            if public_task.done():
                public_task.result()
                raise RuntimeError("public listener stopped before startup")
            await asyncio.sleep(0.05)
        if public_task.done():
            public_task.result()
            raise RuntimeError("public listener stopped before private startup")
        tasks.append(asyncio.create_task(private.serve()))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        raise RuntimeError("one serving listener stopped")
    finally:
        public.should_exit = private.should_exit = True
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=shutdown_timeout)
        except TimeoutError:
            public.force_exit = private.force_exit = True
            for task in tasks:
                task.cancel()
            _, pending = await asyncio.wait(tasks, timeout=1.0)
            if pending:
                raise RuntimeError("listener shutdown timed out")


if __name__ == "__main__":
    asyncio.run(serve())
