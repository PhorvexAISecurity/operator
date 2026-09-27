"""Two listeners for one guardrail runtime: public inference and private TLS control.

The public listener never exposes an upstream control route. Both listeners share
the same FastAPI app, classifier state, and drain coordinator in one process.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from pathlib import Path
import re
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


class ServingBoundary:
    def __init__(self, app, upstream_key: str, admin_key: str):
        if upstream_key == admin_key:
            raise ValueError("admin and upstream keys must differ")
        self.app, self.upstream_key, self.admin_key = app, upstream_key, admin_key

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
        if port == PUBLIC_PORT:
            if pair not in PUBLIC_MODEL and pair not in PUBLIC_LOCAL:
                await _reply(send, 404, b"route_unavailable")
                return
            if pair in PUBLIC_MODEL:
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
        await self.app(projected, receive, send)


async def serve():
    import uvicorn
    from guardrail_proxy import GuardrailRuntime, create_app, load_config

    upstream, admin = _credential("VLLM_API_KEY"), _credential("PHORVEX_GUARDRAIL_ADMIN_KEY")
    cert = Path(os.environ["PHORVEX_ADMIN_TLS_CERT_FILE"])
    key = Path(os.environ["PHORVEX_ADMIN_TLS_KEY_FILE"])
    if not cert.is_file() or not key.is_file():
        raise ValueError("admin TLS certificate and key are required")
    runtime = GuardrailRuntime(load_config())
    app = ServingBoundary(create_app(runtime=runtime, upstream_api_key=upstream,
                                     admin_api_key=admin), upstream, admin)
    public = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=PUBLIC_PORT,
                                           lifespan="on", proxy_headers=False, log_level="info"))
    private = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=ADMIN_PORT,
                                            lifespan="off", proxy_headers=False,
                                            ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="info"))
    tasks = [asyncio.create_task(public.serve()), asyncio.create_task(private.serve())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        raise RuntimeError("one serving listener stopped")
    finally:
        public.should_exit = private.should_exit = True
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(serve())
