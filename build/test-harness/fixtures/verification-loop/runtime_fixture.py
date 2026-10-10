#!/usr/bin/env python3
"""Local credential-admission fixture; the downstream is synthetic, not GPU inference.

The production EndpointLease and ServingBoundary files are imported unchanged.
Only the Kubernetes TLS transport and ephemeral listener identity are adapted.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import hmac
import importlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import sys
from urllib.parse import urlsplit

import httpx
import uvicorn

MARKER = "verification-loop-synthetic-downstream"
SCOPE = "credential-admission-with-synthetic-downstream"
MAX_BODY = 8192


def load_runtime(repo: Path):
    directory = repo.resolve(strict=True) / "build/integrations/vllm-live-runtime"
    sys.path.insert(0, str(directory))
    lease = importlib.import_module("endpoint_lease")
    boundary = importlib.import_module("dual_server")
    if Path(lease.__file__).resolve() != directory / "endpoint_lease.py" or \
            Path(boundary.__file__).resolve() != directory / "dual_server.py":
        raise ValueError("production runtime import differs")
    guardrail = repo.resolve(strict=True) / "build/test-harness/guardrail"
    source = lease.source_sha256((guardrail / "guardrail_proxy.py").read_bytes(),
                                (directory / "dual_server.py").read_bytes(),
                                (directory / "endpoint_lease.py").read_bytes(),
                                (guardrail / "drain_v11.py").read_bytes(),
                                (guardrail / "drain_v11_init.py").read_bytes())
    return lease, boundary, source


def api_reader(lease_module, config):
    """Keep production parsing/bounds and exact names, adapting envtest mTLS only."""
    address = urlsplit(config["api_url"])
    if address.scheme != "https" or not address.hostname or \
            not ipaddress.ip_address(address.hostname).is_loopback or \
            address.username or address.password or address.path not in ("", "/") or \
            address.query or address.fragment:
        raise ValueError("envtest API must be a pinned loopback TLS address")
    context = ssl.create_default_context(cafile=config["api_ca_file"])
    context.load_cert_chain(config["api_client_cert_file"], config["api_client_key_file"])

    class EnvtestReader(lease_module.KubernetesReader):
        def __init__(self):
            super().__init__(base_url=config["api_url"].rstrip("/"))

        async def __call__(self, kind):
            if kind == "policy":
                path = "/api/v1/namespaces/vllm/configmaps/" + lease_module.POLICY_NAME
            elif kind == "secret":
                path = "/api/v1/namespaces/vllm/secrets/" + lease_module.SECRET_NAME
            else:
                raise lease_module.AuthorityUnavailable("unknown API resource")
            async with httpx.AsyncClient(verify=context, trust_env=False,
                                         follow_redirects=False,
                                         timeout=httpx.Timeout(2.0, connect=1.0)) as client:
                async with client.stream("GET", self.base_url + path,
                                         headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200 or not response.headers.get(
                            "content-type", "").startswith("application/json"):
                        raise lease_module.AuthorityUnavailable("named Kubernetes API read failed")
                    chunks, size = [], 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > lease_module.MAX_API:
                            raise lease_module.AuthorityUnavailable("named Kubernetes API response exceeds bound")
                        chunks.append(chunk)
            value = lease_module._json(b"".join(chunks))
            if not isinstance(value, dict):
                raise lease_module.AuthorityUnavailable("named Kubernetes API shape differs")
            return value

    return EnvtestReader()


async def reply(send, status, value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def body_bytes(receive):
    chunks, size = [], 0
    async with asyncio.timeout(3):
        while True:
            event = await receive()
            if event["type"] != "http.request":
                raise ValueError("request disconnected")
            chunk = event.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY:
                raise ValueError("request exceeds bound")
            chunks.append(chunk)
            if not event.get("more_body", False):
                return b"".join(chunks)


def authorized(scope, token):
    values = [v for k, v in scope.get("headers", ()) if k.lower() == b"authorization"]
    return len(values) == 1 and hmac.compare_digest(values[0], ("Bearer " + token).encode())


class Downstream:
    def __init__(self, upstream_key):
        self.upstream_key = upstream_key
        self.call_count = 0

    async def __call__(self, scope, receive, send):
        if not authorized(scope, self.upstream_key):
            await reply(send, 401, {"error": "unauthorized"})
            return
        if (scope["method"], scope["path"]) != ("POST", "/v1/completions"):
            await reply(send, 404, {"error": "route_unavailable"})
            return
        try:
            value = json.loads(await body_bytes(receive))
            nonce = value["nonce"]
            if not isinstance(nonce, str) or not 1 <= len(nonce) <= 128 or \
                    any(ord(c) < 33 or ord(c) > 126 for c in nonce):
                raise ValueError("nonce shape differs")
        except (ValueError, KeyError, TypeError, TimeoutError):
            await reply(send, 400, {"error": "invalid_request"})
            return
        self.call_count += 1
        await reply(send, 200, {"marker": MARKER, "nonce": nonce,
                                "call_count": self.call_count, "scope": SCOPE})


class Observer:
    def __init__(self, downstream, admin_token):
        self.downstream, self.admin_token = downstream, admin_token

    async def __call__(self, scope, receive, send):
        if scope["method"] != "GET" or scope["path"] not in ("/stats", "/counter") or \
                scope.get("query_string"):
            await reply(send, 404, {"error": "route_unavailable"})
        elif not authorized(scope, self.admin_token):
            await reply(send, 401, {"error": "unauthorized"})
        else:
            await reply(send, 200, {"call_count": self.downstream.call_count,
                                    "downstreamCalls": self.downstream.call_count,
                                    "marker": MARKER, "scope": SCOPE})


class Proxy:
    def __init__(self, downstream_url):
        self.downstream_url = downstream_url

    async def __call__(self, scope, receive, send):
        if (scope["method"], scope["path"]) == ("GET", "/health"):
            await reply(send, 200, {"scope": SCOPE})
            return
        if (scope["method"], scope["path"]) != ("POST", "/v1/completions"):
            await reply(send, 404, {"error": "route_unavailable"})
            return
        try:
            body = await body_bytes(receive)
            # Only admission's rewritten authorization crosses the local downstream hop.
            headers = [(k, v) for k, v in scope["headers"] if k.lower() in (
                b"authorization", b"content-type")]
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=3.0) as client:
                async with client.stream("POST", self.downstream_url + "/v1/completions",
                                         headers=headers, content=body) as response:
                    chunks, size = [], 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_BODY:
                            raise ValueError("downstream exceeds bound")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    await send({"type": "http.response.start", "status": response.status_code,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", str(len(raw)).encode())]})
                    await send({"type": "http.response.body", "body": raw})
        except (ValueError, TimeoutError, httpx.HTTPError):
            await reply(send, 502, {"error": "fixture_downstream_unavailable"})


class ListenerIdentity:
    """Map a fixed listener socket to the boundary's production logical port."""
    def __init__(self, boundary, logical_port):
        self.boundary, self.logical_port = boundary, logical_port

    async def __call__(self, scope, receive, send):
        projected = dict(scope)
        projected["server"] = (scope["server"][0], self.logical_port)
        await self.boundary(projected, receive, send)


class LocalServer(uvicorn.Server):
    # One fixture coordinator owns SIGTERM/SIGINT for all four listeners.
    @contextmanager
    def capture_signals(self):
        yield


def listener(host, port=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def config_value(config, name, alias=None, default=None):
    if name in config:
        return config[name]
    if alias and alias in config:
        return config[alias]
    if default is not None:
        return default
    raise ValueError("required fixture configuration missing")


def normalize_config(raw):
    names = {"repo_root": "repoRoot", "api_url": "apiURL", "api_ca_file": "apiCA",
             "api_client_cert_file": "apiClientCert", "api_client_key_file": "apiClientKey",
             "pod_uid": "podUID", "service_uid": "serviceUID",
             "policy_configmap_uid": "policyConfigMapUID", "secret_uid": "secretUID",
             "source_sha256": "sourceSHA", "secret_dir": "secretDir",
             "admin_token": "adminBearer", "upstream_key": "upstreamBearer",
             "tls_cert_file": "tlsCertFile", "tls_key_file": "tlsKeyFile",
             "ready_file": "readyFile", "public_port": "publicPort", "admin_port": "adminPort"}
    defaults = {"repo_root": str(Path(__file__).resolve().parents[4]),
                "host": "127.0.0.1", "public_port": 0, "admin_port": 0}
    config = {name: config_value(raw, name, alias, defaults.get(name))
              for name, alias in names.items()}
    config["host"] = config_value(raw, "host", default=defaults["host"])
    host = ipaddress.ip_address(config["host"])
    if host.version != 4 or not host.is_loopback:
        raise ValueError("fixture host must be IPv4 loopback")
    for name in ("admin_token", "upstream_key"):
        token = config[name]
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or \
                any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("fixture credential shape differs")
    if config["admin_token"] == config["upstream_key"]:
        raise ValueError("fixture credentials must differ")
    for name in ("public_port", "admin_port"):
        if type(config[name]) is not int or not 0 <= config[name] <= 65535:
            raise ValueError("fixture listener port differs")
    return config


async def run(config):
    lease_module, boundary_module, source = load_runtime(Path(config["repo_root"]))
    if source != config["source_sha256"]:
        raise ValueError("fixture source pin differs")
    lease = lease_module.EndpointLease(lease_module.Identity(
        pod_uid=config["pod_uid"], service_uid=config["service_uid"],
        policy_configmap_uid=config["policy_configmap_uid"], secret_uid=config["secret_uid"],
        source_sha256=source, source_actual_sha256=source, secret_dir=Path(config["secret_dir"])),
        read_api=api_reader(lease_module, config))
    host = config["host"]
    sockets = []
    servers, tasks = [], []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(name, stop.set)
    try:
        for port in (0, 0, config["public_port"], config["admin_port"]):
            sockets.append(listener(host, port))
        downstream_sock, observer_sock, public_sock, admin_sock = sockets
        downstream = Downstream(config["upstream_key"])
        downstream_url = "http://%s:%d" % downstream_sock.getsockname()
        boundary = boundary_module.ServingBoundary(Proxy(downstream_url), config["upstream_key"],
                                                   config["admin_token"], lease)
        apps = [downstream, Observer(downstream, config["admin_token"]),
                ListenerIdentity(boundary, boundary_module.PUBLIC_PORT),
                ListenerIdentity(boundary, boundary_module.ADMIN_PORT)]
        for index, app in enumerate(apps):
            tls = {} if index != 3 else {"ssl_certfile": config["tls_cert_file"],
                                         "ssl_keyfile": config["tls_key_file"]}
            server = LocalServer(uvicorn.Config(app, host=host, port=sockets[index].getsockname()[1],
                                               lifespan="off", proxy_headers=False, access_log=False,
                                               log_level="error", timeout_graceful_shutdown=3, **tls))
            servers.append(server)
            tasks.append(asyncio.create_task(server.serve(sockets=[sockets[index]])))
        async with asyncio.timeout(10):
            while not all(server.started for server in servers):
                if any(task.done() for task in tasks):
                    raise RuntimeError("fixture listener startup failed")
                await asyncio.sleep(0.02)
        public_port, admin_port = public_sock.getsockname()[1], admin_sock.getsockname()[1]
        ready = {"public_url": f"http://{host}:{public_port}",
                 "admin_url": f"https://{host}:{admin_port}",
                 "observer_url": "http://%s:%d" % observer_sock.getsockname(),
                 "publicPort": public_port, "adminPort": admin_port,
                 "controlPort": observer_sock.getsockname()[1],
                 "marker": MARKER, "scope": SCOPE, "source_sha256": source,
                 "listeners_ready": True}
        ready_path = Path(config["ready_file"])
        temporary = ready_path.with_name(ready_path.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(ready, stream, sort_keys=True)
        os.replace(temporary, ready_path)
        print(json.dumps(ready, sort_keys=True), flush=True)
        stop_task = asyncio.create_task(stop.wait())
        done, _ = await asyncio.wait([*tasks, stop_task], return_when=asyncio.FIRST_COMPLETED)
        if stop_task not in done:
            raise RuntimeError("fixture listener stopped unexpectedly")
        stop_task.cancel()
    finally:
        for server in servers:
            server.should_exit = True
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)
            except TimeoutError:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        for sock in sockets:
            sock.close()
        for name in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.config.open() as stream:
            config = normalize_config(json.load(stream))
        asyncio.run(run(config))
    except Exception as error:
        # Exception messages may contain paths, request data, or credentials.
        print(json.dumps({"event": "fixture_failed", "error_type": type(error).__name__}),
              file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
