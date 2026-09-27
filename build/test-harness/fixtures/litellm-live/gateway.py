"""Owned-client admission sidecar for the installed LiteLLM Service route.

The Service must select this sidecar's port 4001 in each *existing* LiteLLM Pod.
Accepted requests go to that Pod's real LiteLLM process on loopback:4000. The
authenticated status listener binds Pod port 4002 for exact-Pod readback; it
never returns credentials or response text and is not exposed by the Service.
Deployment is opt-in and requires a reviewed owner rollout.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HEX = re.compile(r"[0-9a-f]{64}\Z")
OWNED_TOKEN = re.compile(r"sk-phx2-([ac])-([0-9a-f]{32})-([0-9a-f]{64})\Z")
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 128 * 1024
MAX_PASSTHROUGH_REQUEST = 64 * 1024 * 1024
POLICY_KEYS = {"version", "revision", "entries"}
ENTRY_KEYS = {"active", "operationId", "clientSHA256"}
CLIENT_KEYS = {"version", "seedSHA256", "modelAlias"}
EMPTY_COUNTERS = {"forwardedRequests": 0, "upstreamCompletions": 0,
                  "deniedRequests": 0, "usageTokens": 0}


def strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class LimitedReader:
    def __init__(self, stream, remaining: int):
        self.stream, self.remaining = stream, remaining

    def read(self, size=8192):
        if self.remaining <= 0:
            return b""
        chunk = self.stream.read(min(size, self.remaining))
        self.remaining -= len(chunk)
        return chunk


class Gateway:
    def __init__(self, clients_file: Path, policy_file: Path, seed_file: Path,
                 master_key: str,
                 pod_uid: str, config_map_uid: str, source_sha256: str,
                 status_token: str,
                 upstream_port: int = 4000):
        source = Path(__file__).read_bytes()
        if not HEX.fullmatch(source_sha256) or sha(source) != source_sha256:
            raise ValueError("gateway source digest differs")
        if (not pod_uid or not config_map_uid or not master_key.startswith("sk-") or
                len(status_token) < 32 or len(status_token) > 256):
            raise ValueError("gateway authority incomplete")
        self.clients_file, self.policy_file = clients_file, policy_file
        self.seed = seed_file.read_bytes()
        self.master_key, self.pod_uid = master_key, pod_uid
        self.config_map_uid, self.source_sha256 = config_map_uid, source_sha256
        self.status_token = status_token
        if not 1 <= upstream_port <= 65535:
            raise ValueError("upstream port invalid")
        self.upstream_port = upstream_port
        clients = strict_json(clients_file.read_bytes())
        if (not isinstance(clients, dict) or set(clients) != CLIENT_KEYS or
                type(clients["version"]) is not int or clients["version"] != 2 or
                not isinstance(clients["seedSHA256"], str) or
                not HEX.fullmatch(clients["seedSHA256"]) or
                not 32 <= len(self.seed) <= 64 or sha(self.seed) != clients["seedSHA256"] or
                clients["modelAlias"] != "gpt-4o-mini"):
            raise ValueError("owned-client authority differs")
        self.clients = clients
        self.lock = threading.Lock()
        self.counters = {}
        self.high_water_revision = 0
        self.high_water_entries = {}
        self.policy()  # No listener becomes ready against a missing or wrong policy.

    def policy(self):
        raw = self.policy_file.read_bytes()
        if len(raw) > 65536:
            raise ValueError("policy exceeds bound")
        state = strict_json(raw)
        if raw != json.dumps(state, separators=(",", ":"), sort_keys=True).encode():
            raise ValueError("policy state is not canonical")
        if (not isinstance(state, dict) or set(state) != POLICY_KEYS or
                type(state["version"]) is not int or state["version"] != 2 or
                type(state["revision"]) is not int or not 0 <= state["revision"] <= 256 or
                not isinstance(state["entries"], list) or
                len(state["entries"]) != state["revision"]):
            raise ValueError("policy state differs")
        previous = ""
        for entry in state["entries"]:
            if (not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or
                    entry["active"] is not True or
                    not isinstance(entry["clientSHA256"], str) or
                    not HEX.fullmatch(entry["clientSHA256"]) or
                    entry["clientSHA256"] <= previous or
                    not isinstance(entry["operationId"], str) or
                    not 1 <= len(entry["operationId"]) <= 128):
                raise ValueError("policy entry differs")
            previous = entry["clientSHA256"]
        current = {e["clientSHA256"]: e["operationId"] for e in state["entries"]}
        with self.lock:
            if (state["revision"] < self.high_water_revision or
                    any(current.get(client) != operation
                        for client, operation in self.high_water_entries.items())):
                raise ValueError("policy projection regressed")
            self.high_water_revision = state["revision"]
            self.high_water_entries = current
        return state

    def role(self, authorization: str):
        if not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        match = OWNED_TOKEN.fullmatch(token)
        if not match:
            return None
        role, nonce, mac = match.groups()
        expected = hmac.new(self.seed,
                            f"phorvex-litellm-live-v2:{nonce}:{role}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return None
        return role, sha(token.encode("ascii"))

    def status(self, client_sha: str):
        if not HEX.fullmatch(client_sha):
            raise ValueError("status client hash invalid")
        try:
            policy = self.policy()
        except (OSError, ValueError, TypeError):
            return {"version": 2, "podUID": self.pod_uid,
                    "sourceSHA256": self.source_sha256,
                    "seedSHA256": self.clients["seedSHA256"],
                    "configMapUID": self.config_map_uid,
                    "clientSHA256": client_sha,
                    "active": False, "revision": -1, "operationId": "", "role": "", "ready": False,
                    "counters": self.copy_counters(client_sha)}
        entry = next((e for e in policy["entries"] if e["clientSHA256"] == client_sha), None)
        return {"version": 2, "podUID": self.pod_uid,
                "sourceSHA256": self.source_sha256,
                "seedSHA256": self.clients["seedSHA256"],
                "configMapUID": self.config_map_uid,
                "clientSHA256": client_sha,
                "active": entry is not None, "revision": policy["revision"],
                "operationId": entry["operationId"] if entry else "",
                "role": self.client_role(client_sha), "ready": True,
                "counters": self.copy_counters(client_sha)}

    def client_role(self, client_sha: str):
        with self.lock:
            role = self.counters.get(client_sha, {}).get("role", "")
            return {"a": "attacker", "c": "control"}.get(role, "")

    def copy_counters(self, client_sha: str):
        with self.lock:
            return {key: self.counters.get(client_sha, EMPTY_COUNTERS)[key]
                    for key in EMPTY_COUNTERS}

    def bump(self, client_sha: str, role: str, key: str, count: int = 1):
        with self.lock:
            if client_sha not in self.counters:
                if len(self.counters) >= 512:
                    raise ValueError("gateway client counter capacity exhausted")
                self.counters[client_sha] = dict(EMPTY_COUNTERS)
                self.counters[client_sha]["role"] = role
            if self.counters[client_sha]["role"] != role:
                raise ValueError("gateway client role changed")
            self.counters[client_sha][key] += count


class PublicHandler(BaseHTTPRequestHandler):
    gateway: Gateway

    def log_message(self, *_):
        pass  # No key, prompt, or response bytes in process logs.

    def respond(self, status: int, body: bytes, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Phorvex-Gateway-Pod-UID", self.gateway.pod_uid)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        owned = self.gateway.role(self.headers.get("Authorization", ""))
        length = self.headers.get("Content-Length", "")
        bound = MAX_REQUEST if owned is not None else MAX_PASSTHROUGH_REQUEST
        if not length.isdigit() or not 0 < int(length) <= bound:
            self.respond(413, b'{"error":{"code":"request_bound"}}')
            return
        if owned is None:
            # Preserve LiteLLM's own existing auth response. Never substitute
            # the master key for an unrecognized caller.
            self.passthrough("POST", int(length))
            return
        request = self.rfile.read(int(length))
        if self.path != "/v1/chat/completions":
            self.respond(404, b'{"error":{"code":"owned_route_unavailable"}}')
            return
        try:
            policy = self.gateway.policy()
        except (OSError, ValueError, TypeError):
            self.respond(503, b'{"error":{"code":"policy_unavailable"}}')
            return
        try:
            value = strict_json(request)
            if (not isinstance(value, dict) or value.get("model") != self.gateway.clients["modelAlias"] or
                    value.get("stream", False) is not False or
                    type(value.get("max_tokens")) is not int or not 1 <= value["max_tokens"] <= 64 or
                    not isinstance(value.get("messages"), list) or not 1 <= len(value["messages"]) <= 4 or
                    any(not isinstance(m, dict) or set(m) != {"role", "content"} or
                        m["role"] != "user" or not isinstance(m["content"], str) or
                        not 1 <= len(m["content"]) <= 1024 for m in value["messages"])):
                raise ValueError("owned request shape")
        except (ValueError, TypeError):
            self.respond(400, b'{"error":{"code":"owned_request_invalid"}}')
            return
        role, client_sha = owned
        if role == "a" and any(e["clientSHA256"] == client_sha for e in policy["entries"]):
            self.gateway.bump(client_sha, role, "deniedRequests")
            self.respond(429, b'{"error":{"code":"PHORVEX_CLIENT_REVOKED"}}')
            return
        self.forward(request, "Bearer " + self.gateway.master_key, role, client_sha)

    def do_GET(self):
        owned = self.gateway.role(self.headers.get("Authorization", ""))
        if owned is None:
            self.passthrough("GET", None)
            return
        if self.path != "/v1/models":
            self.respond(404, b'{"error":{"code":"owned_route_unavailable"}}')
            return
        role, client_sha = owned
        try:
            policy = self.gateway.policy()
        except (OSError, ValueError, TypeError):
            self.respond(503, b'{"error":{"code":"policy_unavailable"}}')
            return
        if role == "a" and any(e["clientSHA256"] == client_sha for e in policy["entries"]):
            self.gateway.bump(client_sha, role, "deniedRequests")
            self.respond(429, b'{"error":{"code":"PHORVEX_CLIENT_REVOKED"}}')
            return
        self.forward(None, "Bearer " + self.gateway.master_key, role, client_sha)

    def passthrough(self, method: str, request_length: int | None):
        """Preserve existing master-key clients, including streaming completions."""
        conn = http.client.HTTPConnection("127.0.0.1", self.gateway.upstream_port, timeout=35)
        started = False
        try:
            hop = {"host", "connection", "content-length", "transfer-encoding", "keep-alive",
                   "proxy-authorization", "proxy-authenticate", "upgrade"}
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in hop and "\r" not in value and "\n" not in value}
            if request_length is not None:
                headers["Content-Length"] = str(request_length)
            body = LimitedReader(self.rfile, request_length) if request_length is not None else None
            conn.request(method, self.path, body=body, headers=headers)
            upstream = conn.getresponse()
            self.send_response(upstream.status)
            for key in ("Content-Type", "Content-Encoding"):
                value = upstream.getheader(key)
                if value and "\r" not in value and "\n" not in value:
                    self.send_header(key, value)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            started = True
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.close_connection = True
        except (OSError, TimeoutError, http.client.HTTPException):
            if not started:
                self.respond(502, b'{"error":{"code":"upstream_unavailable"}}')
            self.close_connection = True
        finally:
            conn.close()

    def forward(self, request: bytes | None, authorization: str, role: str, client_sha: str):
        conn = http.client.HTTPConnection("127.0.0.1", self.gateway.upstream_port, timeout=35)
        try:
            headers = {"Authorization": authorization, "Accept": "application/json"}
            if request is not None:
                headers["Content-Type"] = "application/json"
            self.gateway.bump(client_sha, role, "forwardedRequests")
            conn.request("POST" if request is not None else "GET", self.path, body=request, headers=headers)
            upstream = conn.getresponse()
            body = upstream.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                self.respond(502, b'{"error":{"code":"upstream_bound"}}')
                return
            if request is not None and upstream.status == 200:
                try:
                    result = strict_json(body)
                    usage = result.get("usage", {})
                    if result.get("object") == "chat.completion" and isinstance(result.get("choices"), list):
                        self.gateway.bump(client_sha, role, "upstreamCompletions")
                        tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
                        if type(tokens) is int and 0 <= tokens <= 100000:
                            self.gateway.bump(client_sha, role, "usageTokens", tokens)
                except (ValueError, TypeError, AttributeError):
                    pass
            content_type = upstream.getheader("Content-Type", "application/json")
            self.respond(upstream.status, body, content_type)
        except (OSError, TimeoutError, http.client.HTTPException):
            self.respond(502, b'{"error":{"code":"upstream_unavailable"}}')
        finally:
            conn.close()


class StatusHandler(BaseHTTPRequestHandler):
    gateway: Gateway

    def log_message(self, *_):
        pass

    def do_GET(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""),
                                   "Bearer " + self.gateway.status_token):
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        prefix = "/v1/admission/state?clientSHA256="
        client_sha = self.path[len(prefix):] if self.path.startswith(prefix) else ""
        if not HEX.fullmatch(client_sha):
            self.send_error(404)
            return
        body = json.dumps(self.gateway.status(client_sha), separators=(",", ":"), sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve():
    status_token = Path(os.environ["PHORVEX_LITELLM_STATUS_TOKEN_FILE"]).read_text().strip()
    gateway = Gateway(Path(os.environ["PHORVEX_LITELLM_CLIENTS_FILE"]),
                      Path(os.environ["PHORVEX_LITELLM_POLICY_FILE"]),
                      Path(os.environ["PHORVEX_LITELLM_TRIAL_SEED_FILE"]),
                      os.environ["LITELLM_MASTER_KEY"], os.environ["POD_UID"],
                      os.environ["PHORVEX_LITELLM_POLICY_CONFIGMAP_UID"],
                      os.environ["PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256"],
                      status_token)
    public = type("BoundPublicHandler", (PublicHandler,), {"gateway": gateway})
    status = type("BoundStatusHandler", (StatusHandler,), {"gateway": gateway})
    admin = ThreadingHTTPServer(("0.0.0.0", 4002), status)
    thread = threading.Thread(target=admin.serve_forever, daemon=True)
    thread.start()
    try:
        ThreadingHTTPServer(("0.0.0.0", 4001), public).serve_forever()
    finally:
        admin.shutdown()


if __name__ == "__main__":
    serve()
