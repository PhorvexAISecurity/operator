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
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 128 * 1024
MAX_PASSTHROUGH_REQUEST = 1024 * 1024
MAX_PASSTHROUGH_RESPONSE = 8 * 1024 * 1024
POLICY_KEYS = {"version", "active", "revision", "operationId", "clientSHA256"}
CLIENT_KEYS = {"version", "attackerSHA256", "controlSHA256", "modelAlias"}


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


class Gateway:
    def __init__(self, clients_file: Path, policy_file: Path, master_key: str,
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
        self.master_key, self.pod_uid = master_key, pod_uid
        self.config_map_uid, self.source_sha256 = config_map_uid, source_sha256
        self.status_token = status_token
        if not 1 <= upstream_port <= 65535:
            raise ValueError("upstream port invalid")
        self.upstream_port = upstream_port
        clients = strict_json(clients_file.read_bytes())
        if (not isinstance(clients, dict) or set(clients) != CLIENT_KEYS or
                type(clients["version"]) is not int or clients["version"] != 1 or
                not HEX.fullmatch(clients["attackerSHA256"]) or
                not HEX.fullmatch(clients["controlSHA256"]) or
                clients["attackerSHA256"] == clients["controlSHA256"] or
                clients["modelAlias"] not in ("gpt-3.5-turbo", "gpt-4o-mini")):
            raise ValueError("owned-client authority differs")
        self.clients = clients
        self.lock = threading.Lock()
        self.counters = {role: {"forwardedRequests": 0, "upstreamCompletions": 0,
                                "deniedRequests": 0, "usageTokens": 0}
                         for role in ("attacker", "control")}
        self.policy()  # No listener becomes ready against a missing or wrong policy.

    def policy(self):
        raw = self.policy_file.read_bytes()
        if len(raw) > 2048:
            raise ValueError("policy exceeds bound")
        state = strict_json(raw)
        if raw != json.dumps(state, separators=(",", ":"), sort_keys=True).encode():
            raise ValueError("policy state is not canonical")
        if (not isinstance(state, dict) or set(state) != POLICY_KEYS or
                type(state["version"]) is not int or state["version"] != 1 or
                type(state["active"]) is not bool or
                type(state["revision"]) is not int or state["revision"] < 0 or
                not isinstance(state["operationId"], str) or
                not isinstance(state["clientSHA256"], str) or
                state["clientSHA256"] != self.clients["attackerSHA256"] or
                (state["active"] and (state["revision"] < 1 or not state["operationId"])) or
                (not state["active"] and (state["revision"] != 0 or state["operationId"] != ""))):
            raise ValueError("policy state differs")
        return state

    def role(self, authorization: str):
        if not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if len(token) < 24 or len(token) > 256 or not token.startswith("sk-"):
            return None
        token_sha = sha(token.encode("utf-8"))
        for role in ("attacker", "control"):
            if hmac.compare_digest(token_sha, self.clients[role + "SHA256"]):
                return role
        return None

    def status(self):
        try:
            policy = self.policy()
        except (OSError, ValueError, TypeError):
            return {"version": 1, "podUID": self.pod_uid,
                    "sourceSHA256": self.source_sha256,
                    "configMapUID": self.config_map_uid,
                    "clientSHA256": self.clients["attackerSHA256"],
                    "active": False, "revision": -1, "operationId": "", "ready": False,
                    "counters": self.copy_counters()}
        return {"version": 1, "podUID": self.pod_uid,
                "sourceSHA256": self.source_sha256,
                "configMapUID": self.config_map_uid,
                "clientSHA256": policy["clientSHA256"],
                "active": policy["active"], "revision": policy["revision"],
                "operationId": policy["operationId"], "ready": True,
                "counters": self.copy_counters()}

    def copy_counters(self):
        with self.lock:
            return {role: dict(values) for role, values in self.counters.items()}

    def bump(self, role: str, key: str, count: int = 1):
        with self.lock:
            self.counters[role][key] += count


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
        role = self.gateway.role(self.headers.get("Authorization", ""))
        length = self.headers.get("Content-Length", "")
        bound = MAX_REQUEST if role is not None else MAX_PASSTHROUGH_REQUEST
        if not length.isdigit() or not 0 < int(length) <= bound:
            self.respond(413, b'{"error":{"code":"request_bound"}}')
            return
        request = self.rfile.read(int(length))
        if role is None:
            # Preserve LiteLLM's own existing auth response. Never substitute
            # the master key for an unrecognized caller.
            self.passthrough("POST", request)
            return
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
        if role == "attacker" and policy["active"]:
            self.gateway.bump(role, "deniedRequests")
            self.respond(429, b'{"error":{"code":"PHORVEX_CLIENT_REVOKED"}}')
            return
        self.forward(request, "Bearer " + self.gateway.master_key, role)

    def do_GET(self):
        role = self.gateway.role(self.headers.get("Authorization", ""))
        if role is None:
            self.passthrough("GET", None)
            return
        if self.path != "/v1/models":
            self.respond(404, b'{"error":{"code":"owned_route_unavailable"}}')
            return
        if role is not None:
            try:
                policy = self.gateway.policy()
            except (OSError, ValueError, TypeError):
                self.respond(503, b'{"error":{"code":"policy_unavailable"}}')
                return
            if role == "attacker" and policy["active"]:
                self.gateway.bump(role, "deniedRequests")
                self.respond(429, b'{"error":{"code":"PHORVEX_CLIENT_REVOKED"}}')
                return
        authorization = "Bearer " + self.gateway.master_key if role else self.headers.get("Authorization", "")
        self.forward(None, authorization, role)

    def passthrough(self, method: str, request: bytes | None):
        """Preserve existing master-key clients, including streaming completions."""
        conn = http.client.HTTPConnection("127.0.0.1", self.gateway.upstream_port, timeout=35)
        started = False
        try:
            hop = {"host", "connection", "content-length", "transfer-encoding", "keep-alive",
                   "proxy-authorization", "proxy-authenticate", "upgrade"}
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in hop and "\r" not in value and "\n" not in value}
            conn.request(method, self.path, body=request, headers=headers)
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
            total = 0
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PASSTHROUGH_RESPONSE:
                    break
                self.wfile.write(chunk)
            self.close_connection = True
        except (OSError, TimeoutError, http.client.HTTPException):
            if not started:
                self.respond(502, b'{"error":{"code":"upstream_unavailable"}}')
            self.close_connection = True
        finally:
            conn.close()

    def forward(self, request: bytes | None, authorization: str, role: str | None):
        conn = http.client.HTTPConnection("127.0.0.1", self.gateway.upstream_port, timeout=35)
        try:
            headers = {"Authorization": authorization, "Accept": "application/json"}
            if request is not None:
                headers["Content-Type"] = "application/json"
            if role:
                self.gateway.bump(role, "forwardedRequests")
            conn.request("POST" if request is not None else "GET", self.path, body=request, headers=headers)
            upstream = conn.getresponse()
            body = upstream.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                self.respond(502, b'{"error":{"code":"upstream_bound"}}')
                return
            if role and request is not None and upstream.status == 200:
                try:
                    result = strict_json(body)
                    usage = result.get("usage", {})
                    if result.get("object") == "chat.completion" and isinstance(result.get("choices"), list):
                        self.gateway.bump(role, "upstreamCompletions")
                        tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
                        if type(tokens) is int and 0 <= tokens <= 100000:
                            self.gateway.bump(role, "usageTokens", tokens)
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
        if self.path != "/v1/admission/state":
            self.send_error(404)
            return
        if not hmac.compare_digest(self.headers.get("Authorization", ""),
                                   "Bearer " + self.gateway.status_token):
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(self.gateway.status(), separators=(",", ":"), sort_keys=True).encode()
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
