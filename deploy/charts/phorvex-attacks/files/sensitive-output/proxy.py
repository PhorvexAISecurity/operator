import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

POLICY = Path(os.environ.get("OUTPUT_POLICY_DIR", "/policy"))
MARKER = "SYNTHETIC-AUDIT-MARKER-7F3A9C2E-NOT-A-CREDENTIAL"
REDACTED = "[REDACTED-BY-OUTPUT-POLICY]"


def state():
    try:
        value = json.loads((POLICY / "activation.json").read_bytes())
        if set(value) != {"active", "configMapUID", "operationId", "revision", "ruleId", "version"}:
            raise ValueError()
        return {"ready": True, "active": value["active"], "revision": value["revision"],
                "operationId": value["operationId"]}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"ready": False, "active": False, "revision": 0, "operationId": ""}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            current = state()
            self.reply(200 if current["ready"] else 503, {"status": "ok" if current["ready"] else "not-ready"})
        elif self.path == "/v1/output-policy/state":
            self.reply(200, state())
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/support/case":
            self.reply(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 4096:
            self.reply(413, {"error": "request too large"})
            return
        self.rfile.read(length)
        self.reply(200, {"diagnostics": {"internalAuditMarker": REDACTED if state()["active"] else MARKER}})

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
