"""Support-app liveness sidecar for the catalogue sensitive-output fixture.

The console oracle talks only to the guardrail proxy (port 8000); this companion
container exists so the Pod mirrors the reviewed two-container support topology
and contributes the support-source digest the output-policy rule binds. It serves
a single health endpoint and holds no sensitive state. No import-time side effects
so it stays unit testable; the server only starts under __main__.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        raw = json.dumps({"status": "ok"}, separators=(",", ":")).encode("utf-8")
        self.send_response(200 if self.path == "/healthz" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        pass


def main():
    ThreadingHTTPServer(("0.0.0.0", 8002), Handler).serve_forever()


if __name__ == "__main__":
    main()
