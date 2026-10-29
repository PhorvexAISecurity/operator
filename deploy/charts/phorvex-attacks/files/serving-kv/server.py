import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

POD = os.environ["POD_NAME"]
IMPLANT_KEY = "prompt_inject_implant"
cache = {"benign_prefix": "the quick brown fox"}
marker = None
reset_count = 0


def state():
    value = cache.get(IMPLANT_KEY)
    return {"pod": POD, "implant_present": IMPLANT_KEY in cache, "implant_marker": marker,
            "value_sha256": hashlib.sha256(value.encode()).hexdigest() if value else None,
            "keys": sorted(cache), "reset_count": reset_count}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"status": "ok"})
        elif self.path == "/v1/models":
            self.reply(200, {"object": "list", "data": [{"id": "catalogue-kv-fixture-v1"}]})
        elif self.path == "/kv":
            self.reply(200, state())
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        global marker, reset_count
        if self.path == "/reset_prefix_cache":
            cache.clear()
            marker = None
            reset_count += 1
            self.reply(200, {"success": True})
        elif self.path == "/seed":
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                self.reply(400, {"error": "invalid request"})
                return
            body = json.loads(self.rfile.read(length))
            cache[body.get("key", IMPLANT_KEY)] = body.get("val", "")
            marker = body.get("marker")
            self.reply(200, state())
        else:
            self.reply(404, {"error": "not found"})

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
