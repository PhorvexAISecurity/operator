"""The engine metrics listener serves exactly GET /metrics and nothing else."""
import contextlib
import http.server
import io
import socket
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

import dual_server

BODY = b"# TYPE vllm:num_requests_running gauge\nvllm:num_requests_running 1.0\n"


class _Engine(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_response(418)
            self.end_headers()


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class EngineMetricsListener(unittest.TestCase):
    def setUp(self):
        self.engine = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Engine))
        upstream = "http://127.0.0.1:%d/metrics" % self.engine.server_address[1]
        self.listener = _serve(dual_server.metrics_server(port=0, upstream=upstream, host="127.0.0.1"))
        self.base = "http://127.0.0.1:%d" % self.listener.server_address[1]

    def tearDown(self):
        for server in (self.listener, self.engine):
            server.shutdown()
            server.server_close()

    def status(self, path, method="GET"):
        req = urllib.request.Request(self.base + path, method=method, data=b"" if method == "POST" else None)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read(), resp.headers.get("Content-Type")
        except urllib.error.HTTPError as err:
            return err.code, err.read(), err.headers.get("Content-Type")

    def test_metrics_are_relayed_verbatim(self):
        code, body, content_type = self.status("/metrics")
        self.assertEqual(code, 200)
        self.assertEqual(body, BODY)
        self.assertEqual(content_type, "text/plain; version=0.0.4")

    def test_no_other_route_or_method(self):
        for path in ("/", "/v1/models", "/metrics/", "/metrics?x=1", "/reset_prefix_cache", "/v1/chat/completions"):
            self.assertEqual(self.status(path)[0], 404, path)
        self.assertEqual(self.status("/metrics", method="POST")[0], 405)

    def test_engine_unavailable_is_502(self):
        self.engine.shutdown()
        self.engine.server_close()
        code, body, _ = self.status("/metrics")
        self.assertEqual(code, 502)
        self.assertIn(b"engine_metrics_unavailable", body)
        self.engine = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Engine))

    def test_port_in_use_never_blocks_serving(self):
        with socket.socket() as held:
            held.bind(("0.0.0.0", 0))
            held.listen()
            with mock.patch.object(dual_server, "METRICS_PORT", held.getsockname()[1]), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertIsNone(dual_server.start_metrics_listener())
        self.assertIn('"event":"engine_metrics_unavailable"', out.getvalue())


if __name__ == "__main__":
    unittest.main()
