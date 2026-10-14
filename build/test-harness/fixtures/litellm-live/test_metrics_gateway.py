"""Light localhost protocol checks for terminal gateway metrics and boundary isolation."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import re
import socket
import struct
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_gateway as baseline
import gateway_metrics as gateway
from pathlib import Path


CANDIDATE_SOURCE = Path(__file__).with_name("gateway_metrics.py")


class ObservedMetrics(gateway.RequestMetrics):
    def __init__(self):
        super().__init__("litellm", "litellm-fixture-gateway")
        self.finished = threading.Event()

    def observe(self, *args):
        super().observe(*args)
        self.finished.set()


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, *_):
        pass


class MetricsGatewayTests(baseline.GatewayTests):
    # The admission/policy/auth/large-response controls also run with metrics enabled.
    def setUp(self):
        legacy_fixture = mock.patch.multiple(baseline, gateway=gateway, SOURCE=CANDIDATE_SOURCE)
        legacy_fixture.start()
        self.addCleanup(legacy_fixture.stop)
        super().setUp()
        self.metrics = ObservedMetrics()
        self.g.metrics = self.metrics
        self.metrics_token = b"a" * 64
        bound = type("TestMetrics", (gateway.MetricsHandler,),
                     {"metrics": self.metrics, "metrics_token": self.metrics_token})
        self.metrics_server = QuietServer(("127.0.0.1", 0), bound)
        threading.Thread(target=self.metrics_server.serve_forever, daemon=True).start()
        self.addCleanup(self.metrics_server.server_close)
        self.addCleanup(self.metrics_server.shutdown)

    def finish(self):
        self.assertTrue(self.metrics.finished.wait(3), "terminal accounting did not complete")
        self.metrics.finished.clear()

    def count(self):
        with self.metrics.lock:
            return sum(value[0] for value in self.metrics.series.values())

    def test_terminal_populations_match_histogram_and_hide_request_content(self):
        self.assertEqual(self.post(self.attacker)[0], 200)
        self.finish()
        self.assertEqual(self.post("sk-private-invalid-token-123456789")[0], 401)
        self.finish()
        self.revoke(self.attacker, "private-operation-987654321")
        self.assertEqual(self.post(self.attacker)[0], 429)
        self.finish()
        self.policy.write_text("invalid")
        self.assertEqual(self.post(self.control)[0], 503)
        self.finish()
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        failed = mock.Mock()
        failed.request.side_effect = TimeoutError("private-upstream-url")
        with mock.patch.object(gateway.http.client, "HTTPConnection", return_value=failed):
            conn.request("GET", "/other/private-client-id?prompt=secret-prompt", headers={"Authorization": "secret-auth"})
            response = conn.getresponse()
            self.assertEqual(response.status, 502)
            response.read()
            self.finish()
        conn.close()
        self.assertEqual(self.count(), 5)
        text = self.metrics.exposition().decode()
        counters = dict(re.findall(r'^http_requests_total\{(.*)\} (\d+)$', text, re.M))
        histograms = dict(re.findall(r'^http_request_duration_seconds_count\{(.*)\} (\d+)$', text, re.M))
        infinite = dict(re.findall(r'^http_request_duration_seconds_bucket\{(.*),le="\+Inf"\} (\d+)$', text, re.M))
        self.assertEqual(counters, histograms)
        self.assertEqual(counters, infinite)
        self.assertIn('status_class="5xx",outcome="timeout"', text)
        self.assertIn('namespace="litellm",pod="litellm-fixture-gateway",target="litellm"', text)
        for secret in (self.attacker, self.control, self.g.master_key, self.g.status_token,
                       self.attacker_sha, self.g.source_sha256, "Say OK.", "secret-prompt",
                       "secret-auth", "private-client-id", "private-operation", "private-upstream-url",
                       self.metrics_token.decode()):
            self.assertNotIn(secret, text)

    def test_upstream_error_and_unsupported_method_each_count_once(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        failed = mock.Mock()
        failed.request.side_effect = ConnectionRefusedError()
        with mock.patch.object(gateway.http.client, "HTTPConnection", return_value=failed):
            conn.request("GET", "/v1/models")
            response = conn.getresponse()
            self.assertEqual(response.status, 502)
            response.read()
            self.finish()
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        conn.request("CUSTOM", "/arbitrary/id")
        response = conn.getresponse()
        self.assertEqual(response.status, 501)
        response.read()
        conn.close()
        self.finish()
        self.assertEqual(self.count(), 2)
        self.assertIn(("other", "other", "5xx", "completed"), self.metrics.series)
        self.assertIn(("GET", "/v1/models", "5xx", "upstream_error"), self.metrics.series)

    def stream_server(self, mode="normal"):
        first = threading.Event()
        proceed = threading.Event()
        self.addCleanup(proceed.set)
        class Stream(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(8192 * (2 if mode == "normal" else 100)))
                self.end_headers()
                self.wfile.write(b"x" * 8192)
                first.set()
                proceed.wait(3)
                if mode == "truncated":
                    self.close_connection = True
                    return
                try:
                    self.wfile.write(b"z" * (8192 * (1 if mode == "normal" else 99)))
                except OSError:
                    pass
        server = QuietServer(("127.0.0.1", 0), Stream)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.g.upstream_port = server.server_address[1]
        return first, proceed

    def test_stream_full_eof_uses_monotonic_lifetime(self):
        first, proceed = self.stream_server()
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        with mock.patch.object(gateway.time, "monotonic", return_value=100.0) as clock:
            conn.request("POST", "/v1/chat/completions", b'{}', {"Authorization": "Bearer " + self.g.master_key})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(first.wait(1))
            self.assertEqual(len(response.read(8192)), 8192)
            self.assertEqual(self.count(), 0)
            clock.return_value = 280.0  # Three-minute stream without a slow test.
            proceed.set()
            self.assertEqual(response.read(), b"z" * 8192)
            self.finish()
        conn.close()
        self.assertEqual(self.count(), 1)
        population = self.metrics.series[("POST", "/v1/chat/completions", "2xx", "completed")]
        self.assertEqual(population[1], 180.0)
        self.assertEqual(population[2][gateway.METRIC_BUCKETS.index(120)], 0)
        self.assertEqual(population[2][gateway.METRIC_BUCKETS.index(300)], 1)

    def test_stream_disconnect_retains_delivered_200(self):
        first, proceed = self.stream_server("disconnect")
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        conn.request("POST", "/v1/chat/completions", b'{}', {"Authorization": "Bearer " + self.g.master_key})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertTrue(first.wait(1))
        self.assertEqual(len(response.read(8192)), 8192)
        # RST the synthetic downstream before allowing more upstream bytes.
        response.fp.raw._sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        response.close()
        conn.close()
        proceed.set()
        self.finish()
        self.assertEqual(self.count(), 1)
        self.assertIn(("POST", "/v1/chat/completions", "2xx", "disconnect"), self.metrics.series)
        self.assertNotIn('status_class="5xx"', self.metrics.exposition().decode())

    def test_truncated_stream_keeps_headers_and_records_upstream_error(self):
        first, proceed = self.stream_server("truncated")
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=3)
        conn.request("POST", "/v1/chat/completions", b'{}', {"Authorization": "Bearer " + self.g.master_key})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertTrue(first.wait(1))
        self.assertEqual(len(response.read(8192)), 8192)
        proceed.set()
        self.assertEqual(response.read(), b"")
        self.finish()
        conn.close()
        self.assertEqual(self.count(), 1)
        self.assertIn(("POST", "/v1/chat/completions", "2xx", "upstream_error"), self.metrics.series)

    def test_metrics_listener_exact_get_only_and_no_upstream_or_status_access(self):
        before = baseline.Upstream.calls
        for method, path, expected in [
            ("GET", "/metrics", 200), ("GET", "/metrics?query=private", 404),
            ("GET", "/metrics/", 404), ("GET", "//metrics", 404),
            ("GET", "/%6detrics", 404), ("GET", "/metrics#private", 404),
            ("GET", "http://localhost/metrics", 404), ("GET", "/v1/models", 404),
            ("GET", "/v1/chat/completions", 404), ("GET", "/v1/admission/state?clientSHA256=" + "a" * 64, 404),
            ("GET", "/v1/output-policy/state", 404), ("POST", "/metrics", 501),
            ("HEAD", "/metrics", 501), ("OPTIONS", "/metrics", 501),
            ("PUT", "/metrics", 501), ("DELETE", "/metrics", 501),
            ("CONNECT", "/metrics", 501), ("CUSTOM", "/metrics", 501),
            ("GET", "/" + "x" * 300, 414),
        ]:
            with self.subTest(method=method, path=path):
                conn = http.client.HTTPConnection("127.0.0.1", self.metrics_server.server_address[1], timeout=3)
                conn.request(method, path, headers={"Authorization": "Bearer " + self.metrics_token.decode()})
                response = conn.getresponse()
                self.assertEqual(response.status, expected)
                self.assertIsNone(response.getheader("Location"))
                raw = response.read()
                self.assertNotIn(self.g.status_token.encode(), raw)
                conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", self.metrics_server.server_address[1], timeout=3)
        conn.request("GET", "/metrics", b"private-body")
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        conn.close()
        self.assertEqual(baseline.Upstream.calls, before)
        self.assertEqual(self.count(), 0)
        conn = http.client.HTTPConnection("127.0.0.1", self.metrics_server.server_address[1], timeout=3)
        conn.request("GET", "/metrics", headers={"X-Oversized": "x" * 4096})
        response = conn.getresponse()
        self.assertEqual(response.status, 431)
        response.read()
        conn.close()

    def metrics_call(self, authorization=(), path="/metrics", method="GET", other=()):
        conn = http.client.HTTPConnection("127.0.0.1", self.metrics_server.server_address[1], timeout=3)
        try:
            conn.putrequest(method, path)
            for value in authorization:
                conn.putheader("Authorization", value)
            for key, value in other:
                conn.putheader(key, value)
            conn.endheaders()
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_metrics_bearer_rejects_ambiguous_malformed_and_other_credentials(self):
        token = self.metrics_token.decode()
        valid = "Bearer " + token
        before = baseline.Upstream.calls
        for values in ((), ("Bearer " + "b" * 64,), (valid, valid), (valid, "Basic private"),
                       (valid + "," + valid,), ("Basic " + token,), ("Bearer  " + token,),
                       (valid + " ",), (valid + "\t",), ("Bearer\t" + token,),
                       ("Bearer " + "A" * 64,), ("Bearer " + "g" * 64,),
                       ("Bearer " + "a" * 63,), ("Bearer " + "a" * 65,),
                       ("Bearer " + "a" * 512,), ("Bearer " + "é" * 64,),
                       ("Bearer " + self.g.status_token,), ("Bearer " + self.g.master_key,),
                       ("Bearer " + self.attacker,), ("Bearer " + self.control,)):
            with self.subTest(authorization=values):
                status, headers, body = self.metrics_call(values)
                self.assertEqual((status, body), (401, b""))
                self.assertEqual(headers.get("WWW-Authenticate"), "Bearer")
                self.assertEqual(headers.get("Connection"), "close")
                self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(baseline.Upstream.calls, before)
        self.assertEqual(self.count(), 0)

    def test_valid_metrics_auth_uses_bytes_comparison_and_parser_normalization(self):
        token = self.metrics_token.decode()
        for value in ("Bearer " + token, "bearer " + token, "BEARER " + token,
                      "  Bearer " + token):  # Leading OWS is normalized by the HTTP parser.
            with self.subTest(value=value), mock.patch.object(gateway.hmac, "compare_digest",
                                                              wraps=gateway.hmac.compare_digest) as compare:
                status, headers, body = self.metrics_call((value,))
                self.assertEqual(status, 200)
                self.assertEqual(headers.get("Cache-Control"), "no-store")
                self.assertEqual(headers.get("Connection"), "close")
                self.assertTrue(headers.get("Content-Type", "").startswith("text/plain; version=0.0.4"))
                self.assertNotIn(self.metrics_token, body)
                compare.assert_called_once_with(self.metrics_token, self.metrics_token)
        self.assertEqual(self.count(), 0)

    def test_metrics_body_framing_rejected_before_auth_including_empty_transfer_encoding(self):
        for authorization in ((), ("Bearer " + self.metrics_token.decode(),)):
            for headers in ((("Content-Length", "1"),), (("Content-Length", "00"),),
                            (("Content-Length", "0"), ("Content-Length", "0")),
                            (("Transfer-Encoding", "chunked"),), (("Transfer-Encoding", ""),),
                            (("Content-Length", "0"), ("Transfer-Encoding", ""))):
                with self.subTest(authorization=authorization, headers=headers):
                    self.assertEqual(self.metrics_call(authorization, other=headers)[0], 400)
            self.assertEqual(self.metrics_call(authorization, path="/metrics?private")[0], 404)
        self.assertEqual(self.metrics_call(("Bearer " + self.metrics_token.decode(),),
                                          other=(("Content-Length", "0"),))[0], 200)
        self.assertEqual(self.count(), 0)

    def test_metrics_token_is_independent_of_status_and_model_credentials(self):
        before = baseline.Upstream.calls
        conn = http.client.HTTPConnection("127.0.0.1", self.status_server.server_address[1], timeout=3)
        conn.request("GET", "/v1/admission/state?clientSHA256=" + self.attacker_sha,
                     headers={"Authorization": "Bearer " + self.metrics_token.decode()})
        response = conn.getresponse()
        self.assertEqual((response.status, response.read()), (401, b""))
        conn.close()
        self.assertEqual(baseline.Upstream.calls, before)
        self.assertEqual(self.post(self.metrics_token.decode())[0], 401)
        self.finish()
        self.assertEqual(baseline.Upstream.calls, before + 1)  # Existing invalid-model auth response.
        self.assertNotIn(self.metrics_token, self.metrics.exposition())


class RegistryTests(unittest.TestCase):
    def test_default_off_identity_validation_and_cardinality_bound(self):
        self.assertIsNone(gateway.configured_metrics({}))
        self.assertIsNone(gateway.configured_metrics({"PHORVEX_LITELLM_METRICS_ENABLED": "0"}))
        for env in ({"PHORVEX_LITELLM_METRICS_ENABLED": "true"},
                    {"PHORVEX_LITELLM_METRICS_ENABLED": "1"},
                    {"PHORVEX_LITELLM_METRICS_ENABLED": "1", "POD_NAMESPACE": "litellm", "POD_NAME": 'bad"pod'}):
            with self.assertRaises(ValueError):
                gateway.configured_metrics(env)
        metrics = gateway.RequestMetrics("litellm", "actual-gateway-pod")
        for i in range(2000):
            metrics.observe("USER-METHOD-" + str(i), "/client-" + str(i) + "?private", 200, "completed", .25)
        self.assertEqual(len(metrics.series), 1)
        for route in ("/health", "/health/readiness?private", "/metrics", "/metrics?query=x",
                      "/v1/admission/state?clientSHA256=x", "/v1/output-policy/state"):
            metrics.observe("GET", route, 200, "completed", 1)
        self.assertEqual(sum(v[0] for v in metrics.series.values()), 2000)
        self.assertNotIn("client-", metrics.exposition().decode())
        metrics.observe("GET", "/v1/admission/stateevil?private", 404, "completed", .25)
        self.assertEqual(sum(v[0] for v in metrics.series.values()), 2001)
        self.assertNotIn("stateevil", metrics.exposition().decode())

    def test_concurrent_observation_and_scrape_are_consistent(self):
        metrics = gateway.RequestMetrics("litellm", "actual-gateway-pod")
        def batch(_):
            for i in range(100):
                metrics.observe("POST", "/v1/chat/completions", 200, "completed", .125)
                if i % 10 == 0:
                    raw = metrics.exposition().decode()
                    count = re.search(r'^http_requests_total.* (\d+)$', raw, re.M)[1]
                    self.assertIn("_count{" + raw.split("http_requests_total{")[1].split("}")[0] + "} " + count, raw)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(batch, range(8)))
        value = next(iter(metrics.series.values()))
        self.assertEqual((value[0], value[1]), (800, 100.0))
        self.assertEqual(value[2][-1], 800)


if __name__ == "__main__":
    unittest.main()
