#!/usr/bin/env python3
"""Run only on isolated EC2: PHORVEX_STAGE6_ISOLATED_TESTS=1 python3 -B -m unittest -v test_metrics."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import metrics
import verify_metrics_auth as probe

ISOLATED = os.environ.get("PHORVEX_STAGE6_ISOLATED_TESTS") == "1"
TOKEN = b"0123456789abcdef" * 4  # Synthetic fixture, never an installed credential.
BODY = b"".join(name.encode("ascii") + b" 1\n"
                for name in probe.REQUIRED_FAMILIES)
AUTH = b"Authorization: Bearer " + TOKEN + b"\r\n"
CREATE_CONNECTION = socket.create_connection


def request(path=b"/metrics", method=b"GET", headers=AUTH, body=b"", version=b"HTTP/1.1"):
    return method + b" " + path + b" " + version + b"\r\nHost: fixture\r\n" + headers + b"\r\n" + body


def read_response(connection):
    connection.settimeout(5)
    wire = bytearray()
    while True:
        try:
            part = connection.recv(65536)
        except ConnectionResetError:
            if wire:
                break
            raise
        if not part:
            break
        wire.extend(part)
        if len(wire) > metrics.MAX_BODY + 16384:
            raise AssertionError("unbounded listener reply")
    head, marker, body = bytes(wire).partition(b"\r\n\r\n")
    if not marker:
        raise AssertionError("missing HTTP response")
    lines = head.split(b"\r\n")
    fields = dict(line.lower().split(b": ", 1) for line in lines[1:])
    return int(lines[0].split(b" ")[1]), body, fields


def exchange(address, data):
    with CREATE_CONNECTION(address, 3) as connection:
        connection.sendall(data)
        return read_response(connection)


def response(body=BODY, status=b"200 OK", fields=()):
    return (b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(len(body)).encode("ascii")
            + b"\r\n" + b"".join(fields) + b"\r\n" + body)


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("fixture did not reach expected state")


class Engine(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, reply=None, address=("127.0.0.1", 0)):
        self.requests = []
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.reply = reply or (lambda connection: connection.sendall(response()))
        super().__init__(address, EngineHandler)
        self.thread = threading.Thread(target=self.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        if getattr(self, "_test_closed", False):
            return
        self._test_closed = True
        self.release.set()
        self.shutdown()
        self.server_close()
        self.thread.join(2)


class EngineHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 8192:
                part = self.request.recv(4096)
                if not part:
                    return
                data.extend(part)
            with self.server.lock:
                self.server.requests.append(bytes(data))
            self.server.reply(self.request)
        except OSError:
            pass


class _ListenerFixture:
    def setUp(self):
        self.engine = Engine()
        self.upstream = mock.patch.object(metrics, "UPSTREAM_ADDRESS", self.engine.server_address)
        self.upstream.start()
        self.addCleanup(self.upstream.stop)
        self.addCleanup(self.engine.close)
        self.listener = metrics.MetricsServer(("127.0.0.1", 0), TOKEN)
        self.thread = threading.Thread(target=self.listener.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_listener)

    def close_listener(self):
        self.engine.release.set()
        self.listener.shutdown()
        self.listener.server_close()
        self.thread.join(2)
        self.assertFalse(any(worker.is_alive() for worker in self.listener._workers))

    def call(self, data=None):
        return exchange(self.listener.server_address, request() if data is None else data)

    def assert_empty(self, expected, data):
        status, body, fields = self.call(data)
        self.assertEqual(status, expected)
        self.assertEqual(body, b"")
        self.assertEqual(fields[b"content-length"], b"0")
        self.assertEqual(fields[b"connection"], b"close")
        self.assertEqual(fields[b"cache-control"], b"no-store")


@unittest.skipUnless(ISOLATED, "isolated EC2 execution required")
class ListenerTests(_ListenerFixture, unittest.TestCase):
    def test_native_bytes_close_and_no_store(self):
        status, body, fields = self.call()
        self.assertEqual(status, 200)
        self.assertEqual(body, BODY)
        self.assertEqual(fields[b"connection"], b"close")
        self.assertEqual(fields[b"cache-control"], b"no-store")
        self.assertEqual(int(fields[b"content-length"]), len(BODY))
        self.assertEqual(self.engine.requests, [metrics.UPSTREAM_REQUEST])
        self.assertEqual(self.call(request(version=b"HTTP/1.0"))[0], 200)
        self.assertEqual(self.call(request(headers=AUTH + b"Content-Length: 0\r\n"))[0], 200)

    def test_missing_wrong_duplicate_and_malformed_credentials(self):
        bad = (
            b"", b"Authorization: Bearer " + b"0" * 64 + b"\r\n",
            AUTH + AUTH, AUTH + b"aUtHoRiZaTiOn: Bearer " + TOKEN + b"\r\n",
            b"Authorization: bearer " + TOKEN + b"\r\n",
            b"Authorization: Basic " + TOKEN + b"\r\n",
            b"Authorization: Bearer\t" + TOKEN + b"\r\n",
            b"Authorization: Bearer  " + TOKEN + b"\r\n",
            b"Authorization: Bearer " + TOKEN + b" \r\n",
            b"Authorization: Bearer " + TOKEN.upper() + b"\r\n",
            b"Authorization: Bearer " + TOKEN[:-1] + b"\r\n",
            b"Authorization: Bearer " + TOKEN + b"0\r\n",
            b"Authorization: Bearer " + TOKEN + b"\x00\r\n",
            b"Authorization: Bearer\r\n " + TOKEN + b"\r\n",
        )
        for fields in bad:
            with self.subTest(fields=fields[:20]):
                self.assert_empty(401, request(headers=fields))
        self.assertEqual(self.engine.requests, [])
        with mock.patch.object(metrics.hmac, "compare_digest", wraps=metrics.hmac.compare_digest) as compare:
            self.assertEqual(self.call()[0], 200)
            self.assert_empty(401, request(headers=b"Authorization: Bearer " + b"0" * 64 + b"\r\n"))
            self.assertEqual(compare.call_count, 2)

    def test_routes_methods_and_absolute_urls_never_reach_engine(self):
        for path in (b"/", b"/metrics/", b"/metrics?x=1", b"/metrics#x", b"/%6detrics",
                     b"//metrics", b"/health", b"/admin", b"/status", b"/v1/models",
                     b"/v1/chat/completions", b"/reset_prefix_cache", b"/drain",
                     b"http://127.0.0.1:8001/metrics", b"http://example.invalid/metrics"):
            with self.subTest(path=path):
                self.assert_empty(404, request(path=path))
        for method in (b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE"):
            self.assert_empty(405, request(method=method))
        self.assertEqual(self.engine.requests, [])

    def test_request_body_transfer_and_ambiguous_headers_refused(self):
        for fields, body in (
            (AUTH + b"Content-Length: 1\r\n", b"x"),
            (AUTH + b"Content-Length: -1\r\n", b""),
            (AUTH + b"Content-Length: 0\r\nContent-Length: 0\r\n", b""),
            (AUTH + b"Transfer-Encoding: chunked\r\n", b"0\r\n\r\n"),
            (AUTH + b"Transfer-Encoding: identity\r\n", b""),
            (AUTH + b"Expect: 100-continue\r\n", b""),
            (AUTH + b"Upgrade: websocket\r\n", b""),
            (AUTH + b"Bad Header: x\r\n", b""),
            (AUTH + b"X: x\r\n folded\r\n", b""),
        ):
            self.assert_empty(502, request(headers=fields, body=body))
        self.assertEqual(self.engine.requests, [])

    def test_request_line_and_aggregate_headers_have_exact_bounds(self):
        # The request-line limit includes CRLF. A bounded unknown route is 404.
        base = b"GET / HTTP/1.1\r\n"
        path = b"/" + b"x" * (metrics.MAX_REQUEST_LINE - len(base))
        self.assert_empty(404, request(path=path))
        self.assert_empty(502, request(path=path + b"x"))
        base_headers = b"Host: fixture\r\n" + AUTH + b"\r\n"
        padding = b"X-Pad: " + b"x" * (metrics.MAX_HEADERS - len(base_headers) - 9) + b"\r\n"
        self.assertEqual(self.call(request(headers=AUTH + padding))[0], 200)
        self.assert_empty(502, request(headers=AUTH + padding[:-2] + b"x\r\n"))
        self.assert_empty(502, b"GET /metrics HTTP/1.1\n" + AUTH + b"\n")

    def test_caller_headers_and_environment_proxies_are_not_forwarded(self):
        fields = (AUTH + b"Cookie: secret-cookie\r\nX-Forwarded-For: 192.0.2.5\r\n"
                  b"X-Forwarded-Host: example.invalid\r\nProxy-Authorization: secret-proxy\r\n"
                  b"X-API-Key: secret-engine-key\r\nForwarded: for=192.0.2.5\r\n"
                  b"Accept-Encoding: gzip\r\n")
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1",
                                          "HTTPS_PROXY": "http://127.0.0.1:1",
                                          "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
            self.assertEqual(self.call(request(headers=fields))[0], 200)
        self.assertEqual(self.engine.requests, [metrics.UPSTREAM_REQUEST])
        self.assertNotIn(TOKEN, self.engine.requests[0])

    def test_redirects_and_upstream_errors_never_follow_or_leak(self):
        trap = Engine()
        self.addCleanup(trap.close)
        location = b"Location: http://127.0.0.1:" + str(trap.server_address[1]).encode("ascii") + b"/v1/models\r\n"
        for status in (b"301 Moved", b"302 Found", b"307 Temporary Redirect", b"308 Permanent Redirect",
                       b"401 Unauthorized", b"500 Error", b"204 No Content"):
            self.engine.reply = lambda connection, status=status: connection.sendall(
                response(b"secret-engine-error", status, (location, b"X-Secret: secret-header\r\n")))
            self.assert_empty(502, request())
        self.assertEqual(trap.requests, [])
        self.engine.reply = lambda connection: connection.sendall(response())
        self.assertEqual(self.call()[0], 200)

    def test_large_content_length_is_rejected_before_body_read(self):
        self.engine.reply = lambda connection: connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n")
        self.assert_empty(502, request())

    def test_body_bound_exact_length_chunked_and_eof(self):
        maximum = b"x" * metrics.MAX_BODY
        for wire in (
            response(maximum),
            b"HTTP/1.1 200 OK\r\n\r\n" + maximum,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n" + maximum + b"\r\n0\r\n\r\n",
        ):
            self.engine.reply = lambda connection, wire=wire: connection.sendall(wire)
            status, body, _ = self.call()
            self.assertEqual(status, 200)
            self.assertEqual(body, maximum)
        for wire in (
            b"HTTP/1.1 200 OK\r\n\r\n" + maximum + b"x",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n" + maximum + b"\r\n1\r\nx\r\n0\r\n\r\n",
        ):
            self.engine.reply = lambda connection, wire=wire: connection.sendall(wire)
            self.assert_empty(502, request())

    def test_chunked_native_response_is_decoded_verbatim(self):
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + format(len(BODY), "x").encode("ascii") + b";ignored=1\r\n" + BODY
                + b"\r\n0\r\nX-Trailer: private-trailer\r\n\r\n")
        self.engine.reply = lambda connection: connection.sendall(wire)
        self.assertEqual(self.call()[:2], (200, BODY))

    def test_bad_upstream_framing_and_headers_are_fixed_errors(self):
        for wire in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nextra-body",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxNO",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra-body",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192 + b"\r\n\r\n",
        ):
            self.engine.reply = lambda connection, wire=wire: connection.sendall(wire)
            self.assert_empty(502, request())

    def test_errors_and_requests_never_log_private_input(self):
        out, err = io.StringIO(), io.StringIO()
        self.engine.reply = lambda connection: connection.sendall(response(b"engine-private-body", b"500 Error"))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assert_empty(404, request(path=b"/private-request-url?prompt=secret"))
            self.assert_empty(502, request(headers=AUTH + b"X-Private: private-header\r\n"))
            with mock.patch.object(metrics, "_fetch_metrics", side_effect=ValueError("private-exception " + TOKEN.decode())):
                self.assert_empty(502, request())
        self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_two_workers_include_slow_clients_and_overload_spawns_none(self):
        entered = threading.Event()
        original = metrics._handle
        count = 0
        lock = threading.Lock()
        def watched(*args):
            nonlocal count
            with lock:
                count += 1
                if count == 2:
                    entered.set()
            return original(*args)
        with mock.patch.object(metrics, "_handle", side_effect=watched), contextlib.ExitStack() as stack:
            clients = [stack.enter_context(CREATE_CONNECTION(self.listener.server_address, 2)) for _ in range(2)]
            for client in clients:
                client.sendall(b"G")
            self.assertTrue(entered.wait(2))
            workers = tuple(self.listener._workers)
            for _ in range(8):
                self.assert_empty(503, request())
            self.assertEqual(tuple(self.listener._workers), workers)
            self.assertEqual(len(workers), 2)
            self.assertTrue(all(worker.is_alive() for worker in workers))
            self.assertEqual(count, 2)
            self.assertEqual(self.engine.requests, [])
            for client in clients:
                client.sendall(request()[1:])
                self.assertEqual(read_response(client)[0], 200)
        wait_for(lambda: self.listener._slots._value == 2)
        self.assertEqual(self.call()[0], 200)

    def test_two_upstreams_overload_and_worker_recovery(self):
        def held(connection):
            self.engine.release.wait(2)
            connection.sendall(response())
        self.engine.reply = held
        with contextlib.ExitStack() as stack:
            clients = [stack.enter_context(CREATE_CONNECTION(self.listener.server_address, 2)) for _ in range(2)]
            for client in clients:
                client.sendall(request())
            wait_for(lambda: len(self.engine.requests) == 2)
            for _ in range(4):
                self.assert_empty(503, request())
            self.assertEqual(len(self.engine.requests), 2)
            self.engine.release.set()
            for client in clients:
                self.assertEqual(read_response(client)[0], 200)
        wait_for(lambda: self.listener._slots._value == 2)
        self.assertEqual(self.call()[0], 200)

    def test_trickled_client_has_absolute_three_second_deadline(self):
        with CREATE_CONNECTION(self.listener.server_address, 2) as connection:
            connection.sendall(b"G")
            stop = threading.Event()
            def trickle():
                while not stop.wait(0.2):
                    try:
                        connection.sendall(b"x")
                    except OSError:
                        return
            thread = threading.Thread(target=trickle, daemon=True)
            thread.start()
            started = time.monotonic()
            try:
                self.assertEqual(read_response(connection)[:2], (503, b""))
                self.assertLess(time.monotonic() - started, 3.5)
            finally:
                stop.set()
                thread.join(1)
        self.assertEqual(self.engine.requests, [])
        wait_for(lambda: self.listener._slots._value == 2)
        self.assertEqual(self.call()[0], 200)

    def test_trickled_upstream_headers_and_body_have_absolute_deadline(self):
        for prefix in (b"HTTP/1.1 200 OK\r\nX-Trickle: ",
                       b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"):
            def trickle(connection, prefix=prefix):
                connection.sendall(prefix)
                for _ in range(25):
                    if self.engine.release.wait(0.2):
                        return
                    connection.sendall(b"x")
            self.engine.reply = trickle
            started = time.monotonic()
            self.assert_empty(503, request())
            self.assertLess(time.monotonic() - started, 3.5)
            self.engine.release.set()
            wait_for(lambda: self.listener._slots._value == 2)
            self.engine.release.clear()
        self.engine.reply = lambda connection: connection.sendall(response())
        self.assertEqual(self.call()[0], 200)

    def test_engine_refusal_does_not_close_listener(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            address = reserved.getsockname()  # Bound but deliberately not listening.
            with mock.patch.object(metrics, "UPSTREAM_ADDRESS", address):
                for _ in range(3):
                    self.assert_empty(502, request())
                    self.assertTrue(self.thread.is_alive())
        self.assertEqual(self.call()[0], 200)

    def test_client_and_upstream_share_one_deadline(self):
        def delayed(connection):
            self.engine.release.wait(2.0)
            connection.sendall(response())
        self.engine.reply = delayed
        with CREATE_CONNECTION(self.listener.server_address, 2) as connection:
            started = time.monotonic()
            connection.sendall(b"G")
            time.sleep(1.3)
            connection.sendall(request()[1:])
            self.assertEqual(read_response(connection)[:2], (503, b""))
            self.assertLess(time.monotonic() - started, 3.5)
        self.assertEqual(len(self.engine.requests), 1)


@unittest.skipUnless(ISOLATED, "isolated EC2 execution required")
class CredentialAndStartupTests(unittest.TestCase):
    def test_exact_token_bytes_and_bounded_read(self):
        for invalid in (b"", TOKEN[:-1], TOKEN + b"\n", TOKEN + b" ", TOKEN.upper(), b"g" * 64, TOKEN * 100):
            token_file = mock.mock_open(read_data=invalid)
            with mock.patch("builtins.open", token_file):
                with self.assertRaises(ValueError):
                    metrics.load_token()
                token_file().read.assert_called_once_with(65)
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_bytes(TOKEN)
            self.assertEqual(metrics.load_token(token_path), TOKEN)
            token_path.write_bytes(TOKEN + b"\n")
            with self.assertRaises(ValueError):
                metrics.load_token(token_path)

    def test_invalid_unreadable_and_missing_credentials_fail_before_bind(self):
        for error in (ValueError("secret-value"), PermissionError("secret-path"), FileNotFoundError("secret-path")):
            err = io.StringIO()
            with mock.patch.object(metrics, "load_token", side_effect=error), \
                 mock.patch.object(metrics, "MetricsServer") as server, \
                 mock.patch.object(metrics, "_stay_alive") as stay, contextlib.redirect_stderr(err):
                metrics.main()
                server.assert_not_called()
                stay.assert_called_once_with()
            self.assertEqual(err.getvalue(), "metrics_listener_disabled\n")

    def test_bind_failure_is_one_nonsecret_event_and_alive_state(self):
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            held.listen()
            err = io.StringIO()
            with mock.patch.object(metrics, "load_token", return_value=TOKEN), \
                 mock.patch.object(metrics, "LISTEN_ADDRESS", held.getsockname()), \
                 mock.patch.object(metrics, "_stay_alive") as stay, contextlib.redirect_stderr(err):
                metrics.main()
                stay.assert_called_once_with()
            self.assertEqual(err.getvalue(), "metrics_listener_disabled\n")

    def test_production_transport_and_process_constants(self):
        self.assertEqual(metrics.LISTEN_ADDRESS, ("0.0.0.0", 9102))
        self.assertEqual(metrics.UPSTREAM_ADDRESS, ("127.0.0.1", 8001))
        self.assertEqual(metrics.TOKEN_PATH, "/etc/phorvex-vllm-metrics/token")
        self.assertEqual(metrics.MAX_WORKERS, 2)
        self.assertEqual(metrics.TIMEOUT_SECONDS, 3.0)
        self.assertEqual(metrics.MAX_REQUEST_LINE, 2048)
        self.assertEqual(metrics.MAX_HEADERS, 8192)
        self.assertEqual(metrics.MAX_BODY, 1048576)


METRICS_PROCESS = r'''
import metrics, sys
original = metrics.load_token
metrics.load_token = lambda: original(sys.argv[1])
metrics.LISTEN_ADDRESS = ("127.0.0.1", int(sys.argv[2]))
metrics.UPSTREAM_ADDRESS = ("127.0.0.1", int(sys.argv[3]))
metrics.main()
'''
SERVING_PROCESS = r'''
import http.server
class Serving(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"independent-serving-fixture"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Serving)
print(server.server_address[1], flush=True)
server.serve_forever()
'''


@unittest.skipUnless(ISOLATED, "isolated EC2 execution required")
class ProcessIndependenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.token_path = Path(self.directory.name) / "token"
        self.token_path.write_bytes(TOKEN)
        self.serving = self.start(SERVING_PROCESS)
        with selectors.DefaultSelector() as selector:
            selector.register(self.serving.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(3), "serving fixture failed to start")
        self.serving_address = ("127.0.0.1", int(self.serving.stdout.readline()))

    def start(self, program, *arguments):
        process = subprocess.Popen([sys.executable, "-B", "-c", program, *map(str, arguments)],
                                   cwd=Path(__file__).resolve().parent,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        return process

    def stop(self, process):
        if hasattr(process, "_test_output"):
            return process._test_output
        if process.poll() is None:
            process.terminate()
        try:
            output = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            output = process.communicate(timeout=2)
        process._test_output = output
        return output

    def assert_serving(self):
        self.assertIsNone(self.serving.poll())
        status, body, _ = exchange(self.serving_address, request(path=b"/health", headers=b""))
        self.assertEqual((status, body), (200, b"independent-serving-fixture"))

    def test_invalid_mount_and_bind_failure_keep_process_alive_and_serving_independent(self):
        for mode in ("malformed", "missing", "unreadable_mount", "bind"):
            with self.subTest(mode=mode), socket.socket() as held:
                held.bind(("127.0.0.1", 0))
                address = held.getsockname()
                if mode == "bind":
                    held.listen()
                    token_path = self.token_path
                elif mode == "missing":
                    token_path = Path(self.directory.name) / "missing"
                elif mode == "unreadable_mount":
                    token_path = Path(self.directory.name)
                else:
                    token_path = Path(self.directory.name) / "bad"
                    token_path.write_bytes(TOKEN + b"\n")
                child = self.start(METRICS_PROCESS, token_path, address[1], 1)
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stderr, selectors.EVENT_READ)
                    self.assertTrue(selector.select(3), "no disabled event")
                self.assertEqual(child.stderr.readline(), b"metrics_listener_disabled\n")
                for _ in range(3):
                    self.assertIsNone(child.poll())
                    self.assert_serving()
                    time.sleep(0.05)
                if mode != "bind":
                    with self.assertRaises(OSError):
                        CREATE_CONNECTION(address, 0.2)
                self.assertEqual(self.stop(child), (b"", b""))

    def test_engine_startup_outage_recovery_and_listener_removal_leave_serving_alive(self):
        with socket.socket() as listener_slot, socket.socket() as engine_slot:
            listener_slot.bind(("127.0.0.1", 0))
            engine_slot.bind(("127.0.0.1", 0))
            address, upstream = listener_slot.getsockname(), engine_slot.getsockname()
        child = self.start(METRICS_PROCESS, self.token_path, address[1], upstream[1])
        def child_listening():
            try:
                return exchange(address, request(headers=b""))[0] == 401
            except OSError:
                return False
        wait_for(child_listening, 3)
        self.assertEqual(exchange(address, request())[0], 502)
        self.assert_serving()
        engine = Engine(address=upstream)
        self.addCleanup(engine.close)
        self.assertEqual(exchange(address, request())[:2], (200, BODY))
        self.assertIsNone(child.poll())
        self.assert_serving()
        engine.close()
        # Cleanup is idempotent for a stopped TCPServer.
        self.assertEqual(exchange(address, request())[0], 502)
        self.assertIsNone(child.poll())
        self.assert_serving()
        engine = Engine(address=upstream)
        self.addCleanup(engine.close)
        self.assertEqual(exchange(address, request())[:2], (200, BODY))
        self.stop(child)
        self.assert_serving()


@unittest.skipUnless(ISOLATED, "isolated EC2 execution required")
class ProbeTests(_ListenerFixture, unittest.TestCase):
    def test_probe_round_trip_has_only_status_hash_and_fixed_family_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            token_path, namespace_path = Path(directory) / "token", Path(directory) / "namespace"
            token_path.write_bytes(TOKEN)
            namespace_path.write_bytes(b"monitoring")
            targets = []
            def connect(address, timeout):
                targets.append(address)
                return CREATE_CONNECTION(self.listener.server_address if address == probe.TARGET else address, timeout)
            with mock.patch.object(probe, "TOKEN_PATH", str(token_path)), \
                 mock.patch.object(probe, "NAMESPACE_PATH", str(namespace_path)), \
                 mock.patch.object(probe.socket, "create_connection", side_effect=connect):
                receipt = probe.run_probe()
            self.assertTrue(receipt["ok"])
            self.assertEqual(len(receipt["cases"]), 18)
            valid = next(row for row in receipt["cases"] if row["case"] == "valid")
            self.assertEqual(valid["metrics_body_sha256"], hashlib.sha256(BODY).hexdigest())
            self.assertTrue(all(valid["native_families_present"].values()))
            self.assertEqual(targets.count(probe.TARGET), 18)
            self.assertEqual(self.engine.requests, [metrics.UPSTREAM_REQUEST])
            encoded = json.dumps(receipt)
            self.assertNotIn(TOKEN.decode(), encoded)
            self.assertNotIn(BODY.decode(), encoded)

    def test_probe_invalid_token_and_namespace_never_make_requests(self):
        for namespace, token in ((b"vllm", TOKEN), (b"monitoring", TOKEN + b"\n"),
                                 (b"monitoring-more", TOKEN), (b"monitoring", b"")):
            with tempfile.TemporaryDirectory() as directory:
                token_path, namespace_path = Path(directory) / "token", Path(directory) / "namespace"
                token_path.write_bytes(token)
                namespace_path.write_bytes(namespace)
                out = io.StringIO()
                with mock.patch.object(probe, "TOKEN_PATH", str(token_path)), \
                     mock.patch.object(probe, "NAMESPACE_PATH", str(namespace_path)), \
                     mock.patch.object(probe, "_exchange") as send, contextlib.redirect_stdout(out):
                    self.assertEqual(probe.main(), 1)
                    send.assert_not_called()
                self.assertEqual(json.loads(out.getvalue()), {
                    "schema": probe.SCHEMA, "ok": False, "event": "probe_precondition_failed"})

    def test_probe_errors_do_not_echo_response_or_exception_text(self):
        private = "private-token-or-url " + TOKEN.decode()
        with mock.patch("builtins.open", mock.mock_open(read_data=b"monitoring")), \
             mock.patch.object(probe, "_load_token", return_value=TOKEN), \
             mock.patch.object(probe, "_exchange", side_effect=ValueError(private)):
            receipt = probe.run_probe()
        self.assertFalse(receipt["ok"])
        self.assertEqual(len(receipt["cases"]), 18)
        self.assertNotIn(private, json.dumps(receipt))
        self.assertTrue(all(row["event"] == "probe_exchange_failed" for row in receipt["cases"]))

    def test_probe_family_comments_do_not_count_as_samples(self):
        fake = b"".join(b"# TYPE " + name.encode() + b" gauge\n" for name in probe.REQUIRED_FAMILIES)
        def reply(data):
            return (200, fake) if AUTH in data and b"GET /metrics HTTP" in data else (401, b"")
        with mock.patch("builtins.open", mock.mock_open(read_data=b"monitoring")), \
             mock.patch.object(probe, "_load_token", return_value=TOKEN), \
             mock.patch.object(probe, "_exchange", side_effect=reply):
            receipt = probe.run_probe()
        valid = next(row for row in receipt["cases"] if row["case"] == "valid")
        self.assertFalse(valid["ok"])
        self.assertFalse(any(valid["native_families_present"].values()))

    def test_probe_private_error_bodies_are_not_printed(self):
        private = b"private-engine-response " + TOKEN
        statuses = [expected for _, expected, _ in probe._cases(TOKEN)]
        with mock.patch("builtins.open", mock.mock_open(read_data=b"monitoring")), \
             mock.patch.object(probe, "_load_token", return_value=TOKEN), \
             mock.patch.object(probe, "_exchange", side_effect=[(status, private) for status in statuses]):
            receipt = probe.run_probe()
        self.assertFalse(receipt["ok"])
        self.assertNotIn(private.decode(), json.dumps(receipt))
        self.assertNotIn(TOKEN.decode(), json.dumps(receipt))

    def test_probe_dns_failure_and_resolution_are_time_bounded(self):
        def stalled_dns(*args, **kwargs):
            time.sleep(10)
        started = time.monotonic()
        with mock.patch.object(probe.socket, "getaddrinfo", side_effect=stalled_dns):
            with self.assertRaises(TimeoutError):
                probe._exchange(probe._request(b"GET", b"/metrics"))
        self.assertLess(time.monotonic() - started, 3.5)

    def test_probe_oversize_headers_body_redirect_and_short_body_are_rejected(self):
        wires = (
            b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/secret\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192 + b"\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nshort",
        )
        for wire in wires:
            target = Engine(reply=lambda connection, wire=wire: connection.sendall(wire))
            try:
                def connect(address, timeout):
                    self.assertEqual(address, probe.TARGET)
                    return CREATE_CONNECTION(target.server_address, timeout)
                with mock.patch.object(probe.socket, "create_connection", side_effect=connect):
                    with self.assertRaises(probe._ProbeError):
                        probe._exchange(probe._request(b"GET", b"/metrics"))
                self.assertEqual(len(target.requests), 1)
            finally:
                target.close()


if __name__ == "__main__":
    unittest.main()
