#!/usr/bin/env python3
"""Bounded, independent native vLLM metrics listener. Python stdlib only."""

import hmac
import queue
import re
import socket
import socketserver
import sys
import threading
import time

LISTEN_ADDRESS = ("0.0.0.0", 9102)
UPSTREAM_ADDRESS = ("127.0.0.1", 8001)
UPSTREAM_REQUEST = (
    b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:8001\r\n"
    b"Accept: text/plain\r\nConnection: close\r\n\r\n"
)
TOKEN_PATH = "/etc/phorvex-vllm-metrics/token"
TIMEOUT_SECONDS = 3.0
MAX_WORKERS = 2
MAX_REQUEST_LINE = 2048
MAX_HEADERS = 8192
MAX_BODY = 1024 * 1024
_TOKEN = re.compile(rb"[0-9a-f]{64}")
_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_STATUS = {200: b"OK", 401: b"Unauthorized", 404: b"Not Found",
           405: b"Method Not Allowed", 502: b"Bad Gateway",
           503: b"Service Unavailable"}


class _Rejected(Exception):
    def __init__(self, status=502):
        self.status = status


def load_token(path=TOKEN_PATH):
    """Read at most 65 bytes; projected token bytes are never normalized."""
    with open(path, "rb") as token_file:
        token = token_file.read(65)
    if _TOKEN.fullmatch(token) is None:
        raise ValueError("invalid metrics credential")
    return token


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    return remaining


class _Reader:
    """Every read observes the same absolute deadline, including header reads."""
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()

    def _recv(self, limit):
        self.connection.settimeout(_remaining(self.deadline))
        return self.connection.recv(min(4096, limit))

    def line(self, limit):
        while True:
            _remaining(self.deadline)
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end + 1 > limit:
                    raise _Rejected()
                result = bytes(self.buffer[:end + 1])
                del self.buffer[:end + 1]
                if not result.endswith(b"\r\n"):
                    raise _Rejected()
                return result
            if len(self.buffer) >= limit:
                raise _Rejected()
            part = self._recv(limit - len(self.buffer))
            if not part:
                raise _Rejected()
            self.buffer.extend(part)

    def exact(self, length):
        result = bytearray()
        while len(result) < length:
            _remaining(self.deadline)
            if self.buffer:
                take = min(length - len(result), len(self.buffer))
                result.extend(self.buffer[:take])
                del self.buffer[:take]
            else:
                part = self._recv(length - len(result))
                if not part:
                    raise _Rejected()
                result.extend(part)
        return bytes(result)

    def until_eof(self, limit):
        result = bytearray(self.buffer)
        self.buffer.clear()
        while len(result) <= limit:
            part = self._recv(limit + 1 - len(result))
            if not part:
                return bytes(result)
            result.extend(part)
        raise _Rejected()


def _headers(reader, request=False):
    fields = {}
    remaining = MAX_HEADERS
    previous = None
    while True:
        line = reader.line(remaining)
        remaining -= len(line)
        if line == b"\r\n":
            return fields
        if line[:1] in (b" ", b"\t"):
            raise _Rejected(401 if request and previous == b"authorization" else 502)
        name, colon, value = line[:-2].partition(b":")
        name = name.lower()
        if not colon or _FIELD_NAME.fullmatch(name) is None:
            raise _Rejected()
        previous = name
        # One conventional space after ':' is HTTP syntax, not token trimming.
        if value.startswith(b" "):
            value = value[1:]
        if any(c < 32 and c != 9 or c > 126 for c in value):
            raise _Rejected(401 if request and name == b"authorization" else 502)
        fields.setdefault(name, []).append(value)


def _request(reader, token):
    line = reader.line(MAX_REQUEST_LINE)
    parts = line[:-2].split(b" ")
    if (len(parts) != 3 or _FIELD_NAME.fullmatch(parts[0]) is None
            or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1")):
        raise _Rejected()
    method, path, _ = parts
    fields = _headers(reader, request=True)
    if method != b"GET":
        raise _Rejected(405)
    if path != b"/metrics":
        raise _Rejected(404)
    credentials = fields.get(b"authorization", [])
    if (len(credentials) != 1 or not credentials[0].startswith(b"Bearer ")
            or _TOKEN.fullmatch(credentials[0][7:]) is None
            or not hmac.compare_digest(credentials[0][7:], token)):
        raise _Rejected(401)
    if (b"transfer-encoding" in fields or b"expect" in fields
            or b"upgrade" in fields
            or fields.get(b"content-length", [b"0"]) != [b"0"]
            or reader.buffer):
        raise _Rejected()


def _chunked(reader):
    result = bytearray()
    while True:
        size_field = reader.line(MAX_REQUEST_LINE)[:-2].split(b";", 1)[0]
        if re.fullmatch(rb"[0-9a-fA-F]{1,16}", size_field) is None:
            raise _Rejected()
        size = int(size_field, 16)
        if size > MAX_BODY - len(result):
            raise _Rejected()
        if size == 0:
            _headers(reader)  # Trailers have the same aggregate bound.
            return bytes(result)
        result.extend(reader.exact(size))
        if reader.exact(2) != b"\r\n":
            raise _Rejected()


def _fetch_metrics(deadline):
    # Raw TCP to a literal loopback address: no URL, proxy, redirect handler,
    # caller headers, environment configuration, or engine/admin credential.
    with socket.create_connection(UPSTREAM_ADDRESS, _remaining(deadline)) as upstream:
        upstream.settimeout(_remaining(deadline))
        upstream.sendall(UPSTREAM_REQUEST)
        reader = _Reader(upstream, deadline)
        status_line = reader.line(MAX_REQUEST_LINE)[:-2]
        if re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", status_line) is None:
            raise _Rejected()
        fields = _headers(reader)
        if fields.get(b"content-encoding", [b"identity"]) != [b"identity"]:
            raise _Rejected()
        transfer = fields.get(b"transfer-encoding")
        lengths = fields.get(b"content-length")
        if transfer is not None:
            if transfer != [b"chunked"] or lengths is not None:
                raise _Rejected()
            body = _chunked(reader)
            reader.until_eof(0)  # Our fixed request requires upstream close.
            return body
        if lengths is None:
            return reader.until_eof(MAX_BODY)
        if (len(lengths) != 1 or re.fullmatch(rb"[0-9]{1,10}", lengths[0]) is None
                or int(lengths[0]) > MAX_BODY):
            raise _Rejected()
        body = reader.exact(int(lengths[0]))
        reader.until_eof(0)  # Reject extra bytes instead of returning a prefix.
        return body


def _response(status, body=b""):
    headers = (b"HTTP/1.1 " + str(status).encode("ascii") + b" " + _STATUS[status]
               + b"\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: "
               + str(len(body)).encode("ascii") + b"\r\n")
    if status == 200:
        headers += b"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
    return headers + b"\r\n" + body


def _fixed_error(connection, status):
    # No worker is created for overload. Bound even the accept-loop's error write.
    try:
        connection.settimeout(0.05)
        connection.sendall(_response(status))
    except OSError:
        pass


def _handle(connection, token, deadline):
    try:
        _request(_Reader(connection, deadline), token)
        body = _fetch_metrics(deadline)
        connection.settimeout(_remaining(deadline))
        connection.sendall(_response(200, body))
    except _Rejected as error:
        _fixed_error(connection, error.status)
    except TimeoutError:
        _fixed_error(connection, 503)
    except Exception:
        # Never print exceptions, peer/request data, or upstream content.
        _fixed_error(connection, 502)


class MetricsServer(socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 4

    def __init__(self, address, token):
        if not isinstance(token, bytes) or _TOKEN.fullmatch(token) is None:
            raise ValueError("invalid metrics credential")
        self.token = token
        self._slots = threading.BoundedSemaphore(MAX_WORKERS)
        self._pending = queue.Queue(maxsize=MAX_WORKERS)
        self._closed = threading.Event()
        self._workers = []
        super().__init__(address, socketserver.BaseRequestHandler)
        try:
            for _ in range(MAX_WORKERS):
                worker = threading.Thread(target=self._worker,
                                          name="native-metrics-worker", daemon=True)
                worker.start()
                self._workers.append(worker)
        except Exception:
            self.server_close()
            raise

    def process_request(self, request, client_address):
        deadline = time.monotonic() + TIMEOUT_SECONDS
        if self._closed.is_set() or not self._slots.acquire(blocking=False):
            _fixed_error(request, 503)
            self.shutdown_request(request)
            return
        try:
            self._pending.put_nowait((request, deadline))
        except Exception:
            self._slots.release()
            _fixed_error(request, 503)
            self.shutdown_request(request)

    def _worker(self):
        while True:
            try:
                request, deadline = self._pending.get(timeout=0.1)
            except queue.Empty:
                if self._closed.is_set():
                    return
                continue
            try:
                _handle(request, self.token, deadline)
            finally:
                try:
                    self.shutdown_request(request)
                finally:
                    self._slots.release()
                    self._pending.task_done()

    def server_close(self):
        self._closed.set()
        super().server_close()
        for worker in self._workers:
            worker.join(TIMEOUT_SECONDS + 0.2)

    def handle_error(self, request, client_address):
        pass


def _stay_alive():
    # SIGTERM retains its default behavior. No retries/probes couple this process
    # to model startup, readiness, engine outages, or serving-process lifetime.
    threading.Event().wait()


def main():
    server = None
    try:
        token = load_token()
        server = MetricsServer(LISTEN_ADDRESS, token)
        server.serve_forever(poll_interval=0.25)
    except Exception:
        if server is not None:
            server.server_close()
        try:
            sys.stderr.write("metrics_listener_disabled\n")
            sys.stderr.flush()
        except OSError:
            pass
        _stay_alive()


if __name__ == "__main__":
    main()
