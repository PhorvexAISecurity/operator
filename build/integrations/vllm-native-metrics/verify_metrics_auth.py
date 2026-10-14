#!/usr/bin/env python3
"""One-shot cross-namespace auth proof, never a serving/sidecar health probe."""

import hashlib
import json
import re
import signal
import socket
import time

TARGET = ("phorvex-vllm-native-metrics.vllm.svc.cluster.local", 9102)
TOKEN_PATH = "/etc/phorvex-vllm-metrics/token"
NAMESPACE_PATH = "/etc/phorvex-vllm-metrics-probe/namespace"
SCHEMA = "phorvex.vllm-native-metrics-auth.v1"
TIMEOUT_SECONDS = 3.0
MAX_HEADERS = 8192
MAX_BODY = 1024 * 1024
REQUIRED_FAMILIES = (
    "vllm:num_requests_running", "vllm:num_requests_waiting",
    "vllm:request_success_total", "vllm:prompt_tokens_total",
    "vllm:generation_tokens_total", "vllm:e2e_request_latency_seconds_bucket",
    "vllm:e2e_request_latency_seconds_count", "vllm:e2e_request_latency_seconds_sum",
    "vllm:time_to_first_token_seconds_bucket",
    "vllm:time_to_first_token_seconds_count", "vllm:time_to_first_token_seconds_sum",
)


class _ProbeError(Exception):
    pass


def _load_token():
    with open(TOKEN_PATH, "rb") as token_file:
        token = token_file.read(65)
    if re.fullmatch(rb"[0-9a-f]{64}", token) is None:
        raise _ProbeError()
    return token


def _request(method, path, fields=(), body=b""):
    # Inputs are exclusively the fixed test cases below, never user URLs.
    return (method + b" " + path + b" HTTP/1.1\r\nHost: "
            + TARGET[0].encode("ascii") + b":9102\r\nConnection: close\r\n"
            + b"".join(name + b": " + value + b"\r\n" for name, value in fields)
            + b"\r\n" + body)


def _alarm(signum, frame):
    raise TimeoutError()


def _exchange(request):
    # Socket timeouts alone do not bound DNS or trickled HTTP headers. On the
    # Linux in-cluster main thread, SIGALRM also bounds resolution and every read.
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        with socket.create_connection(TARGET, TIMEOUT_SECONDS) as connection:
            def receive(limit):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                connection.settimeout(remaining)
                return connection.recv(min(4096, limit))

            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.sendall(request)
            buffer = bytearray()
            while b"\r\n\r\n" not in buffer:
                if len(buffer) > MAX_HEADERS:
                    raise _ProbeError()
                part = receive(MAX_HEADERS + 1 - len(buffer))
                if not part:
                    raise _ProbeError()
                buffer.extend(part)
            end = buffer.index(b"\r\n\r\n") + 4
            if end > MAX_HEADERS:
                raise _ProbeError()
            lines = bytes(buffer[:end - 4]).split(b"\r\n")
            status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [\x20-\x7e]*", lines[0])
            if status is None:
                raise _ProbeError()
            fields = {}
            for line in lines[1:]:
                name, colon, value = line.partition(b":")
                if (not colon or re.fullmatch(rb"[A-Za-z0-9-]+", name) is None
                        or any(c < 32 or c > 126 for c in value)):
                    raise _ProbeError()
                fields.setdefault(name.lower(), []).append(value.strip(b" "))
            lengths = fields.get(b"content-length", [])
            if (len(lengths) != 1 or re.fullmatch(rb"[0-9]{1,10}", lengths[0]) is None
                    or int(lengths[0]) > MAX_BODY or b"transfer-encoding" in fields
                    or fields.get(b"connection") != [b"close"]
                    or fields.get(b"cache-control") != [b"no-store"]):
                raise _ProbeError()
            length = int(lengths[0])
            body = bytearray(buffer[end:])
            if len(body) > length:
                raise _ProbeError()
            while len(body) < length:
                part = receive(length - len(body))
                if not part:
                    raise _ProbeError()
                body.extend(part)
            return int(status[1]), bytes(body)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _cases(token):
    auth = ((b"Authorization", b"Bearer " + token),)
    wrong = (b"0" if token[:1] != b"0" else b"1") + token[1:]
    yield "missing", 401, _request(b"GET", b"/metrics")
    yield "wrong", 401, _request(b"GET", b"/metrics", ((b"Authorization", b"Bearer " + wrong),))
    yield "duplicate", 401, _request(b"GET", b"/metrics", auth + auth)
    yield "malformed", 401, _request(b"GET", b"/metrics", ((b"Authorization", b"Bearer " + token + b" "),))
    yield "valid", 200, _request(b"GET", b"/metrics", auth)
    for name, path in (
        ("models", b"/v1/models"), ("inference", b"/v1/chat/completions"),
        ("control", b"/reset_prefix_cache"), ("health", b"/health"),
        ("query", b"/metrics?x=1"), ("trailing_slash", b"/metrics/"),
    ):
        yield name, 404, _request(b"GET", path, auth)
    for method in (b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS"):
        yield method.decode("ascii").lower(), 405, _request(method, b"/metrics", auth)
    yield "body", 502, _request(b"GET", b"/metrics", auth + ((b"Content-Length", b"1"),), b"x")
    yield "transfer_encoding", 502, _request(b"GET", b"/metrics", auth + ((b"Transfer-Encoding", b"chunked"),), b"0\r\n\r\n")


def run_probe():
    # Downward API proves this Job is in monitoring. No service-account mount,
    # API calls, Kubernetes RBAC, token arguments, or arbitrary target option.
    with open(NAMESPACE_PATH, "rb") as namespace_file:
        if namespace_file.read(11) != b"monitoring":
            raise _ProbeError()
    token = _load_token()
    receipt = {"schema": SCHEMA, "probe_namespace": "monitoring",
               "target_namespace": "vllm", "target_service": TARGET[0],
               "target_port": 9102, "ok": True, "cases": []}
    for name, expected, request in _cases(token):
        result = {"case": name, "expected_status": expected}
        try:
            status, body = _exchange(request)
            result.update(status=status, bytes=len(body))
            result["ok"] = status == expected and (expected == 200 or not body)
            if name == "valid" and status == 200:
                samples = set(re.findall(rb"(?m)^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{|[ \t])", body))
                families = {family: family.encode("ascii") in samples for family in REQUIRED_FAMILIES}
                result["native_families_present"] = families
                result["metrics_body_sha256"] = hashlib.sha256(body).hexdigest()
                result["ok"] = result["ok"] and all(families.values())
        except Exception:
            result.update(ok=False, event="probe_exchange_failed")
        receipt["ok"] = receipt["ok"] and result["ok"]
        receipt["cases"].append(result)
    return receipt


def main():
    try:
        receipt = run_probe()
    except Exception:
        receipt = {"schema": SCHEMA, "ok": False, "event": "probe_precondition_failed"}
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
