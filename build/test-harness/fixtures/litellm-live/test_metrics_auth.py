"""Token byte/startup controls; execute process tests on the isolated executor."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import gateway_metrics as gateway


SOURCE = Path(__file__).with_name("gateway_metrics.py").resolve()
SAFE_ERROR = "metrics authentication configuration invalid"
SYNTHETIC_TOKEN = b"0123456789abcdef" * 4


class MetricsTokenLoaderTests(unittest.TestCase):
    def test_disabled_does_not_open_or_validate_token_path(self):
        for enabled in (None, "0"):
            for path in ("", "relative", "/missing", "/malformed"):
                env = {"PHORVEX_LITELLM_METRICS_TOKEN_FILE": path}
                if enabled is not None:
                    env["PHORVEX_LITELLM_METRICS_ENABLED"] = enabled
                with self.subTest(enabled=enabled, path=path), mock.patch.object(Path, "open") as opened:
                    self.assertIsNone(gateway.configured_metrics_token(env))
                    opened.assert_not_called()

    def test_exact_bytes_and_projected_symlink_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "token"
            path.write_bytes(SYNTHETIC_TOKEN)
            path.chmod(0o440)
            projected = Path(temp) / "projected-token"
            projected.symlink_to(path)
            for file in (path, projected):
                token = gateway.configured_metrics_token({"PHORVEX_LITELLM_METRICS_ENABLED": "1",
                                                          "PHORVEX_LITELLM_METRICS_TOKEN_FILE": str(file)})
                self.assertEqual(token, SYNTHETIC_TOKEN)
                self.assertIsInstance(token, bytes)

    def test_bounded_read_without_whitespace_normalization(self):
        for raw in (b"", b"a" * 63, b"a" * 65, SYNTHETIC_TOKEN + b"\n", b" " + b"a" * 63,
                    b"a" * 63 + b" ", b"a" * 63 + b"\t", b"A" * 64, b"g" * 64, b"\xff" * 64):
            with self.subTest(raw=raw), mock.patch.object(Path, "open", mock.mock_open(read_data=raw)) as opened:
                with self.assertRaisesRegex(ValueError, "^" + SAFE_ERROR + "$"):
                    gateway.configured_metrics_token({"PHORVEX_LITELLM_METRICS_ENABLED": "1",
                                                      "PHORVEX_LITELLM_METRICS_TOKEN_FILE": "/private/path/token"})
                opened().read.assert_called_once_with(65)

    def test_bad_paths_and_os_errors_are_fixed_safe_errors(self):
        for env in ({"PHORVEX_LITELLM_METRICS_ENABLED": "1"},
                    {"PHORVEX_LITELLM_METRICS_ENABLED": "1", "PHORVEX_LITELLM_METRICS_TOKEN_FILE": "relative-private-path"},
                    {"PHORVEX_LITELLM_METRICS_ENABLED": "true"}):
            with self.assertRaisesRegex(ValueError, "^" + SAFE_ERROR + "$"):
                gateway.configured_metrics_token(env)
        for error in (FileNotFoundError("private-path"), PermissionError("private-data"), OSError("private-token")):
            with mock.patch.object(Path, "open", side_effect=error):
                with self.assertRaisesRegex(ValueError, "^" + SAFE_ERROR + "$"):
                    gateway.configured_metrics_token({"PHORVEX_LITELLM_METRICS_ENABLED": "1",
                                                      "PHORVEX_LITELLM_METRICS_TOKEN_FILE": "/private/path/token"})

    def test_serve_loads_token_before_gateway_or_any_server(self):
        env = {"PHORVEX_LITELLM_METRICS_ENABLED": "1", "POD_NAMESPACE": "litellm",
               "POD_NAME": "litellm-startup-fixture", "PHORVEX_LITELLM_METRICS_TOKEN_FILE": "/missing/private-token"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(gateway, "ThreadingHTTPServer") as http_server, \
                mock.patch.object(gateway, "MetricsHTTPServer") as metrics_server, mock.patch.object(gateway, "Gateway") as admission:
            with self.assertRaisesRegex(SystemExit, "^" + SAFE_ERROR + "$"):
                gateway.serve()
            admission.assert_not_called()
            http_server.assert_not_called()
            metrics_server.assert_not_called()


class MetricsStartupProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
                    "PHORVEX_LITELLM_METRICS_ENABLED": "1", "POD_NAMESPACE": "litellm",
                    "POD_NAME": "litellm-startup-fixture"}

    def test_invalid_auth_process_exits_before_any_listener_bind_with_no_leak(self):
        # Reserve every listener. If startup attempts even the admission/status
        # bind before auth validation, its error differs from the fixed auth error.
        reserved = []
        try:
            for port in (4001, 4002, 4003):
                listener = socket.socket()
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", port))
                listener.listen()
                reserved.append(listener)
            path = self.root / "private-token-file"
            variants = [("missing-path", None), ("empty", b""), ("short", b"a" * 63),
                        ("oversized", b"a" * 65), ("newline", SYNTHETIC_TOKEN + b"\n"),
                        ("whitespace", b"a" * 63 + b" "), ("nonhex", b"g" * 64),
                        ("uppercase", b"A" * 64), ("nonascii", b"\xff" * 64),
                        ("unreadable", SYNTHETIC_TOKEN)]
            for name, raw in variants:
                with self.subTest(name=name):
                    if path.exists():
                        path.unlink()
                    if raw is not None:
                        path.write_bytes(raw)
                        path.chmod(0o000 if name == "unreadable" else 0o644)
                    env = dict(self.env, PHORVEX_LITELLM_METRICS_TOKEN_FILE=str(path))
                    identity = {"user": 10001, "group": 10001, "extra_groups": []} if os.geteuid() == 0 else {}
                    process = subprocess.run([sys.executable, "-B", str(SOURCE)], env=env,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, **identity)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertEqual(process.stdout, b"")
                    self.assertEqual(process.stderr, (SAFE_ERROR + "\n").encode())
                    self.assertNotIn(SYNTHETIC_TOKEN, process.stdout + process.stderr)
                    self.assertNotIn(str(path).encode(), process.stdout + process.stderr)
        finally:
            for listener in reserved:
                listener.close()

    def test_disabled_bad_token_starts_admission_and_status_without_metrics(self):
        seed = b"synthetic-owned-trial-seed-32-bytes-0001"
        (self.root / "seed").write_bytes(seed)
        (self.root / "clients").write_text(json.dumps({"version": 2, "seedSHA256": hashlib.sha256(seed).hexdigest(),
                                                      "modelAlias": "gpt-4o-mini"}))
        (self.root / "policy").write_text('{"entries":[],"revision":0,"version":2}')
        (self.root / "status").write_text("synthetic-status-token-at-least-32-bytes")
        (self.root / "malformed-metrics-token").write_bytes(b"private-invalid-token\n")
        for enabled in (None, "0"):
            with self.subTest(enabled=enabled):
                env = dict(self.env, PHORVEX_LITELLM_METRICS_TOKEN_FILE=str(self.root / "malformed-metrics-token"),
                           PHORVEX_LITELLM_CLIENTS_FILE=str(self.root / "clients"),
                           PHORVEX_LITELLM_POLICY_FILE=str(self.root / "policy"),
                           PHORVEX_LITELLM_TRIAL_SEED_FILE=str(self.root / "seed"),
                           PHORVEX_LITELLM_STATUS_TOKEN_FILE=str(self.root / "status"),
                           PHORVEX_LITELLM_POLICY_CONFIGMAP_UID="policy-uid", POD_UID="pod-uid",
                           PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                           LITELLM_MASTER_KEY="sk-synthetic-master")
                if enabled is None:
                    env.pop("PHORVEX_LITELLM_METRICS_ENABLED")
                else:
                    env["PHORVEX_LITELLM_METRICS_ENABLED"] = enabled
                process = subprocess.Popen([sys.executable, "-B", str(SOURCE)], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            connection = socket.create_connection(("127.0.0.1", 4002), timeout=.2)
                            connection.close()
                            break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                self.fail("disabled process did not start status listener")
                            time.sleep(.025)
                    status = http.client.HTTPConnection("127.0.0.1", 4002, timeout=2)
                    status.request("GET", "/v1/admission/state")
                    response = status.getresponse()
                    self.assertEqual((response.status, response.read()), (401, b""))
                    status.close()
                    public = http.client.HTTPConnection("127.0.0.1", 4001, timeout=2)
                    public.request("OPTIONS", "/v1/models")
                    response = public.getresponse()
                    self.assertEqual(response.status, 501)
                    response.read()
                    public.close()
                    with self.assertRaises(OSError):
                        socket.create_connection(("127.0.0.1", 4003), timeout=.2)
                finally:
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                self.assertEqual((stdout, stderr), (b"", b""))


if __name__ == "__main__":
    unittest.main()
