"""Listener/import regression checks; successful admission is proved by envtest Go case."""

import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

import httpx


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SPEC = importlib.util.spec_from_file_location("verification_runtime_fixture", HERE / "runtime_fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class RuntimeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.cert, cls.key = root / "tls.crt", root / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.lease_module, cls.boundary_module, source = fixture.load_runtime(REPO)
        cls.admin = "a" * 48
        cls.ready_file = root / "ready.json"
        # An unreachable pinned TLS API is a real transport failure. No fake policy
        # reader or successful authority is provided to these process checks.
        config = {"repo_root": str(REPO), "api_url": "https://127.0.0.1:1",
                  "api_ca_file": str(cls.cert), "api_client_cert_file": str(cls.cert),
                  "api_client_key_file": str(cls.key), "host": "127.0.0.1",
                  "pod_uid": "11111111-1111-1111-1111-111111111111",
                  "service_uid": "22222222-2222-2222-2222-222222222222",
                  "policy_configmap_uid": "33333333-3333-3333-3333-333333333333",
                  "secret_uid": "44444444-4444-4444-4444-444444444444",
                  "source_sha256": source, "secret_dir": str(root / "secret"),
                  "admin_token": cls.admin, "upstream_key": "u" * 48,
                  "tls_cert_file": str(cls.cert), "tls_key_file": str(cls.key),
                  "ready_file": str(cls.ready_file)}
        config_file = root / "config.json"
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o600)
        cls.process = subprocess.Popen([sys.executable, str(HERE / "runtime_fixture.py"),
                                        "--config", str(config_file)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        while not cls.ready_file.exists() and cls.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not cls.ready_file.exists():
            cls.process.terminate()
            stdout, stderr = cls.process.communicate(timeout=8)
            raise AssertionError("fixture failed to start: " + stderr + stdout)
        cls.ready = json.loads(cls.ready_file.read_text())
        cls.public = httpx.Client(base_url=cls.ready["public_url"], trust_env=False, timeout=3)
        context = ssl.create_default_context(cafile=str(cls.cert))
        cls.private = httpx.Client(base_url=cls.ready["admin_url"], verify=context,
                                   trust_env=False, timeout=3)
        cls.observer = httpx.Client(base_url=cls.ready["observer_url"], trust_env=False, timeout=3)

    @classmethod
    def tearDownClass(cls):
        for client in (cls.public, cls.private, cls.observer):
            client.close()
        cls.process.terminate()
        cls.stdout, cls.stderr = cls.process.communicate(timeout=8)
        if cls.process.returncode != 0:
            raise AssertionError("fixture SIGTERM teardown failed: " + cls.stderr)
        if cls.admin in cls.stdout or cls.admin in cls.stderr or "u" * 48 in cls.stdout + cls.stderr:
            raise AssertionError("fixture exposed credentials")
        cls.temp.cleanup()

    def test_uses_actual_production_classes_and_composite_source(self):
        runtime = REPO / "build/integrations/vllm-live-runtime"
        self.assertEqual(Path(self.lease_module.__file__).resolve(), runtime / "endpoint_lease.py")
        self.assertEqual(Path(self.boundary_module.__file__).resolve(), runtime / "dual_server.py")
        self.assertEqual(self.ready["source_sha256"], fixture.load_runtime(REPO)[2])
        self.assertEqual(self.ready["scope"], fixture.SCOPE)

    def test_invalid_token_is_denied_and_cannot_reach_downstream(self):
        response = self.public.post("/v1/completions", json={"nonce": "invalid-token"},
                                    headers={"Authorization": "Bearer short"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "unauthorized"})
        stats = self.observer.get("/stats", headers={"Authorization": "Bearer " + self.admin})
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.json()["call_count"], 0)

    def test_unavailable_api_does_not_create_admission_success(self):
        response = self.public.post("/v1/completions", json={"nonce": "api-unavailable"},
                                    headers={"Authorization": "Bearer " + "c" * 48})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": "lease_unavailable"})
        self.assertEqual(self.public.get("/health").status_code, 503)
        stats = self.observer.get("/stats", headers={"Authorization": "Bearer " + self.admin})
        self.assertEqual(stats.json()["call_count"], 0)

    def test_admin_route_is_isolated_authenticated_and_tls_only(self):
        query = {"revokedClientHMAC": "0" * 64, "retainedClientHMAC": "1" * 64}
        auth = {"Authorization": "Bearer " + self.admin}
        self.assertEqual(self.public.get("/v1/endpoint-lease/state", params=query,
                                         headers=auth).status_code, 404)
        self.assertEqual(self.private.get("/v1/endpoint-lease/state", params=query).status_code, 401)
        self.assertEqual(self.private.get("/v1/endpoint-lease/state", params=query,
                                          headers=auth).status_code, 503)
        self.assertEqual(self.observer.get("/stats").status_code, 401)
        with httpx.Client(trust_env=False, timeout=2) as client:
            with self.assertRaises(httpx.HTTPError):
                client.get(self.ready["admin_url"].replace("https:", "http:") + "/health",
                           headers=auth)


if __name__ == "__main__":
    unittest.main()
