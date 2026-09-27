"""Exercise the embedded admin probe against real CA-issued TLS certificates."""

import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest


SOURCE = Path(__file__).with_name("endpoint_lease_probe.go")
HOST = "vllm-admin.vllm.svc"


def openssl(*args):
    subprocess.run(("openssl", *map(str, args)), check=True, capture_output=True)


class EndpointLeaseProbeTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", cls.root / "ca.key", "-out", cls.root / "ca.crt",
                "-subj", "/CN=probe-test-ca",
                "-addext", "basicConstraints=critical,CA:TRUE")
        for name, hostname in (("expected", HOST), ("other", HOST),
                               ("wrong-host", "other.vllm.svc")):
            openssl("req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", cls.root / (name + ".key"),
                    "-out", cls.root / (name + ".csr"),
                    "-subj", "/CN=" + hostname)
            ext = cls.root / (name + ".ext")
            ext.write_text("basicConstraints=critical,CA:FALSE\n"
                           "extendedKeyUsage=serverAuth\n"
                           "subjectAltName=DNS:" + hostname + "\n")
            openssl("x509", "-req", "-in", cls.root / (name + ".csr"),
                    "-CA", cls.root / "ca.crt", "-CAkey", cls.root / "ca.key",
                    "-CAcreateserial", "-out", cls.root / (name + ".crt"),
                    "-days", "1", "-sha256", "-extfile", ext)
        source = SOURCE.read_text()
        match = re.search(r"const endpointLeaseAdminProbe = `([^`]*)`", source)
        if match is None:
            raise AssertionError("embedded endpoint lease probe unavailable")
        cls.probe = match.group(1)
        assert cls.probe.count("('127.0.0.1',8443)") == 1

    def run_probe(self, server_cert, trust_cert, omit_partial_chain=False):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = listener.getsockname()[1]
        errors = []

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.root / (server_cert + ".crt"),
                                        self.root / (server_cert + ".key"))
                    with ctx.wrap_socket(connection, server_side=True) as channel:
                        channel.recv(4096)
                        body = b'{"ready":true}'
                        channel.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                        + b"Content-Length: " + str(len(body)).encode()
                                        + b"\r\nConnection: close\r\n\r\n" + body)
            except (OSError, ssl.SSLError) as error:
                errors.append(error)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        code = self.probe.replace("('127.0.0.1',8443)", f"('127.0.0.1',{port})")
        if omit_partial_chain:
            code = code.replace("ctx.verify_flags|=ssl.VERIFY_X509_PARTIAL_CHAIN\n", "")
        # Python releases differ in their default verify flags. Start from the
        # older default so this test proves the probe explicitly enables trust
        # in the mounted CA-issued leaf.
        prelude = ("import ssl\n"
                   "_default_context=ssl.create_default_context\n"
                   "def _without_partial_chain(*args,**kwargs):\n"
                   " ctx=_default_context(*args,**kwargs)\n"
                   " ctx.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN\n"
                   " return ctx\n"
                   "ssl.create_default_context=_without_partial_chain\n")
        code = prelude + code
        env = dict(os.environ, PHORVEX_GUARDRAIL_ADMIN_KEY="a" * 48,
                   PHORVEX_ADMIN_TLS_CERT_FILE=str(self.root / (trust_cert + ".crt")))
        result = subprocess.run((sys.executable, "-B", "-c", code),
                                input=json.dumps({"revokedClientHMAC": "b" * 64,
                                                  "retainedClientHMAC": "c" * 64}),
                                text=True, capture_output=True, timeout=15, env=env)
        server.join(timeout=8)
        self.assertFalse(server.is_alive(), "test TLS server did not finish")
        return result

    def test_ca_issued_mounted_leaf_is_trusted(self):
        result = self.run_probe("expected", "expected")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"ready": True})
        without_fix = self.run_probe("expected", "expected", omit_partial_chain=True)
        self.assertNotEqual(without_fix.returncode, 0)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", without_fix.stderr)

    def test_different_ca_issued_leaf_is_rejected(self):
        result = self.run_probe("other", "expected")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", result.stderr)

    def test_wrong_hostname_is_rejected(self):
        result = self.run_probe("wrong-host", "wrong-host")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Hostname mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
