import http.server
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from .evidence import EvidenceError, Journal, STREAMS
from .observe import Kube, collect, discover, resource_paths
from .test_evidence import inventory, scope


class Proxy:
    """A real localhost HTTP transport behind a fake kubectl process."""
    def __init__(self, status, uid, requests):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_DELETE(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, body))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"kind": "Status", "details": {"uid": uid}, "reason": "Success" if status == 200 else "Conflict"}).encode())
            def log_message(self, *args):
                pass
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        read_fd, write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "rb")
        os.write(write_fd, ("Starting to serve on 127.0.0.1:%d\n" % self.server.server_port).encode())
        os.close(write_fd)

    def terminate(self):
        self.server.shutdown()
        self.server.server_close()
        self.stdout.close()

    def wait(self, timeout=None):
        self.thread.join(timeout)
        return 0


class ObserverTests(unittest.TestCase):
    def test_delete_sends_real_uid_precondition_and_scope_to_http_api(self):
        requests = []
        proxy = Proxy(200, "pod-uid", requests)
        with mock.patch("benchmark.stage.observe.subprocess.Popen", return_value=proxy) as launch:
            receipt = Kube("explicit-stage-context").delete_uid("phorvex-staging-demo", "stage-bench-pod", "pod-uid")
        self.assertTrue(receipt["acknowledged"])
        self.assertEqual(requests[0][0], "/api/v1/namespaces/phorvex-staging-demo/pods/stage-bench-pod")
        self.assertEqual(requests[0][1]["preconditions"], {"uid": "pod-uid"})
        self.assertEqual(requests[0][1]["gracePeriodSeconds"], 30)
        self.assertEqual(launch.call_args[0][0][:3], ["kubectl", "--context", "explicit-stage-context"])
        self.assertIn("--address=127.0.0.1", launch.call_args[0][0])

    def test_conflict_or_different_success_uid_is_never_acknowledgement(self):
        for status, returned_uid in ((409, "replacement-uid"), (200, "replacement-uid")):
            with self.subTest(status=status):
                requests = []
                proxy = Proxy(status, returned_uid, requests)
                with mock.patch("benchmark.stage.observe.subprocess.Popen", return_value=proxy):
                    receipt = Kube("stage-context").delete_uid("phorvex-staging-demo", "pod", "original-uid")
                self.assertFalse(receipt["acknowledged"])
                self.assertEqual(requests[0][1]["preconditions"]["uid"], "original-uid")

    def test_discovery_rejects_production_before_any_api_call(self):
        kube = mock.Mock()
        with self.assertRaisesRegex(EvidenceError, "stage namespace"):
            discover(kube, "production", "p", "d", "s", "a" * 40, "sha256:" + "b" * 64)
        kube.get.assert_not_called()

    def test_all_watch_routes_are_namespaced_and_exactly_filtered(self):
        paths = resource_paths(scope())
        self.assertEqual(set(paths), set(STREAMS))
        for path in paths.values():
            self.assertIn("/namespaces/phorvex-staging-demo/", path)
            self.assertTrue("labelSelector=" in path or "fieldSelector=" in path)

    def test_raw_watch_failure_records_gap_and_no_automatic_relist(self):
        objects = inventory()
        class Process:
            def __init__(self):
                self.stdout = io.BytesIO(json.dumps({"type": "ERROR", "object": {"code": 410, "reason": "Expired"}}).encode() + b"\n")
                self.stderr = io.BytesIO()
            def poll(self): return 0
            def wait(self, timeout=None): return 0
        class Client:
            def __init__(self): self.reads = 0
            def get(self, path):
                self.reads += 1
                stream = next(k for k, v in resource_paths(scope()).items() if v == path)
                return {"metadata": {"resourceVersion": "1"}, "items": objects[stream]}
            def watch(self, path, rv, seconds): return Process()
        client = Client()
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(Path(directory) / "evidence.db", scope())
            try:
                with mock.patch("benchmark.stage.observe.Kube", return_value=client), self.assertRaisesRegex(EvidenceError, "410"):
                    collect(journal, 1)
                records = list(journal.records())
                self.assertTrue(any(r["kind"] == "gap" and "410" in r["data"]["reason"] for r in records))
                self.assertEqual(sum(r["kind"] == "session" for r in records), 1)
                self.assertLessEqual(client.reads, len(STREAMS))
            finally:
                journal.close()

    def test_long_window_does_not_force_hourly_disconnect(self):
        with mock.patch("benchmark.stage.observe.subprocess.Popen") as launch:
            Kube("stage-context").watch("/api/v1/namespaces/stage/pods?labelSelector=app%3Dfixture", "123", 31 * 86400)
        arguments = launch.call_args[0][0]
        self.assertIn("timeoutSeconds=2678460", arguments[-2])
        self.assertEqual(arguments[-1], "--request-timeout=0")


if __name__ == "__main__":
    unittest.main()
