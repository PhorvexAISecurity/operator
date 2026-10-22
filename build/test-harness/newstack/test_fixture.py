"""Local contract tests; never contacts Kubernetes or a provider."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class FixtureContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("owned_fixture", Path(__file__).with_name("fixture.py"))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.guard = Path(self.directory.name) / "denied.json"
        self.module.GUARD = str(self.guard)
        self.module.POD_UID = "owned-pod-uid"
        self.server = self.module.ThreadingHTTPServer(("127.0.0.1", 0), self.module.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def request(self, path, value=None):
        request = Request(self.base + path, data=None if value is None else json.dumps(value).encode(),
                          headers={"Content-Type": "application/json"})
        try:
            response = urlopen(request, timeout=2)
        except HTTPError as response:
            return response.code, json.loads(response.read())
        with response:
            return response.status, json.loads(response.read())

    def test_real_cross_record_refund_then_projected_exact_revoke_and_legitimate_control(self):
        self.guard.write_text('{"denied_order_ids":[]}', encoding="utf-8")
        status, owner = self.request("/orders/by-phone?phone=%2B15551230002")
        self.assertEqual(status, 200)
        self.assertEqual(owner["account_id"], "AC-1002")
        self.assertEqual(owner["orders"], [{"order_id": "OR-5002", "account_id": "AC-1002"}])
        abuse = {"order_id": "OR-5002", "amount": 0.01, "reason": "cross-record caller AC-1001"}
        status, first = self.request("/refunds", abuse)
        self.assertEqual(status, 200)
        self.assertEqual(first["status"], "issued")
        self.assertTrue(first["refund_id"].startswith("RF-"))
        self.guard.write_text('{"denied_order_ids":["OR-5002"]}', encoding="utf-8")
        self.assertEqual(self.request("/phorvex-guard/state"), (200, {"denied_order_ids": ["OR-5002"]}))
        self.assertEqual(self.request("/refunds", abuse)[0], 403)
        status, legitimate = self.request("/refunds", {**abuse, "order_id": "OR-5001"})
        self.assertEqual(status, 200)
        self.assertEqual(legitimate["order_id"], "OR-5001")

    def test_marker_is_exact_pod_process_state(self):
        self.assertEqual(self.request("/health"), (200, {"ok": True, "pod_uid": "owned-pod-uid"}))
        self.assertEqual(self.request("/foothold")[1]["markers"], [])
        self.assertEqual(self.request("/foothold", {"marker": "owned-run"})[0], 200)
        self.assertEqual(self.request("/foothold")[1], {"pod_uid": "owned-pod-uid", "markers": ["owned-run"]})
        spec = importlib.util.spec_from_file_location("fresh_incarnation", Path(__file__).with_name("fixture.py"))
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)
        self.assertEqual(fresh.MARKERS, set())

    def test_malformed_guard_refuses_refunds_and_bounded_body(self):
        self.guard.write_text('{"denied_order_ids":[],"unexpected":true}', encoding="utf-8")
        self.assertEqual(self.request("/refunds", {"order_id": "OR-5002", "amount": 0.01})[0], 503)
        self.assertEqual(self.request("/foothold", {"marker": "x" * 129})[0], 400)
        self.assertEqual(self.request("/refunds", {"order_id": "OR-5002", "amount": 5})[0], 400)


if __name__ == "__main__":
    unittest.main()
