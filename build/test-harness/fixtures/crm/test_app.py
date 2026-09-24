"""Local handler control: exact app.py with an in-memory Mongo API boundary."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from urllib.parse import urlsplit

import mongomock
import pymongo
from fastapi.testclient import TestClient


SOURCE = Path(__file__).with_name("app.py")
EXPECTED_SHA256 = "328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350"


def digest(document):
    clean = {key: value for key, value in document.items() if key != "_id"}
    return hashlib.sha256(json.dumps(clean, sort_keys=True).encode()).hexdigest()


class InstalledCRMHandlerTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), EXPECTED_SHA256)
        self.mongo = mongomock.MongoClient()
        with patch.object(pymongo, "MongoClient", return_value=self.mongo):
            spec = importlib.util.spec_from_file_location("crm_installed_fixture", SOURCE)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        self.module = module
        self.db = module._db
        self.a = {"account_id": "AC-SYN-A", "phone": "+15550000101", "name": "Fixture A", "tier": "standard"}
        self.b = {"account_id": "AC-SYN-B", "phone": "+15550000102", "name": "Fixture B", "tier": "standard"}
        self.order_a = {"order_id": "OR-SYN-A", "account_id": self.a["account_id"], "item": "synthetic-a", "amount": 1.0, "status": "delivered"}
        self.order_b = {"order_id": "OR-SYN-B", "account_id": self.b["account_id"], "item": "synthetic-b", "amount": 1.0, "status": "delivered"}
        self.db.accounts.insert_many([dict(self.a), dict(self.b)])
        self.db.orders.insert_many([dict(self.order_a), dict(self.order_b)])
        self.baseline = {key: digest(doc) for key, doc in (("a", self.a), ("b", self.b), ("oa", self.order_a), ("ob", self.order_b))}
        self.client = TestClient(module.app)

    def assert_baseline(self):
        docs = {"a": self.db.accounts.find_one({"account_id": self.a["account_id"]}),
                "b": self.db.accounts.find_one({"account_id": self.b["account_id"]}),
                "oa": self.db.orders.find_one({"order_id": self.order_a["order_id"]}),
                "ob": self.db.orders.find_one({"order_id": self.order_b["order_id"]})}
        self.assertEqual({key: digest(doc) for key, doc in docs.items()}, self.baseline)

    def test_actual_refund_handler_and_mongo_readback(self):
        account = self.client.get("/accounts/by-phone/%2B15550000101")
        orders = self.client.get("/orders/by-phone/%2B15550000101")
        self.assertEqual(account.status_code, 200)
        self.assertEqual(account.json()["account_id"], self.a["account_id"])
        self.assertEqual([x["order_id"] for x in orders.json()["orders"]], [self.order_a["order_id"]])
        appointment = self.client.post("/appointments", json={"phone": self.a["phone"], "date": "2030-01-01"})
        own = self.client.post("/refunds", json={"order_id": self.order_a["order_id"], "amount": 1.0})
        cross = self.client.post("/refunds", json={"order_id": self.order_b["order_id"], "amount": 1.0})
        self.assertEqual((appointment.status_code, own.status_code, cross.status_code), (200, 200, 200))
        self.assertEqual(self.db.appointments.count_documents({"appointment_id": appointment.json()["appointment_id"]}), 1)
        self.assertEqual(self.db.refunds.find_one({"refund_id": own.json()["refund_id"]})["order_id"], self.order_a["order_id"])
        self.assertEqual(self.db.refunds.find_one({"refund_id": cross.json()["refund_id"]})["order_id"], self.order_b["order_id"])
        self.assert_baseline()

    def test_actual_reset_handler_and_mongo_readback(self):
        own = self.client.post("/password-resets", json={"phone": self.a["phone"]})
        cross = self.client.post("/password-resets", json={"phone": self.b["phone"]})
        self.assertEqual((own.status_code, cross.status_code), (200, 200))
        records_a = list(self.db.resets.find({"phone": self.a["phone"]}))
        records_b = list(self.db.resets.find({"phone": self.b["phone"]}))
        self.assertEqual((len(records_a), len(records_b)), (1, 1))
        self.assertNotEqual(records_a[0]["_id"], records_b[0]["_id"])
        self.assertEqual((records_a[0]["account_id"], records_b[0]["account_id"]), (self.a["account_id"], self.b["account_id"]))
        self.assert_baseline()

    def test_probe_seed_http_and_independent_mongo_receipts(self):
        # Exercise the source-real probe phases without opening a network socket.
        # The boundary replacement is only TestClient transport and MongoClient.
        self.db.accounts.delete_many({})
        self.db.orders.delete_many({})
        probe_spec = importlib.util.spec_from_file_location("crm_fixture_probe", SOURCE.with_name("probe.py"))
        probe = importlib.util.module_from_spec(probe_spec)
        probe_spec.loader.exec_module(probe)

        class Response:
            def __init__(self, response):
                self.status = response.status_code
                self.body = io.BytesIO(response.content)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, size):
                return self.body.read(size)

        def open_request(request, timeout):
            self.assertEqual(urlsplit(request.full_url).netloc, "127.0.0.1:8080")
            path = urlsplit(request.full_url).path
            response = self.client.request(request.get_method(), path, content=request.data,
                                           headers=dict(request.header_items()))
            return Response(response)

        def phase(name, case, run, *ids):
            output = io.StringIO()
            with redirect_stdout(output), patch.object(probe, "MongoClient", return_value=self.mongo), \
                 patch.object(probe.OPENER, "open", side_effect=open_request):
                probe.main(["probe.py", name, case, run, *ids])
            return json.loads(output.getvalue())

        run = "abcdef0123456789"
        seed = phase("seed", "refund", run)
        execution = phase("execute", "refund", run)
        observation = phase("observe", "refund", run, execution["own_refund_id"], execution["cross_refund_id"])
        self.assertEqual(execution["cross_status"], 200)
        self.assertEqual((observation["own_exact_count"], observation["cross_exact_count"], observation["appointment_exact_count"]), (1, 1, 1))
        self.assertEqual(seed["baseline_hashes"], observation["baseline_hashes"])

        # Reset uses a fresh Mongo instance to preserve exact one-record IDs.
        self.mongo = mongomock.MongoClient()
        self.db = self.mongo["crm"]
        self.module._db = self.db
        seed = phase("seed", "reset", run)
        execution = phase("execute", "reset", run)
        observation = phase("observe", "reset", run, execution["own_reset_account_id"], execution["cross_reset_account_id"])
        self.assertEqual(execution["cross_status"], 200)
        self.assertEqual((observation["own_exact_count"], observation["cross_exact_count"]), (1, 1))
        self.assertTrue(observation["own_created_id"] and observation["cross_created_id"])
        self.assertEqual(seed["baseline_hashes"], observation["baseline_hashes"])

    def test_refund_response_denied_after_handler_write_is_db_observed(self):
        self.db.accounts.delete_many({})
        self.db.orders.delete_many({})
        probe_spec = importlib.util.spec_from_file_location("crm_fixture_probe_denied", SOURCE.with_name("probe.py"))
        probe = importlib.util.module_from_spec(probe_spec)
        probe_spec.loader.exec_module(probe)

        class Response:
            def __init__(self, response):
                self.status = response.status_code
                self.body = io.BytesIO(response.content)
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, size):
                return self.body.read(size)

        def open_request(request, timeout):
            self.assertEqual(urlsplit(request.full_url).netloc, "127.0.0.1:8080")
            response = self.client.request(request.get_method(), urlsplit(request.full_url).path,
                                           content=request.data, headers=dict(request.header_items()))
            return Response(response)

        original_request = probe.request
        def denied_after_write(method, path, body=None):
            status, response = original_request(method, path, body)
            if path == "/refunds" and body.get("order_id", "").endswith("order-b"):
                self.assertEqual(status, 200)  # The real handler wrote first.
                return 403, {}
            return status, response

        def phase(name, *ids, deny=False):
            output = io.StringIO()
            with redirect_stdout(output), patch.object(probe, "MongoClient", return_value=self.mongo), \
                 patch.object(probe.OPENER, "open", side_effect=open_request):
                if deny:
                    with patch.object(probe, "request", side_effect=denied_after_write):
                        probe.main(["probe.py", name, "refund", "abcdef0123456789", *ids])
                else:
                    probe.main(["probe.py", name, "refund", "abcdef0123456789", *ids])
            return json.loads(output.getvalue())

        seed = phase("seed")
        execution = phase("execute", deny=True)
        self.assertEqual(execution["cross_status"], 403)
        self.assertIsNone(execution["cross_refund_id"])
        observed = phase("observe", execution["own_refund_id"], "-")
        self.assertEqual(observed["cross_exact_count"], 1)
        self.assertEqual(observed["cross_order_id"], seed["order_ids"][1])
        self.assertTrue(observed["cross_created_id"])
        self.assertEqual(observed["baseline_hashes"], seed["baseline_hashes"])
        with self.assertRaisesRegex(RuntimeError, "response ID differs"):
            phase("observe", execution["own_refund_id"], "RF-mismatched")
        self.db.refunds.insert_one({"refund_id": "RF-duplicate", "order_id": seed["order_ids"][1],
                                    "amount": 1.0, "reason": "synthetic-cross-control"})
        with self.assertRaisesRegex(RuntimeError, "cardinality is inconclusive"):
            phase("observe", execution["own_refund_id"], "-")



if __name__ == "__main__":
    unittest.main()
