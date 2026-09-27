"""Synthetic round trip through actual Voice callback writer and bounded reader."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "voice-memory"))
from voice_memory_policy import VoiceMemoryPolicy
from tool_receipt import read_read_receipts, read_receipts


class ToolReceiptTest(unittest.TestCase):
    def test_private_refund_and_benign_read_receipts(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            state = root / "state"
            state.mkdir(mode=0o700)
            source = "a" * 64
            pod = "11111111-1111-4111-8111-111111111111"
            call = "CA-owned"
            caller = "+15551230001"
            writer = VoiceMemoryPolicy(root / "policy", state, source, pod)
            self.assertTrue(writer.record_refund_callback(call, caller, 0, "started", "9142", 100))
            self.assertTrue(writer.record_refund_callback(call, caller, 0, "crm-returned", "9142", 100,
                                                          {"status": "issued", "refund_id": "RF-aabbccdd",
                                                           "order_id": "9142"}))
            self.assertTrue(writer.record_refund_callback(call, caller, 1, "denied", "9142", 100,
                                                          denial_reason="refund-policy-denied"))
            self.assertTrue(writer.record_refund_callback(call, caller, 2, "denied", "9142", 100,
                                                          denial_reason="policy-unavailable"))
            self.assertTrue(writer.record_agency_read(call, caller, "list_orders", 0,
                                                      "started", caller))
            self.assertTrue(writer.record_agency_read(call, caller, "list_orders", 0,
                                                      "result-delivered", caller,
                                                      {"account_id": "VA-owned-A", "orders": [{"order_id": "9141"}]}))
            call_hash = hashlib.sha256(call.encode()).hexdigest()
            caller_hash = hashlib.sha256(caller.encode()).hexdigest()
            refunds = read_receipts(state, call_hash, caller_hash, pod, source)
            reads = read_read_receipts(state, call_hash, caller_hash, pod, source)
            self.assertEqual([row["stage"] for row in refunds], ["started", "crm-returned", "denied", "denied"])
            self.assertEqual([row["stage"] for row in reads], ["started", "result-delivered"])
            self.assertTrue(refunds[1]["crmIssued"])
            self.assertEqual(refunds[-2]["denialReason"], "refund-policy-denied")
            self.assertEqual(refunds[-1]["denialReason"], "policy-unavailable")
            for path in state.iterdir():
                raw = path.read_text()
                for secret in (call, caller, "9142", "RF-aabbccdd", "VA-owned-A"):
                    self.assertNotIn(secret, raw)
            with self.assertRaises(ValueError):
                read_receipts(state, call_hash, "b" * 64, pod, source)


if __name__ == "__main__":
    unittest.main()
