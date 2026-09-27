"""Exact Voice refund denial policy and replacement-Pod continuity checks."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from voice_memory_policy import (PolicyError, VoiceRefundPolicy, canonical_bytes,
                                 parse_refund_rule)


DEPLOYMENT_UID = "11111111-1111-4111-8111-111111111111"
POLICY_UID = "22222222-2222-4222-8222-222222222222"
POD_UID = "33333333-3333-4333-8333-333333333333"
SOURCE_SHA = "a" * 64
OP = "b" * 64


def entry(caller: str, order: str, operation: str = OP) -> dict:
    return {"assertedCallerSHA256": hashlib.sha256(caller.encode()).hexdigest(),
            "orderSHA256": hashlib.sha256(order.encode()).hexdigest(), "operationId": operation}


def rule(revision: int = 0, entries: list | None = None, operation: str = "") -> dict:
    return {"version": 1, "deploymentUID": DEPLOYMENT_UID, "policyUID": POLICY_UID,
            "sourceSHA256": SOURCE_SHA, "revision": revision, "operationId": operation,
            "entries": [] if entries is None else entries}


class VoiceRefundPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy_dir = self.root / "policy"
        self.policy_dir.mkdir()
        self.state_dir = self.root / "state"
        self.policy = VoiceRefundPolicy(self.policy_dir, self.state_dir, SOURCE_SHA, POD_UID, required=True)

    def write(self, value: dict) -> None:
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(value))

    def test_exact_pair_denial_and_unrelated_traffic(self):
        self.assertFalse(self.policy.allow_refund("+15551230001", "9142"))
        self.assertEqual(self.policy.state()[0], 503)
        self.write(rule())
        self.assertTrue(self.policy.allow_refund("+15551230001", "9142"))
        denied = entry("+15551230001", "9142")
        self.write(rule(1, [denied], OP))
        self.assertFalse(self.policy.allow_refund("+15551230001", "9142"))
        self.assertTrue(self.policy.allow_refund("+15551230001", "9141"))
        self.assertTrue(self.policy.allow_refund("+15551230002", "9142"))
        status, state = self.policy.state()
        self.assertEqual(status, 200)
        self.assertEqual(state["entryCount"], 1)
        self.assertEqual(state["ruleSHA256"], hashlib.sha256(canonical_bytes(rule(1, [denied], OP))).hexdigest())
        self.assertNotIn("+15551230001", str(state))

    def test_missing_corrupt_replay_and_append_only_fail_closed(self):
        first = entry("+15551230001", "9142")
        self.write(rule(1, [first], OP))
        self.assertEqual(self.policy.state()[0], 200)
        (self.policy_dir / "rule.json").unlink()
        self.assertFalse(self.policy.allow_refund("+15551230003", "9141"))
        self.write(rule())
        self.assertEqual(self.policy.state()[0], 503)
        next_op = "c" * 64
        second = entry("+15551230003", "9142", next_op)
        self.write(rule(2, sorted([second], key=lambda e: (e["assertedCallerSHA256"], e["orderSHA256"])), next_op))
        self.assertEqual(self.policy.state()[0], 503)
        self.write(rule(2, sorted([first, second], key=lambda e: (e["assertedCallerSHA256"], e["orderSHA256"])), next_op))
        self.assertEqual(self.policy.state()[0], 200)
        self.assertFalse(self.policy.allow_refund("+15551230003", "9142"))
        replacement = VoiceRefundPolicy(self.policy_dir, self.root / "replacement", SOURCE_SHA, POD_UID, required=True)
        self.assertFalse(replacement.allow_refund("+15551230001", "9142"))
        (self.policy_dir / "rule.json").unlink()
        self.assertFalse(replacement.allow_refund("+15551230004", "9141"))

    def test_decision_distinguishes_exact_pair_from_missing_corrupt_or_stale_rule(self):
        caller, order = "+15551230001", "9142"
        self.assertEqual(self.policy.refund_decision(caller, order), "policy-unavailable")
        self.write(rule())
        self.assertEqual(self.policy.refund_decision(caller, order), "allow")
        self.write(rule(1, [entry(caller, order)], OP))
        self.assertEqual(self.policy.refund_decision(caller, order), "exact-pair-denied")
        (self.policy_dir / "rule.json").write_bytes(b"{bad")
        self.assertEqual(self.policy.refund_decision(caller, order), "policy-unavailable")
        self.write(rule())
        self.assertEqual(self.policy.refund_decision(caller, order), "policy-unavailable")
        self.write(rule(1, [entry(caller, order)], OP))
        self.assertEqual(self.policy.refund_decision(caller, order), "exact-pair-denied")

    def test_strict_canonical_schema_capacity_and_duplicates(self):
        base = canonical_bytes(rule())
        for raw in (base + b"\n", base.replace(b'"version":1', b'"version":1,"version":1'),
                    canonical_bytes({**rule(), "unknown": 1})):
            with self.assertRaises(PolicyError):
                parse_refund_rule(raw, SOURCE_SHA)
        with self.assertRaises(PolicyError):
            parse_refund_rule(base, "f" * 64)
        duplicate = entry("+15551230001", "9142")
        with self.assertRaises(PolicyError):
            parse_refund_rule(canonical_bytes(rule(2, [duplicate], OP)), SOURCE_SHA)
        with self.assertRaises(PolicyError):
            parse_refund_rule(canonical_bytes(rule(1, [duplicate, duplicate], OP)), SOURCE_SHA)
        too_many = [entry(f"+1555{i:07d}", "9142") for i in range(257)]
        with self.assertRaises(PolicyError):
            parse_refund_rule(canonical_bytes(rule(1, too_many, OP)), SOURCE_SHA)


if __name__ == "__main__":
    unittest.main()
