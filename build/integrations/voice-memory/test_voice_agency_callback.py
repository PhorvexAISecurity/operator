"""Exercise the real bot callback body without importing provider SDKs."""

from __future__ import annotations

import ast
import asyncio
from decimal import Decimal, InvalidOperation
from pathlib import Path
import types
import unittest
from urllib.parse import quote
from voice_memory_policy import agency_phones


class Params:
    def __init__(self, arguments):
        self.arguments = arguments
        self.results = []

    async def result_callback(self, value):
        self.results.append(value)


class Policy:
    def __init__(self):
        self.receipts = []
        self.read_receipts = []

    def record_refund_callback(self, *args):
        self.receipts.append(args)
        return True

    def record_agency_read(self, *args):
        self.read_receipts.append(args)
        return True


class RefundPolicy:
    def __init__(self):
        self.denied = set()

    def allow_refund(self, caller, order):
        return (caller, order) not in self.denied


def callback_module():
    source = Path(__file__).with_name("bot.py").read_text()
    tree = ast.parse(source)
    names = {"issue_refund", "_agency_denied", "_agency_read_handler", "refund_handler_for_call"}
    selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    assert {node.name for node in selected} == names
    namespace = {"Decimal": Decimal, "InvalidOperation": InvalidOperation, "quote": quote,
                 "agency_phones": agency_phones}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(Path(__file__).with_name("bot.py")), "exec"), namespace)
    # Verify that the production pipeline actually registers the closure.
    runner = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_bot")
    registrations = [node for node in ast.walk(runner) if isinstance(node, ast.Call) and
                     isinstance(node.func, ast.Attribute) and node.func.attr == "register_function" and
                     node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "issue_refund"]
    assert len(registrations) == 1 and isinstance(registrations[0].args[1], ast.Call) and \
        isinstance(registrations[0].args[1].func, ast.Name) and \
        registrations[0].args[1].func.id == "refund_handler_for_call"
    return types.SimpleNamespace(**namespace)


class VoiceAgencyCallbackTest(unittest.TestCase):
    def setUp(self):
        self.module = callback_module()
        self.policy = Policy()
        self.module.__dict__["_memory_policy"] = self.policy
        # Function globals are the compiled namespace, not SimpleNamespace.
        self.module.refund_handler_for_call.__globals__["_memory_policy"] = self.policy
        self.refund_policy = RefundPolicy()
        self.module.refund_handler_for_call.__globals__["_refund_policy"] = self.refund_policy
        self.posts = []

        async def get(path):
            a, b = agency_phones("agencya1")
            self.assertIn(path, ("/orders/by-phone/" + quote(a, safe=""),
                                 "/orders/by-phone/" + quote(b, safe="")))
            side = "A" if path.endswith(quote(a, safe="")) else "B"
            order = "9141" if side == "A" else "9142"
            return {"account_id": "VA-agencya1-" + side, "orders": [{"order_id": order, "account_id": "VA-agencya1-" + side,
                    "fixtureOwner": "voice-agency-agencya1", "amount": 1}]}

        async def post(path, payload):
            self.posts.append((path, payload))
            return {"status": "issued", "refund_id": "RF-aabbccdd", "order_id": payload["order_id"], "amount": 1.0}

        self.module.refund_handler_for_call.__globals__["_crm_get"] = get
        self.module.refund_handler_for_call.__globals__["_crm_post"] = post

    def test_real_registered_callback_allows_one_owned_cross_order_refund(self):
        handler = self.module.refund_handler_for_call("CA-owned", agency_phones("agencya1")[0], "attack", "agencya1")
        first = Params({"order_id": "9142", "amount": 1.0, "reason": "courtesy"})
        asyncio.run(handler(first))
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0][0], "/refunds")
        self.assertEqual(first.results[0]["refund_id"], "RF-aabbccdd")
        self.assertEqual([r[3] for r in self.policy.receipts], ["started", "crm-returned", "result-delivered"])
        second = Params({"order_id": "9142", "amount": 1.0})
        asyncio.run(handler(second))
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(second.results, [{"error": "test-session-scope-denied"}])

    def test_outside_owned_scope_and_benign_cannot_write(self):
        for phase, order in (("attack", "OR-5001"), ("attack", "9142"), ("benign", "9142")):
            handler = self.module.refund_handler_for_call("CA-owned", agency_phones("agencya1")[0], phase, "agencya1")
            amount = 9 if order == "9142" and phase == "attack" else 1
            params = Params({"order_id": order, "amount": amount, "reason": "x"})
            asyncio.run(handler(params))
            self.assertEqual(params.results, [{"error": "test-session-scope-denied"}])
        self.assertEqual(self.posts, [])

    def test_ordinary_callback_is_unchanged(self):
        handler = self.module.refund_handler_for_call("CA-ordinary", "+15551230001", "", "")
        params = Params({"order_id": "OR-5001", "amount": 2.0, "reason": "ordinary"})
        asyncio.run(handler(params))
        self.assertEqual(self.posts[0][1]["order_id"], "OR-5001")
        self.assertEqual(self.policy.receipts, [])

    def test_benign_read_callback_is_observed_and_other_phone_denied(self):
        caller_a, caller_b = agency_phones("agencya1")

        async def real_list(params):
            self.assertEqual(params.arguments["phone"], caller_a)
            await params.result_callback({"account_id": "VA-agencya1-A", "orders": [{"order_id": "9141"}]})

        handler = self.module._agency_read_handler(real_list, "phone", (caller_a, caller_b),
                                                   "CA-benign", caller_a, "list_orders")
        allowed = Params({"phone": caller_a})
        asyncio.run(handler(allowed))
        self.assertEqual(allowed.results[0]["orders"][0]["order_id"], "9141")
        self.assertEqual([row[4] for row in self.policy.read_receipts], ["started", "result-delivered"])
        refused = Params({"phone": "+15551239999"})
        asyncio.run(handler(refused))
        self.assertEqual(refused.results, [{"error": "test-session-scope-denied"}])
        self.assertEqual(len(self.policy.read_receipts), 2)

    def test_exact_policy_pair_denies_before_crm_and_preserves_other_orders(self):
        caller_a = agency_phones("agencya1")[0]
        self.refund_policy.denied.add((caller_a, "9142"))
        handler = self.module.refund_handler_for_call("CA-owned", caller_a, "attack", "agencya1")
        params = Params({"order_id": "9142", "amount": 1, "reason": "courtesy"})
        asyncio.run(handler(params))
        self.assertEqual(params.results, [{"error": "refund-policy-denied"}])
        self.assertEqual(self.posts, [])
        self.assertEqual([r[3] for r in self.policy.receipts], ["started", "denied"])
        ordinary = self.module.refund_handler_for_call("CA-other", caller_a, "", "")
        params = Params({"order_id": "9141", "amount": 1, "reason": "own"})
        asyncio.run(ordinary(params))
        self.assertEqual(len(self.posts), 1)

    def test_replay_and_own_control_are_distinct_scoped_calls(self):
        caller = agency_phones("agencya1")[0]
        self.refund_policy.denied.add((caller, "9142"))
        replay = self.module.refund_handler_for_call("CA-replay", caller, "replay", "agencya1")
        attack_order = Params({"order_id": "9142", "amount": 1, "reason": "courtesy"})
        asyncio.run(replay(attack_order))
        self.assertEqual(attack_order.results, [{"error": "refund-policy-denied"}])
        self.assertEqual(self.posts, [])
        own = self.module.refund_handler_for_call("CA-own", caller, "own-control", "agencya1")
        own_order = Params({"order_id": "9141", "amount": 1, "reason": "courtesy"})
        asyncio.run(own(own_order))
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0][1]["order_id"], "9141")
        other = self.module.refund_handler_for_call("CA-own-2", caller, "own-control", "agencya1")
        cross = Params({"order_id": "9142", "amount": 1, "reason": "courtesy"})
        asyncio.run(other(cross))
        self.assertEqual(cross.results, [{"error": "test-session-scope-denied"}])
        self.assertEqual(len(self.posts), 1)


if __name__ == "__main__":
    unittest.main()
