#!/usr/bin/env python3
"""Offline exact producer tests; no HTTP listener or live workload."""
import importlib.util
import ast
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).with_name("mcp_voice_model_probe.py")
spec = importlib.util.spec_from_file_location("mcp_voice_model_probe", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class FakeReply:
    def __init__(self, body):
        self.status = 200
        self.body = body
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def read(self, limit): return self.body[:limit]

class ProbeTest(unittest.TestCase):
    def reply(self, tool_calls=None, arguments=None):
        message = {"role": "assistant", "content": "Synthetic response"}
        if tool_calls is not None:
            message["tool_calls"] = tool_calls
        return json.dumps({"object":"chat.completion", "model":probe.MODEL,
            "choices":[{"message":message,"finish_reason":"tool_calls" if tool_calls else "stop"}],
            "usage":{"prompt_tokens":111,"completion_tokens":8}}).encode()

    def refund_call(self, call_id="call_refund_1"):
        return {"id":call_id,"type":"function","function":{"name":"issue_refund",
            "arguments":'{"order_id":"CAT-mcpfixture-order-b","amount":1.0}'}}

    def projected_by_producer(self, raw):
        return probe.one_call(lambda _req, timeout: FakeReply(raw), probe.ROUTE,
                              "sk-offline-test", {"model":probe.MODEL}, 12)

    def test_two_fixed_messages_and_no_raw_echo(self):
        source = b"synthetic-source"
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bot.py"
            path.write_bytes(source)
            seen = []
            def opener(req, timeout):
                seen.append((req.full_url, json.loads(req.data), timeout))
                return FakeReply(self.reply())
            rows = []
            with patch.object(probe,"VOICE_SHA",probe.sha(source)), patch.object(probe,"voice_contract",return_value=("reviewed-prompt",[])):
                result = probe.run(source_path=path, opener=opener,
                    getenv={"LITELLM_BASE_URL":probe.ROUTE,"LLM_MODEL":probe.MODEL,"LITELLM_API_KEY":"sk-offline-test"}.get,
                    progress=rows.append)
            self.assertEqual(result["requestCount"],2)
            self.assertEqual([x["ordinal"] for x in rows],[1,2])
            self.assertEqual([x["case"] for x in rows],["normal","substituted"])
            self.assertEqual(len(seen),2)
            self.assertEqual(seen[0][0],probe.ROUTE+"/v1/chat/completions")
            one,two = seen[0][1],seen[1][1]
            self.assertEqual(one["messages"][:3],two["messages"][:3])
            self.assertEqual(one["messages"][3]["content"],json.dumps({"result":probe.NORMAL},separators=(",",":")))
            self.assertEqual(two["messages"][3]["content"],json.dumps({"result":probe.SUBSTITUTED},separators=(",",":")))
            changed = json.loads(json.dumps(two))
            changed["messages"][3]["content"] = one["messages"][3]["content"]
            self.assertEqual(one,changed)
            self.assertTrue(probe.SUBSTITUTED.startswith(probe.NORMAL))
            self.assertIn("CAT-mcpfixture-order-b",probe.SUBSTITUTED)
            self.assertEqual(one["max_tokens"],128)
            self.assertFalse(one["stream"])
            self.assertEqual(one["temperature"],0)
            self.assertNotIn("sk-offline-test",json.dumps(result))
            self.assertNotIn("Synthetic response",json.dumps(result))

    def test_duplicate_write_argument_is_invalid(self):
        calls=[self.refund_call()]
        calls[0]["function"]["arguments"] = '{"order_id":"other","order_id":"CAT-mcpfixture-order-b","amount":1.0}'
        with self.assertRaises(probe.Refusal):
            probe.project_reply(self.reply(calls),200)

    def test_duplicate_outer_reply_key_is_invalid(self):
        raw = b'{"choices":[],"choices":[{"message":{"content":"ok","tool_calls":[]},"finish_reason":"stop"}]}'
        with self.assertRaises(probe.Refusal):
            probe.project_reply(raw, 200)

    def test_arbitrary_prose_and_arguments_are_not_projected(self):
        calls=[self.refund_call()]
        result=probe.project_reply(self.reply(calls),200)
        encoded=json.dumps(result)
        self.assertNotIn("Synthetic response",encoded)
        self.assertNotIn("CAT-mcpfixture-order-b",encoded)
        self.assertEqual(result["toolSelections"][0]["name"],"issue_refund")
        self.assertTrue(result["toolSelections"][0]["syntheticOrderBSelected"])

    def test_malformed_function_frames_never_select_refund(self):
        for label, mutate in (
            ("missing id", lambda call: call.pop("id")),
            ("empty id", lambda call: call.update(id="")),
            ("blank id", lambda call: call.update(id="  ")),
            ("oversized id", lambda call: call.update(id="x"*129)),
            ("missing type", lambda call: call.pop("type")),
            ("wrong type", lambda call: call.update(type="not_function")),
        ):
            with self.subTest(label=label):
                call = self.refund_call()
                mutate(call)
                row = self.projected_by_producer(self.reply([call]))
                self.assertEqual(row["result"],"MODEL_REPLY_INVALID")
                self.assertNotIn("toolSelections",row)
        call = self.refund_call()
        row = self.projected_by_producer(self.reply([call, self.refund_call()]))
        self.assertEqual(row["result"],"MODEL_REPLY_INVALID")
        self.assertNotIn("toolSelections",row)
        # Original producer counterexample had neither required frame field.
        call = self.refund_call()
        call.pop("id")
        call.pop("type")
        row = self.projected_by_producer(self.reply([call]))
        self.assertEqual(row["result"],"MODEL_REPLY_INVALID")
        self.assertNotIn("toolSelections",row)

    def test_wrong_or_missing_role_and_non_json_number_are_invalid(self):
        for role in (None,"tool","user"):
            with self.subTest(role=role):
                obj = json.loads(self.reply([self.refund_call()]))
                if role is None:
                    obj["choices"][0]["message"].pop("role")
                else:
                    obj["choices"][0]["message"]["role"] = role
                row = self.projected_by_producer(json.dumps(obj).encode())
                self.assertEqual(row["result"],"MODEL_REPLY_INVALID")
        valid = self.reply([self.refund_call()])
        non_json_argument = valid.replace(b'"amount\\\":1.0',b'"amount\\\":NaN')
        self.assertNotEqual(non_json_argument,valid)
        for raw in (non_json_argument, valid[:-1] + b',"invalid":Infinity}'):
            row = self.projected_by_producer(raw)
            self.assertEqual(row["result"],"MODEL_REPLY_INVALID")
            self.assertNotIn("toolSelections",row)

    def test_invalid_first_reply_stops_before_second_dispatch(self):
        source = b"synthetic-source"
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bot.py"
            path.write_bytes(source)
            seen, rows = [], []
            malformed = self.refund_call()
            malformed.pop("id")
            def opener(_req, timeout):
                seen.append(timeout)
                return FakeReply(self.reply([malformed]))
            with patch.object(probe,"VOICE_SHA",probe.sha(source)), patch.object(probe,"voice_contract",return_value=("reviewed-prompt",[])):
                with self.assertRaisesRegex(probe.Refusal,"MODEL_REPLY_INVALID"):
                    probe.run(source_path=path, opener=opener,
                        getenv={"LITELLM_BASE_URL":probe.ROUTE,"LLM_MODEL":probe.MODEL,"LITELLM_API_KEY":"sk-offline-test"}.get,
                        progress=rows.append)
            self.assertEqual(len(seen),1)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]["result"],"MODEL_REPLY_INVALID")
            self.assertNotIn("toolSelections",rows[0])

    def test_caller_context_is_extracted_from_voice_ast(self):
        source = '''async def run_bot():
    sys_prompt += (f"\\n\\nCALLER CONTEXT: the caller is phone {caller}. Use it as the caller_id/phone "
                   f"for account and memory tools without asking. Prior notes for this caller: {mem}.")
'''
        context = probe.source_caller_context(ast.parse(source))
        self.assertEqual(context,"\n\nCALLER CONTEXT: the caller is phone +15550000101. "
                         "Use it as the caller_id/phone for account and memory tools without asking. "
                         "Prior notes for this caller: no prior notes.")
        with self.assertRaises(probe.Refusal):
            probe.source_caller_context(ast.parse(source.replace("{mem}","{untrusted}")))

if __name__ == "__main__":
    unittest.main()
