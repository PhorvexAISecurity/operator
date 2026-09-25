#!/usr/bin/env python3
"""Offline exact producer tests; no HTTP listener or live workload."""
import importlib.util
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
            self.assertEqual(one["max_tokens"],128)
            self.assertFalse(one["stream"])
            self.assertEqual(one["temperature"],0)
            self.assertNotIn("sk-offline-test",json.dumps(result))
            self.assertNotIn("Synthetic response",json.dumps(result))

    def test_duplicate_write_argument_is_invalid(self):
        calls=[{"function":{"name":"issue_refund","arguments":'{"order_id":"other","order_id":"CAT-mcpfixture-order-b","amount":1.0}'}}]
        with self.assertRaises(probe.Refusal):
            probe.project_reply(self.reply(calls),200)

    def test_duplicate_outer_reply_key_is_invalid(self):
        raw = b'{"choices":[],"choices":[{"message":{"content":"ok","tool_calls":[]},"finish_reason":"stop"}]}'
        with self.assertRaises(probe.Refusal):
            probe.project_reply(raw, 200)

    def test_arbitrary_prose_and_arguments_are_not_projected(self):
        calls=[{"function":{"name":"issue_refund","arguments":'{"order_id":"CAT-mcpfixture-order-b","amount":1.0}'}}]
        result=probe.project_reply(self.reply(calls),200)
        encoded=json.dumps(result)
        self.assertNotIn("Synthetic response",encoded)
        self.assertNotIn("CAT-mcpfixture-order-b",encoded)
        self.assertEqual(result["toolSelections"][0]["name"],"issue_refund")
        self.assertTrue(result["toolSelections"][0]["syntheticOrderBSelected"])

if __name__ == "__main__":
    unittest.main()
