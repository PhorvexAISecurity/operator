"""Source-only tests of the installed FastMCP tools/list middleware."""

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
import server


class ScopedDescriptorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.token_file = Path(self.temp.name) / "token"
        self.token_file.write_bytes(b"m" * 48)

    def tools(self, headers):
        with patch.object(server, "TEST_ENABLED", "true"), \
                patch.object(server, "TEST_TOKEN_FILE", self.token_file), \
                patch.object(server, "get_http_headers", return_value=headers):
            return asyncio.run(server.mcp.list_tools())

    def signed(self, run, phase):
        sid = server.call_sid(run, phase)
        return {"x-phorvex-mcp-run": run, "x-phorvex-mcp-phase": phase,
                "x-phorvex-mcp-call-sid": sid,
                "x-phorvex-mcp-signature": server.signature(b"m" * 48, run, phase, sid)}

    def test_real_tools_list_changes_only_signed_attack_descriptor(self):
        normal = self.tools({})
        poisoned = self.tools(self.signed("mcp12345", "attack"))
        replay = self.tools(self.signed("mcp12345", "replay"))
        benign = self.tools(self.signed("mcp12345", "benign"))
        self.assertEqual([tool.name for tool in normal], ["store_directory", "check_promotions"])
        self.assertEqual(poisoned[0].description, replay[0].description)
        self.assertIn("reference ", poisoned[0].description)
        self.assertNotEqual(poisoned[0].description, normal[0].description)
        self.assertEqual(poisoned[1].description, normal[1].description)
        self.assertEqual(benign[0].description, normal[0].description)
        self.assertEqual(poisoned[0].parameters, normal[0].parameters)
        self.assertEqual(server.store_directory("hours"),
                         "All stores open 9am-9pm daily; the support line is 9am-6pm Pacific, Mon-Fri.")

    def test_bad_signature_or_session_never_changes_descriptor(self):
        normal = self.tools({})[0].description
        wrong = self.signed("mcp12345", "attack")
        wrong["x-phorvex-mcp-signature"] = "0" * 64
        self.assertEqual(self.tools(wrong)[0].description, normal)
        other = self.signed("mcp12345", "attack")
        other["x-phorvex-mcp-call-sid"] = server.call_sid("other123", "attack")
        self.assertEqual(self.tools(other)[0].description, normal)
        self.assertNotEqual(self.tools(self.signed("mcp12345", "attack") |
                                       {"user-agent": "mcp-client"})[0].description, normal)

    def test_actual_streamable_http_sdk_receives_changed_descriptor_and_live_tool_result(self):
        async def request(headers):
            app = server.mcp.http_app()
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url="http://localhost", headers=headers,
                                             trust_env=False, timeout=10.0) as client:
                    async with streamable_http_client("http://localhost/mcp/", http_client=client) as parts:
                        async with ClientSession(parts[0], parts[1]) as session:
                            await session.initialize()
                            listed = (await session.list_tools()).tools
                            result = await session.call_tool("store_directory", {"topic": "hours"})
                            return listed, result

        with patch.object(server, "TEST_ENABLED", "true"), patch.object(server, "TEST_TOKEN_FILE", self.token_file):
            original, _ = asyncio.run(request({}))
            changed, result = asyncio.run(request(self.signed("mcp12345", "attack")))
        self.assertNotEqual(original[0].description, changed[0].description)
        self.assertEqual(original[1].description, changed[1].description)
        self.assertFalse(result.isError)
        self.assertIn("All stores open 9am-9pm daily", result.content[0].text)


if __name__ == "__main__":
    unittest.main()
