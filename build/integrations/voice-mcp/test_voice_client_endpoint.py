"""Real installed Voice SDK against the published MCP server dependency set.

Run with mcp==2.1.1 and httpx==0.28.1, setting VOICE_MCP_SERVER_PYTHON to
the Python 3.11 FastMCP 3.4.7 server environment. Uses loopback only.
"""

import asyncio
import hashlib
import hmac
from importlib import metadata
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

import httpx
from mcp import ClientSession
from mcp.client import streamable_http


SERVER_PYTHON = os.environ.get("VOICE_MCP_SERVER_PYTHON")
VOICE_SDK = metadata.version("mcp") == "2.1.1" and metadata.version("httpx") == "0.28.1"
SOURCE_SHA = "6cc73f8ec7d270bf30433a85c5b05a6384afdd08d543368c54187f94840e04e5"


@unittest.skipUnless(SERVER_PYTHON and VOICE_SDK, "requires installed Voice SDK and separate published server environment")
class VoiceCanonicalEndpointTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(hashlib.sha256(inspect.getsource(streamable_http).encode()).hexdigest(), SOURCE_SHA)
        versions = subprocess.check_output([SERVER_PYTHON, "-c", "import json; from importlib import metadata; "
                                           "print(json.dumps({p:metadata.version(p) for p in ['fastmcp','mcp','httpx']}))"], text=True)
        self.assertEqual(json.loads(versions), {"fastmcp": "3.4.7", "mcp": "1.30.0", "httpx": "0.28.1"})
        self.assertEqual(hashlib.sha256((Path(__file__).parent / "server.py").read_bytes()).hexdigest(),
                         "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.token = b"m" * 48
        token_file = Path(self.temp.name) / "token"
        token_file.write_bytes(self.token)
        token_file.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        self.log_path = Path(self.temp.name) / "server.log"
        self.log = self.log_path.open("w+")
        self.addCleanup(self.log.close)
        environment = os.environ | {"PORT": str(port), "VOICE_MCP_TEST_ENABLED": "true",
                                    "VOICE_MCP_TEST_TOKEN_FILE": str(token_file)}
        command = [SERVER_PYTHON, "-B", "-c", "import os,server; server.mcp.run(transport='http', "
                   "host='127.0.0.1',port=int(os.environ['PORT']),show_banner=False)"]
        self.server = subprocess.Popen(command, cwd=Path(__file__).parent, env=environment,
                                       stdout=self.log, stderr=subprocess.STDOUT)
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("server exited: " + self.log_path.read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        self.fail("local published MCP server did not start")

    def stop_server(self):
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)

    def retain_evidence(self, requests, responses):
        destination = os.environ.get("VOICE_MCP_ENDPOINT_EVIDENCE_DIR")
        if destination:
            self.stop_server()
            directory = Path(destination)
            directory.mkdir(parents=True, exist_ok=True)
            evidence = {"client": {"mcp": "2.1.1", "httpx": "0.28.1", "sourceSHA256": SOURCE_SHA},
                        "server": {"fastmcp": "3.4.7", "mcp": "1.30.0", "httpx": "0.28.1"},
                        "requests": [(method, path, sorted(headers)) for method, path, headers in requests],
                        "responses": responses, "serverLog": self.log_path.read_text()}
            with os.fdopen(os.open(directory / (self._testMethodName + ".json"),
                                   os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
                json.dump(evidence, out, indent=2)
                out.write("\n")

    def signed(self):
        run, phase = "mcp12345", "attack"
        sid = "CA" + hashlib.sha256(f"voice-mcp:{run}:{phase}".encode()).hexdigest()[:32].upper()
        signature = hmac.new(self.token, f"voice-mcp-descriptor-v1:{run}:{phase}:{sid}".encode(), hashlib.sha256).hexdigest()
        return {"x-phorvex-mcp-run": run, "x-phorvex-mcp-phase": phase,
                "x-phorvex-mcp-call-sid": sid, "x-phorvex-mcp-signature": signature}

    async def request(self, path, headers=None, requests=None, responses=None):
        async def requested(request):
            if requests is not None:
                requests.append((request.method, request.url.path,
                                 set(key for key in request.headers if key.startswith("x-phorvex-"))))
        async def responded(response):
            if responses is not None:
                responses.append((response.request.url.path, response.status_code))
        async def session(stream):
            async with stream as parts:
                async with ClientSession(parts[0], parts[1]) as client:
                    await client.initialize()
                    tools = (await client.list_tools()).tools
                    result = await client.call_tool("store_directory", {"topic": "hours"})
                    return tools, result
        if headers is None:
            return await session(streamable_http.streamable_http_client(self.origin + path))
        # Exact signed client settings from unchanged installed bot.py.
        async with httpx.AsyncClient(headers=headers, timeout=10.0, trust_env=False, follow_redirects=False,
                                     event_hooks={"request": [requested], "response": [responded]}) as client:
            return await session(streamable_http.streamable_http_client(self.origin + path, http_client=client))

    def test_ordinary_and_signed_canonical_receive_real_descriptors_and_tool_result(self):
        ordinary, result = asyncio.run(self.request("/mcp"))
        requests, responses = [], []
        signed, signed_result = asyncio.run(self.request("/mcp", self.signed(), requests, responses))
        self.assertEqual({tool.name for tool in ordinary}, {"store_directory", "check_promotions"})
        self.assertNotEqual(ordinary[0].description, signed[0].description)
        nonce = hashlib.sha256(b"voice-mcp-nonce:mcp12345").hexdigest()[:12].upper()
        self.assertIn(nonce, signed[0].description)
        self.assertEqual(ordinary[1].description, signed[1].description)
        for reply in (result, signed_result):
            self.assertFalse(reply.is_error)
            self.assertIn("All stores open 9am-9pm daily", reply.content[0].text)
        self.assertTrue(requests)
        self.assertTrue(all(path == "/mcp" for _, path, _ in requests))
        self.assertTrue(all(status not in (307, 308) for _, status in responses))
        self.retain_evidence(requests, responses)

    def test_signed_trailing_slash_307_refused_without_forwarding_headers(self):
        requests, responses = [], []
        with self.assertRaises(Exception):
            asyncio.run(self.request("/mcp/", self.signed(), requests, responses))
        self.assertEqual([(method, path) for method, path, _ in requests], [("POST", "/mcp/")])
        self.assertEqual(requests[0][2], set(self.signed()))
        self.assertEqual(responses, [("/mcp/", 307)])
        self.stop_server()  # flush access log before verifying server saw no redirected request
        log = self.log_path.read_text()
        self.assertEqual(log.count('"POST /mcp/ HTTP/1.1" 307'), 1)
        self.assertNotIn('"POST /mcp HTTP/', log)
        self.assertNotIn('"GET /mcp HTTP/', log)
        self.retain_evidence(requests, responses)


if __name__ == "__main__":
    unittest.main()
