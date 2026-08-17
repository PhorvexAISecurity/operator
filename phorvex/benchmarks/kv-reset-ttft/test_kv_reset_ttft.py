import importlib.util
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("kv_reset_ttft.py")
SPEC = importlib.util.spec_from_file_location("kv_reset_ttft", MODULE_PATH)
BENCH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BENCH
SPEC.loader.exec_module(BENCH)


class FakeVLLMHandler(BaseHTTPRequestHandler):
    completions = 0
    resets = 0
    cold = False

    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        if self.path != "/v1/models":
            self.send_error(404)
            return
        self._json({"data": [{"id": "test-model"}]})

    def do_POST(self):
        if self.path == "/reset_prefix_cache":
            type(self).resets += 1
            type(self).cold = True
            self._json(True)
            return
        if self.path != "/v1/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        if payload.get("stream") is not True or payload.get("max_tokens") != 1:
            self.send_error(400)
            return
        type(self).completions += 1
        delay = 0.025 if type(self).cold else 0.001
        type(self).cold = False
        time.sleep(delay)
        body = b'data: {"choices":[{"text":"x"}]}\n\ndata: [DONE]\n\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, body):
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class BenchmarkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FakeVLLMHandler.completions = 0
        FakeVLLMHandler.resets = 0
        FakeVLLMHandler.cold = False
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeVLLMHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def test_paired_protocol_and_model_discovery(self):
        self.assertEqual(BENCH.discover_model(self.base_url, 2), "test-model")
        samples = BENCH.run_benchmark(
            base_url=self.base_url,
            model="test-model",
            prompt="stable prefix",
            sample_count=3,
            timeout=2,
            settle_seconds=0,
        )
        self.assertEqual(FakeVLLMHandler.completions, 9)
        self.assertEqual(FakeVLLMHandler.resets, 3)
        self.assertTrue(all(sample.penalty_ms > 10 for sample in samples))

    def test_summary_is_paired_and_deterministic(self):
        samples = [
            BENCH.PairedSample(1, 10, 12, 2),
            BENCH.PairedSample(2, 11, 16, 5),
            BENCH.PairedSample(3, 9, 18, 9),
            BENCH.PairedSample(4, 10, 22, 12),
        ]
        got = BENCH.summarize(samples)
        self.assertEqual(got["paired_penalty_ms"]["median"], 7)
        self.assertEqual(got["paired_penalty_ms"]["p95"], 12)
        self.assertEqual(got["paired_penalty_ms"]["positive_pairs"], 4)
        low, high = got["paired_penalty_ms"]["median_bootstrap_95pct_ci"]
        self.assertLessEqual(low, 7)
        self.assertGreaterEqual(high, 7)


if __name__ == "__main__":
    unittest.main()
