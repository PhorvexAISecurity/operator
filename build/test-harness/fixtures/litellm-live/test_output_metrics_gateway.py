import hashlib
import hmac
import http.client
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SOURCE = Path(__file__).with_name("gateway_metrics.py")
spec = importlib.util.spec_from_file_location("litellm_output_gateway", SOURCE)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class Model(BaseHTTPRequestHandler):
    requests = []
    extra_secret = False
    last_response = b""
    fail = False

    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append(request)
        if self.headers.get("Authorization") != "Bearer sk-real-master-in-test":
            self.send_error(401)
            return
        system = request["messages"][0]["content"]
        match = re.search(r"PHX-(?:DOC|PROMPT)-[0-9a-f]{64}", system)
        protected = match.group() if match else ""
        if type(self).fail:
            body = json.dumps({"error": {"message": "upstream failed " + protected}}).encode()
            self.send_response(503)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        public = "Case CAT-042 is delivered" if protected.startswith("PHX-DOC-") else "Two plus two is four"
        reply = {"object": "chat.completion", "id": "cmpl-from-model",
                 "model": "gpt-4o-mini", "choices": [{"message": {
                     "role": "assistant", "content": public + "; private text " + protected}}],
                 "usage": {"prompt_tokens": 20, "completion_tokens": 12, "total_tokens": 32}}
        if type(self).extra_secret:
            reply["extra"] = protected
        body = json.dumps(reply).encode()
        type(self).last_response = body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OutputGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.trial = b"owned-trial-seed-for-output-tests-0001"
        trial_file = root / "trial"
        trial_file.write_bytes(self.trial)
        clients = root / "clients"
        clients.write_text(json.dumps({"version": 2, "seedSHA256": gateway.sha(self.trial),
                                      "modelAlias": "gpt-4o-mini"}))
        self.client_policy = root / "client-policy"
        self.client_policy.write_text('{"entries":[],"revision":0,"version":2}')
        self.output_policy = root / "output-policy"
        self.set_output([])
        self.sources = {"d": {"seed": b"private-document-seed-32-bytes-000001", "uid": "doc-uid"},
                        "p": {"seed": b"private-prompt-seed-32-bytes-0000001", "uid": "prompt-uid"}}
        Model.requests = []
        Model.extra_secret = False
        Model.fail = False
        self.model = ThreadingHTTPServer(("127.0.0.1", 0), Model)
        threading.Thread(target=self.model.serve_forever, daemon=True).start()
        self.addCleanup(self.model.server_close)
        self.addCleanup(self.model.shutdown)
        self.accounted = threading.Event()
        accounted = self.accounted
        class OutputMetrics(gateway.RequestMetrics):
            def observe(self, *args):
                super().observe(*args)
                with self.lock:
                    if sum(value[0] for value in self.series.values()) == 4:
                        accounted.set()
        self.g = gateway.Gateway(clients, self.client_policy, trial_file,
                                 "sk-real-master-in-test", "pod-uid", "client-cm-uid",
                                 gateway.sha(SOURCE.read_bytes()), "private-status-bearer-32-chars-0001",
                                 upstream_port=self.model.server_address[1],
                                 output_policy_file=self.output_policy,
                                 output_sources=self.sources, service_uid="service-uid",
                                 deployment_uid="deploy-uid", output_config_map_uid="output-cm-uid",
                                 metrics=OutputMetrics("litellm", "litellm-output-fixture"))
        handler = type("OutputPublic", (gateway.PublicHandler,), {"gateway": self.g})
        self.public = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.public.serve_forever, daemon=True).start()
        self.addCleanup(self.public.server_close)
        self.addCleanup(self.public.shutdown)

    def set_output(self, entries):
        self.output_policy.write_text(json.dumps({"version": 2, "revision": len(entries),
                                                 "entries": entries},
                                                separators=(",", ":"), sort_keys=True))

    def token(self, role, nonce):
        mac = hmac.new(self.trial,
                       f"phorvex-litellm-output-v1:{nonce}:{role}".encode(),
                       hashlib.sha256).hexdigest()
        return f"sk-phx3-{role}-{nonce}-{mac}"

    def call(self, role, nonce):
        body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user",
                           "content": "Give the public answer and private text."}],
                           "max_tokens": 64, "temperature": 0, "stream": False}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.public.server_address[1], timeout=5)
        try:
            conn.request("POST", "/v1/chat/completions", body,
                         {"Authorization": "Bearer " + self.token(role, nonce)})
            response = conn.getresponse()
            return response.status, response.read(), body
        finally:
            conn.close()

    def entry(self, role, nonce, operation):
        objective = gateway.OUTPUT_OBJECTIVES[role]
        source = self.sources[role]
        protected = self.g.output_value(objective, nonce, source["seed"])
        entry = {"objectiveId": objective, "runNonce": nonce,
                 "protectedSHA256": gateway.sha(protected.encode()),
                 "sourceSHA256": self.g.source_sha256, "serviceUID": "service-uid",
                 "deploymentUID": "deploy-uid", "targetPodUID": "pod-uid",
                 "peerPodUID": "peer-uid", "contextSecretUID": source["uid"],
                 "contextSeedSHA256": gateway.sha(source["seed"]),
                 "operationId": operation}
        entry["ruleSHA256"] = gateway.sha(json.dumps(self.g.output_rule(entry),
                                                     separators=(",", ":"), sort_keys=True).encode())
        return entry

    def test_distinct_server_context_real_model_then_exact_filter(self):
        for role, nonce in (("d", "a" * 32), ("p", "b" * 32)):
            objective = gateway.OUTPUT_OBJECTIVES[role]
            protected = self.g.output_value(objective, nonce, self.sources[role]["seed"])
            status, raw, attacker_request = self.call(role, nonce)
            self.assertEqual(status, 200)
            self.assertNotIn(protected.encode(), attacker_request)
            self.assertIn(protected.encode(), raw)
            self.assertEqual(raw, Model.last_response)
            self.assertIn(protected, Model.requests[-1]["messages"][0]["content"])
            self.assertEqual(Model.requests[-1]["messages"][1]["role"], "user")
            entry = self.entry(role, nonce, "selected-" + role)
            current = json.loads(self.output_policy.read_text())["entries"]
            self.set_output(sorted(current + [entry], key=lambda x: (x["objectiveId"], x["runNonce"])))
            status, raw, _ = self.call(role, nonce)
            self.assertEqual(status, 200)
            self.assertNotIn(protected.encode(), raw)
            self.assertNotIn(protected, json.dumps(json.loads(raw)))
            self.assertIn(b"delivered" if role == "d" else b"four", raw)
            state = self.g.output_status(objective, nonce)
            self.assertEqual((state["active"], state["operationId"], state["counters"]["redactions"]),
                             (True, "selected-" + role, 1))
        self.assertEqual(len(Model.requests), 4)
        self.assertTrue(self.accounted.wait(3))
        self.assertEqual(sum(value[0] for value in self.g.metrics.series.values()), 4)
        text = self.g.metrics.exposition().decode()
        for private in ("PHX-DOC-", "PHX-PROMPT-", "selected-d", "selected-p", self.g.master_key):
            self.assertNotIn(private, text)

    def test_rollback_or_wrong_secret_refuses_without_forwarding(self):
        nonce = "c" * 32
        entry = self.entry("d", nonce, "selected")
        self.set_output([entry])
        self.assertEqual(self.call("d", nonce)[0], 200)
        self.set_output([])
        self.assertFalse(self.g.output_status(gateway.OUTPUT_OBJECTIVES["d"], nonce)["ready"])
        self.assertEqual(self.call("d", nonce)[0], 503)
        self.assertEqual(len(Model.requests), 1)

    def test_active_policy_fails_closed_when_another_field_leaks(self):
        nonce = "d" * 32
        self.set_output([self.entry("d", nonce, "selected")])
        Model.extra_secret = True
        status, raw, _ = self.call("d", nonce)
        self.assertEqual(status, 502)
        self.assertNotIn(self.g.output_value(gateway.OUTPUT_OBJECTIVES["d"], nonce,
                                              self.sources["d"]["seed"]).encode(), raw)
        self.assertEqual(self.g.output_status(gateway.OUTPUT_OBJECTIVES["d"], nonce)
                         ["counters"]["redactions"], 0)

    def test_active_policy_never_relays_upstream_error_content(self):
        nonce = "e" * 32
        self.set_output([self.entry("p", nonce, "selected")])
        Model.fail = True
        status, raw, _ = self.call("p", nonce)
        self.assertEqual(status, 502)
        protected = self.g.output_value(gateway.OUTPUT_OBJECTIVES["p"], nonce,
                                        self.sources["p"]["seed"])
        self.assertNotIn(protected.encode(), raw)
        self.assertEqual(self.g.output_status(gateway.OUTPUT_OBJECTIVES["p"], nonce)
                         ["counters"]["redactions"], 0)


if __name__ == "__main__":
    unittest.main()
