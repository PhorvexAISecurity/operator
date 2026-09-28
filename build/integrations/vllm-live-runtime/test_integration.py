import asyncio
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boundary = load("dual_server")
renderer = load("render")


class BoundaryTest(unittest.TestCase):
    def request(self, port, method, path, authorization=None, body=b""):
        seen = {}
        async def app(scope, receive, send):
            seen["authorization"] = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
            seen["body"] = (await receive()).get("body")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        headers = [] if authorization is None else [(b"authorization", authorization.encode())]
        emitted = []
        async def send(value):
            emitted.append(value)
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        scope = {"type": "http", "method": method, "path": path,
                 "server": ("127.0.0.1", port), "headers": headers}
        asyncio.run(boundary.ServingBoundary(app, "u" * 32, "a" * 32)(scope, receive, send))
        return emitted[0]["status"], seen

    def test_public_inference_uses_private_upstream_key(self):
        status, seen = self.request(8000, "POST", "/v1/chat/completions", "Bearer caller")
        self.assertEqual(status, 200)
        self.assertEqual(seen["authorization"], [b"Bearer " + b"u" * 32])

    def test_public_cannot_reach_raw_or_named_controls(self):
        for path in ("/reset_prefix_cache", "/v1/load_lora_adapter", "/v1/guardrail/reload", "/v1/kv/invalidate"):
            self.assertEqual(self.request(8000, "POST", path)[0], 404)

    def test_admin_auth_and_key_separation(self):
        self.assertEqual(self.request(8443, "POST", "/reset_prefix_cache")[0], 401)
        self.assertEqual(self.request(8443, "POST", "/reset_prefix_cache", "Bearer wrong")[0], 401)
        status, seen = self.request(8443, "POST", "/reset_prefix_cache", "Bearer " + "a" * 32)
        self.assertEqual(status, 200)
        self.assertEqual(seen["authorization"], [b"Bearer " + b"u" * 32])
        status, seen = self.request(8443, "POST", "/v1/guardrail/reload", "Bearer " + "a" * 32)
        self.assertEqual(status, 200)
        self.assertEqual(seen["authorization"], [b"Bearer " + b"a" * 32])

    def test_admin_body_bound_and_unknown_path(self):
        self.assertEqual(self.request(8443, "POST", "/v1/load_lora_adapter", "Bearer " + "a" * 32, b"x" * 65537)[0], 413)
        self.assertEqual(self.request(8443, "POST", "/arbitrary", "Bearer " + "a" * 32)[0], 404)

    def test_websocket_cannot_bypass_http_control_gate(self):
        emitted=[]
        async def app(*_):
            raise AssertionError("websocket reached unguarded app")
        async def receive():
            return {"type":"websocket.connect"}
        async def send(value):
            emitted.append(value)
        asyncio.run(boundary.ServingBoundary(app,"u"*32,"a"*32)(
            {"type":"websocket","path":"/reset_prefix_cache","server":("127.0.0.1",8000)},receive,send))
        self.assertEqual(emitted,[{"type":"websocket.close","code":1008}])


class RendererTest(unittest.TestCase):
    def fixture(self):
        dep = {"kind": "Deployment", "metadata": {"name": "vllm", "namespace": "vllm", "uid": "old"},
               "spec": {"selector": {"matchLabels": {"app": "vllm"}},
                        "template": {"metadata": {"labels": {"app": "vllm"}, "annotations": {}}, "spec": {
                   "containers": [{"name": "vllm", "image": renderer.LIVE_BASE_IMAGE,
                       "args": ["--model", "m", "--enable-lora", "--port", "8001"],
                       "env": [{"name": "VLLM_SERVER_DEV_MODE", "value": "1"},
                               {"name": "VLLM_ALLOW_RUNTIME_LORA_UPDATING", "value": "1"}],
                       "readinessProbe": {"httpGet": {"path": "/health", "port": 8001}, "periodSeconds": 10},
                       "startupProbe": {"httpGet": {"path": "/health", "port": 8001}},
                       "livenessProbe": {"httpGet": {"path": "/health", "port": 8001}}},
                       {"name": "guardrail", "command": ["sh", "-c", "pip install stuff && exec python /src/guardrail_proxy.py"],
                        "ports": [{"containerPort": 8000}], "volumeMounts": []}], "volumes": []}}}}
        cm = {"kind": "ConfigMap", "metadata": {"name": "guardrail-proxy", "namespace": "vllm"},
              "data": {"guardrail_proxy.py": "old"}}
        policy = {"metadata": {"namespace": "vllm", "name": "vllm-defense", "uid": "policy-uid"}}
        return dep, cm, policy

    def test_candidate_preserves_settings_and_binds_private_control(self):
        dep, cm, pol = self.fixture()
        original = copy.deepcopy(dep)
        with mock.patch.multiple(renderer, ORIGINAL_PROXY_SHA256=hashlib.sha256(b"old").hexdigest(),
                                 LEGACY_PROXY_SHA256=renderer.sha(renderer.PROXY.read_bytes()),
                                 LEGACY_DUAL_SHA256=renderer.sha(renderer.DUAL.read_bytes())):
            output = renderer.render(dep, cm, pol, renderer.PUBLISHED_IMAGE,
                                     "vllm-control", "vllm-serving-admin", "vllm-admin.vllm.svc")
        import json
        candidate = json.loads(output["deployment.candidate.json"])
        vllm, guard = candidate["spec"]["template"]["spec"]["containers"]
        self.assertEqual(original["spec"]["template"]["spec"]["containers"][0]["args"][:2], vllm["args"][:2])
        self.assertEqual(vllm["args"][-2:], ["--host", "127.0.0.1"])
        self.assertIn("exec", vllm["readinessProbe"])
        self.assertEqual(candidate["spec"]["template"]["metadata"]["annotations"]["phorvex.ai/serving-port"], "8443")
        self.assertEqual(candidate["spec"]["template"]["metadata"]["labels"]["phorvex.ai/lora-enabled"], "true")
        self.assertTrue(guard["command"][2].endswith("exec python /src/dual_server.py"))
        self.assertNotIn(b"admin-bearer-value", b"".join(output.values()))
        values = json.loads(output["values.overlay.yaml"])
        self.assertEqual(values["phorvex"]["phorvex"]["servingSecurity"]["bindings"][0]["policyUID"], "policy-uid")

    def test_refuses_unreviewed_source_or_missing_lora_capability(self):
        dep, cm, pol = self.fixture()
        image = renderer.PUBLISHED_IMAGE
        with self.assertRaises(ValueError):
            renderer.render(dep, cm, pol, image, "vllm-control", "vllm-serving-admin", "vllm-admin.vllm.svc")
        dep["spec"]["template"]["spec"]["containers"][0]["args"].remove("--enable-lora")
        with mock.patch.multiple(renderer, ORIGINAL_PROXY_SHA256=hashlib.sha256(b"old").hexdigest(),
                                 LEGACY_PROXY_SHA256=renderer.sha(renderer.PROXY.read_bytes()),
                                 LEGACY_DUAL_SHA256=renderer.sha(renderer.DUAL.read_bytes())), self.assertRaises(ValueError):
            renderer.render(dep, cm, pol, image, "vllm-control", "vllm-serving-admin", "vllm-admin.vllm.svc")


if __name__ == "__main__":
    unittest.main()


class AdminServiceTest(RendererTest):
    """The admin surface is only reachable if something routes its DNS name to its port.

    Without the Service, every serving-effect operation opened a receipt, failed to dial
    server_name, and stayed non-terminal in "dispatching" -- which then blocked the next
    operation on that domain for good and left one more stuck receipt per rollout.
    """

    def render_ok(self, dep, cm, pol, server="vllm-admin.vllm.svc"):
        with mock.patch.multiple(renderer, ORIGINAL_PROXY_SHA256=hashlib.sha256(b"old").hexdigest(),
                                 LEGACY_PROXY_SHA256=renderer.sha(renderer.PROXY.read_bytes()),
                                 LEGACY_DUAL_SHA256=renderer.sha(renderer.DUAL.read_bytes())):
            return renderer.render(dep, cm, pol, renderer.PUBLISHED_IMAGE,
                                   "vllm-control", "vllm-serving-admin", server)

    def test_publishes_an_admin_service_that_reaches_the_guardrail_port(self):
        import json
        dep, cm, pol = self.fixture()
        output = self.render_ok(dep, cm, pol)
        self.assertIn("service.candidate.json", output)
        svc = json.loads(output["service.candidate.json"])
        self.assertEqual(svc["kind"], "Service")
        # the name the serving binding dials and the certificate is issued for
        self.assertEqual(svc["metadata"]["name"], "vllm-admin")
        self.assertEqual(svc["metadata"]["namespace"], "vllm")
        contract = json.loads(output["secret-contract.json"])
        self.assertEqual(contract["certificateSAN"],
                         "%s.%s.svc" % (svc["metadata"]["name"], svc["metadata"]["namespace"]))
        # and it must land on the admin port the guardrail actually opened
        port = svc["spec"]["ports"][0]
        self.assertEqual(port["port"], 8443)
        self.assertEqual(port["targetPort"], "admin-tls")
        candidate = json.loads(output["deployment.candidate.json"])
        guard = candidate["spec"]["template"]["spec"]["containers"][1]
        self.assertIn({"name": "admin-tls", "containerPort": 8443, "protocol": "TCP"}, guard["ports"])
        # selecting exactly the pods this Deployment owns
        self.assertEqual(svc["spec"]["selector"], dep["spec"]["selector"]["matchLabels"])

    def test_refuses_a_server_name_outside_the_workload_namespace(self):
        dep, cm, pol = self.fixture()
        with self.assertRaises(ValueError):
            self.render_ok(dep, cm, pol, server="vllm-admin.other.svc")

    def test_refuses_to_publish_an_unbound_service(self):
        dep, cm, pol = self.fixture()
        dep["spec"].pop("selector", None)
        with self.assertRaises(ValueError):
            self.render_ok(dep, cm, pol)
