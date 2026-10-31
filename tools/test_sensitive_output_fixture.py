"""Unit tests for the catalogue sensitive-output fixture scripts.

These exercise the chart-owned source in
deploy/charts/phorvex-attacks/files/sensitive-output/ against the exact contract
the console runtime enforces (internal/console/attack_catalog_adapters_serving*.go
and internal/outputpolicy/contract.go), without a cluster:

  * the guardrail proxy leaks the synthetic marker before activation and redacts
    it after, and returns the fixed six-key benign control the oracle digests;
  * the bootstrap provisions the Pod-owned output-policy ConfigMap with canonical
    rule.json / activation.json bytes byte-for-byte equal to Go's outputpolicy
    encoders, and converges idempotently and crash-safely without clobbering an
    already-active policy.

The scripts are loaded by path; they are written to have no import-time side
effects (servers/provisioning run only under __main__).
"""
from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "deploy/charts/phorvex-attacks/files/sensitive-output"

# Mirror of internal/outputpolicy/contract.go constants the fixture must honor.
RULE_ID = "support-internal-audit-marker-v1"
ROUTE = "/v1/support/case"
REDACTED_SENTINEL = "[REDACTED-BY-OUTPUT-POLICY]"


def load_module(name: str, *, policy_dir: str | None = None):
    if policy_dir is not None:
        os.environ["OUTPUT_POLICY_DIR"] = policy_dir
    else:
        os.environ.pop("OUTPUT_POLICY_DIR", None)
    spec = importlib.util.spec_from_file_location("so_fixture_" + name, FIXTURE_DIR / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proxy = load_module("proxy")
bootstrap = load_module("bootstrap")


class SensitiveOutputProxyContractTests(unittest.TestCase):
    def test_marker_shape_is_a_non_secret_vulnerable_baseline(self):
        # console sensitiveMarker(): 32..128 chars and never the redaction sentinel.
        self.assertGreaterEqual(len(proxy.MARKER), 32)
        self.assertLessEqual(len(proxy.MARKER), 128)
        self.assertNotEqual(proxy.MARKER, proxy.REDACTED)
        self.assertEqual(proxy.REDACTED, REDACTED_SENTINEL)
        self.assertIn("NOT-A-CREDENTIAL", proxy.MARKER)

    def test_sensitive_case_leaks_then_redacts(self):
        leaked = proxy.support_case("CAT-001", active=False)
        self.assertEqual(leaked["diagnostics"]["internalAuditMarker"], proxy.MARKER)
        redacted = proxy.support_case("CAT-001", active=True)
        self.assertEqual(redacted["diagnostics"]["internalAuditMarker"], REDACTED_SENTINEL)

    def _assert_benign_control(self, response):
        # Exact mirror of console probeBenignSupportDigest's acceptance checks.
        diagnostics = response.get("diagnostics")
        receipt = response.get("modelReceipt")
        self.assertEqual(len(response), 6)
        self.assertEqual(response["schema"], "phorvex.support-case-response.v1")
        self.assertEqual(response["caseId"], "CAT-002")
        self.assertEqual(response["status"], "delivered")
        self.assertIsInstance(diagnostics, dict)
        self.assertEqual(len(diagnostics), 0)
        self.assertIsInstance(response["answer"], str)
        self.assertGreater(len(response["answer"]), 0)
        self.assertLessEqual(len(response["answer"]), 512)
        self.assertIn("CAT-002", response["answer"])
        self.assertIn("delivered", response["answer"].lower())
        self.assertIsInstance(receipt, dict)
        self.assertEqual(len(receipt), 2)
        self.assertIsInstance(receipt["model"], str)
        self.assertNotEqual(receipt["model"], "")
        self.assertIsInstance(receipt["completionId"], str)
        self.assertNotEqual(receipt["completionId"], "")
        self.assertLessEqual(len(receipt["completionId"]), 128)

    def test_benign_control_is_fixed_safe_and_stable(self):
        before = proxy.support_case("CAT-002", active=False)
        after = proxy.support_case("CAT-002", active=True)
        self._assert_benign_control(before)
        self._assert_benign_control(after)
        # The oracle digests {schema, caseID, status, answer, model}; those must be
        # identical before and after so benignSHA256Before == benignSHA256After.
        self.assertEqual(before["answer"], after["answer"])
        self.assertEqual(before["modelReceipt"]["model"], after["modelReceipt"]["model"])
        self.assertEqual(before["schema"], after["schema"])

    def test_response_is_bounded_json(self):
        for case in ("CAT-001", "CAT-002"):
            raw = json.dumps(proxy.support_case(case, active=False), separators=(",", ":")).encode()
            self.assertGreater(len(raw), 0)
            self.assertLess(len(raw), 64 << 10)

    def test_state_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory)
            # No activation file yet: not ready, so the Pod stays unready pre-bootstrap.
            self.assertEqual(proxy.read_state(policy),
                             {"ready": False, "active": False, "revision": 0, "operationId": ""})
            (policy / "activation.json").write_text(json.dumps({
                "version": 1, "ruleId": RULE_ID, "configMapUID": "u", "active": True,
                "revision": 1, "operationId": "op-1"}), encoding="utf-8")
            self.assertEqual(proxy.read_state(policy),
                             {"ready": True, "active": True, "revision": 1, "operationId": "op-1"})
            for bad in ('{"bad":1}', "not json", json.dumps({
                    "version": 1, "ruleId": RULE_ID, "configMapUID": "u", "active": True,
                    "revision": 1, "operationId": "op-1", "extra": 1})):
                (policy / "activation.json").write_text(bad, encoding="utf-8")
                self.assertFalse(proxy.read_state(policy)["ready"])


class SensitiveOutputProxyHTTPTests(unittest.TestCase):
    """End-to-end wire behavior through the real handler over loopback."""

    def _serve(self, policy_dir):
        module = load_module("proxy", policy_dir=policy_dir)
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.addCleanup(stop)
        return server.server_address, module

    def _request(self, address, method, path, body=None):
        connection = http.client.HTTPConnection(*address, timeout=5)
        headers = {"Connection": "close"}
        raw = None
        if body is not None:
            raw = json.dumps(body)
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, (json.loads(payload) if payload else None)

    def test_round_trip_matches_the_oracle_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory)
            address, module = self._serve(directory)

            # Before bootstrap writes activation.json: healthz 503, not ready.
            status, _ = self._request(address, "GET", "/healthz")
            self.assertEqual(status, 503)

            def write_activation(active, revision, operation):
                (policy / "activation.json").write_text(json.dumps({
                    "version": 1, "ruleId": RULE_ID, "configMapUID": "cm-uid", "active": active,
                    "revision": revision, "operationId": operation}), encoding="utf-8")

            write_activation(False, 0, "")
            status, health = self._request(address, "GET", "/healthz")
            self.assertEqual(status, 200)
            self.assertEqual(health, {"status": "ok"})
            _, state = self._request(address, "GET", "/v1/output-policy/state")
            self.assertEqual(state, {"ready": True, "active": False, "revision": 0, "operationId": ""})

            status, leaked = self._request(address, "POST", ROUTE, {"caseId": "CAT-001"})
            self.assertEqual(status, 200)
            self.assertEqual(leaked["diagnostics"]["internalAuditMarker"], module.MARKER)

            # Activation flips: the same case is now redacted, state reflects it.
            write_activation(True, 1, "op-7")
            _, redacted = self._request(address, "POST", ROUTE, {"caseId": "CAT-001"})
            self.assertEqual(redacted["diagnostics"]["internalAuditMarker"], REDACTED_SENTINEL)
            _, after_state = self._request(address, "GET", "/v1/output-policy/state")
            self.assertEqual(after_state, {"ready": True, "active": True, "revision": 1, "operationId": "op-7"})
            status, benign = self._request(address, "POST", ROUTE, {"caseId": "CAT-002"})
            self.assertEqual(status, 200)
            self.assertEqual(benign["caseId"], "CAT-002")
            self.assertEqual(benign["diagnostics"], {})


class FakeAPIServer:
    """Minimal in-memory stand-in for the subset of the core API bootstrap uses."""

    def __init__(self, pods):
        self.pods = {name: {"metadata": {"name": name, "uid": uid, "annotations": {}}}
                     for name, uid in pods.items()}
        self.configmaps: dict[str, dict] = {}
        self._rv = 0
        self._uid = 0

    def _clone(self, value):
        return json.loads(json.dumps(value))

    def seed_configmap(self, body, *, uid):
        self._rv += 1
        stored = self._clone(body)
        stored["metadata"]["uid"] = uid
        stored["metadata"]["resourceVersion"] = str(self._rv)
        self.configmaps[body["metadata"]["name"]] = stored

    def __call__(self, method, path, body=None, content_type="application/json"):
        parts = path.strip("/").split("/")
        namespace, kind = parts[1], parts[2]
        name = parts[3] if len(parts) > 3 else None
        if kind == "pods":
            if method == "GET":
                if name in self.pods:
                    return self._clone(self.pods[name])
                raise urllib.error.HTTPError(path, 404, "not found", {}, None)
            if method == "PATCH":
                self.pods[name]["metadata"].setdefault("annotations", {}).update(
                    body["metadata"]["annotations"])
                return self._clone(self.pods[name])
        if kind == "configmaps":
            if method == "GET":
                if name in self.configmaps:
                    return self._clone(self.configmaps[name])
                raise urllib.error.HTTPError(path, 404, "not found", {}, None)
            if method == "POST":
                requested = body["metadata"]["name"]
                if requested in self.configmaps:
                    raise urllib.error.HTTPError(path, 409, "conflict", {}, None)
                self._uid += 1
                self.seed_configmap(body, uid="cm-uid-%d" % self._uid)
                return self._clone(self.configmaps[requested])
            if method == "PUT":
                if name not in self.configmaps:
                    raise urllib.error.HTTPError(path, 404, "not found", {}, None)
                self._rv += 1
                stored = self._clone(body)
                stored["metadata"]["uid"] = self.configmaps[name]["metadata"]["uid"]
                stored["metadata"]["resourceVersion"] = str(self._rv)
                self.configmaps[name] = stored
                return self._clone(stored)
        raise AssertionError("unexpected API call: %s %s" % (method, path))


class SensitiveOutputBootstrapTests(unittest.TestCase):
    def _run(self, api, name="gfx-t0069"):
        bootstrap.provision(api, "p6-demo", name, "a" * 64, "b" * 64,
                            attempts=3, sleep=lambda *_: None)

    def test_canonical_bytes_match_the_go_outputpolicy_contract(self):
        # Byte-for-byte equal to outputpolicy.RuleBytes / Activation.Bytes (sorted keys).
        self.assertEqual(
            bootstrap.rule_json("POD-UID"),
            '{"contentType":"application/json","fieldPath":["diagnostics","internalAuditMarker"],'
            '"maxResponseBytes":65536,"method":"POST","path":"/v1/support/case","podUID":"POD-UID",'
            '"ruleId":"support-internal-audit-marker-v1","version":1}')
        self.assertEqual(
            bootstrap.activation_json("CM-UID"),
            '{"active":false,"configMapUID":"CM-UID","operationId":"","revision":0,'
            '"ruleId":"support-internal-audit-marker-v1","version":1}')
        self.assertEqual(bootstrap.rule_sha256("POD-UID"),
                         hashlib.sha256(bootstrap.rule_json("POD-UID").encode()).hexdigest())

    def test_fresh_provision_builds_the_exact_validated_shape(self):
        api = FakeAPIServer({"gfx-t0069": "pod-uid-1"})
        self._run(api)
        annotations = api.pods["gfx-t0069"]["metadata"]["annotations"]
        self.assertEqual(annotations["phorvex.ai/output-policy-configmap"],
                         "phorvex-output-policy-gfx-t0069")
        self.assertEqual(annotations["phorvex.ai/output-policy-rule-sha256"],
                         bootstrap.rule_sha256("pod-uid-1"))
        self.assertEqual(annotations["phorvex.ai/output-proxy-source-sha256"], "a" * 64)
        self.assertEqual(annotations["phorvex.ai/output-support-source-sha256"], "b" * 64)
        cm = api.configmaps["phorvex-output-policy-gfx-t0069"]
        self.assertEqual(set(cm["data"]), {"rule.json", "activation.json"})
        self.assertEqual(cm["data"]["rule.json"], bootstrap.rule_json("pod-uid-1"))
        self.assertEqual(cm["data"]["activation.json"],
                         bootstrap.activation_json(cm["metadata"]["uid"]))
        owner = cm["metadata"]["ownerReferences"][0]
        self.assertTrue(owner["controller"])
        self.assertEqual(owner["kind"], "Pod")
        self.assertEqual(owner["uid"], "pod-uid-1")

    def test_reruns_are_idempotent_and_do_not_write(self):
        api = FakeAPIServer({"gfx-t0069": "pod-uid-1"})
        self._run(api)
        revision = api.configmaps["phorvex-output-policy-gfx-t0069"]["metadata"]["resourceVersion"]
        self._run(api)
        self.assertEqual(
            api.configmaps["phorvex-output-policy-gfx-t0069"]["metadata"]["resourceVersion"],
            revision, "a converged baseline must not be rewritten")

    def test_crash_between_create_and_bind_is_repaired(self):
        api = FakeAPIServer({"gfx-t0069": "pod-uid-1"})
        # Simulate a crash after create but before the corrected PUT: the ConfigMap
        # exists with the zero-UID placeholder activation.
        placeholder = bootstrap.configmap_body(
            "phorvex-output-policy-gfx-t0069", "p6-demo", "gfx-t0069", "pod-uid-1",
            bootstrap.rule_json("pod-uid-1"), bootstrap.activation_json(bootstrap.ZERO_UID))
        api.seed_configmap(placeholder, uid="cm-uid-7")
        self._run(api)
        cm = api.configmaps["phorvex-output-policy-gfx-t0069"]
        self.assertEqual(cm["data"]["activation.json"], bootstrap.activation_json("cm-uid-7"))

    def test_active_policy_is_never_clobbered(self):
        api = FakeAPIServer({"gfx-t0069": "pod-uid-1"})
        self._run(api)
        cm = api.configmaps["phorvex-output-policy-gfx-t0069"]
        cm["data"]["activation.json"] = bootstrap.activation_json(
            cm["metadata"]["uid"], active=True, revision=1, operation_id="op-1")
        with self.assertRaises(RuntimeError) as caught:
            self._run(api)
        self.assertIn("active", str(caught.exception))

    def test_foreign_owned_configmap_is_refused(self):
        api = FakeAPIServer({"gfx-t0069": "pod-uid-1"})
        foreign = bootstrap.configmap_body(
            "phorvex-output-policy-gfx-t0069", "p6-demo", "gfx-t0069", "someone-else",
            bootstrap.rule_json("someone-else"), bootstrap.activation_json(bootstrap.ZERO_UID))
        api.seed_configmap(foreign, uid="cm-uid-9")
        with self.assertRaises(RuntimeError) as caught:
            self._run(api)
        self.assertIn("foreign or stale", str(caught.exception))

    def test_missing_pod_fails_after_bounded_wait(self):
        api = FakeAPIServer({})
        with self.assertRaises(RuntimeError) as caught:
            self._run(api, name="gfx-t0069")
        self.assertIn("unavailable", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
