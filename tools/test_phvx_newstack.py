"""Offline driver failure/recovery contracts; never contacts SSH or Kubernetes."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("phvx_newstack", Path(__file__).with_name("phvx-newstack.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
CASE = "newstack:voice-rotate"
CATALOG = {"schema": "newstack-catalog-v1", "namespace": DRIVER.NAMESPACE, "enabled": True,
           "fireEndpoint": "/api/newstack/fire", "items": [{"id": CASE}]}
RUN = {"schema": "newstack-run-v1", "namespace": DRIVER.NAMESPACE, "caseId": CASE,
       "runId": "ns-" + "a" * 32, "verdict": "DEFENDED", "cleanupComplete": True, "postflightClean": True}


class DriverTests(unittest.TestCase):
    def run_driver(self, argv, responder, snapshot_effect=None):
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(DRIVER, "snapshot", side_effect=snapshot_effect, return_value={"items": []}))
            stack.enter_context(patch.object(DRIVER, "deployment_gates", return_value=[]))
            stack.enter_context(patch.object(DRIVER, "cleanup_deployment_gates", return_value=[]))
            stack.enter_context(patch.object(DRIVER, "token_for", return_value="test-short-lived-token"))
            stack.enter_context(patch.object(DRIVER, "console_connection", return_value=contextlib.nullcontext(("unused", "token"))))
            calls = stack.enter_context(patch.object(DRIVER, "api", side_effect=responder))
            stack.enter_context(contextlib.redirect_stdout(output))
            code = DRIVER.main(argv)
        return code, json.loads(output.getvalue()), calls

    def response(self, connection, route, payload=None, **kwargs):
        if route.endswith("/catalog"):
            return dict(CATALOG)
        if "/check?" in route:
            return {"ok": True, "caseId": CASE}
        if route.endswith("/cleanup"):
            return {"ok": True, "cleanupComplete": True}
        if route.endswith("/fire"):
            return dict(RUN)
        raise AssertionError(route)

    def test_exact_defended_result_is_preserved_after_clean_reconcile(self):
        code, result, calls = self.run_driver(["fire", CASE], self.response)
        self.assertEqual(code, 0)
        self.assertEqual(result["verdict"], "DEFENDED")
        self.assertEqual(result["runId"], RUN["runId"])
        self.assertEqual([c.args[1].split("?")[0] for c in calls.call_args_list],
                         ["/api/newstack/catalog", "/api/newstack/check", "/api/newstack/fire", "/api/newstack/cleanup"])

    def test_transport_error_still_cleans_postflights_and_saves_evidence(self):
        def broken(connection, route, payload=None, **kwargs):
            if route.endswith("/fire"):
                raise TimeoutError("lost fire response")
            return self.response(connection, route, payload, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            code, result, _ = self.run_driver(["--output", str(path), "fire", CASE], broken)
            self.assertEqual(code, 2)
            self.assertEqual(result["verdict"], "ERROR")
            self.assertEqual(result["clientError"], "lost fire response")
            self.assertTrue(result["cleanupReconcile"]["cleanupComplete"])
            self.assertEqual(result["clientPostflightIssues"], [])
            self.assertEqual(json.loads(path.read_text()), result)

    def test_interruption_runs_cleanup_and_does_not_earn_defense(self):
        def interrupted(connection, route, payload=None, **kwargs):
            if route.endswith("/fire"):
                raise KeyboardInterrupt()
            return self.response(connection, route, payload, **kwargs)
        code, result, _ = self.run_driver(["fire", CASE], interrupted)
        self.assertEqual(code, 2)
        self.assertEqual(result["verdict"], "ERROR")
        self.assertTrue(result["cleanupReconcile"]["cleanupComplete"])

    def test_postflight_failure_does_not_discard_obtained_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            code, result, _ = self.run_driver(["--output", str(path), "fire", CASE], self.response,
                                             snapshot_effect=[{"items": []}, RuntimeError("postflight API down")])
            self.assertEqual(code, 2)
            self.assertEqual(result["runId"], RUN["runId"])
            self.assertEqual(result["clientPostflightIssues"], ["postflight API down"])
            self.assertTrue(path.exists())

    def test_negative_authenticated_check_has_nonzero_exit(self):
        def denied(connection, route, payload=None, **kwargs):
            if "/check?" in route:
                return {"ok": False, "caseId": CASE}
            return self.response(connection, route, payload, **kwargs)
        code, result, _ = self.run_driver(["check", CASE], denied)
        self.assertEqual(code, 2)
        self.assertIn("console admission check failed", result["issues"])

    def test_wrong_catalog_is_refused_before_any_mutating_route(self):
        def wrong(connection, route, payload=None, **kwargs):
            if route.endswith("/catalog"):
                return {**CATALOG, "namespace": "unrelated"}
            raise AssertionError("must not call " + route)
        code, result, calls = self.run_driver(["fire", CASE], wrong)
        self.assertEqual(code, 2)
        self.assertEqual(len(calls.call_args_list), 1)
        self.assertIn("catalogue", result["clientError"])

    def test_mismatched_run_cannot_supply_defended(self):
        def wrong(connection, route, payload=None, **kwargs):
            if route.endswith("/fire"):
                return {**RUN, "caseId": "newstack:litellm-rotate"}
            return self.response(connection, route, payload, **kwargs)
        code, result, _ = self.run_driver(["fire", CASE], wrong)
        self.assertEqual(code, 2)
        self.assertEqual(result["verdict"], "ERROR")

    def test_cleanup_works_without_a_healthy_brain(self):
        only_recovery = {"items": [{"metadata": {"name": name}, "status": {"readyReplicas": 1},
                                    "spec": {"template": {"spec": {"containers": [{"name": "service", "env": []}]}}}}
                                    for name in (DRIVER.SERVICE, "staging-attacks")]}
        self.assertEqual(DRIVER.cleanup_deployment_gates(only_recovery), [])
        self.assertTrue(DRIVER.deployment_gates(only_recovery))
        code, result, _ = self.run_driver(["cleanup", CASE], self.response)
        self.assertEqual(code, 0)
        self.assertEqual(result["verdict"], "CLEAN")

    def test_default_cleanup_selects_the_actual_lane_case(self):
        crm = "newstack:crm-refund-revoke"
        with patch.object(DRIVER, "kube_json", return_value={"items": [{"data": {"caseId": crm}}]}):
            code, _, calls = self.run_driver(["cleanup"], self.response)
        self.assertEqual(code, 0)
        self.assertEqual(calls.call_args.args[2], {"caseId": crm})

    def test_no_lane_cleanup_checks_every_fixture_for_orphans(self):
        with patch.object(DRIVER, "kube_json", return_value={"items": []}):
            code, result, calls = self.run_driver(["cleanup"], self.response)
        self.assertEqual(code, 0)
        self.assertEqual([call.args[2]["caseId"] for call in calls.call_args_list], list(DRIVER.CASES))
        self.assertEqual(len(result["cleanup"]), 3)

    def test_claimed_defense_with_failed_cleanup_has_nonzero_exit(self):
        def bad(connection, route, payload=None, **kwargs):
            if route.endswith("/cleanup"):
                return {"cleanupComplete": False}
            return self.response(connection, route, payload, **kwargs)
        code, result, _ = self.run_driver(["fire", CASE], bad)
        self.assertEqual(code, 2)
        self.assertTrue(result["clientCleanupErrors"])


if __name__ == "__main__":
    unittest.main()
