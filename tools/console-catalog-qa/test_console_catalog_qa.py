#!/usr/bin/env python3
"""Hermetic fake-HTTP tests for the resumable Console catalogue QA driver."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from urllib.parse import parse_qs, urlsplit


MODULE_PATH = Path(__file__).with_name("console_catalog_qa.py")
SPEC = importlib.util.spec_from_file_location("console_catalog_qa", MODULE_PATH)
qa = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = qa
SPEC.loader.exec_module(qa)


TOKEN = "test-token-value.0123456789"
IDS = [f"QA.ID.{number:03d}" for number in range(1, 193)]


def repository_catalog(path: Path, ids: list[str] | None = None) -> None:
    values = IDS if ids is None else ids
    path.write_text(json.dumps({
        "schema": "phorvex.attack-catalogue.v1",
        "count": 192,
        "entries": [{"id": value, "order": index} for index, value in enumerate(values, 1)],
    }), encoding="utf-8")


def status(run_id: str, catalogue_id: str, *, state: str = "done", cleanup: str = "verified", unsafe: bool = False) -> dict:
    return {
        "id": run_id,
        "config": catalogue_id,
        "state": state,
        "executionKind": "catalogue-validation",
        "outcome": "DEFENDED" if state == "done" else "",
        "cleanupStatus": cleanup,
        "unsafeToRetry": unsafe,
        "triggerMode": "reactive",
        "executionMode": "active",
    }


def strict_evidence(
    run_id: str,
    catalogue_id: str,
    *,
    cleanup_verified: bool = True,
    physical_validated: bool = True,
    receipt_observed: bool = True,
    verdict: str = "DEFENDED",
) -> dict:
    return {
        "id": run_id,
        "state": "done",
        "attackCatalogueResult": {
            "schema": "phorvex.attack-catalogue-result.v1",
            "catalogueID": catalogue_id,
            "runID": run_id,
            "triggerMode": "reactive",
            "executionMode": "active",
            "visible": True,
            "available": True,
            "launched": True,
            "reactiveOnly": True,
            "expectedAction": "identity-rotate",
            "verdict": verdict,
            "unsafeToRetry": not cleanup_verified,
            "signal": {
                "created": True,
                "observed": True,
                "uid": "signal-uid",
                "targetUID": "target-uid",
            },
            "decision": {
                "observed": True,
                "selected": True,
                "feasible": True,
                "action": "identity-rotate",
                "dispatchOutcome": "emitted",
            },
            "actuator": {
                "receiptObserved": receipt_observed,
                "handler": "identity-rotate",
                "objectsTouched": ["ServiceAccount/test"],
            },
            "physicalValidation": {
                "validated": physical_validated,
                "oldServiceAccountUID": "old-uid",
                "newServiceAccountUID": "new-uid" if physical_validated else "old-uid",
            },
            "cleanup": {
                "attempted": True,
                "eventDeleted": cleanup_verified,
                "markerDeleted": cleanup_verified,
                "verified": cleanup_verified,
            },
        },
        "prometheusEvidence": {
            "schema": "phorvex.prometheus-run-evidence.v1",
            "runID": run_id,
            "catalogueID": catalogue_id,
            "triggerMode": "reactive",
            "executionMode": "active",
            "status": "COMPLETE",
            "errors": [],
            "observedDecisionModes": ["reactive"],
            "metrics": [
                {
                    "key": "selected-action",
                    "deltas": [{
                        "labels": {"mode": "reactive"},
                        "finalPresent": True,
                        "delta": 1,
                        "counterReset": False,
                    }],
                },
                {
                    "key": "accepted-actuation",
                    "deltas": [{
                        "labels": {},
                        "finalPresent": True,
                        "delta": 1,
                        "counterReset": False,
                    }],
                },
            ],
        },
    }


class Scenario:
    def __init__(self) -> None:
        self.auth_failure = False
        self.available = {catalogue_id: True for catalogue_id in IDS}
        self.api_ids = list(IDS)
        self.launches: list[dict] = []
        self.stops: list[str] = []
        self.status_calls: dict[str, int] = {}
        self.evidence_calls: dict[str, int] = {}
        self.launch_hook = None
        self.status_hook = None
        self.evidence_hook = None
        self.stop_hook = None

    def catalog(self) -> dict:
        return {"items": [
            {
                "entryID": catalogue_id,
                "catalogueID": catalogue_id,
                "catalogueOrder": index,
                "launchKind": "catalogue-entry",
                "available": self.available.get(catalogue_id, True),
                "unavailableReason": "metadata only" if not self.available.get(catalogue_id, True) else "",
                "reactiveCompatible": True,
            }
            for index, catalogue_id in enumerate(self.api_ids, 1)
        ]}

    def launch(self, body: dict) -> tuple[int, dict]:
        self.launches.append(body)
        if self.launch_hook:
            return self.launch_hook(body, len(self.launches))
        return 200, {
            "id": f"run-{len(self.launches)}",
            "catalogueID": body["id"],
            "triggerMode": body.get("triggerMode"),
            "executionMode": body.get("executionMode"),
        }

    def run_status(self, run_id: str) -> tuple[int, dict]:
        count = self.status_calls.get(run_id, 0) + 1
        self.status_calls[run_id] = count
        if self.status_hook:
            return self.status_hook(run_id, count)
        return 200, status(run_id, IDS[0])

    def evidence(self, run_id: str) -> tuple[int, dict]:
        count = self.evidence_calls.get(run_id, 0) + 1
        self.evidence_calls[run_id] = count
        if self.evidence_hook:
            return self.evidence_hook(run_id, count)
        return 200, strict_evidence(run_id, IDS[0])

    def stop(self, run_id: str) -> tuple[int, dict]:
        self.stops.append(run_id)
        if self.stop_hook:
            return self.stop_hook(run_id, len(self.stops))
        return 200, {"id": run_id, "status": "stopping"}


class FakeConsole:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args) -> None:
                return

            def _send(self, status_code: int, body: dict) -> None:
                raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authorized(self) -> bool:
                if owner.scenario.auth_failure or self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._send(401, {"error": "unauthorized"})
                    return False
                return True

            def do_GET(self) -> None:
                if not self._authorized():
                    return
                parsed = urlsplit(self.path)
                if parsed.path == "/api/catalog":
                    self._send(200, owner.scenario.catalog())
                    return
                run_id = parse_qs(parsed.query).get("id", [""])[0]
                if parsed.path == "/api/runs/status":
                    code, body = owner.scenario.run_status(run_id)
                    self._send(code, body)
                    return
                if parsed.path == "/api/runs/evidence":
                    code, body = owner.scenario.evidence(run_id)
                    self._send(code, body)
                    return
                self._send(404, {"error": "not found"})

            def do_POST(self) -> None:
                if not self._authorized():
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/catalog/launch":
                    code, response = owner.scenario.launch(body)
                    self._send(code, response)
                    return
                if self.path == "/api/runs/stop":
                    code, response = owner.scenario.stop(body.get("id", ""))
                    self._send(code, response)
                    return
                self._send(404, {"error": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> "FakeConsole":
        self.thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


class DriverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.catalog = self.root / "catalog.json"
        repository_catalog(self.catalog)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(
        self,
        server: FakeConsole,
        output: Path,
        *extra: str,
        environ: dict[str, str] | None = None,
    ) -> int:
        argv = [
            "--base-url", server.url,
            "--catalog-file", str(self.catalog),
            "--output", str(output),
            "--id", IDS[0],
            "--request-timeout-seconds", "1",
            "--poll-interval-seconds", "0.01",
            "--timeout-seconds", "1",
            "--cancel-grace-seconds", "0.2",
            *extra,
        ]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return qa.main(argv, environ or {qa.TOKEN_ENV: TOKEN})

    def summary(self, output: Path) -> dict:
        return json.loads((output / "summary.json").read_text(encoding="utf-8"))

    def events(self, output: Path) -> list[dict]:
        return [json.loads(line) for line in (output / "attempts.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_auth_failure_fails_before_launch(self) -> None:
        scenario = Scenario()
        scenario.auth_failure = True
        output = self.root / "auth"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 1)
        self.assertEqual(scenario.launches, [])
        if (output / "attempts.jsonl").exists():
            retained = (output / "attempts.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(TOKEN, retained)

    def test_metadata_only_id_is_never_launched(self) -> None:
        scenario = Scenario()
        scenario.available[IDS[0]] = False
        output = self.root / "unavailable"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 2)
        self.assertEqual(scenario.launches, [])
        result = self.summary(output)["results"][0]
        self.assertEqual(result["localVerdict"], "UNAVAILABLE")

    def test_dry_run_with_fd_credential_makes_no_mutation(self) -> None:
        scenario = Scenario()
        output = self.root / "dry-run"
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, TOKEN.encode("ascii"))
            os.close(write_fd)
            write_fd = -1
            with FakeConsole(scenario) as server:
                self.assertEqual(
                    self.invoke(
                        server,
                        output,
                        "--dry-run",
                        environ={qa.TOKEN_FD_ENV: str(read_fd)},
                    ),
                    0,
                )
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
        self.assertEqual(scenario.launches, [])
        self.assertEqual(self.summary(output)["results"][0]["localVerdict"], "DRY_RUN")

    def test_repository_api_exact_set_mismatch_fails_before_launch(self) -> None:
        scenario = Scenario()
        scenario.api_ids[-1] = "QA.ID.WRONG"
        output = self.root / "catalog-mismatch"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 1)
        self.assertEqual(scenario.launches, [])

    def test_launch_exact_id_mismatch_is_stopped_and_never_passes(self) -> None:
        scenario = Scenario()

        def mismatch(body: dict, _count: int) -> tuple[int, dict]:
            return 200, {
                "id": "run-wrong",
                "catalogueID": IDS[1],
                "triggerMode": body["triggerMode"],
                "executionMode": body["executionMode"],
            }

        scenario.launch_hook = mismatch
        output = self.root / "id-mismatch"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 2)
        self.assertEqual(scenario.stops, ["run-wrong"])
        self.assertEqual(self.summary(output)["results"][0]["localVerdict"], "FAIL")

    def test_timeout_is_preserved_then_safe_retry_passes(self) -> None:
        scenario = Scenario()
        stopped: set[str] = set()

        def launch(body: dict, count: int) -> tuple[int, dict]:
            run_id = f"run-{count}"
            return 200, {
                "id": run_id,
                "catalogueID": body["id"],
                "triggerMode": body["triggerMode"],
                "executionMode": body["executionMode"],
            }

        def run_status(run_id: str, _count: int) -> tuple[int, dict]:
            if run_id == "run-1" and run_id not in stopped:
                return 200, status(run_id, IDS[0], state="running", cleanup="")
            if run_id == "run-1":
                return 200, status(run_id, IDS[0], state="stopped", cleanup="verified")
            return 200, status(run_id, IDS[0])

        def evidence(run_id: str, _count: int) -> tuple[int, dict]:
            value = strict_evidence(run_id, IDS[0])
            if run_id == "run-1":
                value["state"] = "stopped"
                value["attackCatalogueResult"]["verdict"] = "INCONCLUSIVE"
            return 200, value

        def stop(run_id: str, _count: int) -> tuple[int, dict]:
            stopped.add(run_id)
            return 200, {"id": run_id, "status": "stopping"}

        scenario.launch_hook = launch
        scenario.status_hook = run_status
        scenario.evidence_hook = evidence
        scenario.stop_hook = stop
        output = self.root / "timeout-resume"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output, "--timeout-seconds", "0.06"), 2)
            self.assertEqual(self.summary(output)["results"][0]["localVerdict"], "TIMEOUT")
            self.assertEqual(self.invoke(server, output), 0)
        self.assertEqual(len(scenario.launches), 2)
        summary = self.summary(output)
        self.assertEqual(summary["results"][0]["localVerdict"], "PASS")
        self.assertEqual(summary["results"][0]["attempts"], 2)
        finished = [event for event in self.events(output) if event["type"] == "attempt_finished"]
        self.assertEqual([event["localVerdict"] for event in finished], ["TIMEOUT", "PASS"])

    def test_unfinished_run_is_resumed_without_relaunch(self) -> None:
        scenario = Scenario()
        scenario.status_hook = lambda run_id, _count: (200, status(run_id, IDS[0]))
        scenario.evidence_hook = lambda run_id, _count: (200, strict_evidence(run_id, IDS[0]))
        output = self.root / "resume"
        output.mkdir()
        ledger = qa.StateLedger(output)
        ledger.record(
            "attempt_started",
            catalogueID=IDS[0],
            attemptID=f"{IDS[0]}#0001",
            triggerMode="reactive",
            executionMode="active",
        )
        ledger.record(
            "launch_response",
            catalogueID=IDS[0],
            attemptID=f"{IDS[0]}#0001",
            runID="run-resumed",
            verified=True,
            response={"status": 200, "body": {
                "id": "run-resumed",
                "catalogueID": IDS[0],
                "triggerMode": "reactive",
                "executionMode": "active",
            }},
        )
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 0)
        self.assertEqual(scenario.launches, [])
        self.assertEqual(self.summary(output)["results"][0]["runID"], "run-resumed")

    def test_cleanup_failure_blocks_retry(self) -> None:
        scenario = Scenario()
        scenario.status_hook = lambda run_id, _count: (
            200,
            status(run_id, IDS[0], cleanup="unverified", unsafe=True),
        )
        scenario.evidence_hook = lambda run_id, _count: (
            200,
            strict_evidence(run_id, IDS[0], cleanup_verified=False),
        )
        output = self.root / "cleanup"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 2)
            self.assertEqual(self.invoke(server, output), 2)
        self.assertEqual(len(scenario.launches), 1)
        result = self.summary(output)["results"][0]
        self.assertEqual(result["localVerdict"], "FAIL")
        self.assertFalse(result["retrySafe"])

    def test_defended_and_emitted_without_physical_oracle_never_passes(self) -> None:
        scenario = Scenario()
        scenario.evidence_hook = lambda run_id, _count: (
            200,
            strict_evidence(
                run_id,
                IDS[0],
                physical_validated=False,
                receipt_observed=False,
                verdict="DEFENDED",
            ),
        )
        output = self.root / "false-defended"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 2)
        result = self.summary(output)["results"][0]
        self.assertEqual(result["localVerdict"], "FAIL")
        evidence_events = [event for event in self.events(output) if event["type"] == "evidence_response"]
        raw_verdict = evidence_events[0]["response"]["body"]["attackCatalogueResult"]["verdict"]
        self.assertEqual(raw_verdict, "DEFENDED")
        self.assertFalse(result["bindings"]["physicalOracle"])

    def test_successful_strict_record_and_reports(self) -> None:
        scenario = Scenario()
        output = self.root / "success"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 0)
        self.assertEqual(scenario.launches, [{
            "executionMode": "active",
            "id": IDS[0],
            "triggerMode": "reactive",
        }])
        summary = self.summary(output)
        self.assertTrue(summary["allPassed"])
        result = summary["results"][0]
        self.assertEqual(result["localVerdict"], "PASS")
        self.assertTrue(all(result["bindings"].values()))
        self.assertTrue((output / "report.md").is_file())
        retained = (output / "attempts.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(TOKEN, retained)
        self.assertIn('"type":"launch_response"', retained)
        self.assertIn('"type":"evidence_response"', retained)

    def test_terminal_evidence_read_is_retried(self) -> None:
        scenario = Scenario()

        def evidence(run_id: str, count: int) -> tuple[int, dict]:
            if count == 1:
                return 404, {"error": "evidence not visible yet"}
            return 200, strict_evidence(run_id, IDS[0])

        scenario.evidence_hook = evidence
        output = self.root / "evidence-retry"
        with FakeConsole(scenario) as server:
            self.assertEqual(self.invoke(server, output), 0)
        self.assertEqual(scenario.evidence_calls["run-1"], 2)


if __name__ == "__main__":
    unittest.main()
