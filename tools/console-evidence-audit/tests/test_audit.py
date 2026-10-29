from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("console_evidence_audit", ROOT / "audit.py")
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

AS_OF = datetime(2026, 10, 29, 12, 10, tzinfo=timezone.utc)


def valid_record() -> dict:
    bundle = json.loads((ROOT / "fixtures" / "strict-valid.json").read_text())
    return bundle["records"][0]


def native_runtime_record() -> dict:
    return json.loads((ROOT / "fixtures" / "persisted-runtime-incomplete.json").read_text())


def check(verdict: dict, name: str) -> dict:
    return next(entry for entry in verdict["checks"] if entry["name"] == name)


class StrictEvidenceTests(unittest.TestCase):
    def verdict(self, record: dict, max_age: int = 300) -> dict:
        return audit.validate_record(record, AS_OF, max_age)

    def test_one_strict_valid_record_passes_every_check(self) -> None:
        verdict = self.verdict(valid_record())

        self.assertEqual(verdict["verdict"], "PASS")
        self.assertTrue(all(entry["status"] == "PASS" for entry in verdict["checks"]))

    def test_oracle_registry_is_the_exact_13_catalogue_families(self) -> None:
        self.assertEqual(
            set(audit.ORACLE_SPECS),
            {
                "agent-action", "controller-stop", "credential", "datastore",
                "identity-sa-rotate", "image", "network-edge", "node-recycle",
                "pod-rotate", "quarantine", "sensitive-output", "serving-kv",
                "serving-rate",
            },
        )

    def test_duplicate_json_keys_are_rejected_before_evaluation(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            audit.strict_json_loads('{"run_id":"one","run_id":"two"}')

    def test_metadata_only_signal_is_invalid(self) -> None:
        record = valid_record()
        record["signal"]["evidence_kind"] = "catalogue-metadata"

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "fresh_signal")["status"], "INVALID")
        self.assertIn("metadata-only", check(verdict, "fresh_signal")["reason"])

    def test_stale_signal_is_invalid(self) -> None:
        verdict = self.verdict(valid_record(), max_age=1)

        self.assertEqual(check(verdict, "fresh_signal")["status"], "INVALID")
        self.assertIn("stale", check(verdict, "fresh_signal")["reason"])

    def test_cross_run_decision_is_invalid(self) -> None:
        record = valid_record()
        record["decision"]["run_id"] = "another-run"

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "selected_feasible_decision")["status"], "INVALID")
        self.assertIn("does not match", check(verdict, "selected_feasible_decision")["reason"])

    def test_cross_catalogue_signal_is_invalid(self) -> None:
        record = valid_record()
        record["signal"]["catalogue_id"] = "T9999"

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "fresh_signal")["status"], "INVALID")

    def test_merely_emitted_actuator_is_not_a_receipt(self) -> None:
        record = valid_record()
        record["actuator"]["status"] = "emitted"
        record["actuator"].pop("receipt_id")

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "accepted_actuator_receipt")["status"], "INVALID")
        self.assertIn("merely emitted", check(verdict, "accepted_actuator_receipt")["reason"])

    def test_unselected_decision_is_a_failed_run(self) -> None:
        record = valid_record()
        record["decision"]["selected"] = False

        verdict = self.verdict(record)

        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertEqual(check(verdict, "selected_feasible_decision")["status"], "FAIL")

    def test_oracle_pass_boolean_cannot_hide_unchanged_target(self) -> None:
        record = valid_record()
        target = record["oracle"]["observations"][0]
        target["after"] = target["before"]
        self.assertTrue(record["oracle"]["passed"])
        self.assertTrue(target["passed"])

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "family_physical_oracle")["status"], "INVALID")
        self.assertIn("does not satisfy", check(verdict, "family_physical_oracle")["reason"])

    def test_missing_raw_prometheus_response_is_blocked(self) -> None:
        record = valid_record()
        record["prometheus"]["metrics"][0].pop("raw")

        verdict = self.verdict(record)

        self.assertEqual(verdict["verdict"], "BLOCKED")
        self.assertEqual(check(verdict, "prometheus_evidence")["status"], "BLOCKED")

    def test_inconsistent_prometheus_payload_hash_is_invalid(self) -> None:
        record = valid_record()
        record["prometheus"]["metrics"][0]["final"]["payload"]["data"]["result"][0]["value"][1] = "2"

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "prometheus_evidence")["status"], "INVALID")
        self.assertIn("sha256 does not match", check(verdict, "prometheus_evidence")["reason"])

    def test_trigger_mode_cannot_be_active_policy_mode(self) -> None:
        record = valid_record()
        record["trigger"]["mode"] = "active"

        verdict = self.verdict(record)

        self.assertEqual(check(verdict, "trigger_policy")["status"], "INVALID")
        self.assertIn("conflated", check(verdict, "trigger_policy")["reason"])

    def test_missing_evidence_is_blocked_even_with_screenshots(self) -> None:
        record = valid_record()
        record.pop("signal")
        record["screenshots"] = [
            {
                "kind": "console",
                "catalogue_id": "T1610",
                "run_id": "run-001",
                "sha256": "f" * 64,
            }
        ]

        verdict = self.verdict(record)

        self.assertEqual(verdict["verdict"], "BLOCKED")
        self.assertEqual(check(verdict, "fresh_signal")["status"], "BLOCKED")

    def test_screenshot_attachment_does_not_change_authoritative_digest(self) -> None:
        record = valid_record()
        original = self.verdict(record)["evidence_sha256"]
        record["screenshots"] = [{"kind": "console", "sha256": "f" * 64}]

        attached = self.verdict(record)["evidence_sha256"]

        self.assertEqual(attached, original)

    def test_unclean_postflight_is_a_failed_run(self) -> None:
        record = valid_record()
        record["postflight_clean"] = False
        record["postflight"]["clean"] = False

        verdict = self.verdict(record)

        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertEqual(check(verdict, "postflight_clean")["status"], "FAIL")

    def test_expected_run_rejects_only_exported_cross_run_record(self) -> None:
        record = valid_record()
        record["run_id"] = "wrong-run"
        merged = audit.merge_records([record], [])

        selected = audit.select_campaign_records(merged, [("T1610", "run-001")])
        verdict = self.verdict(selected[0])

        self.assertEqual(verdict["verdict"], "INVALID")
        self.assertIn("only other run IDs", check(verdict, "identity")["reason"])

    def test_native_console_export_is_consumed_but_not_upgraded_to_pass(self) -> None:
        document = {
            "id": "run-001",
            "attackCatalogueResult": {
                "schema": "phorvex.attack-catalogue-result.v1",
                "catalogueID": "T1610",
                "runID": "run-001",
                "family": "pod-rotate",
                "expectedAction": "rotate",
                "reactiveOnly": True,
                "startedAt": "2026-10-29T12:00:00Z",
                "finishedAt": "2026-10-29T12:05:00Z",
                "signal": {"observed": True, "uid": "event-001", "targetUID": "pod-old"},
                "decision": {"id": "decision-001", "selected": True, "feasible": True, "action": "rotate", "dispatchOutcome": "emitted"},
                "actuator": {"receiptObserved": True},
                "physicalValidation": {"validated": True},
                "cleanup": {"verified": True},
            },
        }
        records, expected, companions = audit.extract_document(document, 0)
        self.assertFalse(expected)
        self.assertFalse(companions)

        verdict = self.verdict(records[0])

        self.assertNotEqual(verdict["verdict"], "PASS")
        self.assertEqual(check(verdict, "postflight_clean")["status"], "BLOCKED")

    def test_persisted_runtime_record_uses_actual_modes_and_stays_fail_closed(self) -> None:
        records, expected, companions = audit.extract_document(native_runtime_record(), 0)
        self.assertFalse(expected)
        self.assertFalse(companions)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["trigger"]["mode"], "reactive")
        self.assertEqual(record["policy"]["mode"], "active")
        self.assertEqual(record["actuator"]["action"], "controller-stop")
        self.assertEqual(record["oracle"]["native_kind"], "k8s-controller-stop-rotate-eviction.v1")

        verdict = self.verdict(record)

        self.assertNotEqual(verdict["verdict"], "PASS")
        self.assertEqual(check(verdict, "fresh_signal")["status"], "BLOCKED")
        self.assertEqual(check(verdict, "accepted_actuator_receipt")["status"], "BLOCKED")
        self.assertEqual(check(verdict, "prometheus_evidence")["status"], "BLOCKED")
        self.assertEqual(check(verdict, "postflight_clean")["status"], "BLOCKED")

    def test_persisted_runtime_mode_disagreement_is_invalid(self) -> None:
        document = native_runtime_record()
        document["result"]["executionMode"] = "dryRun"
        records, _, _ = audit.extract_document(document, 0)

        verdict = self.verdict(records[0])

        self.assertEqual(check(verdict, "identity")["status"], "INVALID")
        self.assertIn("executionMode", check(verdict, "identity")["reason"])


class ReportTests(unittest.TestCase):
    def test_cli_writes_per_id_matrix_provenance_and_screenshot_slots(self) -> None:
        fixture = ROOT / "fixtures" / "strict-valid.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "audit"
            result = audit.main(
                [
                    str(fixture),
                    "--output",
                    str(output),
                    "--as-of",
                    "2026-10-29T12:10:00Z",
                    "--expected-count",
                    "1",
                ]
            )

            self.assertEqual(result, 0)
            summary = json.loads((output / "summary.json").read_text())
            bindings = json.loads((output / "screenshot-bindings.json").read_text())
            verdict_files = list((output / "verdicts").glob("*.json"))
            self.assertEqual(summary["campaign_verdict"], "PASS")
            self.assertRegex(summary["provenance"][0]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(len(verdict_files), 1)
            self.assertTrue((output / "matrix.md").is_file())
            self.assertTrue((output / "matrix.csv").is_file())
            self.assertFalse(bindings["authoritative_for_verdict"])
            self.assertFalse(bindings["bindings"][0]["source_of_truth"])
            self.assertEqual(bindings["bindings"][0]["run_id"], "run-001")

    def test_empty_bundle_cannot_produce_a_passing_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "empty.json"
            output = root / "audit"
            source.write_text(
                json.dumps(
                    {
                        "schema": "phorvex.console-evidence-audit.bundle.v1",
                        "exported_at": "2026-10-29T12:10:00Z",
                        "expected_runs": [],
                        "records": [],
                    }
                )
            )

            result = audit.main(
                [str(source), "--output", str(output), "--as-of", "2026-10-29T12:10:00Z"]
            )
            summary = json.loads((output / "summary.json").read_text())

            self.assertEqual(result, 1)
            self.assertEqual(summary["campaign_verdict"], "INVALID")


if __name__ == "__main__":
    unittest.main()
