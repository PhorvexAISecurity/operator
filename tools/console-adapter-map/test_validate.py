import copy
import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("validate_console_adapter_map", HERE / "validate.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ConsoleAdapterMapValidationTest(unittest.TestCase):
    def document(self):
        return MODULE.build_document()

    def assert_invalid(self, document, message):
        with self.assertRaisesRegex(MODULE.ValidationError, message):
            MODULE.validate_document(document)

    def test_exact_source_coverage_is_valid(self):
        document = self.document()
        MODULE.validate_document(document)
        self.assertEqual(192, len(document["mappings"]))
        self.assertEqual(13, len(document["familyProfiles"]))
        self.assertEqual(192, len({item["id"] for item in document["mappings"]}))
        self.assertEqual(192, sum(item["registrationStatus"] == "eligible" for item in document["mappings"]))
        unavailable = [item for item in document["mappings"] if item["registrationStatus"] == "unavailable"]
        self.assertEqual([], unavailable)

    def test_missing_id_fails_closed(self):
        document = self.document()
        document["mappings"].pop()
        self.assert_invalid(document, "missing mapping IDs")

    def test_duplicate_id_is_rejected(self):
        document = self.document()
        document["mappings"].append(copy.deepcopy(document["mappings"][0]))
        self.assert_invalid(document, "duplicate mapping IDs")

    def test_unknown_id_is_rejected(self):
        document = self.document()
        document["mappings"][-1]["id"] = "UNKNOWN-CATALOGUE-ID"
        self.assert_invalid(document, "unknown mapping IDs")

    def test_family_drift_is_rejected(self):
        document = self.document()
        document["mappings"][0]["family"] = "serving-rate"
        self.assert_invalid(document, "family drift")

    def test_missing_support_cannot_be_registration_eligible(self):
        document = self.document()
        document["mappings"][0]["supportingImplementationExists"] = False
        self.assert_invalid(document, "current Console implementation support drift")

    def test_missing_support_reference_fails_closed(self):
        document = self.document()
        available = next(item for item in document["mappings"] if item["supportingImplementationExists"])
        available["supportingImplementationRefs"] = []
        self.assert_invalid(document, "current Console implementation support drift")

    def test_incomplete_family_profile_is_rejected(self):
        document = self.document()
        document["familyProfiles"][0].pop("physicalOracle")
        self.assert_invalid(document, "incomplete or drifted family profile")

    def test_trigger_and_execution_modes_cannot_be_conflated(self):
        document = self.document()
        document["modeContract"]["executionMode"] = ["reactive", "proactive+reactive"]
        self.assert_invalid(document, r"execution mode must remain.*active\|dryRun")

    def test_static_launchable_claim_is_forbidden(self):
        document = self.document()
        document["mappings"][0]["launchable"] = True
        self.assert_invalid(document, "must not represent an ID as launchable")


if __name__ == "__main__":
    unittest.main()
