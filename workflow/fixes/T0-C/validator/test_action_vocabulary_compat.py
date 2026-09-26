"""Frozen action accounting for historical v7 and named current traces."""

import copy
import unittest

import audit_trace_validator as validator


class ActionVocabularyCompatibilityTest(unittest.TestCase):
    @staticmethod
    def trace(actions, marker=None):
        trace = {
            "schemaVersion": validator.TRACE_V7,
            "selectedAction": "noop",
            "actionStatus": [
                {"action": action, "status": "not-enabled", "exclusionKind": "not-enabled", "scored": False}
                for action in actions
            ],
            "candidates": [],
        }
        if marker is not None:
            trace["actionVocabularyVersion"] = marker
        return trace

    def test_existing_unmarked_v7_frozen_fifteen_is_accepted(self):
        self.assertEqual(len(validator.LEGACY_MUTATING_ACTIONS), 15)
        historical = self.trace(validator.LEGACY_MUTATING_ACTIONS)
        self.assertEqual(validator.v3_action_status(historical), [])
        self.assertEqual(validator.check_ordering(historical).status, validator.PASS)

    def test_explicit_empty_marker_is_legacy_and_null_is_unknown(self):
        empty = self.trace(validator.LEGACY_MUTATING_ACTIONS, "")
        self.assertEqual(validator.v3_action_status(empty), [])
        self.assertEqual(validator.check_ordering(empty).status, validator.PASS)
        empty["schemaVersion"] = validator.TRACE_V2
        self.assertEqual(validator.check_ordering(empty).status, validator.PASS)
        null = self.trace(validator.LEGACY_MUTATING_ACTIONS)
        null["actionVocabularyVersion"] = None
        self.assertIn("unknown", "; ".join(validator.v3_action_status(null)))

    def test_new_marked_sixteen_is_accepted(self):
        current = self.trace(validator.MUTATING_ACTIONS, validator.ACTION_VOCABULARY_OUTPUT16)
        self.assertEqual(validator.v3_action_status(current), [])
        self.assertEqual(validator.check_ordering(current).status, validator.PASS)

    def test_new_marked_fifteen_and_unknown_marker_are_refused(self):
        incomplete = self.trace(validator.LEGACY_MUTATING_ACTIONS, validator.ACTION_VOCABULARY_OUTPUT16)
        self.assertIn("want 16", "; ".join(validator.v3_action_status(incomplete)))
        unknown = self.trace(validator.MUTATING_ACTIONS, "v3-unknown")
        self.assertIn("unknown", "; ".join(validator.v3_action_status(unknown)))

    def test_v2_cannot_claim_new_vocabulary(self):
        pre_accounting = self.trace(validator.MUTATING_ACTIONS, validator.ACTION_VOCABULARY_OUTPUT16)
        pre_accounting["schemaVersion"] = validator.TRACE_V2
        self.assertEqual(validator.check_ordering(pre_accounting).status, validator.FAIL)

    def test_unmarked_new_action_in_status_candidate_or_selection_is_refused(self):
        historical = self.trace(validator.LEGACY_MUTATING_ACTIONS)
        new_action = validator.MUTATING_ACTIONS[-1]
        bad_status = copy.deepcopy(historical)
        bad_status["actionStatus"][-1]["action"] = new_action
        self.assertTrue(validator.v3_action_status(bad_status))
        bad_candidate = copy.deepcopy(historical)
        bad_candidate["candidates"] = [{"action": new_action}]
        self.assertIn("outside", "; ".join(validator.v3_action_status(bad_candidate)))
        self.assertEqual(validator.check_ordering(bad_candidate).status, validator.FAIL)
        bad_selection = copy.deepcopy(historical)
        bad_selection["selectedAction"] = new_action
        self.assertIn("outside", "; ".join(validator.v3_action_status(bad_selection)))


if __name__ == "__main__":
    unittest.main()
