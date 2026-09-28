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
        current = self.trace(validator.OUTPUT16_ACTIONS, validator.ACTION_VOCABULARY_OUTPUT16)
        self.assertEqual(validator.v3_action_status(current), [])
        self.assertEqual(validator.check_ordering(current).status, validator.PASS)
        expanded = self.trace(validator.MUTATING_ACTIONS, validator.ACTION_VOCABULARY_OUTPUT16)
        self.assertIn("want 16", "; ".join(validator.v3_action_status(expanded)))

    def test_both_historical_seventeen_orders_are_preserved(self):
        for actions, marker in (
            (validator.VOICE17_ACTIONS, validator.ACTION_VOCABULARY_VOICE17),
            (validator.LITELLM17_ACTIONS, validator.ACTION_VOCABULARY_LITELLM17),
        ):
            with self.subTest(marker=marker):
                historical = self.trace(actions, marker)
                self.assertEqual(validator.v3_action_status(historical), [])
                self.assertEqual(validator.check_ordering(historical).status, validator.PASS)
                prior = self.trace(validator.OUTPUT16_ACTIONS, marker)
                self.assertIn("want 17", "; ".join(validator.v3_action_status(prior)))
                combined = self.trace(validator.MUTATING_ACTIONS, marker)
                self.assertIn("want 17", "; ".join(validator.v3_action_status(combined)))

    def test_current_eighteen_requires_its_new_marker(self):
        current = self.trace(validator.LIVE18_ACTIONS, validator.ACTION_VOCABULARY_LIVE18)
        self.assertEqual(validator.v3_action_status(current), [])
        self.assertEqual(validator.check_ordering(current).status, validator.PASS)
        prior = self.trace(validator.VOICE17_ACTIONS, validator.ACTION_VOCABULARY_LIVE18)
        self.assertIn("want 18", "; ".join(validator.v3_action_status(prior)))

    def test_live20_remains_historical_and_live21_appends_mcp(self):
        historical = self.trace(validator.LIVE20_ACTIONS, validator.ACTION_VOCABULARY_LIVE20)
        self.assertEqual(validator.v3_action_status(historical), [])
        live21 = self.trace(validator.LIVE21_ACTIONS, validator.ACTION_VOCABULARY_LIVE21)
        self.assertEqual(validator.v3_action_status(live21), [])
        self.assertEqual(validator.check_ordering(live21).status, validator.PASS)
        self.assertIn("want 20", "; ".join(validator.v3_action_status(
            live21 | {"actionVocabularyVersion": validator.ACTION_VOCABULARY_LIVE20})))

    def test_live22_appends_endpoint_lease_without_reinterpreting_live21(self):
        live22 = self.trace(validator.LIVE22_ACTIONS, validator.ACTION_VOCABULARY_LIVE22)
        self.assertEqual(validator.v3_action_status(live22), [])
        self.assertEqual(validator.check_ordering(live22).status, validator.PASS)
        self.assertIn("want 21", "; ".join(validator.v3_action_status(
            live22 | {"actionVocabularyVersion": validator.ACTION_VOCABULARY_LIVE21})))

    def test_live23_appends_admission_without_reinterpreting_live22(self):
        self.assertEqual(len(validator.LIVE22_ACTIONS), 22)
        self.assertEqual(len(validator.MUTATING_ACTIONS), 23)
        self.assertEqual(validator.MUTATING_ACTIONS[:-1], validator.LIVE22_ACTIONS)
        self.assertEqual(validator.MUTATING_ACTIONS[-1], "voice-session-admission-enforce")
        live23 = self.trace(validator.MUTATING_ACTIONS, validator.ACTION_VOCABULARY_LIVE23)
        self.assertEqual(validator.v3_action_status(live23), [])
        self.assertEqual(validator.check_ordering(live23).status, validator.PASS)
        self.assertIn("want 22", "; ".join(validator.v3_action_status(
            live23 | {"actionVocabularyVersion": validator.ACTION_VOCABULARY_LIVE22})))

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
        for new_action in validator.MUTATING_ACTIONS[16:]:
            with self.subTest(action=new_action):
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
