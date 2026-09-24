import unittest

import audit_trace_validator as validator


class ResourceCapacityV7Test(unittest.TestCase):
    def trace(self, version, status="infeasible", scored=False):
        rows = [
            {"action": action, "status": "not-enabled", "exclusionKind": "not-enabled", "scored": False}
            for action in validator.MUTATING_ACTIONS
        ]
        rows[0] = {
            "action": "rotate", "status": status, "exclusionKind": "resource-capacity", "scored": scored,
            "reason": "resource-capacity: fixture",
        }
        return {"schemaVersion": version, "actionStatus": rows,
                "candidates": [{"action": "rotate", "coverKeys": ["pod|owned/source|identity"],
                                "existingExclusionReason": "resource-capacity: fixture",
                                "selected": False}],
                "resources": [{"scope": {"kind": "move-count", "namespace": "owned",
                                         "controllerUID": "policy-uid"},
                               "limit": 1, "outstanding": 0, "selected": 0}]}

    def test_v7_accepts_typed_unscored_refusal_and_inherits_v6_resource_law(self):
        trace = self.trace(validator.TRACE_V7)
        self.assertEqual(validator.v3_action_status(trace), [])
        self.assertEqual(validator.check_resources_v6(trace).status, validator.PASS)
        trace["resources"][0]["selected"] = 2
        self.assertEqual(validator.check_resources_v6(trace).status, validator.FAIL)

    def test_v6_rejects_new_closed_enum(self):
        self.assertTrue(validator.v3_action_status(self.trace(validator.TRACE_V6)))

    def test_v7_rejects_scored_or_non_infeasible_resource_refusal(self):
        self.assertTrue(validator.v3_action_status(self.trace(validator.TRACE_V7, scored=True)))
        self.assertTrue(validator.v3_action_status(self.trace(validator.TRACE_V7, status="no-cover")))

    def test_v7_rejects_fabricated_numeric_score_on_capacity_exclusion(self):
        trace = self.trace(validator.TRACE_V7)
        trace["candidates"][0]["marginalCoverage"] = {"present": True, "value": 1}
        self.assertTrue(validator.v3_action_status(trace))

    def test_early_quarantine_capacity_can_precede_cover_and_absent_flow_optional(self):
        trace = self.trace(validator.TRACE_V7)
        trace["candidates"][0]["coverKeys"] = []
        trace["candidates"][0]["flowPredictedMean"] = {"present": False, "value": 0}
        self.assertEqual(validator.v3_action_status(trace), [])


if __name__ == "__main__":
    unittest.main()
