import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze  # noqa: E402


def probe(status, before, after, marker=True, error=""):
    body = {"marker": analyze.MARKER, "call_count": after} if status == 200 and marker else {"error": "unauthorized"}
    return {"status": status, "before_calls": before, "after_calls": after, "body": body, "error": error}


def episode(arm, a_outcomes, facts, post_facts, replacement=()):
    return {"arm": arm, "a": [(float(i), o, 20.0) for i, o in enumerate(a_outcomes)], "b": [],
            "a_after_replacement": list(replacement), "facts": facts, "post_facts": post_facts,
            "post_weights": {k: 0.0 for k in post_facts}}


class Statistics(unittest.TestCase):
    def test_wilson_matches_reference_values(self):
        p, lo, hi = analyze.wilson(10, 10)
        self.assertEqual(p, 1.0)
        self.assertAlmostEqual(lo, 0.7225, places=4)
        self.assertAlmostEqual(hi, 1.0)
        self.assertIsNone(analyze.wilson(0, 0))

    def test_newcombe_difference_of_all_or_nothing_arms(self):
        d, lo, hi = analyze.newcombe(10, 10, 0, 10)
        # Newcombe hybrid score: 1 - sqrt(2 * (1 - 0.7225)^2).
        self.assertEqual(d, 1.0)
        self.assertAlmostEqual(lo, 0.6075, places=4)
        self.assertAlmostEqual(hi, 1.0)

    def test_rank_coefficients_handle_ties(self):
        self.assertAlmostEqual(analyze.kendall_tau_b([3, 2, 1, 1], [1, 0, 0, 0]), 0.7746, places=4)
        self.assertAlmostEqual(analyze.spearman([3, 2, 1, 1], [1, 0, 0, 0]), 0.8165, places=4)
        self.assertIsNone(analyze.kendall_tau_b([1, 1], [0, 1]))


class Outcomes(unittest.TestCase):
    def test_only_a_proven_downstream_call_is_success(self):
        self.assertEqual(analyze.outcome(probe(200, 3, 4)), "success")
        self.assertEqual(analyze.outcome(probe(401, 4, 4)), "denied")
        # A 200 without the downstream counter moving, or a 401 that still ran downstream, proves nothing.
        self.assertEqual(analyze.outcome(probe(200, 3, 3)), "indeterminate")
        self.assertEqual(analyze.outcome(probe(401, 4, 5)), "indeterminate")
        self.assertEqual(analyze.outcome(probe(200, 3, 4, error="timeout")), "indeterminate")
        self.assertEqual(analyze.outcome(probe(503, 3, 3)), "indeterminate")


class Invalidation(unittest.TestCase):
    pre = {"pod|ns/p|endpointLeaseReuse": 1.0, "pod|ns/p|inMemory": 0.3}

    def test_cleared_fact_with_removed_capability_is_confirmed(self):
        e = episode("intervention", ["denied"] * 3, self.pre, ["pod|ns/p|inMemory"])
        inv = analyze.invalidation(e)
        self.assertEqual(inv["true"], ["endpointLeaseReuse"])
        self.assertEqual(inv["false"], [])

    def test_cleared_fact_with_usable_capability_is_false_invalidation(self):
        e = episode("cf-rotate", ["success"] * 3, self.pre, ["pod|ns/p-new|inMemory"], replacement=["success"])
        inv = analyze.invalidation(e)
        self.assertEqual(inv["false"], ["endpointLeaseReuse"])
        self.assertEqual(inv["reminted"], ["inMemory"])
        self.assertEqual(len(inv["keys_cleared"]), 2)

    def test_missing_post_observation_is_unavailable_not_cleared(self):
        e = episode("cf-rotate", ["success"], self.pre, [])
        e["post_facts"] = None
        self.assertIsNone(analyze.invalidation(e))

    def test_no_determinate_probe_leaves_capability_unknown(self):
        e = episode("intervention", ["indeterminate"], self.pre, [])
        self.assertIsNone(analyze.capability_removed(e))
        self.assertIsNone(analyze.interrupted(e))


class Rows(unittest.TestCase):
    def test_unexecuted_candidates_have_status_not_zero(self):
        e = episode("intervention", ["denied"] * 2, {"pod|ns/p|endpointLeaseReuse": 1.0}, [])
        e.update({"dir": "001", "executed_action": "endpoint-lease-revoke", "decision_id": "d", "asset": "ns/p", "asset_uid": "u",
                  "selected": "endpoint-lease-revoke", "asset_value": 1.6, "p_hold": 0.3, "urgency": 0.3, "dispersion": 1,
                  "pre_a": ["success"], "pre_b_latency": [], "hold_s": 20.0, "post_target": "same pod", "post_error": "", "post_selected": "noop",
                  "candidates": [
                      {"action": "endpoint-lease-revoke", "feasible": True, "selected": True, "blocking_gate": "", "status_reason": "", "cover": ["pod|ns/p|endpointLeaseReuse"],
                       "gross": 1.0, "marginal": 1.0, "net": 0.9, "provenance": 1, "expected_cost": 0.1},
                      {"action": "rotate", "feasible": False, "selected": False, "blocking_gate": "availability", "status_reason": "", "cover": [],
                       "gross": 0.9, "marginal": None, "net": None, "provenance": 1, "expected_cost": 0}]})
        rows = {r["action_id"]: r for r in analyze.episode_rows(e, {"p": 1.0, "k": 10, "n": 10})}
        self.assertEqual(set(rows), {"endpoint-lease-revoke", "rotate", "noop"})
        rotate = rows["rotate"]
        for col in ("attack_success_with_action", "time_to_reacquire_s", "estimated_risk_reduction", "measured_disruption"):
            self.assertEqual(rotate[col], "")
            self.assertTrue(rotate[col.replace("_s", "") + "_status" if col == "time_to_reacquire_s" else col + "_status"].startswith("UNAVAILABLE"))
        self.assertEqual(rotate["predicted_marginal_gain"], "")
        elr = rows["endpoint-lease-revoke"]
        self.assertEqual(elr["attack_success_with_action"], "0.0000")
        self.assertEqual(elr["estimated_risk_reduction"], "1.0000")
        self.assertTrue(elr["time_to_reacquire_status"].startswith("CENSORED"))
        self.assertEqual(elr["confirmed_invalidated_keys"], "endpointLeaseReuse")


if __name__ == "__main__":
    unittest.main()
