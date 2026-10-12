import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze  # noqa: E402


def lease_probe(status, before, after, error=""):
    body = {"marker": analyze.MARKER, "call_count": after} if status == 200 else {"error": "unauthorized"}
    return {"status": status, "before_calls": before, "after_calls": after, "body": body, "error": error}


def token_probe(status, error=""):
    body = {"authenticated": True, "username": "system:serviceaccount:vllm:lease-proxy"} if status == 201 else {"error": "unauthorized"}
    return {"status": status, "body": body, "error": error, "capability": analyze.TOKEN}


def stats(outcomes, step=1.0):
    return analyze.capability_stats([(i * step, o) for i, o in enumerate(outcomes)])


def episode(scenario, outcomes, facts, post, executed="endpoint-lease-revoke"):
    caps = analyze.SCENARIOS[scenario]["caps"]
    return {"scenario": scenario, "caps": caps, "executed_action": executed, "facts": facts, "post": post,
            "stats": {c: stats(outcomes[c]) for c in caps}}


def fact(w, attributed=False):
    return {"w": w, "attributed": attributed}


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
    def test_only_a_proven_downstream_call_is_lease_success(self):
        self.assertEqual(analyze.outcome(lease_probe(200, 3, 4)), "success")
        self.assertEqual(analyze.outcome(lease_probe(401, 4, 4)), "denied")
        # A 200 without the downstream counter moving, or a 401 that still ran downstream, proves nothing.
        self.assertEqual(analyze.outcome(lease_probe(200, 3, 3)), "indeterminate")
        self.assertEqual(analyze.outcome(lease_probe(401, 4, 5)), "indeterminate")
        self.assertEqual(analyze.outcome(lease_probe(200, 3, 4, error="timeout")), "indeterminate")
        self.assertEqual(analyze.outcome(lease_probe(503, 3, 3)), "indeterminate")

    def test_token_success_is_authentication_and_denial_is_exact_401(self):
        self.assertEqual(analyze.outcome(token_probe(201)), "success")
        self.assertEqual(analyze.outcome(token_probe(401)), "denied")
        self.assertEqual(analyze.outcome(token_probe(201, error="connection reset")), "indeterminate")
        self.assertEqual(analyze.outcome(dict(token_probe(403), body={"error": "forbidden"})), "indeterminate")


class CapabilityStats(unittest.TestCase):
    def test_immediate_removal(self):
        s = stats(["denied"] * 5)
        self.assertFalse(s["usable_at_end"])
        self.assertFalse(s["succeeded_after_branch"])
        self.assertEqual(s["removal_s"], 0.0)

    def test_delayed_removal_is_first_denial_after_last_success(self):
        # The API server keeps accepting a retired bearer for its authentication-cache lifetime.
        s = stats(["success"] * 10 + ["denied"] * 10)
        self.assertFalse(s["usable_at_end"])
        self.assertTrue(s["succeeded_after_branch"])
        self.assertEqual(s["removal_s"], 10.0)
        self.assertEqual(s["k"], 10)

    def test_success_at_the_end_means_usable(self):
        s = stats(["denied"] * 10 + ["success"])
        self.assertTrue(s["usable_at_end"])
        self.assertIsNone(s["removal_s"])

    def test_no_determinate_probe_is_unavailable(self):
        self.assertIsNone(stats(["indeterminate"] * 3))


class Invalidation(unittest.TestCase):
    pre = {"pod|ns/p|endpointLeaseReuse": fact(1.0, True), "pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True),
           "pod|ns/p|inMemory": fact(0.3)}

    def test_attributed_fact_cleared_with_removed_capability_is_true(self):
        e = episode("lease", {"lease": ["denied"] * 3}, self.pre, {"pod|ns/p|inMemory": fact(0.3)})
        self.assertEqual(analyze.invalidation(e)["per_cap"], {"lease": "true"})

    def test_attributed_fact_cleared_with_usable_capability_is_false(self):
        e = episode("lease", {"lease": ["success"] * 3}, self.pre, {"pod|ns/p-new|inMemory": fact(0.0)}, executed="rotate")
        inv = analyze.invalidation(e)
        self.assertEqual(inv["false"], ["endpointLeaseReuse"])
        self.assertEqual(inv["reminted"], ["inMemory"])

    def test_combined_partial_effect(self):
        post = {"pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True), "pod|ns/p|inMemory": fact(0.3)}
        e = episode("combined", {"lease": ["denied"] * 3, "token": ["success"] * 3}, self.pre, post)
        self.assertEqual(analyze.invalidation(e)["per_cap"], {"lease": "true", "token": "persisting"})

    def test_removed_capability_whose_fact_persists_is_uncredited(self):
        post = {"pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True)}
        e = episode("token", {"token": ["denied"] * 3}, self.pre, post, executed="rotate")
        self.assertEqual(analyze.invalidation(e)["per_cap"], {"token": "uncredited"})

    def test_missing_post_observation_is_unavailable_not_cleared(self):
        e = episode("lease", {"lease": ["success"]}, self.pre, None, executed="rotate")
        self.assertIsNone(analyze.invalidation(e))


class Rows(unittest.TestCase):
    def make(self, scenario, outcomes, executed, post):
        e = episode(scenario, outcomes, {"pod|ns/p|endpointLeaseReuse": fact(1.0, True), "pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True)}, post, executed)
        e.update({"dir": "001", "arm": "selected", "decision_id": "d", "asset": "ns/p", "asset_uid": "u", "selected": "endpoint-lease-revoke",
                  "asset_value": 1.6, "p_hold": 0.5, "urgency": 0.3, "dispersion": 1, "post_target": "same pod", "post_error": "",
                  "post_selected": "noop", "pre": {c: ["success"] for c in e["caps"]}, "pre_b_latency": [20.0],
                  "legit": [(1.0, "success", 25.0, "a")],
                  "candidates": [
                      {"action": "endpoint-lease-revoke", "feasible": True, "selectable": True, "selected": True, "blocking_gate": "", "status_reason": "",
                       "cover": ["pod|ns/p|endpointLeaseReuse"], "gross": 1.0, "marginal": 1.0, "net": 0.9, "provenance": 1, "expected_cost": 0.1},
                      {"action": "rotate", "feasible": True, "selectable": False, "selected": False, "blocking_gate": "conformal-slo", "status_reason": "",
                       "cover": ["pod|ns/p|podBoundKubeAPIAuthPotential"], "gross": 1.9, "marginal": None, "net": None, "provenance": 1, "expected_cost": 0}]})
        return {r["action_id"]: r for r in analyze.episode_rows(e, {"p": 1.0, "n": 10})}

    def test_unexecuted_candidates_have_status_not_zero(self):
        rows = self.make("combined", {"lease": ["denied"] * 4, "token": ["success"] * 4}, "endpoint-lease-revoke",
                         {"pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True)})
        self.assertEqual(set(rows), {"endpoint-lease-revoke", "rotate", "noop"})
        rotate = rows["rotate"]
        for col in ("attack_success_with_action", "time_to_reacquire_s", "estimated_risk_reduction", "measured_disruption"):
            self.assertEqual(rotate[col], "")
        for col in ("attack_success_with_action_status", "time_to_reacquire_status", "estimated_risk_reduction_status", "measured_disruption_status"):
            self.assertTrue(rotate[col].startswith("UNAVAILABLE"), col)
        self.assertEqual(rotate["selectable"], "false")
        self.assertEqual(rotate["predicted_marginal_gain"], "")

    def test_partial_removal_is_reported_as_partial(self):
        rows = self.make("combined", {"lease": ["denied"] * 4, "token": ["success"] * 4}, "endpoint-lease-revoke",
                         {"pod|ns/p|podBoundKubeAPIAuthPotential": fact(1.0, True)})
        elr = rows["endpoint-lease-revoke"]
        self.assertEqual(elr["attack_success_with_action"], "0.5000")
        self.assertEqual(elr["estimated_risk_reduction"], "0.5000")
        self.assertTrue(elr["time_to_reacquire_status"].startswith("PARTIAL"))
        self.assertEqual(elr["confirmed_invalidated_keys"], "endpointLeaseReuse")
        self.assertIn("Pod-bound bearer", elr["remaining_attacker_capabilities"])

    def test_full_removal_is_censored(self):
        rows = self.make("token", {"token": ["success"] * 2 + ["denied"] * 6}, "rotate", {"pod|ns/p-r|inMemory": fact(0.0)})
        rotate = rows["rotate"]
        self.assertEqual(rotate["time_to_capability_removal_s"], "token=2.00")
        self.assertTrue(rotate["time_to_reacquire_status"].startswith("CENSORED"))
        self.assertEqual(rotate["confirmed_invalidated_keys"], "podBoundKubeAPIAuthPotential")
        self.assertTrue(rotate["measured_disruption_status"].startswith("PARTIAL"))


if __name__ == "__main__":
    unittest.main()
