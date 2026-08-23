from __future__ import annotations

import copy
import math
import unittest

from exact_tier import (
    CPSATResult, coverage_is_disjoint, greedy_then_swaps, run_exact_tier,
    solve_cp_sat, solve_cp_sat_hard_deadline,
)
from production_checker import check_solution


def candidate(index: int, asset: str, cover: list[str], ecost: float = 0.0):
    return {
        "id": f"c{index}", "key": asset, "action": "rotate",
        "cover": cover, "ecost": ecost,
    }


def record(candidates, weights, budget=2):
    return {
        "cands": candidates, "weights": weights, "b": budget, "lambda": 0.3,
        "policy": {"max_moves_per_tick": budget, "enabled_actions": ["rotate"]},
    }


class HeuristicTests(unittest.TestCase):
    def test_duplicate_cover_keys_do_not_inflate_value(self):
        data = record(
            [candidate(0, "a", ["shared", "shared"], 0.0), candidate(1, "b", ["other"], 0.0)],
            {"shared": 1.0, "other": 1.5}, 1,
        )
        result = greedy_then_swaps(data)
        self.assertEqual((1,), result.selected_indices)
        self.assertAlmostEqual(1.5, result.objective)

    def test_disjoint_and_budget_one_routes_skip_exact(self):
        disjoint = record(
            [candidate(0, "a", ["a"]), candidate(1, "b", ["b"])],
            {"a": 1.0, "b": 2.0}, 2,
        )
        self.assertTrue(coverage_is_disjoint(disjoint))
        decision = run_exact_tier(disjoint, deadline_seconds=0.1)
        self.assertEqual("greedy-disjoint", decision.route)
        self.assertEqual((0, 1), decision.selected_indices)

        shared = copy.deepcopy(disjoint)
        shared["cands"][1]["cover"].append("a")
        shared["b"] = shared["policy"]["max_moves_per_tick"] = 1
        decision = run_exact_tier(shared, deadline_seconds=0.1)
        self.assertEqual("greedy-budget-one", decision.route)


class CPSATTests(unittest.TestCase):
    def setUp(self):
        # A deterministic one-swap local optimum: greedy settles on 0+1 (10
        # facts), while CP-SAT finds 2+3 (11 facts).  Neither individual swap
        # improves the incumbent, so this exercises the exact escalation.
        self.shared = record(
            [
                candidate(0, "a", ["9", "1", "11", "8", "0", "5", "2"]),
                candidate(1, "b", ["8", "1", "7", "4", "6"]),
                candidate(2, "c", ["6", "7", "2", "0", "1", "3", "8"]),
                candidate(3, "d", ["4", "5", "6", "10", "0", "9"]),
                candidate(4, "e", ["9", "3", "8", "6", "1", "0"]),
                candidate(5, "f", ["10", "8"]),
            ],
            {str(i): 1.0 for i in range(12)},
            2,
        )

    def test_cp_sat_matches_unscaled_objective_at_multiple_scales(self):
        objectives = []
        for scale in (100, 1_000, 1_000_000):
            solved = solve_cp_sat(self.shared, deadline_seconds=1.0, coefficient_scale=scale)
            self.assertEqual("optimal", solved.status, solved.error)
            self.assertTrue(solved.checker_passed, solved.violations)
            self.assertLessEqual(solved.max_coefficient_rounding_error, 0.5 / scale + 1e-12)
            objectives.append(solved.objective)
        self.assertLess(max(objectives) - min(objectives), 1e-7)

    def test_exact_tier_improves_greedy_incumbent(self):
        heuristic = greedy_then_swaps(self.shared)
        decision = run_exact_tier(self.shared, deadline_seconds=1.0)
        self.assertEqual("exact-escalation", decision.route)
        self.assertEqual("cp-sat", decision.solution_source)
        self.assertGreater(decision.objective, heuristic.objective)
        check = check_solution(self.shared, decision.x_values, decision.y_values, decision.objective)
        self.assertTrue(check.passed, check.violations)

    def test_timeout_and_error_return_valid_incumbent(self):
        def unavailable(*_args, **_kwargs):
            return CPSATResult(
                "time_limit", "UNKNOWN", math.nan, math.nan, math.nan, math.nan,
                (), (), {}, False, ("solver-status:time_limit",), 1_000_000,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                2.0, False, 0, 0,
            )

        decision = run_exact_tier(self.shared, deadline_seconds=1.0, solver_fn=unavailable)
        self.assertEqual("greedy-plus-swaps", decision.solution_source)
        self.assertTrue(decision.fallback_used)
        check = check_solution(self.shared, decision.x_values, decision.y_values, decision.objective)
        self.assertTrue(check.passed, check.violations)

    def test_infeasible_model_falls_back(self):
        infeasible = copy.deepcopy(self.shared)
        infeasible["b"] = 1
        infeasible["test_required_min_moves"] = 2
        # Force the exact path despite B=1 by calling the adapter directly.
        result = solve_cp_sat(infeasible, deadline_seconds=1.0)
        self.assertEqual("infeasible", result.status)
        self.assertFalse(result.checker_passed)

    def test_hard_deadline_keeps_the_incumbent_available(self):
        incumbent = greedy_then_swaps(self.shared)
        result = solve_cp_sat_hard_deadline(
            self.shared, deadline_seconds=0.001,
            coefficient_scale=1_000_000, incumbent=incumbent,
        )
        self.assertIn(result.status, {"time_limit", "error"})
        self.assertLess(result.total_ms, 100.0)


if __name__ == "__main__":
    unittest.main()
