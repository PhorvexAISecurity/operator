from __future__ import annotations

import os
import unittest
from pathlib import Path

from benchmark import checker_cases, objective_for, simple_record
from model_adapters import solve_ortools, solve_ortools_external_cbc, solve_pulp, solve_pyomo
from production_checker import accept_or_fallback, check_solution


CBC = Path(os.environ.get("PHORVEX_CBC", "/missing/cbc"))


class ProductionCheckerTests(unittest.TestCase):
    def test_every_targeted_law(self):
        for name, record, x, y, expected in checker_cases():
            with self.subTest(name=name):
                check = check_solution(record, x, y, objective_for(record, x, y))
                accepted = accept_or_fallback("optimal", check)
                self.assertEqual(expected, accepted.accepted, check.violations)

    def test_statuses_fail_closed(self):
        record = simple_record()
        check = check_solution(record, [1.0], {"fact": 1.0}, objective_for(record, [1.0], {"fact": 1.0}))
        self.assertTrue(accept_or_fallback("feasible", check).accepted)
        for status in ("time_limit", "error", "unknown", "infeasible", "unbounded"):
            with self.subTest(status=status):
                result = accept_or_fallback(status, None)
            self.assertFalse(result.accepted)
            self.assertEqual("no-action", result.fallback)

    def test_future_reward_is_independently_recomputed(self):
        record = simple_record()
        record["cands"][0]["future_reward"] = 2.5
        objective = objective_for(record, [1.0], {"fact": 1.0})
        self.assertTrue(
            check_solution(record, [1.0], {"fact": 1.0}, objective).passed
        )
        self.assertFalse(
            check_solution(record, [1.0], {"fact": 1.0}, objective - 2.5).passed
        )


@unittest.skipUnless(CBC.exists(), "set PHORVEX_CBC to the external CBC executable")
class EquivalentModelTests(unittest.TestCase):
    def test_small_model_matches(self):
        record = simple_record()
        results = [
            solve_pulp(record, CBC),
            solve_pyomo(record, CBC),
            solve_ortools(record),
            solve_ortools_external_cbc(record, CBC),
        ]
        for result in results:
            self.assertEqual("optimal", result.status, result.error)
            self.assertTrue(result.acceptance.accepted, result.acceptance.violations)
        self.assertLess(max(r.objective for r in results) - min(r.objective for r in results), 1e-7)

    def test_candidate_future_reward_matches_across_frameworks(self):
        record = simple_record()
        record["cands"][0]["future_reward"] = -100.0
        results = [
            solve_pulp(record, CBC),
            solve_pyomo(record, CBC),
            solve_ortools(record),
            solve_ortools_external_cbc(record, CBC),
        ]
        for result in results:
            self.assertEqual("optimal", result.status, result.error)
            self.assertTrue(result.acceptance.accepted, result.acceptance.violations)
            self.assertEqual([], result.selected_indices)
            self.assertAlmostEqual(0.0, result.objective)

    def test_intentionally_infeasible(self):
        record = simple_record()
        record["b"] = 0
        record["test_required_min_moves"] = 1
        results = [solve_pulp(record, CBC), solve_pyomo(record, CBC), solve_ortools(record)]
        for result in results:
            self.assertEqual("infeasible", result.status, (result.native_status, result.error))
            self.assertFalse(result.acceptance.accepted)
            self.assertEqual("no-action", result.acceptance.fallback)

    def test_real_solver_failures_fall_back(self):
        record = simple_record()
        results = [
            solve_pulp(record, Path("/missing/cbc")),
            solve_pyomo(record, Path("/missing/cbc")),
            solve_ortools(record, backend="MISSING_BACKEND"),
        ]
        for result in results:
            self.assertEqual("error", result.status)
            self.assertFalse(result.acceptance.accepted)
            self.assertEqual("no-action", result.acceptance.fallback)


if __name__ == "__main__":
    unittest.main()
