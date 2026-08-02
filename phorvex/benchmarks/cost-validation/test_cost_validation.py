#!/usr/bin/env python3

import importlib.util
import json
import math
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cost_validation", HERE / "cost_validation.py")
assert SPEC and SPEC.loader
cv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cv)


class CostValidationTests(unittest.TestCase):
    def test_observed_label_omits_missing_terms(self):
        value, terms = cv.observed_label({
            "availability_loss": 0.2,
            "p99_before_ms": 100,
            "p99_after_ms": 150,
            "time_to_ready_sec": 40,
            "state_or_kv_loss": 1,
        })
        self.assertEqual(terms, 4)
        self.assertAlmostEqual(value, 0.45)

    def test_grouped_split_has_no_scenario_seed_leakage(self):
        rows = [
            {"scenario_id": f"s{i}", "seed": seed}
            for i in range(7)
            for seed in range(3)
            for _ in range(4)
        ]
        train, test = cv.grouped_split(rows)
        self.assertFalse(train & test)
        self.assertEqual(len(train | test), 21)
        self.assertEqual(len(train), 14)
        self.assertEqual(len(test), 7)

    def test_nnls_is_nonnegative_and_fits_known_weights(self):
        expected = [0.1, 0.2, 0.3, 0.15, 0.25]
        rows = []
        for index in range(30):
            x = [((index + offset * 3) % 11) / 10 for offset in range(5)]
            rows.append({
                **dict(zip(cv.FEATURES, x)),
                "cost_observed": sum(a * b for a, b in zip(expected, x)),
            })
        got = cv.fit_nnls(rows)
        self.assertTrue(all(value >= 0 for value in got))
        for actual, want in zip(got, expected):
            self.assertAlmostEqual(actual, want, places=6)

    def test_ranking_metrics_handle_ties(self):
        truth = [0.1, 0.2, 0.2, 0.9]
        self.assertAlmostEqual(cv.spearman(truth, truth), 1)
        self.assertAlmostEqual(cv.kendall_tau_b(truth, truth), 1)
        self.assertAlmostEqual(cv.pairwise_accuracy(truth, truth), 1)

    def test_e2e_outputs_required_artifacts(self):
        actions = ["noop", "rotate", "quarantine"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "observations.jsonl"
            catalog_path = root / "catalog.json"
            catalog_path.write_text(json.dumps([
                {"action": action, "candidate_generated": True, "cost_model_available": True,
                 "cost_components_used": ["norm", "flow"], "unexecuted_classification": "not executable"}
                for action in actions
            ]))
            rows = []
            for scenario in range(7):
                for seed in range(3):
                    for action_index, action in enumerate(actions):
                        observed = 0.02 + 0.1 * action_index + 0.005 * scenario
                        rows.append({
                            "schema_version": "phorvex.cost-validation-observation.v1",
                            "scenario_id": f"scenario-{scenario}", "seed": seed,
                            "tick_id": "tick-0", "workload_id": f"workload-{scenario}",
                            "workload_type": "rag" if scenario == 6 else "stateless",
                            "load_profile": "high" if scenario % 2 else "low",
                            "action": action, "candidate_generated": True,
                            "feasibility_status": "feasible", "emitted": action != "noop",
                            "actuation_error": "", "security_value": 1 + action_index * 0.02,
                            "lambda": 1, "c_norm": action_index / 2, "c_flow": observed,
                            "c_state": 0, "c_gpu": 0, "c_availability": action_index / 4,
                            "c0_cost": 0.4 * action_index / 2 + 0.6 * observed,
                            "availability_loss": observed, "cost_observed": observed,
                            "slo_violation": False,
                        })
            input_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            args = cv.parse_args([
                "--input", str(input_path), "--action-catalog", str(catalog_path),
                "--output-dir", str(root / "out"),
            ])
            result = cv.evaluate(args)
            self.assertIn(result["recommendation"], {
                "keep the current formula", "promote the calibrated formula", "collect more measurements"
            })
            for name in (
                "cost-validation-results.csv", "cost-validation-summary.md", "c2-weights.json",
                "action-cost-coverage.csv", "cost-validation-provenance.json",
            ):
                self.assertTrue((root / "out" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
