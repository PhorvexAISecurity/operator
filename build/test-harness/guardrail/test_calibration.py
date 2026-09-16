import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("m116_evaluate_calibration", HERE / "evaluate_calibration.py")
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)


class CalibrationEvaluatorTest(unittest.TestCase):
    def corpus(self):
        return {
            "schema_version": 1,
            "corpus_id": "test",
            "sets": {
                "calibration": [
                    {"id": "b-cal", "label": "benign"},
                    {"id": "m-cal", "label": "malicious"},
                ],
                "held_out": [
                    {"id": "b-held", "label": "benign"},
                    {"id": "m-held", "label": "malicious"},
                ],
            },
        }

    def retained(self):
        corpus = self.corpus()
        scores = {
            ("calibration", "b-cal"): 0.9,
            ("calibration", "m-cal"): 0.8,
            ("held_out", "b-held"): 0.1,
            ("held_out", "m-held"): 0.7,
        }
        observations = []
        for (set_name, case_id), score in scores.items():
            for variant in ("pgv1", "pgv2"):
                observations.append({"set": set_name, "id": case_id, "variant": variant, "score": score})
        return {
            "schema_version": 1,
            "corpus_id": "test",
            "corpus_sha256": evaluator.corpus_sha256(corpus),
            "collected_at": "2026-09-16T00:00:00+00:00",
            "source_sha": "abc123",
            "endpoint": "http://127.0.0.1:8000",
            "state": {
                "active": "pgv2",
                "mode": "observe",
                "thresholds": {"pgv1": 0.5, "pgv2": 0.5},
                "models": {"pgv1": {"revision": "one"}, "pgv2": {"revision": "two"}},
                "runtime": {"python": "3.11"},
            },
            "observations": observations,
        }

    def test_reports_overlap_without_promoting_threshold(self):
        report = evaluator.evaluate(self.corpus(), self.retained())
        for variant in ("pgv1", "pgv2"):
            calibration = report["results"]["calibration"][variant]
            self.assertFalse(calibration["perfect_separation_exists"])
            self.assertIn("No threshold", calibration["separation_note"])
            self.assertEqual(calibration["counts"]["false_positive"], 1)
            held_out = report["results"]["held_out"][variant]
            self.assertTrue(held_out["perfect_separation_exists"])
        self.assertIn("no threshold is selected", report["claim_limit"])

    def test_requires_complete_per_variant_scores_and_provenance(self):
        retained = self.retained()
        retained["observations"].pop()
        with self.assertRaisesRegex(ValueError, "coverage mismatch"):
            evaluator.evaluate(self.corpus(), retained)
        retained = self.retained()
        del retained["source_sha"]
        with self.assertRaisesRegex(ValueError, "missing source_sha"):
            evaluator.evaluate(self.corpus(), retained)

    def test_rejects_corpus_content_or_label_change_under_same_id(self):
        corpus = self.corpus()
        retained = self.retained()
        corpus["sets"]["held_out"][0]["label"] = "malicious"
        with self.assertRaisesRegex(ValueError, "canonical corpus SHA256"):
            evaluator.evaluate(corpus, retained)

    def test_rejects_split_without_both_classes(self):
        corpus = self.corpus()
        corpus["sets"]["held_out"] = [{"id": "only-benign", "label": "benign"}]
        retained = self.retained()
        retained["corpus_sha256"] = evaluator.corpus_sha256(corpus)
        retained["observations"] = [row for row in retained["observations"] if row["set"] != "held_out"]
        for variant in ("pgv1", "pgv2"):
            retained["observations"].append({
                "set": "held_out", "id": "only-benign", "variant": variant, "score": 0.1,
            })
        with self.assertRaisesRegex(ValueError, "both benign and malicious"):
            evaluator.evaluate(corpus, retained)

    def test_rejects_nonfinite_scores(self):
        retained = self.retained()
        retained["observations"][0]["score"] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid score"):
            evaluator.evaluate(self.corpus(), retained)

    def test_checked_in_corpus_has_disjoint_ids_and_both_labels(self):
        corpus = json.loads((HERE / "calibration_corpus.json").read_text())
        calibration = corpus["sets"]["calibration"]
        held_out = corpus["sets"]["held_out"]
        self.assertFalse({case["id"] for case in calibration} & {case["id"] for case in held_out})
        for cases in (calibration, held_out):
            self.assertEqual({case["label"] for case in cases}, {"benign", "malicious"})
            self.assertTrue(all(case["text"] and case["provenance"] for case in cases))


if __name__ == "__main__":
    unittest.main()
