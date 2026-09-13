"""The three outputs have to make the same claim.

JSON is the record, the HTML dashboard is what a person opens, and the Markdown is what
lands on the pull request — and the Markdown is the one most likely to be read alone. A
green word there over a run that observed nothing is the failure mode this file exists to
prevent, so the summary is driven as a real subprocess over a document the real pipeline
produced.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import fixtures as F
import report
from run_output import SCHEMA, SCHEMA_ACCEPTED

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "summary.py"


def markdown(path, *args):
    return subprocess.run([sys.executable, str(SUMMARY), str(path), *args],
                          text=True, capture_output=True, timeout=30)


class SchemaAgreementTests(unittest.TestCase):
    def test_the_pr_comment_accepts_the_schema_the_pipeline_writes(self):
        source = SUMMARY.read_text()
        self.assertIn(repr(SCHEMA_ACCEPTED[0]), source)
        self.assertIn(SCHEMA, SCHEMA_ACCEPTED)
        # The migration promise: the previous schema still renders.
        self.assertIn("phorvex.e2e/1", source)

    def test_a_previous_schema_document_still_renders(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.json"
            path.write_text(json.dumps({
                "schema": "phorvex.e2e/1", "verdict": "PASS", "checks": [], "tally": {},
                "counts": {"records": 3}, "mode": "observe"}))
            got = markdown(path)
            self.assertEqual(got.returncode, 0, got.stderr)
            self.assertIn("All contracts held", got.stdout)


class AgreementTests(unittest.TestCase):
    """One real run, rendered three ways."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        records = [F.record(namespace="voice", pod="voice-a"),
                   F.record(namespace="voice", pod="voice-b", stage="exploit",
                            nextStage="persist", reason="second explanation")]
        cls.doc, cls.rc = F.run_offline(cls.root, records=records, run_id="agreement")
        cls.json_path = cls.root / "run-agreement.json"
        cls.html = (cls.root / "run-agreement.html").read_text()
        cls.md = markdown(cls.json_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_the_run_completed_and_wrote_a_matching_json_pair(self):
        self.assertEqual(json.loads(self.json_path.read_text()), self.doc)
        self.assertEqual(self.doc["schema"], SCHEMA)
        self.assertEqual(self.md.returncode, 0, self.md.stderr)

    def test_the_verdict_is_identical_in_all_three(self):
        verdict = self.doc["verdict"]
        self.assertIn(verdict, self.html)
        self.assertIn(f"**{verdict}**", self.md.stdout)

    def test_the_tally_is_identical_in_all_three(self):
        tally = self.doc["tally"]
        rendered = report.render(self.doc)
        for key in ("pass", "fail", "warn", "skip"):
            self.assertIn(f"<b>{tally[key]}</b>", rendered)
        lines = self.md.stdout.splitlines()
        header = next(i for i, line in enumerate(lines) if line.startswith("| Passed |"))
        numbers = [cell.strip() for cell in lines[header + 2].split("|")[1:5]]
        self.assertEqual(numbers, [str(tally[k]) for k in ("pass", "fail", "warn", "skip")])

    def test_coverage_is_reported_in_all_three(self):
        coverage = self.doc["coverage"]
        self.assertGreater(coverage["full"] + coverage["partial"], 0)
        self.assertIn("Check coverage", self.html)
        self.assertIn("Full cov.", self.md.stdout)

    def test_the_declared_capture_scope_travels_to_the_reader(self):
        scope = self.doc["capture"]["scope"]
        self.assertFalse(scope["global"])
        self.assertEqual(scope["namespaces"], ["voice"])
        self.assertIn("Capture scope", self.html)
        self.assertIn("Capture scope: `voice`", self.md.stdout)
        self.assertIn("not the whole cluster", self.md.stdout)

    def test_every_check_carries_its_coverage_into_the_json(self):
        for check in self.doc["checks"]:
            with self.subTest(check=check["id"]):
                self.assertIn(check["coverage"],
                              ("full", "partial", "none", "not-applicable"))
                self.assertIn("inputs", check)


class HonestHeadlineTests(unittest.TestCase):
    def base(self):
        return {"schema": SCHEMA, "verdict": "PASS", "checks": [], "tally": {},
                "counts": {"records": 5}, "mode": "observe",
                "coverage": {"full": 39, "criticalUnobserved": []},
                "capture": {"complete": True, "scope": {"global": True}}}

    def render(self, doc, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            path.write_text(json.dumps(doc))
            return markdown(path, *args)

    def test_a_pass_over_an_incomplete_window_is_refused_not_rendered(self):
        doc = self.base()
        doc["capture"] = {"complete": False, "reason": "the stream stopped mid-frame"}
        got = self.render(doc)
        self.assertEqual(got.returncode, 1)
        self.assertIn("ABORTED", got.stdout)
        self.assertNotIn("All contracts held", got.stdout)

    def test_a_pass_over_an_unobserved_critical_contract_is_refused(self):
        doc = self.base()
        doc["coverage"] = {"full": 38, "criticalUnobserved": ["A06"]}
        got = self.render(doc)
        self.assertEqual(got.returncode, 1)
        self.assertIn("ABORTED", got.stdout)

    def test_a_warn_over_an_incomplete_window_states_the_hole(self):
        doc = dict(self.base(), verdict="WARN")
        doc["capture"] = {"complete": False, "reason": "the stream stopped mid-frame"}
        doc["coverage"] = {"full": 30, "none": 2, "criticalUnobserved": ["A06", "B07"]}
        got = self.render(doc)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("was not fully captured", got.stdout)
        self.assertIn("stopped mid-frame", got.stdout)
        self.assertIn("could not be observed at all", got.stdout)
        self.assertIn("`A06`", got.stdout)
        self.assertIn("unavailable, not satisfied", got.stdout)

    def test_unavailable_attribution_is_stated_rather_than_implied(self):
        doc = dict(self.base(), verdict="WARN")
        doc["attribution"] = {"support": "event-name", "supported": False,
                              "reason": "no forensic event UID (PR171/M18)"}
        got = self.render(doc)
        self.assertIn("Causal attribution unavailable", got.stdout)
        self.assertIn("not as a defended attack", got.stdout)

    def test_ground_truth_evidence_and_attribution_are_columns_of_their_own(self):
        doc = dict(self.base(), verdict="WARN")
        doc["groundTruth"] = [
            {"verdict": "confirmed", "action": "rotate", "namespace": "voice",
             "pod": "voice-a", "detail": "successor is Ready",
             "evidenceLevel": "object-identity", "effectObserved": True,
             "attribution": "unsupported"},
            {"verdict": "confirmed", "action": "quarantine", "namespace": "voice",
             "pod": "voice-b", "detail": "a deny-all policy selects the pod",
             "evidenceLevel": "configuration", "effectObserved": False,
             "attribution": "unsupported"}]
        got = self.render(doc)
        self.assertIn("| verdict | evidence | attribution |", got.stdout)
        self.assertIn("| confirmed | object-identity | unsupported |", got.stdout)
        # The one that matters: a configured policy must not read as measured isolation.
        self.assertIn("| confirmed | configuration (not measured) | unsupported |", got.stdout)

    def test_a_skipped_check_shows_whether_it_was_unobservable_or_irrelevant(self):
        doc = dict(self.base(), verdict="WARN")
        doc["checks"] = [
            {"id": "A03", "title": "cluster confirms", "summary": "nothing actuated",
             "status": "skip", "coverage": "not-applicable"},
            {"id": "A06", "title": "kill switch", "summary": "scrape refused",
             "status": "skip", "coverage": "none"}]
        doc["tally"] = {"skip": 2}
        got = self.render(doc)
        self.assertIn("`A03` [not-applicable]", got.stdout)
        self.assertIn("`A06` [none]", got.stdout)


if __name__ == "__main__":
    unittest.main()
