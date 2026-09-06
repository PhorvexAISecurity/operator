from __future__ import annotations

import importlib.util
import hashlib
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "workflow.py"
SPEC = importlib.util.spec_from_file_location("phorvex_workflow_tool", TOOL)
assert SPEC and SPEC.loader
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)


class WorkflowIntegrityTests(unittest.TestCase):
    def test_issue_split_is_lossless(self) -> None:
        _, metadata, tokens = workflow.render_base()
        legacy = (
            workflow.ROOT
            / "archive"
            / "register-v1"
            / "PHORVEX_MASTER_ISSUES.md"
        ).read_text(encoding="utf-8")
        legacy_layout, legacy_entries, legacy_order = workflow.split_legacy_register(
            legacy
        )
        current_layout = (workflow.ISSUES / "layout.md").read_text(encoding="utf-8")
        self.assertEqual(current_layout, legacy_layout)
        self.assertEqual(tokens, legacy_order)
        for issue_id, body in legacy_entries.items():
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            self.assertEqual(metadata[issue_id]["migration_body_sha256"], digest)
        self.assertEqual(len(tokens), 159)
        self.assertEqual(len(metadata), 159)
        self.assertEqual(len(tokens), len(set(tokens)))

    def test_master_is_reproducible(self) -> None:
        current = (workflow.ISSUES / "MASTER_ISSUES.md").read_text(encoding="utf-8")
        self.assertEqual(current, workflow.render_master())

    def test_active_issue_resolution(self) -> None:
        self.assertEqual(workflow.resolve_fix("M-160"), ["T1-M160"])
        self.assertEqual(workflow.resolve_fix("T1-M023"), ["T1-M023"])
        self.assertIn("T1-M020", workflow.resolve_fix("M-20"))

    def test_all_indexed_statuses_have_next_action(self) -> None:
        index = workflow.load_yaml(workflow.FIXES / "INDEX.yaml")
        self.assertEqual(index, workflow.synchronized_index(index))
        for fix_id in index["fixes"]:
            status = workflow.load_yaml(workflow.FIXES / fix_id / "STATUS.yaml")
            self.assertEqual(status["fix_id"], fix_id)
            self.assertIn(status["state"], workflow.ALLOWED_STATES)
            self.assertTrue(status["next_action"]["action"])

    def test_fix_ids_cannot_escape_fix_root(self) -> None:
        for unsafe in ("../escape", "/tmp/escape", "_template", "bad id"):
            with self.assertRaises(ValueError):
                workflow.validate_fix_id(unsafe)

    def test_human_gate_and_transition_prerequisites_are_explicit(self) -> None:
        self.assertIn("IN_PR", workflow.HUMAN_GATED_STATES)
        self.assertIn("DEPLOYED", workflow.HUMAN_GATED_STATES)
        status = workflow.load_yaml(workflow.FIXES / "T1-M160" / "STATUS.yaml")
        missing = workflow.transition_prerequisites(
            workflow.FIXES / "T1-M160", status, "IN_PR"
        )
        self.assertIn("pull_request.url", missing)


if __name__ == "__main__":
    unittest.main()
