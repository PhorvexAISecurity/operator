from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_operations import sandbox, workflow as w, run


def enable_v2(required: list[str] | None = None) -> bytes:
    marker = {
        "schema_version": 2,
        "discovery": {
            "status_glob": "*/STATUS.yaml",
            "aliases_file": "ALIASES.yaml",
            "exclude": ["_template"],
            "required_alias_metadata": sorted(required or []),
        },
    }
    w.write_yaml(w.FIXES / "INDEX.yaml", marker)
    return (w.FIXES / "INDEX.yaml").read_bytes()


class DerivedFixIndexTests(unittest.TestCase):
    def test_schema2_discovers_records_and_never_rewrites_marker(self):
        with sandbox():
            marker = enable_v2()
            fix = w.create_fix_record("FIX-ONE", [])
            self.assertEqual((w.FIXES / "INDEX.yaml").read_bytes(), marker)
            self.assertIn("FIX-ONE", w.load_fix_index()["fixes"])
            status = w.load_yaml(fix / "STATUS.yaml")
            status["roles"] = {
                "human_owner": "owner", "proposer": "author",
                "implementer": "author", "skeptic": "reviewer",
                "live_verifier": "reviewer", "coordinator": "coordinator",
            }
            w.write_yaml(fix / "STATUS.yaml", status)
            update = fix / "update.yaml"
            w.write_yaml(update, {"title": "Derived index fixture"})
            result = w.cmd_configure(argparse.Namespace(
                fix_id="FIX-ONE", file=str(update), by="coordinator",
                expect_revision=0, approval_ref=None,
            ))
            self.assertEqual(result, 0)
            self.assertEqual((w.FIXES / "INDEX.yaml").read_bytes(), marker)
            self.assertEqual(
                w.load_fix_index()["fixes"]["FIX-ONE"]["state"], "TRIAGED"
            )

    def test_alias_metadata_is_lossless_and_fails_closed(self):
        with sandbox():
            w.create_fix_record("FIX-ONE", [])
            w.create_fix_record("FIX-TWO", [])
            enable_v2(["FIX-ONE"])
            w.write_yaml(w.FIXES / "FIX-ONE" / "ALIASES.yaml", {
                "schema_version": 1, "fix_id": "FIX-ONE", "aliases": ["OLD-ONE"],
            })
            self.assertEqual(w.resolve_fix("OLD-ONE"), ["FIX-ONE"])
            (w.FIXES / "FIX-ONE" / "ALIASES.yaml").unlink()
            with self.assertRaisesRegex(ValueError, "missing required"):
                w.load_fix_index()
            w.write_yaml(w.FIXES / "FIX-ONE" / "ALIASES.yaml", {
                "schema_version": 1, "fix_id": "FIX-ONE", "aliases": ["OLD-ONE"],
            })
            w.write_yaml(w.FIXES / "FIX-TWO" / "ALIASES.yaml", {
                "schema_version": 1, "fix_id": "FIX-TWO", "aliases": ["OLD-ONE"],
            })
            with self.assertRaisesRegex(ValueError, "is shared"):
                w.load_fix_index()
            (w.FIXES / "FIX-TWO" / "ALIASES.yaml").unlink()
            orphan = w.FIXES / "ORPHAN"
            orphan.mkdir()
            w.write_yaml(orphan / "ALIASES.yaml", {
                "schema_version": 1, "fix_id": "ORPHAN", "aliases": ["OLD-X"],
            })
            with self.assertRaisesRegex(ValueError, "orphan"):
                w.load_fix_index()

    def test_malformed_marker_and_discovered_identity_fail_closed(self):
        with sandbox():
            w.create_fix_record("FIX-ONE", [])
            enable_v2()
            marker = w.load_yaml(w.FIXES / "INDEX.yaml")
            marker["discovery"]["required_alias_metadata"] = [["not-a-string"]]
            w.write_yaml(w.FIXES / "INDEX.yaml", marker)
            with self.assertRaisesRegex(ValueError, "sorted and unique"):
                w.load_fix_index()
            enable_v2()
            status_path = w.FIXES / "FIX-ONE" / "STATUS.yaml"
            status = w.load_yaml(status_path)
            status["fix_id"] = "WRONG"
            w.write_yaml(status_path, status)
            with self.assertRaisesRegex(ValueError, "fix_id mismatch"):
                w.load_fix_index()

    def test_failed_schema2_refresh_rolls_back_status_and_marker(self):
        with sandbox():
            fix = w.create_fix_record("FIX-ONE", [])
            marker = enable_v2(["FIX-ONE"])
            status = w.load_yaml(fix / "STATUS.yaml")
            status["roles"] = {
                "human_owner": "owner", "proposer": "author",
                "implementer": "author", "skeptic": "reviewer",
                "live_verifier": "reviewer", "coordinator": "coordinator",
            }
            w.write_yaml(fix / "STATUS.yaml", status)
            before = (fix / "STATUS.yaml").read_bytes()
            update = fix / "update.yaml"
            w.write_yaml(update, {"title": "Must roll back"})
            self.assertEqual(w.cmd_configure(argparse.Namespace(
                fix_id="FIX-ONE", file=str(update), by="coordinator",
                expect_revision=0, approval_ref=None,
            )), 1)
            self.assertEqual((fix / "STATUS.yaml").read_bytes(), before)
            self.assertEqual((w.FIXES / "INDEX.yaml").read_bytes(), marker)

    def test_independent_fix_branches_merge_without_index_edits(self):
        with sandbox() as (repo, _, _):
            marker = enable_v2()
            run(["git", "add", "workflow/fixes/INDEX.yaml"], repo)
            run(["git", "commit", "-m", "use derived fix index fixture"], repo)
            base = run(["git", "rev-parse", "HEAD"], repo)
            create_heads = []
            for branch, fix_id in (("create-one", "FIX-ONE"), ("create-two", "FIX-TWO")):
                run(["git", "checkout", "-B", branch, base], repo)
                w.create_fix_record(fix_id, [])
                run(["git", "add", f"workflow/fixes/{fix_id}"], repo)
                run(["git", "commit", "-m", f"create {fix_id}"], repo)
                changed = run(["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"], repo)
                self.assertNotIn("workflow/fixes/INDEX.yaml", changed.splitlines())
                create_heads.append(run(["git", "rev-parse", "HEAD"], repo))
            run(["git", "checkout", "-B", "integration", base], repo)
            for head in create_heads:
                run(["git", "merge", "--no-edit", head], repo)
            self.assertEqual((w.FIXES / "INDEX.yaml").read_bytes(), marker)
            self.assertEqual(set(w.load_fix_index()["fixes"]), {"FIX-ONE", "FIX-TWO"})
            merged = run(["git", "rev-parse", "HEAD"], repo)
            update_heads = []
            for branch, fix_id in (("update-one", "FIX-ONE"), ("update-two", "FIX-TWO")):
                run(["git", "checkout", "-B", branch, merged], repo)
                path = w.FIXES / fix_id / "STATUS.yaml"
                status = w.load_yaml(path)
                status["next_action"]["action"] = f"Continue {fix_id}."
                w.write_yaml(path, status)
                run(["git", "add", str(path.relative_to(repo))], repo)
                run(["git", "commit", "-m", f"update {fix_id}"], repo)
                update_heads.append(run(["git", "rev-parse", "HEAD"], repo))
            run(["git", "checkout", "integration"], repo)
            for head in update_heads:
                run(["git", "merge", "--no-edit", head], repo)
            self.assertEqual((w.FIXES / "INDEX.yaml").read_bytes(), marker)
            self.assertEqual(set(w.load_fix_index()["fixes"]), {"FIX-ONE", "FIX-TWO"})


if __name__ == "__main__":
    unittest.main()
