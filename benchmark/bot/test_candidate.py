"""Offline tests for benchmark/bot/candidate.py.

A throwaway working repository stands in for the real one: a tiny phorvex/ tree
whose HEAD has moved past a base tag and whose working copy is dirty, so a
candidate built from the wrong place, or one that writes back to the working
repo, is visible. No network and no LLM: the diff is supplied directly.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate  # noqa: E402

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "seed", "GIT_AUTHOR_EMAIL": "seed@example.invalid",
    "GIT_COMMITTER_NAME": "seed", "GIT_COMMITTER_EMAIL": "seed@example.invalid",
}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True, env={**os.environ, **GIT_ENV}).stdout.strip()


def diff_replacing(path, old, new):
    return textwrap.dedent(f"""\
        --- a/{path}
        +++ b/{path}
        @@ -1 +1 @@
        -{old}
        +{new}
        """)


class CandidateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bot-candidate-"))
        self.addCleanup(lambda: subprocess.run(["chmod", "-R", "u+w", str(self.tmp)]) or __import__("shutil").rmtree(self.tmp))
        self.repo = self.tmp / "work"
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        (self.repo / "phorvex" / "internal" / "decision").mkdir(parents=True)
        (self.repo / "phorvex" / "tools" / "servicerelease").mkdir(parents=True)
        self.decision = "phorvex/internal/decision/decision.go"
        self.tool = "phorvex/tools/servicerelease/main.go"
        self.test_file = "phorvex/internal/decision/decision_test.go"
        self.outside = "deploy/docker/operator.Dockerfile"
        self.write(self.decision, "const Threshold = 1")
        self.write(self.test_file, "package decision // test")
        self.write(self.tool, "package main // tool")
        (self.repo / "deploy" / "docker").mkdir(parents=True)
        self.write(self.outside, "FROM scratch")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        git(self.repo, "tag", "-a", "-m", "base", "manager-v0.11.0")
        self.base = git(self.repo, "rev-parse", "HEAD")
        # HEAD moves on, and the working tree is left dirty and with junk.
        self.write(self.decision, "const Threshold = 999")
        git(self.repo, "commit", "-q", "-am", "later")
        self.write(self.decision, "const Threshold = 7")
        self.write("phorvex/untracked.go", "package decision")

    def write(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")

    def work_state(self):
        return (git(self.repo, "status", "--porcelain=v1", "-uall"),
                git(self.repo, "for-each-ref"), git(self.repo, "rev-parse", "HEAD"),
                (self.repo / self.decision).read_text())

    def invoke(self, diff_text, *, run_id="a1b2c3", base_tag="manager-v0.11.0",
            base_commit=None, out=True, extra=None):
        diff_file = self.tmp / f"{run_id}.diff"
        diff_file.write_text(diff_text)
        argv = ["--src-repo", str(self.repo), "--run-dir", str(self.run_dir), "--run-id", run_id,
                "--base-tag", base_tag, "--base-commit", base_commit or self.base,
                "--diff", str(diff_file), "--planner", "stub", "--model", "stub-1"]
        if out:
            argv += ["--out", str(self.run_dir / f"CANDIDATE-{run_id}.json")]
        if extra:
            argv += extra
        return candidate.main(argv)

    def capture(self, *a, **k):
        from io import StringIO
        out, err = StringIO(), StringIO()
        old = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = self.invoke(*a, **k)
        finally:
            sys.stdout, sys.stderr = old
        return code, out.getvalue(), err.getvalue()

    def test_lands_an_in_scope_change_on_a_candidate_branch_and_tag(self):
        before = self.work_state()
        code, out, err = self.capture(diff_replacing(self.decision, "const Threshold = 1", "const Threshold = 42"))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "bench-a1b2c3")

        record = json.loads((self.run_dir / "CANDIDATE-a1b2c3.json").read_text())
        clone = Path(record["repo"])
        self.assertEqual(record["candidateBranch"], "bench-candidate/a1b2c3")
        self.assertEqual(record["candidateTag"], "bench-a1b2c3")
        self.assertEqual(record["baseCommit"], self.base)
        self.assertEqual(record["changedPaths"], [{"status": "M", "path": self.decision}])
        self.assertEqual(record["planner"], "stub")
        # The candidate is built from the base, not HEAD or the dirty tree.
        self.assertEqual(git(clone, "rev-parse", "bench-a1b2c3^{commit}"), record["candidateCommit"])
        self.assertEqual(git(clone, "rev-parse", f"{record['candidateCommit']}~1"), self.base)
        self.assertEqual((clone / self.decision).read_text(), "const Threshold = 42\n")
        self.assertNotRegex(record["candidateTag"], r"^(manager|brain|sensor|actuator|console|attacks)-v")
        author = git(clone, "log", "-1", "--format=%an <%ae>", record["candidateCommit"])
        self.assertEqual(author, "phorvex-benchmark-bot <benchmark-bot@phorvex.invalid>")
        self.assertNotIn("Co-authored-by", git(clone, "log", "-1", "--format=%B", record["candidateCommit"]))
        # The working repository is untouched.
        self.assertEqual(self.work_state(), before)

    def test_candidate_is_consumable_by_build_image_contract(self):
        self.capture(diff_replacing(self.decision, "const Threshold = 1", "const Threshold = 2"))
        record = json.loads((self.run_dir / "CANDIDATE-a1b2c3.json").read_text())
        clone = record["repo"]
        # build-image.sh resolves the tag to the commit from the candidate repo.
        self.assertEqual(git(clone, "rev-parse", "--verify", f"refs/tags/{record['candidateTag']}^{{commit}}"),
                         record["candidateCommit"])
        # The Dockerfile is inherited from the base, unchanged, so no drift.
        self.assertEqual(git(clone, "show", f"{record['candidateCommit']}:{self.outside}"),
                         git(self.repo, "show", f"{self.base}:{self.outside}"))

    def test_out_of_scope_paths_are_refused(self):
        cases = [
            (diff_replacing(self.outside, "FROM scratch", "FROM evil"), "out of scope"),
            (diff_replacing(self.tool, "package main // tool", "package main // hacked"), "out of scope"),
            (diff_replacing(self.test_file, "package decision // test", "package decision // weakened"), "out of scope"),
        ]
        for diff_text, needle in cases:
            with self.subTest(needle=diff_text.splitlines()[0]):
                code, _, err = self.capture(diff_text, run_id="bbbbbb", out=False)
                self.assertEqual(code, 5, err)
                self.assertIn(needle, err)
                # A refused candidate is cleaned up, so the next attempt is clean.
                self.assertFalse((self.run_dir / "candidate-src").exists())

    def test_new_go_file_in_scope_is_allowed(self):
        diff_text = textwrap.dedent("""\
            --- /dev/null
            +++ b/phorvex/internal/decision/extra.go
            @@ -0,0 +1 @@
            +package decision
            """)
        code, out, err = self.capture(diff_text)
        self.assertEqual(code, 0, err)
        record = json.loads((self.run_dir / "CANDIDATE-a1b2c3.json").read_text())
        self.assertEqual(record["changedPaths"], [{"status": "A", "path": "phorvex/internal/decision/extra.go"}])

    def test_new_file_outside_scope_is_refused(self):
        diff_text = textwrap.dedent("""\
            --- /dev/null
            +++ b/phorvex/internal/decision/notes.txt
            @@ -0,0 +1 @@
            +just notes
            """)
        code, _, err = self.capture(diff_text, out=False)
        self.assertEqual(code, 5, err)
        self.assertIn("out of scope", err)

    def test_deletion_is_refused_unless_allowed(self):
        diff_text = textwrap.dedent(f"""\
            --- a/{self.decision}
            +++ /dev/null
            @@ -1 +0,0 @@
            -const Threshold = 1
            """)
        code, _, err = self.capture(diff_text, out=False)
        self.assertEqual(code, 5, err)
        self.assertIn("deletion not allowed", err)
        code, _, err = self.capture(diff_text, run_id="cccccc", extra=["--allow-delete"])
        self.assertEqual(code, 0, err)

    def test_diff_that_does_not_apply(self):
        code, _, err = self.capture(diff_replacing(self.decision, "const Threshold = THISISWRONG", "x"), out=False)
        self.assertEqual(code, 4, err)
        self.assertIn("does not apply", err)

    def test_empty_and_noop_diffs(self):
        code, _, err = self.capture("\n   \n", out=False)
        self.assertEqual(code, 6, err)
        self.assertIn("empty", err)

    def test_base_tag_must_resolve_to_base_commit(self):
        head = git(self.repo, "rev-parse", "HEAD")
        code, _, err = self.capture(diff_replacing(self.decision, "const Threshold = 1", "const Threshold = 3"),
                                    base_commit=head, out=False)
        self.assertEqual(code, 3, err)
        self.assertIn("does not resolve to --base-commit", err)

    def test_run_dir_must_be_outside_the_working_repo(self):
        inside = self.repo / "run"
        inside.mkdir()
        diff_file = self.tmp / "d.diff"
        diff_file.write_text(diff_replacing(self.decision, "const Threshold = 1", "const Threshold = 9"))
        code = candidate.main(["--src-repo", str(self.repo), "--run-dir", str(inside), "--run-id", "a1b2c3",
                               "--base-tag", "manager-v0.11.0", "--base-commit", self.base, "--diff", str(diff_file)])
        self.assertEqual(code, 2)

    def test_bad_arguments(self):
        diff_file = self.tmp / "d.diff"
        diff_file.write_text(diff_replacing(self.decision, "const Threshold = 1", "const Threshold = 9"))
        base = ["--src-repo", str(self.repo), "--run-dir", str(self.run_dir), "--diff", str(diff_file)]
        for extra in (["--run-id", "A1B2C3", "--base-tag", "manager-v0.11.0", "--base-commit", self.base],
                      ["--run-id", "a1b2c3", "--base-tag", "manager-v0.11.0", "--base-commit", self.base[:12]]):
            with self.subTest(extra=extra):
                self.assertEqual(candidate.main(base + extra), 2)


class ScopeUnitTest(unittest.TestCase):
    def test_in_scope(self):
        for path in ("phorvex/internal/decision/decision.go", "phorvex/cmd/brain/main.go"):
            self.assertTrue(candidate.in_scope(path), path)
        for path in ("phorvex/tools/servicerelease/main.go", "phorvex/internal/decision/decision_test.go",
                     "deploy/docker/operator.Dockerfile", "phorvex/go.mod", "benchmark/bot/candidate.py",
                     "phorvex/README.md", "phorvex", "go.mod"):
            self.assertFalse(candidate.in_scope(path), path)


if __name__ == "__main__":
    unittest.main()
