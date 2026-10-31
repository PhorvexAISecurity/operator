"""The planner -> candidate handoff, offline and end to end.

A fake OpenAI transport yields a diff; the planner writes it; candidate.py
lands it on a throwaway branch and tag. This proves the two modules agree on
the diff contract and on the edit scope, without a network or a build.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate  # noqa: E402
import planner  # noqa: E402

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "seed", "GIT_AUTHOR_EMAIL": "seed@example.invalid",
    "GIT_COMMITTER_NAME": "seed", "GIT_COMMITTER_EMAIL": "seed@example.invalid",
}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True, env={**os.environ, **GIT_ENV}).stdout.strip()


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bot-pipeline-"))
        self.addCleanup(lambda: subprocess.run(["chmod", "-R", "u+w", str(self.tmp)])
                        or __import__("shutil").rmtree(self.tmp))
        self.repo = self.tmp / "work"
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.path = "phorvex/internal/decision/decision.go"
        (self.repo / "phorvex" / "internal" / "decision").mkdir(parents=True)
        (self.repo / self.path).write_text("const RotateThreshold = 3\n")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        git(self.repo, "tag", "-a", "-m", "base", "manager-v0.11.0")
        self.base = git(self.repo, "rev-parse", "HEAD")
        for k, v in (("OPENAI_API_KEY", "sk-x"), ("OPENAI_MODEL", "test-model")):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)

    def test_planner_diff_is_landed_by_candidate(self):
        diff_text = (f"--- a/{self.path}\n+++ b/{self.path}\n@@ -1 +1 @@\n"
                     "-const RotateThreshold = 3\n+const RotateThreshold = 11\n")
        prompt = self.tmp / "prompt.txt"
        prompt.write_text("Raise the rotate threshold.\n")

        def transport(url, headers, payload, timeout):
            return {"choices": [{"message": {"content": diff_text}, "finish_reason": "stop"}]}

        plan_args = planner.parse_args([
            "--src-repo", str(self.repo), "--base-commit", self.base, "--prompt-file", str(prompt),
            "--out-diff", str(self.run_dir / "brain.diff"), "--out", str(self.run_dir / "PLAN.json"),
            "--context", self.path])
        planner.plan(plan_args, transport)

        code = candidate.main([
            "--src-repo", str(self.repo), "--run-dir", str(self.run_dir), "--run-id", "abc123",
            "--base-tag", "manager-v0.11.0", "--base-commit", self.base,
            "--diff", str(self.run_dir / "brain.diff"), "--prompt-file", str(prompt),
            "--planner", "openai", "--model", "test-model", "--out", str(self.run_dir / "CANDIDATE.json")])
        self.assertEqual(code, 0)

        record = json.loads((self.run_dir / "CANDIDATE.json").read_text())
        clone = record["repo"]
        self.assertEqual(record["changedPaths"], [{"status": "M", "path": self.path}])
        self.assertEqual(git(clone, "show", f"{record['candidateTag']}:{self.path}"), "const RotateThreshold = 11")
        # The chain of identities build-image.sh will be given.
        self.assertEqual(git(clone, "rev-parse", f"refs/tags/{record['candidateTag']}^{{commit}}"),
                         record["candidateCommit"])


if __name__ == "__main__":
    unittest.main()
