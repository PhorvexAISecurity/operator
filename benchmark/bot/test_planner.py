"""Offline tests for benchmark/bot/planner.py.

No network: a fake transport records the request payloads and returns canned
OpenAI responses. A throwaway repo supplies the brain source read at the base
commit. The guardrail under test is that only an in-scope unified diff ever
leaves the planner, and that the API key is never written out.
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
import planner  # noqa: E402

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "seed", "GIT_AUTHOR_EMAIL": "seed@example.invalid",
    "GIT_COMMITTER_NAME": "seed", "GIT_COMMITTER_EMAIL": "seed@example.invalid",
}
KEY = "sk-secret-value-should-never-be-logged"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True, env={**os.environ, **GIT_ENV}).stdout.strip()


def reply(content, finish="stop"):
    return {"choices": [{"message": {"content": content}, "finish_reason": finish}]}


def diff_for(path, old, new):
    return f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{old}\n+{new}\n"


class FakeTransport:
    """Returns queued responses; records every (url, headers, payload)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, payload, timeout):
        self.calls.append({"url": url, "headers": headers, "payload": payload, "timeout": timeout})
        if not self.responses:
            raise AssertionError("transport called more times than queued")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bot-planner-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp)
        self.repo = self.tmp / "work"
        (self.repo / "phorvex" / "internal" / "decision").mkdir(parents=True)
        (self.repo / "phorvex" / "internal" / "feasibility").mkdir(parents=True)
        (self.repo / "phorvex" / "tools").mkdir(parents=True)
        self.decision = "phorvex/internal/decision/decision.go"
        self.write(self.decision, "const RotateThreshold = 3")
        self.write("phorvex/internal/feasibility/limits.go", "const MaxRotate = 10")
        self.write("phorvex/internal/decision/decision_test.go", "package decision // test")
        self.write("phorvex/tools/gen.go", "package main")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.prompt = self.tmp / "prompt.txt"
        self.prompt.write_text("Raise the rotate threshold in the decision logic.\n")
        self.env = {"OPENAI_API_KEY": KEY, "OPENAI_MODEL": "test-model"}
        self._restore = {k: os.environ.get(k) for k in
                         ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL",
                          "OPENAI_REASONING_EFFORT", "OPENAI_TEMPERATURE")}
        self.addCleanup(self._restore_env)
        for k in self._restore:
            os.environ.pop(k, None)
        os.environ.update(self.env)

    def _restore_env(self):
        for k, v in self._restore.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def write(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")

    def args(self, context=None, max_attempts=2):
        return planner.parse_args([
            "--src-repo", str(self.repo), "--base-commit", self.base,
            "--prompt-file", str(self.prompt), "--out-diff", str(self.tmp / "brain.diff"),
            "--out", str(self.tmp / "PLAN.json"), "--max-attempts", str(max_attempts),
            *(a for c in (context or []) for a in ("--context", c)),
        ])

    def test_happy_path_writes_in_scope_diff_and_builds_request(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 9")
        transport = FakeTransport([reply(good)])
        record, diff_text = planner.plan(self.args(context=[self.decision]), transport)

        self.assertEqual(diff_text, good)
        self.assertEqual((self.tmp / "brain.diff").read_text(), good)
        self.assertEqual(record["attempts"][-1]["result"], "ok")
        self.assertTrue(record["diffFound"])
        self.assertEqual(record["model"], "test-model")
        self.assertEqual(record["baseUrl"], planner.DEFAULT_BASE_URL)

        call = transport.calls[0]
        self.assertEqual(call["url"], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(call["headers"]["Authorization"], f"Bearer {KEY}")
        self.assertEqual(call["payload"]["model"], "test-model")
        user = call["payload"]["messages"][1]["content"]
        self.assertIn("const RotateThreshold = 3", user, "base source is included as context")
        self.assertIn("Raise the rotate threshold", user)

    def test_api_key_is_never_written_to_disk(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 9")
        planner.plan(self.args(context=[self.decision]), FakeTransport([reply(good)]))
        for path in (self.tmp / "PLAN.json", self.tmp / "brain.diff"):
            self.assertNotIn(KEY, path.read_text(), path.name)
        self.assertNotIn(KEY, json.dumps(json.loads((self.tmp / "PLAN.json").read_text())))

    def test_retries_on_prose_then_succeeds(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 5")
        transport = FakeTransport([reply("Sure! Here is what I would change ..."), reply(good)])
        record, diff_text = planner.plan(self.args(context=[self.decision]), transport)
        self.assertEqual(diff_text, good)
        self.assertEqual([a["result"] for a in record["attempts"]], ["no diff", "ok"])
        # The second request carries the corrective note.
        self.assertIn("did not return a unified diff", transport.calls[1]["payload"]["messages"][1]["content"])

    def test_strips_a_diff_code_fence(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 7")
        transport = FakeTransport([reply("```diff\n" + good.strip() + "\n```")])
        _, diff_text = planner.plan(self.args(context=[self.decision]), transport)
        self.assertEqual(diff_text.strip(), good.strip())
        self.assertNotIn("```", diff_text)

    def test_out_of_scope_diff_is_rejected_and_retried(self):
        bad = diff_for("phorvex/tools/gen.go", "package main", "package main // hacked")
        test_edit = diff_for("phorvex/internal/decision/decision_test.go",
                             "package decision // test", "package decision // weakened")
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 4")
        transport = FakeTransport([reply(bad), reply(test_edit), reply(good)])
        record, diff_text = planner.plan(self.args(context=[self.decision], max_attempts=3), transport)
        self.assertEqual(diff_text, good)
        self.assertEqual([a["result"] for a in record["attempts"]], ["out of scope", "out of scope", "ok"])
        self.assertIn("phorvex/tools/gen.go", record["attempts"][0]["violations"])
        self.assertIn("out of scope", transport.calls[1]["payload"]["messages"][1]["content"])

    def test_never_emits_an_out_of_scope_diff_even_if_that_is_all_the_model_gives(self):
        bad = diff_for("deploy/docker/operator.Dockerfile", "FROM scratch", "FROM evil")
        transport = FakeTransport([reply(bad), reply(bad)])
        with self.assertRaises(planner.PlannerError) as cm:
            planner.plan(self.args(context=[self.decision], max_attempts=2), transport)
        self.assertEqual(cm.exception.code, 8)
        self.assertFalse((self.tmp / "brain.diff").exists(), "no diff file on failure")
        record = json.loads((self.tmp / "PLAN.json").read_text())
        self.assertFalse(record["diffFound"])
        self.assertEqual(len(record["attempts"]), 2)

    def test_model_declines_stops_early(self):
        transport = FakeTransport([reply("NO CHANGE POSSIBLE")])
        with self.assertRaises(planner.PlannerError) as cm:
            planner.plan(self.args(context=[self.decision], max_attempts=3), transport)
        self.assertEqual(cm.exception.code, 8)
        self.assertEqual(len(transport.calls), 1, "declining ends the loop")

    def test_ranked_context_selection_without_explicit_files(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 6")
        transport = FakeTransport([reply(good)])
        record, _ = planner.plan(self.args(), transport)  # no --context
        self.assertEqual(record["contextSelection"], "ranked")
        included = {c["path"] for c in record["contextFiles"]}
        # The prompt mentions "rotate"/"threshold"/"decision"; the decision file ranks in.
        self.assertIn(self.decision, included)
        self.assertNotIn("phorvex/internal/decision/decision_test.go", included, "tests never context")
        self.assertNotIn("phorvex/tools/gen.go", included, "tools never context")

    def test_context_budget_and_out_of_scope_requests_are_skipped(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 8")
        transport = FakeTransport([reply(good)])
        args = self.args(context=[self.decision, "phorvex/tools/gen.go",
                                  "phorvex/internal/decision/decision_test.go", "phorvex/does/not/exist.go"])
        record, _ = planner.plan(args, transport)
        reasons = {s["path"]: s["reason"] for s in record["contextSkipped"]}
        self.assertEqual(reasons["phorvex/tools/gen.go"], "out of scope")
        self.assertEqual(reasons["phorvex/internal/decision/decision_test.go"], "out of scope")
        self.assertEqual(reasons["phorvex/does/not/exist.go"], "absent at base commit")

    def test_optional_params_passed_through_only_when_set(self):
        good = diff_for(self.decision, "const RotateThreshold = 3", "const RotateThreshold = 2")
        transport = FakeTransport([reply(good)])
        planner.plan(self.args(context=[self.decision]), transport)
        self.assertNotIn("reasoning_effort", transport.calls[0]["payload"])
        self.assertNotIn("temperature", transport.calls[0]["payload"])

        os.environ["OPENAI_REASONING_EFFORT"] = "high"
        os.environ["OPENAI_TEMPERATURE"] = "0.2"
        os.environ["OPENAI_BASE_URL"] = "https://gateway.internal/v1"
        transport = FakeTransport([reply(good)])
        record, _ = planner.plan(self.args(context=[self.decision]), transport)
        self.assertEqual(transport.calls[0]["payload"]["reasoning_effort"], "high")
        self.assertEqual(transport.calls[0]["payload"]["temperature"], 0.2)
        self.assertEqual(transport.calls[0]["url"], "https://gateway.internal/v1/chat/completions")
        self.assertEqual(record["baseUrl"], "https://gateway.internal/v1")

    def test_missing_key_or_model_is_a_config_error(self):
        os.environ.pop("OPENAI_API_KEY")
        with self.assertRaises(planner.PlannerError) as cm:
            planner.plan(self.args(context=[self.decision]), FakeTransport([]))
        self.assertEqual(cm.exception.code, 2)
        os.environ["OPENAI_API_KEY"] = KEY
        os.environ.pop("OPENAI_MODEL")
        with self.assertRaises(planner.PlannerError) as cm:
            planner.plan(planner.parse_args([
                "--src-repo", str(self.repo), "--base-commit", self.base,
                "--prompt-file", str(self.prompt), "--out-diff", str(self.tmp / "x.diff")]),
                FakeTransport([]))
        self.assertEqual(cm.exception.code, 2)

    def test_transport_error_surfaces_as_code_9(self):
        transport = FakeTransport([planner.PlannerError(9, "OpenAI API request failed: timeout")])
        with self.assertRaises(planner.PlannerError) as cm:
            planner.plan(self.args(context=[self.decision]), transport)
        self.assertEqual(cm.exception.code, 9)


class ExtractDiffUnitTest(unittest.TestCase):
    def test_variants(self):
        body = "--- a/phorvex/x.go\n+++ b/phorvex/x.go\n@@ -1 +1 @@\n-a\n+b\n"
        self.assertEqual(planner.extract_diff(body).strip(), body.strip())
        self.assertEqual(planner.extract_diff("```diff\n" + body + "```").strip(), body.strip())
        self.assertEqual(planner.extract_diff("diff --git a/x b/x\n" + body).splitlines()[0], "diff --git a/x b/x")
        self.assertEqual(planner.extract_diff("just prose, no diff"), "")
        self.assertEqual(planner.extract_diff("NO CHANGE POSSIBLE"), "")
        self.assertEqual(planner.extract_diff(None), "")

    def test_scope_violations(self):
        ok = "--- a/phorvex/internal/decision/d.go\n+++ b/phorvex/internal/decision/d.go\n"
        self.assertEqual(planner.scope_violations(ok), [])
        bad = "--- a/go.mod\n+++ b/go.mod\n--- a/phorvex/tools/x.go\n+++ b/phorvex/tools/x.go\n"
        self.assertEqual(planner.scope_violations(bad), ["go.mod", "phorvex/tools/x.go"])


if __name__ == "__main__":
    unittest.main()
