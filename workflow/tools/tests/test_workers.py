"""Runner regression tests drive a fake Claude executable; no real model, session or bus is contacted."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

COORD = Path(__file__).resolve().parents[2] / "coordination"
sys.path.insert(0, str(COORD))
import workers

DEFAULT_RUNTIME = workers.RUNTIME
TERMINAL = workers.TERMINAL_STATES
FIXTURES = Path(__file__).resolve().parent / "fixtures"
DENIED_STREAM = FIXTURES / "claude-stream-permission-denied.jsonl"

FAKE_CLAUDE = r'''#!/usr/bin/env python3
"""Stands in for the Claude CLI: records its argv and emits stream-json events."""
import json, os, signal, subprocess, sys, time, uuid

argv = sys.argv[1:]
mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")


def value(name):
    return argv[argv.index(name) + 1] if name in argv else None


session = value("--session-id") or value("--resume")
prompt = sys.stdin.read()
with open(os.environ["FAKE_CLAUDE_LOG"], "a") as log:
    log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "session": session,
                          "resumed": "--resume" in argv, "prompt": prompt,
                          "pid": os.getpid(), "mode": mode}) + "\n")


def emit(event):
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


if mode == "auth_error":
    sys.stderr.write("Invalid API key - please run /login\n")
    sys.exit(1)

if mode == "replay":
    # Real recorded event shapes, sanitized; only the session id is substituted.
    for line in open(os.environ["FAKE_CLAUDE_REPLAY"]):
        if line.strip():
            sys.stdout.write(line.replace("SESSION", session))
    sys.stdout.flush()
    sys.exit(0)

if mode == "descendant":
    # A same-group child that ignores SIGTERM, like a real tool subprocess.
    descendant = subprocess.Popen([sys.executable, "-c",
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
    with open(os.environ["FAKE_CLAUDE_LOG"] + ".descendant", "w") as marker:
        marker.write(str(descendant.pid))

reported = "claude-sonnet-5" if mode == "other_model" else "claude-opus-5-fake"
if mode != "no_init":
    emit({"type": "system", "subtype": "init", "session_id": session, "model": reported})
if mode in ("hang", "descendant"):
    time.sleep(600)
    sys.exit(0)
emit({"type": "assistant", "session_id": session,
      "message": {"model": reported, "content": [{"type": "text", "text": "working"}]}})
if mode == "denied":
    emit({"type": "user", "session_id": session, "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_1", "is_error": True,
         "content": "Permission denied: Bash(rm:*) requested permissions"}]}})
if mode == "non_object":
    sys.stdout.write(json.dumps("a bare string line") + "\n")
    sys.stdout.flush()
if mode == "kill":
    os.kill(os.getpid(), signal.SIGKILL)
if mode == "no_result":
    sys.exit(0)
result = {"type": "result", "subtype": "success", "is_error": False, "session_id": session,
          "result": "implementation finished; awaiting lead review", "num_turns": 2,
          "model": reported}
if mode == "mismatch":
    result["session_id"] = str(uuid.uuid4())
if mode == "error_result":
    result.update(subtype="error_during_execution", is_error=True, result="tool loop failed")
if mode == "plain_result":
    result = {"type": "result", "session_id": session, "result": "done"}
if mode == "null_result_text":
    result["result"] = None
if mode == "no_error_flag":
    result.pop("is_error")
if mode == "denied":
    result["permission_denials"] = [{"tool_name": "Bash", "tool_use_id": "toolu_1",
                                     "tool_input": {"command": "rm -rf /"}}]
emit(result)
if mode == "two_results":
    emit(dict(result, result="a second, conflicting final result"))
sys.exit({"error_result": 1, "nonzero": 3}.get(mode, 0))
'''


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        # `git init` honours the host umask, so on this multi-user host the
        # fixture's common directory would be group-writable and the runner
        # would rightly refuse it. Make the fixture private instead of relaxing
        # the production check.
        (self.repo / ".git").chmod(0o700)
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--allow-empty", "-qm", "fixture")
        self.peer = root / "peer"
        self.git("worktree", "add", "-q", "--detach", str(self.peer), "HEAD")
        self.bus = self.repo / "workflow" / "coordination" / "bus.py"
        self.bus.parent.mkdir(parents=True)
        self.bus.write_text("# stub bus CLI; never executed in tests\n")
        self.runtime = root / "runtime"
        for name, value in {"RUNTIME": self.runtime, "COMMON_DIR": self.repo / ".git"}.items():
            patcher = patch.object(workers, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.claude = root / "bin" / "claude"
        self.claude.parent.mkdir()
        self.claude.write_text(FAKE_CLAUDE)
        self.claude.chmod(0o755)
        self.log = root / "fake-claude.log"
        os.environ["FAKE_CLAUDE_LOG"] = str(self.log)
        os.environ["FAKE_CLAUDE_MODE"] = "ok"
        os.environ["FAKE_CLAUDE_REPLAY"] = str(DENIED_STREAM)
        self.addCleanup(os.environ.pop, "FAKE_CLAUDE_LOG", None)
        self.addCleanup(os.environ.pop, "FAKE_CLAUDE_MODE", None)
        self.addCleanup(os.environ.pop, "FAKE_CLAUDE_REPLAY", None)
        self.addCleanup(self.kill_survivors)
        self.prompt = root / "prompt.md"
        self.prompt.write_text("Implement the approved plan and report honestly.\n")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True)

    def kill_survivors(self):
        with contextlib.suppress(SystemExit):
            for job in workers.load_state()["jobs"].values():
                for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
                    if workers.process_alive(job.get(pid_key), job.get(start_key)):
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(job[pid_key], signal.SIGKILL)
        for directory in (self.runtime / "jobs").glob("*"):
            child = workers.read_json(directory / "child.json")
            for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
                if workers.process_alive(child.get(pid_key), child.get(start_key)):
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child[pid_key], signal.SIGKILL)
        marker = Path(str(self.log) + ".descendant")
        if marker.exists():
            with contextlib.suppress(ValueError, ProcessLookupError, OSError):
                os.kill(int(marker.read_text()), signal.SIGKILL)
        for _ in range(100):
            workers.reap()
            if not workers.SPAWNED:
                break
            time.sleep(0.02)

    # --- helpers -------------------------------------------------------------

    def register(self, worker="w1", worktree=None, role="implementer", extra=()):
        return workers.main(["register", "--worker", worker,
                             "--worktree", str(worktree or self.repo), "--role", role,
                             "--model", "claude-opus-5", "--allow-tool", "Read", *extra])

    def enqueue(self, worker="w1", key="j1", prompt=None, extra=()):
        return workers.main(["enqueue", "--worker", worker, "--key", key,
                             "--prompt-file", str(prompt or self.prompt), *extra])

    def pass_once(self, mode="ok", concurrency=3):
        os.environ["FAKE_CLAUDE_MODE"] = mode
        with workers.locked_state() as state:
            workers.supervisor_pass(state, self.claude, concurrency)
        return workers.load_state()

    def settle(self, *job_ids, mode="ok", timeout=30, concurrency=3):
        deadline = time.time() + timeout
        state = self.pass_once(mode, concurrency)
        while time.time() < deadline:
            if all(state["jobs"][job]["state"] in TERMINAL for job in job_ids):
                return state
            time.sleep(0.1)
            state = self.pass_once(mode, concurrency)
        raise AssertionError(f"jobs did not settle: "
                             f"{[state['jobs'][j]['state'] for j in job_ids]}")

    def invocations(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def wait_for_launch(self, count=1):
        for _ in range(200):
            if len(self.invocations()) >= count:
                return self.invocations()
            time.sleep(0.05)
        raise AssertionError(f"the fake CLI was not launched {count} time(s)")

    def wait_for_cli(self, identifier):
        """The wrapper's durable record of the CLI it started."""
        for _ in range(200):
            child = workers.read_json(workers.job_dir(identifier) / "child.json")
            if child.get("cli_pid"):
                return child
            time.sleep(0.05)
        raise AssertionError("no CLI identity was recorded")

    def wait_for_init(self, identifier):
        stream = workers.job_dir(identifier) / "stdout.jsonl"
        for _ in range(200):
            if '"init"' in workers.read_head(stream, 65536):
                return
            time.sleep(0.05)
        raise AssertionError("no init event was recorded")

    def wait_for_descendant(self):
        """The same-group child the fake CLI started, with its start time."""
        marker = Path(str(self.log) + ".descendant")
        for _ in range(200):
            if marker.exists() and marker.read_text().strip():
                pid = int(marker.read_text())
                start = workers.process_start(pid)
                if start:
                    return pid, start
            time.sleep(0.05)
        raise AssertionError("the fake CLI recorded no descendant")

    def wait_until_dead(self, pid, pid_start):
        for _ in range(200):
            if not workers.process_alive(pid, pid_start):
                return
            time.sleep(0.05)
        raise AssertionError(f"pid {pid} is still alive")

    def capture(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            workers.main(argv)
        return buffer.getvalue()

    def status(self, *extra):
        return self.capture(["status", *extra])


class SessionContinuityTests(RunnerTestCase):
    def test_first_launch_starts_session_and_followup_resumes_the_same_one(self):
        self.register()
        self.enqueue(key="first")
        state = self.settle("w1:first")
        self.assertEqual(state["jobs"]["w1:first"]["state"], "done",
                         state["jobs"]["w1:first"].get("reason"))
        session = state["workers"]["w1"]["session_id"]
        self.assertTrue(state["workers"]["w1"]["session_started"])
        self.enqueue(key="second")
        state = self.settle("w1:second")
        self.assertEqual(state["jobs"]["w1:second"]["state"], "done")
        first, second = self.invocations()
        self.assertIn("--session-id", first["argv"])
        self.assertNotIn("--resume", first["argv"])
        self.assertIn("--resume", second["argv"])
        self.assertNotIn("--session-id", second["argv"])
        self.assertEqual(first["session"], session)
        self.assertEqual(second["session"], session)
        self.assertEqual(state["jobs"]["w1:second"]["resumed"], True)

    def test_prompt_carries_role_worktree_and_standing_rules(self):
        self.register()
        self.enqueue(extra=["--scope", "workflow/coordination only"])
        self.settle("w1:j1")
        prompt = self.invocations()[0]["prompt"]
        self.assertIn("Assigned role: implementer", prompt)
        self.assertIn(f"Workflow root for this job: {self.repo / 'workflow'}", prompt)
        self.assertIn("workflow/coordination only", prompt)
        self.assertIn("Co-authored-by", prompt)
        self.assertIn("work you authored yourself", prompt)
        self.assertIn("submits the work for independent review", prompt)
        self.assertIn("Never bypass a denial", prompt)
        self.assertIn("Implement the approved plan and report honestly.", prompt)

    def test_registered_role_is_preserved_without_assuming_authorship(self):
        self.register(role="reviewer")
        self.enqueue()
        self.settle("w1:j1")
        prompt = self.invocations()[0]["prompt"]
        self.assertIn("Assigned role: reviewer", prompt)
        self.assertNotIn("You are the implementation author", prompt)
        self.assertIn("Perform your assigned role only", prompt)

    def test_invocation_runs_in_the_assigned_worktree_with_scoped_permissions(self):
        self.register(extra=["--permission-mode", "acceptEdits",
                             "--allow-tool", "Bash(git status:*)", "--deny-tool", "WebFetch"])
        self.enqueue()
        self.settle("w1:j1")
        call = self.invocations()[0]
        argv = call["argv"]
        self.assertEqual(Path(call["cwd"]).resolve(), self.repo.resolve())
        self.assertIn("--verbose", argv)
        self.assertEqual(argv[argv.index("--output-format") + 1], "stream-json")
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "acceptEdits")
        self.assertEqual(argv[argv.index("--permission-prompts") + 1], "none")
        self.assertEqual(argv[argv.index("--setting-sources") + 1], "")
        self.assertIn("--strict-mcp-config", argv)
        self.assertEqual(json.loads(argv[argv.index("--mcp-config") + 1]), {"mcpServers": {}})
        self.assertEqual(argv[argv.index("--allowedTools") + 1], "Read,Bash(git status:*)")
        self.assertEqual(argv[argv.index("--disallowedTools") + 1], "WebFetch")
        self.assertNotIn("--dangerously-skip-permissions", argv)
        self.assertNotIn("--bare", argv)
        settings = json.loads(Path(argv[argv.index("--settings") + 1]).read_text())
        self.assertEqual(settings, {"attribution": {"commit": "", "pr": ""}})

    def test_pinned_model_and_effort_are_persisted_and_sent_on_launch_and_resume(self):
        workers.main(["register", "--worker", "w1", "--worktree", str(self.repo),
                      "--role", "implementer", "--allow-tool", "Read"])
        worker = workers.load_state()["workers"]["w1"]
        self.assertEqual(worker["model"], "claude-opus-5")
        self.assertEqual(worker["effort"], "max")
        self.enqueue(key="first")
        self.settle("w1:first")
        self.enqueue(key="second")
        self.settle("w1:second")
        first, second = self.invocations()
        for call in (first, second):
            argv = call["argv"]
            self.assertEqual(argv[argv.index("--model") + 1], "claude-opus-5")
            self.assertEqual(argv[argv.index("--effort") + 1], "max")
        self.assertIn("--session-id", first["argv"])
        self.assertIn("--resume", second["argv"])
        report = json.loads(self.status())
        self.assertEqual(report["workers"][0]["model"], "claude-opus-5")
        self.assertEqual(report["workers"][0]["effort"], "max")
        self.assertEqual(report["jobs"][0]["effort_requested"], "max")
        self.assertEqual(report["jobs"][0]["models_observed"], ["claude-opus-5-fake"])
        self.assertFalse(report["jobs"][0]["model_mismatch"])

    def test_floating_model_aliases_and_unknown_efforts_are_rejected(self):
        for bad in ("opus", "default", "claude-opus-latest", "sonnet", "gpt-5"):
            with self.subTest(model=bad), self.assertRaisesRegex(SystemExit, "pinned"):
                self.register(extra=["--model", bad])
        with self.assertRaises(SystemExit):
            self.register(extra=["--effort", "maximum"])
        self.register(extra=["--model", "claude-opus-5-20260501", "--effort", "high"])
        worker = workers.load_state()["workers"]["w1"]
        self.assertEqual(worker["model"], "claude-opus-5-20260501")
        self.assertEqual(worker["effort"], "high")

    def test_substituted_model_is_reported_and_never_relabelled(self):
        self.register()
        self.enqueue()
        job = self.settle("w1:j1", mode="other_model")["jobs"]["w1:j1"]
        self.assertTrue(job["model_mismatch"])
        self.assertEqual(job["models_observed"], ["claude-sonnet-5"])
        self.assertIn("model mismatch: requested claude-opus-5, observed claude-sonnet-5",
                      job["reason"])
        self.assertEqual(job["state"], "failed")
        self.assertIn("claude-sonnet-5", self.status())

    def test_dated_variant_of_the_requested_model_is_not_a_mismatch(self):
        self.assertTrue(workers.same_model_family("claude-opus-5", "claude-opus-5-20260501"))
        self.assertFalse(workers.same_model_family("claude-opus-5", "claude-sonnet-5"))
        self.assertFalse(workers.same_model_family("claude-opus-5", ""))

    def test_invocation_exposes_only_needed_tools_and_empties_attribution(self):
        self.register(extra=["--allow-tool", "Bash(git status:*)",
                             "--allow-tool", "Bash(git diff:*)", "--deny-tool", "WebFetch"])
        self.enqueue()
        self.settle("w1:j1")
        argv = self.invocations()[0]["argv"]
        self.assertEqual(argv[argv.index("--tools") + 1], "Read,Bash")
        self.assertEqual(argv[argv.index("--allowedTools") + 1],
                         "Read,Bash(git status:*),Bash(git diff:*)")
        settings = json.loads(Path(argv[argv.index("--settings") + 1]).read_text())
        self.assertEqual(settings, {"attribution": {"commit": "", "pr": ""}})
        self.assertNotIn("includeCoAuthoredBy", json.dumps(settings))
        for forbidden in workers.FORBIDDEN_TOOLS:
            self.assertNotIn(forbidden, argv[argv.index("--tools") + 1])
        self.assertEqual(json.loads(self.status())["workers"][0]["tools_exposed"],
                         ["Read", "Bash"])

    def test_agent_and_monitor_tools_cannot_be_registered(self):
        for forbidden in ("Agent", "Task", "Monitor", "Agent(worker:*)"):
            with self.subTest(tool=forbidden), \
                 self.assertRaisesRegex(SystemExit, "refusing to expose"):
                self.register(extra=["--allow-tool", forbidden])
        self.assertEqual(workers.tool_names(["Read", "Bash(git status:*)", "Bash(git diff:*)"]),
                         ["Read", "Bash"])

    def test_permission_modes_match_the_installed_cli_and_exclude_bypass(self):
        self.assertNotIn("bypassPermissions", workers.PERMISSION_MODES)
        self.assertNotIn("default", workers.PERMISSION_MODES)  # rejected by CLI 2.1.267
        self.assertEqual(workers.DEFAULT_PERMISSION_MODE, "manual")
        for bad in ("bypassPermissions", "default"):
            with self.subTest(mode=bad), self.assertRaises(SystemExit):
                self.register(extra=["--permission-mode", bad])
        with self.assertRaises(SystemExit):
            self.register(extra=["--allow-tool", "Bash(git status:*); rm -rf /\n"])
        with self.assertRaisesRegex(SystemExit, "tool surface must be explicit"):
            workers.main(["register", "--worker", "w9", "--worktree", str(self.repo),
                          "--role", "implementer", "--model", "claude-opus-5"])
        self.register()
        self.assertEqual(workers.load_state()["workers"]["w1"]["permission_mode"], "manual")


class SchedulingTests(RunnerTestCase):
    def test_two_workers_run_in_parallel_but_one_worker_stays_serialized(self):
        self.register("w1", self.repo)
        self.register("w2", self.peer)
        self.enqueue("w1", "a")
        self.enqueue("w1", "b")
        self.enqueue("w2", "c")
        state = self.pass_once("hang")
        self.assertEqual(state["jobs"]["w1:a"]["state"], "running")
        self.assertEqual(state["jobs"]["w2:c"]["state"], "running")
        self.assertEqual(state["jobs"]["w1:b"]["state"], "queued")
        workers.main(["stop", "--job", "w1:a"])
        workers.main(["stop", "--job", "w2:c"])
        state = self.settle("w1:b", timeout=30)
        self.assertEqual(state["jobs"]["w1:b"]["state"], "done")

    def test_global_concurrency_limit_holds_back_extra_workers(self):
        for name, tree in (("w1", self.repo), ("w2", self.peer)):
            self.register(name, tree)
            self.enqueue(name, "k")
        state = self.pass_once("hang", concurrency=1)
        running = [job["job_id"] for job in state["jobs"].values() if job["state"] == "running"]
        self.assertEqual(running, ["w1:k"])
        workers.main(["stop", "--job", "w1:k"])

    def test_unresolved_job_holds_its_worker_and_its_concurrency_slot(self):
        self.register("w1", self.repo)
        self.register("w2", self.peer)
        self.enqueue("w1", "a")
        self.enqueue("w2", "b")
        with workers.locked_state() as state:
            workers.interrupt(state["jobs"]["w1:a"], "fixture interruption")
        state = self.pass_once("hang", concurrency=1)
        self.assertEqual(state["jobs"]["w2:b"]["state"], "queued")
        self.assertEqual(json.loads(self.status())["held_slots"], 1)
        workers.main(["resolve", "--job", "w1:a"])
        state = self.pass_once("hang", concurrency=1)
        self.assertEqual(state["jobs"]["w2:b"]["state"], "running")
        workers.main(["stop", "--job", "w2:b"])

    def test_supervisor_drains_queued_work_and_records_its_heartbeat(self):
        self.register()
        self.enqueue()
        workers.main(["run", "--drain", "--interval", "0.1", "--no-notices",
                      "--claude", str(self.claude)])
        self.assertEqual(workers.load_state()["jobs"]["w1:j1"]["state"], "done")
        supervisor = json.loads((self.runtime / "supervisor.json").read_text())
        self.assertEqual(supervisor["pid"], os.getpid())
        self.assertEqual(supervisor["claude"], str(self.claude))

    def test_drain_reports_rather_than_spins_when_an_unresolved_job_blocks_work(self):
        self.register()
        self.enqueue(key="a")
        self.enqueue(key="b")
        with workers.locked_state() as state:
            workers.interrupt(state["jobs"]["w1:a"], "fixture interruption")
        output = self.capture(["run", "--drain", "--interval", "0.1", "--no-notices",
                               "--claude", str(self.claude)])
        self.assertIn("WORKERS_DRAIN_BLOCKED", output)
        self.assertEqual(workers.load_state()["jobs"]["w1:b"]["state"], "queued")
        self.assertEqual(self.invocations(), [])

    def test_duplicate_enqueue_is_idempotent_and_rejects_a_changed_prompt(self):
        self.register()
        self.enqueue(key="dup")
        self.enqueue(key="dup")
        self.assertEqual(len(workers.load_state()["jobs"]), 1)
        other = Path(self.temp.name) / "other.md"
        other.write_text("A different task entirely.\n")
        with self.assertRaisesRegex(SystemExit, "different prompt"):
            self.enqueue(key="dup", prompt=other)
        self.settle("w1:dup")
        self.assertEqual(len(self.invocations()), 1)

    def test_removed_worktree_fails_the_job_before_any_launch(self):
        self.register("w2", self.peer)
        self.enqueue("w2", "j")
        self.git("worktree", "remove", "--force", str(self.peer))
        state = self.pass_once()
        job = state["jobs"]["w2:j"]
        self.assertEqual(job["state"], "failed")
        self.assertIn("revalidation", job["reason"])
        self.assertEqual(self.invocations(), [])


class OutcomeTests(RunnerTestCase):
    def outcome(self, mode, key="j1"):
        self.register()
        self.enqueue(key=key)
        return self.settle(f"w1:{key}", mode=mode)["jobs"][f"w1:{key}"]

    def test_nonzero_exit_fails_even_with_a_successful_result_event(self):
        job = self.outcome("nonzero")
        self.assertEqual(job["state"], "failed")
        self.assertIn("exit status 3", job["reason"])

    def test_result_is_error_fails_despite_a_recorded_stream(self):
        job = self.outcome("error_result")
        self.assertEqual(job["state"], "failed")
        self.assertIn("is_error is True", job["reason"])
        self.assertEqual(job["is_error"], True)

    def test_missing_result_event_is_a_failure_not_a_success(self):
        job = self.outcome("no_result")
        self.assertEqual(job["state"], "failed")
        self.assertIn("found 0", job["reason"])
        self.assertEqual(job["exit_status"], 0)

    def test_session_id_mismatch_fails_the_job(self):
        job = self.outcome("mismatch")
        self.assertEqual(job["state"], "failed")
        self.assertIn("result session id does not match", job["reason"])
        self.assertFalse(job["session_match"])

    def test_missing_init_event_fails_even_with_a_good_result(self):
        job = self.outcome("no_init")
        self.assertEqual(job["state"], "failed")
        self.assertIn("exactly one init event", job["reason"])

    def test_result_without_an_explicit_error_flag_or_subtype_is_not_success(self):
        job = self.outcome("plain_result")
        self.assertEqual(job["state"], "failed")
        self.assertIn("is_error is None, not an explicit false", job["reason"])
        self.assertIn("not a success subtype", job["reason"])

    def test_result_missing_only_the_error_flag_still_fails(self):
        job = self.outcome("no_error_flag")
        self.assertEqual(job["state"], "failed")
        self.assertIn("not an explicit false", job["reason"])

    def test_empty_final_result_text_fails(self):
        job = self.outcome("null_result_text")
        self.assertEqual(job["state"], "failed")
        self.assertIn("final result text is missing", job["reason"])

    def test_conflicting_final_results_fail(self):
        job = self.outcome("two_results")
        self.assertEqual(job["state"], "failed")
        self.assertIn("exactly one final result event, found 2", job["reason"])

    def test_non_object_json_lines_fail_visibly(self):
        job = self.outcome("non_object")
        self.assertEqual(job["state"], "failed")
        self.assertIn("non-object JSON stream line", job["reason"])
        self.assertEqual(job["non_object_stream_lines"], 1)

    def test_success_captures_model_timestamps_and_submitted_state(self):
        job = self.outcome("ok")
        self.assertEqual(job["state"], "done")
        self.assertIsNone(job["reason"])
        self.assertFalse(job["unresolved"])
        self.assertEqual(job["model_requested"], "claude-opus-5")
        self.assertEqual(job["model_reported"], "claude-opus-5-fake")
        self.assertIn("independent review", job["submitted"])
        self.assertTrue(job["started_at"] and job["finished_at"])
        self.assertEqual(job["num_turns"], 2)
        self.assertTrue(job["session_match"])

    def test_tool_denials_stay_visible_in_the_record(self):
        job = self.outcome("denied")
        self.assertEqual(job["state"], "done")
        self.assertEqual(job["execution_verdict"], "succeeded with denials")
        self.assertEqual({denial["tool"] for denial in job["denials"]}, {"Bash", None})
        self.assertEqual({denial["tool_use_id"] for denial in job["denials"]}, {"toolu_1"})
        self.assertEqual({denial["source"] for denial in job["denials"]},
                         {"result", "tool_result"})
        self.assertEqual(job["denial_count"], 2)
        self.assertIn("denials stay visible", job["submitted"])
        self.assertIn("Bash", self.status("--worker", "w1"))

    def test_authentication_failure_is_reported_with_stderr_evidence(self):
        job = self.outcome("auth_error")
        self.assertEqual(job["state"], "failed")
        self.assertIn("exit status 1", job["reason"])
        self.assertIn("Invalid API key", job["stderr_tail"])

    def test_hard_child_crash_is_reported_without_a_silent_retry(self):
        job = self.outcome("kill")
        self.assertEqual(job["state"], "failed")
        self.assertIn("exit status -9", job["reason"])
        self.assertEqual(job["attempts"], 1)
        self.assertEqual(len(self.invocations()), 1)

    def test_timeout_ends_the_cli_tree_before_another_job_dispatches(self):
        self.register()
        self.enqueue(key="slow", extra=["--timeout", "0.5"])
        self.enqueue(key="next")
        self.pass_once("hang")
        child = self.wait_for_cli("w1:slow")
        state = self.settle("w1:slow", mode="hang", timeout=40)
        job = state["jobs"]["w1:slow"]
        self.assertEqual(job["state"], "failed")
        self.assertIn("timed out", job["reason"])
        self.assertFalse(job["unresolved"])
        self.assertFalse(workers.process_alive(child["cli_pid"], child["cli_pid_start"]))

    def test_one_broken_job_record_does_not_stop_the_supervisor(self):
        self.register()
        self.enqueue(key="broken")
        self.enqueue(key="fine")
        with workers.locked_state() as state:
            state["jobs"]["w1:broken"].update(state="running", invocation_id="x",
                                              timeout_seconds=None, requested_at="not-a-number")
        state = self.pass_once()
        self.assertEqual(state["jobs"]["w1:broken"]["state"], "failed")
        self.assertIn("reconcile error", state["jobs"]["w1:broken"]["reason"])
        self.assertTrue(state["jobs"]["w1:broken"]["unresolved"])


SESSION = "11111111-2222-4333-8444-555555555555"
INIT = {"type": "system", "subtype": "init", "session_id": SESSION, "model": "claude-opus-5"}
ASSISTANT = {"type": "assistant", "session_id": SESSION,
             "message": {"role": "assistant", "model": "claude-opus-5",
                         "content": [{"type": "text", "text": "done"}]}}
RESULT = {"type": "result", "subtype": "success", "session_id": SESSION, "is_error": False,
          "result": "implemented and reporting one denial", "num_turns": 3}
DENIED_SYSTEM = {"type": "system", "subtype": "permission_denied", "session_id": SESSION,
                 "tool_name": "Bash", "tool_use_id": "toolu_1",
                 "decision_reason": "no interactive host is attached",
                 "decision_reason_type": "asyncAgent",
                 "message": "Permission for this tool use was denied. It requires approval."}


class StreamShapeTests(RunnerTestCase):
    """Real CLI streams put strings where objects were assumed; none may crash."""

    def summary(self, events, requested="claude-opus-5"):
        return workers.summarize(events, SESSION, requested_model=requested)

    def test_recorded_denial_stream_is_execution_success_with_visible_denials(self):
        self.register()
        self.enqueue()
        job = self.settle("w1:j1", mode="replay")["jobs"]["w1:j1"]
        self.assertEqual(job["state"], "done", job.get("reason"))
        self.assertIsNone(job["reason"])
        self.assertEqual(job["execution_verdict"], "succeeded with denials")
        self.assertEqual(job["denial_count"], 3)
        self.assertEqual(
            sorted((d["source"], d["tool"], d["tool_use_id"]) for d in job["denials"]),
            [("result", "Bash", "toolu_synthetic_bash"),
             ("system", "Bash", "toolu_synthetic_bash"),
             ("tool_result", None, "toolu_synthetic_bash")],
            "each reported denial stays visible; none is discarded as a duplicate")
        self.assertEqual(job["models_observed"], ["claude-opus-5"])
        self.assertFalse(job["model_mismatch"])
        self.assertIn("claude-haiku-4-5-20251001", job["model_usage_ids"])
        self.assertEqual(job["num_turns"], 4)
        self.assertTrue(job["session_match"])
        self.assertEqual(job["exit_status"], 0)
        report = self.status()
        self.assertIn("succeeded with denials", report)
        self.assertIn("asyncAgent", report)
        self.assertIn("never means the implementation was reviewed", report)

    def test_fixture_still_carries_the_shapes_it_protects(self):
        events, malformed, non_object = workers.read_events(DENIED_STREAM)
        self.assertEqual((malformed, non_object), (0, 0))
        denials = [event for event in events if event.get("subtype") == "permission_denied"]
        self.assertEqual(len(denials), 1)
        self.assertIsInstance(denials[0]["message"], str,
                              "the regression is a STRING message on a system event")
        subtypes = {event.get("subtype") for event in events if event.get("type") == "system"}
        self.assertLessEqual({"init", "thinking_tokens", "vcs_state_changed", "task_started",
                              "task_notification", "permission_denied"}, subtypes)
        final = [event for event in events if event.get("type") == "result"][-1]
        self.assertIsInstance(final["permission_denials"], list)
        self.assertNotIn("model", final, "the real final event carries modelUsage, not model")

    def test_string_and_dynamic_system_messages_never_crash_collection(self):
        events = [DENIED_SYSTEM,
                  {"type": "system", "subtype": "status", "message": "dynamic status text"},
                  {"type": "system", "subtype": "thinking_tokens", "estimated_tokens": 5},
                  {"type": "system", "subtype": "vcs_state_changed", "branch": "main"},
                  {"type": "assistant", "message": "unexpectedly a string"},
                  {"type": "user", "message": ["also wrong"]},
                  {"type": "stream_event", "message": None}]
        denials = workers.collect_denials(events)
        self.assertEqual([denial["source"] for denial in denials], ["system"])
        self.assertEqual(denials[0]["tool"], "Bash")
        self.assertEqual(denials[0]["reason_type"], "asyncAgent")
        self.assertEqual(denials[0]["detail"], "no interactive host is attached")

    def test_minimal_denied_sequence_classifies_as_success(self):
        summary = self.summary([INIT, DENIED_SYSTEM, ASSISTANT, RESULT])
        self.assertEqual(summary["problems"], [])
        self.assertTrue(summary["session_match"])
        self.assertEqual([denial["tool"] for denial in summary["denials"]], ["Bash"])
        self.assertEqual(summary["models_observed"], ["claude-opus-5"])

    def test_assistant_message_of_the_wrong_type_is_reported_not_crashed(self):
        for message in ("a string", ["a list"], 7):
            with self.subTest(message=message):
                summary = self.summary([INIT, {"type": "assistant", "message": message}, RESULT])
                self.assertTrue(any("not an object" in problem
                                    for problem in summary["problems"]), summary["problems"])
                self.assertEqual(summary["models_observed"], ["claude-opus-5"])

    def test_non_string_model_ids_are_reported_and_never_accepted(self):
        events = [dict(INIT, model=5),
                  {"type": "assistant", "session_id": SESSION,
                   "message": {"model": {"id": "claude-opus-5"}, "content": []}},
                  RESULT]
        summary = self.summary(events)
        self.assertEqual(len([p for p in summary["problems"] if "non-string model id" in p]), 2)
        self.assertEqual(summary["models_observed"], [])
        self.assertIsNone(summary["model"])
        self.assertFalse(summary["model_mismatch"])

    def test_malformed_final_metadata_and_denial_arrays_are_reported(self):
        final = dict(RESULT, permission_denials="denied", modelUsage="none",
                     num_turns="four", usage=[])
        summary = self.summary([INIT, ASSISTANT, final])
        for field in ("permission_denials", "modelUsage", "num_turns", "usage"):
            self.assertTrue(any(f"final {field} is a" in problem
                                for problem in summary["problems"]), summary["problems"])
        self.assertEqual(summary["denials"], [], "a non-list denial array yields no entries")
        self.assertEqual(summary["model_usage_ids"], [])
        entries = workers.collect_denials([{"type": "result",
                                            "permission_denials": ["oops", {"tool_name": "Bash"}]}])
        self.assertEqual([entry["tool"] for entry in entries], [None, "Bash"],
                         "a malformed item is still counted, never silently dropped")

    def test_denied_tool_content_shapes_are_all_recognised(self):
        block = {"type": "tool_result", "tool_use_id": "t1", "is_error": True}
        for content in ("Permission for this tool use was denied.",
                        [{"type": "text", "text": "permission denied for Bash"}],
                        {"text": "the user doesn't want to proceed"}):
            with self.subTest(content=type(content).__name__):
                events = [{"type": "user", "message": {"content": [dict(block, content=content)]}}]
                self.assertEqual([d["source"] for d in workers.collect_denials(events)],
                                 ["tool_result"])
        allowed = [{"type": "user", "message": {"content": [
            dict(block, is_error=False, content="Permission for this tool use was denied.")]}}]
        self.assertEqual(workers.collect_denials(allowed), [],
                         "a successful tool result is not a denial")

    def test_no_valid_final_result_is_never_success(self):
        without = self.summary([INIT, DENIED_SYSTEM, ASSISTANT])
        self.assertTrue(any("found 0" in problem for problem in without["problems"]))
        self.assertFalse(without["session_match"])
        bare = self.summary([INIT, ASSISTANT, {"type": "result", "session_id": SESSION}])
        self.assertTrue(any("not an explicit false" in p for p in bare["problems"]))
        self.assertTrue(any("not a success subtype" in p for p in bare["problems"]))
        self.assertTrue(any("result text is missing" in p for p in bare["problems"]))

    def test_original_session_and_model_checks_still_apply(self):
        other = dict(RESULT, session_id="another-session")
        self.assertTrue(any("result session id does not match" in p
                            for p in self.summary([INIT, ASSISTANT, other])["problems"]))
        swapped = dict(ASSISTANT, message={"model": "claude-sonnet-5", "content": []})
        problems = self.summary([INIT, swapped, RESULT])["problems"]
        self.assertTrue(any("model mismatch" in problem for problem in problems), problems)
        self.assertTrue(self.summary([INIT, ASSISTANT, RESULT, RESULT])["problems"])


class RecoveryTests(RunnerTestCase):
    def test_restart_adopts_a_live_child_instead_of_spawning_a_duplicate(self):
        self.register()
        self.enqueue()
        self.pass_once("hang")
        self.wait_for_launch()
        state = self.pass_once("hang")  # A restarted supervisor reconciles the same runtime.
        self.assertEqual(state["jobs"]["w1:j1"]["state"], "running")
        self.assertEqual(len(self.invocations()), 1)
        workers.main(["stop", "--job", "w1:j1"])

    def test_receipt_written_by_the_child_survives_supervisor_death(self):
        self.register()
        self.enqueue()
        with workers.locked_state() as state:
            workers.dispatch(state, self.claude, 3)
        directory = workers.job_dir("w1:j1")
        for _ in range(200):
            if (directory / "receipt.json").exists():
                break
            time.sleep(0.05)
        receipt = json.loads((directory / "receipt.json").read_text())
        self.assertEqual(receipt["exit_status"], 0)
        self.assertTrue(receipt["cli_pid"])
        state = self.pass_once()  # The replacement supervisor finalizes from the receipt.
        self.assertEqual(state["jobs"]["w1:j1"]["state"], "done")
        self.assertEqual(len(self.invocations()), 1)

    def test_crash_inside_the_spawn_window_is_interrupted_not_replayed(self):
        self.register()
        self.enqueue()
        with workers.locked_state() as state:
            state["jobs"]["w1:j1"].update(state="starting", invocation_id=str(uuid.uuid4()),
                                          requested_at=time.time() - 600)
        state = self.pass_once()
        job = state["jobs"]["w1:j1"]
        self.assertEqual(job["state"], "interrupted")
        self.assertTrue(job["needs_lead_decision"])
        self.assertTrue(job["unresolved"])
        self.assertIn("spawn window", job["reason"])
        self.assertEqual(self.invocations(), [])

    def test_vanished_child_tree_without_a_receipt_is_interrupted(self):
        self.register()
        self.enqueue()
        self.pass_once("hang")
        child = self.wait_for_cli("w1:j1")
        # Wrapper first: it must not get the chance to write a receipt.
        for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
            os.killpg(child[pid_key], signal.SIGKILL)
            self.wait_until_dead(child[pid_key], child[start_key])
        state = self.pass_once()
        self.assertEqual(state["jobs"]["w1:j1"]["state"], "interrupted")
        self.assertIn("without a receipt", state["jobs"]["w1:j1"]["reason"])
        self.assertTrue(state["jobs"]["w1:j1"]["unresolved"])

    def test_orphaned_cli_holds_the_worker_until_the_lead_resolves_it(self):
        self.register()
        self.enqueue(key="a")
        self.enqueue(key="b")
        self.pass_once("hang")
        child = self.wait_for_cli("w1:a")
        self.wait_for_init("w1:a")
        # Kill ONLY the wrapper: its Claude CLI keeps running in its own session.
        os.kill(child["pid"], signal.SIGKILL)
        self.wait_until_dead(child["pid"], child["pid_start"])
        self.assertTrue(workers.process_alive(child["cli_pid"], child["cli_pid_start"]))

        state = self.pass_once("hang")
        first = state["jobs"]["w1:a"]
        self.assertEqual(first["state"], "interrupted")
        self.assertTrue(first["unresolved"])
        self.assertIn("still running", first["reason"])
        self.assertEqual(first["cli_pid"], child["cli_pid"])
        # No second invocation may share the session while the first is unaccounted for.
        self.assertEqual(state["jobs"]["w1:b"]["state"], "queued")
        self.assertEqual(len(self.invocations()), 1)
        self.assertTrue(workers.process_alive(child["cli_pid"], child["cli_pid_start"]))
        # Session-start evidence is durable even though no receipt exists.
        self.assertTrue(state["workers"]["w1"]["session_started"])

        # Inspection alone must not release the worker.
        self.assertEqual(workers.main(["resolve", "--job", "w1:a"]), 1)
        self.assertTrue(workers.load_state()["jobs"]["w1:a"]["unresolved"])
        self.assertEqual(self.pass_once("hang")["jobs"]["w1:b"]["state"], "queued")

        self.assertEqual(workers.main(["resolve", "--job", "w1:a", "--terminate"]), 0)
        self.wait_until_dead(child["cli_pid"], child["cli_pid_start"])
        resolved = workers.load_state()["jobs"]["w1:a"]
        self.assertFalse(resolved["unresolved"])
        self.assertIn("--terminate", resolved["resolution"])

        state = self.pass_once("hang")
        self.assertEqual(state["jobs"]["w1:b"]["state"], "running")
        self.assertTrue(state["jobs"]["w1:b"]["resumed"])
        second = self.wait_for_launch(2)[1]
        self.assertIn("--resume", second["argv"])
        self.assertNotIn("--session-id", second["argv"])
        workers.main(["stop", "--job", "w1:b"])

    def test_resolve_prefers_a_late_receipt_over_a_bare_release(self):
        self.register()
        self.enqueue()
        with workers.locked_state() as state:
            workers.dispatch(state, self.claude, 3)
            state["jobs"]["w1:j1"].update(state="interrupted", unresolved=True,
                                          reason="fixture: supervisor died before the receipt")
        directory = workers.job_dir("w1:j1")
        for _ in range(200):
            if (directory / "receipt.json").exists():
                break
            time.sleep(0.05)
        outcome = json.loads(self.capture(["resolve", "--job", "w1:j1"]))
        self.assertEqual(outcome["action"], "nothing to resolve")
        job = workers.load_state()["jobs"]["w1:j1"]
        self.assertFalse(job["unresolved"])
        self.assertEqual(job["state"], "done", job.get("reason"))
        self.assertIsNone(job["reason"])
        self.assertTrue(workers.load_state()["workers"]["w1"]["session_started"])


class StopTests(RunnerTestCase):
    def live_job(self, key="j1"):
        self.register()
        self.enqueue(key=key)
        self.pass_once("hang")
        return self.wait_for_cli(f"w1:{key}")

    def test_queued_job_is_canceled_before_any_launch(self):
        self.register()
        self.enqueue()
        workers.main(["stop", "--job", "w1:j1"])
        state = self.pass_once()
        self.assertEqual(state["jobs"]["w1:j1"]["state"], "canceled")
        self.assertFalse(state["jobs"]["w1:j1"]["unresolved"])
        self.assertEqual(self.invocations(), [])

    def test_stop_ends_the_whole_owned_tree_not_only_the_wrapper(self):
        child = self.live_job()
        outcome = json.loads(self.capture(["stop", "--job", "w1:j1"]))
        self.assertEqual(outcome["state"], "canceled")
        self.assertFalse(outcome["unresolved"])
        for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
            self.assertFalse(workers.process_alive(child[pid_key], child[start_key]),
                             f"{pid_key} survived cancellation")
        self.assertEqual(workers.load_state()["jobs"]["w1:j1"]["state"], "canceled")

    def test_pid_reuse_refuses_to_signal_and_reports_the_job(self):
        child = self.live_job()
        with workers.locked_state() as state:
            state["jobs"]["w1:j1"].update(
                pid_start=str(int(child["pid_start"]) + 5),
                cli_pid=child["cli_pid"],
                cli_pid_start=str(int(child["cli_pid_start"]) + 5))
        outcome = json.loads(self.capture(["stop", "--job", "w1:j1"]))
        job = workers.load_state()["jobs"]["w1:j1"]
        self.assertEqual(outcome["signaled"], [])
        self.assertTrue(outcome["unresolved"])
        self.assertEqual(job["state"], "interrupted")
        self.assertTrue(job["unresolved"])
        self.assertIn("could not account for every owned process", job["reason"])
        self.assertIn("cli pid", job["reason"])
        self.assertIn("wrapper pid", job["reason"])
        for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
            self.assertTrue(workers.process_alive(child[pid_key], child[start_key]),
                            f"{pid_key}: a mismatched identity must never be signalled")
        for pid_key in ("cli_pid", "pid"):
            os.killpg(child[pid_key], signal.SIGKILL)

    def test_a_recycled_pid_whose_records_disagree_is_never_signalled(self):
        records = [{"label": "cli", "pid": os.getpid(), "pid_start": "1", "agree": False,
                    "alive": False, "present": True},
                   {"label": "wrapper", "pid": 1, "pid_start": None, "agree": True,
                    "alive": False, "present": True}]
        problems = workers.unresolved_processes(records)
        self.assertEqual(len(problems), 1)
        self.assertIn("records disagree", problems[0])
        self.assertIn("refused to signal", problems[0])

    def test_stop_without_a_matching_child_record_signals_nothing(self):
        self.register()
        self.enqueue()
        with workers.locked_state() as state:
            state["jobs"]["w1:j1"].update(state="running", invocation_id="never-launched",
                                          pid=os.getpid(), pid_start=workers.process_start(os.getpid()))
        workers.main(["stop", "--job", "w1:j1"])
        job = workers.load_state()["jobs"]["w1:j1"]
        self.assertEqual(job["state"], "interrupted")
        self.assertIn("refused to signal", job["reason"])
        self.assertTrue(workers.process_alive(os.getpid(), workers.process_start(os.getpid())))

    def test_cancelling_after_init_keeps_the_session_for_the_next_job(self):
        self.register()
        self.enqueue(key="a")
        self.pass_once("hang")
        self.wait_for_cli("w1:a")
        self.wait_for_init("w1:a")
        # Stop before any reconcile pass has seen this invocation.
        outcome = json.loads(self.capture(["stop", "--job", "w1:a"]))
        self.assertEqual(outcome["state"], "canceled")
        self.assertTrue(workers.load_state()["workers"]["w1"]["session_started"],
                        "a cancelled turn that already created the session must be remembered")
        self.enqueue(key="b")
        state = self.settle("w1:b")
        self.assertEqual(state["jobs"]["w1:b"]["state"], "done", state["jobs"]["w1:b"].get("reason"))
        self.assertTrue(state["jobs"]["w1:b"]["resumed"])
        first, second = self.invocations()
        self.assertIn("--session-id", first["argv"])
        self.assertIn("--resume", second["argv"])
        self.assertNotIn("--session-id", second["argv"])
        self.assertEqual(first["session"], second["session"])

    def test_stop_supervisor_reports_when_none_is_running(self):
        self.register()
        self.assertIn("not running", self.capture(["stop", "--supervisor"]))

    def test_stop_on_a_finished_job_changes_nothing(self):
        self.register()
        self.enqueue()
        self.settle("w1:j1")
        workers.main(["stop", "--job", "w1:j1"])
        self.assertEqual(workers.load_state()["jobs"]["w1:j1"]["state"], "done")


GROUP_FIXTURE = r'''
import signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
with open(sys.argv[1], "w") as marker:
    marker.write(str(child.pid))
time.sleep(600)
'''


class ProcessGroupTests(RunnerTestCase):
    def group_fixture(self):
        """A real group leader with a same-group child that ignores SIGTERM."""
        marker = Path(self.temp.name) / "group-descendant.pid"
        leader = subprocess.Popen([sys.executable, "-c", GROUP_FIXTURE, str(marker)],
                                  start_new_session=True)
        self.addCleanup(leader.poll)
        for _ in range(200):
            if marker.exists() and marker.read_text().strip():
                break
            time.sleep(0.05)
        descendant = int(marker.read_text())
        start = workers.process_start(descendant)
        self.addCleanup(lambda: os.kill(descendant, signal.SIGKILL)
                        if workers.process_alive(descendant, start) else None)
        return leader, workers.process_start(leader.pid), descendant, start

    def test_terminate_group_escalates_until_every_member_is_gone(self):
        leader, leader_start, descendant, start = self.group_fixture()
        self.assertIn(descendant, workers.group_members(leader.pid))
        self.assertTrue(workers.process_alive(descendant, start))
        self.assertTrue(workers.terminate_group(leader.pid, leader_start, grace=2.0))
        self.assertFalse(workers.process_alive(leader.pid, leader_start))
        self.assertFalse(workers.process_alive(descendant, start),
                         "a SIGTERM-ignoring descendant must be escalated, not declared gone")
        leader.wait(timeout=5)
        self.assertEqual(workers.group_members(leader.pid), {})

    def test_leftover_group_without_a_verifiable_leader_is_reported_not_signalled(self):
        leader, leader_start, descendant, start = self.group_fixture()
        os.kill(leader.pid, signal.SIGKILL)
        leader.wait(timeout=5)
        self.assertFalse(workers.process_alive(leader.pid, leader_start))
        self.assertTrue(workers.group_present(leader.pid), "the descendant pins the group id")
        self.assertFalse(workers.terminate_group(leader.pid, leader_start, grace=0.5))
        self.assertTrue(workers.process_alive(descendant, start),
                        "a group whose leader cannot be re-identified must not be signalled")
        os.kill(descendant, signal.SIGKILL)
        self.wait_until_dead(descendant, start)
        self.assertTrue(workers.terminate_group(leader.pid, leader_start, grace=0.5))

    def test_empty_and_foreign_group_probes_are_safe(self):
        self.assertFalse(workers.group_present(0))
        self.assertFalse(workers.group_present(-1))
        self.assertEqual(workers.group_members(0), {})
        self.assertIn(os.getpid(), workers.group_members(os.getpgid(os.getpid())))

    def test_cancellation_ends_a_surviving_cli_descendant(self):
        self.register()
        self.enqueue()
        self.pass_once("descendant")
        child = self.wait_for_cli("w1:j1")
        descendant, start = self.wait_for_descendant()
        self.assertTrue(workers.process_alive(descendant, start))
        outcome = json.loads(self.capture(["stop", "--job", "w1:j1"]))
        self.assertEqual(outcome["state"], "canceled")
        self.assertFalse(outcome["unresolved"])
        self.assertFalse(workers.process_alive(descendant, start),
                         "cancellation must account for the whole owned group")
        self.assertEqual(workers.group_members(child["cli_pid"]), {})

    def test_timeout_ends_a_surviving_cli_descendant(self):
        self.register()
        self.enqueue(key="slow", extra=["--timeout", "0.5"])
        self.pass_once("descendant")
        self.wait_for_cli("w1:slow")
        descendant, start = self.wait_for_descendant()
        job = self.settle("w1:slow", mode="descendant", timeout=40)["jobs"]["w1:slow"]
        self.assertEqual(job["state"], "failed")
        self.assertIn("timed out", job["reason"])
        self.assertFalse(job["unresolved"])
        self.assertFalse(workers.process_alive(descendant, start),
                         "a timeout must leave no running descendant")

    def test_a_leftover_group_member_keeps_the_job_unresolved(self):
        self.register()
        self.enqueue()
        self.pass_once("descendant")
        child = self.wait_for_cli("w1:j1")
        descendant, start = self.wait_for_descendant()
        # Kill the wrapper and the CLI leader only; the descendant lives on.
        for pid_key, start_key in (("pid", "pid_start"), ("cli_pid", "cli_pid_start")):
            os.kill(child[pid_key], signal.SIGKILL)
            self.wait_until_dead(child[pid_key], child[start_key])
        self.assertTrue(workers.process_alive(descendant, start))
        state = self.pass_once("descendant")
        job = state["jobs"]["w1:j1"]
        self.assertEqual(job["state"], "interrupted")
        self.assertTrue(job["unresolved"])
        self.assertIn("remain in the process group", job["reason"])
        self.assertEqual(workers.main(["resolve", "--job", "w1:j1", "--terminate"]), 1,
                         "an unverifiable leftover is reported, not blindly signalled")
        os.kill(descendant, signal.SIGKILL)
        self.wait_until_dead(descendant, start)
        self.assertEqual(workers.main(["resolve", "--job", "w1:j1"]), 0)
        self.assertFalse(workers.load_state()["jobs"]["w1:j1"]["unresolved"])


class BoundaryTests(RunnerTestCase):
    def test_registration_requires_an_existing_worktree_root_of_this_repository(self):
        subdirectory = self.repo / "sub"
        subdirectory.mkdir()
        with self.assertRaisesRegex(SystemExit, "worktree root"):
            self.register(worktree=subdirectory)
        plain = Path(self.temp.name) / "plain"
        plain.mkdir()
        with self.assertRaisesRegex(SystemExit, "not a Git worktree|git rev-parse failed"):
            self.register(worktree=plain)
        with self.assertRaisesRegex(SystemExit, "absolute"):
            self.register(worktree=Path("repo"))
        with self.assertRaisesRegex(SystemExit, "does not exist"):
            self.register(worktree=Path(self.temp.name) / "gone")

    def test_registration_rejects_a_worktree_of_another_repository(self):
        other = Path(self.temp.name) / "other"
        other.mkdir()
        subprocess.run(["git", "-C", str(other), "init", "-q"], check=True)
        with self.assertRaisesRegex(SystemExit, "another repository"):
            self.register(worktree=other)

    def test_worktree_paths_with_spaces_are_parsed_line_by_line(self):
        spaced = Path(self.temp.name) / "work tree with spaces"
        self.git("worktree", "add", "-q", "--detach", str(spaced), "HEAD")
        self.assertEqual(workers.resolve_worktree(str(spaced)), spaced.resolve())
        self.register("w3", spaced)
        self.assertEqual(workers.load_state()["workers"]["w3"]["worktree"], str(spaced))

    def test_this_tool_never_creates_or_touches_a_worktree(self):
        before = self.git("worktree", "list", "--porcelain").stdout
        self.register()
        self.enqueue()
        self.settle("w1:j1")
        self.assertEqual(self.git("worktree", "list", "--porcelain").stdout, before)

    def test_identifiers_and_paths_reject_traversal(self):
        self.register()
        for key in ("../escape", "..", "a/b", "j1/../../x", ""):
            with self.subTest(key=key), self.assertRaises(SystemExit):
                self.enqueue(key=key)
        with self.assertRaises(SystemExit):
            workers.main(["register", "--worker", "../w", "--worktree", str(self.repo),
                          "--role", "implementer", "--model", "claude-opus-5",
                          "--allow-tool", "Read"])
        with self.assertRaises(SystemExit):
            workers.job_dir("../../etc:passwd")
        self.assertEqual(workers.job_dir("w1:j1").parent, self.runtime / "jobs")

    def test_enqueue_requires_a_registered_worker_and_a_real_prompt_file(self):
        with self.assertRaisesRegex(SystemExit, "unknown worker"):
            self.enqueue()
        self.register()
        with self.assertRaisesRegex(SystemExit, "regular file"):
            self.enqueue(prompt=Path(self.temp.name) / "missing.md")
        empty = Path(self.temp.name) / "empty.md"
        empty.write_text("   \n")
        with self.assertRaisesRegex(SystemExit, "empty"):
            self.enqueue(prompt=empty)

    def test_non_finite_and_nonpositive_durations_are_rejected(self):
        self.register()
        for bad in ("nan", "inf", "-inf", "0", "-5", "abc", "90000"):
            with self.subTest(timeout=bad), self.assertRaises(SystemExit):
                self.enqueue(extra=["--timeout", bad])
        for bad in ("nan", "inf", "0", "-1", "61", "abc"):
            with self.subTest(interval=bad), self.assertRaises(SystemExit):
                workers.main(["run", "--once", "--no-notices", "--interval", bad,
                              "--claude", str(self.claude)])
        for bad in ("0", "9", "-1"):
            with self.subTest(concurrency=bad), self.assertRaises(SystemExit):
                workers.main(["run", "--once", "--no-notices", "--concurrency", bad,
                              "--claude", str(self.claude)])

    def test_status_works_before_any_registration_and_creates_nothing(self):
        unused = Path(self.temp.name) / "unused-runtime"
        with patch.object(workers, "RUNTIME", unused):
            report = json.loads(self.capture(["status"]))
        self.assertFalse(report["runtime_present"])
        self.assertEqual(report["workers"], [])
        self.assertEqual(report["jobs"], [])
        self.assertFalse(unused.exists())

    def test_missing_or_unsafe_claude_binary_is_a_clear_error(self):
        with self.assertRaisesRegex(SystemExit, "not found"):
            workers.resolve_claude(str(Path(self.temp.name) / "nope" / "claude"))
        with self.assertRaisesRegex(SystemExit, "absolute"):
            workers.resolve_claude("claude")
        self.claude.chmod(0o777)
        with self.assertRaisesRegex(SystemExit, "world-writable"):
            workers.resolve_claude(str(self.claude))
        self.claude.chmod(0o755)
        self.assertEqual(workers.resolve_claude(str(self.claude)), self.claude.resolve())

    def test_discovery_prefers_path_then_the_highest_installed_native_binary(self):
        home = Path(self.temp.name) / "home"
        for version in ("2.1.9", "2.1.267", "2.0.1"):
            binary = home / f".vscode-server/extensions/anthropic.claude-code-{version}-linux-x64/resources/native-binary/claude"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=None), \
             patch.object(Path, "home", staticmethod(lambda: home)):
            self.assertIn("2.1.267", str(workers.resolve_claude(None)))
        with patch.object(workers.shutil, "which", return_value=str(self.claude)):
            self.assertEqual(workers.resolve_claude(None), self.claude.resolve())

    def test_a_second_supervisor_refuses_to_share_the_runtime(self):
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.runtime / "supervisor.lock").open("a+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(SystemExit, "already running"):
                workers.main(["run", "--once", "--no-notices", "--claude", str(self.claude)])


class StateIntegrityTests(RunnerTestCase):
    def test_corrupt_state_fails_closed_and_keeps_a_diagnostic(self):
        self.register()
        path = self.runtime / "state.json"
        original = path.read_text()
        for content, expected in (("{ not json", "unusable"),
                                  (json.dumps([]), "not an object"),
                                  (json.dumps({"schema_version": 99, "workers": {}, "jobs": {},
                                               "sequence": 0}), "schema_version"),
                                  (json.dumps({"schema_version": 1, "workers": [], "jobs": {},
                                               "sequence": 0}), "workers is not a dict")):
            with self.subTest(content=content[:20]):
                path.write_text(content)
                with self.assertRaisesRegex(SystemExit, expected):
                    workers.main(["status"])
                with self.assertRaisesRegex(SystemExit, expected):
                    self.enqueue()
                self.assertEqual(path.read_text(), content, "corrupt state must not be rewritten")
        self.assertTrue(list(self.runtime.glob("state.corrupt.*.txt")))
        path.write_text(original)
        self.assertEqual(json.loads(self.status())["workers"][0]["id"], "w1")

    def test_symlinked_state_or_shared_modes_are_refused(self):
        self.register()
        path = self.runtime / "state.json"
        real = self.runtime / "state.moved.json"
        path.rename(real)
        path.symlink_to(real)
        with self.assertRaisesRegex(SystemExit, "symlinked"):
            workers.main(["status"])
        path.unlink()
        real.rename(path)
        (self.runtime / "jobs").chmod(0o770)
        with self.assertRaisesRegex(SystemExit, "group/world-writable"):
            self.enqueue()
        (self.runtime / "jobs").chmod(0o700)
        self.enqueue()

    def test_symlinked_runtime_directory_is_refused(self):
        real = Path(self.temp.name) / "real-runtime"
        real.mkdir(mode=0o700)
        link = Path(self.temp.name) / "linked-runtime"
        link.symlink_to(real)
        with patch.object(workers, "RUNTIME", link):
            with self.assertRaisesRegex(SystemExit, "symlinked"):
                self.register()

    def test_runtime_stays_private_under_a_permissive_host_umask(self):
        previous = os.umask(0o002)  # The ordinary interactive umask on this host.
        self.addCleanup(os.umask, previous)
        root = Path(self.temp.name) / "umask-case"
        repo = root / "repo"
        repo.mkdir(parents=True)
        root.chmod(0o700)  # The runtime's parent must be private too, explicitly.
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        common = repo / ".git"
        self.assertEqual(common.stat().st_mode & 0o777, 0o775,
                         "git init inherits the host umask; that is what the fixture must fix")
        common.chmod(0o700)  # Fixture repair, not a relaxed production check.
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit",
                        "--allow-empty", "-qm", "fixture"], check=True)
        runtime = root / "runtime"
        with patch.object(workers, "RUNTIME", runtime), \
             patch.object(workers, "COMMON_DIR", common):
            workers.main(["register", "--worker", "u1", "--worktree", str(repo),
                          "--role", "implementer", "--allow-tool", "Read"])
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
            self.assertEqual((runtime / "jobs").stat().st_mode & 0o777, 0o700)
            self.assertEqual((runtime / "state.json").stat().st_mode & 0o777, 0o600)

    def test_group_writable_common_directory_is_still_refused(self):
        common = self.repo / ".git"
        common.chmod(0o775)
        self.addCleanup(common.chmod, 0o700)
        with self.assertRaisesRegex(SystemExit, "group/world-writable"):
            self.register()

    def test_missing_state_file_still_starts_a_first_registry(self):
        self.register()
        self.assertEqual(workers.load_state()["schema_version"], workers.SCHEMA_VERSION)
        (self.runtime / "state.json").unlink()
        self.assertEqual(workers.load_state(), workers.fresh_state())


class PrivacyTests(RunnerTestCase):
    def test_runtime_lives_outside_tracked_files_and_stays_private(self):
        self.assertIn(".git", DEFAULT_RUNTIME.parts, "runtime must sit under the Git common directory")
        self.assertEqual(DEFAULT_RUNTIME.name, "workers")
        self.register()
        self.enqueue()
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o700)
        for name in ("prompt.txt", "composed.txt"):
            self.assertEqual((workers.job_dir("w1:j1") / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.runtime / "state.json").stat().st_mode & 0o777, 0o600)
        tracked = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"],
                                 capture_output=True, text=True, check=True)
        self.assertEqual(tracked.stdout, "?? workflow/\n")  # the test's stub bus CLI only

    def test_status_publishes_no_prompt_text_and_no_raw_session_id(self):
        self.register()
        self.enqueue()
        state = self.settle("w1:j1")
        report = self.status()
        self.assertNotIn("Implement the approved plan", report)
        self.assertNotIn(state["workers"]["w1"]["session_id"], report)
        payload = json.loads(report)
        self.assertEqual(payload["workers"][0]["session_fingerprint"],
                         workers.sha256(state["workers"]["w1"]["session_id"])[:12])
        self.assertEqual(payload["jobs"][0]["prompt_sha256"],
                         workers.sha256(self.prompt.read_text()))
        self.assertIn("stay with the lead", payload["note"])

    def test_result_command_shows_the_final_text_for_the_lead(self):
        self.register()
        self.enqueue()
        self.settle("w1:j1")
        self.assertIn("awaiting lead review", self.capture(["result", "--job", "w1:j1"]))


class NoticeTests(RunnerTestCase):
    def notified_job(self, worker="w1", worktree=None, role="implementer"):
        self.register(worker, worktree, role=role)
        self.enqueue(worker, "j1", extra=["--notify-lead", "--subject-kind", "campaign",
                                          "--subject-id", "claude-workers"])
        return self.settle(f"{worker}:j1")

    def sent_ok(self, argv, **kwargs):
        self.sent.append(argv)
        return subprocess.CompletedProcess(argv, 0, "/inbox/000123-w1-runner.md", "")

    def sent_failing(self, argv, **kwargs):
        self.sent.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "bus down")

    def setUp(self):
        super().setUp()
        self.sent = []

    def test_completion_notice_uses_the_worker_root_role_and_sends_once(self):
        self.notified_job()
        with patch.object(workers.subprocess, "run", self.sent_ok):
            self.assertEqual(workers.notices_pass(), 1)
            self.assertEqual(workers.notices_pass(), 0)  # An ordinary restart must not re-notify.
        self.assertEqual(len(self.sent), 1)
        argv = self.sent[0]
        self.assertEqual(argv[1], str(self.bus), "notices must use the worker worktree's bus CLI")
        self.assertEqual(argv[argv.index("--to") + 1], "codex-lead")
        self.assertEqual(argv[argv.index("--role") + 1], "implementer")
        self.assertEqual(argv[argv.index("--subject-id") + 1], "claude-workers")
        notice = workers.load_state()["jobs"]["w1:j1"]["notice"]
        self.assertTrue(notice["sent"])
        self.assertIn("000123", notice["receipt"])
        body = Path(argv[argv.index("--body-file") + 1]).read_text()
        self.assertIn("Submitted for independent lead review", body)
        self.assertIn("Not an approval", body)
        self.assertNotIn("Implement the approved plan", body)

    def test_notice_role_reflects_the_registration(self):
        self.notified_job(role="investigator")
        with patch.object(workers.subprocess, "run", self.sent_ok):
            workers.notices_pass()
        argv = self.sent[0]
        self.assertEqual(argv[argv.index("--role") + 1], "investigator")

    def test_notification_failure_keeps_the_result_and_retries_with_backoff(self):
        self.notified_job()
        with patch.object(workers.subprocess, "run", self.sent_failing):
            self.assertEqual(workers.notices_pass(), 1)
        job = workers.load_state()["jobs"]["w1:j1"]
        self.assertEqual(job["state"], "done")
        self.assertFalse(job["notice"]["sent"])
        self.assertIn("bus down", job["notice"]["error"])
        self.assertEqual(job["notice"]["attempts"], 1)
        self.assertGreater(job["notice"]["retry_after"], time.time())
        with patch.object(workers.subprocess, "run", self.sent_failing):
            self.assertEqual(workers.notices_pass(), 0)  # Backoff, not a 2-second hot loop.
        self.assertEqual(len(self.sent), 1)
        with workers.locked_state() as state:
            state["jobs"]["w1:j1"]["notice"]["retry_after"] = 0
        with patch.object(workers.subprocess, "run", self.sent_ok):
            self.assertEqual(workers.notices_pass(), 1)
        notice = workers.load_state()["jobs"]["w1:j1"]["notice"]
        self.assertTrue(notice["sent"])
        self.assertEqual(notice["attempts"], 2)
        self.assertLessEqual(workers.notice_backoff(99), max(workers.NOTICE_BACKOFF))

    def test_notice_send_never_holds_the_global_state_lock(self):
        self.notified_job()
        acquired = []

        def probe(argv, **kwargs):
            with (self.runtime / "state.lock").open("a+") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired.append(True)
                    fcntl.flock(handle, fcntl.LOCK_UN)
                except BlockingIOError:
                    acquired.append(False)
            return self.sent_ok(argv, **kwargs)

        with patch.object(workers.subprocess, "run", probe):
            workers.notices_pass()
        self.assertEqual(acquired, [True], "the state lock must be free while the bus is called")

    def test_missing_worker_bus_cli_is_reported_not_silently_rerouted(self):
        self.notified_job("w2", self.peer)  # the peer worktree has no workflow/ tree
        def refuse(argv, **kwargs):
            raise AssertionError("no bus call may be attempted without the worker's own CLI")
        with patch.object(workers.subprocess, "run", refuse):
            self.assertEqual(workers.notices_pass(), 0)
        notice = workers.load_state()["jobs"]["w2:j1"]["notice"]
        self.assertFalse(notice["sent"])
        self.assertIn("no bus CLI", notice["error"])
        self.assertEqual(workers.load_state()["jobs"]["w2:j1"]["state"], "done")

    def test_notice_requires_an_explicit_subject(self):
        self.register()
        with self.assertRaisesRegex(SystemExit, "subject-kind"):
            self.enqueue(extra=["--notify-lead"])
        with self.assertRaises(SystemExit):
            self.enqueue(extra=["--notify-lead", "--subject-kind", "campaign",
                                "--subject-id", "../escape"])


if __name__ == "__main__":
    unittest.main()
