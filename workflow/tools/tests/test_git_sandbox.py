"""Temporary repositories must not outlive their context through Git maintenance."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_operations import run, sandbox


class GitSandboxTests(unittest.TestCase):
    def test_sandbox_disables_maintenance_before_its_first_commit(self):
        # Trace the real baseline commit, not a mocked subprocess. The trace lives
        # outside the sandbox so that its own cleanup cannot race repository removal.
        with tempfile.TemporaryDirectory(prefix="workflow-git-trace-") as raw:
            trace = Path(raw) / "trace.jsonl"
            with patch.dict(os.environ, {"GIT_TRACE2_EVENT": str(trace)}):
                with sandbox() as (repo, _, _):
                    self.assertEqual(
                        run(
                            [
                                "git",
                                "config",
                                "--local",
                                "--bool",
                                "maintenance.auto",
                            ],
                            repo,
                        ),
                        "false",
                    )
                    self.assertEqual(
                        run(
                            ["git", "config", "--local", "--int", "gc.auto"],
                            repo,
                        ),
                        "0",
                    )
                    self.assertTrue(run(["git", "rev-parse", "HEAD"], repo))
            self.assertFalse(repo.exists())
            events = [json.loads(line) for line in trace.read_text().splitlines()]
            children = [
                event.get("argv", [])
                for event in events
                if event.get("event") == "child_start"
            ]
            self.assertFalse(
                [argv for argv in children if "maintenance" in argv or "gc" in argv],
                children,
            )
