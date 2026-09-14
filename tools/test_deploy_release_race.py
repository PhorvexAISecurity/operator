"""Regression tests for serialized, source-bound publication from persistent runners."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "deploy/ci/check-release-head.sh"
PUBLISH = ROOT / "deploy/ci/publish-release.sh"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
VALUES = Path("deploy/helm/phorvex-stack/values-eks.yaml")


def git(cwd, *args, check=True):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=check, text=True, capture_output=True
    )


class ReleaseRepository:
    def __init__(self, root):
        self.root = Path(root)
        self.remote = self.root / "origin.git"
        self.seed = self.root / "seed"
        git(self.root, "init", "--bare", str(self.remote))
        git(self.root, "init", "-b", "main", str(self.seed))
        git(self.seed, "config", "user.name", "test")
        git(self.seed, "config", "user.email", "test@example.invalid")
        path = self.seed / VALUES
        path.parent.mkdir(parents=True)
        path.write_text('operator:\n  image:\n    tag: "0.4.116" # ci:phorvex-tag\n')
        git(self.seed, "add", str(VALUES))
        git(self.seed, "commit", "-m", "source")
        git(self.seed, "remote", "add", "origin", str(self.remote))
        git(self.seed, "push", "-u", "origin", "main")
        git(self.remote, "symbolic-ref", "HEAD", "refs/heads/main")
        self.source = git(self.seed, "rev-parse", "HEAD").stdout.strip()

    def clone(self, name):
        path = self.root / name
        git(self.root, "clone", str(self.remote), str(path))
        git(path, "config", "user.name", "test")
        git(path, "config", "user.email", "test@example.invalid")
        return path

    def advance(self):
        actor = self.clone("actor")
        (actor / "advance.txt").write_text("new main\n")
        git(actor, "add", "advance.txt")
        git(actor, "commit", "-m", "advance main")
        git(actor, "push", "origin", "main")
        return git(actor, "rev-parse", "HEAD").stdout.strip()


class DeployReleaseRaceTests(unittest.TestCase):
    def run_script(self, script, repo, source, **extra):
        output = Path(repo) / "github-output"
        env = dict(os.environ, SOURCE_SHA=source, GITHUB_OUTPUT=str(output), **extra)
        result = subprocess.run(
            ["bash", str(script)], cwd=repo, env=env, text=True,
            capture_output=True, timeout=10
        )
        values = dict(
            line.split("=", 1) for line in output.read_text().splitlines()
        ) if output.exists() else {}
        return result, values

    def test_fresh_source_proceeds_and_prunes_rejected_local_tags(self):
        with tempfile.TemporaryDirectory(prefix="release-race-") as raw:
            fixture = ReleaseRepository(raw)
            job = fixture.clone("job")
            git(job, "tag", "v9.9.9")
            result, outputs = self.run_script(CHECK, job, fixture.source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs["current"], "true")
            self.assertEqual(outputs["remote_sha"], fixture.source)
            self.assertNotIn("v9.9.9", git(job, "tag", "-l").stdout.splitlines())

    def test_source_behind_main_is_superseded_before_release(self):
        with tempfile.TemporaryDirectory(prefix="release-race-") as raw:
            fixture = ReleaseRepository(raw)
            job = fixture.clone("job")
            remote = fixture.advance()
            result, outputs = self.run_script(CHECK, job, fixture.source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs, {"remote_sha": remote, "current": "false"})
            self.assertIn("superseded", result.stdout)

    def test_atomic_publication_moves_main_and_tag_together(self):
        with tempfile.TemporaryDirectory(prefix="release-race-") as raw:
            fixture = ReleaseRepository(raw)
            job = fixture.clone("job")
            path = job / VALUES
            path.write_text(path.read_text().replace("0.4.116", "0.4.117"))
            result, outputs = self.run_script(
                PUBLISH, job, fixture.source, V="0.4.117"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs["released"], "true")
            main = git(fixture.remote, "rev-parse", "refs/heads/main").stdout.strip()
            tag = git(fixture.remote, "rev-list", "-n", "1", "v0.4.117").stdout.strip()
            self.assertEqual(main, tag)
            self.assertEqual(git(fixture.remote, "rev-parse", f"{main}^").stdout.strip(),
                             fixture.source)

    def test_main_advance_during_release_is_a_clean_supersession(self):
        with tempfile.TemporaryDirectory(prefix="release-race-") as raw:
            fixture = ReleaseRepository(raw)
            job = fixture.clone("job")
            path = job / VALUES
            path.write_text(path.read_text().replace("0.4.116", "0.4.117"))
            advanced = fixture.advance()
            result, outputs = self.run_script(
                PUBLISH, job, fixture.source, V="0.4.117"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs["released"], "false")
            self.assertIn("superseded", result.stdout)
            self.assertEqual(git(fixture.remote, "rev-parse", "main").stdout.strip(), advanced)
            self.assertEqual(git(fixture.remote, "tag", "-l", "v0.4.117").stdout, "")
            self.assertEqual(git(job, "tag", "-l", "v0.4.117").stdout, "")

    def test_workflow_gates_side_effects_and_post_deploy_e2e(self):
        doc = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        jobs = doc["jobs"]
        deploy = jobs["deploy"]
        self.assertEqual(deploy["outputs"]["released"],
                         "${{ steps.publish.outputs.released }}")
        steps = deploy["steps"]
        freshness = next(step for step in steps if step.get("id") == "freshness")
        self.assertEqual(freshness["run"], "bash deploy/ci/check-release-head.sh")
        self.assertEqual(freshness["env"]["SOURCE_SHA"], "${{ github.sha }}")
        for name in (
            "Compute the next version", "Decide what was built",
            "Tag the built images with the version",
            "Write the version into the GitOps values",
        ):
            step = next(item for item in steps if item.get("name") == name)
            self.assertIn("steps.freshness.outputs.current == 'true'", step["if"])
        publish = next(step for step in steps if step.get("id") == "publish")
        self.assertEqual(publish["run"], "bash deploy/ci/publish-release.sh")
        self.assertIn("steps.freshness.outputs.current == 'true'", publish["if"])
        for name in ("Provision the SSH host identity", "Wait for ArgoCD to roll it out"):
            step = next(item for item in steps if item.get("name") == name)
            self.assertEqual(step["if"], "steps.publish.outputs.released == 'true'")
        self.assertIn("needs.deploy.outputs.released == 'true'", jobs["e2e-main"]["if"])


if __name__ == "__main__":
    unittest.main()
