"""Regression tests for digest-bound release image retagging."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/ci/retag-images.sh"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
REGISTRY = "753556437180.dkr.ecr.us-east-2.amazonaws.com"
OPERATOR_DIGEST = "sha256:" + "a" * 64
CONSOLE_DIGEST = "sha256:" + "b" * 64


class DeployImageManifestTests(unittest.TestCase):
    def run_retag(self, **overrides):
        with tempfile.TemporaryDirectory(prefix="deploy-retag-test-") as raw:
            tmp = Path(raw)
            calls = tmp / "calls.jsonl"
            docker = tmp / "docker"
            docker.write_text(
                "#!" + sys.executable + "\n"
                "import json, os, pathlib, sys\n"
                "with pathlib.Path(os.environ['FAKE_DOCKER_CALLS']).open('a') as out:\n"
                "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            )
            docker.chmod(0o700)
            env = dict(
                os.environ,
                PATH=str(tmp) + os.pathsep + os.environ["PATH"],
                FAKE_DOCKER_CALLS=str(calls),
                REG=REGISTRY,
                V="0.4.106",
                MARKERS="ci:phorvex-tag ci:console-tag",
                SOURCE_MODE="digest",
                RELEASE_FROM="",
                OPERATOR_DIGEST=OPERATOR_DIGEST,
                CONSOLE_DIGEST=CONSOLE_DIGEST,
            )
            env.update(overrides)
            result = subprocess.run(
                ["bash", str(SCRIPT)], env=env, text=True, capture_output=True, timeout=5
            )
            actual = (
                [json.loads(line) for line in calls.read_text().splitlines()]
                if calls.exists()
                else []
            )
        return result, actual

    def test_normal_release_retags_the_exact_build_digests(self):
        result, calls = self.run_retag()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                ["buildx", "imagetools", "create", "--prefer-index=false", "-t",
                 f"{REGISTRY}/phorvex:0.4.106",
                 f"{REGISTRY}/phorvex@{OPERATOR_DIGEST}"],
                ["buildx", "imagetools", "create", "--prefer-index=false", "-t",
                 f"{REGISTRY}/phorvex-console:0.4.106",
                 f"{REGISTRY}/phorvex-console@{CONSOLE_DIGEST}"],
            ],
        )

    def test_partial_release_only_requires_the_selected_build_digest(self):
        result, calls = self.run_retag(
            MARKERS="ci:console-tag", OPERATOR_DIGEST="", CONSOLE_DIGEST=CONSOLE_DIGEST
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], f"{REGISTRY}/phorvex-console@{CONSOLE_DIGEST}")

    def test_forced_recovery_uses_the_explicit_tag_for_both_images(self):
        result, calls = self.run_retag(
            SOURCE_MODE="tag", RELEASE_FROM="sha-6624065",
            OPERATOR_DIGEST="", CONSOLE_DIGEST=""
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [call[-1] for call in calls],
            [f"{REGISTRY}/phorvex:sha-6624065",
             f"{REGISTRY}/phorvex-console:sha-6624065"],
        )

    def test_invalid_inputs_fail_before_docker(self):
        cases = {
            "missing selected digest": {"OPERATOR_DIGEST": ""},
            "malformed selected digest": {"CONSOLE_DIGEST": "sha256:1234"},
            "uppercase digest": {"OPERATOR_DIGEST": "sha256:" + "A" * 64},
            "unknown marker": {"MARKERS": "ci:phorvex-tag ci:unknown-tag"},
            "duplicate marker": {"MARKERS": "ci:phorvex-tag ci:phorvex-tag"},
            "invalid destination tag": {"V": "bad/tag"},
            "missing forced source": {"SOURCE_MODE": "tag", "RELEASE_FROM": ""},
            "invalid forced source": {"SOURCE_MODE": "tag", "RELEASE_FROM": "bad tag"},
            "tag supplied in digest mode": {"RELEASE_FROM": "sha-deadbeef"},
            "unknown mode": {"SOURCE_MODE": "guess"},
            "invalid registry": {"REG": "registry/path"},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                result, calls = self.run_retag(**overrides)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(calls, [])

    def test_workflow_exports_and_consumes_build_digests(self):
        raw = WORKFLOW.read_text()
        doc = yaml.load(raw, Loader=yaml.BaseLoader)
        jobs = doc["jobs"]

        for job_name in ("build-operator", "build-console"):
            job = jobs[job_name]
            self.assertEqual(job["outputs"]["digest"], "${{ steps.build.outputs.digest }}")
            build = next(step for step in job["steps"]
                         if step.get("uses") == "docker/build-push-action@v6")
            self.assertEqual(build["id"], "build")
            meta = next(step for step in job["steps"]
                        if step.get("uses") == "docker/metadata-action@v5")
            self.assertIn("type=sha,prefix=sha-,format=long", meta["with"]["tags"])

        # Phoenix isn't deployed here, but its convenience SHA tag must follow the same
        # collision-free convention as the other images.
        phoenix_meta = next(step for step in jobs["build-phoenix"]["steps"]
                            if step.get("uses") == "docker/metadata-action@v5")
        self.assertIn("type=sha,prefix=sha-,format=long", phoenix_meta["with"]["tags"])
        self.assertNotIn("format=short", raw)
        self.assertNotIn("git rev-parse --short", raw)

        deploy_steps = jobs["deploy"]["steps"]
        retag = next(step for step in deploy_steps
                     if step.get("name") == "Tag the built images with the version")
        self.assertEqual(retag["run"].strip(), "bash deploy/ci/retag-images.sh")
        self.assertEqual(retag["env"]["OPERATOR_DIGEST"],
                         "${{ needs.build-operator.outputs.digest }}")
        self.assertEqual(retag["env"]["CONSOLE_DIGEST"],
                         "${{ needs.build-console.outputs.digest }}")
        self.assertIn("inputs.force_release && 'tag' || 'digest'", retag["env"]["SOURCE_MODE"])
        self.assertEqual(retag["env"]["RELEASE_FROM"], "${{ inputs.release_from }}")

        version = next(step for step in deploy_steps
                       if step.get("name") == "Compute the next version")
        self.assertNotIn("sha_tag", version["run"])
        chart_checks = "\n".join(step.get("run", "") for step in jobs["chart-sync"]["steps"])
        self.assertIn("bash -n deploy/ci/retag-images.sh", chart_checks)
        self.assertIn("python3 tools/test_deploy_image_manifest.py", chart_checks)


if __name__ == "__main__":
    unittest.main()
