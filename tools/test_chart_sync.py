"""Exercise the actual CI shell step against isolated miniature chart fixtures."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
STEP = next(
    step["run"]
    for step in yaml.safe_load(WORKFLOW.read_text())["jobs"]["chart-sync"]["steps"]
    if step.get("name") == "Vendored subchart matches its source"
)


class ChartSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chart-sync-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner_temp = self.root / "runner temp"
        self.runner_temp.mkdir()
        self.source = self.root / "phorvex/charts/phorvex"
        (self.source / "templates").mkdir(parents=True)
        (self.source / "Chart.yaml").write_text("apiVersion: v2\nname: phorvex\nversion: 0.1.4\n")
        (self.source / "values.yaml").write_text("replicaCount: 1\n")
        (self.source / "templates/deployment.yaml").write_text("kind: Deployment\n")
        self.archive = self.root / "deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz"
        self.archive.parent.mkdir(parents=True)
        self.package()

    def package(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.source, arcname="phorvex")

    def check(self):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", STEP],
            cwd=self.root,
            env=dict(os.environ, RUNNER_TEMP=str(self.runner_temp),
                     PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]),
            capture_output=True, text=True, timeout=30,
        )

    def assert_check(self, success):
        result = self.check()
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        # The extraction must be cleaned on both the success and failure paths.
        self.assertEqual(list(self.runner_temp.iterdir()), [])
        return result

    def test_matching_chart_and_reordered_metadata(self):
        (self.source / "Chart.yaml").write_text("version: 0.1.4\nname: phorvex\napiVersion: v2\n")
        self.assert_check(True)

    def test_stale_runner_files_and_concurrent_checks_are_isolated(self):
        stale = self.runner_temp / "vendored/phorvex/templates/leader-election-rbac.yaml"
        stale.parent.mkdir(parents=True)
        stale.write_text("kind: Role\n")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.check(), range(2)))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(stale.read_text(), "kind: Role\n")
        self.assertEqual(list(self.runner_temp.iterdir()), [self.runner_temp / "vendored"])

    def test_changed_template_still_fails(self):
        (self.source / "templates/deployment.yaml").write_text("kind: StatefulSet\n")
        self.assert_check(False)

    def test_template_removed_from_source_still_fails(self):
        (self.source / "templates/deployment.yaml").unlink()
        self.assert_check(False)

    def test_template_missing_from_archive_still_fails(self):
        (self.source / "templates/service.yaml").write_text("kind: Service\n")
        self.assert_check(False)

    def test_metadata_drift_still_fails(self):
        with (self.source / "Chart.yaml").open("a") as metadata:
            metadata.write("description: Changed metadata\n")
        result = self.assert_check(False)
        self.assertIn("Chart.yaml description", result.stdout)

    def test_missing_archive_still_fails(self):
        self.archive.unlink()
        self.assert_check(False)

    def test_corrupt_archive_still_fails_and_cleans_up(self):
        self.archive.write_bytes(b"not a tar archive")
        self.assert_check(False)


if __name__ == "__main__":
    unittest.main()
