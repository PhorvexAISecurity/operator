"""Keep source-bound bot/worker/stage regressions gating, including real Go runs."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BenchmarkRegressionTests(unittest.TestCase):
    def test_bot_worker_and_stage_with_real_shared_kernel(self):
        version = re.search(r"^go (\d+\.\d+\.\d+)$", (ROOT / "build/test-harness/go.mod").read_text(), re.M).group(1)
        go = os.environ.get("GO_BIN") or shutil.which("go")
        self.assertTrue(go, "exact CI Go compiler is required; benchmark integrations may not skip")
        env = dict(os.environ, ENDPOINT_GO=go, GOTOOLCHAIN="local", PYTHONDONTWRITEBYTECODE="1")
        actual = subprocess.check_output([go, "version"], env=env, text=True).strip()
        self.assertTrue(actual.startswith("go version go" + version + " "), actual)
        build = subprocess.run([sys.executable, "benchmark/endpointv3/build.py"], cwd=ROOT, env=env,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        self.assertEqual(build.returncode, 0, build.stdout)
        print(build.stdout, end="", flush=True)
        # A subprocess per suite prevents identically named test modules from
        # masking one another. A newly skipped integration cannot appear green.
        runner = (
            "import sys,unittest; "
            "suite=unittest.defaultTestLoader.discover(sys.argv[1], pattern='test_*.py', "
            "top_level_dir='.' if sys.argv[1]=='benchmark/stage' else None); "
            "result=unittest.TextTestRunner(verbosity=2).run(suite); "
            "sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1)"
        )
        for suite in ("benchmark/bot", "benchmark/worker", "benchmark/stage"):
            with self.subTest(suite=suite):
                result = subprocess.run([sys.executable, "-c", runner, suite], cwd=ROOT, env=env,
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
                print(result.stdout, end="", flush=True)
                self.assertEqual(result.returncode, 0, result.stdout)
