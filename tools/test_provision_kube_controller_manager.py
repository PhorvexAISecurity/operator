"""Deterministic controls for pinned kube-controller-manager provisioning."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/provision-kube-controller-manager.sh'


def executable(path: Path, body: str) -> None:
    path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class ProvisionKubeControllerManagerTests(unittest.TestCase):
    def run_case(self, *, producer: str = "echo 'Kubernetes v1.34.0'",
                 checksum: str = 'cat >/dev/null') -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix='provision-kcm-') as raw:
            root = Path(raw)
            commands = root / 'commands'
            commands.mkdir()
            curl = '''
out=''
while (($#)); do
  [[ $1 == -o ]] && { out=$2; shift 2; continue; }
  shift
done
cat >"$out" <<'BIN'
#!/usr/bin/env bash
set -euo pipefail
''' + producer + '''
BIN
'''
            executable(commands / 'curl', curl)
            executable(commands / 'sha256sum', checksum + '\n')
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'])
            return subprocess.run(['bash', str(SCRIPT), str(root / 'destination')], text=True,
                                  capture_output=True, env=env, timeout=15)

    def test_verified_exact_version_returns_one_executable_path(self):
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith('/kube-controller-manager'))
        self.assertIn('Kubernetes v1.34.0', result.stderr)

    def test_wrong_version_is_rejected(self):
        result = self.run_case(producer="echo 'Kubernetes v1.33.9'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kube-controller-manager is not Kubernetes v1.34.0', result.stderr)
        self.assertIn('Kubernetes v1.33.9', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_nonzero_binary_is_rejected_even_when_output_matches(self):
        result = self.run_case(producer="echo 'Kubernetes v1.34.0'; exit 9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kube-controller-manager binary does not run', result.stderr)
        self.assertIn('Kubernetes v1.34.0', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_checksum_failure_prevents_execution_and_path_output(self):
        result = self.run_case(producer="echo 'UNVERIFIED BINARY EXECUTED' >&2; echo 'Kubernetes v1.34.0'",
                               checksum='cat >/dev/null; echo checksum-mismatch >&2; exit 4')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum-mismatch', result.stderr)
        self.assertNotIn('UNVERIFIED BINARY EXECUTED', result.stderr)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
