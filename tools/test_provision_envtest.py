"""Deterministic controls for the complete envtest provisioning validation path."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/provision-envtest.sh'


def executable(path: Path, body: str) -> None:
    path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class ProvisionEnvtestTests(unittest.TestCase):
    def run_case(self, *, kube: str = "echo 'Kubernetes v1.34.0'", etcd: str | None = None,
                 missing: str | None = None) -> subprocess.CompletedProcess[str]:
        if etcd is None:
            etcd = "echo 'etcd Version: 3.6.4'; for n in $(seq 1 12000); do echo diagnostic-$n; done; echo drain-complete"
        with tempfile.TemporaryDirectory(prefix='provision-envtest-') as raw:
            root = Path(raw); commands = root/'commands'; commands.mkdir()
            executable(commands/'curl', "out=''; while (($#)); do [[ $1 == -o ]] && { out=$2; shift 2; continue; }; shift; done; printf archive >\"$out\"\n")
            executable(commands/'sha256sum', 'cat >/dev/null\n')
            tar_body = textwrap.dedent(f'''\
                dest=''
                while (($#)); do [[ $1 == -C ]] && {{ dest=$2; shift 2; continue; }}; shift; done
                assets="$dest/controller-tools/envtest"; mkdir -p "$assets"
                ''')
            if missing != 'kube-apiserver':
                tar_body += f"cat >\"$assets/kube-apiserver\" <<'BIN'\n#!/usr/bin/env bash\n{kube}\nBIN\nchmod +x \"$assets/kube-apiserver\"\n"
            if missing != 'etcd':
                tar_body += f"cat >\"$assets/etcd\" <<'BIN'\n#!/usr/bin/env bash\n{etcd}\nBIN\nchmod +x \"$assets/etcd\"\n"
            executable(commands/'tar', tar_body)
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'])
            return subprocess.run(['bash', str(SCRIPT), str(root/'destination')], text=True,
                                  capture_output=True, env=env, timeout=15)

    def test_healthy_multi_write_producer_is_fully_drained_and_accepted(self):
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        stdout_lines = [line for line in result.stdout.splitlines() if line]
        self.assertEqual(len(stdout_lines), 1)
        self.assertTrue(stdout_lines[0].endswith('/controller-tools/envtest'))
        self.assertIn('diagnostic-12000', result.stderr)
        self.assertIn('drain-complete', result.stderr)
        self.assertIn('etcd Version: 3.6.4', result.stderr)

    def test_nonzero_producer_is_rejected_even_when_output_matches(self):
        result = self.run_case(etcd="echo 'etcd Version: 3.6.4'; exit 7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('etcd binary does not run', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_wrong_version_is_rejected_with_diagnostic_output(self):
        result = self.run_case(kube="echo 'Kubernetes v1.33.9'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Kubernetes v1.33.9', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_nonzero_kube_producer_is_rejected_even_when_version_matches(self):
        result = self.run_case(kube="echo 'Kubernetes v1.34.0'; exit 9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kube-apiserver binary does not run', result.stderr)
        self.assertIn('Kubernetes v1.34.0', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_missing_etcd_version_marker_is_rejected(self):
        result = self.run_case(etcd="echo 'etcd 3.6.4 without canonical marker'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('etcd version marker is missing', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_missing_binary_is_rejected(self):
        result = self.run_case(missing='etcd')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing envtest binary:', result.stderr)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
