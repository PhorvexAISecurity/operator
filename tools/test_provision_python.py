"""Deterministic controls for the pinned, relocatable CI Python."""
from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/provision-python.sh'


def executable(path: Path, body: str) -> None:
    path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class ProvisionPythonTests(unittest.TestCase):
    def run_case(self, version: str, *, reported: str | None = None, checksum_ok: bool = True,
                 needs_environment: bool = False) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix='provision-python-') as raw:
            root = Path(raw); commands = root / 'commands'; commands.mkdir()
            executable(commands / 'curl', 'out=""; url=""; while (($#)); do [[ $1 == -o ]] && { out=$2; shift 2; continue; }; url=$1; shift; done\n'
                       f'printf "%s" "$url" > {root}/url; printf archive >"$out"\n')
            executable(commands / 'sha256sum', f'cat > {root}/checksum\n' + ('' if checksum_ok else 'exit 1\n'))
            interpreter = f'echo {reported or "VERSION"}\n'
            if needs_environment:
                interpreter = '[ -n "${LD_LIBRARY_PATH:-}" ] || { echo "libpython not found" >&2; exit 127; }\n' + interpreter
            executable(commands / 'tar', 'dest=""; while (($#)); do [[ $1 == -C ]] && { dest=$2; shift 2; continue; }; shift; done\n'
                       'mkdir -p "$dest/python/bin"\n'
                       f"cat > \"$dest/python/bin/python3\" <<'BIN'\n#!/bin/sh\n{interpreter}BIN\n"
                       'chmod +x "$dest/python/bin/python3"\n')
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], LD_LIBRARY_PATH='/inherited')
            result = subprocess.run(['bash', str(SCRIPT), version, str(root / 'destination')], text=True,
                                    capture_output=True, env=env, timeout=15)
            result.url = (root / 'url').read_text() if (root / 'url').exists() else ''
            result.checksum = (root / 'checksum').read_text() if (root / 'checksum').exists() else ''
            return result

    def pinned(self, version: str) -> str:
        match = re.search(rf'{re.escape(version)}\) VERSION=(\S+)', SCRIPT.read_text())
        return match.group(1)

    def test_pinned_versions_download_by_digest_and_report_their_version(self):
        for version in ('3.11', '3.12'):
            with self.subTest(version=version):
                full = self.pinned(version)
                result = self.run_case(version, reported=full)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.strip().endswith('/destination/python/bin'))
                self.assertEqual(result.url, 'https://github.com/astral-sh/python-build-standalone/releases/download/'
                                 f'20261001/cpython-{full}%2B20261001-x86_64-unknown-linux-gnu-install_only.tar.gz')
                self.assertRegex(result.checksum, r'^[0-9a-f]{64}  .+install_only\.tar\.gz\n$')

    def test_checksum_mismatch_is_refused(self):
        result = self.run_case('3.12', reported=self.pinned('3.12'), checksum_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_interpreter_must_start_without_an_inherited_environment(self):
        result = self.run_case('3.12', reported=self.pinned('3.12'), needs_environment=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not start with an empty environment', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_wrong_version_and_unknown_series_are_refused(self):
        result = self.run_case('3.12', reported='3.12.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not ' + self.pinned('3.12'), result.stderr)
        self.assertEqual(self.run_case('3.13').returncode, 2)


class WorkflowPythonTests(unittest.TestCase):
    def test_workflows_provision_the_pinned_python_instead_of_setup_python(self):
        provisioned = 0
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            raw = path.read_text()
            with self.subTest(workflow=path.name):
                self.assertNotIn('actions/setup-python', raw)
                doc = yaml.load(raw, Loader=yaml.BaseLoader)
                for job in doc['jobs'].values():
                    for step in job.get('steps', []):
                        run = step.get('run', '')
                        if 'tools/provision-python.sh' in run:
                            provisioned += 1
                            # Assigned first, so a failed provision fails the step under bash -e.
                            self.assertRegex(run, r'^bin="\$\(bash tools/provision-python\.sh 3\.1[12] "\$RUNNER_TEMP/python"\)"\n'
                                                  r'echo "\$bin" >> "\$GITHUB_PATH"\n?$')
        self.assertGreater(provisioned, 0)


if __name__ == '__main__':
    unittest.main()
