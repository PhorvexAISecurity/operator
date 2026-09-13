"""Negative controls for the envtest gate: every way a green-looking report can lie must fail."""
from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import envtest_gate as gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ACTUATOR = 'github.com/phorvex/phorvex/internal/actuator'
RUNNER = 'github.com/phorvex/phorvex/internal/runner'


def event(action, package, test=None, **extra):
    e = {'Time': '2026-09-13T00:00:00Z', 'Action': action, 'Package': package}
    if test:
        e['Test'] = test
    e.update(extra)
    return json.dumps(e)


def passing_stream(subtests=()):
    """A well-formed report: every expected test runs and passes, both packages pass."""
    lines = []
    for package, tests in gate.EXPECTED.items():
        lines.append(event('start', package))
        for test in tests:
            lines.append(event('run', package, test))
            lines.append(event('output', package, test, Output=f'=== RUN   {test}\n'))
            for sub in subtests:
                lines.append(event('run', package, f'{test}/{sub}'))
                lines.append(event('pass', package, f'{test}/{sub}', Elapsed=0.01))
            lines.append(event('pass', package, test, Elapsed=1.5))
        lines.append(event('output', package, Output='ok  \t' + package + '\t3.0s\n'))
        lines.append(event('pass', package, Elapsed=3.0))
    return lines


def problems(lines, returncode=0):
    return gate.evaluate(lines, returncode)[0]


class EvaluateTests(unittest.TestCase):
    def test_positive_control_all_ran_and_passed(self):
        found, verdicts, packages = gate.evaluate(passing_stream(subtests=('case-a', 'case-b')), 0)
        self.assertEqual(found, [])
        self.assertEqual(set(verdicts.values()), {'pass'})
        self.assertEqual(set(verdicts), {t for ts in gate.EXPECTED.values() for t in ts})
        self.assertEqual(packages, {ACTUATOR: 'pass', RUNNER: 'pass'})

    def test_empty_report_is_rejected(self):
        found = problems([], 0)
        self.assertTrue(any('empty report' in p for p in found))
        self.assertTrue(any('never ran' in p for p in found))

    def test_missing_expected_test_is_rejected(self):
        lines = [l for l in passing_stream() if '"TestM013RealEventSink"' not in l]
        found = problems(lines)
        self.assertTrue(any('TestM013RealEventSink: never ran' in p for p in found), found)

    def test_skipped_test_is_rejected_even_with_green_exit(self):
        # The baseline CI shape: blank KUBEBUILDER_ASSETS, 8 skips, package pass, exit 0.
        lines = [l.replace('"Action": "pass"', '"Action": "skip"') if '"Test"' in l else l
                 for l in passing_stream()]
        found = problems(lines, 0)
        self.assertEqual(sum('skip' in p for p in found), 8, found)

    def test_one_skip_among_passes_is_rejected(self):
        lines = passing_stream()
        i = next(i for i, l in enumerate(lines) if '"TestM007RestrictedRequests"' in l and '"pass"' in l)
        lines[i] = event('skip', ACTUATOR, 'TestM007RestrictedRequests', Elapsed=0)
        self.assertEqual(problems(lines), [f'{ACTUATOR} TestM007RestrictedRequests: skip'])

    def test_failed_test_is_rejected(self):
        lines = passing_stream()
        i = next(i for i, l in enumerate(lines) if '"TestM005TwoManagersAndHandoff"' in l and '"pass"' in l)
        lines[i] = event('fail', RUNNER, 'TestM005TwoManagersAndHandoff', Elapsed=2)
        j = next(i for i, l in enumerate(lines) if l == event('pass', RUNNER, Elapsed=3.0))
        lines[j] = event('fail', RUNNER, Elapsed=3.0)
        found = problems(lines, 1)
        self.assertIn(f'{RUNNER} TestM005TwoManagersAndHandoff: fail', found)
        self.assertIn(f'package {RUNNER}: fail', found)
        self.assertIn('go test exited 1', found)

    def test_subtest_failure_under_passing_parent_is_rejected(self):
        lines = passing_stream(subtests=('ok',))
        at = lines.index(event('pass', ACTUATOR, 'TestM048APIServerLifecycle', Elapsed=1.5))
        lines[at:at] = [event('run', ACTUATOR, 'TestM048APIServerLifecycle/other-namespace'),
                        event('fail', ACTUATOR, 'TestM048APIServerLifecycle/other-namespace', Elapsed=0.1)]
        self.assertEqual(problems(lines), [f'{ACTUATOR} TestM048APIServerLifecycle/other-namespace: fail'])

    # Stream integrity (review R1.1): every observed selected parent/subtest is tracked to
    # completion. A normal Go run emits run-then-terminal for each; a stream that does not
    # carries no evidence for that test and must fail.
    def test_complete_subtest_run_and_terminal_is_accepted(self):
        lines = passing_stream(subtests=('long-pod-name', 'pod-patch'))
        self.assertEqual(problems(lines), [])

    def test_started_subtest_without_terminal_is_rejected(self):
        lines = passing_stream()
        lines.insert(2, event('run', ACTUATOR, 'TestM47APIServerPreconditions/lost-terminal'))
        self.assertEqual(problems(lines),
                         [f'{ACTUATOR} TestM47APIServerPreconditions/lost-terminal: no terminal event'])

    def test_terminal_without_run_is_rejected(self):
        lines = passing_stream()
        lines.insert(2, event('pass', ACTUATOR, 'TestM47APIServerPreconditions/orphan-pass', Elapsed=0))
        self.assertEqual(problems(lines),
                         [f'{ACTUATOR} TestM47APIServerPreconditions/orphan-pass: pass without a preceding run event'])
        # The same for an expected parent whose run event was lost.
        lines = [l for l in passing_stream() if l != event('run', RUNNER, 'TestM013RealEventSink')]
        self.assertEqual(problems(lines),
                         [f'{RUNNER} TestM013RealEventSink: pass without a preceding run event'])

    def test_terminal_before_run_is_rejected(self):
        lines = passing_stream()
        run_at = lines.index(event('run', RUNNER, 'TestM005TwoManagersAndHandoff'))
        pass_at = lines.index(event('pass', RUNNER, 'TestM005TwoManagersAndHandoff', Elapsed=1.5))
        lines[run_at], lines[pass_at] = lines[pass_at], lines[run_at]
        found = problems(lines)
        self.assertIn(f'{RUNNER} TestM005TwoManagersAndHandoff: pass without a preceding run event', found)
        self.assertIn(f'{RUNNER} TestM005TwoManagersAndHandoff: no terminal event', found)

    def test_repeated_run_or_terminal_is_rejected(self):
        lines = passing_stream()
        lines.insert(lines.index(event('run', ACTUATOR, 'TestM007RestrictedRequests')) + 1,
                     event('run', ACTUATOR, 'TestM007RestrictedRequests'))
        self.assertEqual(problems(lines), [f'{ACTUATOR} TestM007RestrictedRequests: repeated run event'])
        lines = passing_stream()
        lines.insert(lines.index(event('pass', ACTUATOR, 'TestM007RestrictedRequests', Elapsed=1.5)) + 1,
                     event('pass', ACTUATOR, 'TestM007RestrictedRequests', Elapsed=1.5))
        self.assertEqual(problems(lines),
                         [f'{ACTUATOR} TestM007RestrictedRequests: repeated terminal event (pass then pass)'])

    def test_missing_terminal_event_is_rejected(self):
        lines = [l for l in passing_stream()
                 if not (l == event('pass', ACTUATOR, 'TestM47APIServerPreconditions', Elapsed=1.5))]
        self.assertEqual(problems(lines), [f'{ACTUATOR} TestM47APIServerPreconditions: no terminal event'])

    def test_missing_package_terminal_event_is_rejected(self):
        lines = [l for l in passing_stream() if l != event('pass', RUNNER, Elapsed=3.0)]
        self.assertEqual(problems(lines), [f'package {RUNNER}: no terminal event'])

    def test_process_failure_despite_passing_looking_output_is_rejected(self):
        self.assertEqual(problems(passing_stream(), 2), ['go test exited 2'])

    def test_malformed_line_is_rejected(self):
        lines = passing_stream()
        lines.insert(3, 'FAIL\tgithub.com/phorvex/phorvex/internal/actuator [build failed]')
        found = problems(lines)
        self.assertEqual(len(found), 1)
        self.assertIn('not a JSON test event', found[0])

    def test_build_failure_event_is_rejected(self):
        lines = passing_stream()
        lines.insert(0, json.dumps({'ImportPath': ACTUATOR, 'Action': 'build-fail'}))
        self.assertIn(f'build failed for {ACTUATOR}', problems(lines))

    def test_unexpected_package_and_test_are_rejected(self):
        lines = passing_stream()
        lines += [event('run', 'github.com/phorvex/phorvex/internal/other', 'TestSomething'),
                  event('pass', 'github.com/phorvex/phorvex/internal/other', 'TestSomething'),
                  event('pass', 'github.com/phorvex/phorvex/internal/other')]
        found = problems(lines)
        self.assertTrue(all('unexpected package' in p for p in found) and found, found)
        lines = passing_stream() + [event('run', RUNNER, 'TestSomethingElse'), event('pass', RUNNER, 'TestSomethingElse')]
        self.assertEqual(problems(lines), [f'unexpected test {RUNNER} TestSomethingElse'] * 2)

    def test_blank_lines_are_tolerated_but_carry_no_evidence(self):
        self.assertEqual(problems(passing_stream() + ['', '   \n']), [])
        self.assertTrue(problems(['', '\n']))


class SourceBindingTests(unittest.TestCase):
    """The expected names must be the real envtest-guarded tests, and only those."""

    def test_expected_tests_are_exactly_the_envtest_guarded_tests_in_phorvex(self):
        guard = re.compile(r'func (Test\w+)\(t \*testing\.T\) \{\n\tif os\.Getenv\("KUBEBUILDER_ASSETS"\) == "" \{')
        guarded = {}
        for path in (ROOT / 'phorvex').rglob('*_test.go'):
            package = 'github.com/phorvex/phorvex/' + path.parent.relative_to(ROOT / 'phorvex').as_posix()
            for name in guard.findall(path.read_text()):
                guarded.setdefault(package, set()).add(name)
        expected = {p: set(t) for p, t in gate.EXPECTED.items()}
        self.assertEqual(guarded, expected,
                         'every KUBEBUILDER_ASSETS-guarded test must be listed in envtest_gate.EXPECTED '
                         '(otherwise it silently skips in CI) and nothing else may be listed')

    def test_run_pattern_is_anchored_and_exact(self):
        pattern = gate.run_pattern()
        self.assertTrue(pattern.startswith('^(') and pattern.endswith(')$'))
        self.assertEqual(pattern.count('|'), 7)
        for tests in gate.EXPECTED.values():
            for test in tests:
                self.assertRegex(test, pattern)
        self.assertNotRegex('TestM013RealEventSinkExtra', pattern)


class CommandLineTests(unittest.TestCase):
    def run_check(self, lines, exit_code):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / 'raw.jsonl'
            raw.write_text('\n'.join(lines) + ('\n' if lines else ''))
            summary = Path(tmp) / 'summary.json'
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/envtest_gate.py'), 'check',
                                   '--raw-input', str(raw), '--exit-code', str(exit_code),
                                   '--summary', str(summary)], capture_output=True, text=True, timeout=30)
            return proc, json.loads(summary.read_text())

    def test_check_mode_passes_only_a_complete_green_report(self):
        proc, summary = self.run_check(passing_stream(), 0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(summary['result'], 'PASS')
        self.assertEqual(summary['problems'], [])

    def test_check_mode_fails_skips_and_nonzero_exit(self):
        skipped = [l.replace('"Action": "pass"', '"Action": "skip"') if '"Test"' in l else l
                   for l in passing_stream()]
        proc, summary = self.run_check(skipped, 0)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(summary['result'], 'FAIL')
        self.assertIn('envtest gate: FAIL', proc.stderr)
        proc, summary = self.run_check(passing_stream(), 1)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(summary['problems'], ['go test exited 1'])

    # Transport (review R1.2): the runner must drain stdout and stderr concurrently. A
    # synthetic `go` executable substitutes only the subprocess byte streams and exit code;
    # dummy executables stand in for the asset presence check. Nothing here starts an API server.
    def synthetic_go(self, tmp, stderr_bytes, exit_code, lines=None):
        lines = passing_stream() if lines is None else lines
        go = Path(tmp) / 'go'
        go.write_text('#!' + sys.executable + '\n'
                      'import sys\n'
                      'if sys.argv[1:2] == ["version"]:\n'
                      '    print("go version synthetic transport fixture"); sys.exit(0)\n'
                      f'sys.stderr.write("e" * {stderr_bytes}); sys.stderr.flush()\n'
                      f'sys.stdout.write({"".join(l + chr(10) for l in lines)!r}); sys.stdout.flush()\n'
                      f'sys.exit({exit_code})\n')
        go.chmod(0o700)
        assets = Path(tmp) / 'assets'
        assets.mkdir()
        for name in gate.REQUIRED_BINARIES:
            (assets / name).write_text('#!/bin/sh\nexit 0\n')
            (assets / name).chmod(0o700)
        return go, assets

    def run_transport(self, stderr_bytes, exit_code, lines=None, timeout=30):
        with tempfile.TemporaryDirectory() as tmp:
            go, assets = self.synthetic_go(tmp, stderr_bytes, exit_code, lines)
            env = {'PATH': '/usr/bin:/bin', 'KUBEBUILDER_ASSETS': str(assets), 'USE_EXISTING_CLUSTER': 'false'}
            started = time.monotonic()
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/envtest_gate.py'), 'run', '--go', str(go),
                                   '--raw-output', f'{tmp}/out/go-test.jsonl', '--summary', f'{tmp}/out/summary.json'],
                                  cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
            elapsed = time.monotonic() - started
            summary = json.loads(Path(tmp, 'out/summary.json').read_text())
            stderr_file = Path(summary['stderr_output'])
            retained = stderr_file.stat().st_size if stderr_file.exists() else None
            raw = Path(tmp, 'out/go-test.jsonl').read_text()
            return proc, summary, elapsed, retained, raw

    def test_small_stderr_positive_completes_and_passes(self):
        proc, summary, _, retained, raw = self.run_transport(16, 0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(summary['result'], 'PASS')
        self.assertEqual(summary['exit'], 0)
        self.assertEqual((retained, summary['stderr_bytes'], summary['stderr']), (16, 16, 'e' * 16))
        self.assertEqual(raw, ''.join(l + '\n' for l in passing_stream()))

    def test_large_stderr_before_stdout_completes(self):
        # 1 MiB written to stderr before any stdout: far beyond a pipe buffer. Serial
        # draining deadlocked here (lead probe: killed after 3 s); it must now finish.
        proc, summary, elapsed, retained, _ = self.run_transport(1024 * 1024, 0, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertEqual(summary['result'], 'PASS')
        self.assertLess(elapsed, 10)
        self.assertEqual(retained, 1024 * 1024)
        self.assertEqual(summary['stderr_bytes'], 1024 * 1024)
        self.assertEqual(summary['stderr'], 'e' * 4096)  # bounded excerpt in the summary
        self.assertIn('e' * 1024, proc.stderr)  # diagnostics still echoed to the job log

    def test_nonzero_exit_with_normal_output_fails(self):
        proc, summary, _, retained, _ = self.run_transport(16, 3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(summary['result'], 'FAIL')
        self.assertEqual(summary['exit'], 3)
        self.assertEqual(summary['problems'], ['go test exited 3'])
        self.assertEqual(retained, 16)

    def test_incomplete_stream_from_process_fails(self):
        lines = passing_stream()
        lines.insert(2, event('run', ACTUATOR, 'TestM47APIServerPreconditions/lost-terminal'))
        proc, summary, _, _, _ = self.run_transport(0, 0, lines=lines)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(summary['problems'],
                         [f'{ACTUATOR} TestM47APIServerPreconditions/lost-terminal: no terminal event'])

    def test_run_mode_refuses_without_local_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'PATH': '/usr/bin:/bin', 'KUBEBUILDER_ASSETS': ''}
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/envtest_gate.py'), 'run',
                                   '--raw-output', f'{tmp}/raw.jsonl', '--summary', f'{tmp}/summary.json'],
                                  env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('KUBEBUILDER_ASSETS is not set', proc.stderr)
            env = {'PATH': '/usr/bin:/bin', 'KUBEBUILDER_ASSETS': tmp, 'USE_EXISTING_CLUSTER': 'true'}
            proc = subprocess.run([sys.executable, str(ROOT / 'tools/envtest_gate.py'), 'run',
                                   '--raw-output', f'{tmp}/raw.jsonl', '--summary', f'{tmp}/summary.json'],
                                  env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(proc.returncode, 0)
            for name in gate.REQUIRED_BINARIES:
                self.assertIn(f'missing or non-executable envtest binary: {tmp}/{name}', proc.stderr)
            self.assertIn('USE_EXISTING_CLUSTER=true is not allowed', proc.stderr)
            self.assertEqual(json.loads(Path(tmp, 'summary.json').read_text())['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
