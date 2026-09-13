#!/usr/bin/env python3
"""Run the required local API-server (envtest) tests and fail unless every one really ran and passed.

The plain `go -C phorvex test ./...` job deliberately runs with KUBEBUILDER_ASSETS
blank, so the tests below `t.Skip` there and `go test` still exits 0. This gate is
the CI proof that they were executed against local kube-apiserver/etcd binaries:

  * only these exact package/test names are accepted (a rename or removal fails);
  * every expected test must emit a `run` event and terminate with `pass`;
  * every observed selected parent or subtest is tracked to completion: a `run`
    without a terminal event, a terminal event without a preceding `run`, or a
    repeated `run`/terminal for the same test is a stream-integrity failure;
  * any `skip`, `fail` or `build-fail` event, any unexpected package/test, any
    malformed line and any non-zero `go test` exit fails the gate even when the
    output otherwise looks green;
  * every expected package must itself terminate with `pass`;
  * an empty report is never accepted.

`go test` is started directly (no shell pipe). Its stdout is streamed into the
raw JSON evidence file while its stderr is written to a sibling file by the OS
(both pipes are drained concurrently, so a large stderr can never stall the
run); the verdict is computed from the retained stdout file and the real exit.

Usage:
  envtest_gate.py run   --raw-output FILE --summary FILE [--stderr-output FILE] [--go GO] [--timeout 10m]
  envtest_gate.py check --raw-input FILE --exit-code N --summary FILE

Scope: local isolated API servers only. envtest has no kubelet, CNI, garbage
collector, cloud API or AI serving backend; a PASS here is not live acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

MODULE = 'phorvex'
EXPECTED = {
    'github.com/phorvex/phorvex/internal/actuator': (
        'TestM47APIServerPreconditions',
        'TestM038APIServerConditionalDetach',
        'TestM048APIServerLifecycle',
        'TestM048APIServerRestrictedRole',
        'TestM007RestrictedRequests',
        'TestM032CoverageAPIServerReadback',
    ),
    'github.com/phorvex/phorvex/internal/runner': (
        'TestM005TwoManagersAndHandoff',
        'TestM013RealEventSink',
    ),
}
PACKAGES = ('./internal/actuator', './internal/runner')
TERMINAL = ('pass', 'fail', 'skip')
REQUIRED_BINARIES = ('kube-apiserver', 'etcd')


def run_pattern() -> str:
    names = [t for tests in EXPECTED.values() for t in tests]
    return '^(' + '|'.join(names) + ')$'


def go_command(go: str, timeout: str) -> list[str]:
    return [go, '-C', MODULE, 'test', '-json', '-mod=readonly', '-count=1',
            f'-timeout={timeout}', '-run', run_pattern(), *PACKAGES]


def parent(test: str) -> str:
    return test.split('/', 1)[0]


def evaluate(lines, returncode):
    """Return (problems, verdicts, packages) for a retained `go test -json` stream.

    `verdicts` maps every expected test to its terminal action or 'missing';
    `packages` maps every expected package to its terminal action or 'missing'.
    An empty `problems` list is the only PASS.
    """
    problems = []
    verdicts = {t: 'missing' for tests in EXPECTED.values() for t in tests}
    # Every observed selected parent/subtest: 'run' until its terminal action arrives.
    observed = {}
    packages = {p: 'missing' for p in EXPECTED}
    events = 0
    for number, raw in enumerate(lines, 1):
        line = raw.rstrip('\n')
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            problems.append(f'line {number}: not a JSON test event: {line[:120]!r}')
            continue
        if not isinstance(event, dict) or 'Action' not in event:
            problems.append(f'line {number}: not a test2json event: {line[:120]!r}')
            continue
        events += 1
        action = event['Action']
        package = event.get('Package') or event.get('ImportPath')
        test = event.get('Test')
        if action == 'build-fail':
            problems.append(f'build failed for {package}')
            continue
        if package not in EXPECTED:
            if action in TERMINAL or test:
                problems.append(f'unexpected package {package!r} in report')
            continue
        if test:
            if parent(test) not in EXPECTED[package]:
                problems.append(f'unexpected test {package} {test}')
                continue
            key = (package, test)
            if action == 'run':
                if key in observed:
                    problems.append(f'{package} {test}: repeated run event')
                observed[key] = 'run'
            elif action in TERMINAL:
                if key not in observed:
                    problems.append(f'{package} {test}: {action} without a preceding run event')
                elif observed[key] != 'run':
                    problems.append(f'{package} {test}: repeated terminal event ({observed[key]} then {action})')
                observed[key] = action
                if action != 'pass':
                    problems.append(f'{package} {test}: {action}')
                if test in EXPECTED[package]:
                    verdicts[test] = action
        elif action in TERMINAL:
            packages[package] = action
            if action != 'pass':
                problems.append(f'package {package}: {action}')
    if events == 0:
        problems.append('empty report: no test events observed')
    for (package, test), state in observed.items():
        if state == 'run':
            problems.append(f'{package} {test}: no terminal event')
    for package, tests in EXPECTED.items():
        for test in tests:
            if (package, test) not in observed:
                problems.append(f'{package} {test}: never ran')
        if packages[package] == 'missing':
            problems.append(f'package {package}: no terminal event')
    if returncode != 0:
        problems.append(f'go test exited {returncode}')
    return problems, verdicts, packages


def check_assets(env):
    assets = env.get('KUBEBUILDER_ASSETS', '')
    if not assets:
        return ['KUBEBUILDER_ASSETS is not set; refusing to run without local envtest binaries']
    problems = []
    for name in REQUIRED_BINARIES:
        path = Path(assets) / name
        if not path.is_file() or not os.access(path, os.X_OK):
            problems.append(f'missing or non-executable envtest binary: {path}')
    if env.get('USE_EXISTING_CLUSTER', '').lower() == 'true':
        problems.append('USE_EXISTING_CLUSTER=true is not allowed: this gate proves local isolated servers only')
    return problems


def write_summary(path: Path, summary: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')


def report(summary: dict, problems):
    for test, verdict in sorted(summary['verdicts'].items()):
        print(f'{verdict:>8}  {test}')
    for package, verdict in sorted(summary['packages'].items()):
        print(f'{verdict:>8}  package {package}')
    if problems:
        print('envtest gate: FAIL', file=sys.stderr)
        for problem in problems:
            print(f'  - {problem}', file=sys.stderr)
        return 1
    print(f'envtest gate: PASS ({len(summary["verdicts"])} required tests ran and passed)')
    return 0


def cmd_run(args) -> int:
    env = dict(os.environ)
    problems = check_assets(env)
    raw = Path(args.raw_output)
    raw.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        'expected': {p: list(t) for p, t in EXPECTED.items()},
        'assets': env.get('KUBEBUILDER_ASSETS', ''),
        'raw_output': str(raw),
        'scope': 'local isolated envtest API servers only; not a shared cluster and not live acceptance',
    }
    if problems:
        summary.update(exit=None, command=None, problems=problems, verdicts={}, packages={}, result='FAIL')
        write_summary(Path(args.summary), summary)
        return report(summary, problems)
    # Never attach to a cluster: local binaries only, whatever the caller exported.
    env['KUBECONFIG'] = '/dev/null'
    env['USE_EXISTING_CLUSTER'] = 'false'
    go = args.go or shutil.which('go')
    if not go:
        problems = ['go toolchain not found on PATH']
        summary.update(exit=None, command=None, problems=problems, verdicts={}, packages={}, result='FAIL')
        write_summary(Path(args.summary), summary)
        return report(summary, problems)
    command = go_command(go, args.timeout)
    summary['command'] = command
    summary['go_version'] = subprocess.run([go, 'version'], capture_output=True, text=True).stdout.strip()
    stderr_path = Path(args.stderr_output) if args.stderr_output else raw.with_name(raw.name + '.stderr.txt')
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    summary['stderr_output'] = str(stderr_path)
    # stderr goes straight to its file (no pipe to drain), so streaming stdout here
    # cannot deadlock against a process that fills stderr first.
    with raw.open('w') as out, stderr_path.open('w') as err:
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=err, text=True)
        for line in proc.stdout:
            out.write(line)
            try:
                event = json.loads(line)
            except ValueError:
                event = None
            if isinstance(event, dict) and event.get('Test') and event.get('Action') in ('run', *TERMINAL):
                print(f'{event["Action"]:>5} {event.get("Package")} {event["Test"]}', flush=True)
        returncode = proc.wait()
    stderr = stderr_path.read_text(errors='replace')
    if stderr.strip():
        print(stderr, file=sys.stderr, end='' if stderr.endswith('\n') else '\n')
    summary['stderr_bytes'] = stderr_path.stat().st_size
    summary['stderr'] = stderr[:4096]
    with raw.open() as retained:
        problems, verdicts, packages = evaluate(retained, returncode)
    summary.update(exit=returncode, problems=problems, verdicts=verdicts, packages=packages,
                   result='FAIL' if problems else 'PASS')
    write_summary(Path(args.summary), summary)
    return report(summary, problems)


def cmd_check(args) -> int:
    raw = Path(args.raw_input)
    with raw.open() as retained:
        problems, verdicts, packages = evaluate(retained, args.exit_code)
    summary = {
        'expected': {p: list(t) for p, t in EXPECTED.items()},
        'raw_input': str(raw), 'exit': args.exit_code, 'problems': problems,
        'verdicts': verdicts, 'packages': packages, 'result': 'FAIL' if problems else 'PASS',
        'scope': 'verdict recomputed from a retained report; not a new execution',
    }
    write_summary(Path(args.summary), summary)
    return report(summary, problems)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='mode', required=True)
    run = sub.add_parser('run', help='execute the required tests and gate on the retained report')
    run.add_argument('--raw-output', required=True, help='where the verbatim go test -json stream is retained')
    run.add_argument('--summary', required=True, help='where the machine-readable verdict is written')
    run.add_argument('--stderr-output', default=None,
                     help='where go test stderr is retained in full (default: <raw-output>.stderr.txt)')
    run.add_argument('--go', default=None, help='go binary (default: PATH)')
    run.add_argument('--timeout', default='10m', help='go test -timeout (default 10m)')
    run.set_defaults(func=cmd_run)
    check = sub.add_parser('check', help='recompute the verdict for a retained report')
    check.add_argument('--raw-input', required=True)
    check.add_argument('--exit-code', type=int, required=True, help='exit status of the go test process that produced it')
    check.add_argument('--summary', required=True)
    check.set_defaults(func=cmd_check)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
