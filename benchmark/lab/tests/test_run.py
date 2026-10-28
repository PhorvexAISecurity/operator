"""Tests for benchmark/run.sh P0, P1, --plan and the exit handler (ticket Part 2
TP-1, TP-2, R4-3, R7-8c, I-1, I-2).

run.sh runs from a throwaway repository (never the working repo) holding the
real run.sh and lab files, against the fake account (fake_aws) and fake tools
(fake_bin); git, jq and python3 are real. Every test checks that no AWS write
was made and that the throwaway repository and the real kubeconfig are
unchanged.
"""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
LAB = TESTS.parent
BENCHMARK = LAB.parent
FAKE_AWS, FAKE_BIN = TESTS / 'fake_aws', TESTS / 'fake_bin'
ACCT = '753556437180'
DEV_SERVER = 'https://DEV.eks.example'
COMMIT = '8acb43ad7ce088460a457e3055d74c53df5e67a5'
COPIED = ['run.sh', 'lab/teardown-by-tag.sh', 'lab/build-image.sh', 'lab/images.lock', 'lab/m23-fixed.sha256',
          'lab/shims/kubectl', 'lab/shims/helm', 'lab/shims/aws', 'lab/shims/shim-lib.sh']
GIT_ENV = {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid'}
READ_OPS = ('describe-', 'list-', 'get-')


def real_version(cmd, pick):
    out = subprocess.run(cmd, text=True, capture_output=True)
    return pick((out.stdout + out.stderr).split())


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, text=True, capture_output=True,
                          env={**os.environ, **GIT_ENV}).stdout


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='run-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # Cleanups run last-in first-out: make the read-only snapshot writable before removing it.
        self.addCleanup(lambda: subprocess.run(['chmod', '-R', 'u+w', str(self.tmp)], capture_output=True) and None)
        self.repo = self.tmp / 'repo'
        for rel in COPIED:
            dst = self.repo / 'benchmark' / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(BENCHMARK / rel, dst)
        self.write_lock()
        git(self.repo, 'init', '-q', '-b', 'main')
        self.commit_repo('throwaway clone of run.sh and lab')
        self.runs = self.tmp / 'runs'
        self.runs.mkdir()
        self.run_dir = self.runs / 'r1'
        self.home = self.tmp / 'home'
        (self.home / '.kube').mkdir(parents=True)
        self.kubeconfig = self.home / '.kube' / 'config'
        self.write_kubeconfig(with_dev=True)
        self.world = self.tmp / 'world.json'
        self.log = self.tmp / 'stub.log'
        (self.tmp / 'scratch').mkdir()
        self.write_world()

    def write_lock(self, **override):
        versions = {'kubectl': '1.36.0', 'helm': '3.19.0', 'aws': '2.31.0', 'eksctl': '0.214.0', 'crane': '0.20.2',
                    'go': '1.26.4', 'git': real_version(['git', '--version'], lambda w: w[2]),
                    'python3': real_version(['python3', '--version'], lambda w: w[1]),
                    'jq': real_version(['jq', '--version'], lambda w: w[0].removeprefix('jq-')), **override}
        (self.repo / 'benchmark/lab/tools.lock').write_text(''.join(f'{k} {v}\n' for k, v in versions.items()))

    def commit_repo(self, message):
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', message)

    def write_kubeconfig(self, with_dev):
        clusters = [{'name': 'other', 'cluster': {'server': 'https://OTHER.example'}}]
        contexts = [{'name': 'other-ctx', 'context': {'cluster': 'other', 'user': 'u'}}]
        if with_dev:
            clusters.append({'name': 'dev', 'cluster': {'server': DEV_SERVER}})
            contexts.append({'name': 'dev-ctx', 'context': {'cluster': 'dev', 'user': 'u'}})
        self.kubeconfig.write_text(json.dumps({'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'other-ctx',
                                               'clusters': clusters, 'contexts': contexts, 'users': [{'name': 'u', 'user': {}}]}))

    def write_world(self, **settings):
        world = {'account': ACCT,
                 'items': [{'kind': 'cluster', 'name': 'phorvex-dev-eks', 'arn': f'arn:aws:eks:us-east-2:{ACCT}:cluster/phorvex-dev-eks',
                            'endpoint': DEV_SERVER, 'version': '1.31', 'tags': {}},
                           {'kind': 'instance', 'id': 'i-prod-gpu', 'arn': 'x', 'state': 'running', 'type': 'g4dn.xlarge', 'tags': {}}],
                 'eks_versions': {'1.36': 'STANDARD_SUPPORT'}, 'gpu_quota': 8, 'instance_types': {'g4dn.xlarge': 4},
                 'budgets': ['phorvex-benchmark-lab'], 'active_cost_tags': ['phorvex.ai/benchmark']}
        world.update(settings)
        self.world.write_text(json.dumps(world))

    def env(self, **extra):
        base = {k: v for k, v in os.environ.items() if not k.startswith(('AWS_', 'STUB_', 'BENCH_', 'KUBECONFIG'))}
        return {**base, 'PATH': f'{FAKE_AWS}:{FAKE_BIN}:/usr/bin:/bin', 'HOME': str(self.home),
                'TMPDIR': str(self.tmp / 'scratch'), 'STUB_WORLD': str(self.world), 'STUB_LOG': str(self.log), **extra}

    def args(self, *extra, run_dir=None, full=True):
        args = ['--run-dir', str(run_dir or self.run_dir), '--aws-account', ACCT, '--region', 'us-east-2',
                '--new-tag', 'manager-v0.11.0', '--new-commit', COMMIT, '--m23', 'stopped', '--plan']
        if full:
            args += ['--scenarios', 'A,B,D']
        return [*args, *extra]

    def run_sh(self, *args, env=None):
        return subprocess.run(['bash', str(self.repo / 'benchmark/run.sh'), *args], text=True, capture_output=True,
                              env=env or self.env(), timeout=120)

    def start(self, *args, env):
        return subprocess.Popen(['bash', str(self.repo / 'benchmark/run.sh'), *args], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def wait_paused(self, proc, step):
        marker = self.run_dir / f'PAUSED-{step}'
        for _ in range(600):
            if marker.exists():
                return marker
            if proc.poll() is not None:
                self.fail(f'run.sh exited {proc.returncode} before pausing at {step}: {proc.stderr.read()}')
            time.sleep(0.1)
        self.fail(f'run.sh never paused at {step}')

    def aws_calls(self):
        if not self.log.exists():
            return []
        return [l.split('\t')[1:] for l in self.log.read_text().splitlines() if l.startswith('aws\t')]

    def assert_no_aws_write(self):
        for call in self.aws_calls():
            if call == ['--version']:
                continue
            words, i = [], 0
            while i < len(call):  # drop flags with their values, as the fake account parses them
                if call[i].startswith('--'):
                    i += 2 if i + 1 < len(call) and not call[i + 1].startswith('--') else 1
                    continue
                words.append(call[i])
                i += 1
            self.assertTrue(words[1].startswith(READ_OPS), f'aws write: {call}')
        commands = self.run_dir / 'COMMANDS.log'
        if commands.exists():
            for line in commands.read_text().splitlines():
                self.assertIn(line.split('\t')[2], ('read', 'dev-read'), line)

    def assert_untouched(self, repo_head, kubeconfig):
        self.assertEqual(git(self.repo, 'status', '--porcelain', '--ignored'), '')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), repo_head)
        self.assertEqual(self.kubeconfig.read_text(), kubeconfig)

    def snapshot(self):
        return git(self.repo, 'rev-parse', 'HEAD'), self.kubeconfig.read_text()

    # TP-1
    def test_plan_runs_p0_p1_and_prints_p2_to_p9(self):
        before = self.snapshot()
        result = self.run_sh(*self.args())
        self.assertEqual(result.returncode, 0, result.stderr)
        for p in ('P2:', 'P3:', 'P4:', 'P5:', 'P6:', 'P8:', 'P9:'):
            self.assertIn(p, result.stderr)
        self.assert_no_aws_write()
        self.assert_untouched(*before)

        run = json.loads((self.run_dir / 'run.json').read_text())
        rid = run['runId']
        self.assertRegex(rid, r'^[0-9a-f]{6}$')
        self.assertEqual(run['lab'], f'phorvex-281-lab-{rid}')
        self.assertEqual(run['real']['tools']['aws'], str(FAKE_AWS / 'aws'))
        self.assertEqual((self.run_dir / 'TEARDOWN-COMMAND.txt').read_text(),
                         f'benchmark/lab/teardown-by-tag.sh --run-id {rid} --region us-east-2 --account {ACCT}\n')
        self.assertEqual(json.loads((self.run_dir / 'CREATED.json').read_text()), {'runId': rid, 'entries': []})
        self.assertEqual((self.run_dir / 'REPO-BEFORE.txt').read_text(), (self.run_dir / 'REPO-AFTER.txt').read_text())
        self.assertEqual((self.run_dir / 'KUBECONFIG-BEFORE.sha256').read_text(),
                         (self.run_dir / 'KUBECONFIG-AFTER.sha256').read_text())
        self.assertEqual(json.loads((self.run_dir / 'state.json').read_text())['forbiddenServers'], [DEV_SERVER])
        dev_info = (self.run_dir / 'DEV-INFO.txt').read_text()
        self.assertIn(f'endpoint {DEV_SERVER}', dev_info)
        self.assertIn('image 753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/manager:0.12.0', dev_info)
        self.assertIn('kubectl, helm and aws resolve to the shims', (self.run_dir / 'run.log').read_text())
        self.assertFalse((self.run_dir / 'TEARDOWN-PROOF.txt').exists(), 'no create, so no teardown')
        for gone in ('home', 'tmp', 'repo', 'shims', 'bin'):
            self.assertFalse((self.run_dir / gone).exists(), f'P9 should have removed {gone}')
        self.assertEqual(self.run_dir.stat().st_mode & 0o777, 0o700)
        # dev was only read: describe-cluster through run.sh, get through dev_read.
        dev_lines = [l.split('\t') for l in (self.run_dir / 'COMMANDS.log').read_text().splitlines() if l.split('\t')[3] == 'dev']
        self.assertEqual({(l[1], l[2]) for l in dev_lines}, {('run.sh', 'read'), ('dev_read', 'dev-read')})

    # DR-37: the lab environment is the allowlist only; caller variables do not leak in.
    def test_lab_environment_is_isolated(self):
        result = self.run_sh(*self.args(), env=self.env(SENTINEL_SECRET='do-not-leak', KUBECONFIG=str(self.kubeconfig),
                                                        AWS_SECRET_ACCESS_KEY='passed-through-by-design'))
        self.assertEqual(result.returncode, 0, result.stderr)
        names = (self.run_dir / 'LAB-ENV.txt').read_text().split()
        self.assertNotIn('SENTINEL_SECRET', names)
        self.assertIn('KUBECONFIG', names)
        self.assertIn('AWS_SECRET_ACCESS_KEY', names)
        self.assertNotIn('do-not-leak', (self.run_dir / 'LAB-ENV.txt').read_text())
        self.assertNotIn('passed-through-by-design', (self.run_dir / 'LAB-ENV.txt').read_text(), 'names only')
        for path in self.run_dir.rglob('*'):
            if path.is_file():
                self.assertNotIn('passed-through-by-design', path.read_text(errors='replace'), path)

    # TP-2, refusals before anything exists.
    def test_argument_refusals_create_nothing(self):
        existing = self.runs / 'existing'
        existing.mkdir()
        (existing / 'keep').write_text('x')
        inside = self.repo / 'inside'
        cases = [
            (self.args(run_dir=inside), 'outside the repository'),
            (self.args(run_dir=self.tmp), 'must not contain the repository'),
            (self.args(run_dir=self.home), 'home directory'),
            (self.args(run_dir=Path('/')), 'must not be /'),
            ([a if a != str(self.run_dir) else 'relative/run' for a in self.args()], 'absolute path'),
            (self.args(run_dir=existing), 'already exists'),
            ([a for a in self.args() if a != '--plan'], 'only --plan is available'),
            (self.args('--max-hours', 'x'), 'whole number'),
            (self.args('--max-hours', '2'), '3 to 15'),
            (self.args('--max-hours', '16'), '3 to 15'),
            (self.args('--fixtures-only', '--max-hours', '1', full=False), '2 to 15'),
            (self.args('--scenarios', 'A,E', full=False), 'comma list'),
            (self.args('--scenarios', 'A,A', full=False), 'twice'),
            ([a for a in self.args() if a not in ('--m23', 'stopped')], '--m23 must be'),
            (self.args('--new-commit', COMMIT[:12]), '40-character'),
            (self.args('--src-remote', 'https://user:tok@example.invalid/r.git'), 'must not carry credentials'),
            (self.args('--fixture-set', 'stub'), 'need --fixtures-only'),
        ]
        for args, needle in cases:
            with self.subTest(needle=needle):
                result = self.run_sh(*args)
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(needle, result.stderr)
        result = self.run_sh(*self.args(), env=self.env(BENCH_TEST_PAUSE_AT='P1.1'))
        self.assertEqual(result.returncode, 10)
        self.assertIn('only with --fixture-set stub', result.stderr)
        self.assertEqual(self.aws_calls(), [], 'nothing reached AWS')
        self.assertEqual([p.name for p in self.runs.iterdir()], ['existing'])
        self.assertEqual((existing / 'keep').read_text(), 'x')
        self.assertFalse(inside.exists())

    # TP-2, preflight refusals: exit 10, no AWS write, the run directory cleaned.
    def test_preflight_refusals(self):
        before = self.snapshot()
        cases = [
            ({'world': {'eks_versions': {'1.36': 'EXTENDED_SUPPORT'}}}, 'not STANDARD_SUPPORT'),
            ({'world': {'budgets': []}}, 'phorvex-benchmark-lab is missing'),
            ({'world': {'gpu_quota': 4}}, 'only 0 on-demand G/VT vCPUs are free'),
            ({'world': {'collide_labs': True}}, 'already exists'),
            ({'world': {'items': []}}, 'cannot describe phorvex-dev-eks'),
            ({'env': {'STUB_CALLER_ACCOUNT': '111111111111'}}, 'account 111111111111, not --aws-account'),
            ({'env': {'AWS_REGION': 'eu-west-1'}}, 'AWS_REGION=eu-west-1 differs'),
            ({'lock': {'helm': 'UNSET'}}, 'helm: tools.lock is UNSET'),
            ({'lock': {'kubectl': '1.30.0'}}, 'kubectl: 1.36.0, tools.lock says 1.30.0'),
        ]
        for n, (case, needle) in enumerate(cases):
            with self.subTest(needle=needle):
                self.write_world(**case.get('world', {}))
                if 'lock' in case:
                    self.write_lock(**case['lock'])
                    self.commit_repo('lock')
                run_dir = self.runs / f'p{n}'
                result = self.run_sh(*self.args(run_dir=run_dir), env=self.env(**case.get('env', {})))
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(needle, result.stderr)
                self.assertTrue((run_dir / 'run.json').exists())
                for gone in ('home', 'tmp', 'repo', 'shims', 'bin'):
                    self.assertFalse((run_dir / gone).exists(), gone)
                if 'lock' in case:
                    self.write_lock()
                    self.commit_repo('lock back')
                    before = self.snapshot()
        self.run_dir = self.runs / 'p0'
        self.assert_no_aws_write()
        self.assert_untouched(*before)

    def test_dirty_repository_is_refused(self):
        (self.repo / 'scratch.txt').write_text('uncommitted\n')
        result = self.run_sh(*self.args())
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn('repository is not clean', result.stderr)
        self.assertFalse((self.run_dir / 'REPO-BEFORE.txt').exists())

    # TP-2, the M-23 gate, with a stub watcher.
    def test_m23_gate(self):
        script = self.tmp / 'm23_watch_loop.sh'
        script.write_text('while :; do sleep 1; done\n')
        watcher = subprocess.Popen(['bash', str(script)])
        self.addCleanup(watcher.wait)
        self.addCleanup(watcher.kill)
        result = self.run_sh(*self.args(run_dir=self.runs / 'stopped'))
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn(f'the M-23 watcher is running: {watcher.pid}', result.stderr)

        fixed = [a if a != 'stopped' else 'fixed' for a in self.args(run_dir=self.runs / 'fixed')]
        result = self.run_sh(*fixed)
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn('not a recorded fixed version', result.stderr)

        import hashlib
        (self.repo / 'benchmark/lab/m23-fixed.sha256').write_text(hashlib.sha256(script.read_bytes()).hexdigest() + '\n')
        self.commit_repo('record the fixed watcher')
        result = self.run_sh(*[a if a != 'stopped' else 'fixed' for a in self.args(run_dir=self.runs / 'ok')])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(watcher.pid), (self.runs / 'ok' / 'PREFLIGHT.txt').read_text())

    def test_inactive_cost_tag_only_warns(self):
        self.write_world(active_cost_tags=[])
        result = self.run_sh(*self.args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('WARNING cost-allocation tag', (self.run_dir / 'PREFLIGHT.txt').read_text())

    def test_dev_context_missing_is_informational(self):
        self.write_kubeconfig(with_dev=False)
        result = self.run_sh(*self.args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('image unavailable', (self.run_dir / 'DEV-INFO.txt').read_text())

    def stub_args(self):
        return self.args('--fixtures-only', '--fixture-set', 'stub', '--max-hours', '2', full=False)

    # R4-3: the cleanup guard deletes nothing when run.json does not carry the run.
    def test_cleanup_guard_with_a_mismatched_run_id(self):
        proc = self.start(*self.stub_args(), env=self.env(BENCH_TEST_PAUSE_AT='P1.10'))
        marker = self.wait_paused(proc, 'P1.10')
        run = json.loads((self.run_dir / 'run.json').read_text())
        (self.run_dir / 'run.json').write_text(json.dumps({**run, 'runId': 'ffffff'}))
        marker.unlink()
        _, err = proc.communicate(timeout=120)
        self.assertEqual(proc.returncode, 0, err)
        self.assertIn('deleting nothing', err)
        for kept in ('home', 'tmp', 'repo', 'shims', 'bin'):
            self.assertTrue((self.run_dir / kept).exists(), kept)

    # R7-8c: a signal before P2 skips teardown, runs P9, and exits with the phase code.
    def test_signal_during_preflight(self):
        before = self.snapshot()
        proc = self.start(*self.stub_args(), env=self.env(BENCH_TEST_PAUSE_AT='P1.5'))
        self.wait_paused(proc, 'P1.5')
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=120)
        self.assertEqual(proc.returncode, 10, err)
        log = (self.run_dir / 'run.log').read_text()
        self.assertIn('no AWS create was started; nothing to tear down', log)
        self.assertIn('exit 10 (TERM)', log)
        self.assertTrue((self.run_dir / 'REPO-AFTER.txt').exists(), 'P9 ran')
        self.assertFalse((self.run_dir / 'repo').exists())
        self.assert_no_aws_write()
        self.assert_untouched(*before)

    # I-1, I-2 and the §12 precedence: 80 > 97 > phase.
    def test_p9_proofs_and_exit_precedence(self):
        def paused_run(name, change):
            self.run_dir = self.runs / name
            proc = self.start(*self.stub_args(), env=self.env(BENCH_TEST_PAUSE_AT='P1.10'))
            marker = self.wait_paused(proc, 'P1.10')
            change()
            marker.unlink()
            _, err = proc.communicate(timeout=120)
            return proc.returncode, err

        def refusal():
            with open(self.run_dir / 'COMMANDS.log', 'a') as f:
                f.write('t\tshim\trefused\tlab\tkubectl get pods # refused: test\n')

        original = self.kubeconfig.read_text()
        code, err = paused_run('refused', refusal)
        self.assertEqual(code, 97, err)

        code, err = paused_run('kubeconfig', lambda: self.kubeconfig.write_text(original + ' '))
        self.assertEqual(code, 80, err)
        self.assertIn('the real kubeconfig', err)
        self.kubeconfig.write_text(original)

        code, err = paused_run('repo', lambda: (self.repo / 'benchmark' / 'stray.txt').write_text('x'))
        self.assertEqual(code, 80, err)
        self.assertIn('benchmark/stray.txt', (self.run_dir / 'REPO-CHANGED.txt').read_text())
        (self.repo / 'benchmark' / 'stray.txt').unlink()

        code, err = paused_run('both', lambda: (refusal(), self.kubeconfig.write_text(original + ' ')))
        self.assertEqual(code, 80, '80 outranks 97')
        self.kubeconfig.write_text(original)


class StaticChecksTest(unittest.TestCase):
    def test_bash_syntax_and_no_set_x(self):
        script = BENCHMARK / 'run.sh'
        subprocess.run(['bash', '-n', str(script)], check=True)
        self.assertTrue(os.access(script, os.X_OK))
        self.assertNotRegex(script.read_text(), r'(?m)^\s*set -[a-zA-Z]*x')

    def test_tools_lock_lists_every_tool(self):
        lock = {l.split()[0]: l.split()[1] for l in (LAB / 'tools.lock').read_text().splitlines()
                if l.strip() and not l.startswith('#')}
        self.assertEqual(set(lock), {'kubectl', 'helm', 'aws', 'eksctl', 'crane', 'git', 'python3', 'jq', 'go'})
        self.assertEqual(lock['eksctl'], '0.214.0')
        self.assertEqual(lock['crane'], '0.20.2')

    @unittest.skipUnless(shutil.which('shellcheck'), 'shellcheck not installed')
    def test_shellcheck(self):
        subprocess.run(['shellcheck', '-x', str(BENCHMARK / 'run.sh'), *map(str, (LAB / 'shims').glob('*'))],
                       check=True, cwd=BENCHMARK)


if __name__ == '__main__':
    unittest.main()
