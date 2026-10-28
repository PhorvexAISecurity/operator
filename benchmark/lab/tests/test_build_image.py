"""Tests for benchmark/lab/build-image.sh (ticket Part 3, TP-1 to TP-9).

The script runs against stub aws, crane and go (tests/stubs), in a throwaway
working repository whose tag, HEAD and working tree all differ. A copy of the
script sits next to a test images.lock that lists the stub Dockerfiles; the
real images.lock is checked against the repository's own Dockerfiles below.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
SCRIPT = LAB / 'build-image.sh'
LOCK = LAB / 'images.lock'
STUBS = Path(__file__).resolve().parent / 'stubs'
REPO_ROOT = LAB.parents[1]
RUN_ID = 'a1b2c3'
ACCOUNT = '753556437180'
REGISTRY = f'{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com'
DIGEST = 'sha256:' + '7' * 64
BASE_DIGEST = 'sha256:' + '1' * 64
SIX = 'FROM stub AS six\n'
EIGHT = 'FROM stub AS eight\n'
GIT_ENV = {
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
}
CLEAN_ENV = {k: v for k, v in os.environ.items()
             if not k.startswith(('GIT_', 'GO', 'AWS_', 'STUB_')) and k not in ('DOCKER_CONFIG', 'CGO_ENABLED')}


def sha256(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, text=True, capture_output=True,
                          env={**CLEAN_ENV, **GIT_ENV}).stdout.strip()


def make_repo(path, dockerfile):
    (path / 'deploy' / 'docker').mkdir(parents=True)
    (path / 'deploy' / 'docker' / 'operator.Dockerfile').write_text(dockerfile)
    (path / 'phorvex').mkdir()
    (path / 'phorvex' / 'PENDING-INVENTORY.md').write_text('# inventory\n')
    (path / 'phorvex' / 'VERSION').write_text('tagged\n')
    git(path, 'init', '-q', '-b', 'main')
    git(path, 'add', '-A')
    git(path, 'commit', '-q', '-m', 'tagged')
    return git(path, 'rev-parse', 'HEAD')


class BuildImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='build-image-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        for d in ('lab', 'repo', 'run', 'state', 'scratch', 'home'):
            (self.tmp / d).mkdir()
        self.repo, self.run_dir, self.state = self.tmp / 'repo', self.tmp / 'run', self.tmp / 'state'
        self.log, self.ledger = self.tmp / 'stub.log', self.tmp / 'run' / 'CREATED.json'
        self.ledger.write_text(json.dumps({'runId': RUN_ID, 'entries': []}))

        # The script beside a lock whose profiles are the real ones, keyed by the stub Dockerfiles.
        real = json.loads(LOCK.read_text())
        six, eight = sorted(real['operatorDockerfiles'].values(), key=lambda p: len(p['setTwo']))
        lock = {**real, 'base': {**real['base'], 'digest': BASE_DIGEST},
                'operatorDockerfiles': {sha256(SIX): six, sha256(EIGHT): eight}}
        self.script = self.tmp / 'lab' / 'build-image.sh'
        shutil.copy2(SCRIPT, self.script)
        (self.tmp / 'lab' / 'images.lock').write_text(json.dumps(lock))
        self.profiles = {'six': six, 'eight': eight}

        self.commit = make_repo(self.repo, SIX)
        git(self.repo, 'tag', '-a', '-m', 'release', 'manager-v0.11.0')
        (self.repo / 'deploy' / 'docker' / 'operator.Dockerfile').write_text(EIGHT)
        git(self.repo, 'commit', '-q', '-am', 'eight binaries')
        self.eight_commit = git(self.repo, 'rev-parse', 'HEAD')
        git(self.repo, 'tag', 'bench-eight')
        (self.repo / 'phorvex' / 'VERSION').write_text('later\n')
        git(self.repo, 'commit', '-q', '-am', 'later')
        (self.repo / 'phorvex' / 'VERSION').write_text('uncommitted\n')
        (self.repo / 'untracked.txt').write_text('local only\n')

    def run_script(self, *args, defaults=True, **stub):
        base = ['--run-dir', str(self.run_dir), '--run-id', RUN_ID, '--ledger', str(self.ledger),
                '--src-repo', str(self.repo), '--tag', 'manager-v0.11.0', '--commit', self.commit,
                '--account', ACCOUNT, '--expires', '2026-10-28T03:00:00Z']
        env = {**CLEAN_ENV, 'PATH': f'{STUBS}:{CLEAN_ENV["PATH"]}', 'HOME': str(self.tmp / 'home'),
               'TMPDIR': str(self.tmp / 'scratch'), 'STUB_LOG': str(self.log), 'STUB_STATE': str(self.state),
               'STUB_ACCOUNT': ACCOUNT, 'STUB_DIGEST': DIGEST, **stub}
        return subprocess.run(['bash', str(self.script), *(base if defaults else []), *args],
                              text=True, capture_output=True, env=env)

    def delete(self, **stub):
        return self.run_script('--delete', '--run-id', RUN_ID, '--ledger', str(self.ledger),
                               '--account', ACCOUNT, defaults=False, **stub)

    def calls(self, tool=None, *prefix):
        lines = [l.split('\t') for l in self.log.read_text().splitlines()] if self.log.exists() else []
        if tool is None:
            return lines
        return [l[1:] for l in lines if l[0] == tool and l[1:1 + len(prefix)] == list(prefix)]

    def recorded(self, key):
        return [l[1] for l in self.calls() if l[0] == key]

    def ecr_calls(self):
        return [c for c in self.calls('aws') if c[:1] == ['ecr']]

    def ledger_entries(self):
        return json.loads(self.ledger.read_text())['entries']

    def repo_state(self):
        g = self.repo / '.git'
        files = sorted(p for d in ('hooks', 'info') for p in (g / d).glob('*') if p.is_file())
        return {
            'status': git(self.repo, 'status', '--porcelain=v1', '--ignored', '-uall'),
            'refs': git(self.repo, 'for-each-ref'), 'head': git(self.repo, 'rev-parse', 'HEAD'),
            'index': sha256(git(self.repo, 'ls-files', '-s')),
            'git-files': {str(p.relative_to(g)): sha256(p.read_bytes())
                          for p in [g / 'HEAD', g / 'config', *files] + ([g / 'packed-refs'] if (g / 'packed-refs').exists() else [])},
            'version': (self.repo / 'phorvex' / 'VERSION').read_text(),
        }

    def assert_fails(self, result, code, needle):
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertIn(needle, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertFalse((self.run_dir / 'IMAGE.json').exists())
        self.assertFalse((self.run_dir / 'src').exists(), 'src left behind')
        self.assertFalse((self.run_dir / 'dockercfg').exists(), 'dockercfg left behind')

    # TP-3, TP-5 (shape), TP-6, TP-7 (dockercfg and src).
    def test_builds_the_tag_and_writes_image_json(self):
        before = self.repo_state()
        stamp = time.time()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

        image = f'{REGISTRY}/phorvex-281-temp-{RUN_ID}@{DIGEST}'
        self.assertEqual(result.stdout, image + '\n')
        record = json.loads((self.run_dir / 'IMAGE.json').read_text())
        names = ['manager', 'brain-replay', 'phorvex-recovery', 'phorvex-mig-allocation-helper',
                 'loss-observer', 'current-inventory-observer']
        self.assertEqual([b['name'] for b in record['binaries']], names)
        self.assertEqual({b['name']: b['stamped'] for b in record['binaries']},
                         {n: n in ('manager', 'brain-replay') for n in names})
        rootfs = self.run_dir / 'build' / 'rootfs'
        for b in record['binaries']:
            self.assertEqual(b['sha256'], sha256((rootfs / b['name']).read_bytes()))
            self.assertEqual((rootfs / b['name']).stat().st_mode & 0o777, 0o755, b['name'])
        self.assertEqual({k: record[k] for k in ('tag', 'commit', 'component', 'repository', 'digest', 'image',
                                                 'goToolchain', 'linkedGitSHA', 'reproducible', 'runId')},
                         {'tag': 'manager-v0.11.0', 'commit': self.commit, 'component': 'manager',
                          'repository': f'{REGISTRY}/phorvex-281-temp-{RUN_ID}', 'digest': DIGEST, 'image': image,
                          'goToolchain': 'go1.26.1', 'linkedGitSHA': self.commit, 'reproducible': True,
                          'runId': RUN_ID})
        self.assertEqual(record['base'], {'image': 'gcr.io/distroless/static-debian12:nonroot', 'digest': BASE_DIGEST})
        self.assertEqual(record['operatorDockerfileSha256'], sha256(SIX))
        self.assertRegex(record['builtAt'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

        # The tag's tree, pendingcheck, then both sets with the Dockerfile's flags.
        go = self.calls('go')
        self.assertEqual(go[0], ['run', './cmd/pendingcheck', '-root', '.', '-inventory', 'PENDING-INVENTORY.md'])
        self.assertEqual(go[1], ['env', 'GOVERSION'])
        builds = [c for c in go if c[0] == 'build']
        self.assertEqual(len(builds), 4, 'two sets, built twice')
        self.assertEqual(builds[0], ['build', '-trimpath', '-ldflags=-s -w -X github.com/phorvex/phorvex/internal/buildinfo.'
                                     f'linkedGitSHA={self.commit}', '-o', f'{self.run_dir}/build/out/', './cmd', './cmd/brain-replay'])
        self.assertEqual(builds[1], ['build', '-trimpath', '-ldflags=-s -w', '-o', f'{self.run_dir}/build/out/', './cmd/recovery',
                                     './cmd/mig-allocation-helper', './cmd/loss-observer', './cmd/current-inventory-observer'])
        envs = self.recorded('go-env')
        for e in envs:
            self.assertIn(f'pwd={self.run_dir}/src/phorvex ', e)
            self.assertIn('GOTOOLCHAIN=go1.26.1 GOFLAGS=-mod=readonly -buildvcs=false', e)
        build_envs = [e for e, c in zip(envs, go) if c[0] == 'build']
        for e in build_envs:
            self.assertIn('CGO_ENABLED=0 GOOS=linux GOARCH=amd64', e)
        self.assertTrue(build_envs[0].endswith('GOCACHE='), 'first build uses the ambient cache')
        self.assertTrue(build_envs[2].endswith(f'GOCACHE={self.run_dir}/build/gocache-rebuild'), 'rebuild cache is fresh')

        # The run's repository, then a root-owned layer on the pinned base.
        (create,) = self.calls('aws', 'ecr', 'create-repository')
        self.assertEqual(create, ['ecr', 'create-repository', '--region', 'us-east-2', '--repository-name',
                                  f'phorvex-281-temp-{RUN_ID}', '--image-tag-mutability', 'IMMUTABLE', '--tags',
                                  f'Key=phorvex.ai/lab-run,Value={RUN_ID}', 'Key=phorvex.ai/benchmark,Value=true',
                                  'Key=phorvex.ai/lab-expires,Value=2026-10-28T03:00:00Z', '--output', 'json'])
        self.assertEqual({c[1] for c in self.ecr_calls()}, {'create-repository', 'get-login-password'},
                         'the only ECR writes are create and push')
        (mutate,) = self.calls('crane', 'mutate')
        self.assertEqual(mutate, ['mutate', f'gcr.io/distroless/static-debian12:nonroot@{BASE_DIGEST}', '--platform',
                                  'linux/amd64', '--append', f'{self.run_dir}/build/rootfs.tar', '-u', '65532:65532',
                                  '--entrypoint', '/manager', '-w', '/', '-t',
                                  f'{REGISTRY}/phorvex-281-temp-{RUN_ID}:{self.commit[:8]}'])
        entries = self.recorded('layer-entry')
        self.assertEqual(entries[0], 'drwxr-xr-x 0/0 ./')
        self.assertEqual(sorted(entries[1:]), sorted(f'-rwxr-xr-x 0/0 ./{n}' for n in names))

        # Registry credentials only in the run's dockercfg, gone after the push; src gone; build kept.
        self.assertEqual(self.recorded('login-password'), ['stub-registry-password'])
        self.assertEqual(self.recorded('login-config'), [f'{self.run_dir}/dockercfg'])
        self.assertFalse((self.run_dir / 'dockercfg').exists())
        self.assertFalse((self.run_dir / 'src').exists())
        self.assertTrue((rootfs / 'brain-replay').exists(), 'brain-replay is kept for the tick-0 replay')
        self.assertEqual(self.ledger_entries(), [{
            'kind': 'ecr-repository', 'name': f'phorvex-281-temp-{RUN_ID}', 'region': 'us-east-2',
            'account': ACCOUNT, 'expires': '2026-10-28T03:00:00Z',
            'at': self.ledger_entries()[0]['at'], 'status': 'created'}])

        # TP-6: the working repository is untouched.
        self.assertEqual(self.repo_state(), before)
        newer = [p for p in self.repo.rglob('*') if '.git' not in p.parts and p.stat().st_mtime > stamp]
        self.assertEqual(newer, [])
        self.assertEqual(list((self.tmp / 'scratch').iterdir()), [], 'temporary files left behind')

    def test_builds_the_eight_binary_dockerfile(self):
        result = self.run_script('--tag', 'bench-eight', '--commit', self.eight_commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.run_dir / 'IMAGE.json').read_text())
        self.assertEqual([b['name'] for b in record['binaries']][-2:], ['persistence-observer', 'cost-budget-admin'])
        self.assertEqual(len(record['binaries']), 8)
        self.assertEqual(record['operatorDockerfileSha256'], sha256(EIGHT))

    def test_tp1_commit_that_is_not_the_tag_target(self):
        result = self.run_script('--commit', self.eight_commit)
        self.assert_fails(result, 11, f'tag manager-v0.11.0 points to {self.commit}, not --commit {self.eight_commit}')
        self.assertEqual(self.ecr_calls(), [])
        self.assertEqual(self.calls('go'), [])

    def test_tag_missing_from_the_source(self):
        result = self.run_script('--tag', 'brain-v9.9.9')
        self.assert_fails(result, 11, 'tag brain-v9.9.9 is not in the source repository')
        self.assertEqual(self.ecr_calls(), [])

    def test_tp2_name_collision(self):
        (self.state / 'ecr-repo').write_text('someone-else\n')
        result = self.run_script()
        self.assert_fails(result, 16, f'phorvex-281-temp-{RUN_ID} already exists')
        self.assertEqual(self.calls('crane', 'mutate'), [], 'nothing pushed')
        self.assertEqual(self.calls('aws', 'ecr', 'delete-repository'), [], 'nothing deleted')
        self.assertEqual(self.ledger_entries()[0]['status'], 'collision')
        self.assertEqual((self.state / 'ecr-repo').read_text(), 'someone-else\n')

        # A recorded collision is never deleted, even by --delete.
        result = self.delete()
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn('recorded name collision', result.stderr)
        self.assertEqual(self.calls('aws', 'ecr', 'delete-repository'), [])

    def test_tp4_unreproducible_build_is_recorded(self):
        result = self.run_script(STUB_REPRO='no')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads((self.run_dir / 'IMAGE.json').read_text())['reproducible'])
        self.assertFalse((self.run_dir / 'build' / 'rebuild').exists())

    def test_tp5_pushed_image_must_be_base_plus_one_layer_with_dockerfile_config(self):
        for stub, needle in ((('STUB_USER', '0:0'),), 'is not user 65532:65532'), ((('STUB_LAYERS', 'bad'),), 'are not the base'):
            with self.subTest(needle=needle):
                shutil.rmtree(self.run_dir / 'build', ignore_errors=True)
                (self.state / 'ecr-repo').unlink(missing_ok=True)
                (self.state / 'pushed').unlink(missing_ok=True)
                self.ledger.write_text(json.dumps({'runId': RUN_ID, 'entries': []}))
                self.assert_fails(self.run_script(**dict(stub)), 15, needle)

    def test_tp7_delete_after_a_build(self):
        self.assertEqual(self.run_script().returncode, 0)
        result = self.delete()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RepositoryNotFoundException', result.stderr)
        (delete,) = self.calls('aws', 'ecr', 'delete-repository')
        self.assertEqual(delete, ['ecr', 'delete-repository', '--region', 'us-east-2', '--repository-name',
                                  f'phorvex-281-temp-{RUN_ID}', '--force', '--output', 'json'])
        self.assertFalse((self.state / 'ecr-repo').exists())
        self.assertEqual(self.delete().returncode, 0, 'idempotent once gone')

    def test_delete_refuses_another_runs_repository(self):
        (self.state / 'ecr-repo').write_text('ffffff\n')
        result = self.delete()
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn(f'not tagged phorvex.ai/lab-run={RUN_ID}', result.stderr)
        self.assertEqual(self.calls('aws', 'ecr', 'delete-repository'), [])

    def test_delete_that_is_not_proven(self):
        (self.state / 'ecr-repo').write_text(RUN_ID + '\n')
        result = self.delete(STUB_DELETE='noop')
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn('still exists', result.stderr)

    def test_tp8_dockerfile_drift_from_a_remote(self):
        remote = self.tmp / 'remote'
        remote.mkdir()
        drift_commit = make_repo(remote, 'FROM golang:1.27 AS changed\n')
        git(remote, 'tag', 'bench-drift')
        result = self.run_script('--src-remote', f'file://{remote}', '--tag', 'bench-drift', '--commit', drift_commit)
        self.assert_fails(result, 18, 'Dockerfile drift')
        self.assertEqual(self.ecr_calls(), [])
        self.assertEqual(self.calls('go'), [])

    def test_remote_clone_with_askpass(self):
        remote = self.tmp / 'remote'
        shutil.copytree(self.repo, remote)
        askpass = self.tmp / 'askpass'
        askpass.write_text('#!/bin/sh\necho unused\n')
        askpass.chmod(0o700)
        result = self.run_script('--src-remote', f'file://{remote}', '--git-askpass', str(askpass))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tp9_push_failure_then_delete(self):
        result = self.run_script(STUB_PUSH='fail')
        self.assert_fails(result, 15, 'command failed')
        self.assertEqual(self.ledger_entries()[0]['status'], 'created', 'the ledger holds the repository')
        self.assertTrue((self.state / 'ecr-repo').exists())
        result = self.delete()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / 'ecr-repo').exists())

    def test_create_failure_other_than_collision(self):
        result = self.run_script(STUB_CREATE='denied')
        self.assert_fails(result, 15, 'could not create ECR repository')
        self.assertEqual(self.ledger_entries()[0]['status'], 'failed')

    def test_pendingcheck_failure(self):
        result = self.run_script(STUB_PENDING='fail')
        self.assert_fails(result, 13, 'pendingcheck failed')
        self.assertEqual(self.ecr_calls(), [])

    def test_build_failures(self):
        cases = (({'STUB_BUILD': 'fail'}, 'go build failed'),
                 ({'STUB_STAMP': 'drop'}, 'manager does not carry linkedGitSHA'),
                 ({'STUB_GOVERSION': 'go1.26.4'}, 'go resolved toolchain go1.26.4, not go1.26.1'))
        for stub, needle in cases:
            with self.subTest(needle=needle):
                shutil.rmtree(self.run_dir / 'build', ignore_errors=True)
                self.assert_fails(self.run_script(**stub), 14, needle)
                self.assertEqual(self.ecr_calls(), [])

    def test_bad_arguments(self):
        inside = self.repo / 'run'
        inside.mkdir()
        cases = [
            (['--run-id', 'A1B2C3'], '--run-id must be 6 lowercase hex digits'),
            (['--commit', self.commit[:12]], '--commit must be a full'),
            (['--account', '7535564371'], '--account must be 12 digits'),
            (['--ledger', str(self.tmp / 'missing.json')], '--ledger must be a JSON file'),
            (['--run-dir', str(inside)], '--run-dir must be outside the working repository'),
            (['--run-dir', str(self.tmp)], '--run-dir must not contain the working repository'),
            (['--run-dir', 'relative/run'], '--run-dir must be an existing absolute directory'),
            (['--src-remote', 'https://user:token@example.invalid/repo.git'], '--src-remote must not carry credentials'),
            (['--git-askpass', '/bin/true'], '--git-askpass needs --src-remote'),
            (['--expires', 'tomorrow'], '--expires must be RFC 3339'),
            (['--tag', '-rf'], '--tag is not a valid tag name'),
            (['--surprise', 'x'], 'unknown argument'),
        ]
        for args, needle in cases:
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(needle, result.stderr)
        self.ledger.write_text(json.dumps({'runId': 'ffffff', 'entries': []}))
        self.assertEqual(self.run_script().returncode, 10, 'ledger of another run')
        self.assertEqual(self.ecr_calls(), [])
        self.assertEqual(self.calls('go'), [])

    def test_existing_run_dir_outputs_are_refused_and_kept(self):
        (self.run_dir / 'src').mkdir()
        (self.run_dir / 'src' / 'keep').write_text('previous run\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn('src already exists', result.stderr)
        self.assertEqual((self.run_dir / 'src' / 'keep').read_text(), 'previous run\n')

    def test_wrong_aws_account(self):
        result = self.run_script(STUB_ACCOUNT='111111111111')
        self.assert_fails(result, 10, 'account 111111111111, not --account 753556437180')
        self.assertEqual(self.ecr_calls(), [])
        self.assertEqual(self.calls('go'), [])


class ImagesLockTest(unittest.TestCase):
    """The real images.lock against the repository's own operator.Dockerfile."""

    @staticmethod
    def parse_dockerfile(text):
        text = text.replace('\\\n', ' ')
        sets = {}
        for line in text.splitlines():
            m = re.search(r'go build -trimpath -ldflags="([^"]*)" -o /out/\s+((?:\./\S+\s*)+)&&', line)
            if m:
                sets['one' if 'linkedGitSHA' in m.group(1) else 'two'] = m.group(2).split()
        renames = dict(re.findall(r'mv /out/(\S+) /(\S+)', text))
        final = text.rsplit('\nFROM ', 1)[1]
        copies = re.findall(r'COPY --from=builder /(\S+) \.', final)
        return sets, renames, copies

    def test_lock_shape(self):
        lock = json.loads(LOCK.read_text())
        self.assertEqual(lock['platform'], 'linux/amd64')
        self.assertEqual(lock['goToolchain'], 'go1.26.1')
        self.assertRegex(lock['base']['digest'], r'^sha256:[0-9a-f]{64}$')
        source, line = lock['base']['source'].split(':')
        self.assertIn(f'{lock["base"]["image"]}@{lock["base"]["digest"]}',
                      (REPO_ROOT / source).read_text().splitlines()[int(line) - 1], 'base pin cites its repo line')

    def test_each_listed_dockerfile_matches_its_build_sets(self):
        lock = json.loads(LOCK.read_text())
        try:
            tags = subprocess.run(['git', '-C', str(REPO_ROOT), 'tag', '-l', 'manager-v*'], check=True,
                                  text=True, capture_output=True).stdout.split()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest('no Git history')
        by_sha = {}
        for tag in tags:
            text = subprocess.run(['git', '-C', str(REPO_ROOT), 'show', f'{tag}:deploy/docker/operator.Dockerfile'],
                                  text=True, capture_output=True).stdout
            by_sha.setdefault(sha256(text), (tag, text))
        if not by_sha:
            self.skipTest('no manager-v* tags in this clone')
        for sha, profile in lock['operatorDockerfiles'].items():
            with self.subTest(sha=sha[:12]):
                self.assertIn(sha, by_sha, 'no manager tag has this Dockerfile')
                sets, renames, copies = self.parse_dockerfile(by_sha[sha][1])
                for key, name in (('setOne', 'one'), ('setTwo', 'two')):
                    self.assertEqual([p['package'] for p in profile[key]], sets[name])
                    self.assertEqual([p['name'] for p in profile[key]],
                                     [renames[p.rsplit('/', 1)[-1]] for p in sets[name]])
                self.assertEqual(sorted(p['name'] for k in ('setOne', 'setTwo') for p in profile[k]), sorted(copies))
        # The acceptance tag, and every newer manager tag, must be buildable.
        for tag in ('manager-v0.11.0', 'manager-v0.12.0'):
            if tag in tags:
                text = subprocess.run(['git', '-C', str(REPO_ROOT), 'show', f'{tag}:deploy/docker/operator.Dockerfile'],
                                      check=True, text=True, capture_output=True).stdout
                self.assertIn(sha256(text), lock['operatorDockerfiles'], tag)


class StaticChecksTest(unittest.TestCase):
    SCRIPTS = [SCRIPT, STUBS / 'aws', STUBS / 'crane', STUBS / 'go']

    def test_bash_syntax_and_executable(self):
        for script in self.SCRIPTS:
            with self.subTest(script=script.name):
                subprocess.run(['bash', '-n', str(script)], check=True)
                self.assertTrue(os.access(script, os.X_OK))

    def test_no_set_x_and_no_secret_on_a_command_line(self):
        text = SCRIPT.read_text()
        self.assertNotRegex(text, r'(?m)^\s*set -[a-zA-Z]*x')
        self.assertNotIn('--password ', text)
        self.assertIn('--password-stdin', text)

    @unittest.skipUnless(shutil.which('shellcheck'), 'shellcheck not installed')
    def test_shellcheck(self):
        subprocess.run(['shellcheck', *map(str, self.SCRIPTS)], check=True)


if __name__ == '__main__':
    unittest.main()
