"""Offline tests for benchmark/build-image.sh, against stub aws/docker CLIs.

Each test builds a throwaway Git repository whose tag and HEAD differ, so a
build from the wrong tree, a moved tag or an edited repository is visible.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BENCHMARK = Path(__file__).resolve().parents[2]
SCRIPT = BENCHMARK / 'build-image.sh'
STUBS = Path(__file__).resolve().parent / 'stubs'
ACCOUNT = '753556437180'
RUN_ID = 'bench-001'
DIGEST = 'sha256:' + 'ab' * 32
GIT_ENV = {
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
}


class BuildImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='bench-image-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'repo'
        self.home = self.tmp / 'home'
        self.scratch = self.tmp / 'scratch'
        self.log = self.tmp / 'stub.log'
        for d in (self.repo, self.scratch, self.home / '.docker' / 'cli-plugins'):
            d.mkdir(parents=True)
        (self.home / '.docker' / 'config.json').write_text('{"sentinel": true}\n')

        (self.repo / 'deploy' / 'docker').mkdir(parents=True)
        (self.repo / 'deploy' / 'docker' / 'service.Dockerfile').write_text('FROM scratch\n')
        (self.repo / 'phorvex').mkdir()
        (self.repo / 'phorvex' / 'VERSION').write_text('tagged\n')
        self.git('init', '-q', '-b', 'main')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'tagged')
        self.git('tag', '-a', '-m', 'release', 'manager-v0.11.0')
        self.commit = self.git('rev-parse', 'HEAD')
        # HEAD moves past the tag, and the working tree is dirty.
        (self.repo / 'phorvex' / 'VERSION').write_text('later\n')
        self.git('commit', '-q', '-am', 'later')
        (self.repo / 'phorvex' / 'VERSION').write_text('uncommitted\n')
        (self.repo / 'untracked.txt').write_text('local only\n')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True, text=True,
                              capture_output=True, env={**os.environ, **GIT_ENV}).stdout.strip()

    def repo_state(self):
        return (self.git('status', '--porcelain=v1', '-uall'), self.git('for-each-ref'),
                self.git('rev-parse', 'HEAD'), (self.repo / 'phorvex' / 'VERSION').read_text())

    def run_script(self, *extra, commit=None, **stub_env):
        args = ['--tag', 'manager-v0.11.0', '--commit', commit or self.commit, '--run-id', RUN_ID,
                '--aws-account', ACCOUNT, '--repo', str(self.repo), *extra]
        env = {**os.environ, **GIT_ENV, 'PATH': f'{STUBS}:{os.environ["PATH"]}', 'HOME': str(self.home),
               'TMPDIR': str(self.scratch), 'STUB_LOG': str(self.log), 'STUB_ACCOUNT': ACCOUNT,
               'STUB_RUN_ID': RUN_ID, 'STUB_DIGEST': DIGEST, **stub_env}
        return subprocess.run(['bash', str(SCRIPT), *args], text=True, capture_output=True, env=env)

    def calls(self):
        if not self.log.exists():
            return []
        return [line.split('\t') for line in self.log.read_text().splitlines()]

    def recorded(self, key):
        return [c[1] for c in self.calls() if c[0] == key]

    def tool_calls(self, tool, *prefix):
        return [c[1:] for c in self.calls() if c[0] == tool and c[1:1 + len(prefix)] == list(prefix)]

    def assert_refused(self, result, needle):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(needle, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.tool_calls('docker'), [])

    def test_builds_tag_tree_and_records_pinned_digest(self):
        before = self.repo_state()
        out = self.tmp / 'image.json'
        result = self.run_script('--out', str(out))
        self.assertEqual(result.returncode, 0, result.stderr)

        registry = f'{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com'
        pinned = f'{registry}/phorvex-bench/{RUN_ID}/brain@{DIGEST}'
        self.assertEqual(result.stdout, pinned + '\n')
        record = json.loads(out.read_text())
        self.assertEqual(record['image'], pinned)
        self.assertEqual(record['digest'], DIGEST)
        self.assertEqual(record['sourceTag'], 'manager-v0.11.0')
        self.assertEqual(record['sourceCommit'], self.commit)
        self.assertEqual(record['component'], 'brain')
        self.assertEqual(record['imageTag'], f'manager-v0.11.0-{self.commit[:12]}')
        self.assertEqual(record['schema'], 'phorvex-bench/image/v1')

        # The tag's committed tree, not HEAD or the working tree, with HEAD = commit.
        self.assertEqual(self.recorded('context-head'), [self.commit])
        self.assertEqual(self.recorded('context-version'), ['tagged'])
        self.assertEqual(self.recorded('context-untracked'), ['absent'])
        (build,) = self.tool_calls('docker', 'build')
        self.assertIn('SERVICE=brain', build)
        self.assertEqual(build[build.index('--platform') + 1], 'linux/amd64')
        self.assertEqual(build[build.index('--tag') + 1],
                         f'{registry}/phorvex-bench/{RUN_ID}/brain:manager-v0.11.0-{self.commit[:12]}')

        (create,) = self.tool_calls('aws', 'ecr', 'create-repository')
        self.assertEqual(create[create.index('--repository-name') + 1], f'phorvex-bench/{RUN_ID}/brain')
        self.assertIn(f'Key=phorvex-bench-run,Value={RUN_ID}', create)
        self.assertIn('IMMUTABLE', create)
        self.assertEqual(len(self.tool_calls('aws', 'ecr', 'put-lifecycle-policy')), 1)

        # Registry credentials go to a temporary Docker config, never ~/.docker.
        self.assertEqual(self.recorded('login-password'), ['stub-registry-password'])
        (config,) = self.recorded('login-config')
        self.assertTrue(config.startswith(str(self.scratch)), config)
        self.assertEqual((self.home / '.docker' / 'config.json').read_text(), '{"sentinel": true}\n')
        self.assertEqual(list(self.scratch.iterdir()), [], 'temporary build directory left behind')
        self.assertEqual(self.repo_state(), before)

    def test_moved_tag_is_refused_before_any_cloud_call(self):
        head = self.git('rev-parse', 'HEAD')
        result = self.run_script(commit=head)
        self.assert_refused(result, f'points to {self.commit}, not --commit {head}')
        self.assertEqual(self.calls(), [])

    def test_missing_tag_is_refused_without_fetching(self):
        result = subprocess.run(['bash', str(SCRIPT), '--tag', 'brain-v9.9.9', '--commit', self.commit,
                                 '--run-id', RUN_ID, '--aws-account', ACCOUNT, '--repo', str(self.repo)],
                                text=True, capture_output=True,
                                env={**os.environ, 'PATH': f'{STUBS}:{os.environ["PATH"]}', 'STUB_LOG': str(self.log)})
        self.assert_refused(result, "tag 'brain-v9.9.9' is not in")
        self.assertEqual(self.calls(), [])

    def test_wrong_aws_account_is_refused_before_any_write(self):
        result = self.run_script(STUB_ACCOUNT='111111111111')
        self.assert_refused(result, 'account 111111111111, not --aws-account 753556437180')
        self.assertEqual(self.tool_calls('aws', 'ecr'), [])

    def test_foreign_repository_is_never_reused(self):
        result = self.run_script(STUB_REPO_STATE='foreign')
        self.assert_refused(result, f'without tag phorvex-bench-run={RUN_ID}')
        self.assertEqual(self.tool_calls('aws', 'ecr', 'create-repository'), [])

    def test_lookup_error_is_not_treated_as_missing(self):
        result = self.run_script(STUB_REPO_STATE='denied')
        self.assert_refused(result, 'could not look up ECR repository')
        self.assertEqual(self.tool_calls('aws', 'ecr', 'create-repository'), [])

    def test_rerun_reuses_this_runs_repository(self):
        result = self.run_script(STUB_REPO_STATE='ours')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tool_calls('aws', 'ecr', 'create-repository'), [])
        self.assertEqual(len(self.tool_calls('docker', 'push')), 1)

    def test_invalid_digest_fails_without_output(self):
        out = self.tmp / 'image.json'
        result = self.run_script('--out', str(out), STUB_DIGEST='None')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('no valid digest', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertFalse(out.exists())

    def test_failed_build_cleans_up_and_writes_nothing(self):
        out = self.tmp / 'image.json'
        before = self.repo_state()
        result = self.run_script('--out', str(out), STUB_BUILD_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.tool_calls('docker', 'push'), [])
        self.assertFalse(out.exists())
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertEqual(self.repo_state(), before)

    def test_dry_run_makes_no_cloud_or_docker_calls(self):
        result = self.run_script('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dry run', result.stderr)
        self.assertEqual(result.stdout.strip(),
                         f'{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/phorvex-bench/{RUN_ID}/brain:manager-v0.11.0-{self.commit[:12]}')
        self.assertEqual(self.calls(), [])

    def test_invalid_arguments_are_usage_errors(self):
        cases = [
            ('--commit', self.commit[:12]),
            ('--run-id', 'Bench_001'),
            ('--aws-account', '7535564371'),
            ('--region', 'ohio'),
            ('--platform', 'windows/amd64'),
            ('--out', str(self.tmp / 'missing' / 'image.json')),
        ]
        for flag, value in cases:
            with self.subTest(flag=flag):
                result = self.run_script(flag, value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('usage:', result.stderr)
        self.assertEqual(self.calls(), [])


class StaticChecksTest(unittest.TestCase):
    SCRIPTS = [SCRIPT, BENCHMARK / 'lab' / 'lib' / 'common.sh', STUBS / 'aws', STUBS / 'docker']

    def test_bash_syntax(self):
        for script in self.SCRIPTS:
            with self.subTest(script=script.name):
                subprocess.run(['bash', '-n', str(script)], check=True)

    def test_entrypoints_are_executable(self):
        for script in (SCRIPT, STUBS / 'aws', STUBS / 'docker'):
            self.assertTrue(os.access(script, os.X_OK), script)

    @unittest.skipUnless(shutil.which('shellcheck'), 'shellcheck not installed')
    def test_shellcheck(self):
        subprocess.run(['shellcheck', '-x', '-P', str(BENCHMARK), *map(str, self.SCRIPTS)],
                       check=True, cwd=BENCHMARK)


if __name__ == '__main__':
    unittest.main()
