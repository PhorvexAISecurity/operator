"""Offline tests for replay_build.py and code_experiment.py.

The brain is the testkit's: it selects a move when a tick's risk exceeds
RotateThreshold, compiled in by the fake go. The analysis, metrics and exports
are the real Math Lab worker's.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import code_experiment  # noqa: E402
import replay_build  # noqa: E402
import testkit  # noqa: E402


class CodeExperimentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='bot-code-exp-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'repo'
        self.base = testkit.make_repo(self.repo, threshold=3)
        self.go, self.template = testkit.write_fake_go(self.tmp / 'fakego')
        os.environ['FAKE_REPLAY_TEMPLATE'] = str(self.template)
        self.addCleanup(os.environ.pop, 'FAKE_REPLAY_TEMPLATE', None)
        self.data = self.tmp / 'dashboard-data'
        testkit.make_corpus(self.data, self.base)
        self.deployed = testkit.write_fake_replay(self.tmp / 'deployed-brain-replay', self.base, 3)

    def build(self, name, src, commit):
        out = self.tmp / 'bin' / name
        replay_build.build(src, commit, out, go=str(self.go))
        return code_experiment.identity(out)

    def candidate(self, new_threshold):
        src = replay_build.checkout(self.repo, self.base, self.tmp / ('cand-%d' % new_threshold))
        (src / testkit.DECISION).write_text('package decision\n\nconst RotateThreshold = %d\n' % new_threshold)
        testkit.git(src, 'commit', '-q', '-am', 'candidate')
        return src, testkit.git(src, 'rev-parse', 'HEAD')

    def request(self, candidate_commit):
        return {'experiment_id': 'code-1', 'title': 'raise the rotate threshold', 'namespace': 'vllm', 'policy': 'vllm-defense',
                'cohort': {'max_snapshots': 500}, 'base_commit': self.base, 'candidate_commit': candidate_commit}

    def run_experiment(self, new_threshold=5):
        base_src = replay_build.checkout(self.repo, self.base, self.tmp / 'base-src')
        base_local = self.build('base-local', base_src, self.base)
        cand_src, cand_commit = self.candidate(new_threshold)
        candidate = self.build('candidate', cand_src, cand_commit)
        control = code_experiment.identity(self.deployed)
        before = sorted(p.name for p in (self.data / 'mathlab/snapshots/vllm/vllm-defense').iterdir())
        result, rows = code_experiment.run(self.data, self.tmp / 'exp', self.request(cand_commit), control, base_local, candidate)
        after = sorted(p.name for p in (self.data / 'mathlab/snapshots/vllm/vllm-defense').iterdir())
        self.assertEqual(before, after, 'the dashboard corpus is only read')
        return result, rows

    def metric(self, rows, arm, metric_id):
        return next(r for r in rows if r['arm_id'] == arm and r['metric_id'] == metric_id and r.get('dimension') is None)

    def test_candidate_change_is_measured_against_the_deployed_brain(self):
        result, rows = self.run_experiment(new_threshold=5)
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual(result['comparison_status'], 'OBSERVATIONAL')
        self.assertEqual(result['toolchain_fidelity'], 'EXACT')
        self.assertEqual(result['population']['control_eligible'], 6)
        # Risks 1..6, threshold 3 -> 5: ticks with risk 4 and 5 stop selecting.
        changed = self.metric(rows, 'candidate', 'M-P21')
        self.assertEqual((changed['numerator'], changed['denominator']), (2, 6))
        self.assertEqual(self.metric(rows, 'base-local', 'M-P21')['value'], 0)
        exp = self.tmp / 'exp'
        for name in ('metrics.json', 'result.json', 'experiment_manifest.json', 'report.md', 'sweep_results.csv',
                     'Phorvex_Math_Lab_Results.xlsx', 'evidence.zip', 'replay.jsonl'):
            self.assertTrue((exp / name).exists(), name)
        replay = [json.loads(l) for l in (exp / 'replay.jsonl').read_text().splitlines()]
        self.assertTrue(all(l['cross_version'] for l in replay if l['arm_id'] == 'candidate'))
        self.assertFalse(any(l['cross_version'] for l in replay if l['arm_id'] != 'candidate'))

    def test_toolchain_divergence_is_reported(self):
        # A "deployed" brain that decides differently from its own commit built here.
        testkit.write_fake_replay(self.deployed, self.base, 3)
        self.data = self.tmp / 'data2'
        testkit.make_corpus(self.data, self.base, recorded_threshold=3)
        base_src = replay_build.checkout(self.repo, self.base, self.tmp / 'b2')
        (base_src / testkit.DECISION).write_text('package decision\n\nconst RotateThreshold = 4\n')
        testkit.git(base_src, 'commit', '-q', '-am', 'drift')  # a different binary claiming the base commit
        drift = testkit.git(base_src, 'rev-parse', 'HEAD')
        out = self.tmp / 'bin/b2'
        replay_build.build(base_src, drift, out, go=str(self.go))
        testkit.write_fake_replay(out, self.base, 4)  # same claimed SHA, different behaviour
        cand_src, cand_commit = self.candidate(5)
        result, rows = code_experiment.run(self.data, self.tmp / 'exp2', self.request(cand_commit),
                                           code_experiment.identity(self.deployed), code_experiment.identity(out),
                                           self.build('c2', cand_src, cand_commit))
        self.assertEqual(result['toolchain_fidelity'], 'DIVERGED')

    def test_refuses_a_cohort_from_another_revision(self):
        cand_src, cand_commit = self.candidate(5)
        other = testkit.write_fake_replay(self.tmp / 'other', 'f' * 40, 3)
        with self.assertRaisesRegex(code_experiment.CodeExperimentError, 'recorded by'):
            code_experiment.run(self.data, self.tmp / 'e', self.request(cand_commit), code_experiment.identity(other),
                                code_experiment.identity(other), self.build('c', cand_src, cand_commit))

    def test_refuses_an_empty_cohort(self):
        cand_src, cand_commit = self.candidate(5)
        req = {**self.request(cand_commit), 'policy': 'nothing-here'}
        with self.assertRaisesRegex(code_experiment.CodeExperimentError, 'no recorded ticks'):
            code_experiment.run(self.data, self.tmp / 'e', req, {}, {}, {})


class ReplayBuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='bot-replay-build-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'repo'
        self.base = testkit.make_repo(self.repo)
        self.go, template = testkit.write_fake_go(self.tmp / 'fakego')
        os.environ['FAKE_REPLAY_TEMPLATE'] = str(template)
        self.addCleanup(os.environ.pop, 'FAKE_REPLAY_TEMPLATE', None)

    def test_builds_the_commit_and_stamps_it(self):
        src = replay_build.checkout(self.repo, self.base, self.tmp / 'src')
        sha = replay_build.build(src, self.base, self.tmp / 'out/brain-replay', go=str(self.go))
        self.assertEqual(sha, replay_build.sha256_file(self.tmp / 'out/brain-replay'))
        self.assertEqual(code_experiment.identity(self.tmp / 'out/brain-replay')['git_sha'], self.base)

    def test_refuses_a_wrong_commit_or_a_dirty_tree_or_a_failed_build(self):
        src = replay_build.checkout(self.repo, self.base, self.tmp / 'src')
        with self.assertRaisesRegex(replay_build.BuildError, 'not'):
            replay_build.build(src, 'f' * 40, self.tmp / 'x', go=str(self.go))
        (src / 'phorvex/stray.go').write_text('package x\n')
        with self.assertRaisesRegex(replay_build.BuildError, 'uncommitted'):
            replay_build.build(src, self.base, self.tmp / 'x', go=str(self.go))
        (src / 'phorvex/stray.go').unlink()
        os.environ['FAKE_GO_FAIL'] = '1'
        self.addCleanup(os.environ.pop, 'FAKE_GO_FAIL', None)
        with self.assertRaisesRegex(replay_build.BuildError, 'go build of brain-replay'):
            replay_build.build(src, self.base, self.tmp / 'x', go=str(self.go))

    def test_checkout_only_reads_the_repo(self):
        before = (testkit.git(self.repo, 'status', '--porcelain'), testkit.git(self.repo, 'for-each-ref'))
        replay_build.checkout(self.repo, self.base, self.tmp / 'src')
        self.assertEqual((testkit.git(self.repo, 'status', '--porcelain'), testkit.git(self.repo, 'for-each-ref')), before)


if __name__ == '__main__':
    unittest.main()
