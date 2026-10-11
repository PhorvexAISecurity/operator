import csv
import json
import tempfile
import unittest
from pathlib import Path

import parameters


class HTTP404(Exception):
    status = 404


class FakeConsole:
    def __init__(self, runtime=None, log=None):
        self.runtime, self.log, self.paths = runtime, log, []

    def request(self, path):
        self.paths.append(path)
        if path.startswith(parameters.RUNTIME_PATH.split('?')[0]) and self.runtime is not None:
            return self.runtime
        if path.startswith('/api/optimizer/parameter-log') and self.log is not None:
            return self.log
        raise HTTP404('not found')


def runtime(generation=8, norm=0.4, status='VERIFIED', brain_generation=8):
    def opt(v):
        return {'present': True, 'value': v}
    return {'catalogue': [{'key': 'normWeight', 'symbol': 'w_N', 'specPath': 'spec.objective.costWeights.normSparsity'},
                          {'key': 'beta', 'symbol': 'β', 'specPath': 'spec.objective.disruptionAversion'}],
            'policies': [{'namespace': 'vllm', 'name': 'vllm-defense', 'generation': generation, 'economicsMode': 'legacy',
                          'brain': {'generation': brain_generation, 'decisionTime': '2026-10-11T00:00:00Z', 'effectiveCostCoefficient': 0, 'lambdaRuntime': 0},
                          'parameters': [{'key': 'normWeight', 'configured': opt(norm), 'observed': opt(norm), 'status': status},
                                         {'key': 'beta', 'configured': {'present': False, 'value': 0}, 'observed': {'present': False, 'value': 0}, 'status': 'NOT_APPLICABLE'}]}]}


class ParametersTest(unittest.TestCase):
    def test_capture_records_a_missing_endpoint_without_failing(self):
        record = parameters.capture(FakeConsole(runtime=runtime()))
        self.assertIsNotNone(record['runtime'])
        self.assertIsNone(record['log'])
        self.assertEqual(record['errors'], ['/api/optimizer/parameter-log unavailable (HTTP 404)'])
        old = parameters.capture(FakeConsole())
        self.assertIsNone(old['runtime'])
        self.assertEqual(len(old['errors']), 2)

    def test_compare_flags_knobs_changed_during_the_run(self):
        before = {'runtime': runtime(), 'fetchedAt': 'a'}
        after = {'runtime': runtime(generation=9, norm=0.3, status='PENDING', brain_generation=8), 'fetchedAt': 'b'}
        merged, changed = parameters.compare(before, after)
        norm = next(r for r in merged if r['parameter'] == 'normWeight')
        self.assertEqual((norm['configured_before'], norm['configured_after'], norm['status_after'], norm['changed_during_run']), (0.4, 0.3, 'PENDING', 'yes'))
        self.assertIn('vllm/vllm-defense:normWeight', changed)
        beta = next(r for r in merged if r['parameter'] == 'beta')
        self.assertEqual(beta['configured_before'], '')  # absent stays absent, never zero
        summary = parameters.summary(before, after)
        self.assertEqual(summary['before']['verdicts'], {'VERIFIED': 1, 'NOT_APPLICABLE': 1})
        self.assertEqual(summary['after']['verdicts'], {'PENDING': 1, 'NOT_APPLICABLE': 1})

    def test_csv_has_one_row_per_app_and_knob(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / parameters.CSV_FILE
            n = parameters.write_csv(path, {'runtime': runtime()}, {'runtime': runtime()})
            with open(path) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(n, 2)
            self.assertEqual(list(rows[0].keys()), parameters.CSV_HEADERS)
            self.assertEqual(rows[1]['status_after'], 'VERIFIED')
            # An older Console: the CSV still exists with headers only.
            self.assertEqual(parameters.write_csv(path, {'runtime': None}, {'runtime': None}), 0)

    def test_observations_append_only_on_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = parameters.observe(tmp, {'runtime': runtime(), 'fetchedAt': 't1'})
            again = parameters.observe(tmp, {'runtime': runtime(), 'fetchedAt': 't2'})
            moved = parameters.observe(tmp, {'runtime': runtime(generation=9, norm=0.3, status='PENDING'), 'fetchedAt': 't3'})
            verified = parameters.observe(tmp, {'runtime': runtime(generation=9, norm=0.3, brain_generation=9), 'fetchedAt': 't4'})
            self.assertEqual((len(first), len(again), len(moved), len(verified)), (1, 0, 1, 1))
            recent = parameters.recent_observations(tmp)
            self.assertEqual([o['observedAt'] for o in recent], ['t4', 't3', 't1'])
            self.assertNotIn('fingerprint', recent[0])
            self.assertEqual(recent[0]['brainGeneration'], 9)
            lines = (Path(tmp) / 'parameters' / 'observations.jsonl').read_text().splitlines()
            self.assertTrue(all(json.loads(l)['schema'] == parameters.OBSERVATION_SCHEMA for l in lines))


if __name__ == '__main__':
    unittest.main()
