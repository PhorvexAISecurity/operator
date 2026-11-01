"""Actual uploaded request routing and early, settings-preserving evidence reports."""
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import endpoint_study as endpoint
import file_requests


class SelfserveRequestTests(unittest.TestCase):
    def original(self):
        source = (HERE / 'testdata/endpoint-v3-10d-original.txt').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), '2e0a40127b9b9b65f7d42e5fa4eb1f155d8a1819aced313b8f39435ab493a9a3')
        return source.decode()

    def test_exact_original_upload_preserves_ten_day_contract_without_codegen(self):
        tasks = file_requests.parse(self.original())
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]['kind'], 'endpoint')
        request = json.loads(tasks[0]['text'])
        self.assertEqual(request['policy'], 'phorvex-staging-demo/demo-api-defense')
        self.assertEqual(request['ticks'], 64)
        self.assertIs(request['sync'], False)
        self.assertEqual(request['study'], {'window': 864000, 'slo_target': .999})
        self.assertEqual(request['config']['lookback'], 86400)
        self.assertAlmostEqual(request['config']['eta'], math.log(1000/.0001)/3600)
        self.assertEqual(tasks[0]['conversion']['normalized_prompt_sha256'], 'c4beaa309f609918a6002711d7dd3a48b8d305bc93f6f2d3db12dd347375e1e8')

    def test_missing_dataset_report_keeps_requested_mode_windows_and_unknowns(self):
        request = {'schema': endpoint.SCHEMA, 'title': 'Exact ten-day request', 'policy': 'phorvex-staging-demo/demo-api-defense',
                   'ticks': 64, 'dataset': 'recorded', 'config': {'lookback': 86400},
                   'study': {'window': 864000, 'slo_target': .999}}
        with tempfile.TemporaryDirectory() as directory:
            result = endpoint.run(request, directory)
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(result.get('requested_mode'), 'PAIRED_BRAIN_REPLAY')
            self.assertEqual(result.get('mode'), 'PAIRED_BRAIN_REPLAY')
            self.assertEqual(result.get('required_windows'), {'budget_seconds': 864000, 'burn_seconds': 86400})
            self.assertFalse(result['v2_executed'])
            self.assertFalse(result['v3_executed'])
            for field in ('changed_choices', 'comparable_ticks', 'noop', 'forecast_endpoint_seconds'):
                self.assertIsNone(result.get(field), field)
            html = (Path(directory) / 'report.html').read_text()
            self.assertIn('864000', html)
            self.assertIn('86400', html)
            self.assertIn('PAIRED_BRAIN_REPLAY', html)

    def test_declarative_endpoint_fields_support_independent_arbitrary_windows(self):
        text = '[endpoint]\npolicy: phorvex-staging-demo/demo-api-defense\nticks: 64\nsync: false\ndataset: recorded\nstudy.window: 43200\nconfig.lookback: 12345\nstudy.slo_target: .995\nconfig.min: .001\nconfig.max: 300\n'
        task = file_requests.parse(text)[0]
        self.assertEqual(task['kind'], 'endpoint')
        request = json.loads(task['text'])
        self.assertEqual(request['study'], {'window': 43200, 'slo_target': .995})
        self.assertEqual(request['config']['lookback'], 12345)
        self.assertAlmostEqual(request['config']['eta'], math.log(300/.001)/3600)
        self.assertIs(request['sync'], False)
        self.assertEqual(json.loads(file_requests.parse(json.dumps(request))[0]['text']), request)

    def test_declarative_rejects_unknown_duplicate_and_non_numeric_fields(self):
        for field in ('study.window: 1\nstudy.window: 2', 'config.lookbak: 2', 'config.lookback: true',
                      'study.window: NaN', 'config.lookback: Infinity', 'study.window: ۸۶۴۰۰',
                      'dataset: /tmp/file', 'sync: maybe', 'ticks: 1.2', 'change: implement entropy',
                      'config.min: 2\nconfig.max: 1', 'config.min: 1\nconfig.max: 1.000000001', 'study.slo_target: 1'):
            with self.subTest(field=field), self.assertRaises(file_requests.RequestError):
                file_requests.parse('[endpoint]\n' + field)

    def test_modified_prose_stays_generic_code_and_never_silently_maps(self):
        original = self.original()
        for changed in (original.replace('W=864000', 'W=432000'),
                        original + '\nImplement entropy and priced-worth instead.',
                        original.replace('J=V-lambda_s*(E/R)', 'J=V-lambda_s*E')):
            with self.subTest(sha=hashlib.sha256(changed.encode()).hexdigest()):
                self.assertNotEqual(changed, original)
                self.assertEqual(file_requests.parse(changed)[0]['kind'], 'bench')

    def test_original_thirty_day_compatibility_sets_explicit_slo_and_window(self):
        raw = (HERE / 'testdata/endpoint-v3-30d-original.txt').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'c4f07c2b1635a89fbf60c37f318805e6a3169438bf6739b9448ba54f910f3687')
        with self.assertRaisesRegex(file_requests.RequestError, 'stage namespace'):
            file_requests.parse(raw.decode())
        # The test explicitly selects stage. Production policy is never remapped.
        selected = raw.decode().replace('policy: vllm/vllm-defense', 'policy: phorvex-staging-demo/demo-api-defense', 1)
        task = file_requests.parse(selected)[0]
        self.assertEqual(task['conversion']['normalized_prompt_sha256'], endpoint.LEGACY_V3_PROMPT_SHA)
        request = json.loads(task['text'])
        self.assertEqual(request['study'], {'window': 2592000, 'slo_target': .999})
        self.assertEqual(request['config']['lookback'], 86400)


if __name__ == '__main__':
    unittest.main()
