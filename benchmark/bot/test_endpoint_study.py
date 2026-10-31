"""Real paired Go execution, truthful evidence and bot upload/routing regressions."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import endpoint_study as endpoint
import file_requests
import service
import test_bot as kit
import test_uploads as uploads


def example(kind='synthetic'):
    return json.loads((HERE/('templates/endpoint-v3-'+kind+'.json')).read_text())


class EndpointStudyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='endpoint-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_validation_does_not_invent_recorded_authority(self):
        req = example()
        req['trace']['evidence'] = 'recorded'
        req['trace']['source_revision'] = 'a'*40
        with self.assertRaisesRegex(ValueError, 'operator installation'):
            endpoint.validate(req)
        for change in ({'config': {'min': 10, 'max': 1}}, {'dataset': '../../secret'}, {'ticks': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                endpoint.validate({**example('recorded'), **change})

    def test_missing_recorded_inputs_produce_blocked_artifacts_without_runner(self):
        with mock.patch.object(endpoint, 'binary_identity', side_effect=AssertionError('must not build/run')):
            r = endpoint.run(example('recorded'), self.tmp/'missing', self.tmp/'data')
        self.assertEqual(r['state'], 'BLOCKED')
        self.assertIsNone(r['changed_choices'])
        self.assertFalse(r['v2_executed']); self.assertFalse(r['v3_executed'])
        for name in ('evidence.zip', 'result.json', 'metrics.csv', 'report.html'):
            self.assertTrue((self.tmp/'missing'/name).is_file())

    def test_install_manifest_fails_closed_on_changed_data(self):
        trace = example()['trace']; trace['evidence'] = 'recorded'; trace['source_revision'] = 'a'*40
        source = self.tmp/'input.json'; source.write_text(json.dumps(trace))
        meta = endpoint.install(source, self.tmp/'data', 'vllm/vllm-defense', 'TEST producer, not empirical evidence')
        self.assertEqual(meta['source_revision'], 'a'*40)
        installed = self.tmp/'data/mathlab/endpoint-traces/vllm/vllm-defense.json'
        installed.write_text(installed.read_text()+' ')
        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
            endpoint.run(example('recorded'), self.tmp/'changed', self.tmp/'data')

    @unittest.skipUnless((HERE.parent/'endpointv3/BUILD.json').is_file(), 'build endpointv3/build.py for Go integration tests')
    def test_real_go_64_ticks_both_arms_adaptive_state_and_determinism(self):
        req = example(); before = copy.deepcopy(req)
        r = endpoint.run(req, self.tmp/'first')
        again = endpoint.run(req, self.tmp/'again')
        self.assertEqual(req, before); self.assertEqual(r, again)
        self.assertEqual((r['state'], r['evidence'], r['comparable_ticks']), ('COMPLETE', 'synthetic', 64))
        self.assertGreater(r['changed_choices'], 0)
        self.assertIsNone(r['counterfactual_actual_charges'])
        self.assertIsNone(r['counterfactual_verified_facts'])
        self.assertTrue(all(t['v2']['executed'] and t['v3']['executed'] for t in r['ticks']))
        self.assertTrue(all(t['lambda']['state_write'] == 'COMMITTED' for t in r['ticks']))
        self.assertEqual(r['ticks'][0]['lambda']['lambda_eff'], 0)
        self.assertAlmostEqual(r['ticks'][0]['lambda']['b'], 2)
        self.assertGreater(r['ticks'][-1]['lambda']['lambda_next'], .0001)
        self.assertEqual(len((self.tmp/'first/metrics.csv').read_text().splitlines()), 257)
        floor = example()
        for t in floor['trace']['ticks']: t['ledger']['moves'] = []
        r = endpoint.run(floor, self.tmp/'floor')
        self.assertEqual(r['changed_choices'], 0)
        self.assertTrue(all(t['lambda']['lambda_eff'] == 0 for t in r['ticks']))

    @unittest.skipUnless((HERE.parent/'endpointv3/BUILD.json').is_file(), 'build endpointv3/build.py for Go integration tests')
    def test_missing_telemetry_is_not_a_comparable_zero_effect(self):
        req = example()
        for t in req['trace']['ticks']: t['ledger']['measurement'] = 'replica-readiness'
        r = endpoint.run(req, self.tmp/'blocked')
        self.assertEqual(r['state'], 'BLOCKED'); self.assertEqual(r['comparable_ticks'], 0)
        self.assertIsNone(r['changed_choices']); self.assertIsNone(r['forecast_endpoint_seconds'])
        self.assertTrue(all(t['lambda']['lambda_eff'] == 0 for t in r['ticks']))


class EndpointBotTest(unittest.TestCase):
    setUp = kit.BotTest.setUp
    bot = kit.BotTest.bot
    upload = uploads.UploadTest.upload

    def test_recorded_upload_reaches_batch_blocked_and_sends_evidence(self):
        bot = self.bot()
        self.upload(bot, json.dumps(example('recorded')), filename='endpoint.json')
        self.assertEqual(len(bot.queue), 1)
        job = bot.queue.pop(0)
        bot.execute_job(job)
        self.assertEqual(job.state, 'BLOCKED')
        batch = json.loads((job.dir/'BATCH.json').read_text())
        self.assertEqual(batch['results'][0]['state'], 'BLOCKED')
        self.assertEqual(len(self.fake.documents()), 6)
        self.assertTrue(any('BLOCKED' in t for t in self.fake.texts()))

    def test_exact_reviewed_prompt_routes_before_llm_and_storage_guards(self):
        # A local fixture binds the reviewed prompt hash, avoiding any dependency
        # on a user's external upload directory in CI.
        prompt = 'fixture exact reviewed V3 request'
        digest = endpoint.hashlib.sha256(prompt.encode()).hexdigest()
        bot = self.bot()
        job = service.Job('bench', kit.OWNER, kit.OWNER, 'ticks=64 nosync '+prompt)
        job.dir = self.tmp/'exact'; job.dir.mkdir()
        with mock.patch.object(endpoint, 'LEGACY_V3_PROMPT_SHA', digest), \
             mock.patch.object(bot, 'run_endpoint', return_value='endpoint') as run, \
             mock.patch.object(bot, 'maintain_storage', side_effect=AssertionError('old code path')):
            self.assertEqual(bot.run_bench(job), 'endpoint')
            self.assertEqual(run.call_args.args[1]['dataset'], 'recorded')
            self.assertIsNone(endpoint.legacy_request(prompt+' changed algorithm', 'vllm/vllm-defense', 64))


if __name__ == '__main__': unittest.main()
