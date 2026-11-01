"""Real paired Go execution, truthful evidence and bot upload/routing regressions."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import struct
import subprocess
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
import testkit
from benchmark.stage import test_evidence as observed
from benchmark.stage.normalize import normalize, install


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

    def test_strict_custom_study_settings_and_templates_validate_before_queue(self):
        for study in ({'slo_target': 0}, {'slo_target': 1}, {'window': 0}, {'window': 2592001},
                      {'window': True}, {'worth_threshold': -1}, {'facts': []}, {'accepted': True},
                      {'slo_target': float('nan')}, {'window': '600'}, None):
            with self.subTest(study=study), self.assertRaises(ValueError):
                endpoint.validate({**example('recorded'), 'study': study})
        for name in ('endpoint-v3-stage-600s.json', 'endpoint-v3-original-30d-pending.json'):
            request = json.loads((HERE/'templates'/name).read_text())
            self.assertEqual(file_requests.parse(json.dumps(request))[0]['kind'], 'endpoint')

    def observed_trace(self):
        # Real journal/reducer/normalizer on explicit Kubernetes fixture events;
        # this exercises coverage and retention, not a mocked READY flag.
        journal = observed.Journal(self.tmp/'observations.sqlite', observed.scope())
        self.addCleanup(journal.close)
        observed.seed(journal)
        observed.rotate(journal)
        observed.seal(journal, 1000)
        trace, metadata = normalize(journal.scope, journal.records, [observed.export(650)], .9, 300, 300, 0)
        self.assertEqual(metadata['state'], 'READY')
        self.assertEqual(trace['ticks'][0]['ledger']['complete_from'], 10)
        return trace, metadata

    def test_custom_observed_settings_preserve_facts_and_all_retained_history(self):
        trace, metadata = self.observed_trace()
        before, meta_before = copy.deepcopy(trace), copy.deepcopy(metadata)
        request = endpoint.validate({**example('recorded'), 'ticks': 1, 'config': {'lookback': 600},
                                     'study': {'slo_target': .95, 'window': 600, 'worth_threshold': .2}})
        changed, provenance, missing = endpoint.study_trace(trace, request, metadata)
        self.assertEqual(missing, {})
        self.assertEqual((trace, metadata), (before, meta_before))
        original, tick = before['ticks'][0], changed['ticks'][0]
        self.assertEqual(tick['slo'], {'target': .95, 'window': 600, 'accepted': False, 'study_assumption': True})
        self.assertEqual(tick['ledger'], original['ledger'])
        self.assertEqual(tick['candidates'][0]['worth_threshold'], .2)
        for field in set(original['candidates'][0]) - {'worth_threshold'}:
            self.assertEqual(tick['candidates'][0][field], original['candidates'][0][field], field)
        self.assertEqual(tick['candidates'][0]['samples'][0]['duration'], 10)
        self.assertEqual(tick['ledger']['moves'][0]['intervals'][0]['start'], 23)
        self.assertFalse(tick['ledger']['authoritative'])
        self.assertEqual(provenance['original_normalization_study_settings']['window'], 300)
        self.assertEqual(provenance['ticks'][0]['available_history_seconds'], 640)

    def test_expanded_window_requires_proven_retention_and_sealed_coverage(self):
        trace, metadata = self.observed_trace()
        request = endpoint.validate({**example('recorded'), 'ticks': 1, 'config': {'lookback': 600},
                                     'study': {'window': 600}})
        for mutation, reason in [('retention', 'RETAINED_HISTORY_UNPROVEN'),
                                 ('seal', 'OBSERVED_HISTORY_BINDING_INVALID'),
                                 ('history', 'DURATION_HISTORY_UNKNOWN'),
                                 ('window', 'OBSERVED_HISTORY_INSUFFICIENT')]:
            doc, meta, req = copy.deepcopy(trace), copy.deepcopy(metadata), copy.deepcopy(request)
            if mutation == 'retention': meta.pop('retention', None)
            elif mutation == 'seal': meta['bindings'][0]['sealed_until'] = 649
            elif mutation == 'history': doc['ticks'][0]['candidates'][0]['history_known'] = False
            else: req['study']['window'] = 641
            with self.subTest(mutation=mutation):
                _, _, missing = endpoint.study_trace(doc, req, meta)
                self.assertIn(reason, ' '.join(missing[doc['ticks'][0]['id']]))

    def test_insufficient_original_30d_history_returns_blocked_preserving_installed_data(self):
        trace, metadata = self.observed_trace()
        policy = metadata['scope']['namespace']+'/'+metadata['scope']['policy_name']
        data = self.tmp/'data'
        pin = testkit.write_stage_pin(data, trace['source_revision'], policy, metadata['scope']['policy_uid'])
        metadata['scope']['image_digest'] = pin['brain']['image_digest']
        manifest = install(trace, metadata, data, 'unit-test real normalizer with explicit fixture events')
        pointer = data/'mathlab/endpoint-traces'/(policy+'.manifest.json')
        installed = pointer.parent/manifest['trace_file']
        before = installed.read_bytes(), pointer.read_bytes()
        req = {**example('recorded'), 'policy': policy, 'ticks': 1, 'config': {'lookback': 86400},
               'study': {'slo_target': .999, 'window': 2592000, 'worth_threshold': 0}}
        with mock.patch.object(endpoint, 'subprocess') as process:
            result = endpoint.run(req, self.tmp/'history-blocked', data)
            process.run.assert_not_called()
        self.assertEqual((result['state'], result['comparable_ticks']), ('BLOCKED', None))
        self.assertFalse(result['v2_executed']); self.assertFalse(result['v3_executed'])
        self.assertIn('retained continuous history=640.0 s', str(result['missing_reasons']))
        self.assertEqual(before, (installed.read_bytes(), pointer.read_bytes()))
        self.assertEqual(json.loads((self.tmp/'history-blocked/dataset-manifest.json').read_text()), manifest)
        self.assertEqual(result['study']['original_normalization_study_settings']['window'], 300)
        self.assertTrue((self.tmp/'history-blocked/evidence.zip').is_file())

    def test_missing_recorded_inputs_produce_blocked_artifacts_without_runner(self):
        with mock.patch.object(endpoint, 'binary_identity', side_effect=AssertionError('must not build/run')):
            r = endpoint.run(example('recorded'), self.tmp/'missing', self.tmp/'data')
        self.assertEqual(r['state'], 'BLOCKED')
        self.assertIsNone(r['changed_choices'])
        self.assertFalse(r['v2_executed']); self.assertFalse(r['v3_executed'])
        for name in ('evidence.zip', 'result.json', 'metrics.csv', 'report.html'):
            self.assertTrue((self.tmp/'missing'/name).is_file())

    def test_native_lane_keeps_verified_receipt_without_cross_version_flag(self):
        # Real PXMS selection/freeze and baseline subprocesses; only the native
        # registry and paired transport are scripted. Actual stage engine proof
        # belongs to live acceptance, not this command-routing control.
        trace, metadata = self.observed_trace()
        data, policy = self.tmp/'native-data', 'phorvex-staging-demo/stage-bench-defense'
        pin = testkit.write_stage_pin(data, trace['source_revision'], policy, 'policy-uid')
        pin['study_engine_lane'] = 'native-stage-image'
        (data/'mathlab/stage.json').write_text(json.dumps(pin))
        directory = data/'mathlab/snapshots'/policy
        old = testkit.make_snapshot(directory, trace['source_revision'], 4, True, '1970-01-01T00:10:50Z')
        source = directory/(old+'.pxms'); raw = source.read_bytes(); n = struct.unpack('>I',raw[8:12])[0]
        header = json.loads(raw[12:12+n]); header.update(policyName='stage-bench-defense',policyUID='policy-uid')
        encoded = json.dumps(header).encode(); raw = raw[:8]+struct.pack('>I',len(encoded))+encoded+raw[12+n:]
        digest = hashlib.sha256(raw).hexdigest(); source.unlink(); (directory/(digest+'.pxms')).write_bytes(raw)
        trace['ticks'][0]['id'] = digest
        metadata['snapshot_digests'] = [digest]; metadata['bindings'][0]['snapshot_digest'] = digest
        metadata['scope']['image_digest'] = pin['brain']['image_digest']
        install(trace,metadata,data,'real normalizer fixture with explicit transport test cohort')
        engine = {'lane':'native-stage-image','candidate':pin['replay'],'base_local':pin['replay'],
                  'baseline_evidence':[{'path':'scripted registry receipt'}]}
        calls, activity = [], []
        original_run = subprocess.run
        def paired(command, **kwargs):
            if '--endpoint-study' not in command:
                return original_run(command, **kwargs)
            calls.append(command)
            output = Path(command[command.index('--out')+1])
            output.write_text(json.dumps({'state':'COMPLETE','mode':'PAIRED_BRAIN_REPLAY','evidence':'recorded',
                'baseline_exact_count':1,'snapshot_digests':[digest],'comparable_ticks':1,'ticks':[]}))
            return subprocess.CompletedProcess(command,0,'','')
        request = {**example('recorded'),'policy':policy,'ticks':1,'config':{'lookback':300}}
        with mock.patch.object(endpoint.stage_scope,'study_engine',return_value=engine), \
             mock.patch.object(endpoint.subprocess,'run',side_effect=paired):
            result = endpoint.run(request,self.tmp/'native-result',data,activity=activity.append)
        self.assertEqual(len(calls),1)
        self.assertNotIn('--allow-cross-version',calls[0])
        self.assertFalse(result['runner']['cross_version'])
        self.assertEqual(result['runner']['comparison_status'],'MATCHED_REPLAY')
        self.assertEqual(result['runner']['study_engine']['lane'],'native-stage-image')
        self.assertEqual(activity,['replay_started','replay_started'])
        for label in ('capture-control','base-local'):
            rows=[json.loads(line) for line in (self.tmp/'native-result'/(label+'.jsonl')).read_text().splitlines()]
            self.assertEqual(len(rows),1); self.assertTrue(rows[0]['baseline_check']['reproduced'])

    def test_nested_input_errors_are_rejected_before_queueing(self):
        for field,value in [('k','1'),('facts_known',1),('samples',[{'duration':'bad'}]),('gates',['ok',False]),('typo',1)]:
            req=example(); req['trace']['ticks'][0]['candidates'][0][field]=value
            with self.subTest(field=field), self.assertRaises(file_requests.RequestError):
                file_requests.parse(json.dumps(req))
        req=example();req['trace']['ticks'][0]['ledger']['moves'][0]['intervals'][0]['end']='later'
        with self.assertRaises(file_requests.RequestError): file_requests.parse(json.dumps(req))
        req=example();req['trace']['ticks'][0]['ledger']=None
        self.assertEqual(file_requests.parse(json.dumps(req))[0]['kind'],'endpoint')

    def test_unqualified_json_install_is_rejected_and_changed_manifest_fails_closed(self):
        trace = example()['trace']; trace['evidence'] = 'recorded'; trace['source_revision'] = 'a'*40
        source = self.tmp/'input.json'; source.write_text(json.dumps(trace))
        with self.assertRaisesRegex(ValueError, 'stage journal'):
            endpoint.install(source, self.tmp/'data', 'phorvex-staging-demo/demo-api-defense', 'self-declared producer')
        installed = self.tmp/'data/mathlab/endpoint-traces/phorvex-staging-demo/demo-api-defense.json'
        installed.parent.mkdir(parents=True)
        installed.write_text(json.dumps(trace))
        installed.with_suffix('.manifest.json').write_text(json.dumps({'policy': example('recorded')['policy'],
                                                                    'trace_sha256': endpoint.sha(installed)}))
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

    @unittest.skipUnless((HERE.parent/'endpointv3/BUILD.json').is_file(), 'build endpointv3/build.py for Go integration tests')
    def test_custom_study_settings_reach_real_shared_go_kernel(self):
        req = example(); before = copy.deepcopy(req)
        req['study'] = {'slo_target': .9, 'window': 600, 'worth_threshold': 20}
        req['config']['lookback'] = 600
        result = endpoint.run(req, self.tmp/'custom-kernel')
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual(result['comparable_ticks'], 64)
        self.assertAlmostEqual(result['ticks'][0]['budget']['R'], 240)
        self.assertEqual(result['study']['requested'], req['study'])
        executed = json.loads((self.tmp/'custom-kernel/trace.json').read_text())
        self.assertEqual(req['trace'], before['trace'])
        for original, tick in zip(req['trace']['ticks'], executed['ticks']):
            self.assertEqual(tick['ledger'], original['ledger'])
            self.assertEqual(tick['candidates'][0]['facts'], original['candidates'][0]['facts'])
            self.assertEqual(tick['candidates'][0]['worth_threshold'], 20)
        self.assertTrue(all(not tick[arm]['pick'] for tick in result['ticks'] for arm in ('v2', 'v3')))


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
        self.assertEqual(len(self.fake.documents()), 7)  # Includes the separate runtime validation report.
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
            self.assertIsNone(endpoint.legacy_request(prompt+' changed algorithm', 'phorvex-staging-demo/demo-api-defense', 64))


if __name__ == '__main__': unittest.main()
