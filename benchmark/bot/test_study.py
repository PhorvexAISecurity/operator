"""Reference formulas, evidence semantics, reproducibility and actual bot dispatch."""
import copy
import json
import math
from pathlib import Path
import random
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import file_requests
import study
import study_math as formulas
import study_schema as schema
import study_data
import test_bot as kit
import test_uploads as uploads


def example(name='history-synthetic'):
    return json.loads((HERE / ('templates/study-%s.json' % name)).read_text())


class FormulaTest(unittest.TestCase):
    def test_cost_examples_units_and_censored_bounds(self):
        for cls, prior, expected in [('stateless', 43, 159), ('gpu', 130, 420),
                                     ('stateful', 141, 453), ('unknown', 400, 1230)]:
            c = {'action': 'rotate', 'cost': {'class': cls, 'k': 1, 'samples': [], 'overdue': 0}}
            out = formulas.price(c, {'kind': 'endpoint-v1', 'delta': 30}, None)
            self.assertEqual((out['rho'], out['flow'], out['norm']), (expected, prior, expected-prior))
        mid, upper, pf = formulas.duration_estimate([100], 43, 0)
        self.assertEqual((mid, upper), (43, 100))
        self.assertAlmostEqual(pf, .95)
        self.assertEqual(formulas.confidence_rank(29), 29)
        mid, upper, pf = formulas.duration_estimate([10]*59, 43, 0)
        self.assertEqual((mid, upper), (10, 10))
        self.assertAlmostEqual(pf, 1-.05**(1/59))
        self.assertLess(pf, .05)
        self.assertTrue(math.isinf(formulas.duration_estimate([None], 43, 1)[1]))
        self.assertTrue(math.isinf(formulas.duration_estimate([10]*28+[None], 43, 1)[1]))
        c['cost'].update(samples=[None], overdue=1, k=0)
        self.assertEqual(formulas.price(c, {'kind': 'endpoint-v1', 'delta': 30}, None)['rho'], 0)

    def test_quarantine_hold_is_not_a_standard_rotate(self):
        c = {'action': 'quarantine', 'cost': {'class': 'stateless', 'k': 1, 'samples': [],
                                            'overdue': 0, 'sample_action': 'rotate', 'hold_cap': 1800}}
        out = formulas.price(c, {'kind': 'endpoint-v1', 'delta': 30}, {'r': 1000, 'used': 0, 'held': 0})
        self.assertEqual(out['rho'], 1000)
        self.assertEqual(out['hold'], 841)
        self.assertEqual(out['flow'], 884)
        self.assertEqual(out['c'], 1000)
        self.assertEqual(formulas.price(c, {'kind': 'endpoint-v1', 'delta': 30},
                                       {'r': 159, 'used': 0, 'held': 0})['refusal'], 'BUDGET')

    def test_history_weighted_ties_and_epsilon_zero_are_exact(self):
        config = {'kind': 'history', 'epsilon': 0, 'score_scale': .1}
        p, _ = formulas.distribution([10, 10, 2], config, [1, 2, 100])
        self.assertEqual(p, [1/3, 2/3, 0])
        # No nonmaximal mass when floating-point subtraction would round L to 0.
        p, _ = formulas.distribution([10, 2], config, [1, 1])
        self.assertEqual(p, [1, 0])

    def test_regret_bounds_for_random_scales_weights_and_scores(self):
        rng = random.Random(42)
        for kind in ('history', 'entropy'):
            for _ in range(150):
                scores = [rng.uniform(-100, 100) for i in range(5)]
                weights = [10**rng.uniform(-6, 6) for i in scores]
                epsilon = rng.choice([0, .5, 20])
                config = {'kind': kind, 'epsilon': epsilon, 'score_scale': 10**rng.uniform(-5, 5), 'tau': 1000}
                p, diagnostics = formulas.distribution(scores, config, weights)
                self.assertAlmostEqual(sum(p), 1)
                self.assertTrue(all(0 <= x <= 1 for x in p))
                self.assertLessEqual(sum(x*(max(scores)-j) for x, j in zip(p, scores)), epsilon+1e-10)
        p, _ = formulas.distribution([10, 2], {'kind': 'history', 'epsilon': .5, 'score_scale': 100}, [1, 1000000])
        self.assertLessEqual(p[1], .0625+1e-12)


class StudyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='study-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_study(self, request, name='run', **kwargs):
        root = self.tmp/name
        result = study.run(request, root, **kwargs)
        candidates = root/'candidates.jsonl'
        rows = [json.loads(line) for line in candidates.read_text().splitlines()] if candidates.exists() else []
        return result, rows

    def test_all_arms_seeds_real_exports_and_reproducibility(self):
        request = example()
        original = copy.deepcopy(request)
        result, rows = self.run_study(request)
        again, other = self.run_study(request, 'repeat')
        self.assertEqual(request, original)
        self.assertEqual(result, again)
        self.assertEqual(rows, other)
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual(len(result['metrics']), 12)
        self.assertEqual(len(rows), 12*3*4*3)
        self.assertEqual(result['evidence'], 'synthetic')
        self.assertIsNone(result['verified_coverage']['value'])
        self.assertIsNone(result['realized_cost']['value'])
        for name in ('report.html', 'candidates.csv', 'metrics.csv', 'ticks.csv', 'manifest.json', 'evidence.zip'):
            self.assertTrue((self.tmp/'run'/name).is_file(), name)
        # A reordered arm list must not change any arm's samples or history.
        request['arms'].reverse()
        _, reordered = self.run_study(request, 'reordered')
        key = lambda r: (r['arm_id'], r['seed'], r['tick_id'], r['candidate_id'])
        self.assertEqual(sorted(rows, key=key), sorted(reordered, key=key))

    def test_rollover_ack_semantics_and_identity_levels(self):
        h = study.History(10)
        event = {'kind': 'opportunity', 'workload_uid': 'w', 'pod_uid': 'old', 'generation': 1,
                 'action': 'rotate', 'tick_id': 't', 'at': 1}
        h.add(event); h.add(event)  # stale retry must not inflate F
        config = schema.validate(example())['arms'][-1]['selector']
        tick = {'at': 2, 'workload_uid': 'w'}
        _, weights = h.weights(tick, event, config)
        self.assertEqual((weights['F_pair'], weights['S_pair']), (1, 0))
        h.add({**event, 'kind': 'execution_start', 'at': 3})
        _, weights = h.weights(tick, event, config)
        self.assertEqual((weights['F_pair'], weights['S_pair']), (1, 1))
        _, replaced = h.weights(tick, {**event, 'pod_uid': 'new', 'generation': 2}, config)
        self.assertEqual((replaced['F_pair'], replaced['S_pair'], replaced['F_action'], replaced['S_action']), (0, 0, 1, 1))
        h.advance(13)
        _, expired = h.weights({'at': 13, 'workload_uid': 'w'}, event, config)
        self.assertEqual((expired['F_pair'], expired['S_pair']), (0, 0))

    def test_no_ack_is_not_success_and_no_verification_credit(self):
        req = example()
        for tick in req['trace']['ticks']:
            for c in tick['candidates']:
                c['simulated_start'] = False
        result, rows = self.run_study(req)
        history = [r for r in rows if r['arm_id'] == 'history']
        self.assertTrue(all(r['S_pair'] == 0 for r in history))
        self.assertTrue(any(r['F_pair'] > 1 for r in history))
        self.assertIsNone(result['verified_coverage']['value'])

    def test_observed_history_does_not_learn_from_counterfactual_draws(self):
        req = example(); req['history']['mode'] = 'observed'
        c = req['trace']['ticks'][0]['candidates'][1]
        event = {'id': 'opp', 'at': 99990, 'kind': 'opportunity', 'tick_id': 'observed-tick',
                 'workload_uid': 'synthetic-workload', 'pod_uid': c['pod_uid'], 'generation': 1, 'action': 'rotate'}
        req['trace']['events'] = [event, {**event, 'id': 'start', 'at': 99991,
                                        'kind': 'execution_start', 'opportunity_id': 'opp'}]
        _, rows = self.run_study(req)
        history = [r for r in rows if r['arm_id'] == 'history']
        self.assertTrue(all(r['S_pair'] == (1 if r['candidate_id'] == 'pair-1' else 0) for r in history))

    def test_missing_history_falls_back_and_missing_budget_invalidates_tick(self):
        req = example(); req['trace']['history_complete_from'] = None
        result, rows = self.run_study(req)
        self.assertEqual(result['state'], 'PARTIAL')
        history = [r for r in rows if r['arm_id'] == 'history']
        self.assertTrue(all(r['probability'] == (1 if r['candidate_id'] == 'pair-0' else 0) for r in history))
        self.assertTrue(all(not r['history_available'] and 'S_pair' not in r for r in history))
        self.assertIn('missing history store or incomplete lookback', result['data_gaps'])
        req = example()
        req['trace']['ticks'][0].pop('budget')
        result, rows = self.run_study(req, 'missing-budget')
        self.assertEqual(result['state'], 'PARTIAL')
        self.assertTrue(all(not r['selected'] for r in rows if r['tick_id'] == 'tick-0'))
        self.assertEqual(sum(m['needs_data'] for m in result['metrics']), 12)

    def test_noop_mandatory_guard_and_unauthorized_randomization(self):
        req = example()
        ticks = req['trace']['ticks']
        ticks[0]['selection'] = 'noop'
        ticks[1].update(selection='mandatory', mandatory_candidate='pair-2')
        ticks[2]['candidates'][0]['guard_admitted'] = False
        ticks[3]['randomization_authorized'] = False
        result, rows = self.run_study(req)
        for row in rows:
            if row['tick_id'] == 'tick-0':
                self.assertFalse(row['selected'])
            if row['tick_id'] == 'tick-1':
                self.assertEqual(row['selected'], row['candidate_id'] == 'pair-2')
            if row['tick_id'] == 'tick-2' and row['candidate_id'] == 'pair-0':
                self.assertEqual(row['probability'], 0)
            if row['tick_id'] == 'tick-3':
                self.assertEqual(row['selected'], row['candidate_id'] == 'pair-0')
        self.assertEqual(result['state'], 'PARTIAL')

    def test_missing_recorded_dataset_returns_actionable_artifacts(self):
        result, rows = self.run_study(example('history-recorded'), data_dir=self.tmp)
        self.assertEqual(result['state'], 'NEEDS_DATA')
        self.assertIn('normalized recorded trace', result['reason'])
        self.assertFalse(rows)
        self.assertTrue((self.tmp/'run'/'evidence.zip').exists())

    def test_cancellation_and_report_html_escaping(self):
        req = example(); req['title'] = '<script>bad()</script>'
        result, rows = self.run_study(req, cancelled=lambda: True)
        self.assertEqual(result['state'], 'CANCELLED')
        self.assertFalse(rows)
        self.assertNotIn('<script>', (self.tmp/'run'/'report.html').read_text())

    def test_existing_output_is_never_overwritten_or_archived(self):
        root = self.tmp/'run'; root.mkdir()
        (root/'unrelated.txt').write_text('preserve')
        with self.assertRaisesRegex(schema.StudyError, 'empty'):
            study.run(example(), root)
        self.assertEqual((root/'unrelated.txt').read_text(), 'preserve')
        self.assertEqual(len(list(root.iterdir())), 1)

    def test_recorded_trace_import_load_and_freeze(self):
        req = example('history-recorded')
        trace = example()['trace']
        trace.update(evidence='recorded', source_revision='a'*40)
        source = self.tmp/'trace.json'; source.write_text(json.dumps(trace))
        metadata = study_data.install(source, self.tmp/'data', req['policy'])
        installed = Path(metadata['path'])
        self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
        result, rows = self.run_study(req, data_dir=self.tmp/'data')
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual(result['evidence'], 'recorded')
        frozen = json.loads((self.tmp/'run'/'resolved-request.json').read_text())['trace']
        installed.write_text('{}')
        self.assertEqual(frozen, trace)
        self.assertTrue(all(r.get('S_pair', 0) == 0 for r in rows))

    def test_verified_fact_novelty_and_anticipation_are_separate_from_execution(self):
        h = study.History(100)
        tick = {'at': 85, 'workload_uid': 'w'}
        c = {'pod_uid': 'p', 'generation': 1, 'action': 'rotate', 'facts': [
            {'id': 'f:gen1', 'weight': 10, 'origin': 0, 'deadline': 100, 'required': True, 'validated': True}]}
        config = schema.validate(example())['arms'][-1]['selector']
        config.update(eta_pair=0, eta_action=0, eta_fact=1, q_ref=1, x0=.7, a0=0)
        weight, row = h.weights(tick, c, config)
        self.assertAlmostEqual(row['Q'], 5)
        self.assertAlmostEqual(weight, 6)
        h.add({'kind': 'verified', 'at': 80, 'workload_uid': 'w', 'fact_id': 'f:gen1'})
        weight, row = h.weights(tick, c, config)
        self.assertAlmostEqual(row['Q'], 2.5)
        h.add({'kind': 'verified', 'at': 81, 'workload_uid': 'another', 'fact_id': 'f:gen1'})
        self.assertAlmostEqual(h.weights(tick, c, config)[1]['Q'], 2.5)
        h.advance(180)
        self.assertAlmostEqual(h.weights(tick, c, config)[1]['Q'], 5)

    def test_schema_rejects_ambiguous_unsafe_and_unbounded_inputs(self):
        invalid = []
        req = example(); req['seeds'] = [True]; invalid.append(req)
        req = example(); req['command'] = 'run anything'; invalid.append(req)
        req = example(); req['trace']['ticks'].append(req['trace']['ticks'][0]); invalid.append(req)
        req = example(); req['trace']['ticks'][0]['candidates'][0]['value'] = float('nan'); invalid.append(req)
        req = example(); req['trace']['evidence'] = 'recorded'; invalid.append(req)
        req = example(); req['arms'][3]['selector']['x0'] = 1; invalid.append(req)
        req = example('history-recorded'); req['dataset'] = '../../secrets'; invalid.append(req)
        req = example(); req['trace']['ticks'][0]['candidates'][0].pop('simulated_start'); invalid.append(req)
        for req in invalid:
            with self.subTest(req=str(req)[:80]), self.assertRaises(ValueError):
                schema.validate(req)
        for text in ('{"schema":1,"schema":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(schema.StudyError):
                schema.strict_json(text)


class StudyUploadTest(unittest.TestCase):
    setUp = kit.BotTest.setUp
    bot = kit.BotTest.bot
    history = kit.BotTest.history
    upload = uploads.UploadTest.upload

    def test_json_upload_runs_without_model_dashboard_or_go_and_sends_results(self):
        def forbidden(*args, **kwargs):
            self.fail('a declarative study must not call the LLM')
        bot = self.bot(openai=forbidden)
        text = json.dumps(example())
        self.upload(bot, text, filename='study.json', caption='/validate')
        self.assertEqual(bot.queue, [])
        self.upload(bot, text, filename='study.json')
        self.assertEqual(len(bot.queue), 1)
        self.assertTrue(bot.run_next())
        self.assertEqual([r['kind'] for r in self.history()], ['study', 'batch'])
        self.assertTrue(all(r['state'] == 'DONE' for r in self.history()))
        self.assertEqual(len(self.fake.documents()), 6)
        self.assertTrue(any('evidence=synthetic' in t for t in self.fake.texts()))

    def test_missing_recorded_data_is_not_a_planner_failure(self):
        bot = self.bot(MATHLAB_DATA_DIR=str(self.tmp/'absent'))
        self.upload(bot, json.dumps(example('history-recorded')), filename='study.json')
        bot.run_next()
        self.assertEqual([r['state'] for r in self.history()], ['NEEDS_DATA', 'NEEDS_DATA'])
        self.assertTrue(any('legacy snapshots' in t for t in self.fake.texts()))


if __name__ == '__main__':
    unittest.main()
