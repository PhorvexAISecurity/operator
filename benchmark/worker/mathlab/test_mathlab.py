import json
import math
import struct
import tempfile
import unittest
from pathlib import Path

from mathlab import analysis, experiment, exports, registry, stats
from mathlab.common import write_json

DIGEST_A = 'a' * 64
DIGEST_B = 'b' * 64
DIGEST_C = 'c' * 64


def funnel(pairs=4, admitted=2, veto=None, backed=1, useful=1, selected=1):
    veto = veto or {'G4-capability': 1, 'G9-chi-ceiling': pairs - admitted - 1}
    return {'assets': 2, 'attack_backed_assets': backed, 'enabled_pairs': pairs, 'first_veto_by_gate': veto, 'admitted': admitted,
            'scored': admitted, 'positive_gain': admitted, 'selected': selected, 'noop_by_reason': {}, 'complete_feasible_evidence': True,
            'attack_backed_assets_with_positive_gain_feasible': useful, 'g9_categories': {'G9_PASS': admitted},
            'unassessed_gate_pairs': 3, 'applicable_gate_pairs': 30}


def line(digest, arm, selected_set, status='OK', reproduced=True, objective=1.0, covered=2.0, fun=None):
    decisions = [{'asset': 'vllm/a', 'action': 'rotate', 'selected': bool(selected_set), 'attack_backed': True,
                  'common_weight_covered': covered if selected_set else 0, 'expected_cost': .3, 'noop_reason': '' if selected_set else 'FEASIBLE_NONPOSITIVE_GAIN'},
                 {'asset': 'vllm/b', 'action': 'noop', 'selected': False, 'attack_backed': False, 'noop_reason': 'NO_FEASIBLE_CANDIDATE'}]
    out = {'snapshot': {'snapshot_digest': digest, 'captured_at': '2026-10-09T00:00:0%dZ' % ord(digest[0])}, 'arm_id': arm, 'status': status,
           'selected_set': selected_set, 'estimated_objective_m_p18': objective, 'decisions': decisions, 'funnel': fun or funnel(),
           'replay_seconds': .01, 'arm_max_moves_per_tick': 1, 'dispatch': [{'asset': 'vllm/a', 'selected': True, 'dry_run': True}]}
    if arm == 'control':
        out['baseline_check'] = {'reproduced': reproduced}
    return out


def ctx(arms=('control', 'trial')):
    return {'experiment_id': 'e', 'arms': list(arms), 'control': arms[0], 'parameter_id': 'P-FEA-006', 'policy': 'vllm/vllm-defense',
            'seed': 7, 'comparison_status': 'MATCHED_REPLAY',
            'arm_values': {a: {'value': None, 'label': a} for a in arms}}


class StatsTest(unittest.TestCase):
    def test_wilson_known_values_and_missing_denominator(self):
        lo, hi = stats.wilson(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.27753, places=4)
        lo, hi = stats.wilson(10, 10)
        self.assertEqual(hi, 1.0)
        self.assertIsNone(stats.wilson(0, 0))
        with self.assertRaises(ValueError):
            stats.wilson(3, 2)

    def test_bootstrap_is_seeded_and_needs_two_units(self):
        values = [1, 2, 3, 4, 5, 6]
        self.assertEqual(stats.bootstrap_mean(values, seed=1), stats.bootstrap_mean(values, seed=1))
        self.assertIsNone(stats.bootstrap_mean([3]))
        self.assertIsNone(stats.bootstrap_ratio([(1, 0), (2, 0)]))


class AnalysisTest(unittest.TestCase):
    def test_only_matched_ticks_compare_and_unobservable_metrics_are_unavailable(self):
        lines = [line(DIGEST_A, 'control', ['vllm/a:rotate']), line(DIGEST_A, 'trial', ['vllm/a:quarantine']),
                 line(DIGEST_B, 'control', ['vllm/a:rotate']), line(DIGEST_B, 'trial', ['vllm/a:rotate']),
                 line(DIGEST_C, 'control', ['vllm/a:rotate'], reproduced=False), line(DIGEST_C, 'trial', [])]
        rows, plots, population = analysis.analyze(lines, ctx())
        self.assertEqual(population['control_eligible'], 2)
        self.assertEqual(population['control_exclusions'], {'control-not-reproduced': 1})
        p21 = next(r for r in rows if r['metric_id'] == 'M-P21' and r['arm_id'] == 'trial' and r['comparison'] == 'ARM_LEVEL')
        self.assertEqual((p21['numerator'], p21['denominator'], p21['value']), (1, 2, .5))
        for mid in analysis.UNAVAILABLE_IN_REPLAY:
            row = next(r for r in rows if r['metric_id'] == mid and r['arm_id'] == 'trial')
            self.assertEqual(row['data_status'], 'UNAVAILABLE')
            self.assertIsNone(row['value'])
        self.assertIn('M-P21', plots['dose_response'])

    def test_zero_denominator_is_unavailable_not_zero(self):
        lines = [line(DIGEST_A, 'control', ['vllm/a:rotate'], fun=funnel(backed=0, useful=0)),
                 line(DIGEST_A, 'trial', ['vllm/a:rotate'], fun=funnel(backed=0, useful=0))]
        rows, _, _ = analysis.analyze(lines, ctx())
        p22 = next(r for r in rows if r['metric_id'] == 'M-P22' and r['arm_id'] == 'control')
        self.assertEqual(p22['data_status'], 'UNAVAILABLE')
        self.assertIsNone(p22['value'])
        self.assertEqual(p22['reason'], 'ZERO_DENOMINATOR')

    def test_first_veto_shares_and_admission_partition_the_enabled_pairs(self):
        lines = [line(DIGEST_A, 'control', ['vllm/a:rotate']), line(DIGEST_A, 'trial', ['vllm/a:rotate'])]
        rows, plots, _ = analysis.analyze(lines, ctx())
        shares = [r for r in rows if r['metric_id'] == 'M-P03' and r['arm_id'] == 'control']
        vetoed = sum(r['numerator'] for r in shares)
        stages = {s['stage']: s['count'] for s in plots['funnel']['control']}
        self.assertEqual(vetoed + stages['admitted'], stages['enabled pairs'])

    def test_dispatch_funnel_is_production_record_of_control_only(self):
        lines = [line(DIGEST_A, 'control', ['vllm/a:rotate']), line(DIGEST_A, 'trial', ['vllm/a:rotate'])]
        rows, _, _ = analysis.analyze(lines, ctx())
        dispatch = [r for r in rows if r['metric_id'] == 'M-P24']
        self.assertTrue(dispatch and all(r['arm_id'] == 'control' and r['comparison'] == 'PRODUCTION_RECORD' for r in dispatch))
        self.assertIn('suppressed: dry-run', {r['dimension'] for r in dispatch})


def write_fake_snapshot(directory, digest, git_sha='sha-1', mode='legacy-runtime-lambda-v1'):
    header = json.dumps({'schema': 'math-lab.snapshot.v1', 'capturedAt': '2026-10-09T00:00:00Z', 'gitSHA': git_sha, 'namespace': 'vllm',
                         'policyName': 'vllm-defense', 'policyUID': 'u', 'economicsMode': mode, 'processConfigHash': 'p',
                         'parameterManifestHash': 'm', 'policyOverridesHash': 'o', 'finalized': True}).encode()
    (Path(directory) / (digest + '.pxms')).write_bytes(b'PXMLSNP1' + struct.pack('>I', len(header)) + header + b'payload')


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = self.tmp.name
        corpus = Path(self.data) / 'mathlab' / 'snapshots' / 'vllm' / 'vllm-defense'
        corpus.mkdir(parents=True)
        write_fake_snapshot(corpus, DIGEST_A)
        self.binary = {'git_sha': 'sha-1', 'image_digest': 'sha256:x', 'binary_sha256': 'y', 'path': '/nonexistent'}

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, **kw):
        req = {'schema_version': 'math-lab.experiment.v1', 'mode': 'REPLAY', 'parameter_id': 'P-FEA-006', 'namespace': 'vllm',
               'policy': 'vllm-defense', 'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}, {'arm_id': 't', 'value': 1.5}]}
        req.update(kw)
        return req

    def codes(self, req, binary=True):
        return {e['error_code'] for e in experiment.preflight(self.data, req, self.binary if binary else None)['errors']}

    def test_valid_request_passes_with_protected_warning(self):
        pf = experiment.preflight(self.data, self.request(), self.binary)
        self.assertEqual(pf['status'], 'PASS', pf['errors'])
        self.assertIn('PROTECTED_PARAMETER', {c['id'] for c in pf['checks']})

    def test_invalid_values_and_parameters_are_refused(self):
        self.assertIn('NON_FINITE', self.codes(self.request(arms=[{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}, {'arm_id': 't', 'value': float('nan')}])))
        self.assertIn('OUT_OF_DOMAIN', self.codes(self.request(arms=[{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}, {'arm_id': 't', 'value': -1}])))
        self.assertIn('NOT_AN_EXPERIMENT_KNOB', self.codes(self.request(parameter_id='P-FEA-001')))
        self.assertIn('UNKNOWN_PARAMETER', self.codes(self.request(parameter_id='P-XXX-999')))
        self.assertIn('MODE_UNSUPPORTED', self.codes(self.request(mode='SANDBOX')))
        self.assertIn('CONTROL_ARM', self.codes(self.request(arms=[{'arm_id': 'a', 'value': 1}, {'arm_id': 'b', 'value': 2}])))
        self.assertIn('DUPLICATE_VALUE', self.codes(self.request(arms=[{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}, {'arm_id': 'a', 'value': 2}, {'arm_id': 'b', 'value': 2.0}])))

    def test_version_mismatch_and_missing_binary_block_the_run(self):
        self.binary['git_sha'] = 'sha-2'
        self.assertIn('VERSION_MISMATCH', self.codes(self.request()))
        self.assertIn('REPLAY_BINARY_UNAVAILABLE', self.codes(self.request(), binary=False))

    def test_beta_on_cost_preferences_policy_is_a_mode_conflict(self):
        corpus = Path(self.data) / 'mathlab' / 'snapshots' / 'vllm' / 'vllm-defense'
        write_fake_snapshot(corpus, DIGEST_B, mode='independent-cost-preferences-v1')
        req = self.request(parameter_id='P-OBJ-003', arms=[{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'}, {'arm_id': 't', 'value': 0.5}])
        self.assertIn('MODE_CONFLICT', self.codes(req))


class RegistryOverlayTest(unittest.TestCase):
    def test_configured_versus_effective_and_read_only_classes(self):
        reg = registry.load_registry()
        inspection = {'snapshot_digest': DIGEST_A, 'configured_spec': {'slo': {'minAvailableReplicas': 0, 'costCeiling': '1.2'}},
                      'effective': {'spec.slo.minAvailableReplicas': 1, 'spec.slo.costCeiling': 1.2}, 'learned': {'lambdaRuntime': 0.0},
                      'header': {'processConfig': {'gpu-envelope-max': '0.2925'}}}
        merged = {i['param_id']: i for i in registry.overlay(reg, inspection)['items']}
        floor = merged['P-FEA-001']
        self.assertEqual((floor['configured_value'], floor['effective_value'], floor['effective_status']), (0, 1, 'OBSERVED'))
        knobs = [i for i in reg['items'] if i['control'] == registry.EXPERIMENT_KNOB]
        self.assertEqual(sorted(i['param_id'] for i in knobs), ['P-FEA-006', 'P-OBJ-003'])
        for item in reg['items']:
            if item['class'] in ('LEARNED_STATE', 'OBSERVED_INPUT', 'INTERNAL_CONSTANT', 'DERIVED_RUNTIME', 'REPORT_ONLY'):
                self.assertNotEqual(item['control'], registry.EXPERIMENT_KNOB, item['param_id'])


class ExportSafetyTest(unittest.TestCase):
    def test_cells_are_neutralized_and_missing_stays_empty(self):
        self.assertEqual(exports.safe('=HYPERLINK("x")'), '\'=HYPERLINK("x")')
        self.assertEqual(exports.safe(None), '')
        self.assertEqual(exports.safe(float('nan')), 'NaN')
        self.assertEqual(exports.safe(0), 0)


if __name__ == '__main__':
    unittest.main()


class StreamingAndSyncTest(unittest.TestCase):
    def test_stream_replay_writes_rows_and_returns_compact_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = line(DIGEST_A, 'control', ['vllm/a:rotate'])
            raw['gates'] = [{'asset': 'vllm/a', 'action': 'rotate', 'gate_id': 'G9-chi-ceiling', 'actual_status': 'PASS'}] * 3
            raw['costs'] = [{'asset': 'vllm/a', 'action': 'rotate', 'c_hi': 1.1}]
            raw['candidates'] = [{'asset': 'vllm/a', 'action': '=cmd()'}]
            (root / 'replay.jsonl').write_text(json.dumps(raw) + '\n\n')
            compact = exports.stream_replay(root, 'e', root / 'replay.jsonl')
            self.assertEqual(len(compact), 1)
            self.assertFalse(any(k in compact[0] for k in ('gates', 'costs', 'candidates')))
            self.assertIn('decisions', compact[0])
            self.assertEqual(len((root / 'candidate_gate_trace.csv').read_text().strip().splitlines()), 4)
            self.assertIn("'=cmd()", (root / 'candidates.csv').read_text())

    def test_sync_resumes_after_the_newest_held_tick(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / 'mathlab' / 'snapshots' / 'vllm' / 'vllm-defense'
            corpus.mkdir(parents=True)
            write_fake_snapshot(corpus, DIGEST_A)

            class FakeConsole:
                def __init__(self): self.paths = []
                def request(self, path):
                    self.paths.append(path)
                    return {'entries': [{'digest': DIGEST_A}]}
            console = FakeConsole()
            from mathlab import snapshots
            record = snapshots.sync(tmp, 'vllm', 'vllm-defense', console)
            self.assertIn('since=2026-10-09T00%3A00%3A00Z', console.paths[0])
            self.assertEqual((record['already_held'], record['downloaded']), (1, 0))
