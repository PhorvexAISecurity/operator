from __future__ import annotations

import copy
import io
import json
import shutil
import unittest
from contextlib import contextmanager, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from test_operations import SOURCE_ROOT, sandbox, workflow as w
import attacks

PINS = {'image': 'phorvex:test', 'digest': 'sha256:test', 'source_sha': 'abcdef012345'}


@contextmanager
def fixture(campaign=False):
    with sandbox() as value:
        root = w.ROOT
        shutil.copytree(SOURCE_ROOT / 'attacks', root / 'attacks')
        if campaign:
            owner = root / 'campaigns/test/rounds/round-1'
            owner.mkdir(parents=True)
            status = {'campaign_id': 'test', 'roles': {'campaign_lead': 'verifier', 'coordinator': 'coordinator'},
                      'pins': {'image': PINS['image'], 'digest': PINS['digest'], 'embedded_git_sha': PINS['source_sha']},
                      'rounds': [{'id': 'round-1'}]}
            w.write_yaml(owner.parent.parent / 'STATUS.yaml', status)
        else:
            owner = w.create_fix_record('T1-M001', ['M-1'], 'Test attack integration')
            status = w.load_yaml(owner / 'STATUS.yaml')
            status['roles'].update(live_verifier='verifier', coordinator='coordinator')
            status['deployment'] = {'image': PINS['image'], 'digest': PINS['digest'], 'git_sha': PINS['source_sha']}
            w.write_yaml(owner / 'STATUS.yaml', status)
        evidence = owner / 'evidence'; evidence.mkdir(exist_ok=True)
        (evidence / 'witness.txt').write_text('fixture observations\n')
        _, cases = attacks.catalogue(root)
        capabilities = {key: {'available': True, 'evidence': 'witness.txt'} for case in cases.values() for key in case['requires']}
        capabilities.update(cluster_read=True, operator_ready=True)
        snapshot = {'context': 'fixture', 'namespaces': ['tenant'], 'observed_at': attacks.now(),
                    'pins': PINS.copy(), 'capabilities': capabilities, 'pin_evidence': 'witness.txt'}
        w.write_yaml(evidence / 'preflight.yaml', snapshot)
        w.write_yaml(evidence / 'criteria.yaml', {'targets': [{'namespace': 'tenant', 'workload': 'canary'}],
                     'duration_seconds': 60, 'request_limit': 5, 'success': 'zero hostile access; benign >=99%',
                     'abort': 'stop at first benign failure', 'cleanup': 'delete owned fixture; confirm baseline'})
        yield root, owner, snapshot


def cli(*argv):
    args = w.build_parser().parse_args(['attacks', *map(str, argv)])
    with redirect_stdout(io.StringIO()):
        return args.func(args)


def plan(owner, case='A1', *extra):
    scope = ['--campaign', 'test'] if 'campaigns' in owner.parts else ['--fix', 'T1-M001']
    return cli('plan', *scope, '--case', case, '--by', 'coordinator',
               '--preflight', owner / 'evidence/preflight.yaml', '--permission', 'attack',
               '--approval-ref', 'fixture:authorized-scope', '--criteria-file', 'evidence/criteria.yaml', *extra)


def observation(owner, case='A1', result='PASS'):
    selected = next(c for c in attacks.load(owner / 'attack-plan.yaml')['cases'] if c['id'] == case)
    return {'case': case, 'result': result, 'defense_outcome': selected['expected_defense'],
            'pins': PINS.copy(), 'signal_source': 'detector', 'started_at': '2026-09-07T00:00:00Z',
            'ended_at': '2026-09-07T00:00:10Z', 'requests_sent': 2,
            'stages': dict.fromkeys(selected['required_stages'], 'PASS'), 'findings': [],
            'artifacts': [{'path': 'witness.txt', 'command': 'fixture: collect measured stages'}]}


def record(owner, obs, by='verifier'):
    w.write_yaml(owner / 'evidence/observation.yaml', obs)
    return cli('record', '--plan', (owner / 'attack-plan.yaml').relative_to(w.ROOT),
               '--case', obs['case'], '--observation', owner / 'evidence/observation.yaml', '--by', by)


class AttackIntegrationTests(unittest.TestCase):
    def test_catalogue_and_aliases(self):
        self.assertEqual(attacks.validate_catalogue(SOURCE_ROOT), [])
        data, cases = attacks.catalogue(SOURCE_ROOT)
        self.assertEqual(len(cases), 67)
        self.assertEqual(attacks.resolve(data, cases, 'G2'), 'B4')
        with self.assertRaises(ValueError): attacks.resolve(data, cases, 'G3')
        self.assertTrue(all('attacker_goal' in c['required_stages'] for c in cases.values() if 'defense' in c['claims']))

    def test_missing_capability_is_blocked_not_silently_excluded(self):
        with fixture() as (root, owner, snapshot):
            snapshot['capabilities'] = {'cluster_read': True, 'operator_ready': True}
            w.write_yaml(owner / 'evidence/preflight.yaml', snapshot)
            self.assertEqual(plan(owner), 0)
            self.assertTrue(attacks.load(owner / 'attack-plan.yaml')['cases'][0]['blocked_by'])
            self.assertEqual(record(owner, observation(owner)), 1)
            self.assertTrue(attacks.gate_errors(root, owner))

    def test_wrong_pin_or_absent_scope_rejected(self):
        with fixture() as (_, owner, snapshot):
            self.assertEqual(plan(owner, 'A1', '--approval-ref', ''), 1)
            snapshot['pins']['digest'] = 'sha256:other'
            w.write_yaml(owner / 'evidence/preflight.yaml', snapshot)
            self.assertEqual(plan(owner), 1)
            self.assertFalse((owner / 'attack-plan.yaml').exists())

    def test_doctor_resolves_campaign_evidence_from_its_round(self):
        with sandbox():
            root = w.ROOT
            args = w.build_parser().parse_args([
                'new-campaign', 'Check evidence ownership', '--id', '2026-09-07-evidence-root',
                '--approval-ref', 'fixture:scope', '--environment', 'fixture',
                '--permission', 'read-only', '--duration-ceiling', '1m', '--cost-ceiling', 'zero',
                '--campaign-lead', 'verifier', '--coordinator', 'coordinator'])
            self.assertEqual(args.func(args), 0)
            owner = root / 'campaigns/2026-09-07-evidence-root/rounds/round-1'
            artifact = owner / 'evidence/probe.txt'
            artifact.write_text('retained round observation')
            attacks.manifest_record(w.__dict__, owner, artifact, 'verifier', 'fixture read',
                                    'campaign', '2026-09-07-evidence-root')
            output = io.StringIO()
            with redirect_stdout(output):
                args = w.build_parser().parse_args(['doctor'])
                args.func(args)
            self.assertNotIn('missing artifact evidence/probe.txt', output.getvalue())
            artifact.write_text('changed observation')
            output = io.StringIO()
            with redirect_stdout(output):
                args.func(args)
            self.assertIn('evidence/manifest.yaml: hash mismatch', output.getvalue())

    def test_targets_cannot_escape_preflight_scope(self):
        with fixture() as (_, owner, _):
            path = owner / 'evidence/criteria.yaml'
            criteria = attacks.load(path)
            criteria['targets'][0]['namespace'] = 'outside-scope'
            w.write_yaml(path, criteria)
            self.assertEqual(plan(owner), 1)
            self.assertFalse((owner / 'attack-plan.yaml').exists())

    def test_pass_requires_oracles_real_signal_bounded_execution_and_role(self):
        with fixture() as (_, owner, _):
            self.assertEqual(plan(owner), 0)
            valid = observation(owner)
            variants = []
            bad = copy.deepcopy(valid); bad['stages'].pop('attacker_goal'); variants.append(bad)
            bad = copy.deepcopy(valid); bad['signal_source'] = 'synthetic'; variants.append(bad)
            bad = copy.deepcopy(valid); bad['requests_sent'] = 6; variants.append(bad)
            bad = copy.deepcopy(valid); bad['ended_at'] = '2026-09-07T00:10:00Z'; variants.append(bad)
            bad = copy.deepcopy(valid); bad['pins']['digest'] = 'other'; variants.append(bad)
            for bad in variants:
                self.assertEqual(record(owner, bad), 1)
            self.assertEqual(record(owner, valid, 'coordinator'), 1)
            self.assertEqual(record(owner, valid), 0)
            self.assertEqual(attacks.gate_errors(w.ROOT, owner), [])
            self.assertEqual(record(owner, valid), 1)

    def test_evidence_is_portable_and_tamper_blocks_gate(self):
        with fixture() as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            self.assertEqual(record(owner, observation(owner)), 0)
            (owner / 'evidence/witness.txt').unlink()
            self.assertEqual(attacks.gate_errors(root, owner), [])
            result = next(owner.glob('evidence/attacks/*/A1/result.yaml'))
            raw = attacks.load(result)['artifacts'][0]['path']
            (owner / raw).write_text('tampered')
            self.assertTrue(any('hash' in e for e in attacks.gate_errors(root, owner)))

    def test_replace_keeps_history_and_requires_new_result(self):
        with fixture() as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            self.assertEqual(record(owner, observation(owner)), 0)
            old = attacks.sha(owner / 'attack-plan.yaml')
            self.assertEqual(plan(owner, 'A1', '--replace'), 0)
            self.assertNotEqual(old, attacks.sha(owner / 'attack-plan.yaml'))
            self.assertTrue((owner / f'evidence/attacks/{old}/A1/result.yaml').exists())
            self.assertTrue(any('NOT_RUN' in e for e in attacks.gate_errors(root, owner)))

    def test_campaign_can_report_failure_but_requires_cleanup(self):
        with fixture(campaign=True) as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            obs = observation(owner, result='FAIL')
            obs['defense_outcome'] = 'unmitigated'; obs['stages']['attacker_goal'] = 'FAIL'
            self.assertEqual(record(owner, obs), 0)
            self.assertEqual(attacks.gate_errors(root, owner, closure=True), [])
            self.assertTrue(attacks.gate_errors(root, owner))
            self.assertEqual(plan(owner, 'A1', '--replace'), 0)
            obs['stages']['cleanup'] = 'NOT_REQUIRED'
            self.assertEqual(record(owner, obs), 0)
            self.assertTrue(any('cleanup' in e for e in attacks.gate_errors(root, owner, closure=True)))

    def test_nonexecution_cannot_claim_defense_and_health_cannot_pass_l3(self):
        with fixture() as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            obs = observation(owner, result='NOT_APPLICABLE'); obs['reason'] = 'missing hardware'
            self.assertEqual(record(owner, obs), 1)
            obs['defense_outcome'] = 'not_evaluated'
            self.assertEqual(record(owner, obs), 0)
            self.assertTrue(attacks.gate_errors(root, owner))
            self.assertEqual(plan(owner, 'P-HEALTH', '--replace'), 0)
            self.assertEqual(record(owner, observation(owner, 'P-HEALTH')), 0)
            self.assertTrue(any('non-baseline' in e for e in attacks.gate_errors(root, owner)))

    def test_campaign_transition_and_aggregate_attestation_consume_plan(self):
        with fixture(campaign=True) as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            status = attacks.load(owner.parent.parent / 'STATUS.yaml')
            errors = w.campaign_transition_prerequisites(owner.parent.parent, status, 'CLOSED')
            self.assertTrue(any('attack A1: NOT_RUN' in e for e in errors))
        with fixture() as (root, owner, _):
            self.assertEqual(plan(owner), 0)
            self.assertEqual(record(owner, observation(owner)), 0)
            self.assertEqual(cli('report', '--plan', (owner / 'attack-plan.yaml').relative_to(root)), 0)
            self.assertTrue(list(owner.glob('evidence/attacks/*/coverage.md')))
            status = attacks.load(owner / 'STATUS.yaml')
            status.setdefault('checks', {})['l3'] = {'result': 'PASS', 'attack_plan_sha256': 'old-plan'}
            errors = w.gates.check_errors(root, owner, status, 'l3')
            self.assertTrue(any('attack plan changed' in e for e in errors))

    def test_plan_transaction_rolls_back_partial_writes(self):
        with fixture() as (_, owner, _):
            original = (owner / 'evidence/manifest.yaml').read_bytes()
            with patch.object(attacks, 'manifest_record', side_effect=OSError('injected failure')):
                self.assertEqual(plan(owner), 1)
            self.assertFalse((owner / 'attack-plan.yaml').exists())
            self.assertEqual((owner / 'evidence/manifest.yaml').read_bytes(), original)
            self.assertFalse(list(owner.glob('evidence/attacks/plan-*.yaml')))

    def test_preflight_only_gets_explicit_context_and_omits_sensitive_fields(self):
        pod = {'metadata': {'name': 'operator'}, 'spec': {'containers': [{'name': 'manager', 'image': 'phorvex:test',
               'env': [{'name': 'TOKEN', 'value': 'do-not-export'}]}]}, 'status': {'phase': 'Running',
               'containerStatuses': [{'name': 'manager', 'ready': True, 'imageID': 'sha256:test'}]}}
        calls = []
        def run(cmd, **kwargs):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout=json.dumps({'items': [pod] if 'pods' in cmd else []}))
        with patch.object(attacks.subprocess, 'run', side_effect=run):
            result = attacks.inspect_cluster('explicit', ['tenant'], 'operator', PINS['source_sha'])
        self.assertTrue(result['capabilities']['operator_ready'])
        self.assertNotIn('do-not-export', json.dumps(result))
        self.assertTrue(all(cmd[1:3] == ['--context', 'explicit'] and cmd[4] == 'get' for cmd in calls))

    def test_health_runner_fails_for_unready_targets(self):
        with fixture() as (root, owner, snapshot):
            self.assertEqual(plan(owner, 'P-HEALTH'), 0)
            snapshot.update(errors=[], pods=[{'ready': False}])
            with patch.object(attacks, 'inspect_cluster', return_value=snapshot):
                self.assertEqual(cli('observe-health', '--plan', (owner / 'attack-plan.yaml').relative_to(root), '--by', 'verifier'), 1)
            result = next(owner.glob('evidence/attacks/*/P-HEALTH/result.yaml'))
            self.assertEqual(attacks.load(result)['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
