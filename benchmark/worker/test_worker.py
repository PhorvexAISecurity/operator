import concurrent.futures
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch
from types import SimpleNamespace

import openpyxl

from exporter import COST_FILE, GATES_FILE, optional, source_rows, export_workbooks, typed_links, template_paths
from runner import Campaign, Capture, Console, HTTPFailure, TransportError, dependency_locks, launch_body, drift, controller_pods, readiness_error, error_details


def fixture():
    present = lambda value: {'present': True, 'value': value}
    absent = {'present': False, 'value': 0}
    return {'time': '2026-10-07T09:00:10Z', 'kind': 'phorvex.decision', 'namespace': 'voice', 'tenant': 'voice',
            'decisionTrace': {'decisionID': 'decision-1', 'tickID': 'tick-1', 'policyUID': 'policy-1', 'assetUID': 'pod-1',
                              'timestamp': '2026-10-07T09:00:10Z', 'assetNamespace': 'voice', 'tenantName': 'voice',
                              'assetName': 'voice-pod', 'evaluationRound': 1, 'normWeight': .4, 'flowWeight': .6,
                              'selectedAction': 'noop', 'noopReason': 'no-positive-net', 'costCeiling': .5,
                              'candidates': [
                                  {'action': 'rotate', 'candidateKey': 'rotate-pod-1', 'cNorm': present(0), 'cFlow': present(0),
                                   'expectedCost': present(0), 'marginalCoverage': present(0), 'provenance': present(1),
                                   'netGain': present(0), 'feasible': present(True), 'sloGateResult': present(True), 'selected': False},
                                  {'action': 'quarantine', 'candidateKey': 'quarantine-pod-1', 'cNorm': absent, 'cFlow': absent,
                                   'expectedCost': absent, 'feasible': present(False), 'selected': False,
                                   'existingExclusionReason': 'resource-capacity: retained limit', 'sloGateResult': absent}],
                              'actionStatus': [
                                  {'action': 'rotate', 'status': 'priced-out', 'exclusionKind': 'selection', 'scored': True},
                                  {'action': 'quarantine', 'status': 'infeasible', 'exclusionKind': 'resource-capacity', 'scored': False},
                                  {'action': 'request-drain', 'status': 'not-enabled', 'exclusionKind': 'not-enabled', 'scored': False}]}}


class ExportTests(unittest.TestCase):
    def test_missing_and_zero_do_not_collapse(self):
        self.assertIsNone(optional({'present': False, 'value': 0}))
        self.assertEqual(optional({'present': True, 'value': 0}), 0)
        self.assertIs(optional({'present': True, 'value': False}), False)
        costs, gates = source_rows(fixture(), 'run', 'raw/file:1')
        self.assertEqual(costs[0]['C_total_expected'], 0)
        self.assertNotIn('C_total_measured', costs[0])
        self.assertIsNone(costs[1]['CNorm_expected'])
        self.assertFalse(gates[1]['candidate_generated'])
        self.assertTrue(gates[1]['trace_candidate_present'])
        self.assertEqual(gates[1]['row_kind'], 'excluded_candidate')
        self.assertFalse(gates[1]['final_feasible'])
        self.assertEqual(gates[1]['resource_gate'], 'FAIL')
        self.assertIsNone(gates[1]['slo_cost_gate'])
        self.assertFalse(gates[2]['action_enabled'])
        self.assertFalse(gates[2]['candidate_generated'])
        self.assertEqual(costs[-1]['row_kind'], 'observed_noop')

    def test_temporal_correlation_not_exact(self):
        links = typed_links({'temporalDecisionEvidence': {'decisionId': 'wrong'},
                             'decisionEvidence': {'correlation': 'temporal-workload', 'decisionId': 'also-wrong'},
                             'voiceMemoryProbe': {'selectedDecisionID': 'right'}})
        self.assertEqual(links, {'right'})

    def test_templates_and_window_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); (out / 'raw').mkdir()
            record = fixture()
            # Duplicate canonical trace is deduplicated; outside-window record excluded.
            older = fixture(); older['decisionTrace']['timestamp'] = '2026-10-07T08:59:00Z'
            (out / 'raw' / 'audit-voice.jsonl').write_text('\n'.join(json.dumps(x) for x in (older, record, record)))
            (out / 'cases.jsonl').write_text(json.dumps({'namespace': 'voice', 'id': 'ai2-agent-memory-contamination',
                                                       'status': 'completed', 'result': {'id': 'atk1', 'voiceMemoryProbe': {'selectedDecisionID': 'decision-1'}}}))
            request = {'id': 'run1', 'mode': 'serial'}
            manifest = {'status': 'completed', 'startedAt': '2026-10-07T09:00:00Z', 'finishedAt': '2026-10-07T09:01:00Z'}
            summary = export_workbooks(out, request, manifest)
            self.assertEqual(summary['uniqueTraces'], 1)
            self.assertEqual(summary['costChecksFailed'], 0)
            self.assertEqual(summary['realizedCostsAvailable'], 0)
            for filename, sheet in ((COST_FILE, 'Cost_Comparison'), (GATES_FILE, 'Tick_Action_Gates')):
                workbook = openpyxl.load_workbook(out / filename, data_only=True)
                self.assertEqual(workbook[sheet].max_row, 5)
                self.assertIn('Evidence_Coverage', workbook.sheetnames)
            cost = openpyxl.load_workbook(out / COST_FILE, data_only=True)['Cost_Comparison']
            headers = [c.value for c in cost[1]]
            self.assertEqual(cost.cell(2, headers.index('CNorm_expected') + 1).value, 0)
            self.assertIsNone(cost.cell(2, headers.index('CNorm_measured') + 1).value)


class RunnerTests(unittest.TestCase):
    def test_known_reader_gap_blocks_launch_without_rewriting_live_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            case = {'namespace': 'crm', 'id': 'ai2-cross-record-refund', 'endpoint': '/api/crm/live/fire',
                    'compatible': True, 'armed': True, 'benchmarkBlocked': True,
                    'benchmarkBlockReason': 'Current Console hides crm-refund-live from exact readback'}
            client = SimpleNamespace(request=lambda *_: self.fail('Blocked producer must not launch'))
            campaign = Campaign({'id': 'run'}, directory, client)
            campaign.execute(case)
            self.assertEqual(campaign.cases[0]['status'], 'blocked')
            self.assertTrue(campaign.cases[0]['armed'])
            self.assertTrue(campaign.cases[0]['compatible'])
            self.assertIn('crm-refund-live', campaign.cases[0]['reason'])

    def test_allowlist_rejects_forged_endpoint(self):
        with self.assertRaises(ValueError): launch_body({'namespace': 'voice', 'id': 'foothold', 'endpoint': 'https://bad.invalid'})
        self.assertEqual(launch_body({'namespace': 'vllm', 'id': 'poison', 'endpoint': '/api/vllm/attack'}), {'action': 'poison'})

    def test_post_never_retried(self):
        client = Console.__new__(Console)
        with patch.object(client, 'open', side_effect=TransportError('ambiguous')) as mocked:
            with self.assertRaises(TransportError): client.request('/api/vllm/attack', 'POST', {'action': 'poison'})
            self.assertEqual(mocked.call_count, 1)

    def test_cancel_observes_existing_record_and_stops_next_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); (out / 'raw').mkdir()
            case = {'namespace': 'voice', 'id': 'ai2-agent-memory-contamination', 'endpoint': '/api/voice/live/fire', 'compatible': True, 'armed': True}
            class Fake:
                posts, reads = 0, 0
                def request(self, path, method='GET', body=None):
                    if method == 'POST':
                        self.posts += 1; (out / 'cancel.flag').touch(); return {'attackId': 'record-owned'}
                    if path.startswith('/api/workload/attacks'): return {'live': [case]}
                    self.reads += 1
                    return {'attacks': [{'id': 'record-owned', 'namespace': 'voice', 'status': 'running' if self.reads == 1 else 'done', 'outcome': ''}]}
            fake = Fake(); campaign = Campaign({'id': 'run'}, out, fake)
            ready = threading.Event(); ready.set()
            campaign.captures['voice'] = SimpleNamespace(ready=ready, result={'gaps': []})
            with patch.dict('os.environ', {'BENCHMARK_POLL_SECONDS': '0.001'}):
                campaign.execute(case); campaign.execute(case)
            self.assertEqual(fake.posts, 1)
            self.assertEqual(fake.reads, 2)
            self.assertEqual(campaign.cases[0]['status'], 'completed')
            self.assertEqual(campaign.cases[1]['status'], 'cancelled')

    def test_sse_cap_is_explicit_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); (out / 'raw').mkdir()
            class Response(io.BytesIO):
                headers = {'Content-Type': 'text/event-stream'}
            class Fake:
                def open(self, path, **kwargs): return Response(b': connected\n\ndata: {}\n\n')
            with patch.dict('os.environ', {'BENCHMARK_CAPTURE_MAX_BYTES': '10'}):
                capture = Capture(Fake(), 'voice', out, lambda *_: None); capture.run()
            self.assertEqual(capture.result['records'], 0)
            self.assertTrue(any('byte cap' in gap['reason'] for gap in capture.result['gaps']))

    def test_exact_identity_does_not_take_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            class Fake:
                def request(self, path):
                    self.path = path
                    return {'attacks': [{'id': 'newest', 'attackId': 'wanted', 'status': 'done'}]}
            fake = Fake(); campaign = Campaign({'id': 'r'}, directory, fake)
            self.assertIsNone(campaign.exact_result('wanted'))
            self.assertIn('id=wanted', fake.path)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(fake.path).query)
            self.assertEqual(query['limit'], ['1'])
            # Source-owned max is 50; exact record fetch must always be inside it.
            self.assertLessEqual(int(query['limit'][0]), 50)
            self.assertEqual(query['id'], ['wanted'])

    def test_http_diagnostic_keeps_limit_error_but_not_credentials(self):
        details = error_details(HTTPFailure(400, {'error': 'limit must be between 1 and 50',
                                                 'authorization': 'Bearer secret', 'context': 'Bearer abcdef12345'}))
        self.assertEqual(details['status'], 400)
        self.assertEqual(details['response']['error'], 'limit must be between 1 and 50')
        self.assertEqual(details['response']['authorization'], '[REDACTED]')
        self.assertNotIn('abcdef12345', json.dumps(details))

    def test_parallel_shared_producers_stay_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Campaign({'id': 'run'}, directory, None)
            active, max_active = {}, {}
            guard = threading.Lock()
            def fake_case(case):
                acquired = []
                try:
                    for name in dependency_locks(case):
                        campaign.locks[name].acquire(); acquired.append(campaign.locks[name])
                    with guard:
                        for name in dependency_locks(case):
                            active[name] = active.get(name, 0) + 1
                            max_active[name] = max(max_active.get(name, 0), active[name])
                    time.sleep(.04)
                    with guard:
                        for name in dependency_locks(case): active[name] -= 1
                finally:
                    for lock in reversed(acquired): lock.release()
            cases = [{'namespace': 'voice', 'id': 'ai2-agent-excessive-agency'},
                     {'namespace': 'litellm', 'id': 'ai2-query-extraction'},
                     {'namespace': 'crm', 'id': 'ai2-cross-record-refund'}]
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(fake_case, cases))
            self.assertEqual(max_active['shared-model-gateway'], 1)
            self.assertEqual(max_active['shared-crm'], 1)

    def test_config_drift_preserves_expected_target_rotation(self):
        before = {'apiVersion': {}, 'deployments': [], 'namespaces': [], 'policies': [],
                  'pods': [{'namespace': 'voice', 'uid': 'old'}]}
        after = {**before, 'pods': [{'namespace': 'voice', 'uid': 'new'}]}
        self.assertEqual(drift(before, after), [])
        after['policies'] = [{'namespace': 'voice', 'name': 'defense', 'generation': 2}]
        self.assertEqual(drift(before, after), ['policies'])

    def test_job_pods_not_controller_lineage(self):
        deployments = [{'name': 'operator-controller-manager', 'uid': 'phoenix-deployment'}]
        replicasets = [{'metadata': {'uid': 'phoenix-rs', 'ownerReferences': [{'kind': 'Deployment', 'uid': 'phoenix-deployment'}]}}]
        pods = [{'metadata': {'name': 'operator-controller-manager-x', 'ownerReferences': [{'kind': 'ReplicaSet', 'uid': 'phoenix-rs'}]}},
                {'metadata': {'name': 'phorvex-epss-123', 'ownerReferences': [{'kind': 'Job', 'uid': 'job'}]}}]
        self.assertEqual(controller_pods(pods, replicasets, deployments), pods[:1])
        self.assertIn('Phoenix', readiness_error({'deployments': [], 'pods': []}))

    def test_canonicalized_status_image_is_not_rollout_mismatch(self):
        deployments, pods = [], []
        for name, container, image in [('phorvex-phorvex', 'manager', 'example/phorvex:0.4.216'),
                                       ('phorvex-console', 'console', 'example/console:0.4.216'),
                                       ('operator-controller-manager', 'manager', 'operator:v1.13.0')]:
            deployments.append({'name': name, 'uid': name, 'images': {container: image}, 'generation': 1,
                                'observedGeneration': 1, 'desiredReplicas': 1, 'readyReplicas': 1, 'updatedReplicas': 1})
            pods.append({'name': name + '-pod', 'namespace': 'phorvex-system', 'deploymentUID': name, 'phase': 'Running',
                         'containers': [{'name': container, 'specImage': image, 'image': 'docker.io/library/' + image,
                                         'imageID': 'docker-pullable://repository@sha256:actual-digest', 'ready': True}]})
        self.assertEqual(readiness_error({'deployments': deployments, 'pods': pods}), '')
        pods[-1]['containers'][0]['specImage'] = 'operator:v1.12.0'
        self.assertIn('different image', readiness_error({'deployments': deployments, 'pods': pods}))

    def test_template_allowlist_excludes_appledouble(self):
        names = {path.name for path in template_paths()}
        self.assertEqual(len(names), 2)
        self.assertTrue(all(not name.startswith('.') for name in names))

    def test_rejected_preflight_cannot_report_completed_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); (out / 'raw').mkdir()
            (out / 'cases.jsonl').touch()
            case = {'namespace': 'voice', 'id': 'ai2-agent-memory-contamination', 'endpoint': '/api/voice/live/fire', 'compatible': True, 'armed': True}
            pin = {'apiVersion': {}, 'operator': '0.4.216', 'console': '0.4.216', 'deployments': [],
                   'pods': [], 'namespaces': [], 'policies': [], 'errors': []}
            class FakeCapture:
                def __init__(self, *_):
                    self.result = {'gaps': [], 'records': 0, 'bytes': 0}
                    self.ready = threading.Event(); self.ready.set()
                    self.thread = SimpleNamespace(start=lambda: None)
                def close(self): pass
            campaign = Campaign({'id': 'run', 'applications': ['voice'], 'mode': 'serial'}, out, None)
            with patch('runner.snapshot', return_value=pin), patch('runner.catalogue', return_value={'applications': [{'live': [case]}], 'errors': []}), patch('runner.Capture', FakeCapture):
                manifest = campaign.run()
            self.assertEqual(manifest['status'], 'incomplete')
            self.assertFalse(manifest['preflight']['passed'])
            self.assertTrue(any('Preflight rejected' in error for error in manifest['errors']))
            self.assertEqual(campaign.cases[0]['status'], 'blocked')
            self.assertFalse((out / 'raw' / 'launch-intents.jsonl').exists())


if __name__ == '__main__': unittest.main()
