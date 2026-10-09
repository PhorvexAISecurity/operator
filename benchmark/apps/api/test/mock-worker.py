"""Offline protocol fixture: production runner/exporter, fake Console and captures."""
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import urllib.parse

sys.path.insert(0, str(Path(os.environ['BENCHMARK_TEST_WORKER_ROOT']) / 'worker'))
import runner


class MockConsole:
    def __init__(self, *_): pass
    def close(self): pass
    def kubectl(self, *_): return '{"items":[]}'
    def request(self, path, method='GET', body=None):
        if path == '/api/version': return {'version': 'offline-fixture'}
        if path.startswith('/api/workload/attacks?'):
            ns = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['namespace'][0]
            return {'namespace': ns, 'live': [
                {'id': 'foothold', 'name': 'Opaque ready fixture', 'endpoint': '/api/workload/attack', 'armed': True, 'compatible': True},
                {'id': 'opaque-incompatible', 'name': 'Opaque blocked fixture', 'endpoint': '/api/unreviewed',
                 'armed': False, 'compatible': False, 'reason': 'Fixture serving stack is incompatible'},
                {'id': 'opaque-unwired', 'name': 'Opaque unwired fixture', 'endpoint': '/api/unreviewed',
                 'armed': True, 'compatible': True, 'reason': 'Console fixture reports ready'},
            ]}
        if method == 'POST':
            assert path == '/api/workload/attack' and body['action'] == 'foothold'
            return {'attackId': 'fixture-record-' + body['namespace']}
        if path.startswith('/api/attack-results?'):
            identity = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['id'][0]
            return {'attacks': [{'id': identity, 'namespace': identity.removeprefix('fixture-record-'), 'status': 'done',
                                 'outcome': 'UNKNOWN', 'phorvexAction': '', 'actuated': False}]}
        raise AssertionError('Unexpected mock request: ' + path)


class MockCapture:
    def __init__(self, *_):
        self.ready = threading.Event(); self.ready.set()
        self.result = {'gaps': [], 'records': 0, 'bytes': 0}
        self.thread = SimpleNamespace(start=lambda: None)
    def close(self): pass


def mock_snapshot(_):
    deployments, pods = [], []
    for name in ('phorvex-phorvex', 'phorvex-console', 'operator-controller-manager'):
        deployments.append({'name': name, 'uid': name, 'specSHA256': 'fixture-spec', 'images': {'fixture': 'fixture:1'}, 'generation': 1,
                            'observedGeneration': 1, 'desiredReplicas': 1, 'readyReplicas': 1, 'updatedReplicas': 1})
        pods.append({'name': name + '-pod', 'uid': name + '-pod-uid', 'namespace': 'phorvex-system', 'deploymentUID': name, 'phase': 'Running',
                     'containers': [{'name': 'fixture', 'specImage': 'fixture:1', 'imageID': 'fixture-digest', 'ready': True}]})
    return {'apiVersion': {}, 'operator': 'fixture-1', 'console': 'fixture-1', 'deployments': deployments,
            'pods': pods, 'namespaces': [], 'policies': [], 'errors': []}


runner.Console = MockConsole
runner.Capture = MockCapture
runner.snapshot = mock_snapshot
sys.exit(runner.main())
