"""Preparation and inverse-to-legacy controls on disposable nonsecret snapshots."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import yaml
from render import canonical
from test_render_metrics import originals, patched, AUTH, module
from prepare_metrics_activation import prepare
from prepare_metrics_rollback import prepare as rollback


def owned_inputs(path):
    path.mkdir(exist_ok=True)
    deployment, profiles, policies, labels = originals()
    source = Path(__file__).with_name('gateway.py').read_text()
    clients_raw = canonical({'version': 2, 'modelAlias': 'gpt-4o-mini', 'seedSHA256': 'a' * 64})
    p = json.loads(profiles[0]['data']['profile.json'])
    p['clientsSHA256'] = hashlib.sha256(clients_raw.encode()).hexdigest()
    raw = canonical(p)
    profiles[0]['data']['profile.json'] = raw
    profiles[0]['metadata'].update(name='phorvex-litellm-live-profile-' + hashlib.sha256(raw.encode()).hexdigest()[:12], uid='profile-fixture')
    deployment['spec']['template']['metadata']['annotations']['phorvex.ai/litellm-live-service-uid'] = 'service-fixture'
    objects = {'deployment.json': deployment, 'profiles.json': profiles, 'networkpolicies.json': policies,
        'prometheus-labels.json': labels, 'output-policy.json': None,
        'gateway-source.json': {'apiVersion': 'v1', 'kind': 'ConfigMap', 'immutable': True,
            'metadata': {'namespace': 'litellm', 'name': 'phorvex-litellm-admission-gateway-' + p['sourceSHA256'][:12], 'uid': 'source-fixture'},
            'data': {'gateway.py': source}},
        'clients.json': {'apiVersion': 'v1', 'kind': 'ConfigMap', 'immutable': True,
            'metadata': {'namespace': 'litellm', 'name': 'clients-fixture', 'uid': 'clients-fixture'}, 'data': {'clients.json': clients_raw}},
        'service.json': {'apiVersion': 'v1', 'kind': 'Service',
            'metadata': {'namespace': 'litellm', 'name': 'litellm', 'uid': 'service-fixture'},
            'spec': {'type': 'ClusterIP', 'selector': {'app': 'litellm'}, 'ports': [{'port': 4000, 'targetPort': 4001}]}}}
    for name, value in objects.items():
        (path / name).write_text(canonical(value) + '\n')
    values = {'litellmGatewayMetrics': {'enabled': False, 'protectionMode': 'bearerToken', 'auth': {
        'secretName': module.SECRET_NAME, 'secretKey': 'token'}},
        'phorvex': {'phorvex': {'image': {'tag': 'latest-reviewed-release'}, 'console': {'litellmLive': {
            'enabled': True, 'configMapName': profiles[0]['metadata']['name'],
            'profileSHA256': hashlib.sha256(raw.encode()).hexdigest(),
            'sourceConfigMapName': objects['gateway-source.json']['metadata']['name']},
            'litellmOutput': {'enabled': False}}}}}
    values_path = path / 'values.yaml'
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    return values_path, values


def active_values(values, closure):
    result = copy.deepcopy(values)
    result['litellmGatewayMetrics']['enabled'] = True
    for key in ('configMapName', 'profileSHA256', 'sourceConfigMapName'):
        result['phorvex']['phorvex']['console']['litellmLive'][key] = closure['profiles'][0][key]
    return result


class PrepareTests(unittest.TestCase):
    def test_complete_closure_and_rv_only_refresh_preserve_inverse_and_auth_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            values_path, values = owned_inputs(path)
            candidate = prepare(path, values_path, **AUTH)
            closure = candidate['metrics-closure.json']
            self.assertEqual(closure['baseline']['clientsUID'], 'clients-fixture')
            self.assertEqual(closure['baseline']['previousConsoleBindings'], candidate['previous-console-bindings.json'])
            for name, sha in closure['baseline']['inputsSHA256'].items():
                self.assertEqual(sha, hashlib.sha256((path / name).read_bytes()).hexdigest())
            deployment = json.loads((path / 'deployment.json').read_text())
            self.assertEqual(patched(patched(deployment, candidate['deployment-metrics-json-patch.json']),
                                     candidate['deployment-metrics-rollback-json-patch.json']), deployment)
            deployment['metadata']['resourceVersion'] = '43'
            (path / 'deployment.json').write_text(canonical(deployment) + '\n')
            refreshed = prepare(path, values_path, **AUTH)
            self.assertEqual(refreshed['deployment-metrics-json-patch.json'][1]['value'], '43')
            self.assertEqual(candidate['deployment-metrics-rollback-json-patch.json'], refreshed['deployment-metrics-rollback-json-patch.json'])
            for key in ('metricsProtection', 'candidateTemplateSHA256', 'gatewaySourceSHA256', 'gatewayImageByDigest', 'monitoringSpecsSHA256'):
                self.assertEqual(closure[key], refreshed['metrics-closure.json'][key])

    def test_enabled_reprepare_requires_complete_derived_profile_and_saved_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            values_path, values = owned_inputs(path)
            candidate = prepare(path, values_path, **AUTH)
            baseline = path / 'previous.json'
            baseline.write_text(canonical(candidate['previous-console-bindings.json']))
            active = active_values(values, candidate['metrics-closure.json'])
            values_path.write_text(yaml.safe_dump(active, sort_keys=False))
            self.assertEqual(prepare(path, values_path, baseline, **AUTH), candidate)
            active['litellmGatewayMetrics']['auth']['secretName'] = 'drifted-reference'
            values_path.write_text(yaml.safe_dump(active, sort_keys=False))
            with self.assertRaisesRegex(ValueError, 'active values'):
                prepare(path, values_path, baseline, **AUTH)

    def test_owner_client_service_source_and_profile_drift_refuse_preparation(self):
        mutations = [
            ('clients.json', lambda x: x['metadata'].pop('uid'), 'client inventory'),
            ('clients.json', lambda x: x['data'].update({'clients.json': '{}'}), 'client inventory'),
            ('gateway-source.json', lambda x: x['metadata'].update(name='foreign-source'), 'source bytes'),
            ('service.json', lambda x: x['spec']['selector'].update({'foreign': 'pod'}), 'Service'),
            ('profiles.json', lambda x: x[0]['metadata'].pop('uid'), 'profile closure'),
            ('deployment.json', lambda x: x['spec']['template']['spec']['securityContext'].update(fsGroup=0), 'fsGroup'),
        ]
        for name, mutate, message in mutations:
            with self.subTest(name=name, message=message), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)
                values_path, values = owned_inputs(path)
                value = json.loads((path / name).read_text())
                mutate(value)
                (path / name).write_text(canonical(value))
                with self.assertRaisesRegex(ValueError, message):
                    prepare(path, values_path, **AUTH)

    def test_rollback_restores_previous_auth_references_and_only_reviewed_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            values_path, values = owned_inputs(path)
            # Previously disabled references are allowed to differ from the new reviewed pair.
            values['litellmGatewayMetrics']['auth']['secretName'] = 'previous-reference'
            values_path.write_text(yaml.safe_dump(values, sort_keys=False))
            candidate = prepare(path, values_path, **AUTH)
            closure = candidate['metrics-closure.json']
            active = active_values(values, closure)
            active['litellmGatewayMetrics']['auth']['secretName'] = module.SECRET_NAME
            active['phorvex']['phorvex']['image']['tag'] = 'newer-shared-release'
            values_path.write_text(yaml.safe_dump(active, sort_keys=False))
            closure_path = path / 'closure.json'; closure_path.write_text(canonical(closure))
            previous_path = path / 'previous.json'; previous_path.write_text(canonical(candidate['previous-console-bindings.json']))
            output = path / 'rollback.yaml'
            rollback(values_path, closure_path, previous_path, output)
            expected = copy.deepcopy(values)
            expected['phorvex']['phorvex']['image']['tag'] = 'newer-shared-release'
            self.assertEqual(yaml.safe_load(output.read_text()), expected)
            with self.assertRaises(FileExistsError):
                rollback(values_path, closure_path, previous_path, output)
            active['litellmGatewayMetrics']['auth']['secretName'] = 'other-pair'
            values_path.write_text(yaml.safe_dump(active, sort_keys=False))
            with self.assertRaisesRegex(ValueError, 'auth-reference drift'):
                rollback(values_path, closure_path, previous_path, path / 'refused.yaml')
            self.assertFalse((path / 'refused.yaml').exists())


if __name__ == '__main__':
    unittest.main()
