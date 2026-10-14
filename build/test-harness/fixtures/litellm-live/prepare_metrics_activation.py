"""Prepare authenticated metrics from complete nonsecret owner snapshots; no API access."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import yaml
from render import canonical
from render_metrics import render, SOURCE_ANNOTATION, bind_artifacts, monitoring_objects, protection

INPUT_NAMES = ('deployment.json', 'gateway-source.json', 'clients.json', 'profiles.json',
               'service.json', 'networkpolicies.json', 'prometheus-labels.json', 'output-policy.json')


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def prepare(inputs, values_path, baseline_bindings=None, *, protection_mode=None,
            metrics_secret_name=None, metrics_secret_key=None):
    def read(name):
        return json.loads((inputs / name).read_text())
    values = yaml.safe_load(values_path.read_text())
    console = values['phorvex']['phorvex']['console']
    profiles = read('profiles.json')
    active = json.loads(baseline_bindings.read_text()) if baseline_bindings else console['litellmLive']
    # Only litellmLive is source-bound. The independent output seed profile is preserved.
    if not active['enabled'] or len(profiles) != 1:
        raise ValueError('complete active source-bound profile closure required')
    profile = profiles[0]
    raw = profile['data']['profile.json']
    if (profile['metadata']['name'] != active['configMapName'] or
            hashlib.sha256(raw.encode()).hexdigest() != active['profileSHA256'] or
            not profile['metadata'].get('uid')):
        raise ValueError('active values/profile closure differs')
    deployment = read('deployment.json')
    source = read('gateway-source.json')
    old_sha = deployment['spec']['template']['metadata']['annotations'][SOURCE_ANNOTATION]
    if (source.get('kind') != 'ConfigMap' or source.get('immutable') is not True or
            set(source.get('data', {})) != {'gateway.py'} or source.get('binaryData') or
            not source['metadata'].get('uid') or source['metadata'].get('namespace') != 'litellm' or
            source['metadata']['name'] != active['sourceConfigMapName'] or
            hashlib.sha256(source['data']['gateway.py'].encode()).hexdigest() != old_sha):
        raise ValueError('observed immutable source bytes/values differ')
    clients = read('clients.json')
    p = json.loads(raw)
    if (clients.get('kind') != 'ConfigMap' or clients.get('immutable') is not True or
            set(clients.get('data', {})) != {'clients.json'} or clients.get('binaryData') or
            not clients['metadata'].get('uid') or clients['metadata'].get('namespace') != 'litellm' or
            hashlib.sha256(clients['data']['clients.json'].encode()).hexdigest() != p['clientsSHA256']):
        raise ValueError('observed client inventory differs')
    labels = read('prometheus-labels.json')
    stable_labels = {key: labels[key] for key in ('app.kubernetes.io/name', 'prometheus')}
    service = read('service.json')
    if (service.get('kind') != 'Service' or service['metadata'].get('namespace') != 'litellm' or
            service['metadata'].get('name') != 'litellm' or
            service['metadata']['uid'] != deployment['spec']['template']['metadata']['annotations']['phorvex.ai/litellm-live-service-uid'] or
            service['spec']['selector'] != {'app': 'litellm'} or service['spec'].get('type') != 'ClusterIP' or
            len(service['spec']['ports']) != 1 or service['spec']['ports'][0]['targetPort'] != 4001):
        raise ValueError('observed serving Service differs')
    auth = protection(protection_mode, metrics_secret_name, metrics_secret_key, '')
    expected_policy = monitoring_objects(stable_labels, auth)['metrics-networkpolicy.json']['spec']
    original_policies = []
    for policy in read('networkpolicies.json'):
        if policy.get('metadata', {}).get('name') == 'phorvex-litellm-gateway-metrics':
            # The reviewed opt-in policy may already be staged before the manual rollout.
            unisolated_policy = copy.deepcopy(expected_policy)
            unisolated_policy['ingress'].append({'ports': [{'protocol': 'TCP', 'port': port} for port in (4000, 4001, 4002)]})
            if (policy.get('metadata', {}).get('namespace') != 'litellm' or
                    policy.get('spec') not in (expected_policy, unisolated_policy)):
                raise ValueError('staged metrics NetworkPolicy spec drift')
        else:
            original_policies.append(policy)
    objects = render(deployment, profiles, original_policies, stable_labels, read('output-policy.json'),
                     enabled=True, preserve_unisolated_ingress=not original_policies,
                     protection_mode=protection_mode, metrics_secret_name=metrics_secret_name,
                     metrics_secret_key=metrics_secret_key)
    closure = objects['metrics-closure.json']
    current = console['litellmLive']
    if values['litellmGatewayMetrics']['enabled'] is True:
        binding = closure['profiles'][0]
        if (not current['enabled'] or any(current[key] != binding[key]
                for key in ('configMapName', 'profileSHA256', 'sourceConfigMapName')) or
                values['litellmGatewayMetrics'] != {'enabled': True, 'protectionMode': protection_mode,
                    'auth': {'secretName': metrics_secret_name, 'secretKey': metrics_secret_key}}):
            raise ValueError('active values do not match complete derived auth closure')
    elif any(current[key] != active[key] for key in ('enabled', 'configMapName', 'profileSHA256', 'sourceConfigMapName')):
        raise ValueError('disabled values do not retain preceding Console bindings')
    previous = {key: copy.deepcopy(active[key]) for key in ('enabled', 'configMapName', 'profileSHA256', 'sourceConfigMapName')}
    previous_metrics = active.get('litellmGatewayMetrics', values['litellmGatewayMetrics'])
    previous['litellmGatewayMetrics'] = copy.deepcopy(previous_metrics)
    objects['previous-console-bindings.json'] = previous
    closure['owner'] = {'gateway': 'external manual Deployment; never Helm-adopted',
                       'activationManifests': 'deploy/helm/phorvex-stack/templates/litellm-gateway-metrics.yaml',
                       'activeProfileValues': 'phorvex.phorvex.console.litellmLive'}
    closure['baseline'] = {'deploymentUID': deployment['metadata']['uid'],
        'deploymentSpecSHA256': digest(deployment['spec']),
        'sourceUID': source['metadata']['uid'], 'sourceConfigMapName': source['metadata']['name'],
        'serviceUID': service['metadata']['uid'], 'serviceSpecSHA256': digest(service['spec']),
        'clientsUID': clients['metadata']['uid'], 'clientsConfigMapName': clients['metadata']['name'],
        'clientsSHA256': p['clientsSHA256'], 'previousConsoleBindings': previous,
        'profiles': [{'name': profile['metadata']['name'], 'uid': profile['metadata']['uid'],
                      'profileSHA256': active['profileSHA256']}],
        'prometheusPodLabels': stable_labels,
        'inputsSHA256': {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in INPUT_NAMES}}
    closure['gates'] = ['compatible engine and Console released', 'published image exact mounted-source proof',
        'fresh UID/spec/source/client guards', 'idle catalogue and no prepared client/output operations',
        'quiescent installed output policy', 'real cross-namespace bearer-auth proof and metadata-only Secret UID/RV binding',
        'Hami native vLLM scrape healthy for ten minutes and existing generic bridge/query available']
    return bind_artifacts(objects)


def main():
    parser = argparse.ArgumentParser()
    for name in ('inputs', 'values', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-bindings', type=Path)
    for name in ('protection-mode', 'metrics-secret-name', 'metrics-secret-key'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    objects = prepare(args.inputs, args.values, args.baseline_bindings,
        protection_mode=args.protection_mode, metrics_secret_name=args.metrics_secret_name,
        metrics_secret_key=args.metrics_secret_key)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, obj in objects.items():
        (args.output / name).write_text(canonical(obj) + '\n')
    print('prepared authenticated source/profile/candidate/inverse; production activation still gated')


if __name__ == '__main__':
    main()
