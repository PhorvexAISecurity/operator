"""Restore reviewed preceding metrics/profile values; retain release and compatibility pins."""
import argparse
import copy
import json
from pathlib import Path
import re
import yaml


def prepare(values_path, closure_path, previous_path, output):
    text = values_path.read_text()
    current = yaml.safe_load(text)
    expected = copy.deepcopy(current)
    closure = json.loads(closure_path.read_text())
    previous = json.loads(previous_path.read_text())
    profiles = closure['profiles']
    if len(profiles) != 1 or current['litellmGatewayMetrics']['enabled'] is not True:
        raise ValueError('exact active metrics closure required')
    live = current['phorvex']['phorvex']['console']['litellmLive']
    if live['enabled'] is not True or previous.get('enabled') is not True:
        raise ValueError('active and preceding profiles must be reviewed before rollback')
    for key in ('configMapName', 'profileSHA256', 'sourceConfigMapName'):
        old = profiles[0][key]
        if live[key] != old or text.count(old) != 1:
            raise ValueError('current source/profile drift: refusing rollback')
        text = text.replace(old, previous[key], 1)
        expected['phorvex']['phorvex']['console']['litellmLive'][key] = previous[key]
    schema = closure.get('schema')
    if schema == 'phorvex-litellm-metrics-candidate-v2':
        auth = closure['metricsProtection']
        if current['litellmGatewayMetrics'] != {'enabled': True, 'protectionMode': auth['mode'],
                'auth': {'secretName': auth['secretName'], 'secretKey': auth['secretKey']}}:
            raise ValueError('current auth-reference drift: refusing rollback')
        prior_metrics = previous.get('litellmGatewayMetrics')
        if (not isinstance(prior_metrics, dict) or prior_metrics.get('enabled') is not False or
                previous != closure['baseline']['previousConsoleBindings']):
            raise ValueError('complete reviewed preceding metrics bindings required')
        lines = text.splitlines(keepends=True)
        starts = [i for i, line in enumerate(lines) if line == 'litellmGatewayMetrics:\n']
        if len(starts) != 1:
            raise ValueError('metrics values block differs: refusing rollback')
        start = starts[0]
        end = start + 1
        while end < len(lines) and (lines[end].startswith((' ', '\t')) or not lines[end].strip()):
            end += 1
        replacement = yaml.safe_dump({'litellmGatewayMetrics': prior_metrics}, sort_keys=False)
        text = ''.join(lines[:start]) + replacement + ''.join(lines[end:])
        expected['litellmGatewayMetrics'] = copy.deepcopy(prior_metrics)
    elif schema == 'phorvex-litellm-metrics-candidate-v1':
        text, count = re.subn(r'(?m)^(litellmGatewayMetrics:\n  enabled: )true(?=[ \t]*(?:#.*)?$)', r'\1false', text)
        if count != 1:
            raise ValueError('metrics flag differs: refusing rollback')
        expected['litellmGatewayMetrics']['enabled'] = False
    else:
        raise ValueError('reviewed metrics rollback closure schema required')
    if yaml.safe_load(text) != expected:
        raise ValueError('rollback changed unrelated values')
    with output.open('x') as target:
        target.write(text)
    print('prepared preceding metrics and Console bindings; compatibility and release pins preserved')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('values', 'closure', 'previous', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.values, args.closure, args.previous, args.output)
