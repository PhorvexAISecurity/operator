"""Prepare only four rollback bindings; retain compatible code and release pins."""
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
    if live['enabled'] is not True:
        raise ValueError('active profile must be reviewed before rollback')
    for key in ('configMapName', 'profileSHA256', 'sourceConfigMapName'):
        old = profiles[0][key]
        if live[key] != old or text.count(old) != 1:
            raise ValueError('current source/profile drift: refusing rollback')
        text = text.replace(old, previous[key], 1)
        expected['phorvex']['phorvex']['console']['litellmLive'][key] = previous[key]
    text, count = re.subn(r'(?m)^(litellmGatewayMetrics:\n  enabled: )true(?=[ \t]*(?:#.*)?$)', r'\1false', text)
    if count != 1:
        raise ValueError('metrics flag differs: refusing rollback')
    expected['litellmGatewayMetrics']['enabled'] = False
    if yaml.safe_load(text) != expected:
        raise ValueError('rollback changed unrelated values')
    with output.open('x') as target:
        target.write(text)
    print('prepared four rollback bindings; compatibility and release pins preserved')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('values', 'closure', 'previous', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.values, args.closure, args.previous, args.output)
