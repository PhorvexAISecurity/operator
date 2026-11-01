"""Read-only final inspection, executed as hami on the authorized stage jump host."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path('/home/hami/phorvex-benchmark')
OUT = ROOT / 'stage-data/live/final-handover'
OUT.mkdir(exist_ok=True)
CONTEXT = 'arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
SOURCE = 'ef94fad362dabb51469211388ef80cdfa6eee1d4'
DIGESTS = {
    'brain': 'sha256:f1e5e306a686388196077aaa8d6f6b398ab7509dedc7a28c1649ae92d604dc90',
    'manager': 'sha256:c8764181c667fcd77f1eaad3c5a49d2e561557e568cff5253ae7f44378959e7e',
}


def run(args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def kube(*args):
    return json.loads(run(['kubectl', '--context', CONTEXT, '--request-timeout=30s', *args]))


def fields(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


receipt = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'context': CONTEXT, 'source': SOURCE, 'scope': 'read-only stage handover',
           'services': {}, 'runtime': {}}
for unit in ['phorvex-benchmark-bot.service', 'phorvex-stage-observer.service',
             'phorvex-stage-endpoint-refresh.timer']:
    status = fields(run(['systemctl', '--user', 'show', unit, '-p', 'ActiveState',
                        '-p', 'SubState', '-p', 'UnitFileState', '-p', 'ActiveEnterTimestamp']))
    assert status['ActiveState'] == 'active' and status['UnitFileState'] == 'enabled', status
    receipt['services'][unit] = status
    receipt['services'][unit]['unit_sha256'] = sha(pathlib.Path.home() / '.config/systemd/user' / unit)
receipt['linger'] = fields(run(['loginctl', 'show-user', 'hami', '-p', 'Linger']))
assert receipt['linger']['Linger'] == 'yes'
for service, name in [('brain', 'staging-brain'), ('manager', 'staging-phorvex')]:
    dep = kube('-n', 'phorvex-staging', 'get', 'deployment', name, '-o', 'json')
    wanted = dep['spec'].get('replicas', 1)
    status = dep['status']
    assert status['observedGeneration'] >= dep['metadata']['generation']
    assert all(status.get(k, 0) == wanted for k in ['replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas'])
    selector = ','.join(k + '=' + v for k, v in dep['spec']['selector']['matchLabels'].items())
    pods = kube('-n', 'phorvex-staging', 'get', 'pods', '-l', selector, '-o', 'json')['items']
    actual = []
    for pod in pods:
        if pod['metadata'].get('deletionTimestamp'):
            continue
        c = next(c for c in pod['status']['containerStatuses'] if c['name'] == service)
        assert c['ready'] and c['imageID'].endswith('@' + DIGESTS[service]), c
        version = kube('-n', 'phorvex-staging', 'exec', pod['metadata']['name'], '-c', service,
                       '--', '/service' if service == 'brain' else '/manager', '--version')
        assert version['gitSHA'] == SOURCE and version['service'] == service, version
        actual.append({'name': pod['metadata']['name'], 'uid': pod['metadata']['uid'],
                       'node': pod['spec']['nodeName'], 'image_id': c['imageID'], 'version': version})
    assert len(actual) == wanted
    receipt['runtime'][service] = {'deployment': name, 'uid': dep['metadata']['uid'],
                                   'status': status, 'pods': actual}
fixture = kube('-n', 'phorvex-staging-demo', 'get', 'deployment', 'stage-bench-api', '-o', 'json')
assert fixture['metadata']['uid'] == 'be5030d0-6ab8-4b2f-9921-29876f856248'
assert fixture['spec']['replicas'] == 3 and fixture['status'].get('readyReplicas') == 3
pods = kube('-n', 'phorvex-staging-demo', 'get', 'pods', '-l', 'app.kubernetes.io/name=stage-bench-api', '-o', 'json')['items']
active = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
assert len(active) == 3 and all(all(c['ready'] for c in p['status']['containerStatuses']) for p in active)
receipt['fixture'] = {'uid': fixture['metadata']['uid'], 'ready': 3,
                      'pods': [{'name': p['metadata']['name'], 'uid': p['metadata']['uid'], 'node': p['spec']['nodeName']} for p in active]}
receipt['disk_free_bytes'] = shutil.disk_usage(ROOT).free
assert receipt['disk_free_bytes'] >= 4 * (1 << 30)
receipt['repo'] = {'head': run(['git', '-C', str(ROOT / 'operator-refactored'), 'rev-parse', 'HEAD']),
                   'clean': not run(['git', '-C', str(ROOT / 'operator-refactored'), 'status', '--porcelain'])}
assert receipt['repo']['head'] == 'ec310e276e45e6a218f7520880e22c6c1c687817' and receipt['repo']['clean']
receipt['code_retry'] = json.loads((ROOT / 'stage-data/live/code-bot-retry/acceptance-status.json').read_text())
assert receipt['code_retry']['state'] == 'PASS'
receipt['refresh_at_inspection'] = json.loads((ROOT / 'stage-data/mathlab/endpoint-refresh/phorvex-staging-demo/stage-bench-defense.status.json').read_text())
receipt['result'] = 'PASS_SERVICES_AND_RUNTIME; refresh recovery verified separately'
path = OUT / 'runtime.json'
path.write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'path': str(path), 'sha256': sha(path), 'result': receipt['result'],
                  'free_gib': round(receipt['disk_free_bytes'] / (1 << 30), 3),
                  'refresh_state': receipt['refresh_at_inspection']['state']}))
