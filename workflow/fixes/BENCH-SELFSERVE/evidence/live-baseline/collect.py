"""Read-only baseline collector. Prints selected non-secret metadata only."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess

CTX = 'arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
ROOT = Path('/home/hami/phorvex-benchmark')
commands = []

def run(args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    commands.append({'argv': args, 'rc': p.returncode})
    return {'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr[-1200:]}

def kube(*args):
    r = run(['kubectl', '--context', CTX, *args, '--request-timeout=20s'])
    if r['rc']:
        return {'error': r}
    return json.loads(r['stdout'])

def ident(obj):
    m = obj.get('metadata', {})
    return {k: m.get(k) for k in ('name', 'namespace', 'uid', 'generation', 'resourceVersion')}

def source(s):
    h = s.get('helm', {})
    result = {k: s.get(k) for k in ('repoURL', 'targetRevision', 'path', 'ref') if k in s}
    result['helm'] = {k: h.get(k) for k in ('releaseName', 'valueFiles', 'parameters') if k in h}
    # Values can include unrelated private configuration: retain only capture/image keys.
    if 'valuesObject' in h:
        result['helm']['valuesObject_keys'] = sorted(h['valuesObject'])
    if 'values' in h:
        result['helm']['inline_values_sha256'] = hashlib.sha256(h['values'].encode()).hexdigest()
        result['helm']['inline_capture_lines'] = [l for l in h['values'].splitlines() if any(w in l.lower() for w in ('mathlab', 'capture', 'existingclaim', 'benchmark'))]
    return result

result = {'schema': 'phorvex-bench.selfserve-live-baseline.v1', 'read_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'context': CTX}
appsets = kube('get', 'applicationsets', '-n', 'argocd', '-o', 'json')
result['applicationsets'] = []
for app in appsets.get('items', []):
    if app['metadata']['name'] != 'phorvex-services':
        continue
    spec = app['spec']
    result['applicationsets'].append({'identity': ident(app), 'generators': spec.get('generators'), 'sources': [source(s) for s in spec['template']['spec'].get('sources', [])], 'templatePatch': spec.get('templatePatch'), 'template_syncPolicy': spec['template']['spec'].get('syncPolicy')})
apps = kube('get', 'applications', '-n', 'argocd', '-o', 'json')
result['stage_applications'] = [{'identity': ident(a), 'destination': a['spec'].get('destination'), 'sources': [source(s) for s in a['spec'].get('sources', [])], 'sync': a.get('status', {}).get('sync'), 'health': a.get('status', {}).get('health')} for a in apps.get('items', []) if a['metadata']['name'] in ('phorvex-brain-staging', 'phorvex-manager-staging', 'phorvex-console-staging')]
deployments = kube('get', 'deployments', '-n', 'phorvex-staging', '-o', 'json')
result['deployments'] = []
names = []
for d in deployments.get('items', []):
    if d['metadata']['name'] not in ('staging-brain', 'staging-phorvex-manager', 'staging-console'):
        continue
    names.append(d['metadata']['name'])
    spec = d['spec']['template']['spec']
    containers = []
    for c in spec['containers']:
        args = c.get('args', [])
        containers.append({'name': c['name'], 'image': c['image'], 'command': c.get('command'), 'argument_count': len(args), 'capture_args': [a for a in args if any(k in a for k in ('math-lab', 'brain-service', 'brain-endpoint'))], 'volumeMounts': c.get('volumeMounts'), 'identity_environment': [e for e in c.get('env', []) if e.get('name') in ('BRAIN_IMAGE', 'PHORVEX_BRAIN_IMAGE', 'PHORVEX_CAPTURE_IDENTITY', 'MATHLAB_CAPTURE_IDENTITY', 'PHORVEX_CAPTURE_BRAIN_IMAGE')]})
    result['deployments'].append({'identity': ident(d), 'selector': d['spec']['selector'], 'replicas': d['spec'].get('replicas'), 'ready_replicas': d.get('status', {}).get('readyReplicas'), 'serviceAccountName': spec.get('serviceAccountName'), 'volumes': spec.get('volumes'), 'containers': containers})
pods = kube('get', 'pods', '-n', 'phorvex-staging', '-o', 'json')
result['pods'] = []
for p in pods.get('items', []):
    if not any(p['metadata']['name'].startswith(n + '-') for n in names):
        continue
    obj = {'identity': ident(p), 'nodeName': p['spec'].get('nodeName'), 'phase': p.get('status', {}).get('phase'), 'containers': [{'name': c['name'], 'image': c['image'], 'imageID': c.get('imageID'), 'ready': c.get('ready'), 'restartCount': c.get('restartCount')} for c in p.get('status', {}).get('containerStatuses', [])]}
    if p['metadata']['name'].startswith('staging-brain-'):
        obj['embedded_version'] = run(['kubectl', '--context', CTX, '-n', 'phorvex-staging', 'exec', p['metadata']['name'], '--', '/service', '-version'])
        obj['native_replay_version'] = run(['kubectl', '--context', CTX, '-n', 'phorvex-staging', 'exec', p['metadata']['name'], '--', '/brain-replay', '-version'])
        help_result = run(['kubectl', '--context', CTX, '-n', 'phorvex-staging', 'exec', p['metadata']['name'], '--', '/brain-replay', '-h'])
        obj['native_replay_help'] = {'rc': help_result['rc'], 'lines': [l for l in (help_result['stdout'] + help_result['stderr']).splitlines() if any(w in l for w in ('endpoint-study', 'export-study-candidates', 'allow-cross-version', 'snapshots', 'version'))]}
    elif p['metadata']['name'].startswith('staging-phorvex-manager-'):
        obj['embedded_version'] = run(['kubectl', '--context', CTX, '-n', 'phorvex-staging', 'exec', p['metadata']['name'], '-c', 'manager', '--', '/manager', '-version'])
    result['pods'].append(obj)
pvcs = kube('get', 'pvc', '-n', 'phorvex-staging', '-o', 'json')
result['capture_pvcs'] = [{'identity': ident(p), 'spec': {k: p['spec'].get(k) for k in ('accessModes', 'resources', 'storageClassName', 'volumeMode', 'volumeName')}, 'status': p.get('status')} for p in pvcs.get('items', []) if any(w in p['metadata']['name'] for w in ('brain', 'math', 'capture'))]
sa = kube('get', 'serviceaccounts', '-n', 'phorvex-staging', '-o', 'json')
result['benchmark_serviceaccounts'] = [ident(s) for s in sa.get('items', []) if any(w in s['metadata']['name'] for w in ('bench', 'console'))]
for resource in ('roles', 'rolebindings'):
    data = kube('get', resource, '-n', 'phorvex-staging', '-o', 'json')
    result[resource] = [{'identity': ident(o), 'rules': o.get('rules'), 'roleRef': o.get('roleRef'), 'subjects': o.get('subjects')} for o in data.get('items', []) if any(w in o['metadata']['name'] for w in ('bench', 'console')) or any(any(w in s.get('name','') for w in ('bench','console')) for s in o.get('subjects',[]))]
pin = ROOT/'stage-data/mathlab/stage.json'
if pin.exists():
    p = json.loads(pin.read_text())
    result['installed_stage_pin'] = {k:p.get(k) for k in ('schema','repository','service_namespace','kube_context','brain','manager','policies','replay','created_at','pinned_at')}
    result['installed_stage_pin_sha256'] = hashlib.sha256(pin.read_bytes()).hexdigest()
journal = ROOT/'stage-data/observer/persistent-ef94-1a70/compressed-evidence.db'
if journal.exists():
    db = sqlite3.connect('file:'+str(journal)+'?mode=ro', uri=True)
    result['observer_scope'] = json.loads(db.execute("SELECT value FROM meta WHERE key='scope'").fetchone()[0])
    result['observer_latest_record'] = db.execute('SELECT seq,at,hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
policy = kube('get', 'phorvexpolicy', 'demo-api-defense', '-n', 'phorvex-staging-demo', '-o', 'json')
result['requested_policy'] = {'identity': ident(policy), 'selector': policy.get('spec', {}).get('selector'), 'mode': policy.get('spec',{}).get('mode'), 'dryRun': policy.get('spec',{}).get('dryRun'), 'budget': policy.get('spec',{}).get('budget')}
labels = policy.get('spec',{}).get('selector',{}).get('matchLabels',{})
if labels:
    items=kube('get','deployment,statefulset,pod,service','-n','phorvex-staging-demo','-o','json')
    result['requested_mapping']=[]
    for o in items.get('items',[]):
        ol=o['metadata'].get('labels',{})
        template=o.get('spec',{}).get('template',{}).get('metadata',{}).get('labels',{})
        selector=o.get('spec',{}).get('selector',{})
        if all(ol.get(k)==v for k,v in labels.items()) or all(template.get(k)==v for k,v in labels.items()) or (o['kind']=='Service' and all(selector.get(k)==v for k,v in labels.items())):
            result['requested_mapping'].append({'kind':o['kind'],'identity':ident(o),'selector':selector,'owners':o['metadata'].get('ownerReferences'),'replicas':o.get('spec',{}).get('replicas'),'readyReplicas':o.get('status',{}).get('readyReplicas'),'phase':o.get('status',{}).get('phase')})
result['tools'] = {name:shutil.which(name) for name in ('kubectl','crane','docker','aws','python3','go')}
result['releases'] = sorted(p.name for p in (ROOT/'releases').iterdir())
result['commands']=commands
print(json.dumps(result,sort_keys=True))
