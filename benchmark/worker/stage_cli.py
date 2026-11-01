#!/usr/bin/env python3
"""Pin, sync and inspect actual stage brain data without changing the cluster."""
import argparse
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
import json
import re
import subprocess
import tempfile
import shutil
import time
import hashlib
import os
from pathlib import Path

from mathlab import binary, snapshots, stage_scope
from mathlab.common import read_json, utc, write_json, sha256_file
from mathlab_cli import inspect_latest


def kube(context, namespace, *args, timeout=60):
    if not context:
        raise stage_scope.StageError('an explicit Kubernetes context is required')
    stage_scope.namespace(namespace)
    result = subprocess.run(['kubectl', '--context', context, '-n', namespace, *args],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise stage_scope.StageError('stage Kubernetes read failed; check context access and object names')
    return json.loads(result.stdout)


def runtime_inventory(deadline):
    """Two independent namespace reads reuse one authenticated process each."""
    def read(ns,resources):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise stage_scope.StageError('stage runtime observation deadline exceeded')
        return kube(stage_scope.STAGE_CONTEXT,ns,'get',resources,'-o','json',timeout=remaining)
    requests={stage_scope.STAGE_NAMESPACE:'deployments,replicasets,pods,persistentvolumeclaims',
              'phorvex-staging-demo':'deployments,phorvexpolicies,services'}
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending={ns:pool.submit(read,ns,resources) for ns,resources in requests.items()}
        return {ns:future.result() for ns,future in pending.items()}


def inventory_get(inventory,namespace,kind,name=None):
    items=[item for item in inventory[namespace].get('items',[]) if item.get('kind')==kind]
    if name is None:return {'items':items}
    matches=[item for item in items if item.get('metadata',{}).get('name')==name]
    if len(matches)!=1:raise stage_scope.StageError('stage inventory requires one '+kind+'/'+name)
    return matches[0]


def policy_workload(inventory,policy):
    ns,name=stage_scope.policy(policy);workload_name=stage_scope.POLICY_WORKLOADS[policy]
    pol=inventory_get(inventory,ns,'PhorvexPolicy',name)
    workload=inventory_get(inventory,ns,'Deployment',workload_name)
    service=inventory_get(inventory,ns,'Service',workload_name)
    selector=pol.get('spec',{}).get('selector',{})
    if (not selector.get('matchLabels') or selector.get('matchExpressions') or
            selector!=workload['spec'].get('selector') or service.get('spec',{}).get('selector')!=selector.get('matchLabels')):
        raise stage_scope.StageError('POLICY_WORKLOAD_SCOPE_CHANGED: policy/workload/service selectors no longer match the fixed scope')
    return {'uid':pol['metadata']['uid'],'generation':pol['metadata']['generation'],'mode':pol.get('spec',{}).get('mode'),
            'selector':selector,'workload_name':workload_name,'workload_uid':workload['metadata']['uid'],
            'workload_generation':workload['metadata']['generation'],'service_name':service['metadata']['name'],
            'service_uid':service['metadata']['uid']}


def running_image(context, namespace, deployment, container, deadline=None, inventory=None):
    def read(*args):
        if inventory is not None and args[0]=='get':
            kind={'deployment':'Deployment','replicasets':'ReplicaSet','pods':'Pod'}[args[1]]
            return inventory_get(inventory,namespace,kind,args[2] if args[1]=='deployment' else None)
        if deadline is None:
            return kube(context, namespace, *args)
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise stage_scope.StageError('stage runtime observation deadline exceeded')
        return kube(context, namespace, *args, timeout=min(60, remaining))
    dep = read('get', 'deployment', deployment, '-o', 'json')
    wanted = dep['spec'].get('replicas', 1)
    status = dep.get('status', {})
    if wanted < 1 or any(status.get(key, 0) != wanted for key in ('updatedReplicas', 'readyReplicas', 'availableReplicas', 'replicas')):
        raise stage_scope.StageError('stage deployment rollout is incomplete; all desired replicas must be updated, ready and available')
    containers = {c['name']: c for c in dep['spec']['template']['spec']['containers']}
    spec = containers.get(container)
    if not spec or '@sha256:' not in spec['image']:
        raise stage_scope.StageError('stage deployment must pin the requested container by immutable image digest')
    image, digest = spec['image'].split('@', 1)
    repository, tag = image.rsplit(':', 1) if ':' in image.rsplit('/', 1)[-1] else (image, '')
    match = re.search(r'-git-([0-9a-f]{40})$', tag)
    if not match or not stage_scope.DIGEST.fullmatch(digest):
        raise stage_scope.StageError('stage image must carry a full source SHA tag and immutable digest')
    replicas = read('get', 'replicasets', '-o', 'json')
    revision = dep['metadata'].get('annotations', {}).get('deployment.kubernetes.io/revision')
    owned = {r['metadata']['uid'] for r in replicas.get('items', []) if revision and
        r['metadata'].get('annotations', {}).get('deployment.kubernetes.io/revision') == revision and any(
            o.get('uid') == dep['metadata']['uid'] and o.get('controller') for o in r['metadata'].get('ownerReferences', []))}
    pods = read('get', 'pods', '-o', 'json')
    ready = []
    for pod in pods.get('items', []):
        if not any(o.get('uid') in owned and o.get('controller') for o in pod['metadata'].get('ownerReferences', [])):
            continue
        if pod['metadata'].get('deletionTimestamp') or pod.get('status', {}).get('phase') != 'Running':
            continue
        by_name = {s['name']: s for s in pod.get('status', {}).get('containerStatuses', [])}
        actual = by_name.get(container) or {}
        if not actual.get('ready') or not actual.get('imageID', '').endswith('@' + digest):
            raise stage_scope.StageError('stage deployment is rolling out or runtime image digest differs; wait for rollout')
        ready.append({'name': pod['metadata']['name'], 'uid': pod['metadata']['uid']})
    if len(ready) != wanted or status.get('observedGeneration', 0) < dep['metadata']['generation']:
        raise stage_scope.StageError('stage deployment has no ready observed image')
    embedded = None
    if container in ('brain', 'manager'):
        for pod in ready:
            version = read('exec', pod['name'], '-c', container, '--',
                           '/service' if container == 'brain' else '/manager', '--version')
            if version.get('service') != container or version.get('gitSHA') != match.group(1):
                raise stage_scope.StageError('running ' + container + ' embedded source differs from its pinned image tag')
            embedded = version
    return {'image': spec['image'], 'repository': repository, 'digest': digest, 'image_digest': digest,
            'git_sha': match.group(1), 'deployment': deployment, 'deployment_uid': dep['metadata']['uid'],
            'container': container, 'pods': ready, 'embedded_version': embedded}


def capture_configuration(context, service_namespace, deadline=None, inventory=None):
    def read(name):
        if inventory is not None:return inventory_get(inventory,service_namespace,'Deployment',name)
        remaining = 60 if deadline is None else min(60, deadline-time.monotonic())
        if remaining <= 0:
            raise stage_scope.StageError('stage runtime observation deadline exceeded')
        return kube(context, service_namespace, 'get', 'deployment', name, '-o', 'json', timeout=remaining)
    brain, manager = read('staging-brain'), read('staging-phorvex')
    bc = next(c for c in brain['spec']['template']['spec']['containers'] if c['name'] == 'brain')
    mc = next(c for c in manager['spec']['template']['spec']['containers'] if c['name'] == 'manager')
    flags = {}
    for arg in bc.get('args', []):
        if arg.startswith('--math-lab-'):
            key, sep, value = arg.partition('=')
            if not sep or key in flags:
                raise stage_scope.StageError('stage capture flags are ambiguous or duplicated')
            flags[key] = value
    policies = flags.get('--math-lab-capture-policies', '').split(',')
    policies = [p for p in policies if p]
    if len(set(policies)) != len(policies):
        raise stage_scope.StageError('stage capture policy list is duplicated or ambiguous')
    directory = flags.get('--math-lab-capture-dir')
    mounts = [m for m in bc.get('volumeMounts', []) if m.get('mountPath') == directory and not m.get('readOnly')]
    volumes = {v['name']: v for v in brain['spec']['template']['spec'].get('volumes', [])}
    claim = (volumes.get(mounts[0]['name'], {}).get('persistentVolumeClaim', {}).get('claimName')
             if len(mounts) == 1 else None)
    cost_flags = [a for a in mc.get('args', []) if a.split('=', 1)[0] == '--math-lab-capture-cost-evidence']
    if len(cost_flags) > 1:
        raise stage_scope.StageError('manager cost-evidence flags are duplicated or ambiguous')
    claim_uid=None
    if claim:
        remaining=60 if deadline is None else deadline-time.monotonic()
        if remaining <= 0:raise stage_scope.StageError('stage runtime observation deadline exceeded')
        pvc=(inventory_get(inventory,service_namespace,'PersistentVolumeClaim',claim) if inventory is not None else
             kube(context,service_namespace,'get','pvc',claim,'-o','json',timeout=remaining))
        if pvc.get('status',{}).get('phase')!='Bound':
            raise stage_scope.StageError('stage capture persistent claim is not Bound')
        claim_uid=pvc['metadata']['uid']
    return {'enabled': bool(policies), 'policies': policies, 'directory': directory,
            'persistent_claim': claim, 'persistent_claim_uid':claim_uid,
            'cost_evidence': cost_flags == ['--math-lab-capture-cost-evidence=true']}


def probe_runtime(data_dir, repo, policy, timeout=60):
    """Bounded, read-only readiness observation. Never fetches, pins or syncs."""
    if not 1 <= timeout <= 60:
        raise ValueError('runtime probe timeout must be 1..60 seconds')
    deadline = time.monotonic()+timeout
    result = {'schema': 'phorvex-bench.runtime-readiness.v1', 'status': 'BLOCKED',
              'requested_policy': policy, 'reasons': [], 'pin_sha256': None, 'actual_brain': None,
              'policy': None, 'capture': None, 'available_policies': [],
              'allowed_policies': list(stage_scope.ALLOWED_POLICIES)}
    def blocked(code, message, recovery):
        result['reasons'].append({'code': code, 'message': message, 'recovery': recovery})
    if policy not in stage_scope.ALLOWED_POLICIES:
        blocked('POLICY_NOT_ALLOWED', 'requested policy is outside the configured stage allowlist',
                'Choose one of allowed_policies; uploads cannot expand cluster scope.')
        return result
    path = Path(data_dir)/'mathlab/stage.json'
    try:
        with stage_scope.pin_lock(data_dir, timeout=max(0, deadline-time.monotonic()), readonly=True) as leased:
            if not leased:
                blocked('RECONCILIATION_REQUIRED', 'stage reconciliation lease is not initialized', 'Run the configured stage reconciliation service.')
            if path.is_file():
                result['pin_sha256'] = sha256_file(path)
            try:
                pin = stage_scope.load(data_dir)
                result['available_policies'] = sorted(set(pin.get('policies', {})) & set(stage_scope.ALLOWED_POLICIES))
            except stage_scope.StageError as error:
                pin = None
                blocked('STAGE_PIN_MISSING', str(error), 'Run the configured stage reconciliation service.')
            if pin and (pin.get('kube_context') != stage_scope.STAGE_CONTEXT or pin.get('service_namespace') != stage_scope.STAGE_NAMESPACE):
                blocked('STAGE_SCOPE_MISMATCH', 'installed pin names a different stage context/namespace', 'Reconcile against the fixed approved stage context.')
            inventory=runtime_inventory(deadline)
            actual = running_image(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE, 'staging-brain', 'brain', deadline=deadline,inventory=inventory)
            result['actual_brain'] = actual
            ns, name = stage_scope.policy(policy)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise stage_scope.StageError('stage runtime observation deadline exceeded')
            result['policy']=policy_workload(inventory,policy)
            result['policy']['dry_run']=result['policy']['mode']=='dryRun'
            if pin:
                installed = pin.get('policies', {}).get(policy)
                if not installed:
                    blocked('POLICY_NOT_PINNED', 'requested policy is not in the installed stage capture pin', 'Run stage reconciliation for this allowed policy; do not substitute another policy.')
                elif installed.get('uid') != result['policy']['uid']:
                    blocked('POLICY_UID_CHANGED', 'requested policy was recreated after pin installation', 'Reconcile its new UID and gather new matching snapshots.')
                elif installed.get('generation') != result['policy']['generation']:
                    blocked('POLICY_GENERATION_CHANGED', 'requested policy specification changed after pin installation', 'Reconcile its current generation and capture fresh matching snapshots.')
                if installed and installed.get('workload_uid') and any(installed.get(k) != result['policy'].get(k) for k in ('workload_uid','workload_generation')):
                    blocked('WORKLOAD_IDENTITY_CHANGED', 'target workload identity/generation differs from installed evidence', 'Reconcile the workload and establish a new qualified endpoint observation segment.')
                if installed and installed.get('service_uid')!=result['policy'].get('service_uid'):
                    blocked('SERVICE_IDENTITY_CHANGED','target Service UID differs from installed evidence','Reconcile the Service identity and start a fresh observation scope; old reports remain historical.')
                if any(actual.get(k) != pin['brain'].get(k) for k in ('git_sha', 'image', 'image_digest', 'deployment_uid')):
                    blocked('STAGE_SOURCE_CHANGED', 'running stage source/image/UID differs from installed pin', 'Run stage reconciliation; preserve older cohorts as historical.')
                try:
                    stage_scope.identity(data_dir, pin)
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise stage_scope.StageError('stage runtime observation deadline exceeded')
                    stage_scope.repository(repo, actual['git_sha'], timeout=remaining,complete_tree=True)
                except (stage_scope.StageError, OSError, subprocess.TimeoutExpired) as error:
                    blocked('REPLAY_SOURCE_UNAVAILABLE', str(error), 'Reconcile the exact deployed source and image-extracted replay.')
            capture = capture_configuration(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE, deadline,inventory=inventory)
            result['capture'] = capture
            if pin and pin.get('manager'):
                manager = running_image(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE,
                                        'staging-phorvex', 'manager', deadline=deadline,inventory=inventory)
                result['actual_manager'] = manager
                if any(manager.get(k) != pin['manager'].get(k) for k in ('git_sha', 'image', 'image_digest', 'deployment_uid')):
                    blocked('STAGE_MANAGER_CHANGED', 'running manager source/image/UID differs from installed evidence pin', 'Run stage reconciliation after the manager rollout; cost evidence cannot inherit a different producer.')
            if not capture['enabled'] or policy not in capture['policies']:
                blocked('CAPTURE_DISABLED', 'requested policy is not enabled in the actual stage brain capture flags', 'An operator must apply reviewed durable staging capture values; requests never patch the cluster.')
            if not capture['persistent_claim']:
                blocked('CAPTURE_STORAGE_UNAVAILABLE', 'stage capture has no writable persistent claim mount', 'Restore the approved stage capture PVC through reviewed staging values.')
            if not capture['cost_evidence']:
                blocked('COST_EVIDENCE_DISABLED', 'manager cost-evidence capture is disabled', 'Restore the reviewed staging manager capture-cost-evidence setting.')
            if result['pin_sha256'] != (sha256_file(path) if path.is_file() else None):
                blocked('STAGE_PIN_CHANGED', 'pin changed during readiness observation', 'Retry against one stable installed pin.')
    except (stage_scope.StageError, OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        blocked('RUNTIME_OBSERVATION_UNAVAILABLE', str(error), 'Check stage access/rollout and retry bounded readiness; no cluster mutation was attempted.')
    result['status'] = 'READY' if not result['reasons'] else 'BLOCKED'
    return result


def durable_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.stage-pin-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def publish_pin(data_dir, pin):
    """Caller holds EX lease. One atomic pointer; old identities stay usable."""
    path = Path(data_dir)/'mathlab/stage.json'
    if path.is_file():
        old = read_json(path)
        history = path.parent/'pin-history'/(sha256_file(path)+'.json')
        if history.exists():
            if read_json(history) != old:
                raise stage_scope.StageError('historical stage pin evidence changed')
        else:
            durable_json(history, old)
    durable_json(path, pin)


def pin_stage(data_dir, repo, context, service_namespace, policy, deployment='staging-brain',
              companion=None, console_service='staging-phorvex-console', console_account=None, console_port=80):
    with stage_scope.pin_lock(data_dir, exclusive=True):
        return _pin_stage(data_dir, repo, context, service_namespace, policy, deployment,
                          companion, console_service, console_account, console_port)


def _pin_stage(data_dir, repo, context, service_namespace, policy, deployment,
               companion, console_service, console_account, console_port):
    existing = Path(data_dir) / 'mathlab/snapshots'
    if existing.exists():
        for child in existing.iterdir():
            if child.is_dir():
                try:
                    stage_scope.namespace(child.name)
                except stage_scope.StageError as error:
                    raise stage_scope.StageError('this directory contains a legacy or production corpus; choose a separate stage data directory') from error
    ns, name = stage_scope.policy(policy)
    brain = running_image(context, service_namespace, deployment, 'brain')
    manager = running_image(context, service_namespace, 'staging-phorvex', 'manager')
    if manager['git_sha'] != brain['git_sha']:
        raise stage_scope.StageError('stage manager and brain source differ')
    stage_scope.repository(repo, brain['git_sha'])
    if not brain['repository'].endswith('/phorvex/staging/brain'):
        raise stage_scope.StageError('brain image is outside the isolated staging repository')
    producer = brain
    if companion:
        producer = running_image(context, service_namespace, companion, 'manager')
        if producer['git_sha'] != brain['git_sha'] or not producer['repository'].endswith('/phorvex/staging/manager'):
            raise stage_scope.StageError('companion replay must be the same source as stage brain, from the staging manager image')
    ident = binary.ensure_binary(data_dir, producer)
    if ident.get('git_sha') != brain['git_sha']:
        raise stage_scope.StageError('extracted replay embedded source differs from stage brain image source')
    pol = kube(context, ns, 'get', 'phorvexpolicy', name, '-o', 'json')
    capture = capture_configuration(context, service_namespace)
    if policy not in capture['policies'] or not capture['persistent_claim'] or not capture['cost_evidence']:
        raise stage_scope.StageError('stage capture/PVC/cost-evidence configuration is unavailable; restore reviewed stage values before pinning')
    old = read_json(Path(data_dir) / 'mathlab/stage.json', {})
    policies = old.get('policies', {}) if old.get('brain', {}).get('git_sha') == brain['git_sha'] and old.get('kube_context') == context else {}
    policies[policy] = {'uid': pol['metadata']['uid'], 'generation': pol['metadata']['generation'],
                        'mode': pol.get('spec', {}).get('mode')}
    pin = {'schema': stage_scope.SCHEMA, 'repository': stage_scope.REPOSITORY, 'kube_context': context,
           'service_namespace': service_namespace, 'brain': brain, 'manager': manager, 'policies': policies,
           'replay': {**ident, 'producer': 'same-source-stage-manager-companion' if companion else 'stage-brain-image',
                      'producer_image': producer}, 'installed_at': utc(),
           'identity_binding': 'stage-pin.replay.v1', 'capture': capture,
           'console': {'service': console_service, 'service_account': console_account,
                       'port': console_port, 'audience': 'phorvex-staging-console'}}
    # Revalidate the live identity immediately before one atomic publication.
    actual = running_image(context, service_namespace, deployment, 'brain')
    if any(actual.get(k) != brain.get(k) for k in ('git_sha', 'image', 'digest', 'deployment_uid')):
        raise stage_scope.StageError('stage brain changed before pin publication')
    live = kube(context, ns, 'get', 'phorvexpolicy', name, '-o', 'json')
    if (live['metadata']['uid'] != policies[policy]['uid'] or live['metadata'].get('generation') != policies[policy]['generation']
            or live.get('spec', {}).get('mode') != policies[policy]['mode']):
        raise stage_scope.StageError('stage policy changed before pin publication')
    live_manager = running_image(context, service_namespace, 'staging-phorvex', 'manager')
    if any(live_manager.get(k) != manager.get(k) for k in ('git_sha', 'image', 'image_digest', 'deployment_uid')):
        raise stage_scope.StageError('stage manager changed before pin publication')
    if capture_configuration(context, service_namespace) != capture:
        raise stage_scope.StageError('stage capture configuration changed before pin publication')
    publish_pin(data_dir, pin)
    return pin


def sync_stage(data_dir, repo, policy, progress=None, sync_limit=5000, max_sync_bytes=None,
               recent_seconds=None, recent_progress_root=None):
    ns, name = stage_scope.policy(policy)
    with stage_scope.pin_lock(data_dir), snapshots.sync_lock(data_dir, ns, name):
        return _sync_stage(data_dir, repo, policy, progress, sync_limit, max_sync_bytes,
                           recent_seconds, recent_progress_root)


def _sync_stage(data_dir, repo, policy, progress, sync_limit, max_sync_bytes,
                recent_seconds=None, recent_progress_root=None):
    from runner import Console
    pin = stage_scope.load(data_dir, policy, repo)
    ident = stage_scope.identity(data_dir, pin)
    actual = running_image(pin['kube_context'], pin['service_namespace'], pin['brain']['deployment'], 'brain')
    if (actual['git_sha'], actual['image'], actual['digest'], actual['deployment_uid']) != (
            pin['brain']['git_sha'], pin['brain']['image'], pin['brain']['digest'], pin['brain']['deployment_uid']):
        raise stage_scope.StageError('running stage brain changed; install its new pin before synchronizing')
    ns, name = stage_scope.policy(policy)
    live_policy = kube(pin['kube_context'], ns, 'get', 'phorvexpolicy', name, '-o', 'json')
    if live_policy['metadata']['uid'] != pin['policies'][policy]['uid']:
        raise stage_scope.StageError('stage policy was recreated; install its new UID pin')
    if pin.get('identity_binding') == 'stage-pin.replay.v1' and live_policy['metadata'].get('generation') != pin['policies'][policy]['generation']:
        raise stage_scope.StageError('stage policy generation changed; reconcile before synchronizing')
    cfg = pin['console']
    if not cfg.get('service_account'):
        raise stage_scope.StageError('stage Console reader service account is not configured in the pin')
    console = Console(kube_context=pin['kube_context'], namespace=pin['service_namespace'],
                      service=cfg['service'], token_service_account=cfg['service_account'],
                      service_port=cfg['port'], use_environment=False,
                      token_audience=cfg['audience'], token_duration='10m')
    try:
        if recent_seconds is None:
            result = snapshots.sync(data_dir, ns, name, console, progress=progress,
                                    expected_header=stage_scope.snapshot_header(pin, policy),
                                    limit=sync_limit, max_bytes=max_sync_bytes)
        else:
            from mathlab import recent_snapshots
            result = recent_snapshots.sync(data_dir, ns, name, console, progress=progress,
                expected_header=stage_scope.snapshot_header(pin, policy), scope=pin['policies'][policy],
                progress_root=recent_progress_root or Path(data_dir)/'mathlab/recent-inventory',
                recent_seconds=recent_seconds, limit=sync_limit, max_bytes=max_sync_bytes)
    finally:
        console.close()
    if result.get('latest_scan_complete') is False:
        return result
    # Shared sync has ended. Registration uses a separate exclusive section;
    # it never claims older, foreign or preexisting unowned cache entries.
    from endpoint_refresh import register_downloads
    with snapshots.cache_lock(data_dir, ns, name, exclusive=True):
        register_downloads(data_dir, pin, policy, result['downloaded_digests'])
    inspect_latest(data_dir, ns, name, ident, expected_header=stage_scope.snapshot_header(pin, policy))
    return result


def readiness(data_dir, repo, policy, verify_replay=False):
    ns, name = stage_scope.policy(policy)
    with ExitStack() as readers:
        readers.enter_context(snapshots.cache_lock(data_dir, ns, name))
        return _readiness(data_dir, repo, policy, verify_replay, readers.close)


def _readiness(data_dir, repo, policy, verify_replay, release_cache):
    from mathlab.experiment import select_cohort
    data_dir = Path(data_dir).resolve()
    pin = stage_scope.load(data_dir, policy, repo)
    ident = stage_scope.identity(data_dir, pin)
    ns, name = stage_scope.policy(policy)
    entries = select_cohort(data_dir, {'namespace': ns, 'policy': name,
                            'cohort': {**stage_scope.cohort_filter(pin, policy),
                                       'max_snapshots': 64}})
    provenance = stage_scope.cohort(pin, policy, entries)
    unready = sum(bool(e['header'].get('unreplayableFields')) for e in entries)
    result = {'status': 'BLOCKED' if unready else 'DATA_AVAILABLE', 'ticks': len(entries), 'first': entries[0]['header']['capturedAt'],
            'last': entries[-1]['header']['capturedAt'], 'provenance': provenance,
            'unreplayable': unready, 'baseline_validation': 'NOT_RUN',
            'scope': 'stage recorded replay only; endpoint/history readiness is checked separately'}
    if verify_replay and not unready:
        parent = Path(data_dir) / 'mathlab/readiness'; parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='baseline-', dir=parent) as tmp:
            tmp = Path(tmp); frozen = tmp / 'cohort'; frozen.mkdir()
            for entry in entries:
                source = Path(data_dir) / 'mathlab/snapshots' / policy / (entry['digest'] + '.pxms')
                target = frozen / source.name
                shutil.copy2(source, target)
                if sha256_file(target) != entry['digest']:
                    raise stage_scope.StageError('stage snapshot digest mismatch')
            release_cache()
            binary.run_isolated([ident['path'], '-snapshots', str(frozen), '-out', str(tmp / 'replay.jsonl'),
                                 '-summary', str(tmp / 'summary.json')], timeout=300)
            rows = [json.loads(line) for line in (tmp / 'replay.jsonl').read_text().splitlines() if line.strip()]
            exact = len(rows) == len(entries) and all(row.get('status') == 'OK' and
                (row.get('baseline_check') or {}).get('reproduced') is True for row in rows)
            result.update(status='READY' if exact else 'BLOCKED', baseline_validation='EXACT' if exact else 'DIVERGED',
                          replay_summary=read_json(tmp / 'summary.json'), snapshot_digests=[e['digest'] for e in entries])
        write_json(parent / (policy.replace('/', '--') + '.json'), result)
    return result


def install_study_engine(data_dir, repo, candidate_path, candidate_source, base_path, evidence):
    with stage_scope.pin_lock(data_dir, exclusive=True):
        return _install_study_engine(data_dir, repo, candidate_path, candidate_source, base_path, evidence)


def _install_study_engine(data_dir, repo, candidate_path, candidate_source, base_path, evidence):
    pin = stage_scope.load(data_dir, repo=repo)
    if not candidate_path or not base_path or not evidence or not stage_scope.SHA.fullmatch(candidate_source or ''):
        raise stage_scope.StageError('study binary/source, local base binary and independent review evidence are required')
    stage_scope.repository(repo, candidate_source)
    ancestor = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', pin['brain']['git_sha'], candidate_source],
                              env=stage_scope.observation_git_env(), timeout=30, capture_output=True)
    if ancestor.returncode:
        raise stage_scope.StageError('experimental brain must descend from the pinned stage source')
    candidate = binary.local_identity(Path(candidate_path).resolve())
    base = binary.local_identity(Path(base_path).resolve())
    if candidate.get('git_sha') != candidate_source or base.get('git_sha') != pin['brain']['git_sha']:
        raise stage_scope.StageError('experimental/local-base binaries do not carry their actual declared source revisions')
    originals = []
    receipts = []
    for path in evidence:
        path = Path(path).resolve()
        if not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
            raise stage_scope.StageError('review evidence must be a nonempty bounded file')
        originals.append((path, sha256_file(path)))
        try:
            value = json.loads(path.read_text())
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict) and value.get('schema') == 'phorvex-bench.study-engine-review.v1':
            receipts.append((path, value))
    if len(receipts) != 1:
        raise stage_scope.StageError('provide exactly one structured phorvex-bench.study-engine-review.v1 receipt plus its evidence files')
    receipt_path, receipt = receipts[0]
    expected = {'result': 'PASS', 'source_revision': candidate_source, 'base_source': pin['brain']['git_sha'],
                'candidate_binary_sha256': candidate['binary_sha256'], 'base_binary_sha256': base['binary_sha256']}
    bound_evidence = {digest for path, digest in originals if path != receipt_path}
    if (any(receipt.get(key) != value for key, value in expected.items()) or
            not isinstance(receipt.get('reviewer'), str) or not receipt['reviewer'].strip() or
            not bound_evidence or not isinstance(receipt.get('evidence_sha256'), list) or
            any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in receipt['evidence_sha256']) or
            set(receipt['evidence_sha256']) != bound_evidence):
        raise stage_scope.StageError('review PASS receipt does not bind these exact source revisions, binary hashes and evidence files')
    refs = []
    evidence_dir = Path(data_dir).resolve() / 'mathlab/study-engine-evidence' / candidate_source
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for path, original_digest in originals:
        target = evidence_dir / (original_digest + '-' + path.name)
        if not target.exists():
            fd,temporary=tempfile.mkstemp(prefix='.review-',dir=evidence_dir)
            try:
                with os.fdopen(fd,'wb') as dest,path.open('rb') as source:
                    shutil.copyfileobj(source,dest);dest.flush();os.fsync(dest.fileno())
                if sha256_file(temporary)!=original_digest:
                    raise stage_scope.StageError('review evidence changed during installation')
                os.replace(temporary,target)
                directory=os.open(evidence_dir,os.O_DIRECTORY)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:
                if os.path.exists(temporary):os.unlink(temporary)
        if sha256_file(target) != original_digest:
            raise stage_scope.StageError('review evidence changed during installation')
        refs.append({'path': str(target), 'sha256': original_digest})
    engine = {'schema': 'phorvex-bench.study-engine.v1', 'base_source': pin['brain']['git_sha'],
              'source_revision': candidate_source, 'candidate': candidate, 'base_local': base,
              'review_evidence': refs, 'review_receipt': receipt, 'installed_at': utc(),
              'classification': 'reviewed-experimental-brain; cross-version offline comparison, not deployed V3'}
    from mathlab.common import sha256_json
    target = Path(data_dir).resolve() / 'mathlab/study-engines' / (sha256_json(engine)+'.json')
    durable_json(target, engine)
    pin.update(study_engine_lane='reviewed-cross-source', study_engine_reference={'path':str(target),'sha256':sha256_file(target)})
    stage_scope.study_engine(data_dir, pin)
    publish_pin(data_dir, pin)
    return engine


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['pin', 'sync', 'readiness', 'install-study-engine'])
    p.add_argument('--data', required=True); p.add_argument('--repo', required=True)
    p.add_argument('--policy', default=stage_scope.DEFAULT_POLICY)
    p.add_argument('--context'); p.add_argument('--service-namespace', default='phorvex-staging')
    p.add_argument('--deployment', default='staging-brain')
    p.add_argument('--companion-deployment')
    p.add_argument('--console-service', default='staging-phorvex-console')
    p.add_argument('--console-account'); p.add_argument('--console-port', type=int, default=80)
    p.add_argument('--verify-replay', action='store_true')
    p.add_argument('--sync-limit', type=int, default=5000); p.add_argument('--max-sync-bytes', type=int)
    p.add_argument('--study-binary'); p.add_argument('--study-source'); p.add_argument('--base-binary')
    p.add_argument('--review-evidence', action='append', default=[])
    a = p.parse_args()
    try:
        if a.command == 'pin':
            result = pin_stage(a.data, a.repo, a.context, a.service_namespace, a.policy, a.deployment,
                               a.companion_deployment, a.console_service, a.console_account, a.console_port)
        elif a.command == 'sync': result = sync_stage(a.data, a.repo, a.policy, sync_limit=a.sync_limit, max_sync_bytes=a.max_sync_bytes)
        elif a.command == 'install-study-engine':
            result = install_study_engine(a.data, a.repo, a.study_binary, a.study_source, a.base_binary, a.review_evidence)
        else: result = readiness(a.data, a.repo, a.policy, a.verify_replay)
        print(json.dumps(result, indent=2)); return 0
    except (ValueError, OSError, binary.BinaryError) as error:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(error)})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
