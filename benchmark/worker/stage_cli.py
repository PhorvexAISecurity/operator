#!/usr/bin/env python3
"""Pin, sync and inspect actual stage brain data without changing the cluster."""
import argparse
from contextlib import ExitStack
import json
import re
import subprocess
import tempfile
import shutil
from pathlib import Path

from mathlab import binary, snapshots, stage_scope
from mathlab.common import read_json, utc, write_json, sha256_file
from mathlab_cli import inspect_latest


def kube(context, namespace, *args):
    if not context:
        raise stage_scope.StageError('an explicit Kubernetes context is required')
    stage_scope.namespace(namespace)
    result = subprocess.run(['kubectl', '--context', context, '-n', namespace, *args],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise stage_scope.StageError('stage Kubernetes read failed; check context access and object names')
    return json.loads(result.stdout)


def running_image(context, namespace, deployment, container):
    dep = kube(context, namespace, 'get', 'deployment', deployment, '-o', 'json')
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
    replicas = kube(context, namespace, 'get', 'replicasets', '-o', 'json')
    revision = dep['metadata'].get('annotations', {}).get('deployment.kubernetes.io/revision')
    owned = {r['metadata']['uid'] for r in replicas.get('items', []) if revision and
        r['metadata'].get('annotations', {}).get('deployment.kubernetes.io/revision') == revision and any(
            o.get('uid') == dep['metadata']['uid'] and o.get('controller') for o in r['metadata'].get('ownerReferences', []))}
    pods = kube(context, namespace, 'get', 'pods', '-o', 'json')
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
    if container == 'brain':
        for pod in ready:
            version = kube(context, namespace, 'exec', pod['name'], '-c', container, '--', '/service', '--version')
            if version.get('service') != 'brain' or version.get('gitSHA') != match.group(1):
                raise stage_scope.StageError('running brain embedded source differs from its pinned image tag')
            embedded = version
    return {'image': spec['image'], 'repository': repository, 'digest': digest, 'image_digest': digest,
            'git_sha': match.group(1), 'deployment': deployment, 'deployment_uid': dep['metadata']['uid'],
            'container': container, 'pods': ready, 'embedded_version': embedded}


def pin_stage(data_dir, repo, context, service_namespace, policy, deployment='staging-brain',
              companion=None, console_service='staging-phorvex-console', console_account=None, console_port=80):
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
    old = read_json(Path(data_dir) / 'mathlab/stage.json', {})
    policies = old.get('policies', {}) if old.get('brain', {}).get('git_sha') == brain['git_sha'] and old.get('kube_context') == context else {}
    policies[policy] = {'uid': pol['metadata']['uid'], 'generation': pol['metadata']['generation']}
    pin = {'schema': stage_scope.SCHEMA, 'repository': stage_scope.REPOSITORY, 'kube_context': context,
           'service_namespace': service_namespace, 'brain': brain, 'policies': policies,
           'replay': {**ident, 'producer': 'same-source-stage-manager-companion' if companion else 'stage-brain-image',
                      'producer_image': producer}, 'installed_at': utc(),
           'console': {'service': console_service, 'service_account': console_account,
                       'port': console_port, 'audience': 'phorvex-staging-console'}}
    # Never leave a new pin pointing at an uninstalled binary. A crash between
    # these writes fails closed because the previous pin and identity disagree.
    write_json(Path(data_dir) / 'mathlab/bin/current.json', ident)
    write_json(Path(data_dir) / 'mathlab/stage.json', pin)
    return pin


def sync_stage(data_dir, repo, policy, progress=None, sync_limit=5000, max_sync_bytes=None):
    ns, name = stage_scope.policy(policy)
    with snapshots.sync_lock(data_dir, ns, name):
        return _sync_stage(data_dir, repo, policy, progress, sync_limit, max_sync_bytes)


def _sync_stage(data_dir, repo, policy, progress, sync_limit, max_sync_bytes):
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
    cfg = pin['console']
    if not cfg.get('service_account'):
        raise stage_scope.StageError('stage Console reader service account is not configured in the pin')
    console = Console(kube_context=pin['kube_context'], namespace=pin['service_namespace'],
                      service=cfg['service'], token_service_account=cfg['service_account'],
                      service_port=cfg['port'], use_environment=False,
                      token_audience=cfg['audience'], token_duration='10m')
    try:
        result = snapshots.sync(data_dir, ns, name, console, progress=progress,
                                expected_header=stage_scope.snapshot_header(pin, policy),
                                limit=sync_limit, max_bytes=max_sync_bytes)
    finally:
        console.close()
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
    pin = stage_scope.load(data_dir, repo=repo)
    if not candidate_path or not base_path or not evidence or not stage_scope.SHA.fullmatch(candidate_source or ''):
        raise stage_scope.StageError('study binary/source, local base binary and independent review evidence are required')
    stage_scope.repository(repo, candidate_source)
    ancestor = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', pin['brain']['git_sha'], candidate_source])
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
    for index, (path, original_digest) in enumerate(originals):
        target = evidence_dir / ('%02d-' % index + path.name)
        shutil.copy2(path, target)
        if sha256_file(target) != original_digest:
            raise stage_scope.StageError('review evidence changed during installation')
        refs.append({'path': str(target), 'sha256': original_digest})
    engine = {'schema': 'phorvex-bench.study-engine.v1', 'base_source': pin['brain']['git_sha'],
              'source_revision': candidate_source, 'candidate': candidate, 'base_local': base,
              'review_evidence': refs, 'review_receipt': receipt, 'installed_at': utc(),
              'classification': 'reviewed-experimental-brain; cross-version offline comparison, not deployed V3'}
    write_json(Path(data_dir) / 'mathlab/study-engine.json', engine)
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
