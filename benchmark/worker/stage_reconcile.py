#!/usr/bin/env python3
"""Reconcile the fixed stage capture into verified local replay data.

Cluster operations are reads only. Git fetch obtains exact source objects;
the checkout, cluster configuration, policies and old journals never change.
"""
import argparse
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

import stage_cli
from mathlab import binary, snapshots, stage_scope
from mathlab.common import read_json, sha256_file, sha256_json, utc, write_json
from endpoint_refresh import exact_baseline, json_lines, register_downloads, run_replay, wall_limit, RefreshBlocked, bytes_in, prune_cache, clock

MIN_FREE_BYTES = 4 << 30


def capacity(data, extra=0):
    free = shutil.disk_usage(data).free
    if free < MIN_FREE_BYTES+extra:
        raise ReconcileBlocked('DISK_RESERVE', 'operation cannot preserve the 4 GiB filesystem reserve', 'Free explicitly owned disposable capacity; frozen cohorts, reports, pins and journals are retained.')
    return {'free_bytes':free, 'reserve_bytes':MIN_FREE_BYTES,
            'snapshot_cache_bytes':bytes_in(Path(data)/'mathlab/snapshots'),
            'image_binary_cache_bytes':bytes_in(Path(data)/'mathlab/bin'),
            'native_baseline_bytes':bytes_in(Path(data)/'mathlab/native-baselines')}


class ReconcileBlocked(stage_scope.StageError):
    def __init__(self, code, message, recovery):
        super().__init__(message)
        self.code, self.recovery = code, recovery


def remaining(deadline, maximum=60):
    value = min(maximum, deadline-time.monotonic())
    if value <= 0:
        raise ReconcileBlocked('RECONCILE_TIMEOUT', 'stage reconciliation runtime limit exceeded', 'Retry the bounded service after checking runtime health.')
    return value


def ensure_source(repo, source, deadline):
    """Materialize exact deployed/HEAD trees for offline shared-clone checkout.

    Deliberate object fetches are restricted to the existing approved origin.
    Observational commands deny transports even on older promisor Git versions.
    No checkout, ref, FETCH_HEAD or persistent config is rewritten.
    """
    stage_scope.repository(repo, timeout=remaining(deadline, 20))
    repo=Path(repo).resolve()
    before=shutil.disk_usage(repo).free
    fetched=False
    readonly_options=[]

    def git(args, *, data=None, fetch=False):
        nonlocal fetched
        # Bounded files avoid pipe deadlock/unbounded captured stdout. A reader
        # never enables Git's automatic promisor fetch; only this explicit lane
        # may obtain the requested object IDs from the approved origin.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as input_file:
            if data is not None: input_file.write(data.encode());input_file.seek(0)
            process=subprocess.Popen(['git','-C',str(repo),*([] if fetch else readonly_options),*args],stdin=input_file,
                stdout=output,stderr=subprocess.DEVNULL,start_new_session=True,
                env=os.environ.copy() if fetch else stage_scope.observation_git_env())
            try:
                while process.poll() is None:
                    remaining(deadline)
                    if output.tell()>8 << 20:
                        raise ReconcileBlocked('SOURCE_MANIFEST_CAPACITY','source object manifest exceeds8MiB','Review the deployed tree size; no source is declared complete.')
                    if fetch:
                        free=shutil.disk_usage(repo).free
                        if free<MIN_FREE_BYTES+(64 << 20) or before-free>512 << 20:
                            raise ReconcileBlocked('SOURCE_FETCH_CAPACITY','source retrieval reached its512MiB growth/free-reserve guard','Review repository storage; the checkout and historical objects remain unchanged.')
                    time.sleep(.02)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid,signal.SIGKILL);process.wait()
            output.seek(0);raw=output.read((8 << 20)+1)
            if len(raw)>8 << 20:
                raise ReconcileBlocked('SOURCE_MANIFEST_CAPACITY','source object manifest exceeds8MiB','Review deployed tree size.')
            return process.returncode,raw.decode('utf-8')

    rc,head=git(['rev-parse','HEAD']);head=head.strip()
    if rc or not stage_scope.SHA.fullmatch(source) or not stage_scope.SHA.fullmatch(head):
        raise stage_scope.StageError('exact stage source and valid repository HEAD are required')
    rc,config_path=git(['rev-parse','--git-path','config'])
    config=Path(config_path.strip());config=config if config.is_absolute() else repo/config
    config_before=config.read_bytes()
    _,promisors=git(['config','--name-only','--get-regexp',r'^remote\..*\.promisor$'])
    readonly_options=['-c','extensions.partialClone=']
    for key in promisors.splitlines():readonly_options+=['-c',key+'=false']

    def fetch_objects(objects, filtered=False):
        nonlocal fetched
        if not objects:return
        if any(not stage_scope.SHA.fullmatch(obj) for obj in objects):
            raise stage_scope.StageError('source materialization requires exact object hashes')
        if shutil.disk_usage(repo).free<MIN_FREE_BYTES+(512 << 20):
            raise ReconcileBlocked('SOURCE_FETCH_CAPACITY','source retrieval cannot preserve the filesystem reserve','Free reviewed disposable capacity before fetching source objects.')
        # Runtime -c supplies promisor registration without changing .git/config.
        # Explicit blob/tree wants use no filter; only the missing commit fetch
        # omits unrelated history blobs before its exact tree is materialized.
        options=['-c','fetch.parallel=1','-c','remote.origin.promisor='+('true' if filtered else 'false')]
        if filtered:options+=['-c','remote.origin.partialclonefilter=blob:none']
        args=options+['fetch','--no-tags','--no-write-fetch-head','--no-auto-maintenance',
                      '--no-recurse-submodules','--filter=blob:none' if filtered else '--no-filter','--stdin','origin']
        rc,_=git(args,data=''.join(obj+'\n' for obj in objects),fetch=True)
        if rc:
            raise ReconcileBlocked('SOURCE_FETCH_UNAVAILABLE','cannot retrieve exact deployed-tree objects from the approved repository','Check the host-provisioned credential helper/source access; no request supplies credentials.')
        free=shutil.disk_usage(repo).free
        if free<MIN_FREE_BYTES+(64 << 20) or before-free>512 << 20:
            raise ReconcileBlocked('SOURCE_FETCH_CAPACITY','completed source retrieval exceeded its growth/free-reserve guard','Review retained source object capacity; no pin was published.')
        if config.read_bytes()!=config_before or git(['rev-parse','HEAD'])[1].strip()!=head:
            raise stage_scope.StageError('source retrieval changed repository HEAD/config; no pin was published')
        fetched=True

    if git(['cat-file','-e',source+'^{commit}'])[0]:fetch_objects([source],filtered=True)
    receipts=[]
    for commit in dict.fromkeys((head,source)):
        rc,body=git(['cat-file','-p',commit])
        if rc or not body.startswith('tree '):raise stage_scope.StageError('exact source commit is unavailable')
        root_tree=body.splitlines()[0][5:]
        materialized=set()
        # --no-walk traverses this commit's complete tree without fetching the
        # history's blobs. --missing=print reports promised objects without
        # cat-file's fatal/lazy-fetch behavior on older Git releases.
        for _ in range(128):
            rc,graph=git(['rev-list','--objects','--no-object-names','--no-walk=unsorted','--missing=print',commit])
            entries=graph.splitlines()
            if rc or len(entries)>100000 or any(not stage_scope.SHA.fullmatch(x.lstrip('?')) for x in entries):
                raise stage_scope.StageError('bounded offline source-tree graph is unavailable')
            missing=sorted({x[1:] for x in entries if x.startswith('?')})
            if not missing:break
            if set(missing)<=materialized:
                raise ReconcileBlocked('SOURCE_TREE_INCOMPLETE','required tree objects remain unavailable after explicit fetch','Check repository retention/access; no source is declared ready.')
            for offset in range(0,len(missing),256):fetch_objects(missing[offset:offset+256])
            materialized.update(missing)
        else:
            raise ReconcileBlocked('SOURCE_TREE_CAPACITY','source-tree hydration exceeded128 bounded graph passes','Review unusually deep/incomplete source storage.')
        rc,listing=git(['ls-tree','-r','-z','--full-tree','--format=%(objecttype) %(objectname)',commit])
        if rc:
            fetch_objects([root_tree])
            rc,listing=git(['ls-tree','-r','-z','--full-tree','--format=%(objecttype) %(objectname)',commit])
        if rc:raise stage_scope.StageError('deployed source tree cannot be read offline')
        records=[item.split(' ') for item in listing.split('\0') if item]
        if len(records)>100000 or any(len(item)!=2 for item in records):
            raise ReconcileBlocked('SOURCE_TREE_CAPACITY','deployed source tree exceeds100000 entries','Review source size before code benchmarks.')
        objects=sorted({item[1] for item in records if item[0]=='blob'})
        def inspect_objects():
            rc,values=git(['cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'],data=''.join(obj+'\n' for obj in objects))
            rows=[line.split(' ') for line in values.splitlines()]
            if rc or len(rows)!=len(objects) or [r[0] for r in rows]!=objects:
                raise stage_scope.StageError('source blob completeness observation failed (rc=%s expected=%s observed=%s)'%(rc,len(objects),len(rows)))
            return rows
        rows=inspect_objects()
        if any(len(r)!=3 or r[1]!='blob' or not r[2].isdigit() for r in rows):
            raise ReconcileBlocked('SOURCE_TREE_INCOMPLETE','required deployed/HEAD source blobs remain unavailable offline','Run bounded reconciliation with exact repository access; code readiness is not granted.')
        size=sum(int(r[2]) for r in rows)
        if size>512 << 20:
            raise ReconcileBlocked('SOURCE_TREE_CAPACITY','checkout tree exceeds512MiB decoded source','Review checkout capacity; this native pin is not declared code-ready.')
        receipts.append({'source_revision':commit,'tree':root_tree,'blob_count':len(objects),'decoded_blob_bytes':size,
                         'materialized_blobs':len(set(objects)&materialized),'offline_objects_complete':True})
    if config.read_bytes()!=config_before or git(['rev-parse','HEAD'])[1].strip()!=head:
        raise stage_scope.StageError('source retrieval did not preserve repository HEAD/config')
    return {'source_revision':source,'fetched':fetched,'checkout_head':head,'offline_checkout_trees':receipts}


def observe(policies, deadline):
    inventory=stage_cli.runtime_inventory(deadline)
    brain = stage_cli.running_image(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE,
                                    'staging-brain', 'brain', deadline=deadline,inventory=inventory)
    if brain['repository'] != '753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/brain':
        raise stage_scope.StageError('actual brain image is outside the fixed staging repository')
    capture = stage_cli.capture_configuration(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE, deadline,inventory=inventory)
    if set(capture['policies']) - set(stage_scope.ALLOWED_POLICIES):
        raise ReconcileBlocked('CAPTURE_SCOPE_UNAPPROVED', 'capture contains policies outside the configured benchmark allowlist', 'Review the stage capture scope; automatic reconciliation does not widen it.')
    if not set(policies) <= set(capture['policies']):
        raise ReconcileBlocked('CAPTURE_DISABLED', 'requested policies are absent from the actual brain capture configuration', 'Apply the reviewed durable staging capture values; this service never patches the cluster.')
    if capture['persistent_claim'] != 'staging-brain-mathlab' or not capture['cost_evidence']:
        raise ReconcileBlocked('CAPTURE_CONFIGURATION_INCOMPLETE', 'the approved persistent capture claim or manager cost evidence is unavailable', 'Restore the reviewed stage PVC mount and manager capture settings through GitOps.')
    manager = stage_cli.running_image(stage_scope.STAGE_CONTEXT, stage_scope.STAGE_NAMESPACE,
                                      'staging-phorvex', 'manager', deadline=deadline,inventory=inventory)
    if manager['git_sha'] != brain['git_sha'] or manager['repository'] != '753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/manager':
        raise ReconcileBlocked('STAGE_COMPONENT_SOURCE_MISMATCH', 'brain and manager do not carry the same exact stage source', 'Wait for the approved stage rollout; do not select a different source to hide the mismatch.')
    policy_map = {}
    for policy in policies:
        policy_map[policy]=stage_cli.policy_workload(inventory,policy)
    return {'brain': brain, 'manager': manager, 'capture': capture, 'policies': policy_map}


def same_observation(left, right):
    keys = ('git_sha', 'image', 'image_digest', 'deployment_uid')
    return (all(left['brain'].get(k) == right['brain'].get(k) for k in keys) and
            all((left.get('manager') or {}).get(k) == (right.get('manager') or {}).get(k) for k in keys) and
            left.get('policies') == right.get('policies') and
            left.get('capture') == right.get('capture'))


def new_pin(observed, identity):
    return {'schema': stage_scope.SCHEMA, 'repository': stage_scope.REPOSITORY,
            'kube_context': stage_scope.STAGE_CONTEXT, 'service_namespace': stage_scope.STAGE_NAMESPACE,
            'brain': observed['brain'], 'manager': observed['manager'], 'policies': observed['policies'], 'capture': observed['capture'],
            'identity_binding': 'stage-pin.replay.v1', 'replay': {**identity, 'producer': 'stage-brain-image'},
            'installed_at': utc(), 'console': {'service': 'staging-phorvex-console',
                'service_account': 'staging-brain-benchmark', 'port': 80, 'audience': 'phorvex-staging-console'}}


def selected_entries(data, pin, policy, ticks):
    ns, name = stage_scope.policy(policy)
    entries = snapshots.local_index(data, ns, name, stage_scope.snapshot_header(pin, policy))
    entries = [e for e in entries if e['header'].get('finalized') is True and not e['header'].get('unreplayableFields')]
    now=time.time()
    entries = [e for e in entries if clock(e['header']['capturedAt']) <= now]
    entries = entries[-ticks:]
    if len(entries) < ticks:
        raise ReconcileBlocked('CAPTURE_TICKS_PENDING', 'only %d/%d finalized source-matched snapshots are available for %s' % (len(entries), ticks, policy), 'Keep the approved capture running; the timer retries without backdating or changing the request.')
    stage_scope.cohort(pin, policy, entries)
    if now-clock(entries[-1]['header']['capturedAt']) > 600:
        raise ReconcileBlocked('CAPTURE_STALE', 'latest exact-source capture is more than 600 seconds old', 'Check stage capture/relay and wait for fresh ticks; old data is not relabeled current.')
    return entries


def merge_verified(data, candidate_data, pin, policy, entries, max_corpus_bytes):
    ns, name = stage_scope.policy(policy)
    target = Path(data)/'mathlab/snapshots'/policy
    target.mkdir(parents=True, exist_ok=True)
    with snapshots.cache_lock(data, ns, name, exclusive=True):
        size = bytes_in(Path(data)/'mathlab/snapshots')
        for entry in entries:
            source = Path(candidate_data)/'mathlab/snapshots'/policy/(entry['digest']+'.pxms')
            destination = target/source.name
            if sha256_file(source) != entry['digest']:
                raise stage_scope.StageError('candidate snapshot digest changed before installation')
            if destination.exists():
                if sha256_file(destination) != entry['digest']:
                    raise stage_scope.StageError('existing snapshot evidence is corrupted; it was not overwritten')
                continue
            if size+source.stat().st_size > max_corpus_bytes:
                raise ReconcileBlocked('SNAPSHOT_CACHE_CAPACITY', 'managed snapshot cache capacity would be exceeded', 'Archive task-owned historical caches under the documented retention rules; frozen runs and journals are never removed here.')
            capacity(data, source.stat().st_size+(1 << 20))
            fd, tmp = tempfile.mkstemp(prefix='.reconcile-', dir=target)
            try:
                with os.fdopen(fd, 'wb') as dest, source.open('rb') as src:
                    shutil.copyfileobj(src, dest)
                    dest.flush(); os.fsync(dest.fileno())
                os.replace(tmp, destination)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
            size += source.stat().st_size
        register_downloads(data, pin, policy, [e['digest'] for e in entries])


def reconcile(data_dir, repo, policies=stage_scope.ALLOWED_POLICIES, *, ticks=64, timeout=900,
              max_work_bytes=256 << 20, max_corpus_bytes=2 << 30, recent_seconds=3600):
    policies = tuple(policies)
    if (not policies or len(set(policies)) != len(policies) or set(policies)-set(stage_scope.ALLOWED_POLICIES) or
            type(ticks) is not int or not 1 <= ticks <= 256 or not 30 <= timeout <= 1800 or
            not 32 << 20 <= max_work_bytes <= 1 << 30 or not 64 << 20 <= max_corpus_bytes <= 8 << 30 or
            type(recent_seconds) is not int or not 60 <= recent_seconds <= 86400):
        raise ValueError('invalid fixed stage scope or reconciliation bounds')
    data = Path(data_dir).resolve()
    started = time.monotonic(); deadline = started+timeout
    result = {'schema': 'phorvex-bench.reconcile.v1', 'status': 'RUNNING', 'phase': 'LEASE',
              'started_at': utc(), 'policies': list(policies), 'required_ticks': ticks, 'reasons': []}
    status_path = data/'mathlab/reconcile-status.json'
    def recent_sync(target, policy, max_bytes):
        result = stage_cli.sync_stage(target,repo,policy,sync_limit=max(256,ticks),max_sync_bytes=max_bytes,
            recent_seconds=recent_seconds,recent_progress_root=data/'mathlab/reconcile-inventory')
        if result.get('latest_scan_complete') is not True:
            raise ReconcileBlocked('RECENT_INDEX_INCOMPLETE',
                'bounded recent metadata scan has not reached its frozen upper bound; no latest cohort is claimed',
                'Retry reconciliation to resume retained source-scoped pagination; inspect explicit index bounds if progress cannot advance.')
        return result
    leases = ExitStack()
    try:
        leases.enter_context(stage_scope.pin_lock(data, exclusive=True, timeout=min(20, timeout)))
        result['phase'] = 'CAPACITY'
        with wall_limit(timeout):
            write_json(status_path, result)
            result['capacity_before'] = capacity(data, max_work_bytes+(512 << 20))
            result['phase'] = 'DISCOVER'
            observed = observe(policies, deadline)
            result['observed'] = observed
            result['phase'] = 'SOURCE'
            result['source'] = ensure_source(repo, observed['brain']['git_sha'], deadline)
            old = read_json(data/'mathlab/stage.json', {}) or {}
            if (old.get('identity_binding') == 'stage-pin.replay.v1' and
                    old.get('kube_context') == stage_scope.STAGE_CONTEXT and same_observation(old, observed)):
                stage_scope.study_engine(data, old)
                result['phase'] = 'SYNC'
                result['sync'] = {}
                for policy in policies:
                    ns,name=stage_scope.policy(policy)
                    with snapshots.cache_lock(data, ns, name, exclusive=True):
                        prune_cache(data, old, policy, max(256,ticks))
                    space=capacity(data, max_work_bytes//len(policies))
                    available=max_corpus_bytes-space['snapshot_cache_bytes']
                    if available < 1:
                        raise ReconcileBlocked('SNAPSHOT_CACHE_CAPACITY','total stage snapshot cache cap is exhausted','Review historical cache retention; frozen evidence is not automatically deleted.')
                    result['sync'][policy]=recent_sync(data,policy,min(available,max_work_bytes//len(policies)))
                for policy in policies: selected_entries(data, old, policy, ticks)
                if not same_observation(observed, observe(policies, deadline)):
                    raise ReconcileBlocked('STAGE_CHANGED_DURING_RECONCILIATION', 'stage identity/capture changed while synchronizing', 'Retry one stable rollout; the previous pin remains intact.')
                result.update(status='READY', phase='COMPLETE', pin_reused=True, pin_sha256=sha256_file(data/'mathlab/stage.json'))
            else:
                result['phase'] = 'EXTRACT'
                if bytes_in(data/'mathlab/bin') > 512 << 20:
                    raise ReconcileBlocked('REPLAY_CACHE_CAPACITY','retained replay binary cache exceeds 512 MiB','Archive obsolete image binaries only after proving no historical or active run references them.')
                identity = binary.ensure_binary(data, observed['brain'])
                if bytes_in(data/'mathlab/bin') > 512 << 20:
                    raise ReconcileBlocked('REPLAY_CACHE_CAPACITY', 'retained replay binaries reached the 512 MiB bound', 'Review retained image references; no previous pin was changed.')
                if (identity.get('git_sha') != observed['brain']['git_sha'] or
                        identity.get('image_digest') != observed['brain']['image_digest'] or
                        identity.get('endpoint_study_mode') != 'PAIRED_BRAIN_REPLAY' or
                        identity.get('study_candidates_schema') != 'math-lab.study-candidates.v1'):
                    raise ReconcileBlocked('NATIVE_REPLAY_UNAVAILABLE', 'actual stage image lacks the required verified native replay capabilities', 'Deploy a reviewed compatible stage image; never fabricate a cross-source review receipt.')
                pin = new_pin(observed, identity)
                refs, cohorts = [], {}
                work_root = data/'mathlab/reconcile-work'; work_root.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='candidate-', dir=work_root) as tmp:
                    work = Path(tmp); candidate_data = work/'data'
                    write_json(candidate_data/'mathlab/stage.json', pin)
                    result['sync'] = {}
                    for index, policy in enumerate(policies):
                        result['phase'] = 'SYNC'
                        result['sync'][policy] = recent_sync(candidate_data,policy,max_work_bytes//(4*len(policies)))
                        entries = selected_entries(candidate_data, pin, policy, ticks)
                        frozen = work/('cohort-%d' % index)
                        ns, name = stage_scope.policy(policy)
                        with snapshots.cache_lock(candidate_data, ns, name):
                            snapshots.freeze_cohort(candidate_data, ns, name, entries, frozen)
                        result['phase'] = 'BASELINE'
                        output = work/('baseline-%d.jsonl' % index); summary = work/('baseline-%d.summary.json' % index)
                        run_replay([identity['path'], '-snapshots', str(frozen), '-out', str(output), '-summary', str(summary)],
                                   work, deadline, max_work_bytes)
                        rows = json_lines(output); digests = [e['digest'] for e in entries]
                        exact_baseline(rows, digests, policy)
                        receipt = {'schema': 'phorvex-bench.native-baseline.v1', 'source_revision': identity['git_sha'],
                                   'image_digest': identity['image_digest'], 'binary_sha256': identity['binary_sha256'],
                                   'policy': policy, 'policy_uid': pin['policies'][policy]['uid'],
                                   'snapshot_digests': digests, 'rows': rows, 'summary': read_json(summary), 'at': utc()}
                        retained = data/'mathlab/native-baselines/cohorts'/sha256_json(digests)
                        if not retained.exists():
                            if bytes_in(data/'mathlab/native-baselines')+bytes_in(frozen) > 256 << 20:
                                raise ReconcileBlocked('BASELINE_RETENTION_CAPACITY','immutable native baseline evidence reaches its 256 MiB bound','Archive retained baseline evidence under operator control; it is never silently evicted.')
                            capacity(data, bytes_in(frozen)+(1 << 20))
                            shutil.copytree(frozen,retained)
                            for raw in retained.glob('*.pxms'):
                                with raw.open('rb') as stream: os.fsync(stream.fileno())
                            directory = os.open(retained, os.O_DIRECTORY)
                            try: os.fsync(directory)
                            finally: os.close(directory)
                        for entry in entries:
                            if sha256_file(retained/(entry['digest']+'.pxms')) != entry['digest']:
                                raise stage_scope.StageError('retained native baseline cohort changed')
                        receipt['cohort_path']=str(retained)
                        ref = data/'mathlab/native-baselines'/(sha256_json(receipt)+'.json')
                        stage_cli.durable_json(ref, receipt); refs.append({'path': str(ref), 'sha256': sha256_file(ref)})
                        cohorts[policy] = entries
                    pin.update(study_engine_lane='native-stage-image', native_study={
                        'schema': 'phorvex-bench.native-study.v1', 'source_revision': identity['git_sha'],
                        'image_digest': identity['image_digest'], 'binary_sha256': identity['binary_sha256'], 'baseline_evidence': refs})
                    stage_scope.native_study_engine(candidate_data, pin)
                    result['phase'] = 'PUBLISH'
                    if not same_observation(observed, observe(policies, deadline)):
                        raise ReconcileBlocked('STAGE_CHANGED_BEFORE_PUBLICATION', 'stage image/source/policy/capture changed before atomic publication', 'Wait for one stable rollout and retry; no old pin was replaced.')
                    for policy, entries in cohorts.items():
                        merge_verified(data, candidate_data, pin, policy, entries, max_corpus_bytes)
                    capacity(data, 1 << 20)
                    if not same_observation(observed, observe(policies, deadline)):
                        raise ReconcileBlocked('STAGE_CHANGED_BEFORE_PUBLICATION', 'stage identity changed while freezing verified local evidence', 'Retry one stable rollout; the previous pin remains intact.')
                    stage_cli.publish_pin(data, pin)
                    result.update(status='READY', phase='COMPLETE', pin_reused=False,
                                  pin_sha256=sha256_file(data/'mathlab/stage.json'), baseline_ticks={p:len(e) for p,e in cohorts.items()})
            result['observer_history'] = 'Existing journals remain source/policy bound; a new source requires its own truthful observation segment. Active demo attribution is not synthesized.'
            result['capacity_after']=capacity(data)
            result['retention']='Only ownership-registered same-source working snapshot caches may be pruned under global/policy leases. Native baseline cohorts, pins, reports and journals remain immutable; bounds/free reserve can block later requests and do not prove ten-day capacity.'
    except (stage_scope.StageError, binary.BinaryError, RefreshBlocked, subprocess.TimeoutExpired, OSError) as error:
        result.update(status='BLOCKED', reasons=[{'code': getattr(error, 'code', 'RECONCILIATION_UNAVAILABLE'),
                      'message': str(error), 'recovery': getattr(error, 'recovery', 'Check actual stage capture/source access and retry the configured reconciliation service.')}])
    except Exception as error:
        result.update(status='FAILED', reasons=[{'code':'UNEXPECTED_RECONCILIATION_ERROR','message':str(error)}])
        raise
    finally:
        result.update(finished_at=utc(), elapsed_seconds=round(time.monotonic()-started,3))
        # A failed lease attempt must not overwrite another running reconciler.
        try:
            if result['phase'] != 'LEASE': stage_cli.durable_json(status_path, result)
        finally:
            leases.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True); parser.add_argument('--repo', required=True)
    parser.add_argument('--policy', action='append', choices=stage_scope.ALLOWED_POLICIES)
    parser.add_argument('--ticks', type=int, default=64); parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--max-work-bytes', type=int, default=256 << 20)
    parser.add_argument('--max-corpus-bytes', type=int, default=2 << 30)
    parser.add_argument('--recent-seconds', type=int, default=3600,
                        help='Operational bootstrap inventory horizon60..86400s; never changes requested study W/L')
    args = parser.parse_args()
    result = reconcile(args.data, args.repo, args.policy or stage_scope.ALLOWED_POLICIES,
                       ticks=args.ticks, timeout=args.timeout, max_work_bytes=args.max_work_bytes,
                       max_corpus_bytes=args.max_corpus_bytes, recent_seconds=args.recent_seconds)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['status'] == 'READY' else 2


if __name__ == '__main__':
    raise SystemExit(main())
