"""Bounded read-only request readiness shared by validation and execution.

READY describes currently available prerequisites. Exact replay and all code/test
gates still run during execution. This module never syncs, repins or calls a model.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from mathlab import snapshots, stage_scope
from mathlab.common import sha256_file, sha256_json
import endpoint_study

MAX_FILES = 10000
MAX_HEADER_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_AGE_SECONDS = 900


def descriptor(spec, policy, ticks):
    if spec['kind'] in ('endpoint', 'study'):
        request = json.loads(spec['text'])
        return {'kind': spec['kind'], 'policy': request['policy'], 'ticks': request.get('ticks', 64),
                'sync': request.get('sync', False), 'request': request,
                'recorded': request.get('dataset') == 'recorded'}
    words = spec['text'].split()
    chosen = next((word.split('=', 1)[1] for word in words if word.startswith('policy=')), policy)
    count = next((word.split('=', 1)[1] for word in words if word.startswith('ticks=')), ticks)
    return {'kind': spec['kind'], 'policy': chosen, 'ticks': int(count), 'sync': 'nosync' not in words, 'recorded': True}


def reason(report, code, message, recovery, sync_can_help=False):
    if any(row['code'] == code for row in report['reasons']):
        return
    report['reasons'].append({'code': code, 'message': message, 'recovery': recovery, 'sync_can_help': sync_can_help})
    report['status'] = 'BLOCKED'


def clock(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


@contextmanager
def cache_reader(data_dir, policy, timeout=2):
    """Lock an installed cache without creating files during /validate."""
    ns, name = stage_scope.policy(policy)
    path = Path(data_dir) / 'mathlab/snapshots' / ns / (name + '.cache.lock')
    fd = os.open(path, os.O_RDONLY)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise stage_scope.StageError('snapshot cache is being updated; retry validation shortly')
                time.sleep(.02)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def live_probe(data_dir, repo, policy):
    from stage_cli import probe_runtime
    return probe_runtime(data_dir, repo, policy, timeout=60)


def endpoint_mode(report, observed_policy):
    mode = observed_policy.get('mode')
    report['policy_mode'] = mode
    if mode is None:
        reason(report, 'POLICY_MODE_UNAVAILABLE', 'The requested policy mode is unverified; endpoint attribution cannot be qualified.',
               'Verify the exact live policy UID and mode without changing it; collect qualified evidence for that scope.')
    elif mode != 'dryRun':
        reason(report, 'MOVE_ATTRIBUTION_UNAVAILABLE',
               'The requested active policy has no qualified move-attributed endpoint history. Generic brain snapshots cannot establish it.',
               'Keep this policy unchanged. Install a real attributed endpoint producer and collect its required continuous history; never borrow a fixture ledger.')
        report['missing_fields'] = ['ticks[].ledger.complete_from', 'ticks[].ledger.moves[].id',
                                    'ticks[].ledger.moves[].attributed', 'ticks[].ledger.moves[].intervals[]',
                                    'ticks[].candidates[].samples']
        report['diagnostic_capture'] = {'field': 'inspection.endpoint_cost_evidence.endpoint_loss_status',
            'source': 'phorvex/internal/mathlab/inspect.go',
            'limitation': 'Replica-history capture reports endpoint loss unavailable; waiting alone does not create move-attributed endpoint intervals.'}


def endpoint_history(report, data_dir, pin, request, observed_policy, qualified_digests=None, now=None, max_age=MAX_AGE_SECONDS):
    report.update(endpoint_study.request_context(request))
    endpoint_mode(report, observed_policy)
    pointer = Path(data_dir) / 'mathlab/endpoint-traces' / (request['policy'] + '.manifest.json')
    if not pointer.is_file():
        reason(report, 'ENDPOINT_DATASET_UNAVAILABLE', 'No qualified normalized endpoint dataset is installed for the exact requested policy.',
               'Collect source- and policy-bound endpoint evidence for both requested windows, then refresh that policy. Short fixture controls are separate experiments.')
        return
    if pointer.is_symlink() or pointer.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError('installed endpoint manifest is unsafe or exceeds its bounded size')
    meta = endpoint_study.strict_json(pointer.read_text())
    if (meta.get('schema') != 'phorvex-stage.endpoint-manifest.v1' or meta.get('policy') != request['policy'] or
            meta.get('policy_uid') != pin['policies'][request['policy']]['uid'] or
            meta.get('image_digest') != pin['brain']['image_digest'] or
            meta.get('snapshot_source_revision', meta.get('source_revision')) != pin['brain']['git_sha'] or
            meta.get('repository') not in (stage_scope.REPOSITORY, 'PhorvexSecurity/operator-refactored')):
        reason(report, 'ENDPOINT_SOURCE_DRIFT', 'Installed endpoint evidence belongs to a different source, image or policy UID.',
               'Reconcile the current stage source and start a fresh truthful observation segment; retain the old dataset as history.')
        return
    source_name = meta.get('trace_file')
    expected = pointer.name.removesuffix('.manifest.json') + '.' + str(meta.get('trace_sha256')) + '.trace.json'
    if source_name is None:
        source = pointer.with_name(pointer.name.removesuffix('.manifest.json') + '.json')
    elif source_name == expected and Path(source_name).name == source_name:
        source = pointer.parent / source_name
    else:
        raise ValueError('installed endpoint generation has an unsafe basename')
    if not source.is_file():
        reason(report, 'ENDPOINT_GENERATION_UNAVAILABLE', 'The installed immutable endpoint generation is missing.', 'Refresh the exact current source and policy dataset.')
        return
    if source.is_symlink() or source.stat().st_size > MAX_MANIFEST_BYTES or sha256_file(source) != meta.get('trace_sha256'):
        raise ValueError('installed endpoint generation fails its content hash or size limit')
    normalized = meta.get('normalization') or {}
    bindings = sorted(normalized.get('bindings') or [], key=lambda row: row.get('at', float('-inf')))[-request['ticks']:]
    scope = normalized.get('scope') or {}
    if not observed_policy.get('service_uid') or scope.get('service_uid') != observed_policy['service_uid']:
        reason(report, 'ENDPOINT_SERVICE_UNVERIFIED', 'Endpoint history is not bound to the current observed Service UID.',
               'Start or refresh the current Service observation; a replaced Service cannot inherit earlier endpoint history.')
    if not observed_policy.get('workload_uid') or scope.get('workload_uid') != observed_policy['workload_uid']:
        reason(report, 'ENDPOINT_WORKLOAD_UNVERIFIED', 'Endpoint history is not bound to the current observed workload UID.',
               'Start or refresh the exact current workload observation; never reuse history from a recreated or different workload.')
    for field, current_field in (('policy_generation', 'generation'), ('workload_generation', 'workload_generation')):
        current = observed_policy.get(current_field)
        if current is None or not bindings or any(row.get(field) != current for row in bindings):
            reason(report, 'ENDPOINT_' + field.upper() + '_UNVERIFIED', 'Endpoint history lacks matching current ' + field + ' evidence.',
                   'Normalize fresh source-bound observations with explicit policy and workload generation bindings; older evidence remains historical.')
    if len({row.get('snapshot_digest') for row in bindings}) != len(bindings):
        reason(report, 'ENDPOINT_COVERAGE_UNAVAILABLE', 'Endpoint normalization repeats snapshot bindings.', 'Normalize a unique exact recorded cohort again.')
    history = [float(row['at']) - float(row['complete_from']) for row in bindings
               if type(row.get('at')) in (int, float) and type(row.get('complete_from')) in (int, float)
               and row.get('sealed_until', float('-inf')) >= row['at'] and row['at'] >= row['complete_from']]
    available = min(history) if history and len(history) == len(bindings) else None
    report['endpoint_history'] = {'available_continuous_seconds': available,
                                  'normalized_ticks': len(meta.get('snapshot_digests') or []),
                                  'trace_sha256': meta.get('trace_sha256'), 'capacity_runtime': 'VERIFIED_ONLY_FOR_INSTALLED_GENERATION'}
    if qualified_digests is not None and any(row.get('snapshot_digest') not in qualified_digests for row in bindings):
        reason(report, 'ENDPOINT_GENERATION_STALE', 'Endpoint generation includes snapshots outside the current image, policy UID/generation or retained cache.',
               'Refresh a new immutable endpoint generation from the exact current pin; historical generations remain separate.')
    latest = max((row['at'] for row in bindings if type(row.get('at')) in (int, float)), default=None)
    if latest is not None:
        age = (time.time() if now is None else now) - latest
        report['endpoint_history']['latest_age_seconds'] = age
        if age > max_age or age < -30:
            reason(report, 'ENDPOINT_DATASET_STALE', 'The installed endpoint generation is stale or ahead of the current clock.',
                   'Refresh the current source-bound generation after sufficient continuous history is available.')
    required = report['required_windows']
    if required['budget_seconds'] is None:
        required['budget_seconds'] = (normalized.get('study_settings') or {}).get('window')
    if normalized.get('state') != 'READY' or normalized.get('missing') or available is None:
        reason(report, 'ENDPOINT_COVERAGE_UNAVAILABLE', 'The installed dataset does not prove continuous measured coverage.', 'Collect and normalize complete source-bound history; gaps remain unavailable.')
    elif required['budget_seconds'] is None or available < max(required.values()):
        reason(report, 'OBSERVED_HISTORY_INSUFFICIENT',
               'Requested W=%s s and L=%s s exceed retained continuous history=%s s.' % (required['budget_seconds'], required['burn_seconds'], available),
               'Retain continuous observed history for both windows and verify collection/storage/refresh capacity. Do not shorten either requested window automatically.')
    original = normalized.get('study_settings') or {}
    retention = normalized.get('retention') or {}
    expands = (required['budget_seconds'] is not None and
               (required['budget_seconds'] > original.get('window', 0) or required['burn_seconds'] > original.get('lookback', 0)))
    retained = (retention.get('schema') == 'phorvex-stage.retained-history.v1' and retention.get('moves') == 'all-observed'
                and retention.get('samples') == 'all-observed' and retention.get('interval_clipping') is False)
    if expands and not retained:
        reason(report, 'RETAINED_HISTORY_UNPROVEN', 'Expanded W/L lacks proof that all observed intervals and duration samples were retained.',
               'Normalize the retained full history with the current producer; configuration changes cannot reconstruct trimmed evidence.')
    if len(meta.get('snapshot_digests') or []) < request['ticks']:
        reason(report, 'ENDPOINT_TICK_COUNT_INSUFFICIENT', 'Normalized endpoint dataset has fewer than the requested %d ticks.' % request['ticks'], 'Refresh a full exact requested cohort after the required history is available.')
    try:
        engine = stage_scope.study_engine(data_dir, pin)
        if meta.get('source_revision') != engine['candidate']['git_sha']:
            raise stage_scope.StageError('installed candidate export source differs from the verified native or reviewed cross-source engine')
        report['endpoint_engine'] = {'lane': engine.get('lane', 'reviewed-cross-source'),
                                     'source_revision': engine['candidate']['git_sha'],
                                     'binary_sha256': engine['candidate']['binary_sha256']}
    except stage_scope.StageError as error:
        reason(report, 'ENDPOINT_ENGINE_UNAVAILABLE', str(error),
               'Reconcile and prove the current native image replay, or explicitly install a separately reviewed cross-source engine. Readiness never invents a review approval.')


def inspect(data_dir, repo, requested, probe=None, now=None, max_age=MAX_AGE_SECONDS):
    report = {'schema': 'phorvex-bench.request-readiness.v1', 'syntax': 'VALID', 'status': 'READY',
              'requested_policy': requested['policy'], 'requested_ticks': requested['ticks'],
              'requested_sync': requested['sync'], 'requested_kind': requested['kind'], 'reasons': [],
              'available_policies': [], 'snapshot_count': None, 'latest_captured_at': None,
              'baseline_validation': 'NOT_RUN', 'semantics': 'Read-only prerequisite check; execution rechecks identity, hashes, exact replay and tests.'}
    if requested['kind'] == 'endpoint':
        report.update(endpoint_study.request_context(requested['request']))
    if not requested['recorded']:
        report['runtime_scope'] = 'explicit synthetic reference input'
        return report
    if not data_dir or not repo:
        reason(report, 'STAGE_NOT_CONFIGURED', 'The stage source clone and data directory are not configured.', 'Configure BOT_REPO and MATHLAB_DATA_DIR for the isolated stage and run the authorized stage reconciler.')
        return report
    try:
        # The installed pin lock is created by reconciliation, never validation.
        with stage_scope.pin_lock(data_dir, readonly=True):
            runtime = (probe or live_probe)(data_dir, repo, requested['policy'])
            report['runtime'] = runtime
            report['available_policies'] = runtime.get('available_policies', [])
            for item in runtime.get('reasons', []):
                reason(report, item['code'], item['message'], item.get('recovery', 'Run the authorized stage reconciler.'))
            if runtime.get('status') != 'READY' and not runtime.get('reasons'):
                reason(report, 'RUNTIME_UNAVAILABLE', 'Runtime readiness did not return a complete qualified observation.', 'Run the configured stage reconciler and inspect stage access/capture availability.')
            if requested['kind'] == 'endpoint':
                endpoint_mode(report, runtime.get('policy') or {})
            pin = stage_scope.load(data_dir)  # probe_runtime already verified the exact repository/source.
            report['pin_sha256'] = sha256_json(pin)
            report['available_pinned_policies'] = sorted(pin['policies'])
            if requested['policy'] not in pin['policies']:
                reason(report, 'POLICY_NOT_PINNED', 'Requested policy %s is not in the installed stage capture pin.' % requested['policy'],
                       'Use /policies to see the allowlist. Run the configured stage reconciler to pin and sync this exact allowed policy; no policy is substituted.')
                return report
            stage_scope.identity(data_dir, pin)
            ns, name = stage_scope.policy(requested['policy'])
            try:
                with cache_reader(data_dir, requested['policy']):
                    scan_deadline = time.monotonic() + 10
                    directory = Path(data_dir) / 'mathlab/snapshots' / ns / name
                    paths = []
                    for path in directory.glob('*.pxms'):
                        paths.append(path)
                        if len(paths) > MAX_FILES:
                            reason(report, 'CACHE_SCAN_BOUND', 'Snapshot cache exceeds the bounded validation inventory.', 'Run managed cache retention before validating again.')
                            return report
                    expected = stage_scope.snapshot_header(pin, requested['policy'])
                    expected.update(namespace=ns, policyName=name, finalized=True)
                    entries, qualified_digests, header_bytes = [], set(), 0
                    for path in paths:
                        if path.is_symlink() or not re.fullmatch(r'[0-9a-f]{64}', path.stem):
                            continue
                        with path.open('rb') as stream:
                            prefix = stream.read(len(snapshots.MAGIC) + 4)
                        if len(prefix) != len(snapshots.MAGIC) + 4:
                            raise ValueError('truncated cached snapshot header')
                        header_bytes += struct.unpack('>I', prefix[-4:])[0]
                        if header_bytes > MAX_HEADER_BYTES or time.monotonic() > scan_deadline:
                            reason(report, 'CACHE_SCAN_BOUND', 'Read-only snapshot validation reached its byte/time bound.', 'Run managed cache retention before validating again; an incomplete scan is not a ready cohort.')
                            return report
                        header = snapshots.read_header(path)
                        if all(header.get(k) == v for k, v in expected.items()) and not header.get('unreplayableFields'):
                            entries.append(header)
                            qualified_digests.add(path.stem)
                    report['snapshot_count'] = len(entries)
                    dates = [(clock(h.get('capturedAt')), h.get('capturedAt')) for h in entries]
                    dates = [row for row in dates if row[0] is not None]
                    if dates:
                        last, label = max(dates)
                        age = (time.time() if now is None else now) - last
                        report.update(latest_captured_at=label, latest_age_seconds=age, max_age_seconds=max_age)
                        if age > max_age or age < -30:
                            reason(report, 'SNAPSHOT_FRESHNESS_UNAVAILABLE', 'Newest source-matched snapshot is stale or ahead of the current clock.', 'Sync fresh snapshots from the current stage source; inspect capture/clock health if this continues.', True)
                    if len(dates) < requested['ticks']:
                        reason(report, 'SNAPSHOT_COUNT_INSUFFICIENT', 'Only %d source-matched timestamped snapshots are available; %d were requested.' % (len(dates), requested['ticks']), 'Enable the reviewed stage capture configuration, collect the requested ticks, then sync. sync:false never downloads missing ticks.', True)
                    if requested['kind'] == 'endpoint':
                        endpoint_history(report, data_dir, pin, requested['request'], runtime.get('policy') or pin['policies'][requested['policy']],
                                         qualified_digests, now=now, max_age=max_age)
            except FileNotFoundError:
                reason(report, 'SNAPSHOT_CACHE_UNAVAILABLE', 'No installed snapshot cache is available for this exact policy.', 'Run the configured stage reconciler and collect this policy before benchmarking.', True)
    except stage_scope.StageError as error:
        reason(report, 'STAGE_PREREQUISITE_UNAVAILABLE', str(error), 'Run /policies and the authorized stage reconciler; preserve existing data and verify the current stage rollout.')
    return report
