"""Experiment preflight and execution (REPLAY mode).

An experiment changes exactly one registry knob across arms, on one frozen cohort of
recorded snapshots, with the first arm as the recorded control. The cohort, arms, binary
identity and every hash are written to an immutable manifest before anything runs.
"""
import json
import math
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import analysis, binary, exports, registry
from .common import DIGEST, EXPERIMENT_ID, NAME, data_root, read_json, sha256_file, sha256_json, utc, write_json
from .snapshots import corpus_summary, local_index

MAX_ARMS = 12
MIN_SNAPSHOTS_WARN = 30
MAX_SNAPSHOTS = 5000


def _err(code, field, reason, evidence=None, retryable=False):
    return {'error_code': code, 'field': field, 'reason': reason, 'evidence_ref': evidence, 'retryable': retryable}


def _check(checks, cid, status, message, evidence=None):
    checks.append({'id': cid, 'status': status, 'message': message, 'evidence': evidence})


def _parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def select_cohort(data_dir, request):
    entries = local_index(data_dir, request['namespace'], request['policy'])
    cohort = request.get('cohort') or {}
    since, until = _parse_time(cohort.get('since')), _parse_time(cohort.get('until'))
    wanted = set(cohort.get('digests') or [])
    out = []
    for e in entries:
        captured = _parse_time(e['header'].get('capturedAt'))
        if wanted and e['digest'] not in wanted:
            continue
        if since and captured and captured < since:
            continue
        if until and captured and captured >= until:
            continue
        out.append(e)
    limit = min(int(cohort.get('max_snapshots') or MAX_SNAPSHOTS), MAX_SNAPSHOTS)
    if cohort.get('spacing') == 'even' and len(out) > limit:
        # Evenly spaced across the selected window: consecutive 10 s ticks are strongly
        # autocorrelated, so spreading the cohort makes per-tick intervals less optimistic.
        if limit == 1:
            return [out[-1]]
        return [out[round(i * (len(out) - 1) / (limit - 1))] for i in range(limit)]
    return out[-limit:]


GO_DURATION_PART = re.compile(r'(\d+(?:\.\d*)?|\.\d+)(ns|us|\u00b5s|ms|s|m|h)')
GO_DURATION_UNIT = {'ns': 1e-9, 'us': 1e-6, '\u00b5s': 1e-6, 'ms': 1e-3, 's': 1.0, 'm': 60.0, 'h': 3600.0}


def duration_seconds(value):
    """Seconds for a Go duration string such as "15m0s"; numbers pass through; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    if value == '0':
        return 0.0
    total, pos = 0.0, 0
    for m in GO_DURATION_PART.finditer(value):
        if m.start() != pos:
            return None
        total += float(m.group(1)) * GO_DURATION_UNIT[m.group(2)]
        pos = m.end()
    return total if pos == len(value) else None


def format_seconds(seconds):
    """Compact duration label: 90 -> "1m30s", 900 -> "15m", 3600 -> "1h"."""
    rest = int(round(seconds))
    out = ''
    for unit, size in (('d', 86400), ('h', 3600), ('m', 60)):
        if rest >= size:
            out += '%d%s' % (rest // size, unit)
            rest %= size
    return out + ('%ds' % rest if rest or not out else '')


def arm_values(request, knob, inspection):
    """x-axis value and label per arm; the control is the recorded effective value."""
    out = {}
    recorded = None
    if inspection:
        recorded = (inspection.get('effective') or {}).get(knob.get('config_key'))
    seconds = knob.get('units') == 'seconds'
    if seconds and recorded is not None:
        recorded = duration_seconds(recorded)
    show = format_seconds if seconds else repr
    for arm in request['arms']:
        if arm.get('value_source') == 'RECORDED_EFFECTIVE' or arm is request['arms'][0]:
            label = 'recorded ' + ('UNSET (' + str((inspection or {}).get('learned', {}).get('economicsMode', 'policy mode')) + ')' if recorded is None else show(recorded))
            out[arm['arm_id']] = {'value': recorded, 'label': label}
        elif arm.get('unset'):
            out[arm['arm_id']] = {'value': None, 'label': 'UNSET'}
        else:
            out[arm['arm_id']] = {'value': arm.get('value'), 'label': show(arm.get('value'))}
    return out


def preflight(data_dir, request, binary_identity=None, registry_doc=None):
    """Validate an experiment request. Returns {status, checks, errors, cohort, ...}."""
    checks, errors = [], []
    registry_doc = registry_doc or registry.load_registry()
    if request.get('schema_version') != 'math-lab.experiment.v1':
        errors.append(_err('SCHEMA', 'schema_version', 'must be math-lab.experiment.v1'))
    if request.get('mode') != 'REPLAY':
        errors.append(_err('MODE_UNSUPPORTED', 'mode', 'only REPLAY is enabled; paired sandbox requires a separately approved environment'))
    for field in ('namespace', 'policy'):
        if not NAME.match(str(request.get(field) or '').replace('.', '-')):
            errors.append(_err('INVALID_FIELD', field, 'must be a Kubernetes name'))
    knob = registry.knob(registry_doc, request.get('parameter_id'))
    if not knob:
        errors.append(_err('UNKNOWN_PARAMETER', 'parameter_id', 'not in the parameter registry'))
    elif knob.get('control') != registry.EXPERIMENT_KNOB or 'REPLAY' not in (knob.get('experiment_modes') or []):
        errors.append(_err('NOT_AN_EXPERIMENT_KNOB', 'parameter_id', '%s is %s; only registry EXPERIMENT_KNOB parameters can be varied' % (knob['param_id'], knob.get('control'))))
    arms = request.get('arms') or []
    if len(arms) < 2 or len(arms) > MAX_ARMS:
        errors.append(_err('ARM_COUNT', 'arms', 'need the control plus 1..%d trial arms' % (MAX_ARMS - 1)))
    elif arms[0].get('value_source') != 'RECORDED_EFFECTIVE' or 'value' in arms[0] or arms[0].get('unset'):
        errors.append(_err('CONTROL_ARM', 'arms[0]', 'the first arm must be the recorded control (value_source RECORDED_EFFECTIVE)'))
    ids, seen_values = set(), set()
    domain = ((knob or {}).get('replay_override') or {}).get('domain') or {}
    for i, arm in enumerate(arms):
        aid = str(arm.get('arm_id') or '')
        if not aid or len(aid) > 40 or not all(c.isalnum() or c in '-_.' for c in aid) or aid in ids:
            errors.append(_err('ARM_ID', 'arms[%d].arm_id' % i, 'arm ids must be unique [A-Za-z0-9._-]{1,40}'))
        ids.add(aid)
        if i == 0:
            continue
        if arm.get('unset'):
            if not ((knob or {}).get('replay_override') or {}).get('unset_allowed'):
                errors.append(_err('UNSET_NOT_ALLOWED', 'arms[%d]' % i, 'this parameter has no unset state'))
            key = 'UNSET'
        else:
            v = arm.get('value')
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v):
                errors.append(_err('NON_FINITE', 'arms[%d].value' % i, 'value must be a finite number'))
                continue
            lo, hi = domain.get('min'), domain.get('max')
            if lo is not None and (v < lo or (v == lo and not domain.get('min_inclusive', True))):
                errors.append(_err('OUT_OF_DOMAIN', 'arms[%d].value' % i, 'below the replay domain minimum %s' % lo))
            if hi is not None and (v > hi or (v == hi and not domain.get('max_inclusive', True))):
                errors.append(_err('OUT_OF_DOMAIN', 'arms[%d].value' % i, 'above the replay domain maximum %s' % hi))
            if domain.get('integer') and v != int(v):
                errors.append(_err('OUT_OF_DOMAIN', 'arms[%d].value' % i, 'must be a whole number of %s' % ((knob or {}).get('units') or 'units')))
            key = float(v)
        if key in seen_values:
            errors.append(_err('DUPLICATE_VALUE', 'arms[%d]' % i, 'two arms test the same value'))
        seen_values.add(key)
    cohort = []
    if not errors:
        cohort = select_cohort(data_dir, request)
        n = len(cohort)
        if n == 0:
            errors.append(_err('EMPTY_COHORT', 'cohort', 'no recorded snapshots match; sync the policy first', retryable=True))
        else:
            _check(checks, 'SAMPLE_SIZE', 'PASS' if n >= MIN_SNAPSHOTS_WARN else 'WARN',
                   '%d recorded ticks; replay intervals are per-tick, and replay cannot estimate defense rate at any n' % n)
        summary = corpus_summary(cohort)
        incomplete = [e['digest'] for e in cohort if e['header'].get('unreplayableFields')]
        _check(checks, 'SNAPSHOT_COMPLETENESS', 'PASS' if not incomplete else 'WARN',
               '%d of %d snapshots declare unreplayable fields and will be reported UNREPLAYABLE' % (len(incomplete), n), incomplete[:20])
        for key, label in (('git_sha', 'source revision'), ('policy_uid', 'policy UID'), ('process_config_hash', 'process configuration'),
                           ('parameter_manifest_hash', 'parameter manifest'), ('policy_overrides_hash', 'effective policy overrides'),
                           ('economics_mode', 'economics mode')):
            groups = summary.get(key) or {}
            _check(checks, 'COHORT_UNIFORM_' + key.upper(), 'PASS' if len(groups) <= 1 else 'WARN',
                   ('one %s across the cohort' if len(groups) <= 1 else 'cohort spans %d distinct %ss; arms stay matched per tick, but the population is mixed') % ((label,) if len(groups) <= 1 else (len(groups), label)), groups)
        if binary_identity is None:
            errors.append(_err('REPLAY_BINARY_UNAVAILABLE', 'binary', 'no verified brain-replay for the deployed image', retryable=True))
        else:
            shas = set((summary.get('git_sha') or {}).keys())
            mismatch = sorted(s for s in shas if s != binary_identity.get('git_sha'))
            if mismatch and not request.get('allow_cross_version'):
                errors.append(_err('VERSION_MISMATCH', 'cohort', 'snapshots recorded by %s but the replay binary is %s' % (mismatch, binary_identity.get('git_sha')), binary_identity.get('image_digest')))
            _check(checks, 'VERSION_PIN', 'PASS' if not mismatch else ('WARN' if request.get('allow_cross_version') else 'FAIL'),
                   'replay binary %s from image %s' % (binary_identity.get('git_sha'), binary_identity.get('image_digest')), {'binary_sha256': binary_identity.get('binary_sha256')})
            if knob and knob['param_id'] not in binary.overridable(binary_identity):
                errors.append(_err('KNOB_UNSUPPORTED_BY_REPLAY_BINARY', 'parameter_id',
                                   'the replay binary %s cannot override %s; it needs %s, and a cohort recorded by that release'
                                   % (binary_identity.get('git_sha'), knob['param_id'],
                                      ((knob.get('replay_override') or {}).get('requires') or 'a newer operator release')),
                                   sorted(binary.overridable(binary_identity))))
            if binary_identity.get('local'):
                _check(checks, 'BINARY_PROVENANCE', 'WARN', 'locally supplied binary: results are OBSERVATIONAL (not the deployed image)')
        modes = set((summary.get('economics_mode') or {}).keys())
        if knob and knob['param_id'] == 'P-OBJ-003' and any('preferences' in (m or '') for m in modes):
            errors.append(_err('MODE_CONFLICT', 'parameter_id', 'policy uses costPreferences, which is mutually exclusive with disruptionAversion'))
    if knob and knob.get('protected'):
        _check(checks, 'PROTECTED_PARAMETER', 'WARN', 'protected parameter: replay values are exploratory; any production change needs SRE/security approval through a separate change request')
    _check(checks, 'SECURITY_OUTCOMES', 'INFO', 'replay observes no attack outcomes: M-S01 and M-D* are UNAVAILABLE; the result is decision-mechanism evidence only')
    _check(checks, 'PRODUCTION_WRITE', 'PASS', 'replay runs offline with no cluster credentials; nothing is dispatched')
    for e in errors:
        _check(checks, e['error_code'], 'FAIL', e['field'] + ': ' + e['reason'])
    return {'schema_version': 'math-lab.preflight.v1', 'status': 'FAIL' if errors else 'PASS', 'checks': checks, 'errors': errors,
            'cohort': {'snapshots': len(cohort), 'digests_sha256': sha256_json([e['digest'] for e in cohort]),
                       'summary': corpus_summary(cohort)}, 'parameter': (knob or {}).get('param_id'), 'evaluated_at': utc()}


def _status(path, stage, message, completed=None, total=None, state='RUNNING'):
    write_json(path / 'status.json', {'state': state, 'stage': stage, 'message': message, 'completed': completed, 'total': total, 'updated_at': utc()})


def run(data_dir, experiment_id, binary_identity, registry_doc=None):
    if not EXPERIMENT_ID.match(experiment_id):
        raise ValueError('invalid experiment id')
    root = data_root(data_dir) / 'experiments' / experiment_id
    request = read_json(root / 'request.json')
    if not request:
        raise ValueError('experiment request missing')
    registry_doc = registry_doc or registry.load_registry()
    _status(root, 'preflight', 'validating')
    pf = preflight(data_dir, request, binary_identity, registry_doc)
    write_json(root / 'preflight.json', pf)
    if pf['status'] != 'PASS':
        _status(root, 'preflight', 'preflight failed', state='PREFLIGHT_FAILED')
        return 'PREFLIGHT_FAILED'
    cohort = select_cohort(data_dir, request)
    cohort_dir = root / 'cohort'
    cohort_dir.mkdir(exist_ok=True)
    _status(root, 'cohort', 'freezing %d snapshots' % len(cohort), 0, len(cohort))
    src = Path(data_dir).resolve() / 'mathlab' / 'snapshots' / request['namespace'] / request['policy']
    for i, e in enumerate(cohort):
        dst = cohort_dir / (e['digest'] + '.pxms')
        if not dst.exists():
            try:
                os.link(src / dst.name, dst)
            except OSError:
                shutil.copy2(src / dst.name, dst)
        if sha256_file(dst) != e['digest']:
            raise ValueError('cohort snapshot %s failed its content check' % e['digest'])
    knob = registry.knob(registry_doc, request['parameter_id'])
    arms = [{'arm_id': request['arms'][0]['arm_id'], 'overrides': []}]
    for arm in request['arms'][1:]:
        override = {'param_id': knob['param_id']}
        if arm.get('unset'):
            override['unset'] = True
        else:
            override['value'] = arm['value']
        arms.append({'arm_id': arm['arm_id'], 'overrides': [override]})
    write_json(root / 'arms.json', arms)
    _status(root, 'inspect', 'resolving configured and effective values')
    binary.run_isolated([binary_identity['path'], '-inspect', '-snapshots', str(cohort_dir), '-out', str(root / 'inspect.jsonl')])
    inspections = [json.loads(l) for l in open(root / 'inspect.jsonl') if l.strip()]
    inspection = next((x for x in reversed(inspections) if 'effective' in x), None)
    manifest = {
        'schema_version': 'math-lab.experiment-manifest.v1', 'experiment_id': experiment_id, 'title': request.get('title'),
        'mode': 'REPLAY', 'created_at': request.get('created_at'), 'run_owner': request.get('run_owner'),
        'hypothesis': request.get('hypothesis'), 'primary_metric_id': request.get('primary_metric_id'),
        'secondary_metric_ids': request.get('secondary_metric_ids') or [], 'safety_metric_ids': request.get('safety_metric_ids') or [],
        'parameter': {k: knob.get(k) for k in ('param_id', 'name', 'symbol', 'config_key', 'class', 'protected', 'replay_override', 'warnings')},
        'arms': request['arms'], 'replay_arms': arms, 'policy': request['namespace'] + '/' + request['policy'],
        'cohort': {'snapshot_digests': [e['digest'] for e in cohort], 'digests_sha256': sha256_json([e['digest'] for e in cohort]),
                   'summary': corpus_summary(cohort), 'selection': request.get('cohort')},
        'replay_binary': binary_identity, 'registry_version': registry_doc.get('registry_version'),
        'registry_sha256': sha256_json(registry_doc), 'learner_state_protocol': 'recorded owner state restored exactly per tick (RLS, conformal window, runtime lambda, stage clock, conjugate prior)',
        'comparator_mode': 'MATCHED_SNAPSHOT', 'score_reference': 'CONTROL_FACT_WEIGHTS',
        'control_inspection': inspection and {k: inspection.get(k) for k in ('snapshot_digest', 'effective', 'learned')},
        'limitations': ['Replay measures immediate decision sensitivity on recorded states; it does not observe defense, SLO impact or future-state effects.',
                        'After an arm diverges from the control, later recorded states no longer follow from that arm.',
                        'ScopedOutcomes (reporting-only) is excluded from the exact baseline comparison.'],
        'request_sha256': sha256_json(request), 'started_at': utc()}
    write_json(root / 'experiment_manifest.json', manifest)
    _status(root, 'replay', 'replaying %d ticks x %d arms' % (len(cohort), len(arms)), 0, len(cohort))
    cmd = [binary_identity['path'], '-snapshots', str(cohort_dir), '-arms', str(root / 'arms.json'),
           '-out', str(root / 'replay.jsonl'), '-summary', str(root / 'replay-summary.json')]
    if request.get('allow_cross_version'):
        cmd.append('-allow-cross-version')
    binary.run_isolated(cmd, timeout=3600)
    _status(root, 'analysis', 'computing metrics')
    lines = exports.stream_replay(root, experiment_id, root / 'replay.jsonl')
    cross = any(l.get('cross_version') for l in lines)
    observational = cross or binary_identity.get('local') or len((manifest['cohort']['summary'].get('git_sha') or {})) > 1
    ctx = {'experiment_id': experiment_id, 'arms': [a['arm_id'] for a in arms], 'control': arms[0]['arm_id'],
           'parameter_id': knob['param_id'], 'policy': manifest['policy'], 'seed': 20261009,
           'arm_values': arm_values(request, knob, inspection), 'comparison_status': 'OBSERVATIONAL' if observational else 'MATCHED_REPLAY'}
    rows, plots, population = analysis.analyze(lines, ctx)
    result = {'schema_version': 'math-lab.experiment-result.v1', 'experiment_id': experiment_id, 'comparison_status': ctx['comparison_status'],
              'population': population, 'replay_summary': read_json(root / 'replay-summary.json'), 'arm_values': ctx['arm_values'],
              'finished_at': utc()}
    write_json(root / 'metrics.json', rows)
    write_json(root / 'plots.json', plots)
    write_json(root / 'result.json', result)
    _status(root, 'export', 'writing evidence')
    exports.write_all(root, manifest, rows, plots, result)
    matched_trials = [population['matched_by_arm'].get(a['arm_id'], 0) for a in arms[1:]]
    state = 'COMPLETE' if population['control_eligible'] and all(matched_trials) and population['control_eligible'] == len(cohort) else ('PARTIAL' if population['control_eligible'] else 'INVALID')
    _status(root, 'done', 'finished', len(cohort), len(cohort), state=state)
    return state
