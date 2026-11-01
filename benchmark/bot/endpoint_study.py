"""Paired Go endpoint-cost reference experiments with explicit evidence preflight.

This is not an LLM-generated production brain patch. Uploaded inline traces are
synthetic fixtures; recorded input is installed by an operator, never inferred
from legacy cost scores, pod counts or missing move history.
"""
import argparse
import copy
from contextlib import ExitStack
import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

from study_schema import fields, integer, number, POLICY, strict_json
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from mathlab import stage_scope, snapshots

SCHEMA = 'phorvex-bench.endpoint-study.v1'
TRACE_SCHEMA = 'phorvex-bench.endpoint-trace.v1'
LEGACY_V3_PROMPT_SHA = '4fedcc3e93ec6568564bdc9535928dd1b4cecbd41e49939aaaba518cd0f0d51b'
CONSTANTS = {'lookback': (1, 2592000), 'min': (1e-12, 1e9), 'max': (1e-12, 1e9),
             'eta': (1e-12, 1), 'g_max': (1e-12, 100), 'max_dt': (1e-12, 30), 'delta': (1e-12, 3600)}
STUDY_SETTINGS = {'slo_target': (0, 1), 'window': (1, 2592000), 'worth_threshold': (0, 1e12)}
REQUIRED = [
    {'field': 'ticks[].spec_replicas', 'reason': 'Exact historical workload spec.replicas and UID; observed/ready pod count is not a substitute.'},
    {'field': 'ticks[].ledger', 'reason': 'Coherent measured endpoint-loss intervals attributed to actual move IDs, including open/settled revisions and known coverage.'},
    {'field': 'ticks[].candidates', 'reason': 'Complete candidate set from the pinned generator, grounded fact-to-actuator/provenance mapping and all non-cost hard gates.'},
    {'field': 'ticks[].candidates[].samples', 'reason': 'Qualified workload/action duration samples, censoring, overdue and suspect-lineage evidence; unknown history is not n=0.'},
    {'field': 'ticks[].slo', 'reason': 'Accepted SLO or explicitly labelled study assumptions; neither creates missing history or admission authority.'},
]

# Validate the complete JSON shape before queuing. Missing observational values
# are allowed as null/absent and become BLOCKED evidence, but misspelled fields
# and wrong types are request errors, not failed benchmark jobs.
SHAPES = {
    'slo': {'target':'number','window':'number','accepted':'bool','study_assumption':'bool'},
    'ledger': {'at':'number','complete_from':'number?','authoritative':'bool','measurement':'str','moves':'move[]'},
    'move': {'id':'str','revision':'int','workload_uid':'str','policy_uid':'str','action':'str','containment':'bool',
             'state':'str','observed_at':'number','attributed':'bool','measured':'bool','intervals':'interval[]','reservation':'number?','overdue':'bool'},
    'interval': {'endpoint_uid':'str','start':'number','end':'number'},
    'candidate': {'id':'str','pod_uid':'str','action':'str','facts':'fact[]','facts_known':'bool','gates':'str[]',
                  'gates_known':'bool','worth_threshold':'number?','containment':'bool','k':'int?','class':'str',
                  'history_known':'bool','samples':'sample[]','hold_cap':'number?','documented_bound':'bound?'},
    'sample': {'id':'str','workload_uid':'str','action':'str','at':'number','duration':'number?',
               'censored':'bool','overdue':'bool','suspect':'bool'},
    'fact': {'id':'str','weight':'number'},
    'bound': {'source':'str','approved':'bool','mid':'number','upper':'number','failure_upper':'number'},
}
ARRAY_LIMITS = {'moves':10000,'intervals':1000,'facts':512,'samples':2000,'gates':128}


def typed(value, kind, path):
    if kind.endswith('?'):
        if value is None: return
        kind = kind[:-1]
    if kind.endswith('[]'):
        if value is None: return  # Go nil slices; knowledge flags remain separate.
        if not isinstance(value,list) or len(value)>ARRAY_LIMITS[path.rsplit('.',1)[-1]]:
            raise ValueError(path+' must be a bounded array')
        for item in value: typed(item,kind[:-2],path+'[]')
    elif kind == 'number': number(value,path)
    elif kind == 'int':
        if type(value) is not int or not -(2**31)<=value<2**31: raise ValueError(path+' must be a bounded integer')
    elif kind == 'bool':
        if type(value) is not bool: raise ValueError(path+' must be boolean')
    elif kind == 'str':
        if not isinstance(value,str) or len(value)>2000: raise ValueError(path+' must be a short string')
    else:
        shape=SHAPES[kind]; fields(value,shape)
        for key,item in value.items(): typed(item,shape[key],path+'.'+key)


def legacy_request(prompt, policy, ticks):
    """Recognize only the exact reviewed upload, never fuzzy-map arbitrary prose."""
    if hashlib.sha256(' '.join(prompt.split()).encode()).hexdigest() != LEGACY_V3_PROMPT_SHA:
        return None
    return {'schema': SCHEMA, 'title': 'V3 endpoint cost and adaptive lambda — recorded inputs',
            'policy': policy, 'ticks': ticks, 'dataset': 'recorded', 'config': {}}


def validate(request):
    r = copy.deepcopy(request)
    fields(r, ('schema', 'title', 'policy', 'ticks', 'dataset', 'trace', 'config', 'study'), ('schema', 'title', 'policy'))
    if r['schema'] != SCHEMA or not isinstance(r['title'], str) or not 1 <= len(r['title']) <= 200:
        raise ValueError('unsupported endpoint study schema or title')
    if not isinstance(r['policy'], str) or not POLICY.fullmatch(r['policy']):
        raise ValueError('policy must be namespace/name')
    if ('trace' in r) == ('dataset' in r):
        raise ValueError('provide exactly one of trace or dataset')
    if 'dataset' in r and r['dataset'] != 'recorded':
        raise ValueError('dataset must be recorded; arbitrary paths are forbidden')
    r.setdefault('ticks', 64)
    integer(r['ticks'], 'ticks', 1, 5000)
    r.setdefault('config', {})
    fields(r['config'], CONSTANTS)
    for key, value in r['config'].items():
        number(value, key, *CONSTANTS[key])
    if r['config'].get('min', .0001) >= r['config'].get('max', 1000):
        raise ValueError('lambda min must be below max')
    if 'study' in r:
        fields(r['study'], STUDY_SETTINGS)
        for key, value in r['study'].items():
            number(value, 'study.' + key, *STUDY_SETTINGS[key])
        if 'slo_target' in r['study'] and not 0 < r['study']['slo_target'] < 1:
            raise ValueError('study.slo_target must be strictly between 0 and 1')
    if 'trace' in r:
        validate_trace(r['trace'])
        if r['trace']['evidence'] != 'synthetic':
            raise ValueError('inline uploaded traces are synthetic fixtures; recorded traces require operator installation')
        if len(r['trace']['ticks']) < r['ticks']:
            raise ValueError('inline trace contains fewer ticks than requested; set ticks to the actual fixture length')
    return r


def validate_trace(trace):
    fields(trace, ('schema', 'evidence', 'source_revision', 'ticks'), ('schema', 'evidence', 'source_revision', 'ticks'))
    if trace['schema'] != TRACE_SCHEMA or trace['evidence'] not in ('recorded', 'synthetic'):
        raise ValueError('unsupported endpoint trace schema/evidence')
    if not isinstance(trace['source_revision'], str) or not trace['source_revision']:
        raise ValueError('trace source_revision is required')
    if trace['evidence'] == 'recorded' and not re.fullmatch('[0-9a-f]{40}', trace['source_revision']):
        raise ValueError('recorded trace needs a full source commit SHA')
    ticks = trace['ticks']
    if not isinstance(ticks, list) or not 1 <= len(ticks) <= 5000:
        raise ValueError('trace needs 1..5000 ticks')
    seen = set()
    for tick in ticks:
        fields(tick, ('id', 'at', 'workload_uid', 'policy_uid', 'spec_replicas', 'slo', 'ledger', 'candidates',
                      'candidate_set_complete', 'mandatory_id'),
               ('id', 'at', 'workload_uid', 'policy_uid', 'candidates', 'candidate_set_complete'))
        for key in ('id', 'workload_uid', 'policy_uid'):
            if not isinstance(tick[key], str) or not 1 <= len(tick[key]) <= 160:
                raise ValueError('tick '+key+' must be a short nonempty string')
        if tick['id'] in seen:
            raise ValueError('duplicate tick id')
        seen.add(tick['id']); number(tick['at'], 'tick.at')
        if type(tick['candidate_set_complete']) is not bool:
            raise ValueError('candidate_set_complete must be boolean')
        if tick.get('spec_replicas') is not None:
            integer(tick['spec_replicas'], 'spec_replicas', 0, 1000000)
        if not isinstance(tick['candidates'], list) or len(tick['candidates']) > 256:
            raise ValueError('maximum 256 candidates per tick')
        for key in ('slo','ledger'):
            if tick.get(key) is not None: typed(tick[key],key,'tick.'+key)
        if 'mandatory_id' in tick: typed(tick['mandatory_id'],'str','tick.mandatory_id')
        for c in tick['candidates']:
            typed(c,'candidate','tick.candidate')
            if any(not c.get(k) for k in ('id','pod_uid','action')):
                raise ValueError('candidate id, pod_uid and action are required')
    if sum(len(t['candidates']) for t in ticks) > 100000:
        raise ValueError('maximum 100000 candidate rows')
    # The Go binary independently validates this shape and the contract/gates.
    # Structure validation never establishes empirical readiness.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def study_trace(trace, request, normalization=None):
    """Apply only declared study assumptions; retain source-owned evidence.

    A longer observed window is allowed only when the normalizer explicitly
    retained all moves, untrimmed intervals and duration samples. Knowledge and
    admission flags never become true because of a request override.
    """
    trace = copy.deepcopy(trace)
    requested = request.get('study', {})
    lookback = request['config'].get('lookback', 86400)
    normalized = normalization or {}
    original = normalized.get('study_settings') or {}
    retention = normalized.get('retention') or {}
    retained = (retention.get('schema') == 'phorvex-stage.retained-history.v1' and
                retention.get('moves') == 'all-observed' and retention.get('samples') == 'all-observed' and
                retention.get('interval_clipping') is False)
    bindings = normalized.get('bindings') or []
    by_digest = {binding.get('snapshot_digest'): binding for binding in bindings}
    unique_bindings = len(by_digest) == len(bindings)
    evidence = {'requested': copy.deepcopy(requested), 'config_lookback': lookback,
                'original_normalization_study_settings': copy.deepcopy(original),
                'retention': copy.deepcopy(retention), 'ticks': []}
    missing = {}

    def finite(value):
        return type(value) in (int, float) and math.isfinite(value)

    for tick in trace['ticks']:
        slo = tick.get('slo') or {}
        if requested:
            slo = {**slo, 'accepted': False, 'study_assumption': True}
            if 'slo_target' in requested: slo['target'] = requested['slo_target']
            if 'window' in requested: slo['window'] = requested['window']
            tick['slo'] = slo
            if 'worth_threshold' in requested:
                for candidate in tick['candidates']:
                    candidate['worth_threshold'] = requested['worth_threshold']
        detail = {'tick_id': tick['id'], 'slo_target': slo.get('target'), 'window': slo.get('window'),
                  'worth_thresholds': {c['id']: c.get('worth_threshold') for c in tick['candidates']}}
        evidence['ticks'].append(detail)
        if trace['evidence'] != 'recorded':
            continue
        reasons = []
        at, window = tick['at'], slo.get('window')
        ledger = tick.get('ledger') or {}
        binding = by_digest.get(tick['id']) or {}
        complete = ledger.get('complete_from')
        sealed = binding.get('sealed_until')
        detail.update(complete_from=complete, sealed_until=sealed,
                      available_history_seconds=at-complete if finite(complete) and complete <= at else None)
        if (not unique_bindings or binding.get('at') != at or ledger.get('at') != at or
                binding.get('complete_from') != complete or not finite(sealed) or sealed < at):
            reasons.append('OBSERVED_HISTORY_BINDING_INVALID: normalize again from the sealed stage journal')
        if not finite(window) or window <= 0:
            reasons.append('STUDY_WINDOW_MISSING: supply study.window or normalize a declared window')
        else:
            required = max(window, lookback)
            detail['required_history_seconds'] = required
            if not finite(complete) or complete > at-required:
                available = detail['available_history_seconds']
                reasons.append('OBSERVED_HISTORY_INSUFFICIENT: W=%s s, L=%s s require %s s; retained continuous history=%s s. Collect the missing history and normalize again; no history is backdated.' %
                               (window, lookback, required, available if available is not None else 'unknown'))
            original_window, original_lookback = original.get('window'), original.get('lookback')
            expands = (not finite(original_window) or not finite(original_lookback) or
                       window > original_window or lookback > original_lookback)
            if expands and not retained:
                reasons.append('RETAINED_HISTORY_UNPROVEN: expanded W/L requires all observed moves, untrimmed intervals and all duration samples; normalize again with the current producer')
        if any(candidate.get('history_known') is not True for candidate in tick['candidates']):
            reasons.append('DURATION_HISTORY_UNKNOWN: a study override cannot create recorded duration history')
        if reasons:
            missing[tick['id']] = reasons
    return trace, evidence, missing


def binary_identity():
    root = Path(__file__).resolve().parents[1] / 'endpointv3'
    repo = root.parents[1]
    identity = strict_json((root / 'BUILD.json').read_text())
    binary = root / 'bin' / 'endpoint-v3'
    expected = {str(p.relative_to(repo)) for folder in ('phorvex/internal/cost/endpoint', 'phorvex/cmd/endpoint-v3')
                for p in (repo / folder).glob('*.go')} | {'phorvex/go.mod', 'phorvex/go.sum'}
    if identity.get('schema') != 'phorvex-bench.endpoint-build.v2' or set(identity.get('sources', {})) != expected:
        raise ValueError('endpoint Go build manifest has an incomplete source inventory')
    if identity.get('binary_sha256') != sha(binary):
        raise ValueError('endpoint Go binary does not match its release manifest')
    for name, value in identity.get('sources', {}).items():
        if Path(name).is_absolute() or '..' in Path(name).parts or sha(repo / name) != value:
            raise ValueError('endpoint Go source differs from the verified binary manifest')
    return binary, identity


def recorded_readiness(data_dir, policy, limit, root):
    """Read-only producer-capability audit using the deployed decoder, not guesses."""
    import code_experiment
    from mathlab.common import sha256_file
    try:
        pin = stage_scope.load(data_dir, policy)
        ident = stage_scope.identity(data_dir, pin)
    except stage_scope.StageError as error:
        return {'status': 'BLOCKED', 'reason': str(error), 'required_inputs': REQUIRED}
    ns, name = stage_scope.policy(policy)
    data_dir = Path(data_dir)
    current = data_dir / 'mathlab/bin/current.json'
    if not current.is_file():
        return {'status': 'BLOCKED', 'reason': 'No verified deployed replay binary is available.', 'required_inputs': REQUIRED}
    if sha256_file(ident['path']) != ident['binary_sha256']:
        raise ValueError('deployed replay binary hash mismatch')
    cohort = code_experiment.select_cohort(data_dir, {'namespace': ns, 'policy': name,
                        'cohort': {**stage_scope.cohort_filter(pin, policy),
                                   'max_snapshots': limit, 'spacing': 'even'}})
    frozen = root / 'cohort'; frozen.mkdir()
    for entry in cohort:
        p = data_dir / 'mathlab/snapshots' / policy / (entry['digest']+'.pxms')
        if sha(p) != entry['digest']:
            raise ValueError('snapshot digest mismatch')
        shutil.copy2(p, frozen/p.name)
    try:
        if cohort:
            code_experiment.binary.run_isolated([ident['path'], '-inspect', '-snapshots', str(frozen),
                                                '-out', str(root/'inspection.jsonl')], timeout=300)
        rows = [strict_json(s) for s in (root/'inspection.jsonl').read_text().splitlines()] if cohort else []
    finally:
        shutil.rmtree(frozen)
    return {'status': 'BLOCKED', 'base_commit': ident['git_sha'], 'snapshots_inspected': len(rows),
            'reason': 'No qualified normalized endpoint trace is installed. Legacy snapshots cannot supply missing move-attributed endpoint history or a complete new-cost candidate export.',
            'required_inputs': REQUIRED,
            'ticks': [{'digest': r.get('snapshot_digest'), 'at': r.get('header', {}).get('capturedAt'),
                       'configured_slo': r.get('configured_spec', {}).get('slo'),
                       'endpoint_cost_evidence': r.get('endpoint_cost_evidence'),
                       'missing': r.get('endpoint_cost_missing', ['endpoint_cost_evidence:not-recorded'])} for r in rows]}


def export(root, result):
    (root/'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)+'\n')
    rows = []
    for tick in result.get('ticks', []):
        for arm in ('v2', 'v3'):
            for c in tick.get(arm, {}).get('candidates', []):
                rows.append({'tick': tick['tick_id'], 'at': tick['at'], 'state': tick['state'], 'arm': arm,
                             'candidate': c['candidate_id'], 'action': c['action'], 'V': c['V'],
                             **{k: c['cost'].get(k) for k in ('E', 'rho', 'T_mid', 'T_upper', 'p_f')},
                             **{k: tick['budget'].get(k) for k in ('R', 'used', 'held', 'S')},
                             **{k: tick['lambda'].get(k) for k in ('lambda_prev', 'lambda_next', 'b', 'g', 'dt', 'state_write', 'reason')},
                             'lambda_eff': tick['lambda']['lambda_eff'] if arm == 'v3' else 0,
                             'J': c['J'], 'selected': c['selected'], 'refusals': '; '.join(c['refusals'])})
    if not rows:
        rows = [{'state': result['state'], 'reason': result.get('reason'), 'v2_executed': False, 'v3_executed': False}]
    with (root/'metrics.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    title = 'Paired stage brain endpoint replay' if result.get('mode') == 'PAIRED_BRAIN_REPLAY' else 'Paired endpoint-cost Go reference experiment'
    summary = {'state': result['state'], 'evidence': result.get('evidence'), 'mode': result.get('mode'),
               'capture_source': (result.get('runner') or {}).get('capture_control', {}).get('git_sha'),
               'study_source': (result.get('runner') or {}).get('git_sha'),
               'comparison_status': (result.get('runner') or {}).get('comparison_status'),
               'comparable_ticks': result.get('comparable_ticks'), 'changed_choices': result.get('changed_choices'),
               'noop': result.get('noop'), 'forecast_endpoint_seconds': result.get('forecast_endpoint_seconds'),
               'reason': result.get('reason'), 'missing_reasons': result.get('missing_reasons'),
               'study': result.get('study'),
               'limitations': result.get('limitations'), 'required_inputs': result.get('preflight', {}).get('required_inputs')}
    page = '<!doctype html><meta charset="utf-8"><title>'+title+'</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:36px auto;padding:20px}pre{white-space:pre-wrap;background:#f0f4f6;padding:20px}a{color:#075ba8}</style>'
    page += '<h1>'+title+'</h1><p><strong>'+html.escape(result['state'])+'</strong> — no physical actuation or production deployment.</p>'
    page += '<pre>'+html.escape(json.dumps(summary, indent=2, ensure_ascii=False))+'</pre>'
    page += '<p>Null/blank means unavailable, never zero. Forecast cost is not realized counterfactual cost. Counts refer only to comparable ticks.</p><p><a href="metrics.csv">Candidate CSV</a> · <a href="result.json">Full JSON</a></p>'
    (root/'report.html').write_text(page)
    manifest = {str(p.relative_to(root)): sha(p) for p in root.rglob('*') if p.is_file() and p.name not in ('evidence.zip', 'SHA256SUMS.json')}
    (root/'SHA256SUMS.json').write_text(json.dumps(manifest, indent=2)+'\n')
    with zipfile.ZipFile(root/'evidence.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(root.rglob('*')):
            if p.is_file() and p.name != 'evidence.zip': z.write(p, p.relative_to(root))


def run(request, root, data_dir=None, progress=lambda _: None, cancelled=lambda: False):
    request = validate(request)
    with ExitStack() as readers:
        if request.get('dataset') == 'recorded' and data_dir:
            ns, name = stage_scope.policy(request['policy'])
            readers.enter_context(snapshots.cache_lock(data_dir, ns, name))
        return _run(request, root, data_dir, progress, cancelled, readers.close)


def _run(request, root, data_dir, progress, cancelled, release_cache):
    request = validate(request); root = Path(root); root.mkdir(parents=True, exist_ok=True)
    (root/'request.json').write_text(json.dumps(request, ensure_ascii=False, indent=2)+'\n')
    if cancelled():
        result = {'state': 'CANCELLED', 'reason': 'Cancelled before execution'}; export(root,result); return result
    progress('checking endpoint study evidence and paired Go runner')
    normalized = None
    original_trace_sha256 = None
    if 'trace' in request:
        trace = request['trace']
    else:
        legacy_source = Path(data_dir)/'mathlab/endpoint-traces'/(request['policy']+'.json') if data_dir else None
        provenance = legacy_source.with_suffix('.manifest.json') if legacy_source else None
        if not provenance or not provenance.is_file():
            preflight = recorded_readiness(data_dir, request['policy'], request['ticks'], root) if data_dir else {'reason': 'MATHLAB_DATA_DIR is unavailable', 'required_inputs': REQUIRED}
            result = {'schema': 'phorvex-bench.endpoint-result.v1', 'state': 'BLOCKED', 'mode': 'PAIRED_GO_REFERENCE',
                      'evidence': 'recorded-unavailable', 'reason': preflight['reason'], 'preflight': preflight,
                      'v2_executed': False, 'v3_executed': False, 'changed_choices': None, 'comparable_ticks': 0,
                      'limitations': ['Both requested arms were stopped before execution because mandatory recorded inputs are unavailable. No model tokens or Go builds were spent.']}
            export(root, result); return result
        if provenance.stat().st_size > 64*1024*1024: raise ValueError('installed manifest exceeds 64 MiB')
        meta = strict_json(provenance.read_text())
        name = meta.get('trace_file')
        if name is not None:
            expected_name = legacy_source.stem + '.' + str(meta.get('trace_sha256')) + '.trace.json'
            if not isinstance(name, str) or Path(name).name != name or name != expected_name or not re.fullmatch(r'[0-9a-f]{64}', str(meta.get('trace_sha256'))):
                raise ValueError('installed trace generation must be a safe content-addressed basename')
            source = provenance.parent / name
        else:
            source = legacy_source  # Older reviewed installations remain readable.
        if source.is_symlink() or not source.is_file(): raise ValueError('installed trace generation is missing or unsafe')
        if source.stat().st_size > 64*1024*1024: raise ValueError('installed trace exceeds 64 MiB')
        if meta.get('trace_sha256') != sha(source) or meta.get('policy') != request['policy']:
            raise ValueError('installed recorded trace manifest mismatch')
        trace = strict_json(source.read_text()); validate_trace(trace)
        if trace['evidence'] != 'recorded': raise ValueError('recorded dataset is not recorded evidence')
        if meta.get('source_revision') != trace['source_revision'] or not meta.get('producer'):
            raise ValueError('recorded dataset producer/source revision is missing or mismatched')
        pin = stage_scope.load(data_dir, request['policy'])
        if (meta.get('schema') != 'phorvex-stage.endpoint-manifest.v1' or
                meta.get('policy_uid') != pin['policies'][request['policy']]['uid'] or
                meta.get('image_digest') != pin['brain']['image_digest'] or
                meta.get('snapshot_source_revision', meta.get('source_revision')) != pin['brain']['git_sha'] or
                meta.get('repository') not in (stage_scope.REPOSITORY, 'PhorvexSecurity/operator-refactored')):
            raise ValueError('recorded endpoint dataset is not bound to the installed stage image and policy')
        normalized = meta.get('normalization') or {}
        if normalized.get('state') != 'READY' or normalized.get('missing'):
            raise ValueError('recorded endpoint normalization is not complete')
        if set(meta.get('snapshot_digests', [])) != {tick['id'] for tick in trace['ticks']}:
            raise ValueError('recorded endpoint snapshot manifest differs from trace tick identities')
        original_trace_sha256 = meta['trace_sha256']
        (root/'dataset-manifest.json').write_text(json.dumps(meta, indent=2)+'\n')
    trace = copy.deepcopy(trace)
    trace['ticks'].sort(key=lambda t: (t['at'], t['id']))
    if len(trace['ticks']) < request['ticks']: raise ValueError('recorded dataset has fewer ticks than requested')
    # A contiguous tail avoids silently skipping controller updates in a study.
    trace['ticks'] = trace['ticks'][-request['ticks']:]
    trace, study, missing = study_trace(trace, request, normalized)
    study['original_trace_sha256'] = original_trace_sha256
    (root/'study-settings.json').write_text(json.dumps(study, indent=2, allow_nan=False)+'\n')
    (root/'trace.json').write_text(json.dumps(trace, allow_nan=False)+'\n')
    (root/'config.json').write_text(json.dumps(request['config'])+'\n')
    if missing:
        result = {'schema': 'phorvex-bench.endpoint-result.v1', 'state': 'BLOCKED', 'mode': 'PAIRED_BRAIN_REPLAY',
                  'evidence': 'recorded', 'phase': 'PREFLIGHT', 'study': study,
                  'reason': 'Requested study windows are not supported by the retained observed evidence.',
                  'missing_reasons': missing, 'v2_executed': False, 'v3_executed': False,
                  'changed_choices': None, 'comparable_ticks': 0, 'requested_ticks': len(trace['ticks']),
                  'forecast_endpoint_seconds': None, 'counterfactual_actual_charges': None,
                  'limitations': ['Study settings cannot create missing move history or duration samples. Neither requested arm executed.']}
        export(root, result); return result
    if trace['evidence'] == 'recorded':
        import code_experiment
        pin = stage_scope.load(data_dir, request['policy'])
        control = stage_scope.identity(data_dir, pin)
        engine = None
        if trace['source_revision'] == control['git_sha']:
            identity = control
        else:
            engine = stage_scope.study_engine(data_dir, pin)
            identity = engine['candidate']
            if trace['source_revision'] != identity['git_sha']:
                raise ValueError('recorded endpoint candidate export differs from the reviewed study engine; normalize with the installed engine')
        ns, name = stage_scope.policy(request['policy'])
        digests = [tick['id'] for tick in trace['ticks']]
        if len(set(digests)) != len(digests) or any(not re.fullmatch(r'[0-9a-f]{64}', d) for d in digests):
            raise ValueError('recorded endpoint tick IDs must be unique actual snapshot digests')
        cohort = code_experiment.select_cohort(data_dir, {'namespace': ns, 'policy': name,
                    'cohort': {**stage_scope.cohort_filter(pin, request['policy']),
                               'digests': digests, 'max_snapshots': len(digests)}})
        provenance = stage_scope.cohort(pin, request['policy'], cohort)
        if {e['digest'] for e in cohort} != set(digests):
            raise ValueError('recorded endpoint trace snapshots are missing from the pinned stage corpus')
        frozen = root / 'cohort'; frozen.mkdir()
        for entry in cohort:
            source = Path(data_dir) / 'mathlab/snapshots' / request['policy'] / (entry['digest'] + '.pxms')
            target = frozen / source.name; shutil.copy2(source, target)
            if sha(target) != entry['digest']: raise ValueError('recorded snapshot digest mismatch')
        release_cache()  # Frozen bytes now survive managed-cache pruning.
        if engine:
            progress('verifying captured-stage and local-base baselines before the experimental brain arms')
            for label, baseline in (('capture-control', control), ('base-local', engine['base_local'])):
                output = root / (label + '.jsonl')
                code_experiment.binary.run_isolated([baseline['path'], '-snapshots', str(frozen), '-out', str(output),
                    '-summary', str(root / (label + '-summary.json'))], timeout=1800)
                baseline_rows = [strict_json(line) for line in output.read_text().splitlines() if line.strip()]
                exact = (len(baseline_rows) == len(digests) and
                         {row.get('snapshot', {}).get('snapshot_digest') for row in baseline_rows} == set(digests) and
                         all(row.get('status') == 'OK' and (row.get('baseline_check') or {}).get('reproduced') is True
                             for row in baseline_rows))
                if not exact:
                    raise ValueError('%s did not exactly reproduce every recorded stage baseline; endpoint arms were not run' % label)
        cmd = [identity['path'], '--endpoint-study', str(root / 'trace.json'),
               '--endpoint-study-config', str(root / 'config.json'), '--snapshots', str(frozen),
               '--out', str(root / 'result.json'), '--summary', str(root / 'summary.json')]
        if engine:
            cmd.append('--allow-cross-version')
        identity = {**identity, 'stage_provenance': provenance, 'capture_control': control,
                    'study_engine': engine, 'cross_version': bool(engine),
                    'comparison_status': 'OBSERVATIONAL' if engine else 'MATCHED_REPLAY'}
    else:
        binary, identity = binary_identity()
        cmd = [str(binary), '-trace', str(root/'trace.json'), '-config', str(root/'config.json'),
               '-state-dir', str(root/'lambda-state'), '-out', str(root/'result.json')]
    progress('executing independent V2 and V3 arms in chronological order')
    env = {'PATH': os.environ.get('PATH','/usr/bin:/bin'), 'HOME': str(root), 'KUBECONFIG': os.devnull,
           'LANG': 'C.UTF-8', 'AWS_EC2_METADATA_DISABLED': 'true'}
    process = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    (root/'go-execution.log').write_text(process.stdout+process.stderr)
    if process.returncode: raise ValueError('paired Go runner rejected input: '+(process.stderr.strip()[-800:]))
    result = strict_json((root/'result.json').read_text())
    if trace['evidence'] == 'recorded' and (result.get('mode') != 'PAIRED_BRAIN_REPLAY' or
            result.get('baseline_exact_count') != len(trace['ticks']) or set(result.get('snapshot_digests', [])) != set(digests)):
        raise ValueError('brain study did not prove exact baseline and snapshot parity for every requested tick')
    result['runner'] = identity; result['trace_sha256'] = sha(root/'trace.json'); result['study'] = study
    export(root,result); return result


def install(source, data_dir, policy, producer):
    """Old arbitrary JSON imports cannot establish real stage measurements."""
    raise ValueError('Recorded endpoint input must be produced by benchmark.stage.normalize from the stage journal and exact brain candidate export; use --install-data-dir there')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('trace'); p.add_argument('--data-dir',required=True); p.add_argument('--policy',required=True); p.add_argument('--producer',required=True)
    a = p.parse_args(); print(json.dumps(install(a.trace,a.data_dir,a.policy,a.producer)))
