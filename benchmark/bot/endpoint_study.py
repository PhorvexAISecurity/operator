"""Paired Go endpoint-cost reference experiments with explicit evidence preflight.

This is not an LLM-generated production brain patch. Uploaded inline traces are
synthetic fixtures; recorded input is installed by an operator, never inferred
from legacy cost scores, pod counts or missing move history.
"""
import argparse
import copy
import csv
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from study_schema import fields, integer, number, POLICY, strict_json

SCHEMA = 'phorvex-bench.endpoint-study.v1'
TRACE_SCHEMA = 'phorvex-bench.endpoint-trace.v1'
LEGACY_V3_PROMPT_SHA = '4fedcc3e93ec6568564bdc9535928dd1b4cecbd41e49939aaaba518cd0f0d51b'
CONSTANTS = {'lookback': (1, 2592000), 'min': (1e-12, 1e9), 'max': (1e-12, 1e9),
             'eta': (1e-12, 1), 'g_max': (1e-12, 100), 'max_dt': (1e-12, 30), 'delta': (1e-12, 3600)}
REQUIRED = [
    {'field': 'ticks[].spec_replicas', 'reason': 'Exact historical workload spec.replicas and UID; observed/ready pod count is not a substitute.'},
    {'field': 'ticks[].ledger', 'reason': 'Coherent measured endpoint-loss intervals attributed to actual move IDs, including open/settled revisions and known coverage.'},
    {'field': 'ticks[].candidates', 'reason': 'Complete candidate set from the pinned generator, grounded fact-to-actuator/provenance mapping and all non-cost hard gates.'},
    {'field': 'ticks[].candidates[].samples', 'reason': 'Qualified workload/action duration samples, censoring, overdue and suspect-lineage evidence; unknown history is not n=0.'},
    {'field': 'ticks[].slo', 'reason': 'Accepted SLO or explicitly labelled study assumptions; neither creates missing history or admission authority.'},
]


def legacy_request(prompt, policy, ticks):
    """Recognize only the exact reviewed upload, never fuzzy-map arbitrary prose."""
    if hashlib.sha256(' '.join(prompt.split()).encode()).hexdigest() != LEGACY_V3_PROMPT_SHA:
        return None
    return {'schema': SCHEMA, 'title': 'V3 endpoint cost and adaptive lambda — recorded inputs',
            'policy': policy, 'ticks': ticks, 'dataset': 'recorded', 'config': {}}


def validate(request):
    r = copy.deepcopy(request)
    fields(r, ('schema', 'title', 'policy', 'ticks', 'dataset', 'trace', 'config'), ('schema', 'title', 'policy'))
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
    if sum(len(t['candidates']) for t in ticks) > 100000:
        raise ValueError('maximum 100000 candidate rows')
    # The Go binary performs the complete typed contract/gate validation. JSON
    # validation here establishes bounded structure, never empirical readiness.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def binary_identity():
    root = Path(__file__).resolve().parents[1] / 'endpointv3'
    identity = strict_json((root / 'BUILD.json').read_text())
    binary = root / 'bin' / 'endpoint-v3'
    expected = {str(p.relative_to(root)) for p in root.rglob('*.go')} | {'go.mod'}
    if identity.get('schema') != 'phorvex-bench.endpoint-build.v1' or set(identity.get('sources', {})) != expected:
        raise ValueError('endpoint Go build manifest has an incomplete source inventory')
    if identity.get('binary_sha256') != sha(binary):
        raise ValueError('endpoint Go binary does not match its release manifest')
    for name, value in identity.get('sources', {}).items():
        if Path(name).is_absolute() or '..' in Path(name).parts or sha(root / name) != value:
            raise ValueError('endpoint Go source differs from the verified binary manifest')
    return binary, identity


def recorded_readiness(data_dir, policy, limit, root):
    """Read-only producer-capability audit using the deployed decoder, not guesses."""
    import code_experiment
    from mathlab.common import sha256_file
    ns, name = policy.split('/')
    data_dir = Path(data_dir)
    current = data_dir / 'mathlab/bin/current.json'
    if not current.is_file():
        return {'status': 'BLOCKED', 'reason': 'No verified deployed replay binary is available.', 'required_inputs': REQUIRED}
    ident = strict_json(current.read_text())
    if sha256_file(ident['path']) != ident['binary_sha256']:
        raise ValueError('deployed replay binary hash mismatch')
    cohort = code_experiment.select_cohort(data_dir, {'namespace': ns, 'policy': name,
                        'cohort': {'git_sha': ident['git_sha'], 'max_snapshots': limit, 'spacing': 'even'}})
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
    title = 'Paired endpoint-cost Go reference experiment'
    summary = {'state': result['state'], 'evidence': result.get('evidence'), 'mode': result.get('mode'),
               'comparable_ticks': result.get('comparable_ticks'), 'changed_choices': result.get('changed_choices'),
               'noop': result.get('noop'), 'forecast_endpoint_seconds': result.get('forecast_endpoint_seconds'),
               'reason': result.get('reason'), 'missing_reasons': result.get('missing_reasons'),
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
    request = validate(request); root = Path(root); root.mkdir(parents=True, exist_ok=True)
    (root/'request.json').write_text(json.dumps(request, ensure_ascii=False, indent=2)+'\n')
    if cancelled():
        result = {'state': 'CANCELLED', 'reason': 'Cancelled before execution'}; export(root,result); return result
    progress('checking endpoint study evidence and paired Go runner')
    if 'trace' in request:
        trace = request['trace']
    else:
        source = Path(data_dir)/'mathlab/endpoint-traces'/(request['policy']+'.json') if data_dir else None
        provenance = source.with_suffix('.manifest.json') if source else None
        if not source or not source.is_file() or not provenance.is_file():
            preflight = recorded_readiness(data_dir, request['policy'], request['ticks'], root) if data_dir else {'reason': 'MATHLAB_DATA_DIR is unavailable', 'required_inputs': REQUIRED}
            result = {'schema': 'phorvex-bench.endpoint-result.v1', 'state': 'BLOCKED', 'mode': 'PAIRED_GO_REFERENCE',
                      'evidence': 'recorded-unavailable', 'reason': preflight['reason'], 'preflight': preflight,
                      'v2_executed': False, 'v3_executed': False, 'changed_choices': None, 'comparable_ticks': 0,
                      'limitations': ['Both requested arms were stopped before execution because mandatory recorded inputs are unavailable. No model tokens or Go builds were spent.']}
            export(root, result); return result
        if source.stat().st_size > 64*1024*1024: raise ValueError('installed trace exceeds 64 MiB')
        meta = strict_json(provenance.read_text())
        if meta.get('trace_sha256') != sha(source) or meta.get('policy') != request['policy']:
            raise ValueError('installed recorded trace manifest mismatch')
        trace = strict_json(source.read_text()); validate_trace(trace)
        if trace['evidence'] != 'recorded': raise ValueError('recorded dataset is not recorded evidence')
        if meta.get('source_revision') != trace['source_revision'] or not meta.get('producer'):
            raise ValueError('recorded dataset producer/source revision is missing or mismatched')
        (root/'dataset-manifest.json').write_text(json.dumps(meta, indent=2)+'\n')
    trace = copy.deepcopy(trace)
    trace['ticks'].sort(key=lambda t: (t['at'], t['id']))
    if len(trace['ticks']) < request['ticks']: raise ValueError('recorded dataset has fewer ticks than requested')
    # A contiguous tail avoids silently skipping controller updates in a study.
    trace['ticks'] = trace['ticks'][-request['ticks']:]
    (root/'trace.json').write_text(json.dumps(trace, allow_nan=False)+'\n')
    (root/'config.json').write_text(json.dumps(request['config'])+'\n')
    binary, identity = binary_identity()
    progress('executing independent V2 and V3 arms in chronological order')
    env = {'PATH': os.environ.get('PATH','/usr/bin:/bin'), 'HOME': str(root), 'KUBECONFIG': os.devnull,
           'LANG': 'C.UTF-8', 'AWS_EC2_METADATA_DISABLED': 'true'}
    cmd = [str(binary), '-trace', str(root/'trace.json'), '-config', str(root/'config.json'),
           '-state-dir', str(root/'lambda-state'), '-out', str(root/'result.json')]
    process = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    (root/'go-execution.log').write_text(process.stdout+process.stderr)
    if process.returncode: raise ValueError('paired Go runner rejected input: '+(process.stderr.strip()[-800:]))
    result = strict_json((root/'result.json').read_text())
    result['runner'] = identity; result['trace_sha256'] = sha(root/'trace.json')
    export(root,result); return result


def install(source, data_dir, policy, producer):
    if not POLICY.fullmatch(policy) or not producer.strip(): raise ValueError('policy and concrete producer reference required')
    source = Path(source)
    if source.stat().st_size > 64*1024*1024: raise ValueError('trace exceeds 64 MiB')
    trace = strict_json(source.read_text()); validate_trace(trace)
    if trace['evidence'] != 'recorded': raise ValueError('only recorded input may be installed')
    # Installation is an operator action, not an upload route or a claim that
    # a self-declared JSON provenance string proves physical measurements.
    target = Path(data_dir)/'mathlab/endpoint-traces'/(policy+'.json'); target.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(trace, allow_nan=False)+'\n').encode()
    fd, temp = tempfile.mkstemp(dir=target.parent, prefix='.endpoint-')
    try:
        with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(temp,target)
    finally:
        if os.path.exists(temp): os.unlink(temp)
    manifest = {'policy': policy, 'producer': producer, 'trace_sha256': sha(target), 'source_revision': trace['source_revision']}
    fd, temp = tempfile.mkstemp(dir=target.parent, prefix='.endpoint-manifest-')
    try:
        with os.fdopen(fd,'w') as f: json.dump(manifest,f,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(temp, target.with_suffix('.manifest.json'))
    finally:
        if os.path.exists(temp): os.unlink(temp)
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('trace'); p.add_argument('--data-dir',required=True); p.add_argument('--policy',required=True); p.add_argument('--producer',required=True)
    a = p.parse_args(); print(json.dumps(install(a.trace,a.data_dir,a.policy,a.producer)))
