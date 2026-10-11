"""Brain-verified runtime optimizer parameters, read from the Console.

The Console's Optimizer Bench writes the economic knobs of every app's live PhorvexPolicy and
checks each one against the brain's newest decision trace (GET /api/optimizer/runtime); every
write is audited (GET /api/optimizer/parameter-log). This module only reads both, so a benchmark
run records which parameters the brain was actually deciding with when it started and ended, and
the dashboard can show a timeline of those observations. It never writes to the cluster.
"""
import csv
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

RUNTIME_PATH = '/api/optimizer/runtime'
LOG_PATH = '/api/optimizer/parameter-log?limit=200'
SCHEMA = 'phorvex.benchmark.brain-parameters.v1'
OBSERVATION_SCHEMA = 'phorvex.benchmark.brain-parameter-observation.v1'
CSV_FILE = 'Brain_Parameters.csv'
CSV_HEADERS = ['namespace', 'policy', 'parameter', 'symbol', 'spec_path',
               'configured_before', 'brain_before', 'status_before', 'generation_before', 'brain_generation_before',
               'configured_after', 'brain_after', 'status_after', 'generation_after', 'brain_generation_after', 'changed_during_run']


def utc():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def capture(console):
    """Runtime parameters and change log as one record; a missing endpoint is recorded, never fatal."""
    record = {'schema': SCHEMA, 'fetchedAt': utc(), 'runtime': None, 'log': None, 'errors': []}
    for key, path in (('runtime', RUNTIME_PATH), ('log', LOG_PATH)):
        try:
            record[key] = console.request(path)
        except Exception as error:  # transport, HTTP status or JSON; the reason is recorded verbatim-free
            status = getattr(error, 'status', None)
            record['errors'].append('%s unavailable%s' % (path.split('?')[0], ' (HTTP %s)' % status if status else ''))
    return record


def value(v):
    if not isinstance(v, dict) or not v.get('present'):
        return ''
    return v.get('value')


def rows(record):
    """One row per (app policy, knob): configured value, brain value, verdict and generations."""
    runtime = (record or {}).get('runtime') or {}
    symbols = {c['key']: c for c in runtime.get('catalogue') or []}
    out = {}
    for policy in runtime.get('policies') or []:
        brain = policy.get('brain') or {}
        for p in policy.get('parameters') or []:
            meta = symbols.get(p['key'], {})
            out[(policy['namespace'], policy['name'], p['key'])] = {
                'namespace': policy['namespace'], 'policy': policy['name'], 'parameter': p['key'], 'symbol': meta.get('symbol', ''),
                'spec_path': meta.get('specPath', ''), 'configured': value(p.get('configured')), 'brain': value(p.get('observed')),
                'status': p.get('status', ''), 'generation': policy.get('generation'), 'brain_generation': brain.get('generation'),
                'economics_mode': policy.get('economicsMode')}
    return out


def compare(before, after):
    """Per-row before/after plus the knobs whose configured value moved during the run."""
    one, two = rows(before), rows(after)
    merged, changed = [], []
    for key in sorted(set(one) | set(two)):
        b, a = one.get(key, {}), two.get(key, {})
        moved = bool(b and a and (b['configured'] != a['configured'] or b['generation'] != a['generation']))
        if moved:
            changed.append('%s/%s:%s' % key)
        base = a or b
        merged.append({'namespace': base['namespace'], 'policy': base['policy'], 'parameter': base['parameter'], 'symbol': base['symbol'],
                       'spec_path': base['spec_path'],
                       'configured_before': b.get('configured', ''), 'brain_before': b.get('brain', ''), 'status_before': b.get('status', ''),
                       'generation_before': b.get('generation', ''), 'brain_generation_before': b.get('brain_generation', ''),
                       'configured_after': a.get('configured', ''), 'brain_after': a.get('brain', ''), 'status_after': a.get('status', ''),
                       'generation_after': a.get('generation', ''), 'brain_generation_after': a.get('brain_generation', ''),
                       'changed_during_run': 'yes' if moved else ''})
    return merged, changed


def summary(before, after):
    merged, changed = compare(before, after)
    def verdicts(prefix):
        counts = {}
        for r in merged:
            if r['status_' + prefix]:
                counts[r['status_' + prefix]] = counts.get(r['status_' + prefix], 0) + 1
        return counts
    return {'schema': SCHEMA, 'before': {'fetchedAt': (before or {}).get('fetchedAt'), 'errors': (before or {}).get('errors', []), 'verdicts': verdicts('before')},
            'after': {'fetchedAt': (after or {}).get('fetchedAt'), 'errors': (after or {}).get('errors', []), 'verdicts': verdicts('after')},
            'changedDuringRun': changed,
            'note': 'VERIFIED = the brain decision at the policy generation in force carried the configured value.'}


def write_csv(path, before, after):
    merged, _ = compare(before, after)
    with open(path, 'w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADERS)
        for r in merged:
            writer.writerow([r[h] for h in CSV_HEADERS])
    return len(merged)


def _fingerprint(policy):
    brain = policy.get('brain') or {}
    return json.dumps([policy.get('generation'), policy.get('economicsMode'), brain.get('generation'),
                       [(p['key'], value(p.get('configured')), value(p.get('observed')), p.get('status')) for p in policy.get('parameters') or []]],
                      sort_keys=True)


def observe(data_dir, record, limit_lines=20000):
    """Append one observation per policy whose configured values, generation or verdicts changed
    since its last observation. The file is the dashboard's parameter timeline."""
    root = Path(data_dir) / 'parameters'
    root.mkdir(parents=True, exist_ok=True)
    path = root / 'observations.jsonl'
    last = {}
    if path.exists():
        with open(path) as handle:
            for line in handle:
                try:
                    obs = json.loads(line)
                except ValueError:
                    continue
                last[obs.get('policyKey')] = obs.get('fingerprint')
    added = []
    for policy in ((record or {}).get('runtime') or {}).get('policies') or []:
        key = policy['namespace'] + '/' + policy['name']
        fp = _fingerprint(policy)
        if last.get(key) == fp:
            continue
        brain = policy.get('brain') or {}
        added.append({'schema': OBSERVATION_SCHEMA, 'observedAt': record.get('fetchedAt'), 'policyKey': key, 'fingerprint': fp,
                      'generation': policy.get('generation'), 'economicsMode': policy.get('economicsMode'),
                      'brainGeneration': brain.get('generation'), 'brainDecisionTime': brain.get('decisionTime'),
                      'effectiveCostCoefficient': brain.get('effectiveCostCoefficient'), 'lambdaRuntime': brain.get('lambdaRuntime'),
                      'parameters': [{'key': p['key'], 'configured': value(p.get('configured')), 'brain': value(p.get('observed')),
                                      'status': p.get('status')} for p in policy.get('parameters') or []]})
    if added:
        with open(path, 'a') as handle:
            for obs in added:
                handle.write(json.dumps(obs, sort_keys=True) + '\n')
        _trim(path, limit_lines)
    return added


def _trim(path, limit_lines):
    with open(path) as handle:
        lines = handle.readlines()
    if len(lines) <= limit_lines:
        return
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    with os.fdopen(fd, 'w') as handle:
        handle.writelines(lines[-limit_lines:])
    os.replace(tmp, path)


def recent_observations(data_dir, limit=500):
    path = Path(data_dir) / 'parameters' / 'observations.jsonl'
    if not path.exists():
        return []
    with open(path) as handle:
        lines = handle.readlines()[-limit:]
    out = []
    for line in reversed(lines):
        try:
            obs = json.loads(line)
        except ValueError:
            continue
        obs.pop('fingerprint', None)
        out.append(obs)
    return out
