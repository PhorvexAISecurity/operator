"""Strict, bounded declarative study input. No code, paths or shell expressions."""
import copy
import json
import re

from study_math import number

SCHEMA = 'phorvex-bench.study.v1'
TRACE_SCHEMA = 'phorvex-bench.study-trace.v1'
MAX_ROWS = 100000
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}$')
POLICY = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$')


class StudyError(ValueError):
    pass


def fields(obj, allowed, required=()):
    if not isinstance(obj, dict):
        raise StudyError('expected an object')
    unknown, missing = set(obj)-set(allowed), set(required)-set(obj)
    if unknown or missing:
        raise StudyError('unknown fields: %s; missing fields: %s' % (sorted(unknown), sorted(missing)))


def ident(value, name='id'):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise StudyError(name + ' must be a short identifier')


def boolean(value, name):
    if type(value) is not bool:
        raise StudyError(name + ' must be true or false')


def integer(value, name, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise StudyError('%s must be an integer in [%s, %s]' % (name, lo, hi))


def array(value, name, maximum, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise StudyError('%s must contain %d to %d items' % (name, minimum, maximum))


def strict_json(text):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise StudyError('duplicate JSON key: ' + k)
            out[k] = v
        return out
    def constant(value):
        raise StudyError('non-finite JSON number: ' + value)
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as err:
        raise StudyError(str(err)) from err


def identity(obj):
    for key in ('workload_uid', 'pod_uid', 'action'):
        ident(obj[key], key)
    integer(obj['generation'], 'generation', 0, 2**53-1)


def trace_validate(trace):
    fields(trace, ('schema', 'evidence', 'source_revision', 'history_complete_from', 'events', 'ticks'),
           ('schema', 'evidence', 'source_revision', 'history_complete_from', 'events', 'ticks'))
    if trace['schema'] != TRACE_SCHEMA or trace['evidence'] not in ('recorded', 'synthetic'):
        raise StudyError('unsupported trace schema/evidence')
    ident(trace['source_revision'], 'source_revision')
    if trace['evidence'] == 'recorded' and not re.fullmatch('[0-9a-f]{40}', trace['source_revision']):
        raise StudyError('recorded traces require the full source commit SHA')
    if trace['history_complete_from'] is not None:
        number(trace['history_complete_from'], 'history_complete_from')
    array(trace['events'], 'events', 50000)
    array(trace['ticks'], 'ticks', 5000, 1)
    seen_events, seen_ticks, identities, starts, opportunities = {}, set(), {}, set(), set()
    previous = -1
    for event in trace['events']:
        fields(event, ('id', 'at', 'kind', 'workload_uid', 'pod_uid', 'generation', 'action',
                       'opportunity_id', 'tick_id', 'fact_id'), ('id', 'at', 'kind', 'workload_uid'))
        ident(event['id']); ident(event['workload_uid'])
        number(event['at'], 'event.at')
        if event['at'] < previous or event['id'] in seen_events:
            raise StudyError('events must be chronological with unique ids')
        previous = event['at']
        kind = event['kind']
        if kind not in ('opportunity', 'execution_start', 'verified'):
            raise StudyError('unsupported event kind')
        if kind == 'verified':
            ident(event.get('fact_id'), 'fact_id')
        else:
            if not {'pod_uid', 'generation', 'action'} <= event.keys():
                raise StudyError('history event needs full pair identity')
            identity(event)
            if kind == 'opportunity':
                ident(event.get('tick_id'), 'tick_id')
                key = tuple(event[k] for k in ('tick_id', 'workload_uid', 'pod_uid', 'generation', 'action'))
                if key in opportunities:
                    raise StudyError('duplicate optional opportunity (including stale retry)')
                opportunities.add(key)
            else:
                opportunity = seen_events.get(event.get('opportunity_id'))
                if not opportunity or opportunity['kind'] != 'opportunity':
                    raise StudyError('execution_start must reference an earlier opportunity event')
                if any(event[k] != opportunity[k] for k in ('workload_uid', 'pod_uid', 'generation', 'action')):
                    raise StudyError('execution_start identity differs from its opportunity')
                if event['opportunity_id'] in starts:
                    raise StudyError('an opportunity cannot acknowledge execution twice')
                starts.add(event['opportunity_id'])
        seen_events[event['id']] = event
    previous = -1
    rows = 0
    for tick in trace['ticks']:
        fields(tick, ('id', 'at', 'workload_uid', 'selection', 'mandatory_candidate',
                      'randomization_authorized', 'budget', 'candidates'),
               ('id', 'at', 'workload_uid', 'selection', 'randomization_authorized', 'candidates'))
        ident(tick['id']); ident(tick['workload_uid'])
        number(tick['at'], 'tick.at')
        if tick['at'] < previous or tick['id'] in seen_ticks:
            raise StudyError('ticks must be chronological with unique ids (retries are not new ticks)')
        previous = tick['at']; seen_ticks.add(tick['id'])
        boolean(tick['randomization_authorized'], 'randomization_authorized')
        if tick['selection'] not in ('optional', 'mandatory', 'noop'):
            raise StudyError('selection must be optional, mandatory or noop')
        budget = tick.get('budget')
        if budget is not None:
            fields(budget, ('r', 'used', 'held'), ('r', 'used', 'held'))
            for key in budget:
                number(budget[key], 'budget.'+key)
        array(tick['candidates'], 'candidates', 256)
        ids, pairs = set(), set()
        for c in tick['candidates']:
            fields(c, ('id', 'pod_uid', 'generation', 'action', 'value', 'non_cost_admitted',
                       'guard_admitted', 'entropy_prior', 'facts', 'cost', 'simulated_start'),
                   ('id', 'pod_uid', 'generation', 'action', 'value', 'non_cost_admitted', 'guard_admitted'))
            ident(c['id']); identity({**c, 'workload_uid': tick['workload_uid']})
            pair = (tick['workload_uid'], c['pod_uid'], c['generation'], c['action'])
            if c['id'] in ids or pair in pairs or (c['id'] in identities and identities[c['id']] != pair):
                raise StudyError('duplicate candidate or reused id with different identity')
            ids.add(c['id']); pairs.add(pair); identities[c['id']] = pair
            number(c['value'], 'value', -1e12)
            for key in ('non_cost_admitted', 'guard_admitted', 'simulated_start'):
                if key in c:
                    boolean(c[key], key)
            if 'entropy_prior' in c:
                number(c['entropy_prior'], 'entropy_prior', 1e-12)
            facts = c.get('facts', [])
            array(facts, 'facts', 256)
            fact_ids = set()
            for f in facts:
                fields(f, ('id', 'weight', 'origin', 'deadline', 'required', 'validated'),
                       ('id', 'weight', 'origin', 'deadline', 'required', 'validated'))
                ident(f['id'])
                if f['id'] in fact_ids:
                    raise StudyError('candidate fact identities must be unique')
                fact_ids.add(f['id'])
                for key in ('weight', 'origin', 'deadline'):
                    number(f[key], 'fact.'+key)
                for key in ('required', 'validated'):
                    boolean(f[key], key)
                if f['deadline'] <= f['origin'] or f['origin'] > tick['at']:
                    raise StudyError('invalid fact obligation interval')
            data = c.get('cost', {})
            fields(data, ('c', 'rho', 'norm', 'flow', 'chi', 'class', 'k', 'samples', 'overdue', 'sample_action', 'hold_cap'))
            for key in ('c', 'rho', 'norm', 'flow', 'chi', 'hold_cap'):
                if key in data:
                    number(data[key], 'cost.'+key)
            if 'class' in data and data['class'] not in ('stateless', 'gpu', 'stateful', 'unknown'):
                raise StudyError('unsupported duration class')
            if 'k' in data:
                integer(data['k'], 'k', 0, 1000000)
            if 'sample_action' in data:
                ident(data['sample_action'])
            if 'samples' in data:
                array(data['samples'], 'samples', 200)
                for sample in data['samples']:
                    if sample is not None:
                        number(sample, 'sample', 0, 1e9)
            if 'overdue' in data:
                integer(data['overdue'], 'overdue', 0, len(data.get('samples', [])))
        if tick['selection'] == 'mandatory' and tick.get('mandatory_candidate') not in ids:
            raise StudyError('mandatory selection needs a candidate id present in the tick')
        rows += max(1, len(ids))
    return rows


def validate(request):
    """Return normalized configuration, preserving caller-owned input."""
    r = copy.deepcopy(request)
    fields(r, ('schema', 'title', 'policy', 'seeds', 'arms', 'history', 'trace', 'dataset'),
           ('schema', 'title', 'policy', 'seeds', 'arms', 'history'))
    if r['schema'] != SCHEMA:
        raise StudyError('expected schema ' + SCHEMA)
    if not isinstance(r['title'], str) or not 1 <= len(r['title']) <= 200:
        raise StudyError('title must contain 1 to 200 characters')
    if not isinstance(r['policy'], str) or not POLICY.fullmatch(r['policy']):
        raise StudyError('policy must be namespace/name')
    if ('trace' in r) == ('dataset' in r):
        raise StudyError('provide exactly one of trace or dataset')
    if 'dataset' in r and r['dataset'] != 'recorded':
        raise StudyError('dataset must be recorded; arbitrary server paths are not accepted')
    array(r['seeds'], 'seeds', 16, 1)
    for seed in r['seeds']:
        integer(seed, 'seed', 0, 2**53-1)
    if len(set(r['seeds'])) != len(r['seeds']):
        raise StudyError('seeds must be unique')
    h = r['history']
    fields(h, ('mode', 'window_seconds'), ('mode', 'window_seconds'))
    if h['mode'] not in ('observed', 'simulated-starts'):
        raise StudyError('history.mode must be observed or simulated-starts')
    number(h['window_seconds'], 'window_seconds', 1, 31536000)
    array(r['arms'], 'arms', 8, 1)
    ids = set()
    for arm in r['arms']:
        fields(arm, ('id', 'cost', 'selector', 'lambda_eff', 'coverage_guard'), ('id', 'cost', 'selector'))
        ident(arm['id'])
        if arm['id'] in ids:
            raise StudyError('arm ids must be unique')
        ids.add(arm['id'])
        arm.setdefault('lambda_eff', 0)
        number(arm['lambda_eff'], 'lambda_eff')
        arm.setdefault('coverage_guard', True)
        boolean(arm['coverage_guard'], 'coverage_guard')
        cost = arm['cost']
        kind = cost.get('kind') if isinstance(cost, dict) else None
        keys = {'provided': ('kind',), 'endpoint-v1': ('kind', 'delta'),
                'legacy': ('kind', 'norm_weight', 'flow_weight', 'ceiling')}
        if kind not in keys:
            raise StudyError('cost.kind must be provided, legacy or endpoint-v1')
        fields(cost, keys[kind], ('kind',))
        if kind == 'endpoint-v1':
            cost.setdefault('delta', 30)
        if kind == 'legacy' and not {'norm_weight', 'flow_weight', 'ceiling'} <= cost.keys():
            raise StudyError('legacy cost needs explicit weights and ceiling')
        for key in set(cost)-{'kind'}:
            number(cost[key], 'cost.'+key)
        sel = arm['selector']
        kind = sel.get('kind') if isinstance(sel, dict) else None
        keys = {'deterministic': ('kind',), 'entropy': ('kind', 'tau', 'epsilon'),
                'history': ('kind', 'epsilon', 'score_scale', 'eta_pair', 'eta_action', 'eta_fact',
                            'kappa_pair', 'kappa_action', 'q_ref', 'x0', 'a0')}
        if kind not in keys:
            raise StudyError('selector.kind must be deterministic, entropy or history')
        fields(sel, keys[kind], keys[kind])
        for key in set(sel)-{'kind'}:
            low = 1e-12 if key in ('tau', 'score_scale', 'kappa_pair', 'kappa_action', 'q_ref') else 0
            number(sel[key], 'selector.'+key, low, 1 if key in ('x0', 'a0') else 1e12)
        if sel.get('x0', 0) >= 1:
            raise StudyError('x0 must be less than one')
    if 'trace' in r:
        rows = trace_validate(r['trace'])
        if rows*len(r['arms'])*len(r['seeds']) > MAX_ROWS:
            raise StudyError('study exceeds %d candidate rows across arms and seeds' % MAX_ROWS)
        if h['mode'] == 'simulated-starts' and r['trace']['evidence'] != 'synthetic':
            raise StudyError('simulated-starts requires an explicitly synthetic trace')
        if h['mode'] == 'simulated-starts':
            for tick in r['trace']['ticks']:
                if tick['selection'] == 'optional' and any('simulated_start' not in c for c in tick['candidates']):
                    raise StudyError('simulated-starts needs explicit simulated_start on every optional candidate')
            if any(e['kind'] != 'verified' for e in r['trace']['events']):
                raise StudyError('simulated-starts cannot mix observed opportunity/start counters')
    return r
