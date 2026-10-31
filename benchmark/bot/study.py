"""Versioned, declarative offline studies with explicit provenance and evidence gaps.

This is a reference-model benchmark, not a replacement for brain-replay or an
actuator. All future workload states and budgets remain external observations.
"""
import argparse
import collections
import csv
import hashlib
import html
import json
import math
from pathlib import Path
import random
import sys
import zipfile

from study_math import MissingData, distribution, price, remaining
from study_schema import MAX_ROWS, StudyError, strict_json, validate
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from mathlab import stage_scope


LIMITATIONS = [
    'Reference-model study: does not run or certify the production Go implementation.',
    'Input gates, optional sets, fact mappings, budgets and duration samples are supplied by the trace producer.',
    'Workload states and budgets are exogenous; this is not a closed-loop defense or SLO experiment.',
    'Selection is not execution. No action is dispatched and no verification credit is inferred from a draw.',
    'A changed-decision rate is not an improvement score. Costs with different units are not directly comparable.',
    'B=1. The coverage guard, anti-neglect and response authorization are inputs, not reimplemented schedulers.',
]


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def clean(obj):
    if isinstance(obj, float) and not math.isfinite(obj):
        return 'Infinity' if obj > 0 else '-Infinity' if obj < 0 else 'NaN'
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [clean(v) for v in obj]
    return obj


def write_json(path, obj):
    path.write_text(json.dumps(clean(obj), indent=2, ensure_ascii=False, allow_nan=False)+'\n')


def pair_key(workload, candidate):
    return (workload, candidate['pod_uid'], candidate['generation'], candidate['action'])


class History:
    """Rolling opportunity/acknowledgement counters, separated by immutable identity."""
    def __init__(self, window, events=()):
        self.window = window
        self.pending = iter(events)
        self.next = next(self.pending, None)
        self.active = collections.deque()
        self.counts = collections.Counter()
        self.opportunities = set()
        self.action_opportunities = set()

    def add(self, event):
        kind, work = event['kind'], event['workload_uid']
        if kind == 'verified':
            keys = [('verified', work, event['fact_id'])]
        else:
            pair = pair_key(work, event)
            if kind == 'opportunity':
                token = (event['tick_id'], pair)
                if token in self.opportunities:
                    return
                self.opportunities.add(token)
                action_token = (event['tick_id'], work, event['action'])
                keys = [('F', pair)]
                if action_token not in self.action_opportunities:
                    keys.append(('F_action', work, event['action']))
                    self.action_opportunities.add(action_token)
            else:
                keys = [('S', pair), ('S_action', work, event['action'])]
        self.counts.update(keys)
        self.active.append((event['at'], keys))

    def advance(self, at):
        while self.next and self.next['at'] <= at:
            self.add(self.next)
            self.next = next(self.pending, None)
        while self.active and self.active[0][0] <= at-self.window:
            _, keys = self.active.popleft()
            self.counts.subtract(keys)
            for key in keys:
                if self.counts[key] == 0:
                    del self.counts[key]

    def weights(self, tick, candidate, config):
        work, pair = tick['workload_uid'], pair_key(tick['workload_uid'], candidate)
        F, S = self.counts['F', pair], self.counts['S', pair]
        Fa, Sa = self.counts['F_action', work, candidate['action']], self.counts['S_action', work, candidate['action']]
        N, Na = max(0, F-S), max(0, Fa-Sa)
        a, aa = N/(N+config['kappa_pair']), Na/(Na+config['kappa_action'])
        Q = 0.0
        if config['eta_fact']:
            if 'facts' not in candidate:
                raise MissingData('missing validated fact inputs')
            for fact in candidate['facts']:
                if not fact['validated'] or not fact['required']:
                    continue
                x = min(1.0, max(0.0, (tick['at']-fact['origin'])/(fact['deadline']-fact['origin'])))
                anticipation = config['a0']+(1-config['a0'])*min(1.0, max(0.0, (x-config['x0'])/(1-config['x0'])))
                n = self.counts['verified', work, fact['id']]
                Q += fact['weight']*anticipation/(1+n)
        h = 1+config['eta_pair']*a+config['eta_action']*aa+config['eta_fact']*Q/config['q_ref']
        return h, {'F_pair': F, 'S_pair': S, 'N_pair': N, 'A_pair': a,
                   'F_action': Fa, 'S_action': Sa, 'A_action': aa, 'Q': Q, 'h': h}


def candidate_rows(tick, arm):
    rows = []
    for c in sorted(tick['candidates'], key=lambda c: c['id']):
        row = {'candidate_id': c['id'], 'pod_uid': c['pod_uid'], 'generation': c['generation'],
               'action': c['action'], 'value': c['value'], 'probability': 0, 'selected': False}
        reason = None
        if not c['non_cost_admitted']:
            reason = 'NON_COST_GATE'
        elif arm['coverage_guard'] and not c['guard_admitted']:
            reason = 'COVERAGE_GUARD'
        # Even excluded rows retain available cost evidence; missing cost for a
        # candidate already vetoed by a hard gate cannot create a new opportunity.
        try:
            cost = price(c, arm['cost'], tick.get('budget'))
            row.update(cost)
            if not reason:
                if cost.get('refusal'):
                    reason = cost['refusal']
                elif arm['cost']['kind'] == 'legacy':
                    if cost['chi'] > arm['cost']['ceiling']:
                        reason = 'LEGACY_CHI'
                elif cost['rho'] > 0 and cost['rho'] > remaining(tick.get('budget')):
                    reason = 'BUDGET'
        except MissingData as err:
            row['data_gap'] = str(err)
            if not reason:
                reason = 'MISSING_DATA'
        # Containment/mandatory selection remains unpriced.
        if row.get('c') is not None:
            coefficient = 0 if tick['selection'] == 'mandatory' else arm['lambda_eff']
            row['J'] = c['value']-coefficient*row['c']
        row['refusal'] = reason
        rows.append((c, row))
    return rows


def evaluate(tick, arm, history, config, trace, rng):
    pairs = candidate_rows(tick, arm)
    rows = [row for _, row in pairs]
    summary = {'tick_id': tick['id'], 'at': tick['at'], 'workload_uid': tick['workload_uid'],
               'selection': tick['selection'], 'selected': None, 'expected_regret': None,
               'realized_regret': None, 'status': 'OK', 'reason': None}
    eligible = [(c, row) for c, row in pairs if not row['refusal']]
    if tick['selection'] == 'noop':
        summary['reason'] = 'AUTHORITATIVE_NOOP'
        return rows, summary
    # Missing a required input invalidates this tick, not just the one row. Never
    # make the remaining candidates look superior by silently dropping unknowns.
    if any(row['refusal'] == 'MISSING_DATA' for row in rows):
        summary.update(status='NEEDS_DATA', reason='MISSING_CANDIDATE_INPUT')
        return rows, summary
    if tick['selection'] == 'mandatory':
        chosen = next((row for c, row in eligible if c['id'] == tick['mandatory_candidate']), None)
        if chosen:
            chosen.update(probability=1.0, selected=True)
            summary.update(selected=chosen['candidate_id'], selected_cost=chosen['c'],
                           cost_unit=chosen['unit'], selected_rho=chosen['rho'])
        else:
            summary['reason'] = 'MANDATORY_REFUSED'
        return rows, summary
    if not eligible:
        summary['reason'] = 'NO_FEASIBLE_CANDIDATE'
        return rows, summary
    mode = config['history']['mode']
    if mode == 'simulated-starts':
        for c, _ in eligible:
            history.add({'kind': 'opportunity', 'at': tick['at'], 'tick_id': tick['id'],
                         'workload_uid': tick['workload_uid'], **c})
    selector = arm['selector']
    weights, fallback = [], None
    if selector['kind'] != 'deterministic' and not tick['randomization_authorized']:
        fallback = 'RANDOMIZATION_NOT_AUTHORIZED'
    if selector['kind'] == 'history':
        required_history = any(selector[k] > 0 for k in ('eta_pair', 'eta_action', 'eta_fact'))
        complete_from = trace['history_complete_from']
        history_available = complete_from is not None and complete_from <= tick['at']-history.window
        if required_history and not history_available:
            fallback = 'PICKER_UNAVAILABLE'
        for c, row in eligible:
            row['history_available'] = history_available
            if not history_available:
                if required_history:
                    row['data_gap'] = 'missing history store or incomplete lookback'
                weights.append(1.0)
                continue
            try:
                h, diagnostics = history.weights(tick, c, selector)
                row.update(diagnostics)
                weights.append(h)
            except MissingData as err:
                row['data_gap'] = str(err)
                fallback = 'PICKER_UNAVAILABLE'
    elif selector['kind'] == 'entropy':
        for c, row in eligible:
            if 'entropy_prior' not in c:
                row['data_gap'] = 'missing entropy_prior; uniform is not inferred'
                fallback = 'PICKER_UNAVAILABLE'
            else:
                weights.append(c['entropy_prior'])
    scores = [row['J'] for _, row in eligible]
    if fallback:
        selector = {'kind': 'deterministic'}
        summary.update(status='FALLBACK', reason=fallback)
    probabilities, diagnostics = distribution(scores, selector, weights)
    loss = diagnostics['expected_regret']
    if loss > selector.get('epsilon', 0)+1e-9*max(1, selector.get('epsilon', 0)):
        raise StudyError('numeric expected-regret bound violated')
    draw, cumulative = rng.random(), 0.0
    selected = max(i for i, p in enumerate(probabilities) if p > 0)
    for i, p in enumerate(probabilities):
        cumulative += p
        if draw < cumulative:
            selected = i
            break
    for i, ((c, row), p) in enumerate(zip(eligible, probabilities)):
        row.update(probability=p, selected=i == selected,
                   q=(diagnostics.get('q') or [None]*len(eligible))[i],
                   r_star=(diagnostics.get('r_star') or [None]*len(eligible))[i])
    chosen, chosen_row = eligible[selected]
    summary.update(selected=chosen['id'], draw=draw, expected_regret=loss,
                   realized_regret=max(scores)-chosen_row['J'], alpha=diagnostics.get('alpha'),
                   temperature=diagnostics.get('temperature'), selected_cost=chosen_row['c'],
                   cost_unit=chosen_row['unit'], selected_rho=chosen_row['rho'])
    if mode == 'simulated-starts':
        if 'simulated_start' not in chosen:
            raise MissingData('simulated-starts requires an explicit simulated_start on every selectable candidate')
        if chosen['simulated_start']:
            history.add({'kind': 'execution_start', 'at': tick['at'], 'workload_uid': tick['workload_uid'], **chosen})
        summary['simulated_acknowledged'] = chosen['simulated_start']
    return rows, summary


def load_request(request, data_dir=None):
    request = validate(request)
    if 'dataset' in request:
        if not data_dir:
            raise MissingData('recorded dataset requires MATHLAB_DATA_DIR')
        try:
            pin = stage_scope.load(data_dir, request['policy'])
            stage_scope.identity(data_dir, pin)
        except stage_scope.StageError as error:
            raise MissingData(str(error)) from error
        # Fixed namespace; never accept a user-specified filename or deserialize code.
        path = Path(data_dir)/'mathlab'/'study-traces'/(request['policy']+'.json')
        if not path.exists():
            raise MissingData('normalized recorded trace is absent at mathlab/study-traces/%s.json; '
                              'legacy snapshots do not contain the required ledgers' % request['policy'])
        if path.stat().st_size > 2*1024*1024:
            raise StudyError('recorded trace exceeds 2 MiB')
        trace = strict_json(path.read_text())
        if trace.get('evidence') != 'recorded':
            raise StudyError('recorded dataset must contain recorded evidence')
        manifest = path.with_suffix('.manifest.json')
        if not manifest.exists():
            raise MissingData('recorded reference trace has no stage installation manifest')
        meta = strict_json(manifest.read_text())
        if (meta.get('trace_sha256') != digest(trace) or meta.get('policy') != request['policy'] or
                trace.get('source_revision') != pin['brain']['git_sha'] or
                meta.get('image_digest') != pin['brain']['image_digest'] or meta.get('brain_image') != pin['brain']['image'] or
                meta.get('policy_uid') != pin['policies'][request['policy']]['uid']):
            raise StudyError('recorded reference trace manifest or stage source/policy identity mismatch')
        request.pop('dataset')
        request['trace'] = trace
        request = validate(request)
    return request


def safe_csv(value):
    value = clean(value)
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return "'"+value
    return value


def table(path, rows):
    keys = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows({k: safe_csv(v) for k, v in row.items()} for row in rows)


def candidate_csv(root):
    source = root/'candidates.jsonl'
    if not source.exists():
        return
    keys = {}
    with source.open() as f:
        for line in f:
            keys.update(dict.fromkeys(json.loads(line)))
    with source.open() as src, (root/'candidates.csv').open('w', newline='') as dst:
        writer = csv.DictWriter(dst, fieldnames=list(keys))
        writer.writeheader()
        for line in src:
            writer.writerow({k: safe_csv(v) for k, v in json.loads(line).items()})


def run(request, root, data_dir=None, cancelled=lambda: False, progress=lambda message: None):
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise StudyError('output directory must be empty; use a new directory for each study')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = validate(request)
    write_json(root/'request.json', request)
    manifest = {'schema': 'phorvex-bench.study-manifest.v1', 'request_sha256': digest(request),
                'title': request['title'], 'policy': request['policy'], 'limits': {'max_candidate_rows': MAX_ROWS},
                'limitations': LIMITATIONS, 'implementation_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [Path(__file__), Path(__file__).with_name('study_math.py'), Path(__file__).with_name('study_schema.py')]}}
    metrics, tick_rows, gaps = [], [], collections.Counter()
    result = {'schema': 'phorvex-bench.study-result.v1', 'state': 'COMPLETE', 'mode': 'REFERENCE_STUDY',
              'verified_coverage': {'value': None, 'reason': 'counterfactual verification not observed'},
              'realized_cost': {'value': None, 'reason': 'counterfactual charges not observed'}}
    try:
        request = load_request(request, data_dir)
        trace = request['trace']
        write_json(root/'resolved-request.json', request)
        manifest.update(trace_sha256=digest(trace), source_revision=trace['source_revision'],
                        evidence=trace['evidence'], history=request['history'], arms=request['arms'],
                        seeds=request['seeds'], tick_ids=[t['id'] for t in trace['ticks']])
        result.update(evidence=trace['evidence'], history_mode=request['history']['mode'])
        if request['history']['mode'] == 'simulated-starts':
            if any(e['kind'] != 'verified' for e in trace['events']):
                raise StudyError('simulated-starts cannot mix recorded opportunity/start counters')
            manifest['limitations'] = LIMITATIONS+['Synthetic acknowledgements update picker counters only; '
                'budgets and future states are fixed inputs, not simulated actuator consequences.']
        with (root/'candidates.jsonl').open('w') as raw:
            for arm in request['arms']:
                for seed in request['seeds']:
                    progress('study arm %s, seed %s' % (arm['id'], seed))
                    history = History(request['history']['window_seconds'], trace['events'])
                    start = len(tick_rows)
                    for tick in trace['ticks']:
                        if cancelled():
                            raise InterruptedError('study cancelled')
                        history.advance(tick['at'])
                        # Common random numbers paired by seed/tick, independent of arm
                        # ordering and additions. Full candidate ordering is stable.
                        rng = random.Random(digest([seed, tick['id']]))
                        rows, summary = evaluate(tick, arm, history, request, trace, rng)
                        identity = {'arm_id': arm['id'], 'seed': seed, 'tick_id': tick['id'],
                                    'at': tick['at'], 'workload_uid': tick['workload_uid']}
                        for row in rows:
                            if row.get('data_gap'):
                                gaps[row['data_gap']] += 1
                            raw.write(json.dumps(clean({**identity, **row}), allow_nan=False)+'\n')
                        tick_rows.append({**identity, **summary})
                    run_rows = tick_rows[start:]
                    valid = [r for r in run_rows if r['status'] != 'NEEDS_DATA']
                    losses = [r['expected_regret'] for r in valid if r['expected_regret'] is not None]
                    frequencies = collections.Counter(r['selected'] for r in valid if r['selected'] is not None)
                    priced = [r for r in valid if 'selected_cost' in r]
                    reserved = [r['selected_rho'] for r in priced if r['selected_rho'] is not None]
                    metrics.append({'arm_id': arm['id'], 'seed': seed, 'ticks': len(run_rows),
                                    'usable_ticks': len(valid), 'needs_data': len(run_rows)-len(valid),
                                    'fallback_ticks': sum(r['status'] == 'FALLBACK' for r in valid),
                                    'selected_ticks': sum(frequencies.values()), 'distinct_selected_pairs': len(frequencies),
                                    'mean_expected_regret': math.fsum(losses)/len(losses) if losses else None,
                                    'max_expected_regret': max(losses) if losses else None,
                                    'selection_counts': dict(frequencies)})
                    metrics[-1].update(predicted_cost_sum=math.fsum(r['selected_cost'] for r in priced),
                                       cost_unit='dimensionless' if arm['cost']['kind'] == 'legacy' else 'endpoint-seconds',
                                       selected_reservations_sum=math.fsum(reserved) if reserved else None)
        missing = sum(m['needs_data'] for m in metrics)
        result['state'] = 'NEEDS_DATA' if missing == len(tick_rows) else 'PARTIAL' if missing or any(m['fallback_ticks'] for m in metrics) else 'COMPLETE'
        result['candidate_rows_file'] = 'candidates.jsonl'
    except MissingData as err:
        result.update(state='NEEDS_DATA', reason=str(err))
    except InterruptedError:
        result.update(state='CANCELLED', reason='cancel requested')
    result['metrics'] = metrics
    result['data_gaps'] = dict(gaps)
    result['fallback_reasons'] = dict(collections.Counter(r['reason'] for r in tick_rows if r['status'] == 'FALLBACK'))
    # Paired choices share an input tick and seed. Never compare costs with different units.
    comparisons = []
    base = request['arms'][0]['id']
    baseline = {(r['seed'], r['tick_id']): r for r in tick_rows if r['arm_id'] == base}
    for arm in request['arms'][1:]:
        paired = [(r, baseline.get((r['seed'], r['tick_id']))) for r in tick_rows if r['arm_id'] == arm['id']]
        paired = [(r, b) for r, b in paired if b and r['status'] != 'NEEDS_DATA' and b['status'] != 'NEEDS_DATA']
        changed = sum(r['selected'] != b['selected'] for r, b in paired)
        comparisons.append({'arm_id': arm['id'], 'reference': base, 'paired_tick_seeds': len(paired),
                            'changed_decisions': changed, 'changed_share': changed/len(paired) if paired else None})
    result['comparisons'] = comparisons
    write_json(root/'manifest.json', manifest)
    write_json(root/'result.json', result)
    write_json(root/'ticks.json', tick_rows)
    table(root/'metrics.csv', metrics)
    table(root/'ticks.csv', tick_rows)
    table(root/'comparisons.csv', comparisons)
    candidate_csv(root)
    body = ('<!doctype html><meta charset="utf-8"><title>Phorvex study</title>'
            '<style>body{font:16px/1.5 system-ui;margin:2rem auto;padding:0 1rem;max-width:1200px;color:#17212c}'
            'table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:.5rem;text-align:left;'
            'border-bottom:1px solid #ccd3dc}th{background:#eef3f8}pre{white-space:pre-wrap}'
            'section{overflow:auto}a{color:#135daf}</style>')
    body += '<h1>%s</h1><p><strong>State: %s</strong></p>' % (html.escape(manifest['title']), result['state'])
    body += '<p>Evidence: %s. History: %s. Reference model, B=1.</p>' % (
        html.escape(str(result.get('evidence', 'unavailable'))), html.escape(str(result.get('history_mode', 'unavailable'))))
    if result.get('reason'):
        body += '<p>'+html.escape(result['reason'])+'</p>'
    if gaps or result['fallback_reasons']:
        body += '<h2>Evidence gaps and fallbacks</h2><pre>'+html.escape(json.dumps(
            {'data_gaps': dict(gaps), 'fallback_reasons': result['fallback_reasons']}, indent=2))+'</pre>'
    body += '<ul>'+''.join('<li>'+html.escape(s)+'</li>' for s in manifest['limitations'])+'</ul>'
    columns = ('arm_id', 'seed', 'ticks', 'usable_ticks', 'fallback_ticks', 'selected_ticks',
               'distinct_selected_pairs', 'mean_expected_regret', 'predicted_cost_sum', 'cost_unit')
    body += '<h2>Per-arm and per-seed results</h2><section><table><thead><tr>'+''.join(
        '<th>'+key.replace('_', ' ')+'</th>' for key in columns)+'</tr></thead><tbody>'
    for row in metrics:
        body += '<tr>'+''.join('<td>'+html.escape(str(row.get(key) if row.get(key) is not None else 'unavailable'))+'</td>'
                              for key in columns)+'</tr>'
    body += '</tbody></table></section>'
    body += '<h2>Paired decision comparisons</h2><pre>'+html.escape(json.dumps(comparisons, indent=2))+'</pre>'
    body += '<p>Full evidence: <a href="manifest.json">manifest</a> · <a href="result.json">result</a> · '
    body += '<a href="candidates.csv">candidates CSV</a> · <a href="ticks.csv">ticks CSV</a></p>'
    (root/'report.html').write_text(body)
    with zipfile.ZipFile(root/'evidence.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(root.iterdir()):
            if p.is_file() and p.name != 'evidence.zip':
                z.write(p, p.name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request')
    parser.add_argument('--out', required=True)
    parser.add_argument('--data-dir')
    args = parser.parse_args()
    try:
        result = run(strict_json(Path(args.request).read_text()), args.out, args.data_dir)
    except (ValueError, OSError) as err:
        parser.exit(2, 'study: %s\n' % err)
    print(json.dumps({'state': result['state'], 'output': args.out}))
    return 0 if result['state'] == 'COMPLETE' else 3


if __name__ == '__main__':
    raise SystemExit(main())
