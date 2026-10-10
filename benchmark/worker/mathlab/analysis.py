"""Replay results -> tidy metric rows (math-lab.metric.v1) and plot data.

Rules this module enforces:
- Only MATCHED snapshots enter a comparison: the baseline reproduced production exactly
  and the arm replayed OK on the same recorded state. Everything else is counted and
  reported as excluded, never silently dropped.
- Every row declares its population, numerator/denominator or per-unit values, n, the
  interval method and a measurement kind. A ratio with a zero denominator is UNAVAILABLE.
- Replay observes no outcomes: defense (M-S*) and disruption truth (M-D*) rows are emitted
  as UNAVAILABLE with the reason, never as zero.
- Arms are compared on common, arm-independent valuations (fact weights fixed by the
  recorded state), not on each arm's own objective value.
"""
from collections import Counter, defaultdict

from . import stats

GATE_ORDER = ['G0-recon-absent', 'G1-policy-binding', 'G2-unsupported-action', 'G3-quarantine-capacity', 'G4-capability',
              'G5-shared-resources', 'G6-feasibility', 'G7-cost-nan', 'G9-chi-ceiling']

METRIC_CATALOG = {
    'M-P21': ('Changed-decision share', 'PROCESS', 'proportion', 'matched ticks whose selected set differs from the control / matched ticks', False),
    'M-P22': ('Useful-feasible-opportunity share', 'PROCESS', 'proportion', 'attack-backed asset-ticks with >=1 admitted positive-gain action / attack-backed asset-ticks with complete feasible-set evidence', False),
    'M-P23': ('Unassessed-gate share', 'PROCESS', 'proportion', 'candidate x gate pairs not evaluated (short circuit) / applicable candidate x gate pairs', False),
    'M-P03': ('First-veto gate exclusion share', 'PROCESS', 'proportion', 'enabled pairs whose FIRST veto is gate g / enabled pairs', False),
    'M-P04': ('CHi-ceiling exclusion share', 'PROCESS', 'proportion', 'pairs first-vetoed at G9 / pairs that reached G9', False),
    'M-P19': ('No-op under attack', 'PROCESS', 'proportion', 'attack-backed asset-ticks with no selected move / attack-backed asset-ticks', False),
    'M-P19R': ('No-op reason share', 'PROCESS', 'proportion', 'non-selected asset-ticks with reason r / non-selected asset-ticks', False),
    'M-P06': ('Selected action mix', 'PROCESS', 'proportion', 'selected moves of action a / selected moves', False),
    'M-P02': ('Budget saturation', 'PROCESS', 'proportion', 'ticks whose selected moves reach the move budget B / ticks', False),
    'M-P18': ('Estimated objective of selected set', 'ESTIMATED_MODEL', 'objective units per tick', "sum of selected net gain under the ARM's own pricing (not comparable across differently priced arms)", False),
    'M-P25': ('Common-weight predicted coverage', 'ESTIMATED_MODEL', 'fact weight per tick', 'recon fact weight covered by the selected set, valued with the control arm fact weights', True),
    'M-P26': ('Selected moves per tick', 'PROCESS', 'moves per tick', 'selected (asset, action) moves per matched tick', True),
    'M-P27': ('Feasible candidates per asset-tick', 'PROCESS', 'candidates per asset-tick', 'candidates admitted past every gate per asset-tick', True),
    'M-P28': ('Estimated disruption cost of selected moves', 'ESTIMATED_MODEL', 'normalized cost per tick', 'sum of expected weighted cost (ECost) of selected moves per tick; model estimate, not measured disruption', True),
    'M-P29': ('Replay decision compute time', 'PROCESS', 'seconds per tick', 'wall time of one replayed decision (offline; not production tick latency M-P10)', True),
    'M-P30': ('First-veto feasibility-law share', 'PROCESS', 'proportion', 'enabled pairs whose FIRST veto is G6 hard law l / enabled pairs', True),
    'M-P24': ('Recorded production dispatch funnel', 'OBSERVATIONAL', 'count', 'control-arm production evidence: selected -> dry-run/kill-switch suppressed -> dispatch outcome', False),
    'M-S01': ('Episode defense rate', 'VERIFIED_SECURITY_OUTCOME', 'proportion', '(DEFENDED + PROTECTION_REVALIDATED) / determinate episodes', False),
    'M-D02': ('p99 latency delta', 'OBSERVED_DISRUPTION', 'ms', 'action-window p99 minus matched pre-window p99', False),
    'M-D05': ('Replica loss', 'OBSERVED_DISRUPTION', 'replica-seconds', 'integral of (desired-ready)+ over the action window', False),
    'M-D06': ('Availability-floor breaches', 'OBSERVED_DISRUPTION', 'count', 'intervals with ready < m overlapping an action window', False),
    'M-D07': ('Cost-model error and conformal coverage', 'OBSERVED_DISRUPTION', 'ratio', 'realized vs predicted on a compatible normalized target', False),
    'M-D08': ('Aborted requests', 'OBSERVED_DISRUPTION', 'count', 'in-flight requests aborted per request-drain', False),
    'M-D09': ('Collateral impact', 'OBSERVED_DISRUPTION', 'various', 'M-D02..04 on non-targeted co-located services', False),
}
UNAVAILABLE_IN_REPLAY = ['M-S01', 'M-D02', 'M-D05', 'M-D06', 'M-D07', 'M-D08', 'M-D09']


def index_results(lines, arms):
    by_snapshot = defaultdict(dict)
    for line in lines:
        digest = (line.get('snapshot') or {}).get('snapshot_digest')
        if digest:
            by_snapshot[digest][line.get('arm_id')] = line
    baseline = arms[0]
    eligible, exclusions = [], Counter()
    for digest, results in sorted(by_snapshot.items(), key=lambda kv: (kv[1].get(baseline, {}).get('snapshot', {}).get('captured_at') or '', kv[0])):
        base = results.get(baseline)
        if not base:
            exclusions['control-missing'] += 1
        elif base.get('status') != 'OK':
            exclusions['control-' + str(base.get('status')).lower() + ':' + ';'.join(sorted(r.split(':')[0] for r in base.get('reasons') or []))[:120]] += 1
        elif not (base.get('baseline_check') or {}).get('reproduced'):
            exclusions['control-not-reproduced'] += 1
        else:
            eligible.append(digest)
    matched = {}
    arm_exclusions = {}
    for arm in arms:
        ok, bad = [], Counter()
        for digest in eligible:
            r = by_snapshot[digest].get(arm)
            if r and r.get('status') == 'OK':
                ok.append(digest)
            else:
                bad[(r or {}).get('status', 'MISSING')] += 1
        matched[arm], arm_exclusions[arm] = ok, dict(bad)
    return by_snapshot, eligible, dict(exclusions), matched, arm_exclusions


def _row(ctx, arm, metric_id, **kw):
    name, kind, unit, definition, proposed = METRIC_CATALOG[metric_id]
    row = {'schema_version': 'math-lab.metric.v1', 'experiment_id': ctx['experiment_id'], 'arm_id': arm,
           'control_id': ctx['control'], 'parameter_id': ctx['parameter_id'], 'effective_value': ctx['arm_values'][arm]['value'],
           'effective_value_label': ctx['arm_values'][arm]['label'], 'metric_id': metric_id, 'metric_name': name,
           'metric_kind': kind, 'metric_proposed': proposed, 'unit': unit, 'definition': definition, 'dimension': None,
           'numerator': None, 'denominator': None, 'value': None, 'n': None, 'paired_n': None, 'ci_low': None, 'ci_high': None,
           'ci_method': None, 'data_status': 'OBSERVED', 'comparison': 'ARM_LEVEL', 'comparison_status': ctx['comparison_status'],
           'reason': None, 'population': None}
    row.update(kw)
    if row['value'] is None and row['data_status'] == 'OBSERVED':
        row['data_status'] = 'UNAVAILABLE'
    return row


def _ratio(ctx, arm, metric_id, num, den, population, cluster_pairs=None, dimension=None, ci='wilson'):
    if not den:
        return _row(ctx, arm, metric_id, dimension=dimension, numerator=num, denominator=den, n=den, population=population,
                    data_status='UNAVAILABLE', reason='ZERO_DENOMINATOR')
    interval, method = None, None
    if ci == 'cluster' and cluster_pairs and len(cluster_pairs) >= 2:
        interval, method = stats.bootstrap_ratio(cluster_pairs, seed=ctx['seed']), 'cluster bootstrap by tick (2000, seed %d)' % ctx['seed']
    if interval is None:
        interval, method = stats.wilson(num, den), 'Wilson 95% (units treated as independent)'
    return _row(ctx, arm, metric_id, dimension=dimension, numerator=num, denominator=den, value=num / den, n=den,
                ci_low=interval[0] if interval else None, ci_high=interval[1] if interval else None, ci_method=method, population=population)


def _mean(ctx, arm, metric_id, values, population, dimension=None):
    values = [v for v in values if v is not None]
    if not values:
        return _row(ctx, arm, metric_id, dimension=dimension, n=0, population=population, data_status='UNAVAILABLE', reason='NO_UNITS')
    interval = stats.bootstrap_mean(values, seed=ctx['seed'])
    return _row(ctx, arm, metric_id, dimension=dimension, value=stats.mean(values), n=len(values), population=population,
                ci_low=interval[0] if interval else None, ci_high=interval[1] if interval else None,
                ci_method='bootstrap mean by tick (2000, seed %d)' % ctx['seed'] if interval else 'n<2: no interval')


def _paired(ctx, arm, metric_id, diffs, population):
    diffs = [d for d in diffs if d is not None]
    if not diffs:
        return _row(ctx, arm, metric_id, comparison='PAIRED_DIFF_VS_CONTROL', paired_n=0, population=population,
                    data_status='UNAVAILABLE', reason='NO_MATCHED_PAIRS')
    interval = stats.paired_bootstrap_diff(diffs, seed=ctx['seed'])
    return _row(ctx, arm, metric_id, comparison='PAIRED_DIFF_VS_CONTROL', value=stats.mean(diffs), n=len(diffs), paired_n=len(diffs),
                ci_low=interval[0] if interval else None, ci_high=interval[1] if interval else None, population=population,
                ci_method='paired bootstrap over matched ticks (2000, seed %d)' % ctx['seed'] if interval else 'n<2: no interval')


def per_tick(r):
    decisions = r.get('decisions') or []
    selected = [d for d in decisions if d.get('selected')]
    funnel = r.get('funnel') or {}
    return {
        'selected_set': tuple(r.get('selected_set') or []),
        'objective': r.get('estimated_objective_m_p18'),
        'covered': sum(d.get('common_weight_covered') or 0 for d in selected),
        'moves': len(selected),
        'admitted_per_asset': (funnel.get('admitted', 0) / funnel['assets']) if funnel.get('assets') else None,
        'cost': sum(d.get('expected_cost') or 0 for d in selected),
        'seconds': r.get('replay_seconds'),
        'budget': r.get('arm_max_moves_per_tick'),
    }


def analyze(lines, ctx):
    arms = ctx['arms']
    control = arms[0]
    by_snapshot, eligible, exclusions, matched, arm_exclusions = index_results(lines, arms)
    rows = []
    plots = {'dose_response': defaultdict(list), 'funnel': {}, 'paired': defaultdict(list), 'g9': {}, 'noop': {}, 'action_mix': {}}
    control_ticks = {d: per_tick(by_snapshot[d][control]) for d in matched[control]}
    # One law axis for every arm, so a law that vetoes nothing in one arm reads as 0 there.
    g6_laws = sorted({law for d in matched[control] for a in arms if a in by_snapshot[d]
                      for law in (by_snapshot[d][a].get('first_veto_by_law') or {})})
    plots['g6_laws'] = {}
    for arm in arms:
        digests = matched[arm]
        results = [by_snapshot[d][arm] for d in digests]
        ticks = [per_tick(r) for r in results]
        population = '%d matched ticks of %s' % (len(digests), ctx['policy'])
        # M-P21 changed-decision share (control is 0 by construction).
        changed = sum(1 for d, t in zip(digests, ticks) if d in control_ticks and t['selected_set'] != control_ticks[d]['selected_set'])
        rows.append(_ratio(ctx, arm, 'M-P21', changed, len(digests), population))
        funnels = [r.get('funnel') or {} for r in results]
        complete = [f for f in funnels if f.get('complete_feasible_evidence')]
        num = sum(f.get('attack_backed_assets_with_positive_gain_feasible', 0) for f in complete)
        den = sum(f.get('attack_backed_assets', 0) for f in complete)
        rows.append(_ratio(ctx, arm, 'M-P22', num, den, 'attack-backed asset-ticks with complete evidence',
                           [(f.get('attack_backed_assets_with_positive_gain_feasible', 0), f.get('attack_backed_assets', 0)) for f in complete], ci='cluster'))
        rows.append(_ratio(ctx, arm, 'M-P23', sum(f.get('unassessed_gate_pairs', 0) for f in funnels), sum(f.get('applicable_gate_pairs', 0) for f in funnels),
                           'candidate x gate pairs', [(f.get('unassessed_gate_pairs', 0), f.get('applicable_gate_pairs', 0)) for f in funnels], ci='cluster'))
        pairs = sum(f.get('enabled_pairs', 0) for f in funnels)
        veto = Counter()
        for f in funnels:
            veto.update(f.get('first_veto_by_gate') or {})
        for gate in GATE_ORDER:
            rows.append(_ratio(ctx, arm, 'M-P03', veto.get(gate, 0), pairs, 'enabled (asset, action) pairs',
                               [((f.get('first_veto_by_gate') or {}).get(gate, 0), f.get('enabled_pairs', 0)) for f in funnels], dimension=gate, ci='cluster'))
        if all('first_veto_by_law' in r for r in results):
            law_veto = Counter()
            for r in results:
                law_veto.update(r['first_veto_by_law'])
            for law in g6_laws:
                rows.append(_ratio(ctx, arm, 'M-P30', law_veto.get(law, 0), pairs, 'enabled (asset, action) pairs',
                                   [(r['first_veto_by_law'].get(law, 0), f.get('enabled_pairs', 0)) for r, f in zip(results, funnels)],
                                   dimension=law, ci='cluster'))
            plots['g6_laws'][arm] = {law: law_veto.get(law, 0) for law in g6_laws}
        admitted = sum(f.get('admitted', 0) for f in funnels)
        rows.append(_ratio(ctx, arm, 'M-P04', veto.get('G9-chi-ceiling', 0), veto.get('G9-chi-ceiling', 0) + admitted, 'pairs that reached G9'))
        decisions = [d for r in results for d in (r.get('decisions') or [])]
        backed = [d for d in decisions if d.get('attack_backed')]
        rows.append(_ratio(ctx, arm, 'M-P19', sum(1 for d in backed if not d.get('selected')), len(backed), 'attack-backed asset-ticks'))
        not_selected = [d for d in decisions if not d.get('selected')]
        reasons = Counter(d.get('noop_reason') or 'UNKNOWN' for d in not_selected)
        for reason, count in sorted(reasons.items()):
            rows.append(_ratio(ctx, arm, 'M-P19R', count, len(not_selected), 'non-selected asset-ticks', dimension=reason))
        mix = Counter(d.get('action') for d in decisions if d.get('selected'))
        for action, count in sorted(mix.items()):
            rows.append(_ratio(ctx, arm, 'M-P06', count, sum(mix.values()), 'selected moves', dimension=action))
        budgeted = [t for t in ticks if t['budget'] and t['budget'] > 0]
        rows.append(_ratio(ctx, arm, 'M-P02', sum(1 for t in budgeted if t['moves'] >= t['budget']), len(budgeted), 'ticks with B > 0'))
        rows.append(_mean(ctx, arm, 'M-P18', [t['objective'] for t in ticks], population))
        rows.append(_mean(ctx, arm, 'M-P25', [t['covered'] for t in ticks], population))
        rows.append(_mean(ctx, arm, 'M-P26', [t['moves'] for t in ticks], population))
        rows.append(_mean(ctx, arm, 'M-P27', [t['admitted_per_asset'] for t in ticks], population))
        rows.append(_mean(ctx, arm, 'M-P28', [t['cost'] for t in ticks], population))
        rows.append(_mean(ctx, arm, 'M-P29', [t['seconds'] for t in ticks], population))
        if arm != control:
            pair_pop = '%d ticks matched to the control' % len(digests)
            for metric_id, key in (('M-P25', 'covered'), ('M-P26', 'moves'), ('M-P27', 'admitted_per_asset'), ('M-P28', 'cost')):
                diffs = [(t[key] - control_ticks[d][key]) if t[key] is not None and control_ticks[d][key] is not None else None
                         for d, t in zip(digests, ticks) if d in control_ticks]
                rows.append(_paired(ctx, arm, metric_id, diffs, pair_pop))
            diffs = [(1 if t['selected_set'] != control_ticks[d]['selected_set'] else 0) for d, t in zip(digests, ticks) if d in control_ticks]
            rows.append(_paired(ctx, arm, 'M-P21', diffs, pair_pop))
        for metric_id in UNAVAILABLE_IN_REPLAY:
            rows.append(_row(ctx, arm, metric_id, data_status='UNAVAILABLE', population='replay',
                             reason='REPLAY_OBSERVES_NO_OUTCOMES: requires independently verified paired sandbox episodes (S3)'))
        # Plot data.
        stages = [('enabled pairs', pairs)] + [('first veto ' + g, veto.get(g, 0)) for g in GATE_ORDER] + \
                 [('admitted', admitted), ('scored', sum(f.get('scored', 0) for f in funnels)),
                  ('positive gain', sum(f.get('positive_gain', 0) for f in funnels)), ('selected', sum(f.get('selected', 0) for f in funnels))]
        plots['funnel'][arm] = [{'stage': s, 'count': c} for s, c in stages]
        g9 = Counter()
        for f in funnels:
            g9.update(f.get('g9_categories') or {})
        plots['g9'][arm] = dict(g9)
        plots['noop'][arm] = dict(reasons)
        plots['action_mix'][arm] = dict(mix)
    if ctx['control'] in matched:
        rows.extend(dispatch_rows(ctx, [by_snapshot[d][control] for d in matched[control]]))
    for row in rows:
        if row['comparison'] in ('ARM_LEVEL', 'PAIRED_DIFF_VS_CONTROL') and row['dimension'] is None and row['data_status'] == 'OBSERVED':
            key = row['metric_id'] if row['comparison'] == 'ARM_LEVEL' else row['metric_id'] + ':diff'
            target = plots['dose_response'] if row['comparison'] == 'ARM_LEVEL' else plots['paired']
            target[key].append({'arm_id': row['arm_id'], 'x_label': row['effective_value_label'], 'x_value': row['effective_value'],
                                'is_control': row['arm_id'] == control, 'value': row['value'], 'ci_low': row['ci_low'],
                                'ci_high': row['ci_high'], 'n': row['n'], 'numerator': row['numerator'], 'denominator': row['denominator']})
    plots['dose_response'], plots['paired'] = dict(plots['dose_response']), dict(plots['paired'])
    population = {'snapshots_replayed': len(by_snapshot), 'control_eligible': len(eligible), 'control_exclusions': exclusions,
                  'matched_by_arm': {a: len(matched[a]) for a in arms}, 'arm_exclusions': arm_exclusions}
    return rows, plots, population


def dispatch_rows(ctx, control_results):
    counts = Counter()
    for r in control_results:
        for rec in r.get('dispatch') or []:
            if not rec.get('selected'):
                continue
            counts['selected'] += 1
            if rec.get('dry_run'):
                counts['suppressed: dry-run'] += 1
            elif rec.get('kill_switch'):
                counts['suppressed: kill switch'] += 1
            else:
                counts['dispatch: ' + (rec.get('dispatch_outcome') or 'unknown')] += 1
            if rec.get('actuated'):
                counts['actuated (emitted)'] += 1
    total = counts.get('selected', 0)
    rows = []
    for stage, count in sorted(counts.items()):
        rows.append(_row(ctx, ctx['control'], 'M-P24', dimension=stage, numerator=count, denominator=total or None,
                         value=count, n=total, population='recorded production selections (control arm only)',
                         comparison='PRODUCTION_RECORD', reason='confirmation and verified security outcome are not part of replay'))
    return rows
