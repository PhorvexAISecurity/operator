"""Evidence exports: tidy CSV/JSON, an Excel workbook, SVG plots, a short report and one ZIP.

Every row carries the experiment, arm, snapshot and asset identity so it joins back to the
raw replay output. Missing values stay empty (never 0), and strings are neutralized against
spreadsheet formula injection.
"""
import csv
import html
import json
import math
import zipfile
from pathlib import Path

from .analysis import GATE_ORDER, METRIC_CATALOG
from .common import utc, write_json

ARTIFACTS = ['experiment_manifest.json', 'preflight.json', 'arms.json', 'replay-summary.json', 'result.json', 'metrics.json', 'plots.json',
             'sweep_results.csv', 'candidate_gate_trace.csv', 'decision_funnel.csv', 'cost_truth.csv', 'candidates.csv',
             'Phorvex_Math_Lab_Results.xlsx', 'report.md', 'replay.jsonl', 'inspect.jsonl']


def safe(value):
    if value is None:
        return ''
    if isinstance(value, float) and not math.isfinite(value):
        return 'NaN' if value != value else ('Inf' if value > 0 else '-Inf')
    if isinstance(value, (list, dict)):
        value = json.dumps(value, sort_keys=True)
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def write_csv(path, headers, rows):
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(headers)
        for row in rows:
            w.writerow([safe(row.get(h)) for h in headers])


def _ident(line):
    s = line.get('snapshot') or {}
    return {'snapshot_digest': s.get('snapshot_digest'), 'captured_at': s.get('captured_at'), 'tick_id': s.get('tick_id'),
            'policy_uid': s.get('policy_uid'), 'git_sha': s.get('git_sha'), 'arm_id': line.get('arm_id'), 'arm_status': line.get('status')}


METRIC_HEADERS = ['experiment_id', 'arm_id', 'control_id', 'parameter_id', 'effective_value', 'effective_value_label', 'metric_id', 'metric_name',
                  'metric_kind', 'metric_proposed', 'dimension', 'unit', 'numerator', 'denominator', 'value', 'n', 'paired_n', 'ci_low',
                  'ci_high', 'ci_method', 'comparison', 'comparison_status', 'data_status', 'reason', 'population', 'definition']
GATE_HEADERS = ['experiment_id', 'snapshot_digest', 'captured_at', 'tick_id', 'policy_uid', 'git_sha', 'arm_id', 'arm_status', 'asset', 'asset_uid',
                'action', 'gate_id', 'law', 'actual_status', 'first_veto', 'reason_code', 'reason', 'telemetry_status', 'diagnostic_status',
                'counterfactual_only', 'diagnostic_evaluator', 'would_pass_all_other_gates']
FUNNEL_HEADERS = ['experiment_id', 'snapshot_digest', 'captured_at', 'tick_id', 'policy_uid', 'git_sha', 'arm_id', 'arm_status', 'asset', 'asset_uid',
                  'attack_backed', 'admitted_candidates', 'positive_gain_candidates', 'selected', 'action', 'feasible', 'noop_reason',
                  'engine_noop_reason', 'coverage_value', 'common_weight_covered', 'expected_cost', 'c_hi', 'c_norm', 'c_flow', 'net_gain',
                  'objective_penalty', 'dispatch_status', 'confirmation_status', 'security_outcome_verified']
COST_HEADERS = ['experiment_id', 'snapshot_digest', 'captured_at', 'tick_id', 'policy_uid', 'arm_id', 'asset', 'action', 'action_family',
                'c_norm_expected', 'c_flow_expected', 'expected_cost_weighted', 'c_hi', 'cost_ceiling_effective', 'flow_regime',
                'flow_predicted_mean', 'flow_floor_applied', 'flow_uncertainty_applied', 'conformal_window_ready', 'gpu_envelope_applied',
                'missing_load_regime', 'unactionable_category', 'realized_status', 'compatible_comparison']
CANDIDATE_HEADERS = ['experiment_id', 'snapshot_digest', 'captured_at', 'arm_id', 'asset', 'action', 'first_veto_gate', 'first_veto_reason',
                     'eligibility_kind', 'feasibility_law', 'admitted', 'scored', 'net_gain', 'selected', 'g9_category', 'expected_cost', 'c_hi']


def _flatten(lines, eid, key, extra=None):
    for line in lines:
        ident = _ident(line)
        for row in line.get(key) or []:
            out = {'experiment_id': eid, **ident, **row}
            if extra:
                out.update(extra(line, row))
            yield out


def write_csvs(root, manifest, lines, rows):
    eid = manifest['experiment_id']
    write_csv(root / 'sweep_results.csv', METRIC_HEADERS, rows)
    write_csv(root / 'candidate_gate_trace.csv', GATE_HEADERS, _flatten(lines, eid, 'gates'))
    write_csv(root / 'decision_funnel.csv', FUNNEL_HEADERS, _flatten(lines, eid, 'decisions'))
    write_csv(root / 'cost_truth.csv', COST_HEADERS, _flatten(lines, eid, 'costs'))
    write_csv(root / 'candidates.csv', CANDIDATE_HEADERS, _flatten(lines, eid, 'candidates'))


def write_workbook(root, manifest, rows):
    try:
        from openpyxl import Workbook
    except ImportError:
        return False
    wb = Workbook(write_only=True)
    ws = wb.create_sheet('Read me')
    for line in [['Phorvex Math Lab experiment', manifest['experiment_id']], ['Title', manifest.get('title')],
                 ['Parameter', manifest['parameter']['param_id'] + ' ' + str(manifest['parameter'].get('name'))],
                 ['Policy', manifest['policy']], ['Mode', 'REPLAY (decision mechanism only; no defense or SLO outcomes)'],
                 ['Replay binary', str(manifest['replay_binary'].get('git_sha')) + ' / ' + str(manifest['replay_binary'].get('image_digest'))],
                 ['Cohort', '%d snapshots (%s)' % (len(manifest['cohort']['snapshot_digests']), manifest['cohort']['digests_sha256'])],
                 ['Generated', utc()]] + [['Limitation', x] for x in manifest['limitations']]:
        ws.append([safe(x) for x in line])
    for name, path, headers in (('Metrics', 'sweep_results.csv', METRIC_HEADERS), ('Candidates', 'candidates.csv', CANDIDATE_HEADERS),
                                ('Decisions', 'decision_funnel.csv', FUNNEL_HEADERS), ('Costs', 'cost_truth.csv', COST_HEADERS),
                                ('Gates', 'candidate_gate_trace.csv', GATE_HEADERS)):
        sheet = wb.create_sheet(name)
        with open(root / path, newline='') as f:
            for i, row in enumerate(csv.reader(f)):
                if i > 200000:
                    sheet.append(['truncated at 200000 rows; see ' + path + ' in the ZIP'])
                    break
                sheet.append(row)
    wb.save(root / 'Phorvex_Math_Lab_Results.xlsx')
    return True


def _svg_points(title, subtitle, points, y_label, watermark):
    width, height, left, right, top, bottom = 720, 360, 70, 20, 56, 64
    values = [p for p in points if p.get('value') is not None]
    if not values:
        return None
    lows = [p['ci_low'] if p.get('ci_low') is not None else p['value'] for p in values]
    highs = [p['ci_high'] if p.get('ci_high') is not None else p['value'] for p in values]
    y0, y1 = min(lows + [0]), max(highs)
    if y1 == y0:
        y1 = y0 + 1
    pad = (y1 - y0) * .08
    y0, y1 = y0 - (pad if y0 < 0 else 0), y1 + pad
    n = len(values)
    def x(i): return left + (width - left - right) * (i + .5) / n
    def y(v): return top + (height - top - bottom) * (1 - (v - y0) / (y1 - y0))
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="sans-serif">' % (width, height, width, height),
           '<rect width="100%" height="100%" fill="white"/>',
           '<text x="%d" y="22" font-size="15" font-weight="600">%s</text>' % (left, html.escape(title)),
           '<text x="%d" y="40" font-size="11" fill="#555">%s</text>' % (left, html.escape(subtitle)),
           '<text x="%d" y="%d" font-size="11" fill="#999" text-anchor="end">%s</text>' % (width - right, 22, html.escape(watermark))]
    for k in range(5):
        v = y0 + (y1 - y0) * k / 4
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="#eee"/>' % (left, width - right, y(v), y(v)))
        out.append('<text x="%d" y="%.1f" font-size="10" text-anchor="end" fill="#555">%.3g</text>' % (left - 6, y(v) + 3, v))
    out.append('<text x="14" y="%d" font-size="11" fill="#555" transform="rotate(-90 14 %d)" text-anchor="middle">%s</text>' % ((top + height - bottom) // 2, (top + height - bottom) // 2, html.escape(y_label)))
    for i, p in enumerate(values):
        cx = x(i)
        if p.get('ci_low') is not None and p.get('ci_high') is not None:
            out.append('<line x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f" stroke="#555"/>' % (cx, cx, y(p['ci_low']), y(p['ci_high'])))
        color = '#111' if p.get('is_control') else '#2a6fdb'
        out.append('<circle cx="%.1f" cy="%.1f" r="5" fill="%s"/>' % (cx, y(p['value']), color))
        label = (p.get('x_label') or p.get('arm_id') or '')[:22]
        out.append('<text x="%.1f" y="%d" font-size="10" text-anchor="middle">%s</text>' % (cx, height - bottom + 16, html.escape(label)))
        out.append('<text x="%.1f" y="%d" font-size="9" text-anchor="middle" fill="#777">n=%s</text>' % (cx, height - bottom + 30, p.get('n')))
    out.append('</svg>')
    return '\n'.join(out)


def write_plots(root, manifest, plots, result):
    pdir = root / 'plots'
    pdir.mkdir(exist_ok=True)
    footer = '%s | %s | binary %s | cohort %d ticks | %s' % ('REPLAY MECHANISM', manifest['policy'], str(manifest['replay_binary'].get('git_sha'))[:10],
                                                             len(manifest['cohort']['snapshot_digests']), result['comparison_status'])
    written = []
    for key, points in (plots.get('dose_response') or {}).items():
        mid = key.split(':')[0]
        name, kind = METRIC_CATALOG[mid][0], METRIC_CATALOG[mid][1]
        svg = _svg_points('PL-01 ' + name + ' vs ' + manifest['parameter']['param_id'], footer, points, METRIC_CATALOG[mid][2], kind)
        if svg:
            (pdir / ('PL-01_' + mid + '.svg')).write_text(svg)
            written.append('plots/PL-01_' + mid + '.svg')
    for key, points in (plots.get('paired') or {}).items():
        mid = key.split(':')[0]
        svg = _svg_points('PL-09 paired difference vs control: ' + METRIC_CATALOG[mid][0], footer, points, 'arm - control', METRIC_CATALOG[mid][1])
        if svg:
            (pdir / ('PL-09_' + mid + '.svg')).write_text(svg)
            written.append('plots/PL-09_' + mid + '.svg')
    return written


def write_report(root, manifest, rows, result):
    lines = ['# Math Lab experiment ' + manifest['experiment_id'], '', '**' + str(manifest.get('title') or '') + '**', '',
             '- Parameter: `%s` %s (%s)' % (manifest['parameter']['param_id'], manifest['parameter'].get('name'), manifest['parameter'].get('config_key')),
             '- Policy: `%s`; mode: REPLAY (decision mechanism only)' % manifest['policy'],
             '- Replay binary: source `%s`, image `%s`' % (manifest['replay_binary'].get('git_sha'), manifest['replay_binary'].get('image_digest')),
             '- Cohort: %d recorded ticks, digest list `%s`' % (len(manifest['cohort']['snapshot_digests']), manifest['cohort']['digests_sha256']),
             '- Comparison status: **%s**' % result['comparison_status'],
             '- Control eligible (baseline reproduced exactly): %d; matched per arm: %s' % (result['population']['control_eligible'], result['population']['matched_by_arm']),
             '- Excluded control ticks: %s' % (result['population']['control_exclusions'] or 'none'), '',
             '## Hypothesis', '', str(manifest.get('hypothesis') or '(not stated)'), '', '## Headline metrics', '',
             '| Arm | Value | Metric | Estimate | 95% interval | n | Kind |', '|---|---|---|---|---|---|---|']
    for r in rows:
        if r['dimension'] is None and r['metric_id'] in ('M-P21', 'M-P22', 'M-P04', 'M-P19', 'M-P25', 'M-P26', 'M-P28') and r['data_status'] == 'OBSERVED':
            interval = '' if r['ci_low'] is None else '[%.4g, %.4g]' % (r['ci_low'], r['ci_high'])
            label = r['metric_id'] + (' (diff vs control)' if r['comparison'] == 'PAIRED_DIFF_VS_CONTROL' else '')
            lines.append('| %s | %s | %s | %.4g | %s | %s | %s |' % (r['arm_id'], r['effective_value_label'], label, r['value'], interval, r['n'], r['metric_kind']))
    lines += ['', '## What this does and does not show', ''] + ['- ' + x for x in manifest['limitations']] + [
        '- M-S01 (verified defense rate) and M-D02..M-D09 (observed disruption) are UNAVAILABLE in replay. No row here is a defense or safety result.',
        '- ESTIMATED_MODEL rows are model quantities; PROCESS rows are decision-mechanism counts.', '',
        '_Generated %s. Raw rows: sweep_results.csv, candidate_gate_trace.csv, decision_funnel.csv, cost_truth.csv; replay.jsonl is authoritative._' % utc()]
    (root / 'report.md').write_text('\n'.join(lines) + '\n')


def write_all(root, manifest, lines, rows, plots, result):
    root = Path(root)
    write_csvs(root, manifest, lines, rows)
    workbook = write_workbook(root, manifest, rows)
    plot_files = write_plots(root, manifest, plots, result)
    write_report(root, manifest, rows, result)
    artifacts = [a for a in ARTIFACTS if (root / a).exists()] + plot_files
    write_json(root / 'artifacts.json', {'artifacts': artifacts, 'workbook': workbook, 'generated_at': utc()})
    with zipfile.ZipFile(root / 'evidence.zip', 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for name in artifacts + ['artifacts.json']:
            z.write(root / name, arcname=name)
    return artifacts
