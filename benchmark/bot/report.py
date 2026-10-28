"""The benchmark result as a Telegram summary, a standalone HTML page and a CSV.

Works for both experiment kinds: Math Lab parameter experiments (rows from the
dashboard API) and code experiments (rows from code_experiment.py). Every value
keeps its interval and its data status; missing is shown as missing, never 0.
"""
import csv
import html
import io
import math

HEADLINE = ('M-P21', 'M-P26', 'M-P19', 'M-P22', 'M-P25', 'M-P28', 'M-P02')
CSV_FIELDS = ('experiment_id', 'arm_id', 'effective_value', 'effective_value_label', 'metric_id', 'metric_name', 'unit',
              'value', 'ci_low', 'ci_high', 'ci_method', 'numerator', 'denominator', 'n', 'paired_n', 'data_status',
              'comparison_status', 'population', 'reason')
TELEGRAM_LIMIT = 4000


def headline(rows):
    """Arm-level headline rows, ordered by metric then by arm order of appearance."""
    arms = list(dict.fromkeys(r['arm_id'] for r in rows))
    picked = [r for r in rows if r.get('metric_id') in HEADLINE and r.get('dimension') is None]
    return sorted(picked, key=lambda r: (HEADLINE.index(r['metric_id']), arms.index(r['arm_id'])))


def _num(v):
    if v is None or (isinstance(v, float) and not math.isfinite(v)):
        return None
    return v


def fmt(row):
    value = _num(row.get('value'))
    if value is None:
        return 'n/a (%s)' % (row.get('data_status') or 'UNAVAILABLE').lower()
    lo, hi = _num(row.get('ci_low')), _num(row.get('ci_high'))
    if row.get('unit') == 'proportion':
        text = '%.1f%%' % (100 * value)
        ci = ' [%.1f-%.1f]' % (100 * lo, 100 * hi) if lo is not None and hi is not None else ''
    else:
        text = '%.4g' % value
        ci = ' [%.4g-%.4g]' % (lo, hi) if lo is not None and hi is not None else ''
    counts = ''
    if row.get('numerator') is not None and row.get('denominator') is not None:
        counts = ' (%s/%s)' % (row['numerator'], row['denominator'])
    return text + ci + counts


def summary(meta, result, rows):
    """Plain text for Telegram (no markup, so nothing needs escaping)."""
    pop = result.get('population') or {}
    lines = ['%s: %s' % (meta['kind'], meta['title']), 'state: %s, comparison: %s' % (
        result.get('state') or meta.get('state') or '?', result.get('comparison_status', '?'))]
    if result.get('toolchain_fidelity'):
        lines.append('toolchain fidelity (deployed commit built here): %s' % result['toolchain_fidelity'])
    lines.append('ticks: %s control-eligible; matched per arm %s' % (pop.get('control_eligible', '?'), pop.get('matched_by_arm', {})))
    for key in ('policy', 'base', 'candidate', 'parameter', 'changed'):
        if meta.get(key):
            lines.append('%s: %s' % (key, meta[key]))
    lines.append('')
    current = None
    for r in headline(rows):
        if r['metric_id'] != current:
            current = r['metric_id']
            lines.append('%s %s' % (r['metric_id'], r.get('metric_name')))
        lines.append('  %-12s %s' % (r['arm_id'], fmt(r)))
    lines += ['', 'Replay only: decision mechanism on recorded ticks; no defense or SLO outcome is measured.']
    text = '\n'.join(lines)
    return text if len(text) <= TELEGRAM_LIMIT else text[:TELEGRAM_LIMIT - 20] + '\n... (see report.html)'


def page(meta, result, rows, limitations=()):
    """A standalone HTML report: metrics x arms with intervals, and the provenance."""
    e = html.escape
    arms = list(dict.fromkeys(r['arm_id'] for r in rows))
    table = {}
    for r in headline(rows):
        table.setdefault((r['metric_id'], r.get('metric_name'), r.get('unit')), {})[r['arm_id']] = r
    head = ''.join('<th>%s</th>' % e(str(a)) for a in arms)
    body = ''
    for (mid, name, unit), by_arm in table.items():
        cells = ''.join('<td>%s</td>' % e(fmt(by_arm[a])) if a in by_arm else '<td>-</td>' for a in arms)
        body += '<tr><th>%s</th><td>%s</td><td>%s</td>%s</tr>' % (e(mid), e(str(name)), e(str(unit)), cells)
    facts = ''.join('<tr><th>%s</th><td>%s</td></tr>' % (e(k), e(str(v))) for k, v in (
        ('state', result.get('state') or meta.get('state')), ('comparison', result.get('comparison_status')),
        ('toolchain fidelity', result.get('toolchain_fidelity')),
        ('control-eligible ticks', (result.get('population') or {}).get('control_eligible')),
        ('matched per arm', (result.get('population') or {}).get('matched_by_arm')),
        *((k, meta.get(k)) for k in ('policy', 'parameter', 'base', 'candidate', 'changed', 'request', 'job'))) if v not in (None, ''))
    notes = ''.join('<li>%s</li>' % e(str(x)) for x in limitations)
    return ('<!doctype html><html><head><meta charset="utf-8"><title>%s</title><style>'
            'body{font:14px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;margin:12px 0}'
            'th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}thead th{background:#f2f2f2}'
            '</style></head><body><h1>%s</h1><p>%s</p><table>%s</table><h2>Headline metrics</h2>'
            '<table><thead><tr><th>metric</th><th>name</th><th>unit</th>%s</tr></thead><tbody>%s</tbody></table>'
            '<h2>Limitations</h2><ul>%s<li>Replay only: decision mechanism on recorded ticks; no defense or SLO outcome is measured.</li></ul>'
            '</body></html>') % (e(meta['title']), e(meta['title']), e(meta['kind']), facts, head, body, notes)


def _safe(v):
    if v is None:
        return ''
    if isinstance(v, (list, dict)):
        v = repr(v)
    if isinstance(v, str) and v.startswith(('=', '+', '-', '@')):
        return "'" + v
    return v


def table(rows):
    """Every arm-level row as CSV; strings are neutralized against formula injection."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_FIELDS)
    for r in rows:
        if r.get('dimension') is None:
            w.writerow([_safe(r.get(f)) for f in CSV_FIELDS])
    return out.getvalue().encode()
