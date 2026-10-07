"""Loss-aware exports of original Console records into the owner's RAW templates.

No latency, legacy scalar or absent telemetry is converted into realized CNorm/CFlow.
The current model publishes expected costs but no compatible realized-cost contract.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import sqlite3
import tempfile
from pathlib import Path

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.cell import WriteOnlyCell

TEMPLATES = Path(__file__).with_name('templates')
TEMPLATE_NAMES = ('Phorvex_Cost_Measured_vs_Expected_RAW_TEMPLATE.xlsx',
                  'Phorvex_Tick_Action_Gates_RAW_TEMPLATE.xlsx')
COST_FILE = 'Phorvex_Cost_Measured_vs_Expected.xlsx'
GATES_FILE = 'Phorvex_Tick_Action_Gates.xlsx'
EXTRA = ['decision_id', 'policy_uid', 'asset_uid', 'candidate_key', 'evaluation_round',
         'selection_round', 'row_kind', 'source_ref', 'norm_weight', 'flow_weight',
         'economics_version', 'norm_preference', 'flow_preference', 'effective_cost_coefficient',
         'dispatch_outcome', 'attack_record_ids', 'causal_link_basis', 'capture_gap',
         'action_status', 'exclusion_kind', 'gross_security_score', 'marginal_security_score',
         'net_gain_recorded', 'cost_high', 'selected_reason', 'source_git_sha', 'brain_image', 'parameter_manifest_hash', 'policy_generation']
EXTRA.append('trace_candidate_present')


def template_paths():
    """Exactly the two owner-supplied workbooks, never directory metadata."""
    return [TEMPLATES / name for name in TEMPLATE_NAMES]


def optional(value):
    """OptionalFloat/Bool/Int requires present=true; false and zero are values."""
    if isinstance(value, dict):
        return value.get('value') if value.get('present') is True else None
    return value if value is not None and not isinstance(value, dict) else None


def finite(value):
    value = optional(value)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def js(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def typed_links(result):
    """Only producer-stamped decision IDs; no temporal/namespace link substitution."""
    links = set()
    def visit(value, key=''):
        if isinstance(value, dict):
            if value.get('correlation') in ('temporal-workload', 'temporal-workload-candidate'):
                return
            for name, child in value.items():
                if name.lower() in ('selecteddecisionid', 'selectiondecisionid') and isinstance(child, str) and child:
                    links.add(child)
                if name.lower() == 'decisionid' and value.get('correlation') == 'exact-event-uid' and isinstance(child, str) and child:
                    links.add(child)
                visit(child, name)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    # temporalDecisionEvidence explicitly represents temporal correlation, not an exact causal link.
    visit({key: value for key, value in result.items() if key != 'temporalDecisionEvidence'})
    return links


def row_identity(trace):
    return (trace.get('policyUID'), trace.get('tickID'), trace.get('assetUID'), trace.get('decisionID'))


def source_rows(record, run_id, ref, links=None, gap=''):
    trace = record.get('decisionTrace')
    if not isinstance(trace, dict):
        return [], []
    base = {'run_id': run_id, 'timestamp': trace.get('timestamp', record.get('time')),
            'tick_id': trace.get('tickID'), 'application': trace.get('tenantName', record.get('tenant')),
            'namespace': trace.get('assetNamespace', record.get('namespace')),
            'pod_or_asset': trace.get('assetName', record.get('pod')),
            'decision_id': trace.get('decisionID'), 'policy_uid': trace.get('policyUID'),
            'asset_uid': trace.get('assetUID'), 'evaluation_round': trace.get('evaluationRound'),
            'source_ref': ref, 'norm_weight': trace.get('normWeight'), 'flow_weight': trace.get('flowWeight'),
            'economics_version': trace.get('economicsVersion'),
            'norm_preference': optional(trace.get('normPreference')),
            'flow_preference': optional(trace.get('flowPreference')),
            'effective_cost_coefficient': trace.get('effectiveCostCoefficient'),
            'dispatch_outcome': trace.get('dispatchOutcome'),
            'source_git_sha': trace.get('gitSHA'), 'brain_image': trace.get('brainImage'),
            'parameter_manifest_hash': (record.get('parameterSet') or {}).get('manifestHash'),
            'policy_generation': ((record.get('scopedOutcomes') or {}).get('policy') or {}).get('generation'),
            'attack_record_ids': sorted((links or {}).get(trace.get('decisionID'), [])),
            'causal_link_basis': 'exact producer decision identity' if (links or {}).get(trace.get('decisionID')) else 'UNLINKED; campaign window only',
            'capture_gap': gap}
    statuses = {s['action']: s for s in trace.get('actionStatus', []) if s.get('action')}
    pairs = [(c, statuses.get(c.get('action'), {})) for c in trace.get('candidates', [])]
    seen = {c.get('action') for c, _ in pairs}
    pairs += [({'action': action}, status) for action, status in statuses.items() if action not in seen]
    costs, gates = [], []
    for candidate, status in pairs:
        exclusion = status.get('exclusionKind', '')
        reason = candidate.get('existingExclusionReason') or status.get('reason', '')
        is_candidate = bool(candidate.get('candidateKey'))
        extra = {**base, 'action': candidate.get('action'), 'candidate_key': candidate.get('candidateKey'),
                 'trace_candidate_present': is_candidate,
                 'selection_round': optional(candidate.get('selectionRound')),
                 'action_status': status.get('status'), 'exclusion_kind': status.get('exclusionKind'),
                 'gross_security_score': optional(candidate.get('grossFullValue')), 'marginal_security_score': optional(candidate.get('marginalCoverage')),
                 'net_gain_recorded': optional(candidate.get('netGain')), 'cost_high': optional(candidate.get('costHigh')),
                 'selected_reason': candidate.get('selectionReason'),
                 'row_kind': 'excluded_candidate' if candidate.get('existingExclusionReason') else 'candidate' if is_candidate else 'action_status_only'}
        cost = {**extra, 'security_score': optional(candidate.get('marginalCoverage')),
                'provenance': optional(candidate.get('provenance')),
                'CNorm_expected': finite(candidate.get('cNorm')), 'CFlow_expected': finite(candidate.get('cFlow')),
                'C_total_expected': finite(candidate.get('expectedCost')),
                'telemetry_complete': 'no', 'cost_model_version': trace.get('costModelVersion'),
                'notes': 'Realized CNorm/CFlow UNAVAILABLE: current producer has no compatible measurement definition and window. '
                         + (reason or candidate.get('selectionReason', ''))}
        # None deliberately leaves every measured field and comparison blank.
        costs.append(cost)
        gate = {**extra, 'action_enabled': None if not status or status.get('status') == 'not-evaluated-by-current-model' else exclusion != 'not-enabled',
                'candidate_generated': is_candidate and not candidate.get('existingExclusionReason'),
                'local_feasibility_gate': bool_gate(optional(candidate.get('feasible'))),
                'slo_cost_gate': bool_gate(optional(candidate.get('sloGateResult'))),
                'final_feasible': True if status.get('status') in ('selected', 'candidate', 'priced-out', 'budget-exhausted') else False if status.get('status') in ('infeasible', 'conformal-slo', 'ineligible', 'not-installable', 'no-cover', 'not-enabled') else None,
                'scored': status.get('scored'), 'selected': candidate.get('selected', False) if is_candidate else status.get('status') == 'selected',
                'primary_blocking_gate': exclusion if exclusion not in ('', 'none', 'selection') else None,
                'blocking_reason_detail': reason or status.get('reason'),
                'cost_gate_basis': 'costHigh / costCeiling' if optional(candidate.get('sloGateResult')) is not None else None,
                'missing_telemetry_fields': 'Unemitted gates remain blank; prior selection rounds are not retained.',
                'notes': 'Original status: ' + status.get('status', 'unavailable')}
        mapping = {'no-rbac': 'capability_gate', 'capability-unsupported': 'capability_gate',
                   'not-installable': 'capability_gate', 'operator-opt-out': 'capability_gate',
                   'action-failure-cooldown': 'cooldown_gate', 'recon-cover': 'recon_security_cover_gate',
                   'resource-capacity': 'resource_gate', 'slo-gate': 'slo_cost_gate',
                   'feasibility': 'local_feasibility_gate'}
        if exclusion in mapping:
            gate[mapping[exclusion]] = 'FAIL'
        elif exclusion not in ('', 'none', 'selection'):
            gate['other_gate'] = 'FAIL'
        # Cadence/PDB etc are not guessed from string fragments. Preserve the raw reason.
        if exclusion == 'slo-gate':
            gate.update(blocking_constraint_name='costCeiling', observed_value=finite(candidate.get('costHigh')),
                        required_limit_or_condition=finite(trace.get('costCeiling')))
            if gate['observed_value'] is not None and gate['required_limit_or_condition'] is not None:
                gate['constraint_slack_or_gap'] = gate['required_limit_or_condition'] - gate['observed_value']
        if status.get('rbacUnknown') or candidate.get('rbacUnknown'):
            gate['capability_gate'] = 'UNKNOWN'
            gate['missing_telemetry_fields'] += ' RBAC permission result unknown.'
        gates.append(gate)
    if trace.get('selectedAction') == 'noop':
        extra = {**base, 'action': 'noop', 'row_kind': 'observed_noop'}
        costs.append({**extra, 'telemetry_complete': 'no', 'notes': trace.get('noopReason') or 'Recorded NOOP; no realized cost observation.'})
        gates.append({**extra, 'selected': False, 'candidate_generated': False,
                      'blocking_reason_detail': trace.get('noopReason'), 'notes': 'Observed no-selection outcome, not an inferred candidate.'})
    return costs, gates


def bool_gate(value):
    return 'PASS' if value is True else 'FAIL' if value is False else None


def safe_cell(value):
    if isinstance(value, (dict, list)):
        value = js(value)
    if isinstance(value, str) and len(value) > 32767:
        return value[:32600] + ' [Excel cell shortened; exact evidence in evidence.zip]'
    return value


class DiskRows:
    """Bounded-memory intermediate rows for the small jump host."""
    def __init__(self, connection, name):
        self.connection, self.name, self.count = connection, name, 0
        connection.execute('CREATE TABLE ' + name + ' (id INTEGER PRIMARY KEY, value TEXT)')
    def append(self, row):
        self.connection.execute('INSERT INTO ' + self.name + '(value) VALUES (?)', (js(row),))
        self.count += 1
        if self.count % 1000 == 0: self.connection.commit()
    def extend(self, rows):
        for row in rows: self.append(row)
    def __len__(self): return self.count
    def __iter__(self):
        for row in self.connection.execute('SELECT value FROM ' + self.name + ' ORDER BY id'):
            yield json.loads(row[0])


def stream_sheet(wb, name, headers, rows, count):
    ws = wb.create_sheet(name)
    ws.freeze_panes = 'H2' if len(headers) > 7 else 'A2'
    ws.row_dimensions[1].height = 32
    head = []
    from openpyxl.utils import get_column_letter
    for index, header in enumerate(headers, 1):
        ws.column_dimensions[get_column_letter(index)].width = min(42, max(18, len(str(header or '')) + 2))
        cell = WriteOnlyCell(ws, value=header)
        cell.font = Font(color='FFFFFF', bold=True)
        cell.fill = PatternFill('solid', fgColor='163C49')
        cell.alignment = Alignment(wrap_text=True, vertical='center')
        head.append(cell)
    ws.append(head)
    for row in rows:
        cells = []
        for header in headers:
            value = safe_cell(row.get(header))
            if isinstance(value, str):
                cell = WriteOnlyCell(ws, value=value); cell.data_type = 's'; cells.append(cell)
            else: cells.append(value)
        ws.append(cells)
    ws.auto_filter.ref = 'A1:' + get_column_letter(len(headers)) + str(count + 1)
    return ws


def export_workbooks(out, request, manifest):
    out = Path(out)
    cases = [json.loads(line) for line in (out / 'cases.jsonl').read_text().splitlines() if line.strip()]
    links = {}
    for case in cases:
        result = case.get('result') or {}
        for did in typed_links(result):
            links.setdefault(did, set()).add(result.get('id', case.get('attackRecordId')))
    seen, trace_hashes, conflicts = set(), {}, []
    temporary = tempfile.TemporaryDirectory(prefix='phorvex-benchmark-export-')
    connection = sqlite3.connect(str(Path(temporary.name) / 'rows.sqlite'))
    cost_rows, gate_rows = DiskRows(connection, 'costs'), DiskRows(connection, 'gates')
    started, ended = manifest.get('startedAt', ''), manifest.get('finishedAt', '')
    # RFC3339 strings carry differing fractional precision; parse instants rather than lexicographic comparison.
    from datetime import datetime
    def instant(value):
        try: return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        except (TypeError, ValueError): return None
    lower, upper = instant(started), instant(ended)
    for path in sorted((out / 'raw').glob('audit-*.jsonl')):
        with path.open() as source:
            for line_number, line in enumerate(source, 1):
                try: record = json.loads(line)
                except ValueError: continue
                trace = record.get('decisionTrace')
                if not isinstance(trace, dict): continue
                at = instant(trace.get('timestamp', record.get('time')))
                if at is None or lower is not None and at < lower or upper is not None and at > upper: continue
                identity = row_identity(trace)
                if not all(identity):
                    conflicts.append({'source_ref': f'raw/{path.name}:{line_number}', 'reason': 'incomplete scoped decision identity'})
                    continue
                digest = hashlib.sha256(js(trace).encode()).hexdigest()
                if identity in seen:
                    if trace_hashes[identity] != digest:
                        conflicts.append({'source_ref': f'raw/{path.name}:{line_number}', 'reason': 'conflicting trace identity', 'identity': identity})
                    continue
                seen.add(identity); trace_hashes[identity] = digest
                cs, gs = source_rows(record, request['id'], f'raw/{path.name}:{line_number}', links,
                                     'Capture gaps: see Evidence_Coverage' if manifest.get('captureGaps') else '')
                cost_rows.extend(cs); gate_rows.extend(gs)
    coverage = [dict(namespace=app, status='GAP' if data.get('gaps') else 'CONNECTED', **data)
                for app, data in manifest.get('capture', {}).items()]
    captured_ids = {key[3] for key in seen}
    coverage += [{'namespace': c.get('namespace'), 'case_id': c.get('id'), 'status': c.get('status'),
                  'reason': c.get('reason'), 'attack_record_id': c.get('attackRecordId'),
                  'decision_links': sorted(typed_links(c.get('result') or {})),
                  'full_trace_link_coverage': 'CAPTURED' if typed_links(c.get('result') or {}) & captured_ids else 'UNAVAILABLE'} for c in cases]
    coverage += [{'status': 'CONFLICT', **c} for c in conflicts]
    summary = [{'field': 'run_id', 'value': request['id']}, {'field': 'status', 'value': manifest['status']},
               {'field': 'mode', 'value': request['mode']}, {'field': 'model', 'value': request.get('model')},
               {'field': 'request', 'value': request.get('request')}, {'field': 'context', 'value': request.get('context')},
               {'field': 'started_at', 'value': started}, {'field': 'finished_at', 'value': ended},
               {'field': 'unique_full_decision_traces', 'value': len(seen)},
               {'field': 'realized_cost_status', 'value': 'UNAVAILABLE; no compatible producer-owned cost measurement/window'},
               {'field': 'acceptance', 'value': 'Outcome remains scoped to original producer evidence; capture completeness is separate from defense.'}]
    versions = [{'field': key, 'value': value} for key, value in manifest.get('version', {}).items()]
    case_headers = ['namespace', 'id', 'name', 'status', 'reason', 'attackRecordId', 'startedAt', 'finishedAt',
                    'outcome', 'outcomeClass', 'phorvexAction', 'actuated', 'evidenceKind', 'result']
    checks = DiskRows(connection, 'checks')
    for row in cost_rows:
        nw, fw, cn, cf, expected = (row.get(k) for k in ('norm_weight', 'flow_weight', 'CNorm_expected', 'CFlow_expected', 'C_total_expected'))
        available = all(finite(v) is not None for v in (nw, fw, cn, cf, expected))
        recomputed = nw * cn + fw * cf if available else None
        checks.append({'decision_id': row.get('decision_id'), 'candidate_key': row.get('candidate_key'),
                       'status': ('PASS' if math.isclose(expected, recomputed, rel_tol=1e-9, abs_tol=1e-10) else 'FAIL') if available else 'UNAVAILABLE',
                       'expected_recorded': expected, 'expected_recomputed': recomputed,
                       'difference': expected - recomputed if available else None, 'source_ref': row['source_ref']})
    for template, filename, main, rows in [
        ('Phorvex_Cost_Measured_vs_Expected_RAW_TEMPLATE.xlsx', COST_FILE, 'Cost_Comparison', cost_rows),
        ('Phorvex_Tick_Action_Gates_RAW_TEMPLATE.xlsx', GATES_FILE, 'Tick_Action_Gates', gate_rows)]:
        original = openpyxl.load_workbook(TEMPLATES / template, read_only=True)
        headers = [c.value for c in next(original[main].iter_rows())] + EXTRA
        wb = openpyxl.Workbook(write_only=True)
        stream_sheet(wb, main, headers, rows, len(rows))
        for sheet in original:
            if sheet.title == main: continue
            values = list(sheet.values)
            if sheet.title == 'README':
                values[0] = ('Purpose', 'Live campaign export using the original RAW template; definitions retained.')
                if main == 'Cost_Comparison':
                    values[2] = ('Expected and measured', 'Expected fields are recorded Brain estimates. Realized costs require compatible telemetry and a declared window; current producer supplies neither.')
                else:
                    values[4] = ('Source', 'Original structured decision/status records. Unemitted gates remain blank; candidate presence and final feasibility stay distinct.')
            small_headers = list(values[0])
            small_rows = [dict(zip(small_headers, value)) for value in values[1:]]
            stream_sheet(wb, sheet.title, small_headers, small_rows, len(small_rows))
        original.close()
        stream_sheet(wb, 'Run_Summary', ['field', 'value'], summary, len(summary))
        stream_sheet(wb, 'Versions', ['field', 'value'], versions, len(versions))
        stream_sheet(wb, 'Attack_Outcomes', case_headers, cases, len(cases))
        coverage_headers = sorted({key for row in coverage for key in row}) or ['status']
        stream_sheet(wb, 'Evidence_Coverage', coverage_headers, coverage, len(coverage))
        stream_sheet(wb, 'Expected_Cost_Checks', ['decision_id', 'candidate_key', 'status', 'expected_recorded', 'expected_recomputed', 'difference', 'source_ref'], checks, len(checks))
        wb.save(out / filename)
        # A separate CSV preserves all rows, including cells too large for Excel.
        with (out / (main + '.csv')).open('w', newline='') as target:
            writer = csv.writer(target); writer.writerow(headers)
            for row in rows:
                values = [js(row.get(h)) if isinstance(row.get(h), (dict, list)) else row.get(h) for h in headers]
                writer.writerow(["'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@')) else v for v in values])
    validation = {'uniqueTraces': len(seen), 'candidateCostRows': len(cost_rows), 'actionGateRows': len(gate_rows),
                  'traceConflicts': conflicts, 'costChecksFailed': sum(c['status'] == 'FAIL' for c in checks),
                  'realizedCostsAvailable': 0, 'precision': 'abs1e-10 + rel1e-9',
                  'templateSHA256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in template_paths()}}
    (out / 'export-validation.json').write_text(json.dumps(validation, ensure_ascii=False, indent=2))
    connection.close(); temporary.cleanup()
    return validation
