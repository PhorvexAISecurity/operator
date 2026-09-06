#!/usr/bin/env python3
"""Join generated operations with curated effect columns into the canonical matrix.

SCOPE (bus 213/214): native Enact + native Rollback + the Phoenix actuator + hybrid ROUTE ROWS.
Routing is never a column on a native row: in hybrid, rotate and quarantine never reach the native
handlers, so stamping a route there would score a path that does not run. Still NOT covered: `disable` (declared, not in MutatingActions).

The parked scope mattered. The native surface is opt-in; Phoenix is the DEFAULT, and the same
switch that routes hybrid traffic also decides that 13 of the 15 actions cannot run in the default
mode at all.

K3 206: normalized rows, not one compound cell per action. The rows are canonical; any
per-action summary is derived FROM them. Every column is labelled _GEN or _CURATED so a reader
can tell what a regex proved from what a person asserted, and every curated cell needs an anchor.

`crossing_status` is NOT inferred from the existence of a relation. An operation against a
declared-unwired target is declared-unwired however real the call site looks — that is what
stops `mig.Repartition` reading as a working effect.
"""
import csv, os
from findings import Findings

HERE = os.path.dirname(os.path.abspath(__file__))
def load(n):
    p = os.path.join(HERE, n)
    return list(csv.DictReader(open(p, newline=''), delimiter='\t')) if os.path.exists(p) else []

gen  = load('OPERATIONS_GEN.tsv')
cur  = {(r['action'], r['anchor'], r['verb']): r for r in load('OPERATIONS_CURATED.tsv')}
rels = load('RELATIONS.tsv')
nodes = {n['id']: n for n in load('NODES.tsv')}

# the crossing class of each external target, taken from the RELATION that reaches it
status_of = {}
for r in rels:
    if r['to'].startswith('ext.') and r.get('crossing_status') not in ('', '-'):
        # a target reached by ANY declared-unwired edge is not implemented for our purposes
        prev = status_of.get(r['to'])
        status_of[r['to']] = 'declared-unwired' if 'unwired' in (prev or '', r['crossing_status']) \
                             else r['crossing_status']
for n in nodes.values():
    if n['id'].startswith('ext.') and n['runtime_role'] == 'unwired':
        status_of[n['id']] = 'declared-unwired'

CURATED_COLS = ['acknowledgement_level','postcondition_readback','availability_recovery_observation',
                'security_goal_confirmation','runner_ledger_outcome','notes']
# K3 207: `crossing_status` answered "is the destination wired" and was then read as "does this
# happen". Two separate facts, so two columns — the Kubernetes API is wired (crossing_status
# implemented) while mig-rebind's Pod.Delete never executes (shipped_reachability
# guarded-unreached), and collapsing them scored a would-be success path as if it occurred.
HDR = (['action_GEN','surface_GEN','phase_GEN','reach_condition_GEN','prior_dependency_GEN',
        'shipped_reachability_GEN','unreached_because_GEN','path_class_GEN','path_class_reason_GEN','error_handling_GEN',
        'target_node_GEN','target_resource_GEN',
        'subresource_GEN','operation_GEN','crossing_status_GEN'] +
       [c + '_CURATED' for c in CURATED_COLS] + ['source_anchor_GEN','curation_anchor_CURATED'])

out = []
for g in gen:
    c = cur.get((g['action'], g['anchor'], g['verb']), {})
    row = {
     'action_GEN': g['action'], 'surface_GEN': g['surface'],
     'phase_GEN': g['phase'],
     'reach_condition_GEN': g['reach_condition'], 'prior_dependency_GEN': g['prior_dependency'],
     'shipped_reachability_GEN': g['shipped_reachability'],
     'path_class_GEN': g['path_class'], 'path_class_reason_GEN': g.get('path_class_reason','-'), 'error_handling_GEN': g['error_handling'],
     'unreached_because_GEN': g['unreached_because'] or '-',
     'target_node_GEN': g['target_node'], 'target_resource_GEN': g['target'],
     'subresource_GEN': g['subresource'] or '-', 'operation_GEN': g['verb'],
     'crossing_status_GEN': status_of.get(g['target_node'], 'implemented'),
     'source_anchor_GEN': g['anchor'],
     'curation_anchor_CURATED': c.get('curation_anchor', '-'),
    }
    for col in CURATED_COLS:
        row[col + '_CURATED'] = c.get(col) or 'NOT-YET-CURATED'
    # An effect column on an unreached row would describe a path that does not run. The shipped
    # mig-rebind returns an error at Available; it never emits OutcomeEmitted.
    if row['shipped_reachability_GEN'] != 'reachable':
        for col in ('acknowledgement_level','postcondition_readback',
                    'availability_recovery_observation','security_goal_confirmation',
                    'runner_ledger_outcome'):
            # K3 208: preserving NOT-YET-CURATED here left the unreached rows sitting in the
            # curation queue, as if an effect were still owed for a path that cannot run. They
            # are DONE. `notes` carries why; the effect columns carry n/a.
            row[col + '_CURATED'] = 'n/a — not reached in the shipped binary'
    out.append(row)

with open(os.path.join(HERE, 'OPERATION_MATRIX.tsv'), 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=HDR, delimiter='\t'); w.writeheader(); w.writerows(out)

done = sum(1 for r in out if r['acknowledgement_level_CURATED'] != 'NOT-YET-CURATED')
unreached = sum(1 for r in out if r['shipped_reachability_GEN'] != 'reachable')
def tally(k):
    d = {}
    for r in out: d[r[k]] = d.get(r[k], 0) + 1
    return '  '.join(f'{a} {b}' for a, b in sorted(d.items()))
print(f'operation rows: {len(out)}   columns: {len(HDR)}   settled: {done}/{len(out)} '
      f'({unreached} unreached = done by n/a, {done-unreached} curated)   '
      f'awaiting curation: {len(out)-done}')
print(f'SCOPE: native Enact + native Rollback + Phoenix; hybrid as ROUTE ROWS; disable as one declared-only row')
print(f'surfaces: {tally("surface_GEN")}')
# routing is expressed as ROWS, never as a column on a native row (K3 214)
_ph = {r['action_GEN'] for r in out if r['surface_GEN'] == 'phoenix' and r['phase_GEN'] == 'Actuate'}
print(f'Phoenix-supported actions (the DEFAULT mode): {" ".join(sorted(_ph))} — every other action '
      f'returns "unsupported action" at phoenix.go:114')
print(f'crossing status (is the destination wired): {tally("crossing_status_GEN")}')
print(f'shipped reachability (does this call site run): {tally("shipped_reachability_GEN")}')
print(f'targets: ' + '  '.join(f'{k} {sum(1 for r in out if r["target_node_GEN"]==k)}'
                                for k in sorted({r["target_node_GEN"] for r in out})))
