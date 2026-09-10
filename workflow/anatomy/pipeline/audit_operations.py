#!/usr/bin/env python3
"""Invariants over the normalized operation matrix.

The compound cell could not be wrong in a checkable way — `pod/Create Get Update` had no place
to be inconsistent. Rows can, so these are the checks the old shape could not carry.
"""
import csv, os, re
from findings import Findings
import paths

F = Findings('audit_operations')
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
mx, nodes = load('OPERATION_MATRIX.tsv'), {n['id']: n for n in load('NODES.tsv')}
cur = load('OPERATIONS_CURATED.tsv')

MUTATING = {'Create', 'Update', 'Delete', 'Patch'}
for r in mx:
    a = r['source_anchor_GEN']
    if r['target_resource_GEN'] == 'UNKNOWN':
        F.add('OP_TARGET_UNKNOWN', f'{r["action_GEN"]} {a}: target unresolved and not curated')
    # a declared-only row targets nothing by definition — that is the finding, not an error
    if r['target_node_GEN'] == '-' and r['operation_GEN'] == 'none': pass
    elif r['target_node_GEN'] not in nodes:
        F.add('OP_TARGET_NOT_A_NODE', f'{r["action_GEN"]} {a}: {r["target_node_GEN"]} is not a node')
    # every generated anchor must resolve AND still be the operation it claims
    m = re.match(r'^([A-Za-z0-9_./-]+\.go):(\d+)$', a)
    if not m:
        F.add('OP_ANCHOR_BAD', f'{r["action_GEN"]}: anchor {a!r} is not a path:line'); continue
    line = paths.line_at(m.group(1), int(m.group(2)))
    if line is None:
        F.add('OP_ANCHOR_BAD', f'{r["action_GEN"]}: {a} does not resolve'); continue
    # A dispatch row's verb is synthetic (`routes-to`); what its anchor must show is the call that
    # performs the routing. A declared-only row has no operation to find.
    if r['operation_GEN'] == 'routes-to':
        if not ('.Actuate(' in line or '.EnsurePolicy(' in line):
            F.add('OP_ANCHOR_BAD', f'{r["action_GEN"]} {a}: dispatch anchor shows no route call: {line[:60]}')
    elif r['operation_GEN'] == 'none':
        if 'Emitted: false' not in line and 'Emitted:false' not in line:
            F.add('OP_ANCHOR_BAD', f'{r["action_GEN"]} {a}: declared-only anchor does not show Emitted:false')
    elif r['operation_GEN'] not in line:
        F.add('OP_ANCHOR_BAD',
              f'{r["action_GEN"]} {a}: line does not contain {r["operation_GEN"]}: {line[:60]}')
    # a curated cell must carry its own anchor
    if r['acknowledgement_level_CURATED'] != 'NOT-YET-CURATED' and r['curation_anchor_CURATED'] == '-':
        F.add('OP_CURATION_UNANCHORED',
              f'{r["action_GEN"]} {a}: curated cells with no curation anchor')

# An operation against a declared-unwired target must not be described as a working effect.
for r in mx:
    if r['crossing_status_GEN'] == 'implemented' and \
       nodes.get(r['target_node_GEN'], {}).get('runtime_role') == 'unwired':
        F.add('OP_STATUS_CONTRADICTS',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: implemented against an unwired target')
    # K3 207: the destination being wired says nothing about this call site running. A row that
    # cannot execute must not carry effect claims — that is how mig-rebind's Pod.Delete came to
    # read `implemented` + `OutcomeEmitted` while my own note on the same row said unreachable.
    if r['shipped_reachability_GEN'] != 'reachable':
        for col in ('acknowledgement_level','postcondition_readback',
                    'availability_recovery_observation','security_goal_confirmation',
                    'runner_ledger_outcome'):
            v = r[col + '_CURATED']
            if v == 'NOT-YET-CURATED':
                F.add('OP_UNREACHED_IN_BACKLOG',
                      f'{r["action_GEN"]} {r["source_anchor_GEN"]}: {col} is NOT-YET-CURATED on an '
                      f'unreached row — there is no effect to curate, it is done')
                continue
            if v not in ('n/a — not reached in the shipped binary', 'n/a', '-'):
                F.add('OP_EFFECT_ON_UNREACHED',
                      f'{r["action_GEN"]} {r["source_anchor_GEN"]}: {col} claims {v[:40]!r} '
                      f'on a {r["shipped_reachability_GEN"]} row')
        if r['unreached_because_GEN'] in ('', '-'):
            F.add('OP_UNREACHED_UNEXPLAINED',
                  f'{r["action_GEN"]} {r["source_anchor_GEN"]}: {r["shipped_reachability_GEN"]} with no stated guard')
    # a reach condition must be a condition, not a raw preceding statement
    rc = r['reach_condition_GEN']
    if rc != '-' and ('ctx,' in rc or rc.rstrip().endswith(';')):
        F.add('OP_REACH_NOT_A_CONDITION',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: reach_condition {rc[:50]!r} is a statement, not a condition')

# Curated rows must correspond to a real generated operation — a curation for an operation that
# does not exist is the compound cell's failure mode returning by another door.
gen_keys = {(r['action_GEN'], r['source_anchor_GEN'], r['operation_GEN']) for r in mx}
for c in cur:
    if (c['action'], c['anchor'], c['verb']) not in gen_keys:
        F.add('OP_CURATION_ORPHAN',
              f'curated {c["action"]} {c["verb"]} @ {c["anchor"]} matches no generated operation')

# K3 208: the guarded-unreached rule must stay DERIVED. Re-derive the unwired accessor set here,
# independently of the generator, and require every guarded-unreached row to name a guard that
# calls one of them. If ext.mig_agent ever becomes wired, these rows stop being justified and
# this fails — instead of a hardcoded name silently keeping them unreached forever.
rels_ = load('RELATIONS.tsv')
unwired = {n for n, v in nodes.items() if v['runtime_role'] == 'unwired'}
unwired |= {r['to'] for r in rels_ if r.get('crossing_status') == 'declared-unwired'}
CTL_ACCESSOR = {'ext.vllm': 'vllm', 'ext.guardrail': 'guardrail',
                'ext.kv_local': 'kvxfer', 'ext.mig_agent': 'mig'}
guards = {f'ec.{CTL_ACCESSOR[t]}()' for t in unwired if t in CTL_ACCESSOR}
for r in mx:
    if r['shipped_reachability_GEN'] == 'reachable':
        for col in ('acknowledgement_level','postcondition_readback','security_goal_confirmation',
                    'runner_ledger_outcome'):
            if 'not reached in the shipped binary' in r[col + '_CURATED']:
                F.add('OP_REACHED_CLAIMS_NA',
                      f'{r["action_GEN"]} {r["source_anchor_GEN"]}: {col} says not-reached on a reachable row')
        continue
    # Two distinct unreachable mechanisms, and only the first is guard-based:
    #   guarded-unreached  a dominating guard calls a declared-unwired target
    #   tool-only          the entry point is invoked only from a one-shot tool branch
    if r['shipped_reachability_GEN'] == 'tool-only':
        if 'nativedemo' not in r['unreached_because_GEN']:
            F.add('OP_UNREACHED_NOT_DERIVED',
                  f'{r["action_GEN"]} {r["source_anchor_GEN"]}: tool-only without naming the tool caller')
        continue
    why = r['unreached_because_GEN']
    if why not in ('', '-') and not any(g in why for g in guards):
        F.add('OP_UNREACHED_NOT_DERIVED',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: guarded-unreached by {why[:50]!r}, '
              f'which calls no currently-unwired target {sorted(guards)}')

# K3 210: availability/recovery is a CLOSED token vocabulary. `CONDITIONALLY OBSERVED` is allowed
# only where a later independent read exists in shipped code; `observed` requires the observation
# to ALWAYS run, which no row satisfies today. The conditions belong in notes — 61 rows have to
# stay readable, and a paragraph in a cell is how a vocabulary quietly stops being one.
# K3 211: the ledger was derived from selectionBound(action).Status — an ACTION property — while
# success-vs-compensation is a BRANCH property. A compensation write runs only when the handler is
# about to return an error, and manager.go:1070 then records OutcomeFailed, so it can never carry
# OutcomeCompleted or OutcomeEmitted however the action is classified.
for r in mx:
    if r['path_class_GEN'] != 'compensation' or r['operation_GEN'] in ('Get', 'List'): continue
    # the LEADING token is the claim; the rest is explanation that may legitimately name the
    # outcomes it is ruling out
    led = r['runner_ledger_outcome_CURATED']
    if led.split()[0] in ('OutcomeCompleted', 'OutcomeEmitted'):
        F.add('OP_COMPENSATION_LEDGER',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: compensation path claims {led[:40]!r}; '
              f'the handler returns an error and the runner records OutcomeFailed')

# A discarded error cannot claim acceptance on ANY path, not only a compensation one:
# `_ = ec.Client.Update(...)` makes failure indistinguishable from success at the call site.
for r in mx:
    if r['error_handling_GEN'] == 'DISCARDED' and r['operation_GEN'] not in ('Get', 'List') \
       and r['acknowledgement_level_CURATED'].startswith('API accepted'):
        F.add('OP_DISCARDED_ERROR_ACK',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: ack claims API accepted but the error is discarded')

# The surface a row belongs to is decided by the file its anchor is in, not by a label. A native
# handler row cannot become a hybrid route row by relabelling — the routing happens in hybrid.go.
# A compensation row must actually undo a prior failed MUTATION. Re-derive that from source:
# the enclosing error branch's failed operation must not be a read.
import re as _re2
for r in mx:
    if r['path_class_GEN'] != 'compensation': continue
    # an INHERITED classification is not re-derivable from the helper's own body — the helper
    # reads then writes like any success path; what makes it compensation is who calls it
    if r['path_class_reason_GEN'].startswith('call site'): continue
    m_ = _re2.match(r'^([A-Za-z0-9_./-]+\.go):(\d+)$', r['source_anchor_GEN'])
    if not m_: continue
    ls = paths.lines(m_.group(1)) or []
    n_ = int(m_.group(2))
    # find the NEAREST error assignment above the call site — a fixed window missed
    # phoenix.go:93, whose failed Get is 17 lines up
    failed = ''
    for j in range(n_ - 2, max(n_ - 30, -1), -1):
        if _re2.search(r'\b\w*[Ee]rr\w*\s*:?=\s*[\w.]*\.\w+\(', ls[j]):
            failed = ls[j]; break
    if _re2.search(r'\.(Get|List)\(', failed) and not _re2.search(r'\.(Create|Update|Delete|Patch)\(', failed):
        F.add('OP_COMPENSATION_NOT_UNDO',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: labelled compensation but the failed '
              f'operation above it is a READ — a fallback path, not an undo')

SURFACE_FILE = {'hybrid': 'hybrid.go', 'phoenix': 'phoenix.go'}
for r in mx:
    want = SURFACE_FILE.get(r['surface_GEN'])
    if want and want not in r['source_anchor_GEN']:
        F.add('OP_SURFACE_MISMATCH',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: labelled surface {r["surface_GEN"]} but the '
              f'anchor is not in {want}')
    # Phorvex writes a CR and a controller it does not own produces the effect; nothing here can
    # confirm the security goal, however the row is curated.
    if r['surface_GEN'] == 'phoenix' and r['operation_GEN'] in ('Create', 'Update') \
       and 'NOT CONFIRMED' not in r['security_goal_confirmation_CURATED']:
        F.add('OP_PHOENIX_CONFIRMS',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: a Phoenix CR write cannot confirm a security goal')

AVAIL = {'n/a', 'none', 'CONDITIONALLY OBSERVED', 'observed'}
for r in mx:
    v = r['availability_recovery_observation_CURATED']
    if v == 'NOT-YET-CURATED': continue
    if v.startswith('n/a'): continue                      # n/a may carry a short reason
    tok = v.split('—')[0].strip()
    if tok not in AVAIL:
        F.add('OP_AVAIL_TOKEN_BAD',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: availability {tok[:40]!r} is not one of {sorted(AVAIL)}')
    elif len(v) > 160:
        F.add('OP_AVAIL_TOKEN_BAD',
              f'{r["action_GEN"]} {r["source_anchor_GEN"]}: availability cell is {len(v)} chars — '
              f'token plus a one-line pointer only; conditions belong in notes')

done = sum(1 for r in mx if r['acknowledgement_level_CURATED'] != 'NOT-YET-CURATED')
print(f'operation rows {len(mx)}   curated {done}   awaiting curation {len(mx)-done}')
print(f'mutating operations: {sum(1 for r in mx if r["operation_GEN"] in MUTATING)}   '
      f'reads: {sum(1 for r in mx if r["operation_GEN"] not in MUTATING)}')
F.report('every operation resolves to real source and no curation outruns a generated row')
