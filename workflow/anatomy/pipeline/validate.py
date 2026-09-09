#!/usr/bin/env python3
"""Validate the anatomy inventories. Every check FAILS loudly; nothing is skipped.

Written because build_diagram.py silently skipped unknown relation endpoints and unknown
seam targets, which meant a wrong id rendered as an absent edge instead of an error.
"""
import csv, os, sys, json, collections, re
from findings import Findings
import paths

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = paths.MODULE_STR
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n)), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
bounds = load('INTENTIONAL_BOUNDARIES.tsv')
pkgs = set(json.load(open(os.path.join(HERE, 'packages.json'))).keys())

F = Findings('validate')
def check(cond, code, msg):
    F.check(cond, code, msg)

LANES = {'Foundation','Bootstrap','Orchestration','Sensing','Assembly','Pricing','Choice',
         'Actuation','Observation','Record','Console','Tools',
         # widened surface (bus 202): the shipped SPA, the composed image, and the boundaries
         # where our code crosses into systems we do not own.
         'Product','Delivery','External'}
ROLES  = {'production','shadow','benchmark','observe-only','foundation','tool','unwired','external'}
ENGINE = {'P1','P0','BOTH','NONE'}
MODES  = {'default','optional-native','optional-hybrid','all','none'}
def modes_ok(v):   # set-valued: 'default|optional-hybrid'
    return v and all(p in MODES for p in v.split('|'))
ROLES_REL = ROLES | {'infrastructure'}
# K3 205: a named external system is not automatically a reachable one. Every crossing declares
# which of three classes it is, so conditional dead code cannot look like a runtime crossing.
CROSSING = {'implemented', 'declared-unwired', 'absent-stub', '-'}

def canonical(who, field, value):
    """Every anchor field must START with a repo-relative path:line, and every further
    path:line in it must resolve. Prose is allowed only after an em dash."""
    prose, missing, past = CODEMAP[field]
    if not value:
        F.add(prose, f'{who}: empty {field}'); return
    m = re.match(ANCHOR_PAT, value)
    if not m:
        F.add(prose, f'{who}: {field} does not START with a canonical path:line ({value[:60]!r})'); return
    for p, ln in re.findall(ANCHOR_PAT[1:], value):
        if not paths.exists(p):
            F.add(missing, f'{who}: {field} anchor file missing: {p}'); continue
        total = len(paths.lines(p))
        if int(ln) > total:
            F.add(past, f'{who}: {field} line {ln} past end of {p} ({total})')

# which diagnostic each anchor-bearing field reports under
CODEMAP = {'anchor':            ('REL_ANCHOR_NONCANONICAL','REL_ANCHOR_FILE_MISSING','REL_ANCHOR_LINE_PAST_EOF'),
           'contract_evidence': ('SEAM_EVIDENCE_PROSE','SEAM_EVIDENCE_PROSE','SEAM_EVIDENCE_PROSE'),
           'negative_evidence': ('SEAM_EVIDENCE_PROSE','SEAM_EVIDENCE_PROSE','SEAM_EVIDENCE_PROSE')}
# anchors now span Go, YAML, TypeScript and the Dockerfile
ANCHOR_PAT = r'^([A-Za-z0-9_./-]+\.(?:go|yaml|yml|ts|tsx|Dockerfile|mod|json)):(\d+)'
STATUS = {'gap','gap-unscoped'}
SPLIT = {'actuator','console','cost','decision','runner','slo'}

ids = [n['id'] for n in nodes]
dupes = [k for k,v in collections.Counter(ids).items() if v > 1]
check(not dupes, 'NODE_ID_DUPLICATE', f'duplicate node ids: {dupes}')
idset = set(ids)

# parents exist, no cycles
for n in nodes:
    if n['parent']:
        check(n['parent'] in idset, 'NODE_PARENT_MISSING', f'{n["id"]}: parent {n["parent"]!r} does not exist')
seen = {}
for n in nodes:
    path, cur = [], n['id']
    while cur and cur in idset:
        if cur in path: F.add('NODE_PARENT_CYCLE', f'parent cycle: {path + [cur]}'); break
        path.append(cur)
        cur = {x['id']: x['parent'] for x in nodes}.get(cur)

# closed vocabularies
for n in nodes:
    check(n['lane'] in LANES, 'NODE_LANE_BAD', f'{n["id"]}: lane {n["lane"]!r} not allowed')
    check(n['runtime_role'] in ROLES, 'NODE_ROLE_BAD', f'{n["id"]}: runtime_role {n["runtime_role"]!r} not allowed')
    check(n['engine_scope'] in ENGINE, 'NODE_ENGINE_BAD', f'{n["id"]}: engine_scope {n["engine_scope"]!r} not allowed')
    check(modes_ok(n['deployment_mode']), 'NODE_MODE_BAD', f'{n["id"]}: deployment_mode {n["deployment_mode"]!r} not allowed')

# STRICT anchors. A displayed node is one with no children — a container may name a
# representative file. Directory anchors and bare-file anchors used to pass silently.
has_children = {n['parent'] for n in nodes if n['parent']}
def resolve(who, a, need_line):
    if not a: F.add('NODE_ANCHOR_MISSING', f'{who}: empty source_anchor'); return
    if a.endswith('/'):
        check(not need_line, 'NODE_ANCHOR_NO_LINE', f'{who}: directory anchor {a!r} where path:line is required')
        check(os.path.isdir(paths.full(a)), 'NODE_ANCHOR_MISSING', f'{who}: anchor directory missing: {a}')
        return
    f, _, ln = a.partition(':')
    check(paths.exists(f), 'NODE_ANCHOR_MISSING', f'{who}: anchor file missing: {f}')
    # .yaml/.md contracts carry a line like source does; only the extension differs
    check(bool(ln) or not need_line, 'NODE_ANCHOR_NO_LINE', f'{who}: anchor {a!r} has no :line')
    if ln and paths.exists(f):
        total = len(paths.lines(f))
        check(int(ln) <= total, 'NODE_ANCHOR_MISSING', f'{who}: anchor line {ln} past end of {f} ({total})')

for n in nodes:
    resolve(n['id'], n['source_anchor'], need_line=n['id'] not in has_children)

# relation endpoints must exist — FAIL, never skip
relkeys = collections.Counter()
for r in rels:
    check(r['from'] in idset, 'REL_ENDPOINT_MISSING', f'relation from-endpoint does not exist: {r["from"]}')
    check(r['to'] in idset, 'REL_ENDPOINT_MISSING', f'relation to-endpoint does not exist: {r["to"]}')
    check(r['engine_scope'] in ENGINE, 'REL_ENGINE_BAD', f'relation {r["from"]}->{r["to"]}: engine_scope not allowed')
    check(modes_ok(r['deployment_mode']), 'REL_MODE_BAD', f'relation {r["from"]}->{r["to"]}: deployment_mode not allowed')
    check(r['runtime_role'] in ROLES_REL, 'REL_ROLE_BAD', f'relation {r["from"]}->{r["to"]}: runtime_role not allowed')
    check(bool(r['anchor']), 'REL_ANCHOR_NONCANONICAL', f'relation {r["from"]}->{r["to"]}: no anchor')
    canonical(f'relation {r["from"]}->{r["to"]}', 'anchor', r['anchor'])
    check(r.get('crossing_status','-') in CROSSING, 'REL_CROSSING_BAD',
          f'relation {r["from"]}->{r["to"]}: crossing_status {r.get("crossing_status")!r} not allowed')
    relkeys[(r['from'], r['to'], r['kind'])] += 1
rd = [k for k,v in relkeys.items() if v > 1]
check(not rd, 'REL_DUPLICATE_KEY', f'duplicate relation keys: {rd}')

# seams must attach to a node that exists
for s in seams:
    tgt = s['attaches_to'].split('->')[0].strip()
    check(tgt in idset, 'SEAM_TARGET_MISSING', f'seam {s["seam"]!r} attaches to unknown node {tgt!r}')
    check(s['status'] in STATUS, 'SEAM_STATUS_BAD', f'seam {s["seam"]!r}: status {s["status"]!r} not allowed')
    canonical(f'seam {s["seam"]!r}', 'contract_evidence', s['contract_evidence'])
    canonical(f'seam {s["seam"]!r}', 'negative_evidence', s['negative_evidence'])

# intentional boundaries: same anchor discipline as seams
for b in bounds:
    tgt = b['attaches_to'].split('->')[0].strip()
    check(tgt in idset, 'BOUNDARY_TARGET_MISSING', f'boundary {b["seam"]!r} attaches to unknown node {tgt!r}')
    check(b['status'].startswith('NOT-A-GAP'),
          'BOUNDARY_STATUS_BAD', f'boundary {b["seam"]!r}: status {b["status"]!r} is not an intentional-boundary status')
    canonical(f'boundary {b["seam"]!r}', 'contract_evidence', b['contract_evidence'])
    canonical(f'boundary {b["seam"]!r}', 'negative_evidence', b['negative_evidence'])

# all 28 packages assigned exactly once, or declared as a split
assigned = collections.Counter()
for n in nodes:
    for tok in n['packages_or_files'].replace('internal/', '').replace('.go', '').split():
        b = tok.split('/')[0].strip(',')
        if b in pkgs: assigned[b] += 1
missing = sorted(pkgs - set(assigned))
undeclared = sorted(k for k,v in assigned.items() if v > 1 and k not in SPLIT)
check(not missing, 'PKG_UNASSIGNED', f'packages assigned to no node: {missing}')
check(not undeclared, 'PKG_MULTI_OWNED', f'packages in multiple nodes without a declared split: {undeclared}')

# A child is SYMBOL-SCOPED when its declared files are a subset of an ancestor's — it lives
# inside a file the ancestor already owns, and is located by a line anchor instead. Such a node
# is exempt from file ownership counting but MUST carry that line anchor.
def files_of(n):
    return {t for t in n['packages_or_files'].split() if t.endswith('.go')}
byid = {n['id']: n for n in nodes}
symbol_scoped = set()
for n in nodes:
    if not n['parent']: continue
    own, anc, cur = files_of(n), set(), byid.get(n['parent'])
    while cur:
        anc |= files_of(cur); cur = byid.get(cur['parent'])
    if own and own <= anc:
        symbol_scoped.add(n['id'])
        check(':' in n['source_anchor'],
              'NODE_SYMBOL_CHILD_NO_LINE', f'{n["id"]}: shares an ancestor\'s file but has no line anchor')
    else:
        # The message always said "neither a line anchor NOR its own files"; the code only
        # tested files. A composed binary (bin.kubectl) owns no source and is legitimately
        # located by a Dockerfile line.
        check(bool(n['packages_or_files'].strip()) or ':' in n['source_anchor'],
              'NODE_CHILD_EMPTY', f'{n["id"]}: child with neither a line anchor nor its own files')

# split packages: every non-test .go file owned exactly once
for p in sorted(SPLIT):
    d = SRC + 'internal/' + p
    if not os.path.isdir(d): continue
    files = {f for f in os.listdir(d) if f.endswith('.go') and not f.endswith('_test.go')}
    owned = collections.Counter()
    for n in nodes:
        if n['id'] in symbol_scoped: continue      # shares its parent's file, by line
        for tok in n['packages_or_files'].split():
            t = tok.strip(',')
            if t.startswith(f'internal/{p}/') and t.endswith('.go'):
                owned[t.split('/')[-1]] += 1
    unowned = sorted(files - set(owned))
    twice = sorted(k for k,v in owned.items() if v > 1)
    check(not unowned, 'SPLIT_FILE_UNOWNED', f'split {p}: files owned by no node: {unowned}')
    check(not twice, 'SPLIT_FILE_MULTI_OWNED', f'split {p}: files owned by more than one node: {twice}')

# expected shape
top = [n for n in nodes if not n['parent']]
handlers = [n for n in nodes if n['parent'] == 'actuator.native.handlers']
check(len(handlers) == 16, 'SHAPE_HANDLER_COUNT', f'expected 16 handler rows, found {len(handlers)}')
check(sum(1 for h in handlers if 'optional-native' in h['deployment_mode']
             and h['runtime_role'] == 'production') == 15,
      'SHAPE_GENERATABLE_COUNT', 'expected 15 generatable handlers')
check(len(symbol_scoped) == 22,
      'SHAPE_SYMBOL_SCOPED_COUNT', f'expected 22 symbol-scoped children, found {len(symbol_scoped)} — a path-form mismatch '
      f'between a generated row and its ancestor silently drops them')

# --- semantic invariants: things a shape check passes but that are false ---
check(all('optional-native' in h['deployment_mode'] and 'optional-hybrid' in h['deployment_mode']
          for h in handlers if h['runtime_role'] == 'production'),
      'SEM_HANDLER_MODES', 'every generatable handler must be reachable in BOTH native and hybrid modes')
relset = {(r['from'], r['to']) for r in rels}
for need in [('cmd.main','decision.coverage'), ('cmd.main','decision.p0'),
             ('runner.assembly','decision.coverage'), ('runner.assembly','decision.p0')]:
    check(need in relset, 'SEM_ENGINE_WIRING', f'missing engine wiring/invocation edge: {need[0]} -> {need[1]}')
ig = [r for r in rels if (r['from'], r['to']) == ('ingest','graph')]
check(ig and ig[0]['engine_scope'] == 'BOTH' and ig[0]['runtime_role'] == 'production',
      'SEM_INGEST_GRAPH', 'ingest -> graph is a production BOTH-engine call, not infrastructure/NONE')
# --- CRD vocabulary vs the actuator registry ---
# v0.4.59-64 restored the full action vocabulary to the CRD enum, closing the old
# "12 CRD values vs 15 generatable" gap. Pin the RELATION, not the number: the enum must be
# exactly the registered handlers plus `noop`, which has no handler. A future narrowing of the
# enum (the defect that was just fixed) then fails here instead of ageing silently in prose.
_t = open(SRC + 'api/v1alpha1/phorvexpolicy_types.go').read()
_enum = set(next(x for x in re.findall(r'Enum=([^\s]+)', _t) if 'rotate' in x).split(';'))
_hand = {h['id'].split('.')[-1] for h in handlers}
check(_enum - _hand == {'noop'}, 'CRD_VOCAB_EXTRA',
      f'CRD enum has values with no handler beyond noop: {sorted(_enum - _hand - {"noop"})}')
check(not (_hand - _enum), 'CRD_VOCAB_MISSING',
      f'handlers absent from the CRD enum (a policy cannot request them): {sorted(_hand - _enum)}')

import csv as _csv
mcols = set(_csv.DictReader(open(os.path.join(HERE,'EFFECT_MATRIX.tsv'), newline=''), delimiter='\t').fieldnames or [])
for need in ('target_resource_operation_GEN','write_command_ack_GEN','protocol_effect_ack_CURATED',
             'availability_recovery_observation','runner_ledger_outcome',
             'security_goal_confirmation_CURATED','missing_confirmation_CURATED'):
    check(need in mcols, 'MATRIX_COLUMN_MISSING', f'effect matrix missing required column: {need}')

print(f'nodes {len(nodes)} ({len(top)} top-level, {len(nodes)-len(top)} children, {len(handlers)} handlers)')
print(f'relations {len(rels)}   seams {len(seams)}   boundaries {len(bounds)}   symbol-scoped children {len(symbol_scoped)}')
F.report('every shape, vocabulary, ownership and semantic invariant holds')
