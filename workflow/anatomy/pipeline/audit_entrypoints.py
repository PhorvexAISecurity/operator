#!/usr/bin/env python3
import paths
"""Completeness pass over cmd/* — the class audit_completeness.py excludes.

Entrypoints wire the product together, so an undrawn cmd/* edge hides how the thing is
assembled. Same rule: a call present in source and absent from RELATIONS.tsv is a finding.
"""
import csv, os, re, json, collections, sys
from symbol_owner import owner_of
from findings import Findings
F = Findings('audit_entrypoints')
SRC=paths.MODULE_STR; HERE=os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE,n), newline=''), delimiter='\t'))
nodes, rels = load('NODES.tsv'), load('RELATIONS.tsv')
pkgs = set(json.load(open(os.path.join(HERE,'packages.json'))).keys())
owner = {}
for n in nodes:
    for t in n['packages_or_files'].split():
        if t.startswith('internal/'): owner.setdefault('/'.join(t.strip(',').split('/')[:2]), n['id'])
parent = {n['id']: n['parent'] for n in nodes}
kids = collections.defaultdict(list)
for n in nodes:
    if n['parent']: kids[n['parent']].append(n['id'])
def family(x):
    out, st = set(), [x]
    while st:
        c = st.pop()
        if c in out: continue
        out.add(c); st += kids.get(c, [])
    a = x
    while parent.get(a): a = parent[a]; out.add(a)
    return out
drawn = {(r['from'], r['to']) for r in rels}

found = collections.defaultdict(list)
for root, _, files in os.walk(SRC + 'cmd'):
    for f in files:
        if not f.endswith('.go') or f.endswith('_test.go'): continue
        rel = os.path.join(root, f).replace(SRC, '')
        for i, l in enumerate(open(os.path.join(root, f), errors='ignore'), 1):
            st = l.strip()
            if st.startswith(('//','*','/*')): continue
            code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', st)
            for callee in pkgs:
                if callee in ('model','registry'): continue
                m = re.search(rf'\b{callee}\.([A-Z]\w*)\s*\(', code)
                if m:
                    dst, _hit = owner_of(callee, m.group(1))
                    if not dst: continue
                    # attribute to the binary that actually contains the call
                    src = ('cmd.main' if rel in ('cmd/main.go','cmd/nativedemo.go')
                           else {'cmd/console/main.go':'cmd.console','cmd/redteam-rl/main.go':'cmd.redteam',
                                 'cmd/p4b-soak/main.go':'cmd.p4b_soak','cmd/calib-soak/main.go':'cmd.calib_soak',
                                 'cmd/p3deep/main.go':'cmd.p3deep','cmd/p3report/main.go':'cmd.p3report',
                                 'cmd/pendingcheck/main.go':'cmd.pendingcheck'}.get(rel))
                    if not src: continue
                    if any((src, b) in drawn for b in family(dst)): continue
                    found[(src,dst)].append(f'{rel}:{i}  {st[:66]}')

print(f'cmd/* entrypoint completeness — {sum(len(v) for v in found.values())} call sites unattributed')
for (src, dst), hits in sorted(found.items(), key=lambda x: -len(x[1])):
    # An edge that exists but points at a node which does NOT define the symbol is a different
    # defect from one that is absent entirely; the mutations distinguish them by code.
    code = ('ENTRY_EDGE_WRONG_TARGET' if any(r['from'] == src for r in
            csv.DictReader(open(os.path.join(HERE,'RELATIONS.tsv'), newline=''), delimiter='\t'))
            else 'ENTRY_EDGE_MISSING')
    F.add(code, f'{src} -> {dst}  ({len(hits)} call site{"s" if len(hits)>1 else ""}) e.g. {hits[0]}')
F.report('every cmd/* -> internal call is represented')
