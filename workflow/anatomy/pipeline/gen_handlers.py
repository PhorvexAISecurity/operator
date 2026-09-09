#!/usr/bin/env python3
import paths
"""Emit one node row per literal HandlerRegistry registration. Generated, never authored."""
import re, os, csv, sys
SRC = str(paths.MODULE_PATH / 'internal' / 'actuator') + '/'
files = ['handlers_k8s.go', 'handlers_ai.go', 'handlers_ai_p4set.go']

# type -> (file, line of its Name(), the model.Action constant)
decl = {}
for f in files:
    for i, line in enumerate(open(SRC + f), 1):
        m = re.match(r'func \((\w+)\) Name\(\) string \{ return string\(model\.(\w+)\) \}', line.strip())
        if m: decl[m.group(1)] = (f, i, m.group(2))

# only types actually passed to HandlerRegistry.Register are real nodes
registered = []
for f in files:
    for line in open(SRC + f):
        m = re.search(r'HandlerRegistry\.Register\((\w+)\{\}\)', line)
        if m: registered.append(m.group(1))

# MutatingActions decides generatable vs declared-only
mut = open(paths.MODULE_PATH / 'internal/model/types.go').read()
block = re.search(r'var MutatingActions = \[\]Action\{(.*?)\n\}', mut, re.S).group(1)
generatable = set(re.findall(r'\bAction[A-Z]\w*', re.sub(r'//.*', '', block)))

# action string + mutation kind, read from the handler body
rows = []
for t in registered:
    f, ln, const = decl[t]
    body = open(SRC + f).read()
    act = re.search(rf'{const}\s+Action = "([^"]+)"', mut)
    kind = re.search(rf'func \({t}\) MutationKind\(\) string \{{ return "([^"]+)"', body)
    gen = const in generatable
    rows.append(dict(
        id=f'actuator.native.{act.group(1) if act else const}',
        lane='Actuation',
        display=f'{act.group(1) if act else const} handler',
        packages_or_files=f'internal/actuator/{f}',
        loc='-',
        runtime_role='production' if gen else 'unwired',
        engine_scope='BOTH',
        deployment_mode='optional-native|optional-hybrid' if gen else 'none',
        source_anchor=f'internal/actuator/{f}:{ln}',
        evidence_note=f'{t}; {"in" if gen else "NOT in"} model.MutatingActions'
                      + (f'; MutationKind={kind.group(1)}' if kind else ''),
        parent='actuator.native.handlers'))

print(f'registered handlers: {len(rows)}  generatable: {sum(1 for r in rows if r["runtime_role"]=="production")}'
      f'  declared-only: {sum(1 for r in rows if r["runtime_role"]=="unwired")}')
assert len(rows) == 16, f'expected 16 registrations, found {len(rows)}'
assert sum(1 for r in rows if r['runtime_role'] == 'production') == 15, 'expected 15 generatable'

# splice into NODES.tsv, replacing any previous generated handler rows
existing = list(csv.DictReader(open('NODES.tsv'), delimiter='\t'))
hdr = list(existing[0].keys())
keep = [r for r in existing if r['parent'] != 'actuator.native.handlers']
out = keep + [{k: r.get(k, '') for k in hdr} for r in rows]
with open('NODES.tsv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=hdr, delimiter='\t'); w.writeheader(); w.writerows(out)
for r in rows: print(f"  {r['id']:44} {r['source_anchor']:42} {r['runtime_role']}/{r['deployment_mode']}")
