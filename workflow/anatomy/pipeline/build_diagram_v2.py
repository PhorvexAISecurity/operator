#!/usr/bin/env python3
"""Generate the anatomy diagram from the frozen inventories.

K3 230: a diagram is allowed only if it is generated the way the document is. The old
ANATOMY_V2.mmd / .svg are stale (77-node era) and must not be revived by hand.

Mermaid is unforgiving about label content — earlier attempts failed on curly braces in file globs
and on `~~~`. Every label here is sanitised, and the emitted file is checked for the characters
that broke it before.
"""
import paths
import csv, os, re, json

HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
pin = json.load(open(os.path.join(HERE, 'SOURCE_PIN.json')))
by = {n['id']: n for n in nodes}

# Mermaid reserves these as statement keywords; a node whose id is one of them is a PARSE ERROR,
# not a cosmetic issue. `graph` (the cluster-graph node) took the whole diagram down and neither of
# us saw it, because the .mmd was checked as text and never once rendered by mermaid.
MERMAID_RESERVED = {'graph', 'subgraph', 'end', 'style', 'linkstyle', 'classdef', 'class', 'click',
                    'flowchart', 'direction', 'default', 'call', 'href', 'link', 'callback',
                    'o', 'x', 'v'}
def nid(i):
    s = re.sub(r'[^A-Za-z0-9]', '_', i)
    return s + '_n' if s.lower() in MERMAID_RESERVED else s
def lab(t):
    """Mermaid breaks on braces, quotes, pipes and angle brackets inside a label."""
    t = re.sub(r'[{}|"<>()\[\]]', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()

LANES = ['Bootstrap','Orchestration','Sensing','Assembly','Pricing','Choice','Actuation',
         'Observation','Record','Foundation','Console','Product','Delivery','Tools','External']
# the diagram shows top-level nodes; children are in the document, and 99 boxes is not a map
top = [n for n in nodes if not n['parent']]
shown = {n['id'] for n in top}
# K3 231: the legend claims a bold border means the node carries a seam, but attachments were not
# lifted — runner.feedback's seam left `runner` unmarked, and slo.ledger (the other end of
# ledger-to-selection) was unmarked entirely. Lift BOTH endpoints through the same collapse the
# edges use, so the legend is true rather than approximately true.
def _up_raw(i, byn):
    while i in byn and byn[i]['parent']: i = byn[i]['parent']
    return i
seam_targets = set()
for sm in seams:
    for endpoint in sm['attaches_to'].split('->'):
        e = endpoint.strip()
        if e: seam_targets.add(_up_raw(e, by))

L = []
# no %%{init}%% directive: it is the only thing in the file that would contain braces, and the
# guard below is worth more than the curve style.
L.append('flowchart LR')
for lane in LANES:
    ln = [n for n in top if n['lane'] == lane]
    if not ln: continue
    L.append(f'  subgraph {nid(lane)}["{lab(lane)}"]')
    for n in sorted(ln, key=lambda x: x['id']):
        shape = ('([%s])' if n['lane'] == 'External' else
                 '[/%s/]' if n['runtime_role'] == 'tool' else
                 '[%s]')
        L.append(f'    {nid(n["id"])}{shape % lab(n["display"])}')
    L.append('  end')

# collapse child->parent edges to the parent, and drop self-loops the collapse creates
def up(i):
    while i in by and by[i]['parent']: i = by[i]['parent']
    return i
seen = set()
for r in rels:
    a, b = up(r['from']), up(r['to'])
    if a not in shown or b not in shown or a == b: continue
    style = ('-.->' if (r['runtime_role'] in ('tool', 'benchmark', 'unwired')
                        or r.get('crossing_status') == 'declared-unwired'
                        or by.get(r['to'], {}).get('runtime_role') == 'unwired')
             else '==>' if r.get('crossing_status') == 'implemented' and b.startswith('ext.')
             else '-->')
    k = (a, b, style)
    if k in seen: continue
    seen.add(k)
    L.append(f'  {nid(a)} {style} {nid(b)}')

L.append('  classDef unwired stroke-dasharray: 4 3;')
L.append('  classDef gap stroke-width:3px;')
unw = [n['id'] for n in top if n['runtime_role'] == 'unwired']
gap = [t for t in seam_targets if t in shown]
if unw: L.append('  class ' + ','.join(nid(i) for i in unw) + ' unwired;')
if gap: L.append('  class ' + ','.join(nid(i) for i in sorted(set(gap))) + ' gap;')

out = '\n'.join(L) + '\n'
bad = [c for c in ('{', '}', '~~~') if c in out]
assert not bad, f'characters that broke earlier renders are present: {bad}'
# The character check above was the ONLY render guard, and it passed on a file mermaid could not
# parse: `graph` as a node id is a parse error, not a bad character. Assert on the emitted ids so
# the reserved-word class cannot come back on a machine with no docker to run a real render.
_emitted = set(re.findall(r'^\s{4}([A-Za-z_][A-Za-z0-9_]*)', out, re.M))
_reserved = sorted(i for i in _emitted if i.lower() in MERMAID_RESERVED)
assert not _reserved, f'node ids mermaid reserves as keywords; the diagram will not parse: {_reserved}'
paths.GENERATED_DIR.mkdir(parents=True, exist_ok=True)
out_path = paths.MMD_PATH
open(out_path, 'w').write(out)
print(f'{out_path.name} · {len(top)} nodes in {len(set(n["lane"] for n in top))} lanes · '
      f'{len(seen)} edges · pin {pin["commit"]}')
print(f'dashed = tool/unwired · thick = crossing into a system Phorvex does not own · '
      f'bold border = carries a seam')
