#!/usr/bin/env python3
"""Every process the code execs must be a drawn node, and every drawn binary must be in the image.

A Go call graph cannot see these edges: the console's live scan runs the OPERATOR BINARY as a
subprocess, the catalogue runs the harness, and firing an attack shells out to kubectl. Widening
the anatomy to the console image is what made them visible — and immediately showed two exec
paths whose binary the image never installs.

Nothing here is guessed. A target the regex cannot resolve is reported as UNKNOWN and must be
curated with a reason, exactly like the effect matrix.
"""
import csv, os, re, sys
from findings import Findings
import paths

F = Findings('audit_exec_boundaries')
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = paths.MODULE
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
by = {n['id']: n for n in nodes}
drawn = {(r['from'], r['to']) for r in rels}

# How an exec target expression resolves to a node. Field selectors and literals are mechanical;
# a bare identifier needs the function that produced it, which is stated, not assumed.
FIELD = {'HarnessBin': 'bin.harness', 'PhorvexBin': 'bin.phorvex_cli'}
LITERAL = {'kubectl': 'bin.kubectl', 'go': 'bin.go_toolchain'}
CURATED = {
 ('internal/console/redteam.go', 'bin'):
   ('bin.redteam_rl', 'the parameter of rtRunJob/rtRunCont, assigned from rtBinary() at redteam.go:60 '
                      'which joins <root>/phorvex/bin/redteam-rl'),
 ('internal/epssfeed/sync.go', 's.Path'):
   ('bin.trivy', 'the Scanner.Path field, defaulted to "/trivy" at sync.go:394 and settable '
                 'via --epss-feed-trivy'),
 ('internal/console/subsystems.go', 'bin'):
   ('bin.phorvex_cli', 'execText\'s bin parameter; DefaultConfig sets PhorvexBin to '
                       '<root>/phorvex/bin/phorvex.exe at config.go:28'),
}

# which node owns each source file. A node that claims a WHOLE package (bare `internal/epssfeed`)
# owns every file in it — the same blind spot that made symbol_owner resolve nothing for unsplit
# packages, and it silently hid the Trivy exec site here too.
file_owner, pkg_owner = {}, {}
for n in nodes:
    for t in n['packages_or_files'].split():
        t = t.strip(',')
        if t.endswith('.go'): file_owner.setdefault(t, n['id'])
        elif t.startswith('internal/') and t.count('/') == 1:
            pkg_owner.setdefault(t.split('/')[1], n['id'])

def owner_of_file(rel):
    if rel in file_owner: return file_owner[rel]
    parts = rel.split('/')
    return pkg_owner.get(parts[1]) if len(parts) > 2 and parts[0] == 'internal' else None

EXEC = re.compile(r'exec\.Command(?:Context)?\(\s*[\w.]+\s*,\s*([^,)]+)')
sites = 0
for root, _, files in os.walk(SRC + 'internal'):
    for fn in sorted(files):
        if not fn.endswith('.go') or fn.endswith('_test.go'): continue
        rel = os.path.join(root, fn).replace(SRC, '')
        for i, line in enumerate(open(os.path.join(root, fn), errors='ignore'), 1):
            m = EXEC.search(line)
            if not m: continue
            sites += 1
            expr, owner = m.group(1).strip(), owner_of_file(rel)
            lit = re.fullmatch(r'"([^"]+)"', expr)
            if lit:                       tgt = LITERAL.get(lit.group(1))
            elif '.' in expr:             tgt = (FIELD.get(expr.rsplit('.', 1)[1])
                                                 or (CURATED.get((rel, expr)) or (None,))[0])
            else:                         tgt = (CURATED.get((rel, expr)) or (None,))[0]
            if not tgt:
                F.add('EXEC_TARGET_UNKNOWN',
                      f'{rel}:{i} execs {expr} — no rule resolves it; curate it, do not guess')
                continue
            if not owner:
                F.add('EXEC_TARGET_UNKNOWN', f'{rel}:{i} is owned by no node'); continue
            # a parent may own the edge on a child's behalf
            fam, cur = {owner}, by.get(owner)
            while cur and cur['parent']:
                cur = by.get(cur['parent'])
                if cur: fam.add(cur['id'])
            if not any((f_, tgt) in drawn for f_ in fam):
                F.add('EXEC_EDGE_MISSING',
                      f'{rel}:{i} execs {tgt} from {owner} but no such relation is drawn')

# Availability is NOT decided here. An image-only test called Trivy absent when the Helm chart
# injects it; `audit_delivery.py` composes image COPYs AND deployment injection instead.

print(f'exec call sites scanned: {sites}   binaries modelled: '
      f'{len([n for n in nodes if n["id"].startswith("bin.")])}')
print('availability of each binary is decided by audit_delivery.py, not by the image alone')
F.report('every exec target resolves to a drawn node, and every drawn binary is installed or a recorded gap')
