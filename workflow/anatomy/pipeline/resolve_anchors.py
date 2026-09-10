#!/usr/bin/env python3
import paths
"""Find CALL SITES for each relation, not first regex hits.

The previous resolver took the first match of a loose pattern, which lands on imports,
struct field declarations, flag definitions and function signatures — lines that exist
(so the validator passed) but do not evidence the relation.
"""
import re, os, sys
SRC = paths.MODULE_STR

def sites(path, pat, want='call'):
    """Lines matching `pat` that look like an invocation, not a declaration."""
    out = []
    if not os.path.exists(SRC + path): return out
    for i, l in enumerate(open(SRC + path, errors='ignore'), 1):
        st = l.strip()
        if st.startswith(('//', '*', '/*')): continue
        if not re.search(pat, l): continue
        if want == 'call':
            if not re.search(pat + r'\s*\(', l): continue          # must be invoked
            if st.startswith(('func ', 'type ')): continue          # not a signature
            if re.match(r'^\w+\s+[\w.*\[\]]+$', st): continue       # not a field decl
            if 'flag.' in l: continue                               # not a flag definition
        out.append((i, st[:96]))
    return out

QUERIES = [
 ('cmd.main->runner',              'cmd/main.go',                          r'runner\.NewManager'),
 ('runner.feedback->cost.rls',     'internal/runner/manager.go',           r'observer\.ObserveRotation'),
 ('runner.assembly->exposure',     'internal/runner/manager.go',           r'Clock\.\w+'),
 ('decision.coverage->actionset',  'internal/decision/coverage.go',        r'actionset\.\w+'),
 ('decision.coverage->recon',      'internal/decision/coverage.go',        r'e\.Recon\.\w+|Recon\.\w+'),
 ('decision.coverage->killchain',  'internal/decision/coverage.go',        r'Killchain\.\w+'),
 ('decision.coverage->ctxprov',    'internal/decision/coverage.go',        r'Context\.\w+'),
 ('decision.coverage->cost.p1',    'internal/decision/coverage.go',        r'Cost\.\w+|tcost\.\w+'),
 ('cost.p1->cost.rls',             'internal/cost/p1cost.go',              r'rls\.\w+|RLS\w*\.\w+|Predict'),
 ('runner.assembly->decision.coverage','internal/runner/manager.go',       r'Optimizer\.Decide|decideTick'),
]
for name, path, pat in QUERIES:
    hits = sites(path, pat)
    print(f'\n{name}   [{path}]')
    for i, txt in hits[:4]: print(f'   {path}:{i}  {txt}')
    if not hits: print('   NO CALL SITE FOUND')
