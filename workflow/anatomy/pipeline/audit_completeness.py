#!/usr/bin/env python3
import paths
"""Find production call edges that exist in source but are ABSENT from RELATIONS.tsv.

Every check so far asks whether what we drew is correct. None asks whether we drew everything.
A map that is right about what it shows and silent about a real edge is still wrong.
"""
import csv, os, re, json, collections, sys
from symbol_owner import owner_of
from findings import Findings
F = Findings('audit_completeness')
SRC = paths.MODULE_STR
HERE = os.path.dirname(os.path.abspath(__file__))
nodes = list(csv.DictReader(open(os.path.join(HERE,'NODES.tsv'), newline=''), delimiter='\t'))
rels  = list(csv.DictReader(open(os.path.join(HERE,'RELATIONS.tsv'), newline=''), delimiter='\t'))
pkgs  = json.load(open(os.path.join(HERE,'packages.json')))

# Symbol-scoped children share a file with their parent, so file-level ownership cannot say
# WHICH child made a call — that let a sibling edge mask a missing one. Attribute each call to
# the child whose anchor lies in the same enclosing function.
def func_ranges(path):
    """[(start_line, end_line, func_name)] by brace depth."""
    if not os.path.exists(SRC + path): return []
    src = open(SRC + path, errors='ignore').read()
    ls = src.split('\n'); out = []
    for m in re.finditer(r'^func (?:\([^)]*\) )?(\w+)\(', src, re.M):
        start = src.count('\n', 0, m.start()) + 1
        d, end = 0, start
        for i in range(start - 1, len(ls)):
            d += ls[i].count('{') - ls[i].count('}')
            if d <= 0 and i > start - 1: end = i + 1; break
        out.append((start, end, m.group(1)))
    return out

RANGES = {}
def enclosing(path, line):
    if path not in RANGES: RANGES[path] = func_ranges(path)
    for a, b, name in RANGES[path]:
        if a <= line <= b: return name
    return None

# child node -> the function its anchor sits in
child_func = {}
for n in nodes:
    if n['parent'] and ':' in n['source_anchor']:
        p, ln = n['source_anchor'].rsplit(':', 1)
        fn = enclosing(p, int(ln))
        if fn: child_func.setdefault((p, fn), n['id'])

# which node owns each package/file
owner = {}
for n in nodes:
    for tok in n['packages_or_files'].split():
        t = tok.strip(',')
        if t.startswith('internal/'):
            owner.setdefault(t, n['id'])                     # file-level
            owner.setdefault('/'.join(t.split('/')[:2]), n['id'])  # package-level fallback

drawn = {(r['from'], r['to']) for r in rels}
# collapse a node to its top-level ancestor, so a child edge counts for its parent
parent = {n['id']: n['parent'] for n in nodes}
kids = collections.defaultdict(list)
for n in nodes:
    if n['parent']: kids[n['parent']].append(n['id'])
def family(x):
    """A node's ancestors AND descendants: an edge drawn on a child satisfies the parent,
    and vice versa. Ancestors alone missed runner.tick -> ingest for runner -> ingest."""
    out, stack = set(), [x]
    while stack:                      # descendants
        c = stack.pop()
        if c in out: continue
        out.add(c); stack += kids.get(c, [])
    a = x
    while parent.get(a):              # ancestors ONLY — never their other children
        a = parent[a]; out.add(a)     # a sibling edge must not satisfy another sibling
    return out

# every cross-package call site in non-test source
found = collections.defaultdict(list)
CALLING_FUNCS = set()
for d, meta in pkgs.items():
    pdir = SRC + 'internal/' + d
    if not os.path.isdir(pdir): continue
    for f in os.listdir(pdir):
        if not f.endswith('.go') or f.endswith('_test.go'): continue
        rel = f'internal/{d}/{f}'
        for i, l in enumerate(open(pdir + '/' + f, errors='ignore'), 1):
            st = l.strip()
            if st.startswith(('//','*','/*')) or st.startswith(('type ','func ')): continue
            # strip string literals: a package name inside a quoted string is not a call
            st_code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', st)
            for callee in meta['imports']:
                if callee in ('model','registry'): continue      # foundation, drawn outside call order
                m = (re.search(rf'\b{callee}\.([A-Z]\w*)\s*\(', st_code)
                     or re.search(rf'\b{callee}\.([A-Z]\w*)\.[A-Z]\w*\s*\(', st_code))
                if m:
                    fn = enclosing(rel, i)
                    if fn: CALLING_FUNCS.add((rel, fn))
                    src_node = (child_func.get((rel, fn))
                                or owner.get(rel) or owner.get(f'internal/{d}'))
                    dst_node, _hit = owner_of(callee, m.group(1))
                    if not src_node or not dst_node or src_node == dst_node: continue
                    if any((a,b) in drawn for a in family(src_node) for b in family(dst_node)): continue
                    found[(src_node, dst_node)].append(f'{rel}:{i}  {st[:70]}')

SCOPE = '''SCANNED:   internal/*/*.go (non-test), direct package-qualified exported calls `pkg.Symbol(`,
           attributed to symbol-scoped children by enclosing function, string literals stripped.
SCANNED also: `pkg.ExportedVar.Method(` (e.g. ctxprov.Registry.Default()).
EXCLUDED:  cmd/* entrypoints · INTERFACE DISPATCH through a struct field (e.g. e.Context.Context(v,pol)
           where e.Context is a ctxprov.ContextProvider — the package name never appears) ·
           file/IPC handoffs ·
           init() side effects · external boundaries (Kubernetes, Prometheus, Phoenix, serving
           stack) · the `model` and `registry` foundations (drawn outside call order).
A green result means only: no UNDRAWN edge of the SCANNED class. It is not a proof of
completeness over the EXCLUDED classes.'''
# A calling function in a shared file must resolve to exactly one child, or be explicitly
# parent-owned. An unclassified parent call could otherwise be satisfied by any child.
PARENT_OWNED = {
 # construction / lifecycle — the parent's own responsibility, not any one child's
 ('internal/runner/manager.go', 'NewManager'):     'constructor: wires every child',
 ('internal/runner/manager.go', 'Start'):          'controller-runtime lifecycle entry (:205)',
 ('internal/runner/manager.go', 'Upsert'):         'tenant registry write (:158)',
 ('internal/runner/manager.go', 'Remove'):         'tenant registry delete',
 ('internal/runner/manager.go', 'selectActuator'): 'actuator mode selection (:142)',
 ('internal/runner/manager.go', 'buildPolicy'):    'policy assembly (:1105)',
 ('internal/runner/manager.go', 'decideTick'):     'optimizer dispatch (:952)',
 ('internal/runner/manager.go', 'processTenant'):  'thin wrapper over processTenantWithPhysics (:742)',
 ('internal/runner/manager.go', 'publishRLSMetrics'): 'metrics publication (:336)',
 ('internal/runner/manager.go', 'reconcileWedged'):   'wedged-pod reconcile (:243)',
 ('internal/runner/manager.go', 'selectionBound'):    'pure classifier over slo.Classify (:425)',
 ('internal/console/benchmark_sim.go', 'simulateTemporal'): 'benchmark simulation (:259)',
 # registry introspection over the whole handler set — not any one handler's responsibility
 ('internal/actuator/handler.go', 'MissingHandlers'): 'registry vs generatable-action diff (:101)',
 ('internal/actuator/handler.go', 'OrphanHandlers'):  'registered-but-ungeneratable diff (:113)',
}
unmapped = sorted({(p, fn) for (p, fn) in CALLING_FUNCS
                   if p in {n['source_anchor'].rsplit(':',1)[0] for n in nodes if n['parent']}
                   and (p, fn) not in child_func and (p, fn) not in PARENT_OWNED})
for p_, fn in unmapped:
    F.add('COMPLETENESS_UNMAPPED_FUNC', f'{p_}  {fn}() is in a shared file but attributed to no node')
for (a, b), hits in sorted(found.items(), key=lambda x: -len(x[1])):
    F.add('COMPLETENESS_EDGE_MISSING',
          f'{a} -> {b}  ({len(hits)} call site{"s" if len(hits)>1 else ""}) e.g. {hits[0]}')

print(f'relations drawn: {len(rels)}')
print(SCOPE)
F.report('no undrawn edges of the scanned class; every calling function is attributed')
