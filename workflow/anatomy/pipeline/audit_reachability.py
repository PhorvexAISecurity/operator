#!/usr/bin/env python3
import paths
"""Reconcile every scope label against what the SOURCE actually reaches.

Three independent derivations, because each covers the others' blind spot:

  1. GRAPH reachability from explicit roots (needs RELATIONS.tsv).
  2. SOURCE cross-check — resolves the symbols each engine file references, per symbol,
     without reading RELATIONS.tsv at all. This is what breaks the circularity K3 found:
     a MISSING edge used to make a wrong label look derived-correct.
  3. BRANCH scopes — cmd/main.go holds the operator loop AND five one-shot tools, so a
     file-level rule cannot tell a production anchor from a tool anchor inside it.

All three dimensions of a relation are reconciled: engine_scope, runtime_role, deployment_mode.
Every failure carries a stable diagnostic code so a mutation can assert WHICH check caught it.
"""
import csv, os, re, collections, sys
from findings import Findings
import branch_scopes as B
from symbol_owner import owner_of

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = paths.MODULE_STR
F = Findings('audit_reachability')

def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels = load('NODES.tsv'), load('RELATIONS.tsv')
by = {n['id']: n for n in nodes}

# Roots, from source. An engine/mode is whatever these actually reach.
ROOTS = {
 'P1': [('cmd.main','decision.coverage')],      # cmd/main.go:254
 'P0': [('cmd.main','decision.p0')],            # cmd/main.go:251
 'default':         [('runner.emit','actuator.phoenix')],
 'optional-native': [('runner.emit','actuator.native')],
 'optional-hybrid': [('runner.emit','actuator.router')],
}
STEADY   = {'production','observe-only','shadow','infrastructure'}
ALLMODES = {'default','optional-native','optional-hybrid'}
def modeset(v): return ALLMODES if v.strip() in ('all','') else set(v.split('|')) - {'none'}

def reach(seeds, blocked=(), roles=None):
    """roles: if given, only traverse edges whose runtime_role is in the set. Without this a
    tool or one-shot edge pollutes the steady-state graph."""
    adj = collections.defaultdict(set)
    for r in rels:
        if (r['from'], r['to']) in blocked: continue
        if roles is not None and r['runtime_role'] not in roles: continue
        adj[r['from']].add(r['to'])
    out, stack = set(), list(seeds)
    while stack:
        x = stack.pop()
        if x in out: continue
        out.add(x)
        stack += list(adj.get(x, ()))
        for n in nodes:                      # a parent reaches through its children
            if n['parent'] == x: stack.append(n['id'])
    return out

# Engine scope is not "what the engine reaches". The operator runs the same tick under either
# engine; only the optimizer subtree differs.
engine_edges = {(a, b) for k in ('P1', 'P0') for a, b in ROOTS[k]} | \
              {(r['from'], r['to']) for r in rels if r['to'] in ('decision.coverage', 'decision.p0')}
NON_DECISION = {(r['from'], r['to']) for r in rels
                if r['runtime_role'] == 'benchmark'
                or 'startup' in r['kind'] or 'one-shot' in r['kind'] or 'ablation' in r['kind']}
common = reach(['cmd.main'], blocked=engine_edges | NON_DECISION, roles=STEADY)
p1r = reach(['decision.coverage'], blocked=NON_DECISION, roles=STEADY)
p0r = reach(['decision.p0'],       blocked=NON_DECISION, roles=STEADY)
def derived_engine(nid):
    if nid in common: return 'BOTH'          # on the engine-independent tick path
    inp1, inp0 = nid in p1r, nid in p0r
    if inp1 and not inp0: return 'P1'
    if inp0 and not inp1: return 'P0'
    if inp1 and inp0:     return 'BOTH'
    return 'NONE'

# ---------------------------------------------------------------- node engine labels
justified = []
for n in nodes:
    if n['runtime_role'] in ('tool','foundation','external'): continue  # outside the engine graph by design
    d, claimed = derived_engine(n['id']), n['engine_scope']
    if d == claimed: continue
    # A divergence is allowed ONLY with a written justification — otherwise the audit can be
    # tuned until it agrees with the labels.
    if n.get('scope_justification','').strip():
        justified.append((n['id'], claimed, d, n['scope_justification']))
    else:
        F.add('NODE_ENGINE_UNJUSTIFIED', f'{n["id"]}: labelled {claimed}, reachability derives {d}')

# ---------------------------------------------------------------- branch scopes (source-rooted)
ok, detail = B.declared_ok()
if not ok: F.add('BRANCH_SET_CHANGED', detail)

# Source files that only execute in a one-shot / tool mode and are NOT under cmd/ (those are
# covered by the branch detector, which is finer-grained than any file rule can be).
ONE_SHOT_SOURCES = {
 'internal/runner/ablation_run.go':   'ablation one-shot mode',
 'internal/console/benchmark_sim.go': 'console benchmark simulation',
}
ANCHOR_RE = re.compile(r'^([A-Za-z0-9_./-]+\.(?:go|yaml|yml|ts|tsx|Dockerfile|mod|json)):(\d+)')
def anchor_of(r):
    m = ANCHOR_RE.match(r['anchor'])
    return (m.group(1), int(m.group(2))) if m else (None, None)

tool_only_targets = set()
for r in rels:
    f, ln = anchor_of(r)
    if not f: continue
    edge = f'{r["from"]} -> {r["to"]}'
    if f in ONE_SHOT_SOURCES and r['runtime_role'] in STEADY:
        F.add('BRANCH_ROLE_CONTRADICTS',
              f'{edge}: role {r["runtime_role"]} but {f} only runs in {ONE_SHOT_SOURCES[f]}')
    brs = B.branches_of(f, ln)
    if brs and not (brs & {'steady'}):
        if r['runtime_role'] in STEADY:
            F.add('BRANCH_ROLE_CONTRADICTS',
                  f'{edge}: role {r["runtime_role"]} but {f}:{ln} executes only in '
                  f'one-shot branch(es) {" ".join(sorted(brs))}')
        tool_only_targets.add(r['to'])

# A node whose ONLY cmd-rooted inbound edges are one-shot branches, and that nothing steady
# reaches, cannot be production.
steady_reached = reach(['cmd.main'], roles=STEADY)
for nid in sorted(tool_only_targets):
    n = by.get(nid)
    if n and n['runtime_role'] == 'production' and nid not in steady_reached:
        F.add('BRANCH_NODE_TOOL_ONLY',
              f'{nid}: labelled production but reached only from one-shot branches')

# ---------------------------------------------------------------- PER-ROOT GRAPHS
# K3 202: one graph per tool binary and per cmd.main branch. `cmd.main` is ONE node covering
# six branches, so a single graph rooted there cannot say which entrypoint reaches what. Each
# root's edges are the cmd.main edges whose ANCHOR lies in that branch, plus everything they
# reach; each tool binary is its own root.
TOOL_BINARIES = [n['id'] for n in nodes if n['id'].startswith('cmd.') and n['id'] != 'cmd.main']
# delivery roots: nothing in the runtime graph 'calls' an image or a CI pipeline — each is
# the head of its own composition graph.
DELIVERY_ROOTS = [n['id'] for n in nodes if n['id'].startswith(('image.', 'ci.'))]

root_reach = {}
for br in sorted(B.DECLARED):
    seeds = []
    for r in rels:
        if r['from'] != 'cmd.main': continue
        f, ln = anchor_of(r)
        if f and br in B.branches_of(f, ln): seeds.append(r['to'])
    root_reach[f'cmd.main[{br}]'] = reach(seeds) if seeds else set()
for t in TOOL_BINARIES + DELIVERY_ROOTS:
    root_reach[t] = reach([t]) - {t}

# Two binaries genuinely reach nothing: they are self-contained stdlib analysis tools. The
# exemption is VERIFIED from source rather than asserted — if either ever imports an internal
# package the claim becomes false and this fails instead of silently excusing a real gap.
SELF_CONTAINED = {
 'cmd.p3deep':   ('cmd/p3deep/main.go',   'stdlib-only P3 deep-dive analysis binary'),
 'cmd.p3report': ('cmd/p3report/main.go', 'stdlib-only P3 report generator'),
}
for root, got in sorted(root_reach.items()):
    if got: continue
    if root in SELF_CONTAINED:
        f_, why = SELF_CONTAINED[root]
        src = open(SRC + f_, errors='ignore').read()
        if 'phorvex/internal' in src or 'phorvex/api' in src:
            F.add('ROOT_REACHES_NOTHING',
                  f'{root} is exempted as {why} but {f_} now imports an internal/api package')
        continue
    F.add('ROOT_REACHES_NOTHING',
          f'{root} is a declared entrypoint but reaches no node — the graph cannot be scoped to it')

# Every node must be reachable from SOME declared root. An unreachable node is either dead or
# an entrypoint we have not declared; both are findings, and neither was previously detectable.
LEAF_ROLES = {'foundation'}                    # drawn outside call order by construction
# Declarative contracts are CONSUMED, never called: nothing in our code invokes the CRD schema
# or the RBAC/chart manifests — the API server and Helm read them. They are reached by no root
# because there is no call to draw, and saying so explicitly is the honest form.
NOT_CALLED = {
 'api.v1alpha1': 'a CRD schema the API server validates against; consumed declaratively, never invoked',
 'deploy':       'RBAC role + charts applied by Helm; consumed declaratively, never invoked',
}
covered = set().union(*root_reach.values()) if root_reach else set()
covered |= set(root_reach) | {n['id'] for n in nodes if n['id'].startswith('cmd.')}
covered |= set(NOT_CALLED)
for n in nodes:
    if n['runtime_role'] in LEAF_ROLES or n['parent']: continue
    if n['id'] not in covered:
        F.add('NODE_NO_ROOT', f'{n["id"]} is reached by no declared entrypoint root')

# ---------------------------------------------------------------- relation labels, all 3 dims
for r in rels:
    edge = f'{r["from"]} -> {r["to"]}'
    src_n, dst_n = by.get(r['from']), by.get(r['to'])
    if not src_n or not dst_n: continue           # validate.py owns missing-endpoint

    # (a) runtime_role — impossible combinations, independent of the branch check above
    if r['runtime_role'] == 'production' and 'unwired' in (src_n['runtime_role'], dst_n['runtime_role']):
        F.add('REL_ROLE_CONTRADICTS', f'{edge}: production edge touching an unwired node')
    if r['runtime_role'] in STEADY and src_n['runtime_role'] in ('tool','benchmark'):
        F.add('REL_ROLE_CONTRADICTS',
              f'{edge}: role {r["runtime_role"]} but its source node is {src_n["runtime_role"]}')

    # (b) deployment_mode — a steady edge can only run in modes BOTH endpoints admit
    if r['runtime_role'] in STEADY:
        em, adm = modeset(r['deployment_mode']), modeset(src_n['deployment_mode']) & modeset(dst_n['deployment_mode'])
        if not em <= adm:
            F.add('REL_MODE_CONTRADICTS',
                  f'{edge}: mode {r["deployment_mode"]} not admitted by its endpoints '
                  f'({src_n["deployment_mode"]} / {dst_n["deployment_mode"]})')

    # (c) engine_scope — contradiction AND overbreadth
    if r['runtime_role'] not in STEADY: continue
    de, df = derived_engine(r['to']), derived_engine(r['from'])
    if de in ('P1','P0') and r['engine_scope'] in ('P1','P0') and r['engine_scope'] != de:
        F.add('REL_ENGINE_CONTRADICTS', f'{edge}: labelled {r["engine_scope"]}, target derives {de}')
    elif df in ('P1','P0') and r['engine_scope'] in ('P1','P0') and r['engine_scope'] != df:
        F.add('REL_ENGINE_CONTRADICTS', f'{edge}: labelled {r["engine_scope"]}, source derives {df}')
    elif r['engine_scope'] == 'BOTH' and de == df and de in ('P1','P0'):
        # an overbroad BOTH used to pass silently: neither endpoint is on the shared path
        F.add('REL_ENGINE_OVERBROAD',
              f'{edge}: labelled BOTH but both endpoints derive {de} only')

# ---------------------------------------------------------------- node deployment modes
modes = {m: reach([b for a, b in seeds]) for m, seeds in ROOTS.items() if m in ALLMODES}
for n in nodes:
    if not n['id'].startswith('actuator'): continue
    got = {m for m, s in modes.items() if n['id'] in s}
    claimed = modeset(n['deployment_mode']) if n['deployment_mode'].strip() != 'all' else set()
    if claimed and not got:
        F.add('MODE_UNREACHABLE', f'{n["id"]}: claims {n["deployment_mode"]} but nothing reaches it')
    elif claimed and got and claimed != got:
        F.add('MODE_MISMATCH', f'{n["id"]}: claims {n["deployment_mode"]}, reached in {"|".join(sorted(got))}')

# ---------------------------------------------------------------- source cross-check
ENGINE_FILE = {'P1': 'internal/decision/coverage.go', 'P0': 'internal/decision/engine.go'}
def nodes_used_by(engine):
    """Which NODES this engine's file references, resolved PER SYMBOL. A package-level check is
    too coarse: `cost` is four nodes and both engines reference `cost.` — different symbols."""
    out = set()
    for l in open(SRC + ENGINE_FILE[engine], errors='ignore'):
        st = l.strip()
        if st.startswith(('//', '*', '/*')): continue
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', st)
        for m in re.finditer(r'\b([a-z][a-z0-9]*)\.([A-Z]\w*)', code):
            node, _ = owner_of(m.group(1), m.group(2), fallback_pkg_node=False)
            if node: out.add(node)
    return out

P1_NODES, P0_NODES = nodes_used_by('P1'), nodes_used_by('P0')

# SOURCE-DRIVEN EDGE EXISTENCE. Comparing LABELS is not enough: when the decision.p0 -> ctxprov
# edge was deleted, both labels stayed BOTH and the cross-check said nothing — the graph
# derivation moved instead, so the audit blamed the (correct) label. The non-circular question
# is: does every symbol an engine file references have an edge drawn from that engine?
FAMILY = {}
for n in nodes:
    fam, cur = {n['id']}, n
    while cur and cur['parent']:
        cur = by.get(cur['parent'])
        if cur: fam.add(cur['id'])
    FAMILY[n['id']] = fam
drawn = {(r['from'], r['to']) for r in rels}
for eng, engnode, used in (('P1','decision.coverage',P1_NODES), ('P0','decision.p0',P0_NODES)):
    for tgt in sorted(used):
        if tgt == engnode or by.get(tgt, {}).get('runtime_role') == 'foundation': continue
        if any((engnode, f) in drawn for f in FAMILY.get(tgt, {tgt})): continue
        F.add('SOURCE_EDGE_MISSING',
              f'{ENGINE_FILE[eng]} references {tgt} but no {engnode} -> {tgt} relation is drawn')

for n in nodes:
    if n['runtime_role'] in ('tool','foundation','benchmark','external'): continue
    pkg = next((t.split('/')[1] for t in n['packages_or_files'].split() if t.startswith('internal/')), None)
    if not pkg or pkg in ('runner','actuator','console','model','registry'): continue
    in1, in0 = n['id'] in P1_NODES, n['id'] in P0_NODES
    src = 'BOTH' if (in1 and in0) else 'P1' if in1 else 'P0' if in0 else None
    if src and src != n['engine_scope'] and not (n['engine_scope'] == 'BOTH' and src in ('P1','P0')):
        F.add('SOURCE_XCHECK_DISAGREES', f'{n["id"]}: labelled {n["engine_scope"]}, {ENGINE_FILE[src] if src!="BOTH" else "both engine files"} references it -> {src}')

# ---------------------------------------------------------------- report
print(f'roots: P1 cmd/main.go:254 · P0 cmd/main.go:251 · actuator modes at manager.go:142-155')
print(f'branch roots: {detail}')
print(f'declarative contracts (consumed, never called): {" ".join(sorted(NOT_CALLED))}')
print(f'per-root graphs: {len(root_reach)} roots '
      f'({len(B.DECLARED)} cmd.main branches + {len(TOOL_BINARIES)} tool binaries + {len(DELIVERY_ROOTS)} delivery)')
for r_ in sorted(root_reach): print(f'   {r_:26} reaches {len(root_reach[r_]):3}')
print(f'common tick path {len(common)}   P1-reach {len(p1r)}   P0-reach {len(p0r)}   '
      f'non-decision edges excluded {len(NON_DECISION)}')
if justified:
    print(f'\nDOCUMENTED DIVERGENCES — {len(justified)} (label differs from reachability, with a stated reason):')
    for i, c, d, j in justified:
        print(f'   {i:20} labelled {c:5} derived {d:5}\n      {j[:150]}')
F.report('every engine, role and mode label agrees with graph, source and branch derivation')
