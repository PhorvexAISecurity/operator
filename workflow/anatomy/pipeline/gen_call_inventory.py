#!/usr/bin/env python3
import paths
"""Generated CALL INVENTORY per handler. Facts only — no semantics.

A regex cannot read a branch. Earlier versions of this file inferred meaning and produced
false statements: first-match MutationKind picked failure branches, a templated
"unreachable => Emitted:false" was wrong for request-drain, and one-level helper expansion
reported "no control-plane operation" for warm-swap. This emits what it can prove and marks
itself INCOMPLETE otherwise; the semantics live in a separate curated file.
"""
import re, json, csv, os, collections

A = str(paths.MODULE_PATH / 'internal' / 'actuator') + '/'
FILES = ['handlers_k8s.go', 'handlers_ai.go', 'handlers_ai_p4set.go',
         'gpu_stack.go', 'gpu_stack_p4set.go', 'util.go', 'native.go', 'handler.go']
text = {f: open(A + f).read() for f in FILES}
alltxt = '\n'.join(text.values())
# line index so every fact can carry file:line
lines, off = [], 0
for f in FILES:
    for i, _ in enumerate(text[f].split('\n'), 1): lines.append((f, i))

def at(pos):
    return lines[alltxt.count('\n', 0, pos)] if alltxt.count('\n', 0, pos) < len(lines) else ('?', 0)

def body_from(start):
    i = alltxt.index('{', start); d = 0
    for j in range(i, len(alltxt)):
        if alltxt[j] == '{': d += 1
        elif alltxt[j] == '}':
            d -= 1
            if d == 0: return start, j + 1
    return start, len(alltxt)

funcs = {}
for m in re.finditer(r'func (?:\([^)]*\) )?(\w+)\(', alltxt):
    funcs.setdefault(m.group(1), []).append(body_from(m.start()))

def walk(name, seen, spans):
    """Recursive, cycle-bounded. Returns the set of unresolved local calls."""
    if name in seen: return set()
    seen.add(name)
    unresolved = set()
    for s, e in funcs.get(name, []):
        spans.append((s, e))
        for c in set(re.findall(r'\b([a-z]\w*)\(ctx', alltxt[s:e])):
            if c in funcs: unresolved |= walk(c, seen, spans)
            elif c not in ('append','make','len','fmt','errors'): unresolved.add(c)
    return unresolved

decl = {}
for f in ('handlers_k8s.go','handlers_ai.go','handlers_ai_p4set.go'):
    for i, line in enumerate(text[f].split('\n'), 1):
        m = re.match(r'func \((?:\w+ )?(\w+)\) Name\(\) string \{ return string\(model\.(\w+)\) \}', line.strip())
        if m: decl[m.group(2)] = m.group(1)

types_go = open(paths.MODULE_PATH / 'internal/model/types.go').read()
block = re.search(r'var MutatingActions = \[\]Action\{(.*?)\n\}', types_go, re.S).group(1)
consts = re.findall(r'\bAction[A-Z]\w*', re.sub(r'//.*', '', block))
name_of = {c: re.search(rf'{c}\s+Action = "([^"]+)"', types_go).group(1) for c in consts}

out = {}
for c in consts:
    t = decl[c]
    m = re.search(rf'func \((?:\w+ )?{t}\) Enact\(', alltxt)
    seen, spans = set(), []
    start, end = body_from(m.start())
    spans.append((start, end))
    unresolved = set()
    for callee in set(re.findall(r'\b([a-z]\w*)\(ctx', alltxt[start:end])):
        if callee in funcs: unresolved |= walk(callee, seen, spans)
        elif callee not in ('append','make','len'): unresolved.add(callee)
    seg = '\n'.join(alltxt[s:e] for s, e in spans)

    # per-call SOURCE ANCHORS, not just counts — every fact must be resolvable
    k8s, ctl = [], []
    for s_, e_ in spans:
        for v in ('Create','Update','Delete','Patch','Get'):
            for mm in re.finditer(rf'(?:Client|c)(?:\.SubResource\("(\w+)"\))?\.{v}\(ctx', alltxt[s_:e_]):
                f_, l_ = at(s_ + mm.start())
                k8s.append(f'{v}{f"({mm.group(1)})" if mm.group(1) else ""}@{f_}:{l_}')
        for mm in re.finditer(r'ec\.(?:vllm|guardrail|mig|kvxfer)\(\)\.(\w+)', alltxt[s_:e_]):
            f_, l_ = at(s_ + mm.start())
            ctl.append(f'{mm.group(1)}@{f_}:{l_}')
    k8s, ctl = sorted(set(k8s)), sorted(set(ctl))
    # EVERY MutationKind / Emitted literal with its position — never first-match
    kinds, emits = [], []
    for s, e in spans:
        for mm in re.finditer(r'MutationKind:\s*"([a-z-]+)"', alltxt[s:e]):
            f_, l_ = at(s + mm.start()); kinds.append(f'{mm.group(1)}@{f_}:{l_}')
        for mm in re.finditer(r'Emitted:\s*(true|false)', alltxt[s:e]):
            f_, l_ = at(s + mm.start()); emits.append(f'{mm.group(1)}@{f_}:{l_}')
    # `spans` is walked from a set, so its order varies run to run; without sorting these two
    # lists the generator emitted different bytes for identical source, which makes every
    # regeneration diff untrustworthy.
    kinds, emits = sorted(set(kinds)), sorted(set(emits))
    out[name_of[c]] = dict(handler=t, functions_visited=sorted(seen),
        k8s_call_sites=k8s, control_plane_call_sites=ctl,
        mutation_kind_literals=kinds, emitted_literals=emits,
        unresolved_calls=sorted(unresolved),
        status=('NO_UNRESOLVED_REGEX_CALLS' if not unresolved else 'INCOMPLETE'))

json.dump(out, open('CALL_INVENTORY.json','w'), indent=1)
inc = [k for k,v in out.items() if v['status']=='INCOMPLETE']
print(f"{'action':24}{'k8s call sites':16}{'control-plane call sites':30}{'status'}")
for a,v in out.items():
    print(f"{a:24}{len(v['k8s_call_sites']):<16}"
          f"{' '.join(sorted({c.split('@')[0] for c in v['control_plane_call_sites']}))[:29]:30}{v['status']}")
print('\nstatus NO_UNRESOLVED_REGEX_CALLS means only that every `foo(ctx…)` call resolved to a')
print('local function; it is NOT a proof of an exhaustive Go call graph.')
print(f"\nINCOMPLETE: {inc or 'none'}")
