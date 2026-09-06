#!/usr/bin/env python3
import paths
"""Generate ONE ROW PER STATIC OPERATION for every handler. Facts only.

The old matrix had one compound cell per action, and K3's counterexample showed what that hides:
`quarantine` was recorded as `pod/Create Get Update`, but the Create is a **NetworkPolicy** and
only the Update touches the Pod. A compound cell cannot express "which object did which verb",
which is the entire question the matrix exists to answer.

So: one normalized row per static call site, with the target TYPE resolved from the declaration
of the object being passed. Nothing is guessed — a target the resolver cannot see is `UNKNOWN`
and must be curated with an anchor, exactly like the effect columns.
"""
import re, json, csv, os, collections
import branch_scopes as B

A = str(paths.MODULE_PATH / 'internal' / 'actuator') + '/'
FILES = ['handlers_k8s.go', 'handlers_ai.go', 'handlers_ai_p4set.go',
         'gpu_stack.go', 'gpu_stack_p4set.go', 'util.go', 'native.go', 'handler.go',
         # bus 213: the DEFAULT actuator and the hybrid router were parked, which left the
         # matrix describing the opt-in path and silent on the shipped one.
         'phoenix.go', 'hybrid.go']
text = {f: open(A + f).read() for f in FILES}

def body_span(src, start):
    i = src.index('{', start); d = 0
    for j in range(i, len(src)):
        if src[j] == '{': d += 1
        elif src[j] == '}':
            d -= 1
            if d == 0: return i, j + 1
    return i, len(src)

# every function body, per file, so a call can be resolved in the file that DEFINES it
funcs = collections.defaultdict(list)          # name -> [(file, start, end)]
for f, src in text.items():
    for m in re.finditer(r'func (?:\([^)]*\) )?(\w+)\(', src):
        s, e = body_span(src, m.start())
        funcs[m.group(1)].append((f, s, e))

def line_of(f, pos): return text[f].count('\n', 0, pos) + 1

# `var x pkg.Type` / `x := &pkg.Type{` / `var x pkg.Type` inside one body -> the K8s kind
DECL = [re.compile(r'\bvar\s+%s\s+\w+\.(\w+)\b'), re.compile(r'\b%s\s*:=\s*&\w+\.(\w+)\{')]

# A helper's declared RETURN type resolves the variables assigned from it. `pod, ok, err :=
# getPod(...)` is a Pod because getPod is declared `(*corev1.Pod, bool, error)`. Reading the
# signature is mechanical; assuming "pod means Pod" from the name would not be.
RETURNS = {}
for _f, _src in text.items():
    for _m in re.finditer(r'func (?:\([^)]*\) )?(\w+)\([^)]*\)\s*\(?([^{\n]*)\)?\s*\{', _src):
        _t = re.search(r'\*?\w+\.(\w+)', _m.group(2) or '')
        if _t: RETURNS.setdefault(_m.group(1), _t.group(1))

def kind_of(var, f, s, e):
    seg = text[f][s:e]
    for pat in DECL:
        m = re.search(pat.pattern % re.escape(var), seg)
        if m: return m.group(1)
    m = re.search(rf'\b{re.escape(var)}\b[^\n]*?:=\s*(\w+)\(', seg)
    if m and m.group(1) in RETURNS: return RETURNS[m.group(1)]
    # `old := &leaders.Items[i]` — the element type of a typed List
    m = re.search(rf'\b{re.escape(var)}\s*:=\s*&(\w+)\.Items\[', seg)
    if m:
        k = kind_of(m.group(1), f, s, e)
        if k: return k[:-4] if k.endswith('List') else k
    # `for _, s := range readyByRank` — the element type of the ranged collection
    m = re.search(rf'for\s+[\w_]+\s*,\s*{re.escape(var)}\s*:?=\s*range\s+(\w+)', seg)
    if m:
        src_var = m.group(1)
        d = re.search(rf'\b(?:var\s+)?{re.escape(src_var)}\s*(?::=|\s)[^\n]*?\[\]\*?\w+\.(\w+)', seg)
        if d: return d.group(1)
        d = re.search(rf'\b{re.escape(src_var)}\s*(?::=|\s)[^\n]*?map\[[^\]]+\]\*?\w+\.(\w+)', seg)
        if d: return d.group(1)
        k = kind_of(src_var, f, s, e)
        if k: return k[:-4] if k.endswith('List') else k
    return None

# client verb calls: c.Verb(ctx, X) | c.Get(ctx, key, &X) | c.SubResource("x").Verb(ctx, X)
# Control-plane operations are NOT client verbs. Each goes to a DIFFERENT external target, which
# is the whole point of splitting ext.serving: `ec.guardrail().RotateVariant` and
# `ec.vllm().ResetPrefixCache` share a transport but are different systems with different
# confirmation contracts.
CTL = re.compile(r'\bec\.(vllm|guardrail|mig|kvxfer)\(\)\.(\w+)\(')
CTL_TARGET = {'vllm': 'ext.vllm', 'guardrail': 'ext.guardrail',
              'kvxfer': 'ext.kv_local', 'mig': 'ext.mig_agent'}
VERB = re.compile(r'\b(?:ec\.Client|c|r\.Client|p\.Client|h\.\w+)(?:\.SubResource\("(\w+)"\))?'
                  r'\.(Create|Update|Delete|Patch|Get|List)\(ctx\s*,\s*([^)]*)')

def ops_in(fname, seen):
    """Every client operation reachable from fname, with the file that defines each."""
    if fname in seen: return []
    seen.add(fname)
    out = []
    for f, s, e in funcs.get(fname, []):
        seg = text[f][s:e]
        for m in VERB.finditer(seg):
            sub, verb, args = m.group(1) or '', m.group(2), m.group(3)
            # Get(ctx, key, &obj) puts the object LAST; List(ctx, &list, opts...) and every
            # mutating verb put it FIRST. Treating List like Get resolved the option argument
            # (`client.InNamespace(ns)`) instead of the list, and reported UNKNOWN.
            parts = [a.strip() for a in args.split(',')]
            obj = parts[-1] if verb == 'Get' else parts[0]
            var = obj.lstrip('&').split('.')[0].split('[')[0]
            out.append(dict(func=fname, verb=verb, subresource=sub,
                            target=kind_of(var, f, s, e) or 'UNKNOWN', var=var,
                            anchor=f'internal/actuator/{f}:{line_of(f, s + m.start())}'))
        for m in CTL.finditer(seg):
            out.append(dict(func=fname, verb=m.group(2), subresource='', kindclass='control-plane',
                            target=m.group(1), var='', target_node=CTL_TARGET[m.group(1)],
                            anchor=f'internal/actuator/{f}:{line_of(f, s + m.start())}'))
        for c in sorted(set(re.findall(r'\b([a-z]\w*)\(ctx', seg))):
            if c in funcs and c != fname: out += ops_in(c, seen)
    return out

# handler type -> action, from the Name() method
decl = {}
for f in ('handlers_k8s.go', 'handlers_ai.go', 'handlers_ai_p4set.go'):
    for line in text[f].split('\n'):
        m = re.match(r'func \((?:\w+ )?(\w+)\) Name\(\) string \{ return string\(model\.(\w+)\) \}', line.strip())
        if m: decl[m.group(2)] = m.group(1)
types_go = open(paths.MODULE_PATH / 'internal/model/types.go').read()
block = re.search(r'var MutatingActions = \[\]Action\{(.*?)\n\}', types_go, re.S).group(1)
consts = re.findall(r'\bAction[A-Z]\w*', re.sub(r'//.*', '', block))
name_of = {c: re.search(rf'{c}\s+Action = "([^"]+)"', types_go).group(1) for c in consts}

rows = []
for c in consts:
    t, action = decl[c], name_of[c]
    for f, src in text.items():
        m = re.search(rf'func \((?:\w+ )?{t}\) Enact\(', src)
        if not m: continue
        s, e = body_span(src, m.start())
        seg = src[s:e]
        # direct operations in Enact, plus everything its local helpers reach
        for mm in VERB.finditer(seg):
            sub, verb, args = mm.group(1) or '', mm.group(2), mm.group(3)
            parts = [a.strip() for a in args.split(',')]
            obj = parts[-1] if verb == 'Get' else parts[0]
            var = obj.lstrip('&').split('.')[0].split('[')[0]
            rows.append(dict(action=action, phase='Enact', func='Enact', verb=verb, subresource=sub,
                             target=kind_of(var, f, s, e) or 'UNKNOWN', var=var,
                             anchor=f'internal/actuator/{f}:{line_of(f, s + mm.start())}'))
        for mm in CTL.finditer(seg):
            rows.append(dict(action=action, phase='Enact', func='Enact', verb=mm.group(2),
                             subresource='', kindclass='control-plane', target=mm.group(1), var='',
                             target_node=CTL_TARGET[mm.group(1)],
                             anchor=f'internal/actuator/{f}:{line_of(f, s + mm.start())}'))
        for callee in sorted(set(re.findall(r'\b([a-z]\w*)\(ctx', seg))):
            if callee not in funcs: continue
            for op in ops_in(callee, set()):
                op.update(action=action, phase=f'Enact -> {op["func"]}()')
                rows.append(op)
        break

# PRECONDITION — K3 207 rejected the first attempt on two counts, both correct.
#
#  (a) POLARITY. It stored the condition of `if COND { return }` verbatim. That is the REJECT
#      condition: when it holds the operation never happens. `mig.Available` was recorded as
#      `node == "" || gpuID == ""`, i.e. exactly when Available is NOT reached.
#  (b) IT WAS NOT ALWAYS A GUARD. Any nearby `if` matched, including ones in an inner scope or
#      that only `continue`. `DrainRequests` picked up `f.Name == p.Name` from inside a loop.
#
# A guard only counts when it DOMINATES the operation: same brace depth, and its body returns
# from the function. And `if err := doThing(); err != nil { return }` is not a condition at all —
# it is a prior operation that must have SUCCEEDED, which is a different fact, so it gets its
# own column instead of being bent into a boolean.
# Two distinct forms, and conflating them is what produced `!(= "" || ...)` (the `==` matched the
# assignment) and `!hasMIGDevice(pod) succeeded` (a negated boolean filed as a dependency):
#   if err := doThing(); err != nil { return }   -> doThing() must have SUCCEEDED
#   if COND { return }                           -> the operation is reached when !(COND)
GUARD_ASSIGN = re.compile(r'^if\s+\w+\s*:?=(?!=)\s*(.+?)\s*;\s*\w+\s*!=\s*nil\s*\{$')
GUARD_COND   = re.compile(r'^if\s+(.+?)\s*\{$')

def depth_map(f, s, e):
    """brace depth at the start of each line within a function body"""
    d, out = 0, {}
    for i, line in enumerate(text[f][s:e].split('\n')):
        out[i] = d
        d += line.count('{') - line.count('}')
    return out

def guards_for(action_file, s, e, op_line_idx):
    """(reach_condition, prior_dependency) for an operation at op_line_idx within [s,e)."""
    lines = text[action_file][s:e].split('\n')
    depths = depth_map(action_file, s, e)
    op_d = depths.get(op_line_idx, 0)
    reach, prior = [], []
    for k in range(op_line_idx - 1, -1, -1):
        if depths.get(k, 0) != op_d: continue          # only same-scope statements dominate
        line = lines[k].strip()
        ma, mc = GUARD_ASSIGN.match(line), GUARD_COND.match(line)
        if not (ma or mc): continue
        body = '\n'.join(lines[k + 1:k + 4])
        if 'return' not in body.split('}')[0]: continue  # not a fail-closed guard
        if ma:
            prior.append(re.sub(r'\s+', ' ', ma.group(1)).strip() + ' succeeded')
        else:
            cond = re.sub(r'\s+', ' ', mc.group(1)).strip()
            if cond.endswith(';') or '; ' in cond: continue   # an assignment form we did not parse
            reach.append(cond[1:] if cond.startswith('!') and '(' not in cond.split('(')[0][1:]
                         else f'!({cond})')
        if len(reach) + len(prior) >= 3: break
    return ' && '.join(reversed(reach)) or '-', '; '.join(reversed(prior)) or '-'

# SHIPPED REACHABILITY. K3 206 said not to infer `implemented` from a relation, and 207 showed
# the matrix doing exactly that: mig-rebind's Pod.Delete was `implemented` + `OutcomeEmitted`
# although `Available` always errors while pkgNodeExec is nil, so the Delete never runs. The
# Kubernetes API is wired — that is what crossing_status says — but THIS CALL SITE is not
# reached. Two different facts, so two columns.
# K3 211: I derived the ledger from `selectionBound(action).Status`, which is an ACTION property.
# Whether a call site is on the success path or the compensation path is a BRANCH property, and the
# runner records OutcomeFailed for any handler that returns an error (manager.go:1069-1073). So a
# compensation write can never carry OutcomeCompleted or OutcomeEmitted. Derive the branch class.
ERRBRANCH = re.compile(r'^(?:\}\s*)?if\s+(?:\w+\s*:?=[^;]*;\s*)?\w*[Ee]rr\w*\s*!=\s*nil\s*\{$')

def path_class(f, s, e, op_line_idx):
    """success | compensation — is the IMMEDIATELY enclosing block an `if err != nil`?

    Scanning up for any err-branch at lower depth was wrong three times: it called
    gpu_stack_p4set.go:112 compensation (its enclosing block is `if old.Labels[...] != roleRetiring`)
    and both endpoint-rotate Service rows compensation (enclosing blocks are `if svcName != ""`
    and `if ... err == nil`, a SUCCESS guard). Only the block that actually contains the call
    decides."""
    lines = text[f][s:e].split('\n')
    depths = depth_map(f, s, e)
    op_d = depths.get(op_line_idx, 0)
    # Walk OUT one enclosing block at a time. A `for`/`switch`/plain block is transparent — the
    # flip-back loop at p4set:97 sits inside `for ... { }` which is itself inside the err-branch —
    # but the first `if` encountered decides, so a success guard cannot be walked past.
    d = op_d
    while d > 0:
        opener = None
        for k in range(op_line_idx - 1, -1, -1):
            if depths.get(k, 0) == d - 1 and lines[k].strip().endswith('{'):
                opener = lines[k].strip(); break
        if opener is None: break
        if ERRBRANCH.match(opener):
            # K3 215: `compensation` means a write that UNDOES A PRIOR FAILED MUTATION. An
            # `if err != nil` whose failed operation was a READ is a fallback, not an undo —
            # phoenix.go:93 Create-on-NotFound is EnsurePolicy's intended create path. So the
            # branch is compensation only when the operation that failed was itself mutating.
            failed = opener
            m_ = re.match(r'^(?:\}\s*)?if\s+(\w+)\s*!=\s*nil\s*\{$', opener)
            if m_:                       # bare `if err != nil` — trace the assignment above it
                var = m_.group(1)
                for j in range(k - 1, max(k - 6, -1), -1):
                    if re.search(rf'\b{re.escape(var)}\b\s*:?=', lines[j]):
                        failed = lines[j].strip(); break
            if re.search(r'\.(Get|List)\(', failed) and not re.search(r'\.(Create|Update|Delete|Patch)\(', failed):
                return 'success'
            return 'compensation'
        if opener.startswith('if ') or opener.startswith('} else'): return 'success'
        d -= 1
    return 'success'

def error_handling(f, line_no):
    """checked | DISCARDED — `_ = ec.Client.Update(...)` cannot fail loudly."""
    ls = text[f].split('\n')
    t_ = ls[line_no - 1].strip() if 0 < line_no <= len(ls) else ''
    if t_.startswith('_ =') or t_.startswith('_, _ =') or re.match(r'^_(,\s*_)*\s*=', t_):
        return 'DISCARDED'
    return 'checked'

def enclosing_span(f, line):
    """The function body containing this line — guards are only meaningful within one function."""
    best = None
    for name, places in funcs.items():
        for ff, s_, e_ in places:
            if ff != f: continue
            if line_of(f, s_) <= line <= line_of(f, e_):
                if best is None or (e_ - s_) < (best[1] - best[0]): best = (s_, e_)
    return best

# K3 208: `UNWIRED_CALLS = ['ec.mig().']` is the same class of special case that scored Delete as
# implemented — it would miss the next fail-closed stub. Derive the set: any ec.X() accessor whose
# TARGET NODE is declared-unwired. Adding a new unwired external now updates this automatically.
import csv as _csv
_nodes = list(_csv.DictReader(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                'NODES.tsv'), newline=''), delimiter='\t'))
_rels = list(_csv.DictReader(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               'RELATIONS.tsv'), newline=''), delimiter='\t'))
_unwired = {n['id'] for n in _nodes if n['runtime_role'] == 'unwired'}
_unwired |= {r['to'] for r in _rels if r.get('crossing_status') == 'declared-unwired'}
UNWIRED_CALLS = sorted(f'ec.{acc}().' for acc, node in CTL_TARGET.items() if node in _unwired)
if not UNWIRED_CALLS:
    UNWIRED_CALLS = ['\0no-unwired-target\0']      # never matches, rather than matching everything
def reachability(action_file, s, e, op_line_idx):
    lines = text[action_file][s:e].split('\n')
    depths = depth_map(action_file, s, e)
    op_d = depths.get(op_line_idx, 0)
    for k in range(op_line_idx - 1, -1, -1):
        if depths.get(k, 0) != op_d: continue
        line = lines[k].strip()
        if not line.startswith('if '): continue
        body = '\n'.join(lines[k + 1:k + 4])
        if 'return' not in body.split('}')[0]: continue
        if any(u in line for u in UNWIRED_CALLS):
            return 'guarded-unreached', re.sub(r'\s+', ' ', line)[:80]
    return 'reachable', ''

# A helper's operations are reached according to WHERE THE HELPER IS CALLED, not where they sit
# inside the helper. drainInflight's DrainRequests lives in its own function with no guards, but
# Enact calls drainInflight at :240 — after the Available guard — so it is guarded-unreached too.
# Computing this in the helper's own scope made it look reachable.
CALLSITE = {}
for c_ in consts:
    t_, action_ = decl[c_], name_of[c_]
    for f_, src_ in text.items():
        m_ = re.search(rf'func \((?:\w+ )?{t_}\) Enact\(', src_)
        if not m_: continue
        s_, e_ = body_span(src_, m_.start())
        for line_i, ln_txt in enumerate(src_[s_:e_].split('\n')):
            for callee_ in re.findall(r'\b([a-z]\w*)\(ctx', ln_txt):
                CALLSITE.setdefault((action_, callee_), (f_, s_, e_, line_i))
        break

# bus 213: the parked surfaces are generated BEFORE enrichment so reachability, path_class
# and error_handling are derived for them too — appending afterwards left them blank.
def emit_method(recv, method, action, surface, phase_label):
    out = []
    for f, src in text.items():
        m = re.search(rf'func \((?:\w+ )?\*?{recv}\) {method}\(', src)
        if not m: continue
        s_, e_ = body_span(src, m.start())
        seg = src[s_:e_]
        for mm in VERB.finditer(seg):
            sub, verb, args = mm.group(1) or '', mm.group(2), mm.group(3)
            parts = [a.strip() for a in args.split(',')]
            obj = parts[-1] if verb == 'Get' else parts[0]
            var = obj.lstrip('&').split('.')[0].split('[')[0]
            out.append(dict(action=action, phase=phase_label, func=method, verb=verb, subresource=sub,
                            kindclass='kubernetes', target_node='ext.k8s', surface=surface,
                            target=kind_of(var, f, s_, e_) or 'UNKNOWN', var=var,
                            anchor=f'internal/actuator/{f}:{line_of(f, s_ + mm.start())}'))
        for mm in CTL.finditer(seg):
            out.append(dict(action=action, phase=phase_label, func=method, verb=mm.group(2),
                            subresource='', kindclass='control-plane', surface=surface,
                            target=mm.group(1), var='', target_node=CTL_TARGET[mm.group(1)],
                            anchor=f'internal/actuator/{f}:{line_of(f, s_ + mm.start())}'))
        for callee in sorted(set(re.findall(r'\b([a-z]\w*)\(ctx', seg))):
            if callee not in funcs: continue
            for op in ops_in(callee, set()):
                op.update(action=action, phase=f'{phase_label} -> {op["func"]}()', surface=surface)
                op.setdefault('kindclass', 'kubernetes'); op.setdefault('target_node', 'ext.k8s')
                out.append(op)
        break
    return out

# --- the DEFAULT actuator: Phoenix writes CRs; the effect is a controller's to produce ---
rows += emit_method('PhoenixActuator', 'EnsurePolicy', 'phoenix:ensurepolicy', 'phoenix', 'EnsurePolicy')
rows += emit_method('PhoenixActuator', 'Actuate', 'phoenix:actuate', 'phoenix', 'Actuate')

# --- every handler's Rollback, previously out of scope ---
for c in consts:
    rows += emit_method(decl[c], 'Rollback', name_of[c], 'native-rollback', 'Rollback')

for r in rows: r.setdefault('surface', 'native-enact')

for r in rows:
    r.setdefault('kindclass', 'kubernetes')
    r.setdefault('path_class_reason', '-')
    r.setdefault('target_node', 'ext.k8s')
    f_ = r['anchor'].split('/')[-1].split(':')[0]
    ln = int(r['anchor'].rsplit(':', 1)[1])
    sp = enclosing_span(f_, ln)
    if sp:
        s_, e_ = sp
        idx = ln - line_of(f_, s_)
        r['reach_condition'], r['prior_dependency'] = guards_for(f_, s_, e_, idx)
        r['shipped_reachability'], r['unreached_because'] = reachability(f_, s_, e_, idx)
        r['path_class'] = path_class(f_, s_, e_, idx)
        r['path_class_reason'] = 'local error branch' if r['path_class'] == 'compensation' else '-'
        r['error_handling'] = error_handling(f_, ln)
        # a helper row inherits the reachability of the call site that invokes the helper
        m_ = re.match(r'Enact -> (\w+)\(\)', r['phase'])
        cs = CALLSITE.get((r['action'], m_.group(1))) if m_ else None
        if cs:
            cf, cs_, ce_, ci_ = cs
            # A helper called ONLY from an error branch is a compensation path wherever its own
            # body sits. restoreRoutePodLabels is K3's case: its operations look like ordinary
            # success-path writes inside their own function.
            if path_class(cf, cs_, ce_, ci_) == 'compensation':
                r['path_class'] = 'compensation'
                # record WHY: an inherited classification cannot be re-derived from the helper's
                # own body, where the surrounding code is an ordinary read-then-write.
                r['path_class_reason'] = f'call site {cf}:{line_of(cf, cs_) + ci_} is a compensation branch'
            st, why = reachability(cf, cs_, ce_, ci_)
            if st != 'reachable':
                r['shipped_reachability'], r['unreached_because'] = st, why
                pr = guards_for(cf, cs_, ce_, ci_)[1]
                if pr != '-': r['prior_dependency'] = pr
    else:
        r['reach_condition'] = r['prior_dependency'] = '-'
        r['shipped_reachability'], r['unreached_because'] = 'reachable', ''
        r['path_class'], r['error_handling'], r['path_class_reason'] = 'success', 'checked', '-'

seen_rows, dedup = set(), []
for r in rows:
    k = (r['action'], r['phase'], r['anchor'], r['verb'], r['target'])
    if k in seen_rows: continue
    seen_rows.add(k); dedup.append(r)
rows = dedup

# The ROLLBACK LAYER: NativeActuator.Rollback (native.go:88) is the only way any handler Rollback
# can be invoked, and it has no caller outside its own definition and tests — its comment names a
# "saga coordinator" that does not exist. So these operations are unreachable for a different
# reason than mig-rebind's: not guarded, simply never called. Derived by scanning the module.
import subprocess as _sp
_hits = _sp.run(['grep','-rn','--include=*.go','.Rollback(', paths.MODULE_STR],
                capture_output=True, text=True).stdout.split('\n')
_callers = [h for h in _hits if h and '_test.go' not in h
            and not re.search(r'func \(', h.split(':', 2)[-1])
            and 'internal/actuator/native.go' not in h]
ROLLBACK_WIRED = bool(_callers)
for r in rows:
    if r['surface'] != 'native-rollback': continue
    if not ROLLBACK_WIRED:
        r['shipped_reachability'] = 'no-caller'
        r['unreached_because'] = ('internal/actuator/native.go:88 NativeActuator.Rollback is the only '
                                  'invoker and nothing outside tests calls it')


# HYBRID ROUTING derived from actuator.go's RuleTypeFor switch
# rather than asserted. hybrid.go:60 sends an action to Phoenix when RuleTypeFor != "", else to
# native; and phoenix.go:114 hard-errors "unsupported action" on the empty case — so the same
# switch decides BOTH which actuator handles an action in hybrid mode AND whether the action can
# run at all in the shipped default.
_act = open(paths.MODULE_PATH / 'internal/actuator/actuator.go').read()
_sw = re.search(r'func RuleTypeFor\(a model\.Action\) string \{(.*?)\n\}', _act, re.S).group(1)
PHOENIX_ACTIONS = {name_of[c] for c in consts if re.search(rf'case model\.{c}\b', _sw)}
# K3 214: a route must NOT be stamped onto a native row. In hybrid, rotate and quarantine never
# reach the native handlers at all, so a route column there would score a path that does not run —
# the same collapse as OutcomeCompleted on a compensation write. Routing gets its OWN rows, and
# the effects stay on whichever actuator actually runs.
_ph_actuate = [r for r in rows if r['surface'] == 'phoenix' and r['phase'] == 'Actuate']
rows = [r for r in rows if not (r['surface'] == 'phoenix' and r['phase'] == 'Actuate')]
for act in sorted(PHOENIX_ACTIONS):                      # one Actuate row per SUPPORTED action
    for base in _ph_actuate:
        r = dict(base); r['action'] = act
        r['reach_condition'] = f'RuleTypeFor({act}) != "" (internal/actuator/actuator.go:92)'
        rows.append(r)

def route_row(action, phase, to_node, anchor, cond, prior=''):
    return dict(action=action, surface='hybrid', phase=phase, func='Actuate', verb='routes-to',
                subresource='', kindclass='dispatch', target=to_node.split('.')[-1], var='',
                target_node=to_node, anchor=anchor, reach_condition=cond, prior_dependency=prior or '-',
                shipped_reachability='reachable', unreached_because='', path_class='success',
                error_handling='checked')
for act in sorted(name_of[c] for c in consts):
    if act in PHOENIX_ACTIONS:
        rows.append(route_row(act, 'Actuate', 'actuator.phoenix', 'internal/actuator/hybrid.go:61',
                              'RuleTypeFor(action) != ""'))
    else:
        rows.append(route_row(act, 'Actuate', 'actuator.native', 'internal/actuator/hybrid.go:63',
                              'RuleTypeFor(action) == "" (the default case)'))
# EnsurePolicy is ORDERED: Phoenix first, and a Phoenix error means native never runs.
rows.append(route_row('-', 'EnsurePolicy', 'actuator.phoenix', 'internal/actuator/hybrid.go:50',
                      'always — runs first so a CR error surfaces'))
rows.append(route_row('-', 'EnsurePolicy', 'actuator.native', 'internal/actuator/hybrid.go:53',
                      '-', 'h.phoenix.EnsurePolicy succeeded'))
# `disable`: declared, Emitted:false, no operation. One row, no invented mutation.
rows.append(dict(action='disable', surface='native-enact', phase='Enact', func='Enact',
                 verb='none', subresource='', kindclass='declared-only', target='none', var='',
                 target_node='-', anchor='internal/actuator/handlers_k8s.go:256',
                 reach_condition='-', prior_dependency='-', shipped_reachability='reachable',
                 unreached_because='', path_class='success', error_handling='checked'))


# The ROLLBACK LAYER. I first derived this as "no caller" and that was WRONG — my grep used
# `.Rollback(` where the dot is a wildcard, so it matched the interface DECLARATION and I nearly
# recorded a stronger claim than the source supports. With a literal dot there is exactly one
# caller, `cmd/nativedemo.go:79`, which is the native-demo ONE-SHOT tool branch. So the rollback
# layer is real and invocable, and nothing on the operator's tick path ever invokes it.
import subprocess as _sp
_hits = _sp.run(['grep','-rn','--include=*.go','-F','.Rollback(', paths.MODULE_STR],
                capture_output=True, text=True).stdout.split('\n')
_callers = [h for h in _hits if h and '_test.go' not in h
            and 'internal/actuator/native.go' not in h]
_prod = []
for h in _callers:
    _p = h.split(paths.MODULE_STR, 1)[-1]
    _f, _ln = _p.split(':')[0], int(_p.split(':')[1])
    _brs = B.branches_of(_f, _ln)
    if not _brs or 'steady' in _brs: _prod.append(_p.split(':')[0] + ':' + str(_ln))
for r in rows:
    if r['surface'] != 'native-rollback': continue
    if not _prod:
        r['shipped_reachability'] = 'tool-only'
        r['unreached_because'] = ('the only invoker of NativeActuator.Rollback (internal/actuator/native.go:88) '
                                  'is cmd/nativedemo.go:79, the native-demo one-shot branch; no operator tick '
                                  'path calls it')


hdr = ['action','surface','phase','kindclass','target_node','target','subresource','verb','reach_condition','prior_dependency','shipped_reachability','unreached_because','path_class','path_class_reason','error_handling','var','anchor']
rows.sort(key=lambda r: (r['action'], r['anchor']))
with open('OPERATIONS_GEN.tsv','w',newline='') as f:
    w = csv.DictWriter(f, fieldnames=hdr, delimiter='\t', extrasaction='ignore')
    w.writeheader(); w.writerows(rows)

unk = [r for r in rows if r['target'] == 'UNKNOWN']
print(f'operation rows: {len(rows)}   actions covered: {len({r["action"] for r in rows})}   '
      f'UNKNOWN targets: {len(unk)}')
print(f'\n{"action":22}{"phase":26}{"op":26}{"anchor"}')
for r in rows:
    if r['action'] in ('quarantine','rotate'):
        op = f'{r["target"]}{"/"+r["subresource"] if r["subresource"] else ""}.{r["verb"]}'
        print(f'{r["action"]:22}{r["phase"]:26}{op:26}{r["anchor"]}')
if unk:
    print(f'\nUNKNOWN — must be curated with an anchor, never guessed:')
    for r in unk[:12]: print(f'   {r["action"]:20} {r["verb"]:8} var={r["var"]:14} {r["anchor"]}')
