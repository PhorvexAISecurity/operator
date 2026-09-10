#!/usr/bin/env python3
"""Join the existing issue register to the frozen v2 anatomy.

K3 223: no new IDs, do not rewrite issue bodies, join to nodes/relations/seams/operation rows that
already exist, and report any live issue with nowhere to land BEFORE producing the document.

The join is DERIVED from each issue's own text — the files, packages and symbols it already cites
— not assigned by me. An issue that names nothing the anatomy contains is an exception, and saying
so is the point: a projection that lands everything has stopped being a test of the map.

This legacy projector is retained for anatomy-join archaeology. The canonical
register is rendered by `workflow/tools/workflow.py render-issues`.
"""
import paths
import csv, os, re, collections

HERE = os.path.dirname(os.path.abspath(__file__))
REG  = str(paths.WORKFLOW / 'archive' / 'register-v1' / 'PHORVEX_MASTER_ISSUES.md')
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
mx = load('OPERATION_MATRIX.tsv')

file_node, pkg_node = {}, {}
for n in nodes:
    for t in n['packages_or_files'].split():
        t = t.strip(',')
        if t.endswith('.go'): file_node.setdefault(t, n['id'])
        elif t.startswith('internal/') and t.count('/') == 1: pkg_node.setdefault(t.split('/')[1], n['id'])
op_by_file = collections.defaultdict(list)
for r in mx: op_by_file[r['source_anchor_GEN'].rsplit(':', 1)[0]].append(r)
seam_names = {s['seam'] for s in seams}
node_ids = {n['id'] for n in nodes}

text = open(REG).read()
entries, cur = [], None
for line in text.split('\n'):
    # The heading has a VARIABLE number of ` · ` fields: id · title · [severity ·] status · tag.
    # M-118 carries no severity at all ("· ✅ WORKING (with M-28 caveat) ·"), which a
    # shape-assuming regex drops silently. Split positionally instead of guessing the shape.
    if line.startswith('### M-'):
        parts = [x.strip() for x in line[4:].split(' · ')]
        if len(parts) >= 3:
            mid = parts[1:-1]                      # title, then 0-2 of severity/status
            cur = dict(id=parts[0], title=mid[0], tag=parts[-1],
                       severity=mid[1] if len(mid) > 2 else '',
                       status=mid[-1] if len(mid) > 1 else '', body='')
            entries.append(cur)
            continue
    elif cur is not None:
        if line.startswith('#'): cur = None
        else: cur['body'] += line + '\n'
seen = {}
for e in entries: seen.setdefault(e['id'], e)
entries = list(seen.values())

# K3 225 rejected the first join: LOCUS was the FIRST same-tier hit in insertion order, not the
# most specific thing — the same first-match defect as MutationKind. Three concrete causes:
#   * `\brotate\b` matched inside `route-rotate` and `identity-rotate` ('-' is a word boundary)
#   * an action mentioned in passing in a BODY outranked the subsystem named in the TITLE
#   * the first row of an action is the SHARED getPod, so 5 issues landed on a pre-read
#
# Redesign: THE TITLE NAMES THE DEFECT. What the title addresses is the locus; the body only
# supplies touches. Nothing common-English can match a node.
SHARED_PREREAD = 'internal/actuator/handlers_k8s.go:30'
# K3 227: STOP must apply to EXACT NODE-ID matches and to SYMBOL_NODE too, not only to display
# words — `model` is a node id and was bypassing it, putting four cost/serving issues on the domain
# vocabulary. A backticked token is an explicit reference and still counts.
STOP = {'never', 'cluster', 'objective', 'default', 'state', 'value', 'model', 'policy', 'action',
        'actions', 'target', 'source', 'record', 'runtime', 'console', 'metric', 'metrics',
        'phorvex', 'coverage', 'audit', 'exposure', 'deploy'}
ACTIONS = sorted({r['action_GEN'] for r in mx if not r['action_GEN'].startswith(('phoenix:', '-'))},
                 key=len, reverse=True)          # longest first: route-rotate before rotate
HELPERS = sorted({m.group(1) for r in mx
                  for m in [re.search(r'-> (\w+)\(\)', r['phase_GEN'])] if m})
DISPLAY = {}
for n in nodes:
    for w in re.findall(r"[A-Za-z][\w.-]{4,}", n['display']):
        if w.lower() not in STOP: DISPLAY.setdefault(w.lower(), n['id'])
EXTERNAL = {'mig': 'ext.mig_agent', 'mig-rebind': 'ext.mig_agent', 'nvidia-smi': 'ext.mig_agent', 'node-exec': 'ext.mig_agent',
            'vllm': 'ext.vllm', 'guardrail': 'ext.guardrail', 'prometheus': 'ext.prometheus',
            'phoenix': 'ext.phoenix', 'epss': 'ext.first_epss', 'trivy': 'bin.trivy',
            'kubectl': 'bin.kubectl', 'dashboard': 'dashboard', 'amtd': 'ext.phoenix',
            'crd': 'api.v1alpha1', 'rbac': 'deploy', 'securityevent': 'ext.k8s'}
# A bare code symbol in a title addresses the node that DEFINES it — "WireRemoteNodeExec never
# validates" is about the MIG transport, and nothing else in that title says so.
from symbol_owner import _tables as _symtables
_nodes_, _fileowner_, _sym_, _wholepkg_ = _symtables()
SYMBOL_NODE = {}
for (pkg_, name_), (path_, _ln) in _sym_.items():
    owner = _fileowner_.get(path_) or _wholepkg_.get(pkg_)
    if owner and len(name_) > 6: SYMBOL_NODE.setdefault(name_, owner)

def tok(word, text):
    """hyphen-aware: `rotate` must not match inside `route-rotate`"""
    # prefix must not be a word char or hyphen (so `rotate` misses inside `route-rotate`), but the
    # SUFFIX may be a hyphen — K3 226: `Quarantine-NP` is a quarantine reference and was missed.
    return re.search(rf'(?<![\w-]){re.escape(word)}\b', text) is not None

def rows_for(action, blob):
    """the significant rows of an action: a mutating verb, never the shared pre-read; a row whose
    file the issue actually cites is preferred over its siblings"""
    rs = [r for r in mx if r['action_GEN'] == action and SHARED_PREREAD not in r['source_anchor_GEN']]
    cited = [r for r in rs if r['source_anchor_GEN'].rsplit(':', 1)[0] in blob]
    pool = cited or rs
    mut = [r for r in pool if r['operation_GEN'] in ('Create', 'Update', 'Delete', 'Patch')]
    return (mut or pool)

def address(text, blob, in_title):
    """everything `text` addresses, as (rank, kind, target, why). Lower rank = more specific."""
    out = []
    base = 0 if in_title else 10
    for f in re.findall(r'\b((?:internal|cmd|api|deploy|charts)/[\w./-]+\.\w+)', text):
        for r in op_by_file.get(f, []):
            out.append((base + 0, 'op', f'{r["action_GEN"]} {r["operation_GEN"]} @ {r["source_anchor_GEN"]}', f))
        if f in file_node: out.append((base + 1, 'node', file_node[f], f))
    for a in ACTIONS:
        if tok(a, text.lower()):
            for r in rows_for(a, blob):
                out.append((base + 2, 'op', f'{a} {r["operation_GEN"]} @ {r["source_anchor_GEN"]}', a))
            break                                   # longest action wins; do not also match its suffix
    for h in HELPERS:
        if re.search(rf'\b{re.escape(h)}\b', text):
            hr = [r for r in mx if f'-> {h}()' in r['phase_GEN']]
            # K3 227: `rewarmShadow` is called by several actions; picking one action's Create is
            # first-match. A shared helper resolves to the NODE that owns it.
            if len({r['action_GEN'] for r in hr}) > 1:
                own = file_node.get(hr[0]['source_anchor_GEN'].rsplit(':', 1)[0])
                if own: out.append((base + 3, 'node', own, h))
                for r in hr: out.append((base + 9, 'op', f'{r["action_GEN"]} {r["operation_GEN"]} @ {r["source_anchor_GEN"]}', h))
            else:
                for r in hr: out.append((base + 3, 'op', f'{r["action_GEN"]} {r["operation_GEN"]} @ {r["source_anchor_GEN"]}', h))
    for p_ in re.findall(r'\b(\w+)\.[A-Z]\w+', text):
        if p_ in pkg_node: out.append((base + 4, 'node', pkg_node[p_], p_))
    for w, nid in EXTERNAL.items():
        if tok(w, text.lower()): out.append((base + 5, 'node', nid, w))
    for t2 in re.findall(r'`([\w./-]+)`', text):
        b2 = t2.split('/')[-1].replace('.go', '')
        for cand in (t2, b2):
            if cand in pkg_node: out.append((base + 6, 'node', pkg_node[cand], t2))
            if cand in node_ids: out.append((base + 6, 'node', cand, t2))
            if cand in seam_names: out.append((base + 6, 'seam', cand, t2))
    # only a BACKTICKED symbol is a code reference; `Coverage` with a capital C is English and was
    # landing M-15 on redteam
    for sym in re.findall(r'`([A-Z]\w{5,})`', text):
        if sym in SYMBOL_NODE: out.append((base + 1, 'node', SYMBOL_NODE[sym], sym))
    # an exact node id is never a stopword collision, however common the word looks
    for w in re.findall(r'`([\w.-]{3,})`', text) + [x for x in re.findall(r'\b([a-z][\w.-]{3,})\b', text.lower())
                                                     if x not in STOP]:
        if w in node_ids: out.append((base + 5, 'node', w, w))
    for w, nid in DISPLAY.items():
        if tok(w, text.lower()): out.append((base + 7, 'node', nid, w))
    return out

# K3 226: "If the title produces no join, the body's first action must not become LOCUS. That is
# first-match with a delay." The body supplies TOUCHES only. When the title names nothing, fall
# back to the header TAG's node where that is unambiguous, and otherwise leave it unjoined for the
# curated classes to claim — never to whichever action the body mentioned first.
TAG_NODE = {'ECONOMICS': 'cost.p1', 'CLOCK->CHOICE': 'exposure', 'CLOCK': 'exposure', 'CLOCK->BELIEF': 'belief',
            'CONTROL': 'runner.tick', 'CONTROL->ECONOMICS': 'cost.p1', 'BELIEF': 'belief',
            'SENSING': 'ingest', 'RECORD': 'audit', 'CHOICE': 'decision.coverage',
            'KNOWLEDGE': 'killchain', 'CONTRACT->CHOICE': 'api.v1alpha1', 'SURFACE': 'console',
            # K3 226: CONTRACT is "not an operation row" — the contract NODE is where it belongs.
            'CONTRACT': 'api.v1alpha1',
            # ACTUATION with no anatomy token in the title lands on the dispatch that owns the
            # whole handler surface, not on whichever handler the body happened to mention.
            'ACTUATION': 'actuator.native.handlers',
            # K3 227: slo.ledger is too coarse — M-64 is an epoch write after a landed action.
            'ACTUATION->EFFECT': 'actuator.native.handlers'}

# Curated join classes (K3 226). `absence` is a judgement about what a title's SUBJECT is, so it is
# stated, not regexed: 41 titles contain no/never/silent/zero and most are not absences.
SEAM_ATTACH = {'M-9': 'phoenix-execution-readback'}
AFFECTS_EXTRA = {'M-53': 'label-value construction in the actuator helpers — the same shape as '
                         'M-89 (`truncName`), which is already `affects`: a helper that mangles a '
                         'value performs no operation, so no row is its location'}
ABSENCE = {
 'M-10': 'no trace of an honest non-emit: no metric, no Event, no audit line',
 'M-12': 'no actuation-failure metric exists',
 'M-13': 'no Kubernetes Event is emitted on any actuation',
}

for e in entries:
    blob = e['title'] + '\n' + e['body']
    ranked = address(e['title'], blob, True) + address(e['body'], blob, False)
    seen_t, dedup = set(), []
    for rk, kind, tgt, why in sorted(ranked, key=lambda x: x[0]):
        if (kind, tgt) in seen_t: continue
        seen_t.add((kind, tgt)); dedup.append((rk, kind, tgt, why))
    e['joins'] = [((k, t), w) for _, k, t, w in dedup]
    title_hits = [d for d in dedup if d[0] < 10]
    if e['id'] in SEAM_ATTACH:
        e['primary'] = (0, 'seam', SEAM_ATTACH[e['id']], 'the seam IS this missing contract')
    elif e['id'] in AFFECTS_EXTRA:
        e['primary'] = None; e['affects_note'] = AFFECTS_EXTRA[e['id']]
    elif e['id'] in ABSENCE:
        e['primary'] = None; e['absence'] = ABSENCE[e['id']]
    elif title_hits:
        e['primary'] = title_hits[0]
    else:
        tagnode = TAG_NODE.get(e.get('tag', '').strip('`'))
        e['primary'] = (8, 'node', tagnode, f"no anatomy token in the title; header tag "
                        f"`{e.get('tag','').strip('`')}`") if tagnode and tagnode in node_ids else None
    e['tier'] = e['primary'][0] if e['primary'] else None

# Administratively closed entries are not live issues and must not be counted as landing failures:
# M-97 is folded into M-81, M-31/M-112 are FIXED, M-118 verified-working, M-129 superseded,
# M-133 subsumed. The register's own header says so.
CLOSED_IDS = {'M-97', 'M-31', 'M-112', 'M-118', 'M-129', 'M-24', 'M-2', 'M-3', 'M-5', 'M-7'}   # folded / FIXED / working / superseded; M-24 FIXED eleventh pass (v0.4.73, PR #96); M-2/M-3/M-5/M-7 live-verified FIXED 2026-09-03 at deployed 0.4.74 (K3 installed-object checks; B1 lifted)
for e in entries:
    e['closed'] = e['id'] in CLOSED_IDS
live = [e for e in entries if not e['closed']]
# The six K3 named have loci ESTABLISHED BY ARGUMENT across bus 202-223, not inferable from the
# register's prose — the register predates the anatomy that located them. Deriving them would
# discard the work that found them, so they are stated, each with the anchor that proved it.
CURATED_LOCUS = {
 # K3 227 named these three explicitly. `coverage` had to go into STOP to stop capitalised
 # English landing M-15 on redteam, which also cost the legitimate decision.coverage match — so
 # the ruling is recorded rather than recovered by loosening the word list again.
 'M-15':  ('decision.coverage',
           'coverage is booked by the CoverageEngine at decide-time; the retraction that never '
           'happens would be its own.'),
 'M-93':  ('ext.vllm',
           'the plaintext control plane is the serving stack Phorvex talks to, not the domain '
           'vocabulary that happens to be called `model`.'),
 'M-140': ('cost.p1',
           'header tag CONTROL->ECONOMICS; the resurrected state is the tenant lambda the cost '
           'stack carries.'),
 'M-21':  ('phoenix:actuate SecurityEvent.Create @ internal/actuator/phoenix.go:140',
           'RuleTypeFor is non-empty only for rotate/quarantine (internal/actuator/actuator.go:92); '
           'phoenix.go:114 errors on the rest. The 17 hybrid route rows show the same split.'),
 'M-87':  ('the 18 native-rollback operation rows, shipped_reachability=tool-only',
           'NativeActuator.Rollback (internal/actuator/native.go:88) is the only invoker and its '
           'only caller is cmd/nativedemo.go:79, the native-demo one-shot.'),
 'M-39':  ('kv-migrate-invalidate MigrateRemote @ internal/actuator/handlers_ai_p4set.go:424',
           'ack = ALWAYS ERRORS; the stub is internal/actuator/gpu_stack_p4set.go:196. The LOCAL '
           'invalidate at :399 does cross — only the remote path is absent.'),
 'M-79':  ('ext.k8s -> ext.mig_agent, crossing_status=declared-unwired',
           'WireRemoteNodeExec (internal/actuator/nodeexec.go:73) has zero callers, so the exec at '
           'gpu_stack_p4set.go:241 is unreachable and mig-rebind fail-closes at handlers_ai.go:232.'),
 'M-147': ('route-rotate Service.Update @ internal/actuator/handlers_k8s.go:365',
           'internal/slo/bound.go:95 justifies StatusZero with "does not change Service selectors" '
           'while :363-365 sets svc.Spec.Selector; the runner then records OutcomeCompleted '
           '(internal/runner/manager.go:1093).'),
 # K3 erratum 2026-09-02 (T1-A cycle): the first join landed M-20 on `platform` via the keyword
 # `witness`; the witness is computed and consumed in the runner, so the locus is curated here.
 'M-20':  ('runner',
           'ERRATUM (2026-09-02, T1-A cycle, K3): LOCUS is **runner**, not platform — the witness '
           'is computed in `internal/runner/actions_supported.go:55` (`unsupportedEnabledActions`), '
           'consumed at `internal/runner/manager.go:858`; CONTROL node in the module graph. The '
           'earlier `platform` assignment was a keyword-match artifact (`matched on witness`). '
           'Treat keyword-matched LOCUS fields as unverified until checked against the call site.'),
 # Eleventh pass (2026-09-03): the lever lives in recon (ucw boostFactWeight), the stage side-effect in
 # killchain is secondary; the title's `stage` token would otherwise pull the locus to killchain.
 'M-153': ('recon',
           'boostFactWeight ×3 at internal/recon/ucw.go:176-184 (vectorDominance, :276) keyed on '
           'hasVectorEvent (:280-288, event Type string only); the StagePersist promotion at '
           'killchain/hazard.go:201-205 is the secondary effect. Post-dates the fb52e6c anatomy: no '
           'node or edge describes it.'),
 'M-148': ('the 3 compensation rows with error_handling=DISCARDED: handlers_ai.go:138, '
           'handlers_ai_p4set.go:97, handlers_ai_p4set.go:276',
           'each is `_ = ec.Client.Update(...)` inside an err-branch; the runner records '
           'OutcomeFailed (internal/runner/manager.go:1070) for the action and nothing reports the '
           'failed undo.'),
}
for e in live:
    if e['id'] in CURATED_LOCUS:
        loc, why = CURATED_LOCUS[e['id']]
        e['primary'] = (0, 'curated', loc, why)
        e['tier'] = 0

unjoined = [e for e in live if not e['joins']]
print(f'closed/folded (not projected as open): {sum(1 for e in entries if e["closed"])}')
print(f'issues parsed: {len(entries)}   live: {len(live)}   joined: {len(live)-len(unjoined)}   NO LANDING: {len(unjoined)}')
print(f'unjoined by status: {dict(collections.Counter(e["status"].split()[0] for e in unjoined))}\n')
print('EXCEPTIONS — issues with nowhere to land in the frozen anatomy:')
for e in unjoined:
    print(f'  {e["id"]:7}{e["severity"]:9}{e["status"][:14]:16}{e["title"][:74]}')

# ---------------------------------------------------------------------------
if '--emit' in __import__('sys').argv:
    OUT = str(paths.WORKFLOW / 'issues' / 'MASTER_ISSUES.legacy-projector.md')
    by_id = {e['id']: e for e in entries}
    src = open(REG).read().split('\n')
    out, emitted = [], set()

    _live=[e for e in entries if not e['closed']]
    N_ABS=len([e for e in _live if e.get('absence')])
    N_AFF=len([e for e in _live if e['id'] in {'M-58','M-73','M-89','M-114','M-53'}])
    N_UNJ=len([e for e in _live if not e.get('primary') and not e.get('absence')
               and e['id'] not in {'M-58','M-73','M-89','M-114','M-53'}])
    N_LOC=len(_live)-N_ABS-N_AFF-N_UNJ
    header = f'''> ## v2 anatomy projection — appended {len(by_id)} joins, no bodies rewritten
>
> This is the master issue register with a **join to the frozen v2 anatomy** appended under each
> entry. Nothing else is changed: no new IDs, no severity or status edits, no rewritten bodies.
> The register above each join line is byte-identical to `PHORVEX_MASTER_ISSUES.md`.
>
> **Anatomy pin:** `fb52e6c` / v0.4.64 · frozen at bus 223 ·
> resume document `campaign/anatomy-v2/STATE.md`
>
> **Join set:** 147 headings · 5 administratively closed · **142 live** ·
> {N_LOC} `located-at` · {N_AFF} `affects` · {N_ABS} `absence` · {N_UNJ} unjoined
>
> **`LOCUS`** is the single most specific place the anatomy holds the issue. Specificity is ranked
> by how precisely the issue ITSELF names the thing — cites a file > names an action > names a
> helper > names a subsystem — except for six loci established by argument during the anatomy
> work (M-21, M-39, M-79, M-87, M-147, M-148), which are stated with the anchor that proved them.
>
> **`TOUCHES`** are the other anatomy elements the issue's own text reaches.
>
> **`AFFECTS`** ({N_AFF} issues, §V2-A) is a separate class: the defect is BELOW operation granularity —
> the contents of a call, or a pure helper that performs no operation. The anatomy's finest grain
> is the static call site, and it is not required to have a row for every payload field. These are
> recorded as affecting an operation, not located at one.

'''
    # the projection header goes after the register's own title line, so the file still opens as
    # the register it is a copy of
    for i, line in enumerate(src):
        out.append(line)
        if i == 0 and line.startswith('# '):
            out.append('')
            out.append(header.rstrip())
        m = re.match(r'^### (M-\d+) ', line)
        if not m: continue
        e = by_id.get(m.group(1))
        if not e or e['id'] in emitted: continue
        emitted.add(e['id'])
        j = ['']
        if e['closed']:
            j.append(f'> `V2` **CLOSED** — administratively closed in the register; not projected as open.')
        elif e.get('absence'):
            j.append(f'> `V2` **ABSENCE** — no positive locus: {e["absence"]}')
        elif e['id'] in {'M-58', 'M-73', 'M-89', 'M-114', 'M-53'}:
            j.append(f'> `V2` **AFFECTS** (below operation granularity) — see §V2-A.')
        elif not e['primary']:
            j.append(f'> `V2` **UNJOINED** — the anatomy holds nothing this issue addresses.')
        else:
            kind, tgt = e['primary'][1], e['primary'][2]
            why = e['primary'][3] if e['tier'] == 0 else f'matched on `{e["primary"][3]}`'
            j.append(f'> `V2` **LOCUS** · {tgt}')
            j.append(f'> {why}')
            # TOUCHES must inform. The shared getPod row (handlers_k8s.go:30) appears in every
            # action and says nothing; a touch two tiers below the locus is usually the matcher
            # being generous rather than the issue reaching there.
            # TOUCHES must inform: never the shared pre-read, and never a sibling verb that only
            # shares a FILE with the locus (K3 226: citing handlers_k8s.go pulled custom-inject,
            # debugger, disable and identity-rotate under M-147).
            SHARED = 'internal/actuator/handlers_k8s.go:30'
            locus_act = e['primary'][2].split()[0] if e['primary'] else ''
            rest = []
            for (k, t), w in e['joins'][1:]:
                if SHARED in t: continue
                if k == 'op' and w.endswith('.go') and not t.startswith(locus_act): continue
                rest.append(t)
            rest = rest[:6]
            if rest:
                more = len(e['joins']) - 1 - len(rest)
                j.append('> `V2` TOUCHES · ' + ' · '.join(rest) + (f' (+{more} more)' if more > 0 else ''))
        out.append('\n'.join(j))

    AFFECTS_IDS = {'M-58', 'M-73', 'M-89', 'M-114', 'M-53'}
    aff = [e for e in entries if e['id'] in AFFECTS_IDS]
    absl = [e for e in entries if e.get('absence')]
    out.append('\n\n## §V2-A · `affects` — issues below the anatomy\'s operation granularity\n')
    out.append('The frozen anatomy resolves to the static call site: which object, which verb, which effect.')
    out.append('These four are defects in the CONTENTS of a call or in a pure helper that performs no')
    out.append('operation, so no operation row is their location. Widening the join until they landed would')
    out.append("stop the projection being a test of the map. Each is recorded against what it degrades.\n")
    AFFECTS = {
     'M-53': 'label-value construction in the actuator helpers — same shape as M-89: a helper that mangles a value performs no operation, so no row is its location',
     'M-58': 'the pod spec carried by `custom-inject` / `debugger` Pod.Update @ internal/actuator/handlers_k8s.go:235 — the row is correct about the operation; the defect is in its payload',
     'M-73': 'the acknowledgement of all four control-plane crossings (ext.vllm, ext.guardrail, ext.kv_local) — `okCode` classifies the response; it performs no operation',
     'M-89': 'pod naming inside the actuator helpers — `truncName` performs no operation',
     'M-114': 'a constant inside the physics/sensing computation — no operation row exists for a normalization constant',
    }
    for e in aff:
        out.append(f'- **{e["id"]}** · {e["title"]}\n  affects: {AFFECTS.get(e["id"], "—")}')
    open(OUT, 'w').write('\n'.join(out) + '\n')
    print(f'\nemitted {OUT}')
    print(f'  joins appended: {len(emitted)}   affects section: {len(aff)}')
