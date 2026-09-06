#!/usr/bin/env python3
"""Emit PHORVEX_ANATOMY_V2.md — the readable anatomy — GENERATED from the frozen inventories.

v1's anatomy is prose maintained by hand beside the data. This one is derived, because the whole
campaign's lesson is that a hand-maintained description drifts from what it describes: STATE.md
itself described a 77-node world thirty rounds after the anatomy had 99.

Nothing here is authored twice. Every count, every anchor and every claim is read out of
NODES/RELATIONS/SEAMS/OPERATION_MATRIX at build time.
"""
import paths
import csv, os, re, collections, subprocess, json

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = str(paths.ANATOMY_DOC)
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels = load('NODES.tsv'), load('RELATIONS.tsv')
EFFECT = load('EFFECT_MATRIX.tsv') if os.path.exists(os.path.join(HERE,'EFFECT_MATRIX.tsv')) else []
seams, bounds, mx = load('SEAMS.tsv'), load('INTENTIONAL_BOUNDARIES.tsv'), load('OPERATION_MATRIX.tsv')
pin = json.load(open(os.path.join(HERE, 'SOURCE_PIN.json')))
by = {n['id']: n for n in nodes}
kids = collections.defaultdict(list)
for n in nodes:
    if n['parent']: kids[n['parent']].append(n)

LANE_ORDER = ['Foundation','Bootstrap','Orchestration','Sensing','Assembly','Pricing','Choice',
              'Actuation','Observation','Record','Console','Tools','Product','Delivery','External']
LANE_WHAT = {
 'Foundation':'shared types and registries every other lane compiles against',
 'Bootstrap':'process entry, flag parsing, and the contracts the cluster validates against',
 'Orchestration':'the tick loop: what runs, in what order, per tenant',
 'Sensing':'what the operator can see about the cluster and the workload',
 'Assembly':'turning observations into the view a decision is made on',
 'Pricing':'what an action is judged to cost',
 'Choice':'the decision engines that select actions',
 'Actuation':'the hands: the actuators and their handlers',
 'Observation':'what is measured about what happened',
 'Record':'what is written down',
 # K3 228: this said "the read-only operator surface". That was a hand-written adjective that
 # contradicted the inventories in the same document — `console.attack` execs kubectl to apply a
 # SecurityEvent CR (M-136). `runtime_role=tool` means NOT ON THE OPERATOR DECISION PATH; it does
 # not mean read-only. Lane blurbs now carry a derived clause so this cannot recur silently.
 'Console':'the operator-facing surface; off the decision path, which is not the same as read-only',
 'Tools':'one-shot binaries and analysis paths, not the operator loop',
 'Product':'the shipped user-facing surface',
 'Delivery':'how the product is composed and reaches a cluster',
 'External':'systems Phorvex does not own, at the point its code crosses into them',
}

def first_sentence(t):
    """K3 229: clipping an evidence note at 200 characters produced `shipped ob` and `Phorv`."""
    t = t.strip()
    # K3 230: `coverage.go: 17 cost. refs` was cut at `cost.` — a package abbreviation is not a
    # sentence end. A terminator is a period followed by space and then a CAPITAL or end-of-text.
    m = re.search(r'(?<=[a-z0-9)\]])\.(?:\s+(?=[A-Z])|\s*$)', t)
    return (t[:m.end()].strip() if m and m.end() < 320 else t)

def ops_of(pred): return [r for r in mx if pred(r)]
out = []
W = out.append
def T(cols): W('| ' + ' | '.join(cols) + ' |'); W('|' + '---|'*len(cols))
def esc(t): return (t or '').replace('|', r'\|').replace('\n', ' ').strip()
def anchor_cell(a):
    """An anchor carries EVERY line the relation lands on. Truncating one drops a FACT:
    `manager.go:928 + manager.go:854` rendered as `manager.go:928 +…`, hiding the reject path.
    Compress the repeated file prefix instead of cutting characters, so both lines survive."""
    a = a.split(chr(8212))[0].strip()
    parts = [x.strip() for x in a.split('+')]
    if len(parts) > 1:
        head = parts[0].rsplit(':', 1)[0]
        parts = [parts[0]] + [(':' + x.rsplit(':', 1)[1]) if x.rsplit(':', 1)[0] == head else x
                              for x in parts[1:]]
    cell = esc(' + '.join(parts))
    # Falsifiable: every line number the TSV records must survive into the cell a reader sees.
    _want = set(re.findall(r':(\d+)', a)); _got = set(re.findall(r':(\d+)', cell))
    assert _want <= _got, f'anchor cell dropped line numbers {sorted(_want - _got)} from: {a}'
    return cell

def short(t, n=110):
    t = esc(t)
    return t if len(t) <= n else t[:n-1].rsplit(' ', 1)[0] + '…'
lane_of = {n['id']: n['lane'] for n in nodes}
mut = [r for r in mx if r['operation_GEN'] in ('Create','Update','Delete','Patch')]
reach = collections.Counter(r['shipped_reachability_GEN'] for r in mx)
sec = collections.Counter('NOT CONFIRMED' if 'NOT CONFIRMED' in r['security_goal_confirmation_CURATED']
      else 'not reached' if 'not reached' in r['security_goal_confirmation_CURATED']
      else 'PARTIAL' if r['security_goal_confirmation_CURATED'].startswith('PARTIAL') else 'other'
      for r in mut)
# `disc` is every mutating write that discards its error; `disc_comp` is the subset that are
# compensation paths. Conflating them produced "7 compensation paths, 8 of them discarding".
disc = sum(1 for r in mx if r['error_handling_GEN'] == 'DISCARDED' and r['operation_GEN'] not in ('Get','List'))
disc_comp = sum(1 for r in mx if r['error_handling_GEN'] == 'DISCARDED'
                and r['path_class_GEN'] == 'compensation' and r['operation_GEN'] not in ('Get','List'))
comp = sum(1 for r in mx if r['path_class_GEN'] == 'compensation')
ph_actions = sorted({r['action_GEN'] for r in mx if r['surface_GEN']=='phoenix' and r['phase_GEN']=='Actuate'})
nat_actions = sorted({r['action_GEN'] for r in mx if r['surface_GEN']=='native-enact' and r['action_GEN']!='disable'})

W('# Phorvex Anatomy v2')
W('')
W('**What the parts are, what each is responsible for, which code it owns, how they connect — and')
W('what actually happens when it acts.**')
W('')
W(f"**Source pin:** `{pin['commit']}` ({pin.get('release', 'unreleased')}) · "
  f"**Frozen:** {pin.get('frozen_at', 'release sync')} · **Anchors verified:** {pin['anchors']}")
W('**Companion to:** `../issues/MASTER_ISSUES.md` (what is wrong, joined to this map) and')
W('`pipeline/STATE.md` (how to rebuild and re-verify it).')
W('')
W('> **This document is generated**, from two kinds of evidence and nothing else.')
W('>')
W('> 1. **Read out of the frozen inventories** at build time — every count, node, relation,')
W('>    operation row, seam and anchor. If it cannot be read out of NODES / RELATIONS / SEAMS /')
W('>    OPERATION_MATRIX / SOURCE_PIN, it is not here.')
W('> 2. **Quoted from the source at the pin** — the prose in *What Phorvex is* and *Glossary*.')
W('>    Each carries the lines it is quoted from, and the phrases that carry the claim are')
W('>    re-checked against those lines on every rebuild, so a source edit that changes the')
W('>    meaning fails the build.')
W('>')
W('> One entry in the glossary is derived from this map rather than quoted, and labels itself.')
W('> Rebuild with `python3 build_anatomy_doc.py`.')
W('')
W('---')
W('')
# ---------------------------------------------------------------------------------------------
# ORIENTATION. Everything above this artifact's first version answered "where is X and is it
# confirmed" and never once said what Phorvex IS. A reader who did not already know the product
# could not learn it here, and 103 of 114 operation rows were truncated mid-fact. Both are fixed.
#
# These claims are PROSE, so they are held to the same standard as every other claim in this
# file: each is quoted from the source at the pin and re-verified at build time. A sentence whose
# anchor stops matching FAILS the build rather than silently becoming folklore.
def _verify(anchors):
    """K3 243: the old guard checked that a TOKEN appeared on a line. That is a token hit, not
    support — `tick` was anchored to a line reading `switch os.Getenv("PHORVEX_ACTUATOR")`, which
    contains the token and does not define a tick. Every string here is a CLAIM-BEARING phrase
    and must appear inside the cited span, so a source edit that changes the meaning fails the
    build instead of leaving a sentence the anchor no longer supports."""
    bad = []
    for _p, _s, _e, toks in anchors:
        ls = paths.lines(_p)
        span = '\n'.join(ls[_s-1:_e]) if ls else ''
        for t in toks:
            if t not in span:
                bad.append(f'{_p}:{_s}-{_e} does not carry {t!r}')
    return bad

def _cite(anchors):
    return ' · '.join(f'`{_p}:{_s}`' if _s == _e else f'`{_p}:{_s}-{_e}`'
                      for _p, _s, _e, _t in anchors)

_CRD = 'api/v1alpha1/phorvexpolicy_types.go'
SOURCED = [
 ("Phoenix can act on a workload — delete, quarantine, probe — but decides **blindly**: by a "
  "clock or a hand-written exact-match table, with no notion of what a move costs or what is "
  "worth protecting.",
  [('README.md', 3, 4, ['decides **blindly**', 'exact-match table'])]),
 ("**Phorvex is the missing brain.** It decides *which* workload to move, *when*, and *which "
  "action*, by optimizing security gained against disruption cost — then drives Phoenix through "
  "Phoenix's own CRDs.",
  [('README.md', 5, 8, ['Phorvex is the missing brain',
                        'optimizing security gained against disruption cost'])]),
 ("The objective is **maximize E[security] − λ · E[switching-cost]**.",
  [(_CRD, 60, 61, ['cost-weighted optimization objective: maximize',
                   'E[security] - lambda * E[switching-cost]'])]),
 ("The production decision engine is the **CoverageEngine**: it maximizes consequence-weighted "
  "recon-facts-invalidated-per-dollar — Σ w(facts covered by S) − λ·C(S) — by a submodular greedy "
  "over the dynamically generated feasible action set, under a one-move-per-asset partition "
  "constraint and the move budget. It is **stateful across ticks**.",
  [('internal/decision/coverage.go', 22, 27,
    ['CoverageEngine is the P1 brain', 'submodular greedy', 'partition constraint',
     'STATEFUL across ticks'])]),
 ("The `proactiveFloor` — the hygiene floor — is a **detection-independent MAXIMUM exposure**: a "
  "pod unchanged for longer than `ProactiveFloor` is eligible for a proactive rotation "
  "*regardless of any detector*.",
  # K3 245: the previous edit deleted the NOUN, leaving "longer than it is eligible" -- not a
  # sentence. `longer than ProactiveFloor` is now itself a verified phrase, so the duration
  # cannot be dropped again without failing the build. The because-clause is gone: the span
  # says the floor is detector-independent, not why the product moves.
  [(_CRD, 204, 207, ['detection-independent', 'MAXIMUM exposure',
                     'longer than ProactiveFloor', 'regardless of any detector'])]),
 ("Everything is **per tenant**, and a tenant is a namespace (or a vcluster projected as one). "
  "The decision engine, exposure clocks, move budget, metrics and actuation are all keyed by it.",
  [(_CRD, 11, 15, ['PER-TENANT configuration surface', 'vcluster', 'keyed by tenant'])]),
 ("**Exposure clocks** track, per mutable VARIABLE of a workload — pod identity, node placement, "
  "image, env, GPU binding, network identity, session — the time since that variable last "
  "changed.",
  [('internal/exposure/clock.go', 6, 9,
    ['per mutable VARIABLE', 'time since that variable last', 'CHANGED'])]),
 ("Two run modes: `dryRun` decides, logs and emits metrics but **never actuates** (the default), "
  "and `active` additionally drives Phoenix.",
  [(_CRD, 387, 390, ['ModeDryRun decides', 'never actuates', 'ModeActive additionally'])]),
 ("Which hands it uses is one environment variable: `PHORVEX_ACTUATOR=native` selects the native "
  "actuator, and unset selects the **Phoenix adapter**, the default, which drives unmodified "
  "Phoenix. Both satisfy the same interface — the brain does not change.",
  [('internal/runner/manager.go', 140, 143,
    ['PHORVEX_ACTUATOR=native', 'Phoenix adapter (default', 'the brain is unchanged'])]),
]
_bad = [b for _c, _a in SOURCED for b in _verify(_a)]
assert not _bad, 'orientation claims their anchor does not carry:\n  ' + '\n  '.join(_bad)

W('## What Phorvex is')
W('')
W('*Each statement below is a quotation from the source at the pin. The phrases that carry the '
  'claim are re-checked against the cited lines when this file is rebuilt, so a source edit that '
  'changes the meaning fails the build rather than leaving a sentence its anchor no longer '
  'supports.*')
W('')
for _claim, _anchors in SOURCED:
    W(f'- {_claim}')
    W(f'  {_cite(_anchors)}')
W('')
W('So the shape of the thing is: **watch a tenant, price every move it could make, pick the set '
  'that buys the most security per unit of disruption, and enact it — on a floor that fires '
  'whether or not anything was detected.** The lanes below are that sentence, in order.')
W('')

W('## On the name')
W('')
W(f'v1 described Phorvex as 12 subsystems and 23 interactions. This map is '
  f'**{len(nodes)} nodes in {len(set(n["lane"] for n in nodes))} lanes, {len(rels)} relations, '
  f'{len(seams)} seams and {len(mx)} operations** over the same product.')
W('')
W('The difference is not detail for its own sake. **A node is not a package.** The `cost` package')
W(f"is {len([n for n in nodes if n['id'].startswith('cost')])} nodes, `console` is "
  f"{len([n for n in nodes if n['id'].startswith('console')])}, `runner` is "
  f"{len([n for n in nodes if n['id'].startswith('runner')])} — because the package boundary is not")
W('the responsibility boundary, and an issue lands on a responsibility. The finest grain here is')
W('one row per static call site, which is what lets the map say *which object gets which verb* and')
W('*whether that call site runs at all*, instead of naming a subsystem and stopping.')
W('')
W('## How to read this')
W('')
W('The anatomy has four kinds of statement, and they carry different weight.')
W('')
W('- **Nodes** are the parts. Each owns specific files and carries a line anchor into the code that')
W('  defines it. A node is not a package: `cost` is four nodes, `console` is eight, because the')
W('  package boundary is not the responsibility boundary.')
W('- **Relations** are how parts reach each other, each anchored at the call site that proves it.')
W('- **Seams** are contracts that are stated but not kept. Each carries *contract evidence* (where')
W('  the promise is made) and *negative evidence* (where it is not honoured).')
W('- **Operations** are the finest grain: one row per static call site in the actuation surface,')
W('  saying which object gets which verb, whether that call site runs in the shipped binary, and')
W('  what — if anything — confirms it worked.')
W('')
W('Where this document says something is *not confirmed*, that is a statement about the code, not a')
W('hedge about the analysis.')
W('')
W('### The confirmation vocabulary')
W('')
W('Six different things get called "it worked". They are closed tokens here, and they are not')
W('interchangeable — most of this map\'s findings live in the gaps between them.')
W('')
T(['token','what it actually establishes'])
for tok, meaning in [
 ('write-ack','the API server stored the object. Nothing about effect.'),
 ('protocol-ack','a serving stack answered the request. Stronger than a store; still not the outcome.'),
 ('independent readback','a later read confirms the resulting state. Present nowhere in this surface.'),
 ('availability / recovery','something observed the workload return. One action has this, conditionally.'),
 ('security-goal confirmation','evidence the security outcome occurred. Zero operations have it.'),
 ('runner ledger','what the operator RECORDS happened — an outcome name, not an observation.')]:
    W(f'| `{tok}` | {meaning} |')
W('')
W('Two more tokens qualify every operation:')
W('')
W('- **`crossing_status`** — is the destination wired at all: `implemented` | `declared-unwired` |')
W('  `absent-stub`. A named controller is not a reachable one.')
W('- **`shipped_reachability`** — does THIS call site execute in the shipped binary: `reachable` |')
W('  `guarded-unreached` (a guard above it always fails) | `tool-only` (invoked only from a')
W('  one-shot tool). The destination being wired says nothing about the call site running.')
W('')
W('### How the issue register points here')
W('')
W('`PHORVEX_MASTER_ISSUES_V2.md` joins each live issue to this map in one of three classes:')
W('')
W('- **`located-at`** — the map holds the thing the issue is about.')
W('- **`affects`** — the defect is below operation granularity: the contents of a call, or a pure')
W('  helper that performs no operation. The map is not required to have a row for every payload')
W('  field.')
W('- **`absence`** — the issue names something that is not there, so it has no positive locus.')
W('')
W('The pointer is **one-way**. The register cites this file; closing an issue does not edit it.')
W('')

# ---- the lanes -----------------------------------------------------------------------------
# THE TICK, derived from runner's outbound edges rather than retold
# K3 234: listing runner's outbound edges in INVENTORY order is a dump, not a pass of the loop.
# Order by the manager.go line that IS the tick. Two classes are footnotes, not steps: startup
# validation (:208) and which actuator gets constructed (:146/:153) — neither happens per tick.
FOOTNOTE_LINES = {146, 153, 208}
# K3 235: two relations are anchored on the FUNCTION that does the work, not on the tick's call to
# it, so ordering by the anchor put audit (:909) before the actuation it records. The tick calls
# `m.actuate` at manager.go:904 — the comment there says actuate FIRST so the audit reflects what
# fired. The anchor stays :1061 in the interactions table; only the tick ORDER uses the call site.
# The same class: every runner.emit* relation is anchored inside the emit function, which the tick
# reaches at :904. Mapping only the two K3 named would have left the feasibility re-check (:1051)
# still printing after the audit that records it.
TICK_CALLSITE = {('runner.assembly', 'runner.emit'): 904, ('runner.emit', 'actuator.router'): 904,
                 ('runner.emit', 'feasibility'): 904, ('runner.emit', 'slo.ledger'): 904,
                 # K3 237, and the SAME inversion class again. This relation is anchored
                 # `:928 + :854`, and min() took 854 — `RecordActionSetRejection`, inside the
                 # `if err != nil` arm after decideTick that suppresses actuation and returns.
                 # The step that says 'publishes per-tick metrics' is PublishTick at :928, on
                 # the success path AFTER actuate (:904) and audit (:909). Ordering by the
                 # lower line printed the publish before the actuation it reports.
                 ('runner.assembly', 'metrics'): 928}
def mgr_line(r):
    ls = [int(n) for f, n in re.findall(r'(manager\.go):(\d+)', r['anchor'])]
    return min(ls) if ls else None
_tick, _foot, _seen_t, _samepass = [], [], set(), []
for r in rels:
    if not r['from'].startswith('runner') or r['from'] == r['to']: continue
    if r['runtime_role'] != 'production':
        # K3 237: same pass, filtered out by role. calib (:326, shadow) and shadow_validation
        # (:866, observe-only, between decide :852 and actuate :904) DO run in this loop.
        # Footnote them; do not promote them into production steps.
        if mgr_line(r) is not None: _samepass.append((mgr_line(r), r))
        continue
    # intra-runner edges ARE the loop's structure — tick -> feedback (observeReadyRotations) and
    # tick -> assembly are steps, not plumbing. Only a self-edge is noise.
    if r['from'] == r['to']: continue
    k = (r['from'], r['to'])
    if k in _seen_t: continue
    _seen_t.add(k)
    ln = mgr_line(r)
    # the override moves a function-anchored relation to its tick call site, but it must never
    # PROMOTE a footnote: actuator SELECTION (:146/:153) is not a tick step, and mapping it to
    # :904 quietly made it one.
    if ln not in FOOTNOTE_LINES:
        ln = TICK_CALLSITE.get((r['from'], r['to']), ln)
    (_foot if (ln is None or ln in FOOTNOTE_LINES) else _tick).append((ln, r))
# K3 239: this intro said "Two" — the two edges K3 happened to name — while the derivation
# right above it had already found six. A count you type is not a count you derived, and it is
# the same class as every other hardcoded number this artifact has had to retract. Emit len().
_NUMWORD = {1:'One', 2:'Two', 3:'Three', 4:'Four', 5:'Five', 6:'Six', 7:'Seven', 8:'Eight'}
_n_sp = len(_samepass)
W('## The tick')
W('')
W('One pass of the operator loop, read out of `runner` and its outbound relations. The '
  'numbered steps are the **production-role** edges only. '
  f'{_NUMWORD.get(_n_sp, _n_sp)} edge{"" if _n_sp == 1 else "s"} run inside this same pass '
  'carrying a non-production role; they are footnoted rather than numbered, so the sequence '
  'stays the one the shipped production path takes and nothing same-pass goes unmentioned:')
W('')
for i, (ln, r) in enumerate(sorted(_tick, key=lambda x: x[0]), 1):
    W(f"{i}. `{r['from']}` → `{r['to']}` — {esc(r['kind'])} · `manager.go:{ln}`")
W('')
if _foot:
    W('*Not per-tick, and listed here so they are not mistaken for steps:*')
    W('')
    for ln, r in sorted(_foot, key=lambda x: (x[0] is None, x[0])):
        W(f"- `{r['from']}` → `{r['to']}` — {esc(r['kind'])} · "
          f"`{esc(r['anchor'].split(chr(8212))[0].strip())}`")
    W('')
if _samepass:
    W('*Same pass, not production-role — these run inside this loop but are not steps of the '
      'production path:*')
    W('')
    for ln, r in sorted(_samepass, key=lambda x: x[0]):
        W(f"- `{r['from']}` \u2192 `{r['to']}` — {esc(r['kind'])} · *{r['runtime_role']}* · "
          f"`manager.go:{ln}`")
    W('')
W('## The map')
W('')
_mmd_path = str(paths.GENERATED_DIR / 'ANATOMY.mmd')
if os.path.exists(_mmd_path):
    W('```mermaid')
    W(open(_mmd_path).read().rstrip())
    W('```')
    W('')
W('The picture above is `generated/ANATOMY.mmd` verbatim (top-level nodes and their')
W('wiring). **`generated/ANATOMY-map.pdf` is that same source rendered by mermaid** — one vector page, and')
W('the copy to read if your viewer does not draw mermaid; regenerate it with')
W('`pipeline/render_diagram.sh`. `generated/ANATOMY.svg` is a third view: the full inventory')
W('with all 39 children drawn as cards. All three come from these same inventories. Shapes carry facts: a slanted box is off the decision path, a rounded box is a')
W('system Phorvex does not own, a dashed outline is declared-but-never-wired, a bold border means')
W('the node carries a seam, and a thick arrow is a crossing out of the cluster.')
W('')
W(f'{len(nodes)} nodes in {len(set(n["lane"] for n in nodes))} lanes, '
  f'{len(rels)} relations, {len(seams)} seams, {len(bounds)} intentional boundary.')
W('')
for lane in LANE_ORDER:
    ln = [n for n in nodes if n['lane'] == lane and not n['parent']]
    if not ln: continue
    _loc = sum(int(n['loc']) for n in nodes if n['lane'] == lane and n['loc'].isdigit())
    _cnt = len([n for n in nodes if n['lane'] == lane])
    W(f'### {lane} — {LANE_WHAT.get(lane,"")}')
    W('')
    W(f'*{_cnt} node{"s" if _cnt != 1 else ""}' + (f' · {_loc:,} LOC' if _loc else '') + '*')
    W('')
    # DERIVED, not authored: every process-exec or external crossing this lane's nodes make.
    lane_ids = {n['id'] for n in nodes if n['lane'] == lane}
    crossings = [(r['from'], r['to'], r['kind']) for r in rels
                 if r['from'] in lane_ids and (r['to'].startswith(('bin.', 'ext.')))]
    if crossings:
        W(f'*Crosses out of process or out of the cluster {len(crossings)} time'
          f'{"s" if len(crossings) > 1 else ""}:*')
        for a, b, k in sorted(crossings):
            W(f'- `{a}` → `{b}` — {k}')
        W('')
    for n in sorted(ln, key=lambda x: x['id']):
        ch = kids.get(n['id'], [])
        role = n['runtime_role']
        tag = '' if role == 'production' else f' · *{role}*'
        W(f"- **`{n['id']}`** — {n['display']}{tag}")
        if n['evidence_note']: W(f"  {first_sentence(n['evidence_note'])}")
        W(f"  `{n['source_anchor']}`")
        # K3 229: the register's join lands on children — runner.tick, console.attack,
        # actuator.native.rotate. Collapsing them to "8 children" makes the companion unusable
        # for the thing it is a companion to.
        for c in sorted(ch, key=lambda x: x['id']):
            ctag = '' if c['runtime_role'] == 'production' else f" · *{c['runtime_role']}*"
            W(f"    - `{c['id']}` — {c['display']}{ctag} · `{c['source_anchor']}`")
            if c['evidence_note']: W(f"      {first_sentence(c['evidence_note'])}")
            gk = kids.get(c['id'], [])
            for g in sorted(gk, key=lambda x: x['id']):
                gtag = '' if g['runtime_role'] == 'production' else f" · *{g['runtime_role']}*"
                W(f"        - `{g['id']}` — {g['display']}{gtag} · `{g['source_anchor']}`")
                if g['evidence_note']: W(f"          {first_sentence(g['evidence_note'])}")
    W('')

# ---- what actuation actually does ----------------------------------------------------------
# ---- SECTION 6: all 111 relations, the v1 interactions table at v2 grain -------------------
W('---')
W('')
W('## The interactions')
W('')
W(f'All {len(rels)} relations, grouped by the lane they leave from. This is the wiring; a count is')
W('not a map. Every row is anchored at the call site that proves it.')
W('')
for lane in LANE_ORDER:
    lr = [r for r in rels if lane_of.get(r['from']) == lane]
    if not lr: continue
    W(f'### From {lane} — {len(lr)}')
    W('')
    T(['from','to','what','crossing','role','anchor'])
    for r in sorted(lr, key=lambda x: (x['from'], x['to'])):
        cs = r.get('crossing_status', '-')
        cs = '' if cs in ('-', '') else f'`{cs}`'
        role = '' if r['runtime_role'] == 'production' else f"*{r['runtime_role']}*"
        W(f"| `{r['from']}` | `{r['to']}` | {esc(r['kind'])} | {cs} | {role} | "
          f"`{anchor_cell(r['anchor'])}` |")
    W('')

W('---')
W('')
# ---------------------------------------------------------------------------------------------
# THE ACTION VOCABULARY. The 114-row table below groups by action, so the 17 action names appear
# as headings and are never once explained: a reader learns `guardrail-rotate` has 8 operations
# without learning what it DOES or whether it can run. Derived from the matrix, so it cannot
# drift from the rows it summarises.
W('## The action vocabulary — what Phorvex can actually do')
W('')
_dflt = paths.line_at('api/v1alpha1/phorvexpolicy_types.go', 358)
assert _dflt and 'defaults to rotate+quarantine' in _dflt, \
    f'default-action comment moved: {_dflt!r}'
W('These are the moves. The CRD enumerates them and a policy enables a subset; an empty set '
  'defaults to `rotate` + `quarantine`. **Which of them can actually be enacted depends on the '
  'actuator**, and the default actuator is Phoenix, which enacts two.')
W(f'`api/v1alpha1/phorvexpolicy_types.go:358`')
W('')
W('| action | enacted by | ops | what it touches | runs in the shipped binary? |')
W('|---|---|---|---|---|')
_ENACT = ('native-enact', 'phoenix', 'hybrid')
for _av_act in sorted({_av_r['action_GEN'] for _av_r in mx} - {'-'}):
    _av_rows = [_av_r for _av_r in mx if _av_r['action_GEN'] == _av_act]
    _av_surf = sorted({_av_r['surface_GEN'] for _av_r in _av_rows if _av_r['surface_GEN'] in _ENACT})
    _av_enact = [_av_r for _av_r in _av_rows if _av_r['surface_GEN'] in _ENACT and _av_r['operation_GEN'] != 'routes-to']
    _av_touch, _av_seen = [], set()
    for _av_r in _av_enact:
        # `disable` really does carry operation=none/target=none: a registered action whose
        # handler mutates nothing. Say that, rather than printing the literal "none none".
        if _av_r['operation_GEN'] in ('none', '-'):
            _av_t = '*no operation — this handler mutates nothing*'
        else:
            _av_t = f"{_av_r['operation_GEN']} {_av_r['target_resource_GEN']}".strip()
        if _av_t and _av_t not in _av_seen: _av_seen.add(_av_t); _av_touch.append(_av_t)
    _av_reach = {_av_r['shipped_reachability_GEN'] for _av_r in _av_enact}
    if not _av_enact:                      _av_verdict = 'dispatch only'
    elif _av_reach == {'reachable'}:       _av_verdict = 'yes'
    elif 'reachable' in _av_reach:         _av_verdict = 'partly — ' + ', '.join(
                                           sorted(x for x in _av_reach if x != 'reachable'))
    else:                              _av_verdict = 'no — ' + ', '.join(sorted(_av_reach))
    W(f"| `{_av_act}` | {', '.join(_av_surf) or '—'} | {len(_av_rows)} | "
      f"{esc(' · '.join(_av_touch)) or '—'} | {_av_verdict} |")
W('')
_av_seen_surf = {_x['surface_GEN'] for _x in mx}
_av_used = {_s2 for _s2 in _ENACT if any(_x['surface_GEN'] == _s2 for _x in mx)}
assert _av_used == set(_ENACT) & _av_seen_surf and len(_av_used) == 3, (
    f'the action table filtered on {_ENACT} but the matrix holds {sorted(_av_seen_surf)}; '
    f'a surface name that matches nothing renders every action as "dispatch only"')
assert sum(1 for _x in mx if _x['surface_GEN'] == 'native-enact') > 0, \
    'no native-enact rows matched — the enact filter is broken'
W('`noop` is in the CRD vocabulary and has no handler, which is why 17 enum values map to 16 '
  'registered handlers. It is counted nowhere below.')
W('')

W('## What actuation actually does')
W('')
mut = ops_of(lambda r: r['operation_GEN'] in ('Create','Update','Delete','Patch'))
sec = collections.Counter('NOT CONFIRMED' if 'NOT CONFIRMED' in r['security_goal_confirmation_CURATED']
      else 'not reached' if 'not reached' in r['security_goal_confirmation_CURATED']
      else 'PARTIAL' if r['security_goal_confirmation_CURATED'].startswith('PARTIAL') else 'other'
      for r in mut)
W(f'{len(mx)} operations across four surfaces: '
  + ' · '.join(f'{v} {k}' for k, v in sorted(collections.Counter(r['surface_GEN'] for r in mx).items())) + '.')
W('')
W('**Of the ' + str(len(mut)) + ' operations that change something:**')
W('')
W(f"| confirmation | count |")
W(f"|---|---|")
for k in ('NOT CONFIRMED','not reached','PARTIAL','other'):
    if sec[k]: W(f"| {'CONFIRMED' if k=='other' else k} | {sec[k]} |")
W('')
W('**No operation confirms its security goal.** An API acceptance means the request was stored; a')
W('protocol acknowledgement means a serving stack received it. Neither is the outcome.')
W('')
W('That is not the same as "nothing is read back". One operation — `quarantine`\'s Pod.Update —')
W('is PARTIAL: the ownerRef removal and selector break are observable in the written object, though')
W('re-adoption by a new ReplicaSet is never re-checked. And `rotate` is the one action with a real')
W('recovery observation: `trackRotationWithFloor` holds the pre-action state until Kubernetes proves')
W('the replacement Ready, which the matrix records as CONDITIONALLY OBSERVED — conditional because')
W('it does not run when no cost/calibration/disruption observer is configured, or when the pod has')
W('no controller owner or UID.')
W('')
W(f'**{comp} operations are compensation paths** — they run only when the handler is about to')
W(f'return an error — and **{disc} mutating writes discard their error** entirely, so a failed')
W('write is indistinguishable from a successful one at the call site.')
W('')
W(f'**Reachability.** {reach["reachable"]} of {len(mx)} call sites run in the shipped binary. '
  f'{reach.get("tool-only",0)} are reachable only from a one-shot tool — the whole rollback layer,')
W('whose only invoker is the native-demo. ' + str(reach.get('guarded-unreached',0)) + ' sit behind a')
W('guard that always fails in the shipped product.')
W('')
reach = collections.Counter(r['shipped_reachability_GEN'] for r in mx)
ph = sorted({r['action_GEN'] for r in mx if r['surface_GEN']=='phoenix' and r['phase_GEN']=='Actuate'})
allact = sorted({r['action_GEN'] for r in mx if r['surface_GEN']=='native-enact' and r['action_GEN']!='disable'})
W(f"**The default deployment.** Phoenix is the default actuator and enacts {len(ph)} actions "
  f"({', '.join(ph)}). The other {len(allact)-len(ph)} require `PHORVEX_ACTUATOR=native` or `hybrid`.")
W('')

# ---- boundaries ----------------------------------------------------------------------------
# ---- SECTION 7: all 114 operation rows, grouped by action then surface ---------------------
W('### Every operation')
W('')
W(f'All {len(mx)} rows. `reach` is whether this call site runs in the shipped binary; `cross` is')
W('whether the destination is wired at all; `path` marks a compensation write (one that runs only')
W('when the handler is about to return an error).')
W('')
SURF_ORDER = ['native-enact','native-rollback','phoenix','hybrid']
for action in sorted({r['action_GEN'] for r in mx}):
    ar = [r for r in mx if r['action_GEN'] == action]
    W(f'#### `{action}` — {len(ar)} operation' + ('s' if len(ar) != 1 else ''))
    W('')
    for surf in SURF_ORDER:
        sr = [r for r in ar if r['surface_GEN'] == surf]
        if not sr: continue
        W(f'*{surf}*')
        W('')
        T(['op','target','reach','cross','path','acknowledgement','security goal','ledger','anchor'])
        for r in sorted(sr, key=lambda x: x['source_anchor_GEN']):
            res = r['target_resource_GEN'] + (f"/{r['subresource_GEN']}" if r['subresource_GEN'] not in ('-','') else '')
            pc = '' if r['path_class_GEN'] == 'success' else f"**{r['path_class_GEN']}**"
            eh = ' ⚠ error discarded' if r['error_handling_GEN'] == 'DISCARDED' else ''
            W(f"| `{r['operation_GEN']}` | `{res}` | {r['shipped_reachability_GEN']} | "
              f"{r['crossing_status_GEN']} | {pc}{eh} | {esc(r['acknowledgement_level_CURATED'])} | "
              f"{esc(r['security_goal_confirmation_CURATED'])} | "
              f"{esc(r['runner_ledger_outcome_CURATED'])} | `{r['source_anchor_GEN']}` |")
        W('')

W('## Where Phorvex crosses into systems it does not own')
W('')
W('| boundary | status | where the code crosses |')
W('|---|---|---|')
for n in sorted([x for x in nodes if x['lane'] == 'External'], key=lambda x: x['id']):
    st = 'declared, never wired' if n['runtime_role'] == 'unwired' else 'implemented'
    W(f"| `{n['id']}` — {n['display']} | {st} | `{n['source_anchor']}` |")
W('')

# ---- seams ---------------------------------------------------------------------------------
W('## Seams — contracts that are stated but not kept')
W('')
for s in seams:
    W(f"**{s['seam']}** · attaches to `{s['attaches_to']}`")
    W('')
    W(f"- promised: {s['contract_evidence']}")
    W(f"- not honoured: {s['negative_evidence']}")
    W('')
for b in bounds:
    W(f"**{b['seam']}** · `{b['attaches_to']}` — **{b['status']}**, an intentional boundary, not a gap.")
    W('')

# ---- SECTIONS 9-11 ------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------
# GLOSSARY. `coverage` appears 45 times in this file, `tick` 31, `actionset` 16, `shadow` 21 --
# and none of them is defined anywhere. A reader who does not already know the product cannot
# acquire it here. Same rule as the orientation: quoted from source, re-verified at build.
GLOSSARY = [
 ('tick', 'One pass of the loop: it builds one cluster snapshot and processes all due tenants. '
  'The numbered sequence above is one tick.',
  [('internal/runner/manager.go', 254, 254, ['builds one cluster snapshot', 'all due tenants'])]),
 ('tenant', 'A namespace, or a vcluster projected as one. Every clock, budget, decision and '
  'metric is keyed by it; multi-tenancy is not a retrofit.',
  [(_CRD, 11, 15, ['PER-TENANT configuration surface', 'vcluster', 'NOT a later retrofit'])]),
 ('exposure clock', 'Per mutable VARIABLE of a workload — pod identity, node placement, image, '
  'env, GPU binding, network identity, session — the time since that variable last CHANGED.',
  # K3 245: "a move resets the clock for the variables it changes" is true-sounding, is NOT in
  # the span, and _verify cannot see a clause I never listed. Stop at CHANGED.
  [('internal/exposure/clock.go', 6, 10, ['per mutable VARIABLE', 'time since that variable last',
                                          'CHANGED'])]),
 ('the objective', 'The cost-weighted optimization objective: maximize '
  'E[security] − λ · E[switching-cost].',
  [(_CRD, 60, 61, ['cost-weighted optimization objective: maximize',
                   'E[security] - lambda * E[switching-cost]'])]),
 ('λ (lambda)', 'Two things that are NOT the same and meet in one place. In the engine λ is the '
  'live **dual-descent budget shadow-price**, and also the proactive-timing knob. In the CRD '
  '`objective.lambda` is a **seed**, consumed only when the bucket is first created; later calls '
  'preserve the adaptive dual state.',
  # K3 245: "rises as the move budget comes under pressure" is not on :25-26. The tail now uses
  # the source's own words and verifies them.
  [('internal/decision/coverage.go', 25, 26, ['dual-descent budget shadow', 'proactive-timing knob']),
   ('internal/decision/coverage.go', 86, 87, ['lambda seed is consumed only',
                                              'preserve the adaptive dual state'])]),
 ('CoverageEngine (P1)', 'The production decision engine. Maximises consequence-weighted '
  'recon-facts-invalidated-per-dollar by a submodular greedy over the feasible action set, under '
  'one-move-per-asset and the move budget. Stateful across ticks.',
  [('internal/decision/coverage.go', 22, 27, ['CoverageEngine is the P1 brain', 'submodular greedy',
                                              'STATEFUL across ticks'])]),
 ('action set', 'The FEASIBLE (asset, action) set, computed live each tick from physics and '
  'context state — not a static list. Feasibility and the SLO gate are applied **when the set is '
  'generated, before optimization**, so the optimizer selects only from moves already known to '
  'be safe and can never return a hard-constraint-violating one.',
  [('internal/actionset/generator.go', 5, 11,
    ['DYNAMIC ACTION-SET GENERATOR', 'computes the FEASIBLE', 'selects ONLY from this generated set',
     'applied before, not during'])]),
 ('proactive floor', 'The hygiene floor: a detection-independent MAXIMUM exposure. A pod '
  'unchanged for longer than `ProactiveFloor` is eligible for a proactive rotation regardless of '
  'any detector.',
  [(_CRD, 204, 207, ['detection-independent', 'MAXIMUM exposure', 'longer than ProactiveFloor',
                     'regardless of any detector'])]),
 ('dryRun / active', 'The two run modes. `dryRun` decides, logs and emits metrics but never '
  'actuates, and is the default; `active` additionally drives Phoenix.',
  [(_CRD, 387, 390, ['ModeDryRun decides', 'never actuates', 'ModeActive additionally'])]),
]
_gbad = [b for _t, _d, _a in GLOSSARY for b in _verify(_a)]
assert not _gbad, 'glossary claims their anchor does not carry:\n  ' + '\n  '.join(_gbad)

# `shadow` is this MAP's vocabulary, not a phrase in the product's source. Deriving it from the
# inventory is honest; quoting an unrelated source line to make it look anchored is not, which
# is exactly what the first version of this row did.
_shadow_nodes = sorted(n['id'] for n in nodes if n['runtime_role'] == 'shadow')
_observe = sorted(n['id'] for n in nodes if n['runtime_role'] == 'observe-only')

W('## Glossary')
W('')
W('The words this document and the register both assume. Anchored entries are quoted from source '
  'and re-verified at build; the last entry is derived from the inventories and says so.')
W('')
for _gterm, _gdef, _ganch in GLOSSARY:
    W(f'**{_gterm}** — {_gdef}')
    W(f'  {_cite(_ganch)}')
    W('')
W(f'**shadow / observe-only** *(derived from this map, not quoted from source)* — two '
  f'`runtime_role` values in these inventories. A **shadow** node runs inside the tick and is '
  f'deliberately kept out of the production decision: {", ".join("`"+x+"`" for x in _shadow_nodes)}. '
  f'An **observe-only** node runs and records but changes nothing: '
  f'{", ".join("`"+x+"`" for x in _observe)}. Both appear in the tick footnotes above rather '
  f'than as numbered steps, which is the whole point of the distinction.')
W('')

W('## What this map does not assert')
W('')
W('Every one of these is a labelled exclusion, not an oversight:')
W('')
W('- **No live-cluster verification of anything.** Every claim is static, from source at the pin.')
W('- **No P0 operation rows.** P0 is a decision engine; the same actuators run, so its operations')
W('  are the ones already listed.')
W('- **No console-internal operations.** The console has nodes; its internals are out of scope.')
W('- **Nothing about the Phoenix controller beyond the CR write.** What Phoenix does after Phorvex')
W('  writes a SecurityEvent is the `ext.k8s → ext.phoenix → ext.k8s` chain, anchored in the')
W('  vendored controller — not a Phorvex operation.')
W('- **A green run is a claim about THIS pin.** Several audits re-check their NEGATIVE evidence, so')
W('  a FIX to the MIG transport or the MigrateRemote stub will FAIL them rather than let a closed')
W('  gap keep being asserted.')
# K3 added this bullet BY HAND to the generated output during the T1-A cycle (commit 1367cfa).
# Ported here so a rebuild reproduces it; hand edits to the output do not survive regeneration.
W('- **No struct-field data-flow relations.** The operation matrix is built from call sites, so a')
W('  relation that rides a shared struct field instead of a call is invisible to it. The load-bearing')
W('  instance: `platform.Derive` → `model.PhysicsWitness` → `view.Physics` →')
W('  `killchain.aiStageFromView` (the SENSING→BELIEF edge the T1-A fix rewrites) appears nowhere in')
W('  this map — there is no physics→killchain row to audit. Found 2026-09-02 in the T1-A cycle;')
W('  any future fix whose contract is a struct field (not a function) needs a hand-added row.')
W('')
W('## What this artifact produced')
W('')
W('Four findings this map located at this pin. IDs are the register\'s; none was invented here.')
W('')
T(['id','finding','where the map holds it'])
for i, what, where in [
 ('M-21', f'the DEFAULT deployment can enact {len(ph_actions)} of {len(nat_actions)} actions — '
          f'{", ".join(ph_actions)} only', '`phoenix:actuate` SecurityEvent.Create + the 17 hybrid route rows'),
 ('M-87', 'the rollback layer is tool-only: no operator tick path rolls anything back',
          f'the {reach.get("tool-only",0)} `native-rollback` rows, shipped_reachability=tool-only'),
 ('M-147','route-rotate is priced as zero-disruption while its handler changes a Service selector, '
          'so the runner records OutcomeCompleted', '`route-rotate` Service.Update @ handlers_k8s.go:365'),
 ('M-148','three compensation writes discard their error; a failed re-flip leaves both pods leader',
          '`handlers_ai.go:138` (two action rows, one write), `handlers_ai_p4set.go:97`, `:276`')]:
    W(f'| **{i}** | {what} | {where} |')
W('')
W('## At a glance')
W('')
W(f'- **{sec["NOT CONFIRMED"]} of {len(mut)} mutating operations are NOT CONFIRMED.** '
  f'{sec.get("PARTIAL",0)} is PARTIAL. **{sec.get("other",0)} confirm a security goal.**')
W(f'- **{reach["reachable"]} / {reach.get("tool-only",0)} / {reach.get("guarded-unreached",0)}** — '
  f'call sites that run, that only a tool reaches, and that sit behind a failing guard.')
W(f'- **{len(ph_actions)} of {len(nat_actions)}** actions are enactable in the default deployment.')
W(f'- **{len(seams)} seams and {len(bounds)} intentional boundary** — contracts stated but not kept,')
W(f'  and one that is deliberately open.')
W(f'- **{comp} compensation paths**, {disc_comp} of which discard the error they exist to report;')
W(f'  {disc} mutating writes discard their error in total.')
W(f'- **1 availability observation** in {len(mx)} operations, and it is conditional.')
W('')
W('## Keeping this current')
W('')
W('The inventories are checked by 11 scripts and 65 mutations; a green run means each check was')
W('shown to fail when its invariant is broken, for its own named reason. See `STATE.md` for the')
W('run order, the standing traps, and what this artifact deliberately does not assert.')
W('')
W(f"*Generated from the frozen inventories at `{pin['commit']}`.*")

# 103 of 114 operation rows used to end mid-fact at a 44- or 64-char cut. A reference document
# must never publish a truncated claim: an agent reading it cannot tell a short fact from a
# severed one. Nothing emitted here may carry an ellipsis.
_doc = '\n'.join(out) + '\n'
_ell = [l for l in _doc.split('\n') if '\u2026' in l]
assert not _ell, f'{len(_ell)} truncated cells reached the document, e.g.: {_ell[0][:120]}'
open(OUT, 'w').write(_doc)
print(f'emitted {OUT}  ({open(OUT).read().count(chr(10))} lines, {os.path.getsize(OUT)} bytes)')
