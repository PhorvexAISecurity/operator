#!/usr/bin/env python3
"""Emit the anatomy as a LONG SCROLLABLE page with the map broken into readable pieces.

Why this exists: the one-canvas render (ANATOMY_V2.pdf) is complete and unreadable -- 60 nodes and
88 edges on one sheet means edges no reader can trace. No layout engine fixes that; decomposition
does. This emits the same frozen inventories as ~17 small diagrams you scroll through, each small
enough that every edge is short.

Single source of truth: the tick is PARSED OUT OF the frozen PHORVEX_ANATOMY_V2.md rather than
re-derived, so this page cannot disagree with the document it accompanies.
"""
import paths
import csv, os, re, json, html, collections

HERE = os.path.dirname(os.path.abspath(__file__))
DOC  = str(paths.ANATOMY_DOC)
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
PIN = json.load(open(os.path.join(HERE, 'SOURCE_PIN.json')))['commit']

MERMAID_RESERVED = {'graph','subgraph','end','style','linkstyle','classdef','class','click',
                    'flowchart','direction','default','call','href','link','callback','o','x','v'}
def nid(i):
    s = re.sub(r'[^A-Za-z0-9]', '_', i)
    return s + '_n' if s.lower() in MERMAID_RESERVED else s
def esc(t): return html.escape(str(t), quote=True)
def mlab(t):
    """Mermaid label: no brackets, quotes or pipes, and <br/> for wraps."""
    t = re.sub(r'\s+', ' ', str(t)).strip()
    return t.replace('"', "'").replace('[', '(').replace(']', ')').replace('|', '/')

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
 'Console':'the operator-facing surface; off the decision path, which is not the same as read-only',
 'Tools':'one-shot binaries and analysis paths, not the operator loop',
 'Product':'the shipped user-facing surface',
 'Delivery':'how the product is composed and reaches a cluster',
 'External':'systems Phorvex does not own, at the point its code crosses into them',
}

by_id  = {n['id']: n for n in nodes}
parent = {n['id']: n['parent'] for n in nodes}
kids   = collections.defaultdict(list)
for n in nodes:
    if n['parent']: kids[n['parent']].append(n)
def up(i):
    seen = set()
    while parent.get(i) and i not in seen:
        seen.add(i); i = parent[i]
    return i
lane_of = {n['id']: n['lane'] for n in nodes}
top = [n for n in nodes if not n['parent']]

THEME = ("%%{init:{'theme':'base','themeVariables':{"
         "'darkMode':false,"
         "'background':'#ffffff','mainBkg':'#eaf0f4','primaryColor':'#eaf0f4',"
         "'primaryTextColor':'#1a1e25','primaryBorderColor':'#4d7d97',"
         "'secondaryColor':'#f4f6f8','tertiaryColor':'#ffffff',"
         "'lineColor':'#7d8c9c','textColor':'#1a1e25','nodeTextColor':'#1a1e25',"
         "'titleColor':'#1a1e25','edgeLabelBackground':'#ffffff',"
         "'clusterBkg':'#f6f8fa','clusterBorder':'#c9d3dc',"
         "'fontFamily':'IBM Plex Sans, sans-serif','fontSize':'13px'}}}%%")

def shape(n, ghost=False):
    """Shape carries a fact, exactly as in the frozen .mmd."""
    i, d = nid(n['id']), mlab(n['display'])
    if ghost:                              return f'{i}("{d}")'
    if n['lane'] == 'External':            return f'{i}(["{d}"])'
    if n['runtime_role'] in ('tool','benchmark'): return f'{i}[/"{d}"/]'
    return f'{i}["{d}"]'

def edge(r):
    if r.get('crossing_status') == 'declared-unwired' or \
       by_id.get(r['to'], {}).get('runtime_role') == 'unwired':      return '-.->'
    if by_id.get(r['to'], {}).get('lane') == 'External':             return '==>'
    if r['runtime_role'] not in ('production',):                     return '-.->'
    return '-->'

md_section_used = {}
def md_section(title, stop):
    """Lift a section out of the FROZEN document. Same rule as the tick: this page must not be
    able to state anything the document does not already state."""
    seg = md.split(f'## {title}', 1)[1].split(f'## {stop}', 1)[0]
    md_section_used[title] = True
    return seg.strip('\n')

def md_inline(t):
    t = esc(t)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<em>\1</em>', t)
    return t

def md_block(seg):
    """Markdown -> html for the sections lifted from the frozen document.

    Paragraphs in the source are HARD-WRAPPED, so a line is not a paragraph. The first version
    emitted one <p> per source line and shredded the evidence prose into fragments mid-sentence.
    A paragraph runs until a blank line or a structural token, exactly as markdown says.
    """
    out, i, lines = [], 0, seg.split('\n')
    SPECIAL = ('|', '- ', '#', '>', '---')
    def special(ln):
        return (not ln.strip()) or ln.startswith(SPECIAL)
    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            i += 1; continue
        if ln.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                rows.append([c.strip() for c in lines[i].strip('|').split('|')]); i += 1
            rows = [r for r in rows if not all(set(c) <= set('-: ') for c in r)]
            out.append('<div class="tw"><table>')
            for j, r in enumerate(rows):
                tg = 'th' if j == 0 else 'td'
                out.append('<tr>' + ''.join(f'<{tg}>{md_inline(c)}</{tg}>' for c in r) + '</tr>')
            out.append('</table></div>')
            continue
        if ln.startswith('#### '):
            out.append(f'<h4>{md_inline(ln[5:].strip())}</h4>'); i += 1; continue
        if ln.startswith('### '):
            out.append(f'<h3>{md_inline(ln[4:].strip())}</h3>'); i += 1; continue
        if ln.strip() == '---':
            i += 1; continue
        if ln.startswith('>'):
            q = []
            while i < len(lines) and lines[i].startswith('>'):
                q.append(lines[i].lstrip('>').strip()); i += 1
            out.append('<div class="note">' + ' '.join(md_inline(x) for x in q if x) + '</div>')
            continue
        # An ANCHORED ENTRY is a claim line whose NEXT line is an indented backticked anchor.
        # Testing only for a leading `**` mis-read every bold-led paragraph in the evidence
        # sections as an entry and boxed it.
        anchored = i + 1 < len(lines) and lines[i+1].startswith('  `')
        if ln.startswith('- ') or (anchored and ln.startswith('**')):
            body = ln[2:] if ln.startswith('- ') else ln
            buf = [body]
            i += 1
            while i < len(lines) and not special(lines[i]) and not lines[i].startswith('  `'):
                buf.append(lines[i].strip()); i += 1
            anch = ''
            if i < len(lines) and lines[i].startswith('  `'):
                anch = lines[i].strip().strip('`'); i += 1
            out.append(f'<div class="entry">{md_inline(" ".join(buf))}'
                       + (f'<span class="anch-i">{esc(anch)}</span>' if anch else '') + '</div>')
            continue
        buf = []
        while i < len(lines) and not special(lines[i]):
            buf.append(lines[i].strip()); i += 1
        if buf:
            out.append(f'<p>{md_inline(" ".join(buf))}</p>')
    return '\n'.join(out)

# ---------------------------------------------------------------------------------- the tick
# Parsed from the FROZEN document, never re-derived: the page must not be able to disagree with it.
md = open(DOC).read()
tick_sec = md.split('## The tick', 1)[1].split('## The map', 1)[0]
STEPS = re.findall(r'^\d+\.\s+`([^`]+)`\s*→\s*`([^`]+)`\s*—\s*(.+?)\s*·\s*`([^`]+)`', tick_sec, re.M)
FOOTS = re.findall(r'^-\s+`([^`]+)`\s*→\s*`([^`]+)`\s*—\s*(.+?)\s*·\s*(.+)$', tick_sec, re.M)
assert STEPS, 'no tick steps parsed out of the frozen document'
TICK_INTRO = tick_sec.strip().split('\n')[0].strip()

def tick_diagram():
    # LR, not TB: the tick is a fan-out, and TB spread it 884x233 -- a wide strip with
    # unreadable text in a scrolling column. LR turns the same fan-out vertical (884x700).
    L = [THEME, 'flowchart LR']
    seen, order = set(), []
    for a, b, k, ln in STEPS:
        for x in (a, b):
            if x not in seen and x in by_id: seen.add(x); order.append(x)
    for x in order: L.append('  ' + shape(by_id[x]))
    for i, (a, b, k, ln) in enumerate(STEPS, 1):
        if a in by_id and b in by_id:
            L.append(f'  {nid(a)} -->|"{i}"| {nid(b)}')
    return '\n'.join(L)

def lane_members(lane):
    """Every node of the lane, children included. The diagram used to draw only TOP-LEVEL nodes
    while the table beneath it descended the whole tree, so Orchestration drew 1 box and listed 8,
    and Actuation drew 3 and listed 20 -- omitting all sixteen handlers. Children ARE the
    responsibility boundaries this map exists to name; drawing only their parent hides the point.
    """
    out = []
    def descend(n):
        out.append(n)
        for k in sorted(kids[n['id']], key=lambda x: x['id']):
            descend(k)
    for n in top:
        if n['lane'] == lane: descend(n)
    return out

def lane_diagram(lane):
    """The lane's own nodes (children included), plus the immediate neighbours it touches."""
    mine = lane_members(lane)
    ids  = {n['id'] for n in mine}
    inner, outer = [], collections.OrderedDict()
    for r in rels:
        a, b = r['from'], r['to']
        if a == b: continue
        a_in, b_in = a in ids, b in ids
        if a_in and b_in:
            inner.append((a, b, r))
        elif a_in and b in by_id:
            o = up(b)                      # collapse the far side to its lane's top-level node
            if o in ids or o not in by_id: continue
            outer.setdefault(o, None); inner.append((a, o, r))
        elif b_in and a in by_id:
            o = up(a)
            if o in ids or o not in by_id: continue
            outer.setdefault(o, None); inner.append((o, b, r))
    L = [THEME, 'flowchart LR']
    L.append(f'  subgraph L["{mlab(lane)}"]')
    for n in mine: L.append('    ' + shape(n))
    L.append('  end')
    for o in outer: L.append('  ' + shape(by_id[o], ghost=True))
    seen_e = set()
    for a, b, r in inner:
        if (a, b) in seen_e: continue
        seen_e.add((a, b))
        L.append(f'  {nid(a)} {edge(r)} {nid(b)}')
    # Children carry no relations of their own -- the edges attach to the PARENT node -- so the
    # 16 handlers drew as 16 floating boxes, which reads as a broken diagram rather than as the
    # true fact that they are named sub-responsibilities of one caller. An OPEN link (no
    # arrowhead) states containment without inventing a call that the inventory does not have.
    for n in mine:
        if n['parent'] and n['parent'] in ids:
            L.append(f"  {nid(n['parent'])} --- {nid(n['id'])}")
    _children = [n['id'] for n in mine if n['parent']]
    if _children:
        L.append('  classDef kid fill:#f2f6f9,stroke:#7d9db3,stroke-width:1px;')
        L.append('  class ' + ','.join(nid(i) for i in _children) + ' kid;')
    if outer:
        L.append('  classDef ghost fill:#f4f6f8,stroke:#c3ccd6,color:#66707c,stroke-dasharray:3 3;')
        L.append('  class ' + ','.join(nid(o) for o in outer) + ' ghost;')
    return '\n'.join(L), len(mine), len(outer), len(seen_e)

# ------------------------------------------------------------------------------------ the page
CSS = """
:root{
  --ground:#fcfcfb; --panel:#ffffff; --ink:#191d24; --muted:#5d6874; --faint:#828d99;
  --rule:#e4e8ed; --rule-soft:#eef1f5;
  --accent:#2f6f8f;      /* structure */
  --hazard:#b0601c;      /* declared-but-unwired, seams */
  --crossing:#5b4b93;    /* out of the cluster */
  --code:#f4f6f8;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --ground:#12151a; --panel:#171b21; --ink:#e6eaef; --muted:#9aa5b1; --faint:#7b8693;
  --rule:#262c34; --rule-soft:#1e232a;
  --accent:#6fb2d2; --hazard:#e0954f; --crossing:#a894e0; --code:#1b2027;
}}
:root[data-theme="dark"]{
  --ground:#12151a; --panel:#171b21; --ink:#e6eaef; --muted:#9aa5b1; --faint:#7b8693;
  --rule:#262c34; --rule-soft:#1e232a;
  --accent:#6fb2d2; --hazard:#e0954f; --crossing:#a894e0; --code:#1b2027;
}
*{box-sizing:border-box}
body{background:var(--ground);color:var(--ink);margin:0;
  font:400 15.5px/1.65 "IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:980px;margin:0 auto;padding:0 24px 120px}
code,.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
code{background:var(--code);border-radius:3px;padding:.1em .35em;font-size:.86em}

/* ---- masthead ---- */
header.mast{padding:64px 0 34px;border-bottom:1px solid var(--rule)}
.kicker{font-family:"IBM Plex Mono",monospace;font-size:11px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--accent);margin:0 0 14px}
h1{font-size:clamp(30px,5vw,44px);line-height:1.1;letter-spacing:-.022em;font-weight:600;
  margin:0 0 16px;text-wrap:balance}
.lede{font-size:17.5px;line-height:1.6;color:var(--muted);max-width:64ch;margin:0}
.facts{display:flex;flex-wrap:wrap;gap:0;margin:30px 0 0;border:1px solid var(--rule);
  border-radius:5px;overflow:hidden;background:var(--panel)}
.fact{flex:1 1 132px;padding:13px 16px;border-right:1px solid var(--rule)}
.fact:last-child{border-right:0}
.fact b{display:block;font:600 19px/1.2 "IBM Plex Mono",monospace;font-variant-numeric:tabular-nums}
.fact span{display:block;font-size:11px;color:var(--faint);letter-spacing:.05em;
  text-transform:uppercase;margin-top:4px}

/* ---- sticky nav ---- */
nav.jump{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--ground) 92%,transparent);
  backdrop-filter:blur(9px);border-bottom:1px solid var(--rule);margin-bottom:8px}
nav.jump ul{display:flex;gap:2px;list-style:none;margin:0;padding:9px 0;overflow-x:auto;
  scrollbar-width:thin}
nav.jump a{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--muted);
  text-decoration:none;padding:5px 9px;border-radius:4px;white-space:nowrap;display:block}
nav.jump a:hover{background:var(--rule-soft);color:var(--ink)}
nav.jump a:focus-visible{outline:2px solid var(--accent);outline-offset:1px}

/* ---- sections ---- */
section{padding-top:52px;scroll-margin-top:56px}
h2{font-size:25px;letter-spacing:-.015em;font-weight:600;margin:0 0 6px;text-wrap:balance}
h3{font-size:17px;margin:26px 0 8px;letter-spacing:-.01em}
h4{font-family:"IBM Plex Mono",monospace;font-size:13px;margin:20px 0 6px;color:var(--accent)}
h2 .num{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--accent);
  display:block;margin-bottom:7px;letter-spacing:.1em}
.what{color:var(--muted);margin:0 0 22px;max-width:68ch;font-size:15px}
p{max-width:68ch}

/* ---- diagram ---- */
figure{margin:0 0 26px;border:1px solid var(--rule);border-radius:6px;background:var(--panel);
  overflow:hidden}
.dgm{overflow-x:auto;padding:20px;background:#ffffff}
figure{background:#ffffff}
.mermaid svg text,.mermaid svg .nodeLabel,.mermaid svg .edgeLabel{fill:#1a1e25;color:#1a1e25}
.mermaid svg foreignObject div,.mermaid svg foreignObject span{color:#1a1e25!important}
.mermaid svg .edgeLabel rect,.mermaid svg .edgeLabel foreignObject div{background:#ffffff!important}
figcaption{background:var(--panel)}
.mermaid{min-width:min-content}
.mermaid svg{max-width:100%;height:auto;display:block;margin:0 auto}
figcaption{border-top:1px solid var(--rule-soft);padding:9px 16px;font-size:11.5px;
  color:var(--faint);font-family:"IBM Plex Mono",monospace;display:flex;
  justify-content:space-between;gap:14px;flex-wrap:wrap}

/* ---- tables ---- */
.tw{overflow-x:auto;border:1px solid var(--rule);border-radius:6px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font:600 10.5px/1 "IBM Plex Mono",monospace;letter-spacing:.09em;
  text-transform:uppercase;color:var(--faint);padding:11px 14px;
  border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--rule-soft);vertical-align:top}
tr:last-child td{border-bottom:0}
td.id{font-family:"IBM Plex Mono",monospace;font-size:12.5px;white-space:nowrap}
td.anch{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--muted)}
td.child .id{padding-left:15px;border-left:2px solid var(--rule);display:inline-block}

/* ---- tags ---- */
.tag{display:inline-block;font:600 10px/1 "IBM Plex Mono",monospace;letter-spacing:.06em;
  text-transform:uppercase;padding:3.5px 6px;border-radius:3px;border:1px solid;white-space:nowrap}
.t-tool{color:var(--muted);border-color:var(--rule)}
.t-unwired{color:var(--hazard);border-color:var(--hazard);border-style:dashed}
.t-ext{color:var(--crossing);border-color:var(--crossing)}
.t-shadow{color:var(--accent);border-color:var(--accent)}

/* ---- legend + notes ---- */
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);border-radius:6px;overflow:hidden;margin:22px 0}
.legend div{background:var(--panel);padding:13px 15px;font-size:13.5px}
.legend b{display:block;font-family:"IBM Plex Mono",monospace;font-size:11.5px;
  color:var(--accent);margin-bottom:3px}
.note{border-left:3px solid var(--accent);background:var(--panel);padding:13px 17px;
  margin:22px 0;font-size:14.5px;color:var(--muted);border-radius:0 5px 5px 0}
.note b{color:var(--ink)}
ol.steps{counter-reset:s;list-style:none;padding:0;margin:0}
ol.steps li{padding:8px 0 8px 42px;position:relative;border-bottom:1px solid var(--rule-soft);
  font-size:14px}
ol.steps li:last-child{border-bottom:0}
ol.steps li::before{counter-increment:s;content:counter(s);position:absolute;left:0;top:8px;
  font:600 11px/20px "IBM Plex Mono",monospace;width:24px;text-align:center;height:20px;
  background:var(--code);border-radius:3px;color:var(--accent)}
.entry{border-left:2px solid var(--rule);padding:2px 0 2px 15px;margin:0 0 15px;
  max-width:70ch}
.anch-i{display:block;font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--faint);
  margin-top:5px}
footer{margin-top:70px;padding-top:22px;border-top:1px solid var(--rule);font-size:13px;
  color:var(--faint)}
@media (max-width:640px){.wrap{padding:0 16px 80px}.fact{flex-basis:50%}}
"""

def tag(role, lane):
    if lane == 'External':      return '<span class="tag t-ext">external</span>'
    if role == 'unwired':       return '<span class="tag t-unwired">never wired</span>'
    if role in ('tool','benchmark'): return f'<span class="tag t-tool">{esc(role)}</span>'
    if role in ('shadow','observe-only'): return f'<span class="tag t-shadow">{esc(role)}</span>'
    return ''

H = []
W = H.append
W(f'<title>Phorvex Anatomy</title>')
W(f'<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" '
  f'href="https://fonts.gstatic.com" crossorigin>')
W('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
  'family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">')
W(f'<style>{CSS}</style>')

nav_items = [('what','What it is'), ('howto','How to read'), ('actions','Actions'),
             ('tick','The tick')] + [(l.lower(), l) for l in LANE_ORDER] + \
            [('interactions','Interactions'), ('operations','Operations'), ('crossings','Crossings'),
             ('seams','Seams'), ('glossary','Glossary'), ('produced','Findings'),
             ('glance','At a glance'), ('whole','Whole map')]
W('<nav class="jump"><div class="wrap" style="padding-bottom:0"><ul>')
for a, t in nav_items: W(f'<li><a href="#{esc(a)}">{esc(t)}</a></li>')
W('</ul></div></nav>')

W('<div class="wrap">')
W('<header class="mast">')
W('<p class="kicker">Actuation and control · pin ' + esc(PIN[:7]) + '</p>')
W('<h1>What Phorvex is made of, and what actually runs</h1>')
W('<p class="lede">Every node below is a code path, not a concept. This is the same frozen '
  'inventory as <code>PHORVEX_ANATOMY_V2.md</code>, drawn one lane at a time so the edges stay '
  'short enough to follow. Read it top to bottom: the tick first, then each lane in the order '
  'the loop reaches it.</p>')
W('<div class="facts">')
for v, k in [(len(nodes),'nodes'), (len(rels),'relations'), (len(LANE_ORDER),'lanes'),
             (len(STEPS),'tick steps'), (len(seams),'seams')]:
    W(f'<div class="fact"><b>{v}</b><span>{esc(k)}</span></div>')
W('</div></header>')

W('<div class="legend">')
for b, t in [('rectangle','On the operator decision path.'),
             ('slanted box','A tool or benchmark path — it runs, but never inside the tick.'),
             ('rounded box','A system Phorvex does not own.'),
             ('dashed arrow','Non-production role, or a destination declared and never wired.'),
             ('thick arrow','A crossing out of the cluster.'),
             ('faded node','A neighbour that belongs to another lane, shown for context.'),
             ('plain line, no arrow','Containment: the part below is a named sub-responsibility of the part above, not a call.')]:
    W(f'<div><b>{esc(b)}</b>{esc(t)}</div>')
W('</div>')

W('<section id="what">')
W('<h2><span class="num">ORIENTATION</span>What Phorvex is</h2>')
W(md_block(md_section('What Phorvex is', 'On the name')))
W('</section>')

W('<section id="howto">')
W('<h2><span class="num">METHOD</span>How to read this</h2>')
W(md_block(md_section('How to read this', 'The tick')))
W('</section>')

W('<section id="actions">')
W('<h2><span class="num">VOCABULARY</span>What Phorvex can actually do</h2>')
W(md_block(md_section('The action vocabulary — what Phorvex can actually do',
                      'What actuation actually does')))
W('</section>')

# ---- the tick ----
W('<section id="tick">')
W('<h2><span class="num">THE LOOP</span>The tick</h2>')
W(f'<p class="what">{esc(TICK_INTRO)}</p>')
W('<figure><div class="dgm"><pre class="mermaid">')
W(esc(tick_diagram()))
W(f'</pre></div><figcaption><span>one pass, {len(STEPS)} production-role steps</span>'
  f'<span>internal/runner/manager.go</span></figcaption></figure>')
W('<ol class="steps">')
for a, b, k, ln in STEPS:
    W(f'<li><code>{esc(a)}</code> → <code>{esc(b)}</code> — {esc(k)} '
      f'<span class="mono" style="color:var(--faint)">{esc(ln)}</span></li>')
W('</ol>')
if FOOTS:
    W('<div class="note"><b>Runs in the same pass, but is not a step.</b> '
      'These carry a non-production role, or happen once at startup rather than per tick.</div>')
    W('<div class="tw"><table><tr><th>from</th><th>to</th><th>what</th><th>where</th></tr>')
    for a, b, k, an in FOOTS:
        W(f'<tr><td class="id">{esc(a)}</td><td class="id">{esc(b)}</td><td>{esc(k)}</td>'
          f'<td class="anch">{esc(an.replace("`",""))}</td></tr>')
    W('</table></div>')
W('</section>')

# ---- one section per lane ----
for i, lane in enumerate(LANE_ORDER, 1):
    mine = [n for n in top if n['lane'] == lane]
    if not mine: continue
    dgm, nn, ng, ne = lane_diagram(lane)
    W(f'<section id="{esc(lane.lower())}">')
    W(f'<h2><span class="num">LANE {i:02d} / {len(LANE_ORDER)}</span>{esc(lane)}</h2>')
    W(f'<p class="what">{esc(LANE_WHAT[lane][0].upper() + LANE_WHAT[lane][1:])}.</p>')
    W('<figure><div class="dgm"><pre class="mermaid">')
    W(esc(dgm))
    W(f'</pre></div><figcaption><span>{nn} in this lane · {ng} neighbour'
      f'{"" if ng == 1 else "s"} shown faded</span><span>{ne} relations</span></figcaption></figure>')
    W('<div class="tw"><table><tr><th>node</th><th>what it is</th><th>role</th>'
      '<th>where in the source</th></tr>')
    for n in sorted(mine, key=lambda x: x['id']):
        # Walking ONE level of kids is the exact bug the SVG shipped with: the 16 native
        # handlers are grandchildren and vanished. Descend the whole tree; the assert below
        # is what caught it here.
        def descend(nd, d=0):
            yield nd, d
            for k in sorted(kids[nd['id']], key=lambda x: x['id']):
                yield from descend(k, d + 1)
        rows = [(nd, d > 0) for nd, d in descend(n)]
        for nd, is_child in rows:
            cls = ' class="child"' if is_child else ''
            W(f'<tr{cls}><td class="id"><span class="id">{esc(nd["id"])}</span></td>'
              f'<td>{esc(nd["display"])}</td>'
              f'<td>{tag(nd["runtime_role"], nd["lane"])}</td>'
              f'<td class="anch">{esc(nd["source_anchor"])}</td></tr>')
    W('</table></div></section>')

W('<section id="glossary">')
W('<h2><span class="num">TERMS</span>Glossary</h2>')
W('<p class="what">The words this map and the issue register both assume.</p>')
W(md_block(md_section('Glossary', 'What this map does not assert')))
W('</section>')

W('<section id="interactions">')
W('<h2><span class="num">EDGES</span>The interactions</h2>')
W(md_block(md_section('The interactions',
                      'The action vocabulary — what Phorvex can actually do')))
W('</section>')

W('<section id="operations">')
W('<h2><span class="num">EVIDENCE</span>What actuation actually does</h2>')
W(md_block(md_section('What actuation actually does',
                      'Where Phorvex crosses into systems it does not own')))
W('</section>')

# ---- crossings ----
cross = [r for r in rels if by_id.get(r['to'], {}).get('lane') == 'External']
W('<section id="crossings">')
W('<h2><span class="num">BOUNDARY</span>Where Phorvex crosses into systems it does not own</h2>')
W('<p class="what">Every point where operator code stops being the only thing that decides what '
  'happens. A destination marked <em>declared-unwired</em> is named in the code and has nothing '
  'on the other end.</p>')
W('<div class="tw"><table><tr><th>from</th><th>into</th><th>what it does</th><th>wired?</th>'
  '<th>where</th></tr>')
for r in sorted(cross, key=lambda x: (x['to'], x['from'])):
    cs = r.get('crossing_status', '')
    badge = ('<span class="tag t-unwired">never wired</span>' if cs == 'declared-unwired'
             else esc(cs) if cs else '')
    W(f'<tr><td class="id">{esc(r["from"])}</td><td class="id">{esc(r["to"])}</td>'
      f'<td>{esc(r["kind"])}</td><td>{badge}</td>'
      f'<td class="anch">{esc(r["anchor"].split(chr(8212))[0].strip())}</td></tr>')
W('</table></div></section>')

# ---- seams ----
W('<section id="seams">')
W('<h2><span class="num">GAPS</span>Seams — contracts stated but not kept</h2>')
W('<p class="what">A seam is a place where something is promised in one layer and absent in the '
  'next. Each one is attached to the exact edge it breaks.</p>')
W('<div class="tw"><table><tr><th>seam</th><th>attaches to</th><th>status</th></tr>')
for s in seams:
    st = esc(s['status'])
    if s['status'].startswith('NOT-A-GAP'):
        st = f'<span class="tag t-tool">{st}</span>'
    elif 'gap' in s['status']:
        st = f'<span class="tag t-unwired">{st}</span>'
    W(f'<tr><td>{esc(s.get("what") or s.get("seam") or list(s.values())[0])}</td>'
      f'<td class="id">{esc(s["attaches_to"])}</td><td>{st}</td></tr>')
W('</table></div></section>')

W('<section id="notasserted">')
W('<h2><span class="num">LIMITS</span>What this map does not assert</h2>')
W(md_block(md_section('What this map does not assert', 'What this artifact produced')))
W('</section>')

W('<section id="produced">')
W('<h2><span class="num">FINDINGS</span>What this artifact produced</h2>')
W(md_block(md_section('What this artifact produced', 'At a glance')))
W('</section>')

W('<section id="glance">')
W('<h2><span class="num">SUMMARY</span>At a glance</h2>')
W(md_block(md_section('At a glance', 'Keeping this current')))
W('</section>')

# ---- the whole thing, for reference ----
W('<section id="whole">')
W('<h2><span class="num">REFERENCE</span>The whole map at once</h2>')
W('<p class="what">Every top-level node and edge on one canvas — complete, and harder to read than '
  'the lanes above. It is here so nothing is only visible in pieces. Scroll it sideways if your '
  'screen is narrow.</p>')
W('<figure><div class="dgm"><pre class="mermaid">')
W(esc(THEME + '\n' + open(paths.GENERATED_DIR / 'ANATOMY.mmd').read()))
W(f'</pre></div><figcaption><span>{len(top)} top-level nodes</span>'
  f'<span>ANATOMY_V2.mmd verbatim</span></figcaption></figure>')
W('</section>')

W(f'<footer>Generated from the frozen inventories at <code>{esc(PIN[:12])}</code> by '
  f'<code>campaign/anatomy-v2/build_scroll_page.py</code>. The tick is parsed out of '
  f'<code>PHORVEX_ANATOMY_V2.md</code>, so this page cannot disagree with it. '
  f'Companion to <code>PHORVEX_MASTER_ISSUES_V2.md</code>.</footer>')
W('</div>')

# The page was silently missing 48% of the document -- the 114 operation rows, the 111
# relations and the confirmation vocabulary -- and nothing said so, because nothing compared the
# two. Every `## ` section of the frozen document must be represented here or on the exclusion
# list, with a reason.
_PAGE_EXCLUDES = {
 'On the name': 'a v1-vs-v2 note about node counts; the page states the counts directly',
 'Keeping this current': 'build instructions for this artifact, not anatomy',
}
# Map each document section to the page section that carries it. Some are lifted from the
# document, others are rendered natively from the same inventories -- both count, but the check
# is that the SECTION IS ON THE PAGE, not that a particular function was called. (My first
# version tracked md_section() calls and reported four sections missing that were right there.)
_SECTION_MAP = {
 'What Phorvex is': 'what', 'How to read this': 'howto', 'The tick': 'tick',
 'The map': 'foundation', 'The interactions': 'interactions',
 'The action vocabulary — what Phorvex can actually do': 'actions',
 'What actuation actually does': 'operations',
 'Where Phorvex crosses into systems it does not own': 'crossings',
 'Seams — contracts that are stated but not kept': 'seams', 'Glossary': 'glossary',
 'What this map does not assert': 'notasserted', 'What this artifact produced': 'produced',
 'At a glance': 'glance',
}
_page = '\n'.join(H)
_md_secs = {l[3:].strip() for l in md.split('\n') if l.startswith('## ')}
_unmapped = sorted(t for t in _md_secs if t not in _SECTION_MAP and t not in _PAGE_EXCLUDES)
assert not _unmapped, (f'document sections with no home on this page: {_unmapped} — map them to '
                       f'a section id, or list them in _PAGE_EXCLUDES with a reason')
_missing = sorted(t for t, sid in _SECTION_MAP.items()
                  if t in _md_secs and f'<section id="{sid}">' not in _page)
assert not _missing, f'mapped sections whose page section was never emitted: {_missing}'
# Boss found this by eye: Orchestration DREW 1 node and TABLED 8. The caption even printed
# "1 in this lane" directly above a table of eight. Nothing compared the two sets, so 6 of 15
# lanes were silently drawing a subset of what they listed.
_lane_mismatch = []
for _l in LANE_ORDER:
    _members = {n['id'] for n in lane_members(_l)}
    if not _members: continue
    _sec = re.search(rf'<section id="{_l.lower()}">(.*?)</section>', _page, re.S)
    if not _sec: continue
    _drawn = set(re.findall(r'^\s{4}([A-Za-z_][A-Za-z0-9_]*)\[', _sec.group(1), re.M)) | \
             set(re.findall(r'^\s{4}([A-Za-z_][A-Za-z0-9_]*)[\(\[/]', _sec.group(1), re.M))
    _tabled = set(re.findall(r'<td class="id"><span class="id">([^<]+)</span>', _sec.group(1)))
    if {nid(x) for x in _tabled} - _drawn:
        _lane_mismatch.append(f'{_l}: tables {len(_tabled)} nodes, draws {len(_drawn)}')
assert not _lane_mismatch, ('lanes whose diagram omits nodes their table lists: '
                            + '; '.join(_lane_mismatch))

_lanes_absent = [l for l in LANE_ORDER
                 if any(n['lane'] == l for n in top) and f'<section id="{l.lower()}">' not in _page]
assert not _lanes_absent, f'lanes with nodes but no section: {_lanes_absent}'

paths.GENERATED_DIR.mkdir(parents=True, exist_ok=True)
OUT = paths.GENERATED_DIR / 'ANATOMY.html'
open(OUT, 'w').write('\n'.join(H))

# ------------------------------------------------------------------- guards, not print lines
diagrams = '\n'.join(H).count('<pre class="mermaid">')
assert diagrams == len([l for l in LANE_ORDER if any(n['lane'] == l for n in top)]) + 2, \
    f'diagram count {diagrams} does not match lanes + tick + whole-map'
_ids = set(re.findall(r'<td class="id"><span class="id">([^<]+)</span>', '\n'.join(H)))
_missing = {n['id'] for n in nodes} - _ids
assert not _missing, f'nodes in the inventory that reached no table: {sorted(_missing)[:6]}'
print(f'{OUT}\n  {diagrams} diagrams · {len(_ids)}/{len(nodes)} nodes tabled · '
      f'{len(STEPS)} tick steps · {len(cross)} crossings · {os.path.getsize(OUT)} bytes')
