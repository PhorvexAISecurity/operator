#!/usr/bin/env python3
"""Render the anatomy as static SVG, laid out here rather than by a diagram engine.

Mermaid was failing to parse the labels and left source on the page. This owns the layout,
so nothing between the TSVs and the printed page can silently give up.
"""
import paths
import csv, os, collections, html

HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n)), delimiter='\t'))
nodes, rels, seams = load('NODES.tsv'), load('RELATIONS.tsv'), load('SEAMS.tsv')
import json as _json
PIN = _json.load(open(os.path.join(HERE,'SOURCE_PIN.json')))['commit'] if os.path.exists(
      os.path.join(os.path.dirname(os.path.abspath(__file__)),'SOURCE_PIN.json')) else 'unknown'

FILL = {'production-P1':('#e6f0e0','#38761d'), 'P0-legacy':('#fce5cd','#b45f06'),
        # v2 lanes the old palette predates
        'external':('#efe3f3','#674ea7'), 'product':('#e3eefb','#1f4e79'),
        'delivery':('#f3efe3','#7f6000'),
        'shadow':('#fff2cc','#bf9000'), 'benchmark':('#dbe9ec','#134f5c'),
        'observe-only':('#eeeeee','#5f6469'), 'shared-foundation':('#dce9f8','#1155cc'),
        'tool/surface':('#f0dfe7','#741b47'), 'deliberately-unwired':('#f6ded9','#990000')}
def fill_class(n):
    """The old generator keyed off a `scope` column that no longer exists. Derive the class from
    the columns the frozen schema actually has."""
    if n['lane'] == 'External':        return 'external'
    if n['lane'] == 'Product':         return 'product'
    if n['lane'] == 'Delivery':        return 'delivery'
    if n['runtime_role'] == 'unwired': return 'deliberately-unwired'
    if n['runtime_role'] in ('tool',): return 'tool/surface'
    if n['runtime_role'] == 'benchmark': return 'benchmark'
    if n['engine_scope'] == 'P0':      return 'P0-legacy'
    return 'production-P1'

LANES = [('Bootstrap','Bootstrap and contract'), ('Orchestration','Orchestration'),
         ('Sensing','Sensing'), ('Assembly','Per-tenant assembly (P1)'), ('Pricing','Pricing'),
         ('Choice','Choice'), ('Actuation','Actuation'), ('Observation','Post-action observation'),
         ('Record','Record'), ('Console','Console and policy management'),
         ('Tools','Tool islands (outside the tick)'), ('Foundation','Shared foundation (outside the tick)'),
         ('Product','Product surface'), ('Delivery','Delivery and composition'),
         ('External','Systems Phorvex does not own')]

DRAWN = []
by_id = {}
POS = {}                      # node id -> (x, y, w, h); the layout had the coordinates and
                              # never used them, so the map showed 99 parts and 0 relations
by_id = {n['id']: n for n in nodes}
kids = collections.defaultdict(list)
for n in nodes:
    if n['parent']: kids[n['parent']].append(n)
top = [n for n in nodes if not n['parent']]
seam_by_node = collections.defaultdict(list)
for s in seams:
    if s['status'].startswith('NOT-A-GAP'): continue
    seam_by_node[s['attaches_to'].split('->')[0].strip()].append(s)

W, PAD, LANE_PAD = 1180, 26, 14
CW, CH, GAP = 268, 66, 12          # card width / height / gutter
PER_ROW = (W - 2*PAD - 8) // (CW + GAP)

def esc(t): return html.escape(t, quote=False)

def anchor(n):
    a = n['source_anchor']
    assert a, f"node {n['id']} has no source_anchor"
    return a

out, y = [], PAD
out.append(f'<text x="{PAD}" y="{y+16}" class="ttl">Phorvex — actuation and control anatomy</text>')
out.append(f'<text x="{PAD}" y="{y+36}" class="sub">Generated from the frozen inventories at '
           f'{PIN}. Node identity is a code path. Companion to PHORVEX_ANATOMY_V2.md and '
           f'PHORVEX_MASTER_ISSUES_V2.md.</text>')
y += 58

for key, title in LANES:
    rows = [n for n in top if n['lane'] == key]
    if not rows: continue
    # K3 232: this walked ONE level, so the 16 handler grandchildren
    # (actuator.native.rotate .. kv-migrate-invalidate) were never drawn — while the summary line
    # counted every parented row in the dict and claimed 39. Walk the tree; count what is written.
    def descend(n, depth=0):
        yield n, depth
        for k in sorted(kids[n['id']], key=lambda x: x['id']):
            yield from descend(k, depth + 1)
    cards = [c for n in rows for c in descend(n)]
    nrows = (len(cards) + PER_ROW - 1)//PER_ROW
    lane_h = 26 + nrows*(CH + GAP) + LANE_PAD
    out.append(f'<rect x="{PAD-8}" y="{y}" width="{W-2*PAD+16}" height="{lane_h}" class="lane"/>')
    out.append(f'<text x="{PAD}" y="{y+18}" class="lane-t">{esc(title.upper())}</text>')
    for _c, _d in cards: DRAWN.append((_c['id'], _d))
    cy = y + 26
    for i, (n, _depth) in enumerate(cards):
        col, row = i % PER_ROW, i // PER_ROW
        x = PAD + col*(CW + GAP)
        ny = cy + row*(CH + GAP)
        bg, st = FILL[fill_class(n)]
        dash = ' stroke-dasharray="5 3"' if n['runtime_role'] in ('tool','benchmark','unwired') else ''
        indent = 10 if n['parent'] else 0
        POS[n['id']] = (x + indent, ny, CW - indent, CH)
        out.append(f'<rect x="{x+indent}" y="{ny}" width="{CW-indent}" height="{CH}" rx="2" '
                   f'fill="{bg}" stroke="{st}" stroke-width="1.1"{dash}/>')
        if n['parent']:
            out.append(f'<rect x="{x}" y="{ny}" width="3" height="{CH}" fill="{st}" opacity=".45"/>')
        out.append(f'<text x="{x+indent+10}" y="{ny+18}" class="nid">{esc(n["id"])}</text>')
        out.append(f'<text x="{x+indent+10}" y="{ny+34}" class="nnm">{esc(n["display"])}</text>')
        loc = f' · {n["loc"]} LOC' if n['loc'] not in ('-','') else ''
        out.append(f'<text x="{x+indent+10}" y="{ny+50}" class="nan">{esc(anchor(n)+loc)}</text>')
        for s in seam_by_node.get(n['id'], []):
            tag = 'ABSENT' + (' (unscoped)' if s['status']=='gap-unscoped' else '')
            out.append(f'<rect x="{x+CW-84}" y="{ny+CH-17}" width="80" height="14" rx="1" '
                       f'fill="#efe6fb" stroke="#674ea7" stroke-width=".8" stroke-dasharray="3 2"/>')
            out.append(f'<text x="{x+CW-44}" y="{ny+CH-7}" class="gap">{esc(tag)}</text>')
    y += lane_h + 12

H = y + 8

# ---------------------------------------------------------------------------
# THE RELATIONS. The layout knew every card's coordinates and drew none of the 111 edges, so the
# map showed the parts and not a single connection — a catalogue, not a graph. Edges are routed
# side-to-side with an elbow, drawn UNDER the cards (inserted before them) so labels stay legible.
def anchor_pts(a, b):
    ax, ay, aw, ah = POS[a]; bx, by, bw, bh = POS[b]
    acx, bcx = ax + aw/2, bx + bw/2
    if abs((ay+ah/2) - (by+bh/2)) < 4:                 # same row: go side to side
        if acx < bcx: return (ax+aw, ay+ah/2), (bx, by+bh/2)
        return (ax, ay+ah/2), (bx+bw, by+bh/2)
    if ay < by:      return (acx, ay+ah), (bcx, by)    # downward
    return (acx, ay), (bcx, by+bh)                     # upward

EDGE_STYLE = {                                          # (stroke, width, dash)
 'crossing':  ('#674ea7', 1.5, ''),                     # into a system we do not own
 'unwired':   ('#b45f06', 1.1, ' stroke-dasharray="4 3"'),
 'tool':      ('#8a94a3', 0.9, ' stroke-dasharray="2 3"'),
 'normal':    ('#9aa4b2', 0.9, ''),
}
edges = []
seen_e = set()
for r in rels:
    a, b = r['from'], r['to']
    if a not in POS or b not in POS or a == b: continue
    if (a, b) in seen_e: continue
    seen_e.add((a, b))
    if r.get('crossing_status') == 'declared-unwired' or by_id.get(b, {}).get('runtime_role') == 'unwired':
        kind = 'unwired'
    elif b.startswith('ext.'):                 kind = 'crossing'
    elif r['runtime_role'] in ('tool','benchmark','unwired'): kind = 'tool'
    else:                                      kind = 'normal'
    col, wdt, dash = EDGE_STYLE[kind]
    (x1, y1), (x2, y2) = anchor_pts(a, b)
    mid = (y1 + y2) / 2
    d = (f'M {x1:.0f} {y1:.0f} L {x1:.0f} {mid:.0f} L {x2:.0f} {mid:.0f} L {x2:.0f} {y2:.0f}'
         if abs(y1 - y2) > 4 else f'M {x1:.0f} {y1:.0f} L {x2:.0f} {y2:.0f}')
    edges.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{wdt}" '
                 f'opacity="0.5"{dash} marker-end="url(#ar)"/>')
DEFS = ('<defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" '
        'markerHeight="5" orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="#9aa4b2"/></marker></defs>')
css = ('.lane{fill:#fafbfc;stroke:#e2e6ec;stroke-width:1}'
       '.ttl{font:600 19px "IBM Plex Sans",sans-serif;fill:#141821}'
       '.sub{font:400 11px "IBM Plex Sans",sans-serif;fill:#5c6673}'
       '.lane-t{font:500 9.5px "IBM Plex Mono",monospace;fill:#7b8492;letter-spacing:1.4px}'
       '.nid{font:600 11.5px "IBM Plex Mono",monospace;fill:#141821}'
       '.nnm{font:400 11.5px "IBM Plex Sans",sans-serif;fill:#2c333e}'
       '.nan{font:400 9.5px "IBM Plex Mono",monospace;fill:#6a7381}'
       '.gap{font:600 7.5px "IBM Plex Sans",sans-serif;fill:#674ea7;text-anchor:middle}')
svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">'
       f'<style>{css}</style>{DEFS}<rect width="{W}" height="{H}" fill="#ffffff"/>'
       + ''.join(edges) + ''.join(out) + '</svg>')
paths.GENERATED_DIR.mkdir(parents=True, exist_ok=True)
open(paths.GENERATED_DIR / 'ANATOMY.svg', 'w').write(svg)
# count CARDS ACTUALLY WRITTEN, never the dict
DRAWN_TOP = sum(1 for _i, d in DRAWN if d == 0)
DRAWN_KIDS = sum(1 for _i, d in DRAWN if d > 0)
_missing = {n['id'] for n in nodes} - {i for i, _d in DRAWN}
assert not _missing, f'nodes in the inventory that were never drawn: {sorted(_missing)}'
_undrawn = [(r['from'], r['to']) for r in rels
            if (r['from'] not in POS or r['to'] not in POS) and r['from'] != r['to']]
assert not _undrawn, f'relations whose endpoints were never positioned: {_undrawn[:5]}'
print(f'svg {W}x{H}, {DRAWN_TOP} top-level + {DRAWN_KIDS} descendants written, '
      f'{len(edges)} relations drawn, '
      f'{sum(len(v) for v in seam_by_node.values())} absent markers')
