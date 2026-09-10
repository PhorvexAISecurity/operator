#!/usr/bin/env python3
"""Audit every anchor for whether the cited line plausibly EVIDENCES its claim.

The validator proves a line exists. It cannot prove the line means what the row says.
This flags the shapes that burned us seven times: struct fields, imports, type and func
declarations, flag definitions, comments and blank lines cited as call evidence.
"""
import csv, os, re, sys, json, subprocess
from findings import Findings
import paths
SRC = paths.MODULE_STR
F = Findings('audit_anchors')
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))

def line_at(p, n):
    return paths.line_at(p, n)

def shape(txt):
    if txt is None: return 'MISSING'
    if not txt: return 'BLANK'
    if txt.startswith(('//', '/*', '*')): return 'COMMENT'
    if txt.startswith('import') or re.match(r'^"[^"]+"$', txt): return 'IMPORT'
    if txt.startswith('type '): return 'TYPE-DECL'
    if txt.startswith('func ') and txt.rstrip().endswith('{'): return 'FUNC-SIGNATURE'
    if 'flag.' in txt and 'Var(' in txt: return 'FLAG-DEFINITION'
    if re.match(r'^\w+\s+[\w.*\[\]{}]+(\s+`.*`)?$', txt): return 'STRUCT-FIELD'
    if re.match(r'^\w+:\s', txt) and not txt.endswith('{'): return 'STRUCT-LITERAL-FIELD'
    if '(' in txt: return 'call/expression'
    return 'other'

SUSPECT = {'MISSING','BLANK','COMMENT','IMPORT','TYPE-DECL','FUNC-SIGNATURE',
           'FLAG-DEFINITION','STRUCT-FIELD'}

rows = []
for r in load('RELATIONS.tsv'):
    for p, n in re.findall(r'([A-Za-z0-9_./-]+\.(?:go|yaml|yml|ts|tsx|Dockerfile|mod|json)):(\d+)', r['anchor']):
        rows.append((f'{r["from"]} -> {r["to"]}', r['kind'], p, int(n)))
for r in load('NODES.tsv'):
    if ':' in r['source_anchor']:
        p, n = r['source_anchor'].rsplit(':', 1)
        rows.append((r['id'], 'node', p, int(n)))
for fn in ('SEAMS.tsv','INTENTIONAL_BOUNDARIES.tsv'):
    for r in load(fn):
        for col in ('contract_evidence','negative_evidence'):
            for p, n in re.findall(r'([A-Za-z0-9_./-]+\.(?:go|yaml|yml|ts|tsx|Dockerfile|mod|json)):(\d+)', r[col]):
                rows.append((f'{r["seam"]} [{col}]', 'seam', p, int(n)))

flagged = []
for who, kind, p, n in rows:
    if not p.endswith('.go'): continue    # Go shape heuristics; non-Go anchors are drift-checked only
    s = shape(line_at(p, n))
    # DOCUMENTED EXEMPTIONS — each is the correct shape for what the row claims:
    #  node        -> its own definition IS a type/field/func declaration
    #  seam        -> a contract stated in a comment: the comment IS the evidence
    #  wires…      -> a wiring edge legitimately cites a struct-literal field
    exempt = ((kind == 'node' and s in ('TYPE-DECL','STRUCT-FIELD','FUNC-SIGNATURE','COMMENT'))
              or (kind == 'seam' and s == 'COMMENT')
              or (kind.startswith('wires') and s in ('STRUCT-FIELD','STRUCT-LITERAL-FIELD'))
              #  implements -> the method definition IS the implementation evidence
              or (kind == 'implements' and s == 'FUNC-SIGNATURE'))
    if s in SUSPECT and not exempt:
        flagged.append((who, kind, f'{p}:{n}', s, (line_at(p, n) or '')[:64]))

for who, kind, loc, sh, txt in flagged:
    F.add('ANCHOR_NOT_CODE', f'{who} [{kind}] {loc} is a {sh}: {txt}')

# ---------------------------------------------------------------------------
# QUOTE MUST HIT CODE (K3 220). The seam exemption above — a contract stated in a comment IS the
# evidence — is correct and stays. But it cannot tell that case from a citation that MEANT to
# point at code and landed on the comment above it, which is how the MigrateRemote seam cited
# gpu_stack_p4set.go:195 (a comment) for an error string living on :196.
#
# The discriminator is already in the prose: a cell that QUOTES something is making a claim about
# text that exists, so the quoted text must be on the cited line. A cell that merely describes
# what a comment says quotes nothing and remains exempt.
# case-insensitive: a cell may legitimately quote a sentence with a different leading capital
# ("learned values ..." for a comment that reads "Learned values ..."). Case still cannot rescue a
# quote that is simply absent from the line, which is the defect this exists to catch.
def _norm(t): return re.sub(r'\s+', ' ', (t or '').lower()).strip()

for fn in ('SEAMS.tsv', 'INTENTIONAL_BOUNDARIES.tsv'):
    for r in load(fn):
        for col in ('contract_evidence', 'negative_evidence'):
            cell = r[col]
            quotes = [q for q in re.findall(r'"([^"]{6,})"', cell)]
            if not quotes: continue                  # describes rather than quotes -> exempt
            cites = re.findall(r'([A-Za-z0-9_./-]+\.(?:go|yaml|yml)):(\d+)', cell)
            if not cites: continue
            for q in quotes:
                hit = any(_norm(q)[:40] in _norm(line_at(p_, int(n_)) or '') for p_, n_ in cites)
                if not hit:
                    F.add('SEAM_QUOTE_NOT_AT_LINE',
                          f'{r["seam"]!r} [{col}]: quotes {q[:44]!r} but no cited line contains it '
                          f'({" ".join(f"{a}:{b}" for a, b in cites)})')

# ---------------------------------------------------------------------------
# ANCHOR DRIFT. This is the hole that v0.4.59-64 walked straight through: nine added lines in
# phoenix.go slid three anchors onto entirely different statements, and every audit still
# passed, because a shape check asks whether a line is CODE, never whether it is THE code.
# Each anchor therefore carries a fingerprint of the line it was verified against.
FP = os.path.join(HERE, 'ANCHOR_FINGERPRINTS.tsv')
PIN = os.path.join(HERE, 'SOURCE_PIN.json')

def head():
    try:
        return subprocess.run(['git','-C',SRC,'rev-parse','HEAD'], capture_output=True,
                              text=True).stdout.strip()[:12] or 'unknown'
    except Exception:
        return 'unknown'

def fingerprint(p, n):
    t = line_at(p, n)
    return '' if t is None else re.sub(r'\s+', ' ', t)[:90]

if '--regen' in sys.argv:
    with open(FP, 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t'); w.writerow(['file','line','fingerprint'])
        for k in sorted({(p, n) for _, _, p, n in rows}):
            w.writerow([k[0], k[1], fingerprint(*k)])
    json.dump({'commit': head(), 'anchors': len({(p, n) for _, _, p, n in rows})},
              open(PIN, 'w'), indent=1)
    print(f'regenerated {FP} at {head()}')
    sys.exit(0)

if not os.path.exists(FP):
    print('NO FINGERPRINT FILE — run: python3 audit_anchors.py --regen')
    sys.exit(1)
pin = json.load(open(PIN))
want = {(r['file'], int(r['line'])): r['fingerprint']
        for r in csv.DictReader(open(FP, newline=''), delimiter='\t')}
drift, unpinned = [], []
for who, kind, p, n in rows:
    if (p, n) not in want: unpinned.append((who, f'{p}:{n}')); continue
    got = fingerprint(p, n)
    if got != want[(p, n)]: drift.append((who, f'{p}:{n}', want[(p, n)], got))
for who, loc, was, now in drift:
    F.add('ANCHOR_DRIFTED', f'{who} {loc}\n      verified against: {was}\n      now reads:        {now}')
for who, loc in unpinned:
    F.add('ANCHOR_UNPINNED', f'{who} {loc} has no fingerprint — re-run --regen after review')

print(f'anchors audited: {len(rows)}   fingerprints pinned at {pin["commit"]}   source now at {head()}')
if pin['commit'] != head():
    print(f'  source moved since the pin; {len(rows)-len(drift)-len(unpinned)} anchors still read identically')
F.report('every anchor points at code and still reads exactly as verified')
