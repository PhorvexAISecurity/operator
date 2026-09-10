#!/usr/bin/env python3
"""Adversarial re-check of the CURATED cells against source.

The generated columns each have a mutation behind them. The curated ones rest on my reading, and
K3 called for a real accuracy pass before freeze. This checks the curated claims that CAN be
checked mechanically, and reports the ones that cannot so nobody mistakes silence for proof.

It is written to FAIL me, not to confirm me.
"""
import csv, os, re
from findings import Findings
import paths

F = Findings('audit_curation_accuracy')
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n): return list(csv.DictReader(open(os.path.join(HERE, n), newline=''), delimiter='\t'))
mx = load('OPERATION_MATRIX.tsv')

def body_of(path, line):
    """the enclosing function body of a call site"""
    ls = paths.lines(path)
    if not ls: return []
    start = line - 1
    while start > 0 and not ls[start].startswith('func '): start -= 1
    d, out = 0, []
    for i in range(start, len(ls)):
        out.append((i + 1, ls[i]))
        d += ls[i].count('{') - ls[i].count('}')
        if d == 0 and i > start: break
    return out

# map bare filenames to their real path, so a resolution artifact is not read as a dead citation
BARE = {}
for _root, _d, _fs in os.walk(paths.MODULE + 'internal'):
    for _f in _fs:
        if _f.endswith('.go'): BARE.setdefault(_f, os.path.join(_root, _f).replace(paths.MODULE, ''))
bare_cites = []
READBACK_NONE = 'NONE'
checked = miss = 0
for r in mx:
    ack, rb = r['acknowledgement_level_CURATED'], r['postcondition_readback_CURATED']
    a = r['source_anchor_GEN']
    m = re.match(r'^([A-Za-z0-9_./-]+\.go):(\d+)$', a)
    if not m: continue
    path, line = m.group(1), int(m.group(2))

    # 1. "readback NONE" must mean there is genuinely no later read of the same kind in the body
    if rb.startswith(READBACK_NONE) and r['operation_GEN'] in ('Create', 'Update', 'Delete', 'Patch'):
        checked += 1
        kind = r['target_resource_GEN']
        later = [(n, t) for n, t in body_of(path, line) if n > line
                 and re.search(r'\.(Get|List)\(ctx', t)]
        for n, t in later:
            # a later read naming the same object kind would falsify "no readback"
            if kind.lower()[:6] in t.lower():
                F.add('CURATION_READBACK_WRONG',
                      f'{r["action_GEN"]} {a}: claims readback NONE but {path}:{n} reads {kind} after it: {t.strip()[:60]}')
                miss += 1

    # 2. a "pre-read" ack must actually be on a read
    if 'pre-read' in ack and r['operation_GEN'] not in ('Get', 'List'):
        F.add('CURATION_ACK_WRONG', f'{r["action_GEN"]} {a}: ack says pre-read but the operation is {r["operation_GEN"]}')

    # 3. every ledger cell naming an Outcome must name one that exists in slo/ledger.go
    led = r['runner_ledger_outcome_CURATED']
    for out_name in re.findall(r'\b(Outcome\w+)', led):
        if out_name not in (paths.full('internal/slo/ledger.go') and open(paths.full('internal/slo/ledger.go')).read()):
            F.add('CURATION_LEDGER_UNKNOWN', f'{r["action_GEN"]} {a}: names {out_name}, which is not in slo/ledger.go')

    # 4. every path:line cited INSIDE a curated cell must resolve and be code.
    #    A BARE filename ("phoenix.go:150") is resolved against the known source tree — but that
    #    is a courtesy, and a citation only a reader can place by context is a weaker citation
    #    than a full path. Both are checked; bare ones are reported separately.
    for col in ('acknowledgement_level','postcondition_readback','availability_recovery_observation',
                'security_goal_confirmation','runner_ledger_outcome','notes'):
        for p_, l_ in re.findall(r'([A-Za-z0-9_./-]+\.(?:go|yaml|yml)):(\d+)', r[col + '_CURATED']):
            full = p_ if '/' in p_ else BARE.get(p_)
            if full is None:
                F.add('CURATION_CITATION_DEAD', f'{r["action_GEN"]} {a} [{col}]: cites {p_}:{l_}, no such file')
                continue
            if '/' not in p_: bare_cites.append(f'{r["action_GEN"]} [{col}] {p_}:{l_} -> {full}')
            t = paths.line_at(full, int(l_))
            if t is None:
                F.add('CURATION_CITATION_DEAD', f'{r["action_GEN"]} {a} [{col}]: cites {full}:{l_}, past end of file')
            elif not t.strip() or t.strip().startswith('//'):
                F.add('CURATION_CITATION_NOT_CODE',
                      f'{r["action_GEN"]} {a} [{col}]: cites {full}:{l_}, a comment or blank: {t.strip()[:50]}')

if bare_cites:
    print(f'\nBARE filename citations — resolvable only by context, {len(bare_cites)}:')
    for b in bare_cites[:8]: print(f'   {b}')

print(f'curated rows: {sum(1 for r in mx if r["acknowledgement_level_CURATED"] != "NOT-YET-CURATED")}')
print(f'"readback NONE" claims re-derived from source: {checked}')
print('NOT mechanically checkable, and therefore NOT proven here: the security-goal reasoning,')
print('the availability tokens, and every note. Those need a reader.')
F.report('every mechanically checkable curated claim holds against source')
