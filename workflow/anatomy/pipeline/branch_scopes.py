#!/usr/bin/env python3
import paths
"""Source-rooted branch scopes for cmd/*.

K3: "cmd.main contains production and tool branches under one node." A file-level rule cannot
separate them — cmd/main.go holds the operator loop AND five one-shot tools. This detects each
branch from the source (never from RELATIONS.tsv, and never from hard-coded line numbers that
rot), so an anchor can be asked which branches actually execute it.

Detection is asserted against a DECLARED branch set: if a branch is added, removed or renamed
in main.go the audit fails rather than silently re-scoping the graph.
"""
import re, os, functools

SRC = paths.MODULE_STR
MAIN = 'cmd/main.go'

# Every branch that must exist, and whether it is the steady operator or a one-shot tool.
DECLARED = {
 'steady':           'operator',   # the reconciler + tick loop; the only production branch
 'epss-feed':        'one-shot',
 'integration-emit': 'one-shot',
 'ablation':         'one-shot',
 'native-demo':      'one-shot',
 'scan':             'one-shot',
}
STEADY_ROLES = {'production', 'shadow', 'observe-only', 'infrastructure'}

# flag variable in main() -> branch name. The variable is what the source branches on; the
# branch name is what the anatomy calls it.
FLAGVAR = {'epssFeed': 'epss-feed', 'integrationEmit': 'integration-emit',
           'ablation': 'ablation', 'nativeDemo': 'native-demo', 'scan': 'scan'}

def _span_of_func(text, name):
    """(first_line, last_line) of a top-level func, brace-matched."""
    m = re.search(rf'^func {re.escape(name)}\(', text, re.M)
    if not m: return None
    i = text.index('{', m.start()); d = 0
    for j in range(i, len(text)):
        if text[j] == '{': d += 1
        elif text[j] == '}':
            d -= 1
            if d == 0:
                return text.count('\n', 0, m.start()) + 1, text.count('\n', 0, j) + 1
    return None

@functools.lru_cache(maxsize=1)
def _detect():
    """Returns (branch -> {file: [(lo,hi), ...]}, notes). Pure source analysis."""
    text = open(SRC + MAIN, errors='ignore').read()
    mlo, mhi = _span_of_func(text, 'main')
    lines = text.split('\n')

    # A one-shot branch is a depth-1 `if <flagvar> {` block inside main() that ends in `return`.
    spans, entry = {}, {}
    for var, branch in FLAGVAR.items():
        m = re.search(rf'^\tif {re.escape(var)} \{{$', text, re.M)
        if not m: continue
        lo = text.count('\n', 0, m.start()) + 1
        if not (mlo <= lo <= mhi): continue
        hi = None
        for k in range(lo, mhi + 1):                      # depth-1 close is a lone "\t}"
            if lines[k - 1] == '\t}': hi = k; break
        if hi is None: continue
        body = '\n'.join(lines[lo - 1:hi])
        if '\n\t\treturn\n' not in body + '\n': continue  # not an early-return one-shot
        spans[branch] = {MAIN: [(lo, hi)]}
        fn = re.search(r'if err := (\w+)\(', body)
        if fn: entry[branch] = fn.group(1)

    # The steady operator is everything in main() after the last one-shot block.
    last = max((h for s in spans.values() for _, h in s[MAIN]), default=mlo)
    spans['steady'] = {MAIN: [(last + 1, mhi)]}

    # COMMON REGIONS. main() code outside every one-shot block still runs under some branches
    # but not others: `platform.LoadEPSSFromFile` sits BETWEEN the epss-feed block and the
    # integration-emit block, so it runs in five branches and never under --epss-feed. A single
    # "prologue" span got this wrong by leaving those lines in no branch at all.
    oneshot = sorted((lo, hi, b) for b, f in spans.items() if b != 'steady'
                     for lo, hi in f[MAIN])
    common = []                                   # (lo, hi, frozenset(branches))
    cur = mlo
    for lo, hi, _ in oneshot:
        if cur <= lo - 1:
            # everything whose early return has not happened yet, plus the operator itself
            reach = {b for l2, _, b in oneshot if l2 >= lo} | {'steady'}
            common.append((cur, lo - 1, frozenset(reach)))
        cur = hi + 1

    # Attach each one-shot's entry function body, wherever in cmd/ it is defined.
    cmd_files = [MAIN] + [f'cmd/{f}' for f in sorted(os.listdir(SRC + 'cmd'))
                          if f.endswith('.go') and f != 'main.go']
    for branch, fn in entry.items():
        for cf in cmd_files:
            t = open(SRC + cf, errors='ignore').read()
            sp = _span_of_func(t, fn)
            if sp: spans[branch].setdefault(cf, []).append(sp); break
    return spans, common

def branches_of(path, line):
    """Which branches execute this anchor. Empty set = not a cmd/main.go-rooted anchor."""
    spans, common = _detect()
    out = set()
    if path == MAIN:
        for lo, hi, reach in common:
            if lo <= line <= hi: out |= set(reach)
    for b, files in spans.items():
        for lo, hi in files.get(path, []):
            if lo <= line <= hi: out.add(b)
    return out

def declared_ok():
    """(ok, detail) — the detected branch set must equal the declared one."""
    spans, _ = _detect()
    got, want = set(spans), set(DECLARED)
    if got == want: return True, f'{len(want)} branches detected in {MAIN}'
    return False, f'detected {sorted(got)} but declared {sorted(want)}'

if __name__ == '__main__':
    spans, common = _detect()
    for lo, hi, reach in common:
        print(f'{MAIN}:{lo}-{hi} common to {len(reach)}: {" ".join(sorted(reach))}')
    for b in sorted(spans):
        loc = '  '.join(f'{f}:{lo}-{hi}' for f, sp in spans[b].items() for lo, hi in sp)
        print(f'  {b:18} {DECLARED[b]:9} {loc}')
    print(declared_ok())
