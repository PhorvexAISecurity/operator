#!/usr/bin/env python3
"""Repository-wide product-surface census.

K3's finding: I reported the v0.4.64 drift as "7 files" because I ran `git diff` scoped to
`phorvex/`. The pull changed 12 tracked paths. Scoping the derivation to the Go module made
the module the silent boundary of the anatomy — the shipped console image, the Next.js SPA and
the deployment values were never in scope to be missed.

So the surface is now DECLARED, with a written reason per path, and this fails on anything
tracked that is neither included nor excluded. A new top-level directory cannot appear in the
repository without failing the anatomy.
"""
import subprocess, os, sys, csv
from findings import Findings
import paths

F = Findings('repo_census')
REPO = paths.REPO

# path -> (included?, reason). Reasons are the point: an exclusion must be arguable.
SURFACES = {r['path']: (r['included'] == 'yes', r['reason'])
            for r in csv.DictReader(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      'SURFACES.tsv'), newline=''), delimiter='\t')}

# -z gives NUL-separated RAW paths. Without it git QUOTES any path with a non-ASCII byte
# ("products/Phoenix for AI \342\200\224 ...") and the leading quote became a phantom
# top-level path called '"products'.
tracked = subprocess.run(['git','-C',REPO,'ls-files','-z'],
                         capture_output=True, text=True).stdout.split('\0')
top = sorted({p.split('/')[0] for p in tracked if p.strip()})

for t in top:
    if t not in SURFACES:
        F.add('CENSUS_UNCLASSIFIED',
              f'tracked top-level path {t!r} is neither included nor excluded — classify it with a reason')
# Depth. `build/` is included, but including a directory is not a claim about everything inside
# it: only phoenix-extended and test-harness are compiled or packaged. Any included path that has
# declared children must classify ALL of them, so a new -extended fork cannot arrive unexamined.
DEEPEN = {p_.split('/')[0] for p_ in SURFACES if '/' in p_}
for parent in sorted(DEEPEN):
    for child in sorted(os.listdir(REPO + parent)):
        cp = f'{parent}/{child}'
        if not os.path.isdir(REPO + cp): continue
        if cp not in SURFACES and any(x.startswith(f'{parent}/') for x in SURFACES):
            F.add('CENSUS_UNCLASSIFIED',
                  f'{cp} sits inside included {parent!r} but is neither included nor excluded')

for s, (included, _) in SURFACES.items():
    if os.path.exists(REPO + s):
        continue
    tracked_at_pin = s in tracked or any(p.startswith(s.rstrip('/') + '/') for p in tracked)
    if included or tracked_at_pin:
        F.add('CENSUS_STALE', f'declared surface {s!r} no longer exists in the repository')
    else:
        # Historical local-only exclusions (for example an attack workload checkout) may
        # legitimately be absent from a clean worktree. They were never product input.
        print(f'NOTE CENSUS_OPTIONAL_ABSENT  excluded untracked surface {s!r} is not present')

inc = sorted(s for s, (i, _) in SURFACES.items() if i)
exc = sorted(s for s, (i, _) in SURFACES.items() if not i)
print(f'tracked top-level paths: {len(top)}   included: {len(inc)}   excluded: {len(exc)}')
print('\nINCLUDED — the anatomy must cover these:')
for s in inc: print(f'  {s:22} {SURFACES[s][1]}')
print('\nEXCLUDED — with the reason each is out of scope:')
for s in exc: print(f'  {s:22} {SURFACES[s][1]}')
F.report('every tracked top-level path is classified with a written reason')
