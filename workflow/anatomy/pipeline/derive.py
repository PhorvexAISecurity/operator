#!/usr/bin/env python3
import paths
"""Derive Phorvex's structure from code alone. No reference to the issue register."""
import os,re,json,collections

OUT=os.path.dirname(os.path.abspath(__file__))

ROOT=str(paths.MODULE_PATH / 'internal')
pkgs={}
for d in sorted(os.listdir(ROOT)):
    p=os.path.join(ROOT,d)
    if not os.path.isdir(p): continue
    files=[f for f in os.listdir(p) if f.endswith('.go') and not f.endswith('_test.go')]
    tests=[f for f in os.listdir(p) if f.endswith('_test.go')]
    loc=sum(sum(1 for _ in open(os.path.join(p,f),errors='ignore')) for f in files)
    tloc=sum(sum(1 for _ in open(os.path.join(p,f),errors='ignore')) for f in tests)
    imports=set()
    for f in files:
        for line in open(os.path.join(p,f),errors='ignore'):
            m=re.search(r'"[^"]*phorvex/internal/([a-z0-9]+)"',line)
            if m and m.group(1)!=d: imports.add(m.group(1))
    pkgs[d]=dict(files=len(files),loc=loc,test_files=len(tests),test_loc=tloc,imports=sorted(imports))

# reverse edges
for d in pkgs: pkgs[d]['imported_by']=sorted(k for k,v in pkgs.items() if d in v['imports'])

print(f"{'package':14}{'LOC':>7}{'files':>6}{'testLOC':>8}{'out':>5}{'in':>4}  imports")
for d,v in sorted(pkgs.items(), key=lambda x:-x[1]['loc']):
    print(f"{d:14}{v['loc']:>7}{v['files']:>6}{v['test_loc']:>8}{len(v['imports']):>5}{len(v['imported_by']):>4}  {' '.join(v['imports'])[:60]}")

print("\n=== fan-in ranking (how many packages depend on this one) ===")
for d,v in sorted(pkgs.items(), key=lambda x:-len(x[1]['imported_by']))[:10]:
    print(f"  {d:14} in={len(v['imported_by']):2}  {' '.join(v['imported_by'])}")

json.dump(pkgs, open(os.path.join(OUT,'packages.json'),'w'), indent=1)
print("\ntotal packages:",len(pkgs),"total LOC:",sum(v['loc'] for v in pkgs.values()))

# ---------------------------------------------------------------- second census
# derive.py's import graph covers internal/* only. `imported_by == []` there does NOT
# mean unreachable: a package may be wired from cmd/, api/, or tests. This census counts
# references across the WHOLE tree, split by zone, and is what runtime status must use.
TREE=str(paths.MODULE)
census={}
for d in pkgs:
    hits=collections.Counter(); tagged=0
    for dirpath,_,files in os.walk(TREE):
        rel=dirpath.replace(TREE,'').replace('\\','/').lstrip('/')
        if rel.startswith(f'internal/{d}'): continue
        for f in files:
            if not f.endswith('.go'): continue
            fp=os.path.join(dirpath,f)
            try: txt=open(fp,errors='ignore').read()
            except OSError: continue
            if f'phorvex/internal/{d}"' not in txt: continue
            if re.search(r'^//go:build', txt, re.M): tagged+=1
            zone=('test' if f.endswith('_test.go') else
                  'cmd' if rel.startswith('cmd') else
                  'internal' if rel.startswith('internal') else
                  'api' if rel.startswith('api') else 'other')
            hits[zone]+=1
    h=dict(hits); prod=h.get('internal',0)+h.get('api',0)+h.get('other',0)
    status=('unreferenced' if prod==0 and h.get('cmd',0)==0 and h.get('test',0)==0 else
            'test-only'    if prod==0 and h.get('cmd',0)==0 else
            'cmd-attached' if prod==0 else 'library')
    census[d]=dict(refs=h, build_tagged_importers=tagged, status=status)

json.dump(census, open(os.path.join(OUT,'reference_census.json'),'w'), indent=1)

print("\n=== second census (whole tree, by zone) ===")
print(f"{'package':14}{'internal':>9}{'cmd':>5}{'api':>4}{'test':>6}{'tagged':>8}   status")
for d,v in sorted(census.items(), key=lambda x:(x[1]['status'],x[0])):
    if v['status']=='library': continue
    r=v['refs']
    print(f"{d:14}{r.get('internal',0):>9}{r.get('cmd',0):>5}{r.get('api',0):>4}"
          f"{r.get('test',0):>6}{v['build_tagged_importers']:>8}   {v['status']}")

# ---- asserted classifications: these fail loudly if the tree moves ----
assert census['applier']['status']=='unreferenced', census['applier']
for d in ('console','controller','epssfeed','redteam','pendinggate','soak'):
    assert census[d]['status']=='cmd-attached', (d, census[d])
for d in ('belief','physics'):
    assert pkgs[d]['imported_by']==['decision'], (d, pkgs[d]['imported_by'])
assert pkgs['model']['imports']==[] and len(pkgs['model']['imported_by'])==19
assert pkgs['registry']['imports']==[] and len(pkgs['registry']['imported_by'])==9
print("\nall census assertions passed")
