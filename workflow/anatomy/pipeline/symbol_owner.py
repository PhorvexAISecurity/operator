#!/usr/bin/env python3
import paths
"""Resolve an exported symbol to the NODE that owns its defining file.

Package-first ownership is not semantic ownership: `actuator.NewNativeActuator` was being
attributed to `actuator.router` because the router happened to be the first node listed for
the actuator package. A symbol belongs to whoever defines it.
"""
import csv, os, re, json, functools

SRC = paths.MODULE_STR
HERE = os.path.dirname(os.path.abspath(__file__))

@functools.lru_cache(maxsize=1)
def _tables():
    nodes = list(csv.DictReader(open(os.path.join(HERE, 'NODES.tsv'), newline=''), delimiter='\t'))
    file_owner, whole_pkg = {}, {}
    for n in nodes:
        for t in n['packages_or_files'].split():
            t = t.strip(',')
            if t.endswith('.go'): file_owner.setdefault(t, n['id'])
            # A node that claims a WHOLE package (bare `internal/ctxprov`, no file list) owns
            # every file in it. Without this, strict per-symbol resolution returned None for
            # every unsplit package — `ctxprov.Registry` among them — so checks that looked
            # non-circular were silently resolving nothing at all.
            elif t.startswith('internal/') and t.count('/') == 1:
                whole_pkg.setdefault(t.split('/')[1], n['id'])
    # exported symbol -> defining file, per package
    sym = {}
    for pkg in json.load(open(os.path.join(HERE, 'packages.json'))):
        d = SRC + 'internal/' + pkg
        if not os.path.isdir(d): continue
        for f in sorted(os.listdir(d)):
            if not f.endswith('.go') or f.endswith('_test.go'): continue
            path = f'internal/{pkg}/{f}'
            for i, l in enumerate(open(d + '/' + f, errors='ignore'), 1):
                m = re.match(r'func (?:\([^)]*\) )?([A-Z]\w*)\(', l)
                if m: sym.setdefault((pkg, m.group(1)), (path, i))
                m2 = re.match(r'(?:type|var|const) ([A-Z]\w*)\b', l)
                if m2: sym.setdefault((pkg, m2.group(1)), (path, i))
    return nodes, file_owner, sym, whole_pkg

def owner_of(pkg, symbol, fallback_pkg_node=True):
    """The node that DEFINES pkg.Symbol, or None."""
    nodes, file_owner, sym, whole_pkg = _tables()
    hit = sym.get((pkg, symbol))
    if hit and hit[0] in file_owner: return file_owner[hit[0]], hit
    # unambiguous: the package is not split, so one node owns every file in it
    if hit and pkg in whole_pkg: return whole_pkg[pkg], hit
    if not fallback_pkg_node: return None, hit
    for n in nodes:                        # package-level fallback, explicitly last
        if any(t.strip(',').startswith(f'internal/{pkg}/') or t.strip(',') == f'internal/{pkg}'
               for t in n['packages_or_files'].split()):
            return n['id'], hit
    return None, hit

if __name__ == '__main__':
    for pkg, s in [('actuator','NewNativeActuator'), ('actuator','MissingHandlers'),
                   ('actuator','OrphanHandlers'), ('actuator','NewHybridActuator'),
                   ('actuator','NewPhoenixActuator'), ('decision','NewCoverageEngine'),
                   ('decision','NewEngine'), ('slo','NewLedger'), ('slo','Classify')]:
        node, hit = owner_of(pkg, s)
        print(f'{pkg}.{s:22} -> {node:28} {hit[0]}:{hit[1]}' if hit else f'{pkg}.{s}: NOT FOUND')
