#!/usr/bin/env python3
"""Resolve an anatomy anchor to a file on disk.

Until now every anchor was relative to the Go module (`phorvex/`), which quietly made the
module the boundary of the anatomy. The shipped product is larger: a Next.js SPA, an image
that composes four binaries, and Helm/EKS values. Those anchors are relative to the REPO ROOT.

The two namespaces do not collide — `phorvex/` contains no `dashboard-web`, `deploy` or
`build` — so the prefix alone decides, and `assert_no_collision()` fails if that ever changes.

The workflow copy is portable: `PHORVEX_CODE_REPO` may name any clean worktree.
Otherwise the code repository is the parent of `workflow/`.

Reader-output location is overridable the same way, so a candidate edition can be
generated beside the canonical one without touching it:
`PHORVEX_ANATOMY_DIR` names the output directory (default `workflow/anatomy`),
`PHORVEX_ANATOMY_DOC` the reader filename inside it (default `ANATOMY.md`),
`PHORVEX_ANATOMY_STEM` the diagram basename under `generated/` (default `ANATOMY`) and
`PHORVEX_ANATOMY_EDITION` which edition is being generated (default `canonical`).
Unset, all four resolve exactly as before.

The doc and stem are NAMES, not paths. `PHORVEX_ANATOMY_DOC=../../anatomy/ANATOMY.md`
would have let a "staged" run write the canonical reader, so both are required to be a
single path component and every output is then re-checked to resolve INSIDE the output
directory — which also refuses a `generated/` that has been symlinked elsewhere.

Checking the three named outputs is not enough. The generators write dozens of files into
their own directory by relative name (`open('NODES.tsv','w')`), and a symlink planted at any
of them — or at a directory above them — redirects that write outside the tree while every
named-output check still passes. So the whole anatomy directory is scanned for escaping
symlinks at IMPORT time, which makes this a generator invocation boundary rather than a
CLI-only guarantee.

It is not the ONLY one. Three pipeline scripts write without importing `paths`:
`build_effect_matrix.py`, `build_operation_matrix.py` and `mutation_test.py`. They import
`guard.py`, which runs the same scan over both directories a relative write can land in:
the script's own directory and the process CWD.

What this does NOT cover: a script that imports neither module, and anything the process does
after import. The scan is a precondition, not a sandbox.
"""
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parents[1]
REPO_PATH = Path(os.environ.get("PHORVEX_CODE_REPO", WORKFLOW.parent)).resolve()
MODULE_PATH = REPO_PATH / "phorvex"
REPO = str(REPO_PATH) + "/"
MODULE = str(MODULE_PATH) + "/"
MODULE_STR = MODULE

EDITIONS = ('canonical', 'candidate')


def component(var, value, default):
    """One safe path component, or refuse. Empty/absolute/traversing/nested all refuse."""
    if value is None or value == '':
        value = default
    if (os.path.isabs(value) or os.sep in value or (os.altsep and os.altsep in value)
            or '/' in value or value in ('.', '..') or value != os.path.basename(value)):
        raise SystemExit(f'{var}={value!r} must be a single file name, not a path')
    return value


def contained(path, root, what):
    """`path` must resolve inside `root`. resolve() follows symlinks, which is the point."""
    rp, rr = Path(path).resolve(), Path(root).resolve()
    if rp != rr and rr not in rp.parents:
        raise SystemExit(f'{what} would be written to {rp}, outside the anatomy directory {rr}')
    return path


def escaping_descendants(root):
    """Every symlink under `root` whose target leaves it. Empty when the tree is safe.

    Walks WITHOUT following links, so a directory link is reported rather than descended
    into, and a link cycle cannot hang the walk. Files and directories both, at any depth:
    the reproduction that motivated this was `pipeline/SOURCE_PIN.json` pointing outside.
    """
    root = Path(root).resolve()
    out = []
    if not root.is_dir():
        return out
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs) + list(files):
            here = Path(base) / name
            if not here.is_symlink():
                continue
            there = here.resolve()
            if there != root and root not in there.parents:
                out.append((str(here), str(there)))
    return sorted(out)


ANATOMY_DIR = Path(os.environ.get("PHORVEX_ANATOMY_DIR", WORKFLOW / "anatomy")).resolve()
ANATOMY_DOC = contained(
    ANATOMY_DIR / component('PHORVEX_ANATOMY_DOC', os.environ.get('PHORVEX_ANATOMY_DOC'), 'ANATOMY.md'),
    ANATOMY_DIR, 'the reader document')
GENERATED_DIR = contained(ANATOMY_DIR / "generated", ANATOMY_DIR, 'the generated directory')
DIAGRAM_STEM = component('PHORVEX_ANATOMY_STEM', os.environ.get('PHORVEX_ANATOMY_STEM'), 'ANATOMY')
MMD_PATH = contained(GENERATED_DIR / f"{DIAGRAM_STEM}.mmd", ANATOMY_DIR, 'the diagram')
SVG_PATH = contained(GENERATED_DIR / f"{DIAGRAM_STEM}.svg", ANATOMY_DIR, 'the rendered diagram')
EDITION = os.environ.get("PHORVEX_ANATOMY_EDITION", "canonical")
if EDITION not in EDITIONS:
    raise SystemExit(f'PHORVEX_ANATOMY_EDITION={EDITION!r} must be one of {EDITIONS}')

_escapes = escaping_descendants(ANATOMY_DIR)
if _escapes:
    raise SystemExit(
        f'{len(_escapes)} symlink(s) under {ANATOMY_DIR} point outside it; refusing to run '
        'because the generators write by relative name and would follow them:\n  '
        + '\n  '.join(f'{a} -> {b}' for a, b in _escapes))
IS_CANDIDATE = EDITION == 'candidate'
ROOT_SURFACES = ('dashboard-web/', 'deploy/', 'build/', '.github/', '.dockerignore')
# `phorvex/go.mod` proves WHICH Phoenix is compiled in; it is evidence, not metadata.

def assert_no_collision():
    clash = [s for s in ROOT_SURFACES if (MODULE_PATH / s.rstrip('/')).exists()]
    if clash:
        raise SystemExit(f'anchor namespace collision: phorvex/ now contains {clash} — '
                         f'the prefix rule in paths.py is no longer unambiguous')

def base_of(p):
    """Which root this anchor path is relative to."""
    return REPO_PATH if p.startswith(ROOT_SURFACES) else MODULE_PATH

def full(p):
    return str(base_of(p) / p)

def exists(p):
    return os.path.exists(full(p))

def lines(p):
    if not exists(p): return None
    return open(full(p), errors='ignore').read().split('\n')

def line_at(p, n):
    ls = lines(p)
    if ls is None: return None
    return ls[n-1].strip() if 0 < n <= len(ls) else None

assert_no_collision()
