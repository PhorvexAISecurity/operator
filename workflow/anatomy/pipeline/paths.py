#!/usr/bin/env python3
"""Resolve an anatomy anchor to a file on disk.

Until now every anchor was relative to the Go module (`phorvex/`), which quietly made the
module the boundary of the anatomy. The shipped product is larger: a Next.js SPA, an image
that composes four binaries, and Helm/EKS values. Those anchors are relative to the REPO ROOT.

The two namespaces do not collide — `phorvex/` contains no `dashboard-web`, `deploy` or
`build` — so the prefix alone decides, and `assert_no_collision()` fails if that ever changes.

The workflow copy is portable: `PHORVEX_CODE_REPO` may name any clean worktree.
Otherwise the code repository is the parent of `workflow/`.
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
ANATOMY_DIR = WORKFLOW / "anatomy"
ANATOMY_DOC = ANATOMY_DIR / "ANATOMY.md"
GENERATED_DIR = ANATOMY_DIR / "generated"
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
