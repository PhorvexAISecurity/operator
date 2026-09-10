#!/usr/bin/env python3
"""Import-time containment guard for the pipeline scripts that do NOT import `paths`.

`paths.py` scans the anatomy output directory on import, and the docstring there used to say
"every generator imports this module". That was false, and the lead's R3 probe proved it:
`build_effect_matrix.py` writes `EFFECT_MATRIX.tsv` by relative name and imports neither
`paths` nor anything that does, so a symlink planted at that name was followed on a direct
invocation while every CLI-layer check passed.

Three scripts write into the pipeline directory without going through `paths`:
`build_effect_matrix.py`, `build_operation_matrix.py` and `mutation_test.py`, the last of
which rewrites the inventories in place. They import this instead.

The guard covers BOTH directories a relative write can land in: this module's own directory,
which is where the `HERE`-joining writers put their output, and the process CWD, which is where
the bare-relative-name writers put theirs. A first version checked only the module directory,
on the reasoning that a bare-name writer also READS by bare name and so could only run with the
pipeline directory as CWD. The lead's second R3 probe disproved that in one step: supply the
input files in another CWD and the script runs there, writing through a symlink the
module-directory scan never looked at. When the two are the same directory it is one scan.

What this does NOT cover, stated so it is not read as a sandbox: a script that imports neither
this nor `paths`, anything the process does after import, and any write whose destination is
computed rather than named. It is a precondition.
"""
import os
from pathlib import Path


def escaping_descendants(root):
    """Every symlink under `root` whose target leaves it. Empty when the tree is safe.

    Walks WITHOUT following links, so a directory link is reported rather than descended into
    and a link cycle cannot hang the walk.
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


def refuse_escapes(root):
    """Raise SystemExit if anything under `root` is a symlink pointing out of it."""
    escapes = escaping_descendants(root)
    if escapes:
        raise SystemExit(
            f'{len(escapes)} symlink(s) under {Path(root).resolve()} point outside it; '
            'refusing to run because this generator writes by relative name and would '
            'follow them:\n  ' + '\n  '.join(f'{a} -> {b}' for a, b in escapes))


HERE = Path(__file__).resolve().parent
CWD = Path.cwd().resolve()
GUARDED = tuple(dict.fromkeys((HERE, CWD)))
for _root in GUARDED:
    refuse_escapes(_root)
