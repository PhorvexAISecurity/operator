"""Resolve operator commit hashes recorded in evidence to commits in this repository.

Receipts and reviews keep the hash of the PhorvexSecurity/operator commit they
describe. This repository was imported with rewritten history, so git lookups go
through docs/provenance/operator-commit-map.tsv. A hash that is not in the map is
returned unchanged: it is either a commit made here or absent everywhere.
"""
from functools import lru_cache
from pathlib import Path

MAP = Path(__file__).resolve().parents[1] / "docs/provenance/operator-commit-map.tsv"


@lru_cache(maxsize=1)
def _commit_map():
    rows = MAP.read_text().splitlines()
    if not rows or rows[0] != "operator\toperator_refactored":
        raise ValueError(f"{MAP}: unexpected header")
    return dict(row.split("\t") for row in rows[1:] if row)


def local_commit(sha):
    """Return the commit in this repository that corresponds to an operator commit."""
    mapped = _commit_map().get(sha)
    if mapped == "pruned":
        raise ValueError(f"operator commit {sha} touched only archived evidence and was pruned")
    return mapped or sha
