"""Records imported from the source repository whose evidence stays there.

``ARCHIVE.yaml`` freezes, at import, every fix, campaign (with its rounds) and
assessment that existed in the source repository, with a SHA-256 of each
archived STATUS.yaml. ``doctor`` keeps the structural contract strict for those
records but tolerates evidence files the import removed and skips checks that
need source-repository commits, which the history rewrite replaced. Records not
listed get every check. Archived records are immutable: a STATUS.yaml that
differs from its frozen digest, appears or disappears fails ``doctor``.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

FILE = "ARCHIVE.yaml"
SCHEMA = "archive.schema.json"
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Archive:
    source: dict = field(default_factory=dict)
    fixes: dict = field(default_factory=dict)
    campaigns: dict = field(default_factory=dict)
    assessments: frozenset = frozenset()

    def __bool__(self) -> bool:
        return bool(self.fixes or self.campaigns or self.assessments)

    @property
    def label(self) -> str:
        return f"{self.source.get('repository')}@{str(self.source.get('revision', ''))[:8]}"

    def fix(self, fix_id: str) -> bool:
        return fix_id in self.fixes

    def campaign(self, campaign_id: str) -> bool:
        return campaign_id in self.campaigns

    def round(self, campaign_id: str, round_id: object) -> bool:
        record = self.campaigns.get(campaign_id) or {}
        return str(round_id) in record.get("rounds", [])

    def summary(self) -> str:
        rounds = sum(len(record.get("rounds", [])) for record in self.campaigns.values())
        total = len(self.fixes) + len(self.campaigns) + len(self.assessments)
        return (
            f"{total} archived records (fixes {len(self.fixes)}, campaigns {len(self.campaigns)} "
            f"with {rounds} rounds, assessments {len(self.assessments)}) are verified only "
            f"against {self.label}; here doctor checks their structure, frozen STATUS digests "
            "and retained evidence, not removed evidence or source-commit pins (see ARCHIVE.yaml)"
        )


def read(root: Path) -> dict | None:
    """Return the raw declaration, or None when this tree declares no archive."""
    path = root / FILE
    if not path.is_file():
        return None
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{FILE} must be a mapping")
    return document


def parse(document: dict | None) -> Archive:
    if document is None:
        return Archive()
    records = document.get("records")
    source = document.get("source")
    if not isinstance(records, dict) or not isinstance(source, dict):
        raise ValueError(f"{FILE} needs source and records mappings")
    fixes = records.get("fixes") or {}
    campaigns = records.get("campaigns") or {}
    assessments = records.get("assessments") or []
    if not isinstance(fixes, dict) or not isinstance(campaigns, dict) or not isinstance(assessments, list):
        raise ValueError(f"{FILE} records have an invalid shape")
    for kind, values in (("fixes", fixes), ("campaigns", campaigns)):
        for record_id, record in values.items():
            digest = (record or {}).get("status_sha256")
            if digest is not None and not _SHA256.fullmatch(str(digest)):
                raise ValueError(f"{FILE} {kind}.{record_id}: invalid status_sha256")
    return Archive(
        source=dict(source),
        fixes={str(key): dict(value or {}) for key, value in fixes.items()},
        campaigns={
            str(key): {**(value or {}), "rounds": [str(r) for r in (value or {}).get("rounds", [])]}
            for key, value in campaigns.items()
        },
        assessments=frozenset(str(value) for value in assessments),
    )


def drift(root: Path, archive: Archive) -> list[str]:
    """Archived STATUS.yaml files must keep the bytes they had at import."""
    errors: list[str] = []
    for kind, records in (("fixes", archive.fixes), ("campaigns", archive.campaigns)):
        for record_id, record in sorted(records.items()):
            frozen = record.get("status_sha256")
            path = root / kind / record_id / "STATUS.yaml"
            label = f"{kind}/{record_id}/STATUS.yaml"
            if frozen is None:
                if path.exists():
                    errors.append(
                        f"{label}: archived id had no STATUS.yaml at import; "
                        "archived ids are not reused"
                    )
                continue
            if not path.is_file():
                errors.append(f"{label}: archived record was removed; archived records are immutable")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != frozen:
                errors.append(
                    f"{label}: archived record changed since import; archived records are "
                    "immutable (continue in a new record, or restore its evidence and "
                    f"delist it from {FILE})"
                )
    return errors
