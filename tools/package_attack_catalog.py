#!/usr/bin/env python3
"""Build the production Console catalogue from the pinned, reviewed runner metadata.

This copies metadata only.  Operator paths, shell recipes and farm execution details are
deliberately outside the production artifact.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "live-attack-runner" / "catalog-192.txt"
FIRES = ROOT / "tools" / "live-attack-runner" / "runner" / "fires.d"
OUTPUT = ROOT / "phorvex" / "internal" / "attackcatalog" / "catalog.json"


def manifest_ids(path: Path = MANIFEST) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def fire_specs(path: Path = FIRES) -> dict[str, dict]:
    specs: dict[str, dict] = {}
    for source in sorted(path.glob("*.json")):
        spec = json.loads(source.read_text(encoding="utf-8"))
        name = spec.get("name")
        if not isinstance(name, str) or not name or name in specs:
            raise ValueError(f"invalid or duplicate fire name in {source}")
        specs[name] = spec
    return specs


def build_document() -> dict:
    ids = manifest_ids()
    if len(ids) != 192 or len(set(ids)) != 192 or ids[0] != "AML.T0012":
        raise ValueError("pinned catalogue must contain 192 unique IDs beginning AML.T0012")
    specs = fire_specs()
    entries = []
    for order, name in enumerate(ids, 1):
        try:
            spec = specs[name]
        except KeyError as exc:
            raise ValueError(f"pinned fire {name!r} has no reviewed metadata") from exc
        expected_actions = spec.get("defended")
        if not isinstance(expected_actions, list) or len(expected_actions) != 1:
            raise ValueError(f"{name}: exactly one reviewed defensive action is required")
        required = {
            "description": spec.get("desc"),
            "family": spec.get("family"),
            "expectedAction": expected_actions[0],
            "eventType": spec.get("event_type"),
            "mode": spec.get("mode"),
            "lane": spec.get("lane"),
            "expected": spec.get("expected"),
        }
        if any(not isinstance(value, str) or not value.strip() for value in required.values()):
            raise ValueError(f"{name}: incomplete reviewable fire metadata")
        if required["expected"] != "DEFENDED" or required["mode"] != "lane":
            raise ValueError(f"{name}: pinned catalogue contract changed")
        entries.append({"id": name, "order": order, **required, "reactiveCompatible": True})
    return {"schema": "phorvex.attack-catalogue.v1", "count": 192, "entries": entries}


def encoded_document() -> bytes:
    return (json.dumps(build_document(), ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail unless the embedded document is current")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    want = encoded_document()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != want:
            raise SystemExit(f"{args.output} is stale; run tools/package_attack_catalog.py")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(want)


if __name__ == "__main__":
    main()
