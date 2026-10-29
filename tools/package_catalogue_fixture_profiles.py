#!/usr/bin/env python3
"""Generate the release-owned 13-family fixture catalogue from the 192 IDs."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "phorvex/internal/attackcatalog/catalog.json"
OUTPUT = ROOT / "deploy/charts/phorvex-attacks/files/catalogue-family-profiles.yaml"

# Destination/object identities are the fixed contracts compiled into the exact
# adapters. They are release configuration, never request parameters.
CONTRACTS = {
    "agent-action": {
        "destinations": [{"operatorNamespace": "p6", "namespace": "p6-demo"}],
        "workload": "Deployment/p6-demo/agent-sim",
        "policy": "PhorvexPolicy/p6-demo/agent-defense",
        "cleanup": "guard restored by exact run; chart owns remaining labelled objects",
    },
    "controller-stop": {
        "destinations": [{"operatorNamespace": "p4", "namespace": "p4-demo"}],
        "workload": "Deployment/p4-demo/demo-api",
        "policy": "PhorvexPolicy/p4-demo/demo-api-defense",
        "cleanup": "exact event deleted; replacement Pod ready; chart owns substrate",
    },
    "credential": {
        "destinations": [{"operatorNamespace": "p4", "namespace": "p4-demo"}],
        "workload": "Deployment/p4-demo/demo-api",
        "policy": "PhorvexPolicy/p4-demo/demo-api-defense",
        "cleanup": "run-owned ServiceAccount, Secret, Role and RoleBinding deleted by UID",
    },
    "datastore": {
        "destinations": [{"operatorNamespace": "p2", "namespace": "p2-demo"}],
        "workload": "Deployment/p2-demo/rag-store",
        "policy": "PhorvexPolicy/p2-demo/datastore-defense",
        "cleanup": "run-written poison reconciled to the separate trusted snapshot",
    },
    "identity-sa-rotate": {
        "destinations": [{"operatorNamespace": "p6", "namespace": "console-identity-shared"}],
        "workload": "Deployment/console-identity-shared/console-id-fixture",
        "policy": "PhorvexPolicy/console-identity-shared/console-id-fixture",
        "cleanup": "run-owned token marker removed; rotated identity is retained",
    },
    "image": {
        "destinations": [
            {"operatorNamespace": "p2", "namespace": "p2-demo"},
            {"operatorNamespace": "p3", "namespace": "p3-demo"},
        ],
        "workload": "Deployment/{p2-demo,p3-demo}/demo-api",
        "policy": "one exact selecting PhorvexPolicy per destination",
        "cleanup": "Deployment and running Pods converge to trusted repository@sha256 pin",
    },
    "network-edge": {
        "destinations": [{"operatorNamespace": "p2", "namespace": "p2-demo"}],
        "workload": "Deployment/p2-demo/demo-api and Pod/p2-demo/c2-sink",
        "policy": "PhorvexPolicy/p2-demo/demo-api-defense",
        "cleanup": "run-owned Pod NetworkPolicy deleted and isolation markers removed",
    },
    "node-recycle": {
        "destinations": [{"operatorNamespace": "p3", "namespace": "p3-demo"}],
        "workload": "Deployment/p3-demo/demo-api on Nodes p3-node-a,p3-node-b",
        "policy": "PhorvexPolicy/p3-demo/node-defense",
        "cleanup": "reviewed KWOK node-a recreated clean; node-b identity retained",
    },
    "pod-rotate": {
        "destinations": [{"operatorNamespace": "p2", "namespace": "p2-demo"}],
        "workload": "Deployment/p2-demo/demo-api",
        "policy": "PhorvexPolicy/p2-demo/demo-api-defense",
        "cleanup": "exact event deleted; replacement Pod baseline retained",
    },
    "quarantine": {
        "destinations": [{"operatorNamespace": "p1", "namespace": "p1-demo"}],
        "workload": "Deployment/p1-demo/demo-api",
        "policy": "PhorvexPolicy/p1-demo/demo-api-defense",
        "cleanup": "exact event and quarantine NetworkPolicy deleted; capacity ledger restored",
    },
    "sensitive-output": {
        "destinations": [{"operatorNamespace": "p6", "namespace": "p6-demo"}],
        "workload": "Pods p6-demo/gfx-t0069{,-001,-002}",
        "policy": "PhorvexPolicy/p6-demo/guardrail-output-fixture",
        "cleanup": "Pod-owned policy activation rolled back; exact journal retained",
    },
    "serving-kv": {
        "destinations": [{"operatorNamespace": "p6", "namespace": "p6-demo"}],
        "workload": "Deployment/p6-demo/kv-serving",
        "policy": "PhorvexPolicy/p6-demo/kv-serving-defense",
        "cleanup": "run-owned implants reset on both retained Pods",
    },
    "serving-rate": {
        "destinations": [{"operatorNamespace": "p5", "namespace": "p5-demo"}],
        "workload": "Deployment/p5-demo/rate-target through rate-admission",
        "policy": "PhorvexPolicy/p5-demo/serving-rate-defense",
        "cleanup": "exact load Jobs and event deleted; budget rolled back to quiet contract",
    },
}


def build() -> dict:
    import json

    source = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    entries = source.get("entries")
    if source.get("count") != 192 or not isinstance(entries, list) or len(entries) != 192:
        raise ValueError("embedded catalogue must contain exactly 192 entries")
    grouped: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        family, identifier = entry.get("family"), entry.get("id")
        if family not in CONTRACTS or not isinstance(identifier, str) or not identifier:
            raise ValueError("catalogue family or ID is outside the reviewed fixture table")
        grouped[family].append(entry)
    if set(grouped) != set(CONTRACTS):
        raise ValueError("fixture table must cover exactly 13 catalogue families")

    profiles = []
    seen: set[str] = set()
    for family in sorted(grouped):
        rows = grouped[family]
        expected_actions = {row.get("expectedAction") for row in rows}
        lanes = sorted({row.get("lane") for row in rows})
        ids = [row["id"] for row in rows]
        if len(expected_actions) != 1 or any(not lane for lane in lanes) or seen.intersection(ids):
            raise ValueError(f"{family}: catalogue membership is ambiguous")
        seen.update(ids)
        profile = {
            "family": family,
            "memberCount": len(rows),
            "expectedAction": next(iter(expected_actions)),
            "lanes": lanes,
            **CONTRACTS[family],
            "ids": ids,
        }
        profiles.append(profile)
    if len(profiles) != 13 or len(seen) != 192:
        raise ValueError("fixture profiles do not cover exactly 13 families / 192 IDs")
    return {
        "schema": "phorvex.staging-catalogue-family-fixtures.v1",
        "profileSelection": "exactly-one",
        "cleanupPolicy": "verified-run-cleanup-then-release-owned-object-removal",
        "profiles": profiles,
    }


def encoded() -> bytes:
    header = "# Generated by tools/package_catalogue_fixture_profiles.py; do not edit.\n"
    return (header + yaml.safe_dump(build(), sort_keys=False, width=120)).encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    wanted = encoded()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != wanted:
            raise SystemExit(f"{OUTPUT.relative_to(ROOT)} is stale")
        return
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(wanted)


if __name__ == "__main__":
    main()
