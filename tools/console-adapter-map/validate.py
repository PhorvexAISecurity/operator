#!/usr/bin/env python3
"""Build and validate the exact Console catalogue adapter mapping.

This is an offline source join.  It neither imports the live runner nor talks to a
cluster.  The checked-in JSON is generated deterministically from the pinned 192-ID
manifest, the production catalogue metadata, and the reviewed fires.d specifications.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import copy
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "workflow" / "attacks" / "console-adapters" / "catalogue-map.json"
MANIFEST = ROOT / "tools" / "live-attack-runner" / "catalog-192.txt"
CATALOGUE = ROOT / "phorvex" / "internal" / "attackcatalog" / "catalog.json"
FIRES = ROOT / "tools" / "live-attack-runner" / "runner" / "fires.d"
RUNNER = ROOT / "tools" / "live-attack-runner" / "runner" / "phvx-attack.py"

SCHEMA = "phorvex.console-adapter-map.v1"
PROFILE_SCHEMA = "phorvex.console-family-adapter-profile.v1"
MODE_CONTRACT_REF = "contract:console-runtime-modes:v1"
SIGNAL_CONTRACT_REF = "contract:exact-signal-decision-binding:v1"
CLEANUP_CONTRACT_REF = "contract:verified-exact-cleanup:v1"

EXPECTED_FAMILY_COUNTS = {
    "agent-action": 6,
    "controller-stop": 10,
    "credential": 24,
    "datastore": 5,
    "identity-sa-rotate": 13,
    "image": 27,
    "network-edge": 9,
    "node-recycle": 12,
    "pod-rotate": 27,
    "quarantine": 33,
    "sensitive-output": 3,
    "serving-kv": 3,
    "serving-rate": 20,
}

PYTHON_SOURCE = "tools/live-attack-runner/runner/phvx-attack.py"


def pyref(symbol: str) -> dict[str, str]:
    return {"path": PYTHON_SOURCE, "symbol": symbol}


# These are reviewed references into the current family implementations.  They are
# deliberately family-level: the 192 rows below bind exact membership and never copy
# an implementation per attack ID.
FAMILY_IMPLEMENTATIONS = {
    "agent-action": {
        "class": "AgentActionFamily",
        "expectedAction": "agent-action-deny",
        "destination": ["AgentActionFamily.__init__", "AgentActionFamily.setup"],
        "preflight": ["AgentActionFamily.preflight", "AgentActionFamily.baseline_clean"],
        "signal": ["AgentActionFamily.annotations", "actuated_decisions"],
        "oracle": ["AgentActionFamily.recheck"],
        "cleanup": ["AgentActionFamily.setup", "cmd_fire"],
    },
    "controller-stop": {
        "class": "ControllerStopFamily",
        "expectedAction": "controller-stop",
        "destination": ["_FlagPodFamily.__init__"],
        "preflight": ["_LaneFamily.preflight", "_FlagPodFamily.baseline_clean"],
        "signal": ["_FlagPodFamily.annotations", "actuated_decisions"],
        "oracle": ["RotateFamily.recheck"],
        "cleanup": ["_FlagPodFamily.arm", "cmd_fire"],
    },
    "credential": {
        "class": "CredentialFamily",
        "expectedAction": "credential-revoke",
        "destination": ["CredentialFamily.__init__", "CredentialFamily.setup"],
        "preflight": ["_LaneFamily.preflight", "CredentialFamily.baseline_clean"],
        "signal": ["CredentialFamily.annotations", "actuated_decisions"],
        "oracle": ["CredentialFamily.recheck"],
        "cleanup": ["CredentialFamily.arm", "cmd_fire"],
    },
    "datastore": {
        "class": "DatastoreFamily",
        "expectedAction": "datastore-restore",
        "destination": ["DatastoreFamily.__init__"],
        "preflight": ["_LaneFamily.preflight", "DatastoreFamily.baseline_clean"],
        "signal": ["DatastoreFamily.annotations", "actuated_decisions"],
        "oracle": ["DatastoreFamily.recheck"],
        "cleanup": ["DatastoreFamily.arm", "cmd_fire"],
    },
    "identity-sa-rotate": {
        "class": "IdentitySARotateFamily",
        "expectedAction": "identity-rotate",
        "destination": ["IdentitySARotateFamily.__init__"],
        "preflight": ["IdentitySARotateFamily.preflight", "IdentitySARotateFamily.baseline_clean"],
        "signal": ["IdentitySARotateFamily.custom_fire"],
        "oracle": ["IdentitySARotateFamily.custom_fire"],
        "cleanup": ["IdentitySARotateFamily.custom_fire", "cmd_fire"],
    },
    "image": {
        "class": "ImageFamily",
        "expectedAction": "registry-rollback",
        "destination": ["ImageFamily.__init__"],
        "preflight": ["_LaneFamily.preflight", "ImageFamily.baseline_clean"],
        "signal": ["ImageFamily.annotations", "actuated_decisions"],
        "oracle": ["ImageFamily.recheck"],
        "cleanup": ["ImageFamily.arm", "cmd_fire"],
    },
    "network-edge": {
        "class": "NetworkEdgeFamily",
        "expectedAction": "network-isolate",
        "destination": ["NetworkEdgeFamily.__init__", "NetworkEdgeFamily.setup"],
        "preflight": ["_LaneFamily.preflight", "NetworkEdgeFamily.baseline_clean"],
        "signal": ["NetworkEdgeFamily.annotations", "actuated_decisions"],
        "oracle": ["NetworkEdgeFamily.recheck"],
        "cleanup": ["NetworkEdgeFamily.arm", "cmd_fire"],
    },
    "node-recycle": {
        "class": "NodeRecycleFamily",
        "expectedAction": "node-cordon-drain-replace",
        "destination": ["NodeRecycleFamily.__init__"],
        "preflight": ["NodeRecycleFamily.preflight", "NodeRecycleFamily.baseline_clean"],
        "signal": ["NodeRecycleFamily.annotations", "actuated_decisions"],
        "oracle": ["NodeRecycleFamily.recheck"],
        "cleanup": ["NodeRecycleFamily.arm", "cmd_fire"],
    },
    "pod-rotate": {
        "class": "RotateFamily",
        "expectedAction": "rotate",
        "destination": ["_FlagPodFamily.__init__"],
        "preflight": ["_LaneFamily.preflight", "_FlagPodFamily.baseline_clean"],
        "signal": ["_FlagPodFamily.annotations", "actuated_decisions"],
        "oracle": ["RotateFamily.recheck"],
        "cleanup": ["_FlagPodFamily.arm", "cmd_fire"],
    },
    "quarantine": {
        "class": "QuarantineFamily",
        "expectedAction": "quarantine",
        "destination": ["QuarantineFamily.__init__"],
        "preflight": ["_LaneFamily.preflight", "_FlagPodFamily.baseline_clean"],
        "signal": ["QuarantineFamily.annotations", "actuated_decisions"],
        "oracle": ["QuarantineFamily.recheck"],
        "cleanup": ["QuarantineFamily._cleanup", "cmd_fire"],
    },
    "sensitive-output": {
        "class": "SensitiveOutputFamily",
        "expectedAction": "sensitive-output-policy-activate",
        "destination": ["SensitiveOutputFamily.__init__", "SensitiveOutputFamily.setup"],
        "preflight": ["_LaneFamily.preflight", "SensitiveOutputFamily.baseline_clean"],
        "signal": ["SensitiveOutputFamily.annotations", "actuated_decisions"],
        "oracle": ["SensitiveOutputFamily.recheck"],
        "cleanup": ["SensitiveOutputFamily.setup", "cmd_fire"],
    },
    "serving-kv": {
        "class": "ServingKVFamily",
        "expectedAction": "kv-reset",
        "destination": ["ServingKVFamily.__init__", "ServingKVFamily.setup"],
        "preflight": ["ServingKVFamily.preflight", "ServingKVFamily.baseline_clean"],
        "signal": ["ServingKVFamily.annotations", "actuated_decisions"],
        "oracle": ["ServingKVFamily.recheck"],
        "cleanup": ["ServingKVFamily.setup", "cmd_fire"],
    },
    "serving-rate": {
        "class": "ServingRateFamily",
        "expectedAction": "throttle",
        "destination": ["ServingRateFamily"],
        "preflight": ["ServingRateFamily.preflight", "ServingRateFamily.baseline_clean"],
        "signal": ["ServingRateFamily.custom_fire"],
        "oracle": ["ServingRateFamily.custom_fire"],
        "cleanup": ["ServingRateFamily.custom_fire", "cmd_fire"],
    },
}

# These references prove the packaged Go factory and the central exact-ID registry
# seam.  The six agent-action rows deliberately have no implementation references:
# their reviewed metadata exists, but packaging has no immutable runtime fixture.
REGISTRY_REF = {
    "path": "phorvex/internal/console/attack_catalog_runtime.go",
    "symbol": "newAttackCatalogAdapterRegistry",
}
CONSOLE_FAMILY_IMPLEMENTATIONS = {
    family: [
        {"path": "phorvex/internal/console/attack_catalog_adapters_k8s.go", "symbol": "newK8sCatalogueAdapters"},
        REGISTRY_REF,
    ]
    for family in ("quarantine", "pod-rotate", "controller-stop")
}
CONSOLE_FAMILY_IMPLEMENTATIONS.update({
    family: [
        {"path": "phorvex/internal/console/attack_catalog_adapters_infra.go", "symbol": "newInfraCatalogueAdapters"},
        REGISTRY_REF,
    ]
    for family in ("network-edge", "datastore", "image", "node-recycle")
})
CONSOLE_FAMILY_IMPLEMENTATIONS.update({
    family: [
        {"path": "phorvex/internal/console/attack_catalog_adapters_serving.go", "symbol": "newServingCatalogueAdapters"},
        REGISTRY_REF,
    ]
    for family in ("serving-rate", "sensitive-output", "serving-kv")
})
CONSOLE_FAMILY_IMPLEMENTATIONS.update({
    "credential": [
        {"path": "phorvex/internal/console/attack_catalog_adapters_identity.go", "symbol": "newIdentityCatalogueAdapters"},
        {"path": "phorvex/internal/console/attack_catalog_adapters_identity_credential.go", "symbol": "identityCredentialCatalogueBinding"},
        REGISTRY_REF,
    ],
    "identity-sa-rotate": [
        {"path": "phorvex/internal/console/attack_catalog_adapters_identity.go", "symbol": "newIdentityCatalogueAdapters"},
        {"path": "phorvex/internal/console/attack_catalog_adapters_identity_rotation.go", "symbol": "identityRotationCatalogueBinding"},
        REGISTRY_REF,
    ],
})
AML_T0012_IMPLEMENTATION = [
    {"path": "phorvex/internal/console/attack_catalog_identity_run.go", "symbol": "identityAttackCatalogAdapter"},
    REGISTRY_REF,
]
AGENT_ACTION_UNAVAILABLE_REASON = (
    "agent-action-deny catalogue profile is not installable: packaging has no "
    "digest-pinned server-owned agent-sim image, immutable fixed fixture manifest, "
    "or attacks-service fixture RBAC"
)


def console_implementation_refs(identifier: str, family: str) -> list[dict[str, str]]:
    if family == "agent-action":
        return []
    if identifier == "AML.T0012":
        return copy.deepcopy(AML_T0012_IMPLEMENTATION)
    return copy.deepcopy(CONSOLE_FAMILY_IMPLEMENTATIONS.get(family, []))


class ValidationError(ValueError):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"{path}: duplicate JSON field {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path}: invalid JSON: {exc}") from exc


def manifest_ids() -> list[str]:
    return [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def catalogue_entries() -> list[dict[str, Any]]:
    document = strict_json(CATALOGUE)
    need(isinstance(document, dict) and document.get("schema") == "phorvex.attack-catalogue.v1",
         "production catalogue schema changed")
    entries = document.get("entries")
    need(document.get("count") == 192 and isinstance(entries, list) and len(entries) == 192,
         "production catalogue must contain exactly 192 entries")
    return entries


def fire_specs() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    specs: dict[str, dict[str, Any]] = {}
    paths: dict[str, str] = {}
    for path in sorted(FIRES.glob("*.json")):
        spec = strict_json(path)
        need(isinstance(spec, dict), f"{path}: fire spec is not an object")
        name = spec.get("name")
        need(isinstance(name, str) and name, f"{path}: fire spec has no exact name")
        need(name not in specs, f"duplicate fire spec ID {name!r}")
        specs[name] = spec
        paths[name] = path.relative_to(ROOT).as_posix()
    return specs, paths


def runner_symbols() -> tuple[dict[str, set[str]], set[str], dict[str, str]]:
    source = RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(RUNNER))
    classes: dict[str, set[str]] = {}
    functions: set[str] = set()
    registration: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = {
                child.name for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "LANE_FAMILIES" for target in node.targets):
            need(isinstance(node.value, ast.Dict), "LANE_FAMILIES is no longer a literal exact mapping")
            for key, value in zip(node.value.keys, node.value.values):
                need(isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(value, ast.Name),
                     "LANE_FAMILIES contains a non-literal family registration")
                registration[key.value] = value.id
    return classes, functions, registration


def python_symbol_exists(symbol: str, classes: dict[str, set[str]], functions: set[str]) -> bool:
    if "." in symbol:
        class_name, method = symbol.split(".", 1)
        return class_name in classes and method in classes[class_name]
    return symbol in classes or symbol in functions


def source_symbol_exists(reference: dict[str, str]) -> bool:
    path = ROOT / reference["path"]
    if not path.is_file():
        return False
    source = path.read_text(encoding="utf-8")
    symbol = reference["symbol"]
    suffix = path.suffix
    if suffix == ".go":
        return re.search(r"\b(?:func|type)\s+(?:\([^)]*\)\s*)?" + re.escape(symbol) + r"\b", source) is not None
    return symbol in source


def profile_ref(family: str) -> str:
    return f"console-family-profile:{family}:v1"


def stage_ref(family: str, stage: str) -> str:
    return f"{profile_ref(family)}#{stage}"


def build_profile(family: str, count: int, spec: dict[str, Any]) -> dict[str, Any]:
    implementation = pyref(spec["class"])
    return {
        "schema": PROFILE_SCHEMA,
        "family": family,
        "profileRef": profile_ref(family),
        "memberCount": count,
        "expectedAction": spec["expectedAction"],
        "referenceImplementation": {
            "exists": True,
            "sourceRef": implementation,
            "registrationRef": pyref("LANE_FAMILIES"),
        },
        "fixedDestination": {
            "ref": stage_ref(family, "fixed-destination"),
            "sourceSpecFields": ["/lane", "/target"],
            "callerOverridable": False,
            "sourceRefs": [pyref(symbol) for symbol in spec["destination"]],
        },
        "preflight": {
            "ref": stage_ref(family, "preflight"),
            "mustCompleteBeforeMutation": True,
            "sourceRefs": [pyref(symbol) for symbol in spec["preflight"]],
        },
        "signalDecisionBinding": {
            "ref": stage_ref(family, "signal-decision-binding"),
            "contractRef": SIGNAL_CONTRACT_REF,
            "sourceRefs": [pyref(symbol) for symbol in spec["signal"]],
        },
        "physicalOracle": {
            "ref": stage_ref(family, "physical-oracle"),
            "sourceRefs": [pyref(symbol) for symbol in spec["oracle"]],
        },
        "cleanup": {
            "ref": stage_ref(family, "cleanup"),
            "contractRef": CLEANUP_CONTRACT_REF,
            "sourceRefs": [pyref(symbol) for symbol in spec["cleanup"]],
        },
        "runtimeModes": {
            "contractRef": MODE_CONTRACT_REF,
            "executionMode": {
                "resolvedBy": "preflight",
                "allowed": ["active", "dryRun"],
                "defendedRequires": "active",
            },
            "triggerMode": {
                "resolvedBy": "preflight",
                "allowed": ["reactive", "proactive+reactive"],
            },
        },
    }


def build_document() -> dict[str, Any]:
    ids = manifest_ids()
    entries = catalogue_entries()
    specs, paths = fire_specs()
    need(len(ids) == len(set(ids)) == 192, "pinned manifest must contain exactly 192 unique IDs")
    need([entry.get("id") for entry in entries] == ids, "manifest and production catalogue order differ")

    profiles = [
        build_profile(family, EXPECTED_FAMILY_COUNTS[family], FAMILY_IMPLEMENTATIONS[family])
        for family in sorted(EXPECTED_FAMILY_COUNTS)
    ]
    mappings = []
    for entry in entries:
        identifier = entry["id"]
        family = entry["family"]
        implementation_refs = console_implementation_refs(identifier, family)
        implementation_exists = bool(implementation_refs)
        mappings.append({
            "id": identifier,
            "order": entry["order"],
            "family": family,
            "sourceSpec": paths[identifier],
            "adapterProfileRef": profile_ref(family),
            "fixedDestinationProfileRef": stage_ref(family, "fixed-destination"),
            "preflightRef": stage_ref(family, "preflight"),
            "signalDecisionBindingContractRef": stage_ref(family, "signal-decision-binding"),
            "physicalOracleRef": stage_ref(family, "physical-oracle"),
            "cleanupRef": stage_ref(family, "cleanup"),
            "runtimeModeContractRef": MODE_CONTRACT_REF,
            "supportingImplementationExists": implementation_exists,
            "supportingImplementationRefs": implementation_refs,
            "registrationStatus": "eligible" if implementation_exists else "unavailable",
            "unavailableReason": "" if implementation_exists else AGENT_ACTION_UNAVAILABLE_REASON,
        })
    return {
        "schema": SCHEMA,
        "catalogue": {
            "idSource": MANIFEST.relative_to(ROOT).as_posix(),
            "metadataSource": CATALOGUE.relative_to(ROOT).as_posix(),
            "specSource": FIRES.relative_to(ROOT).as_posix(),
            "expectedIDCount": 192,
            "expectedFamilyCount": 13,
        },
        "modeContract": {
            "ref": MODE_CONTRACT_REF,
            "executionMode": ["active", "dryRun"],
            "triggerMode": ["reactive", "proactive+reactive"],
            "note": "Execution effect and policy trigger posture are independent fields resolved by preflight.",
        },
        "sharedContracts": {
            "signalDecisionBinding": {
                "ref": SIGNAL_CONTRACT_REF,
                "required": [
                    "exact signal identity and target observed",
                    "decision ID observed after the run baseline",
                    "selected and feasible expected action",
                    "dispatch outcome emitted",
                    "accepted actuator receipt bound to the run",
                ],
            },
            "cleanup": {
                "ref": CLEANUP_CONTRACT_REF,
                "required": [
                    "cleanup attempted after any mutation",
                    "exact owned event and fixture mutations reconciled",
                    "postflight absence or restoration verified",
                    "unverified cleanup marks the run unsafe to retry",
                ],
            },
        },
        "familyProfiles": profiles,
        "mappings": mappings,
    }


def reject_launchable_claim(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            need(key != "launchable", f"{path}: static mapping must not represent an ID as launchable")
            reject_launchable_claim(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_launchable_claim(item, f"{path}[{index}]")


def validate_document(document: dict[str, Any]) -> None:
    need(isinstance(document, dict) and document.get("schema") == SCHEMA, "mapping schema changed")
    reject_launchable_claim(document)

    ids = manifest_ids()
    entries = catalogue_entries()
    specs, paths = fire_specs()
    catalogue_by_id = {entry["id"]: entry for entry in entries}
    expected_ids = set(ids)
    need(len(ids) == len(set(ids)) == 192, "authoritative manifest is not exactly 192 unique IDs")
    need([entry.get("id") for entry in entries] == ids, "authoritative manifest/catalogue exact order drift")
    actual_families = Counter(entry.get("family") for entry in entries)
    need(dict(sorted(actual_families.items())) == EXPECTED_FAMILY_COUNTS,
         f"authoritative family drift: {dict(sorted(actual_families.items()))!r}")
    need(set(FAMILY_IMPLEMENTATIONS) == set(EXPECTED_FAMILY_COUNTS), "reviewed family implementation table drift")

    classes, functions, runner_registration = runner_symbols()
    expected_registration = {
        family: FAMILY_IMPLEMENTATIONS[family]["class"] for family in EXPECTED_FAMILY_COUNTS
    }
    need({family: runner_registration.get(family) for family in EXPECTED_FAMILY_COUNTS} == expected_registration,
         "reviewed runner family registration drift")
    for family, implementation in FAMILY_IMPLEMENTATIONS.items():
        for stage in ("destination", "preflight", "signal", "oracle", "cleanup"):
            for symbol in implementation[stage]:
                need(python_symbol_exists(symbol, classes, functions),
                     f"{family}: referenced {stage} symbol {symbol!r} does not exist")

    catalogue = document.get("catalogue")
    need(catalogue == {
        "idSource": "tools/live-attack-runner/catalog-192.txt",
        "metadataSource": "phorvex/internal/attackcatalog/catalog.json",
        "specSource": "tools/live-attack-runner/runner/fires.d",
        "expectedIDCount": 192,
        "expectedFamilyCount": 13,
    }, "mapping catalogue authority/count contract changed")

    mode = document.get("modeContract")
    need(isinstance(mode, dict) and mode.get("ref") == MODE_CONTRACT_REF,
         "runtime mode contract reference changed")
    need(mode.get("executionMode") == ["active", "dryRun"],
         "execution mode must remain the distinct active|dryRun enum")
    need(mode.get("triggerMode") == ["reactive", "proactive+reactive"],
         "trigger mode must remain the distinct reactive|proactive+reactive enum")

    shared = document.get("sharedContracts")
    need(isinstance(shared, dict) and shared.get("signalDecisionBinding", {}).get("ref") == SIGNAL_CONTRACT_REF,
         "exact signal/decision contract is missing")
    need(shared.get("cleanup", {}).get("ref") == CLEANUP_CONTRACT_REF,
         "verified cleanup contract is missing")

    profiles = document.get("familyProfiles")
    need(isinstance(profiles, list), "familyProfiles must be a list")
    profile_families = [profile.get("family") for profile in profiles if isinstance(profile, dict)]
    need(len(profile_families) == len(set(profile_families)), "duplicate family profile")
    need(set(profile_families) == set(EXPECTED_FAMILY_COUNTS) and len(profiles) == 13,
         "family profiles must cover exactly the expected 13 families")
    profile_by_family = {profile["family"]: profile for profile in profiles}
    for family, count in EXPECTED_FAMILY_COUNTS.items():
        profile = profile_by_family[family]
        expected = build_profile(family, count, FAMILY_IMPLEMENTATIONS[family])
        need(profile == expected, f"{family}: incomplete or drifted family profile")

    mappings = document.get("mappings")
    need(isinstance(mappings, list), "mappings must be a list")
    mapped_ids = [item.get("id") for item in mappings if isinstance(item, dict)]
    duplicates = sorted(identifier for identifier, count in Counter(mapped_ids).items() if count > 1)
    need(not duplicates, f"duplicate mapping IDs: {duplicates}")
    unknown = sorted(set(mapped_ids) - expected_ids)
    need(not unknown, f"unknown mapping IDs: {unknown}")
    missing = sorted(expected_ids - set(mapped_ids))
    need(not missing, f"missing mapping IDs: {missing}")
    need(len(mappings) == 192 and mapped_ids == ids, "exact ID coverage/order must be the authoritative 192")

    for index, item in enumerate(mappings, 1):
        need(isinstance(item, dict), f"mapping row {index} is not an object")
        identifier = item["id"]
        entry = catalogue_by_id[identifier]
        family = entry["family"]
        need(item.get("order") == index == entry["order"], f"{identifier}: order drift")
        need(item.get("family") == family, f"{identifier}: family drift")
        need(item.get("sourceSpec") == paths[identifier], f"{identifier}: exact source spec drift")
        spec = specs[identifier]
        need(spec.get("family") == family and spec.get("lane") == entry.get("lane") and
             spec.get("actuator") == entry.get("expectedAction") and spec.get("event_type") == entry.get("eventType"),
             f"{identifier}: catalogue/fire specification drift")
        need(isinstance(spec.get("target"), dict) and spec["target"] and isinstance(spec.get("lane"), str) and spec["lane"],
             f"{identifier}: fixed destination is incomplete")
        refs = {
            "adapterProfileRef": profile_ref(family),
            "fixedDestinationProfileRef": stage_ref(family, "fixed-destination"),
            "preflightRef": stage_ref(family, "preflight"),
            "signalDecisionBindingContractRef": stage_ref(family, "signal-decision-binding"),
            "physicalOracleRef": stage_ref(family, "physical-oracle"),
            "cleanupRef": stage_ref(family, "cleanup"),
            "runtimeModeContractRef": MODE_CONTRACT_REF,
        }
        for field, expected_ref in refs.items():
            need(item.get(field) == expected_ref, f"{identifier}: incomplete or drifted {field}")

        implementation_refs = item.get("supportingImplementationRefs")
        implementation_exists = item.get("supportingImplementationExists")
        need(type(implementation_exists) is bool and isinstance(implementation_refs, list),
             f"{identifier}: supporting implementation status is incomplete")
        expected_refs = console_implementation_refs(identifier, family)
        need(implementation_refs == expected_refs and implementation_exists == bool(expected_refs),
             f"{identifier}: current Console implementation support drift")
        for reference in implementation_refs:
            need(isinstance(reference, dict) and set(reference) == {"path", "symbol"} and source_symbol_exists(reference),
                 f"{identifier}: supporting implementation reference does not exist")
        expected_status = "eligible" if implementation_exists else "unavailable"
        need(item.get("registrationStatus") == expected_status,
             f"{identifier}: unavailable support cannot be registration-eligible")
        expected_reason = "" if implementation_exists else AGENT_ACTION_UNAVAILABLE_REASON
        need(item.get("unavailableReason") == expected_reason,
             f"{identifier}: unavailable reason is missing or imprecise")


def encoded_document(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the deterministic checked-in artifact")
    parser.add_argument("--artifact", type=Path, default=ARTIFACT)
    args = parser.parse_args()

    expected = build_document()
    validate_document(expected)
    wanted = encoded_document(expected)
    if args.write:
        args.artifact.parent.mkdir(parents=True, exist_ok=True)
        args.artifact.write_bytes(wanted)
        return 0
    if not args.artifact.is_file():
        raise SystemExit(f"{args.artifact}: mapping artifact is missing; run with --write")
    actual = strict_json(args.artifact)
    validate_document(actual)
    if args.artifact.read_bytes() != wanted:
        raise SystemExit(f"{args.artifact}: mapping artifact is stale; run with --write")
    print("validated: 192 exact IDs, 13 exact family profiles, 186 registration-eligible, 6 unavailable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
