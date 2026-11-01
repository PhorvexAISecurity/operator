#!/usr/bin/env python3
"""Print one reviewed, fully scoped catalogue-family staging values overlay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "deploy/environments/staging/phorvex.yaml"
PROFILE_SOURCE = ROOT / "deploy/charts/phorvex-attacks/files/catalogue-family-profiles.yaml"
PIN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
DEFAULT_PYTHON = "docker.io/library/python@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d"
DEFAULT_KWOK = "registry.k8s.io/kwok/kwok@sha256:6d25aa8fbdfe78845423160bf125b5513f9522e2770981f0945c2a250c2b26f0"
WORKLOAD_FAMILIES = {
    "controller-stop", "credential", "image",
    "network-edge", "node-recycle", "pod-rotate", "quarantine",
}
PHORVEX_FAMILIES = {"datastore", "serving-kv", "serving-rate"}


def immutable(name: str, value: str, required: bool = False) -> str:
    if required and not value:
        raise ValueError(f"--{name.replace('_', '-')} is required for this profile")
    if value and not PIN.fullmatch(value):
        raise ValueError(f"--{name.replace('_', '-')} must be repository@sha256:<64 lowercase hex>")
    return value


def profiles() -> dict[str, dict]:
    source = yaml.safe_load(PROFILE_SOURCE.read_text(encoding="utf-8"))
    return {item["family"]: item for item in source["profiles"]}


def overlay(args: argparse.Namespace) -> dict:
    profile = profiles()[args.profile]
    destinations = [item["namespace"] for item in profile["destinations"]]
    lanes = profile["lanes"]
    staging = yaml.safe_load(STAGING.read_text(encoding="utf-8"))["phorvex"]
    base_namespaces = ["phorvex-staging-demo", "console-identity-shared"]
    scopes = list(dict.fromkeys(base_namespaces + destinations))
    if args.profile == "identity-sa-rotate" and args.workload_image:
        raise ValueError("--workload-image must be empty for the externally owned identity fixture")
    workload = immutable("workload_image", args.workload_image, args.profile in WORKLOAD_FAMILIES)
    phorvex = immutable("phorvex_image", args.phorvex_image, args.profile in PHORVEX_FAMILIES)
    agent = immutable("agent_image", args.agent_image, args.profile == "agent-action")
    python = immutable("python_image", args.python_image, args.profile in {"sensitive-output", "serving-kv"})
    kwok = immutable("kwok_image", args.kwok_image, args.profile == "node-recycle")
    trusted = ["phorvex-staging/staging-attacks"] + [f"{lane}/{lane}-attacks" for lane in lanes]
    if args.profile == "serving-rate":
        trusted.append("p5-demo/rate-detector")

    grants = json.loads(staging["console"]["auth"]["grants"]["data"])
    for subject in grants["subjects"]:
        subject["tenants"] = [destinations[0]]

    result = {
        "phorvex": {
            "policyNamespaces": list(scopes),
            "actuatorNamespaces": list(scopes),
            "trustedDetectors": trusted,
            "agentActionDeny": {"enabled": args.profile == "agent-action", "namespaces": ["p6-demo"] if args.profile == "agent-action" else []},
            "outputPolicy": {"enabled": False, "targetNamespace": "", "configMapName": "", "configMapNames": []},
            "console": {
                "attackNamespaces": list(scopes),
                "attackCatalog": {
                    "enabled": True,
                    "authorizationTenant": destinations[0],
                    "familyFixtures": {
                        "enabled": True,
                        "profile": args.profile,
                        "cleanupPolicy": "Delete",
                        "images": {"workload": workload, "phorvex": phorvex, "guardrail": "", "python": python, "kwok": kwok},
                    },
                    "agentAction": {"enabled": args.profile == "agent-action", "namespace": "p6-demo", "image": agent},
                    "prometheusEvidence": {"enabled": True},
                },
                "auth": {"grants": {"data": json.dumps(grants, indent=2) + "\n"}},
            },
        }
    }
    if args.profile == "sensitive-output":
        result["phorvex"]["outputPolicy"] = {
            "enabled": True,
            "targetNamespace": "p6-demo",
            "configMapName": "",
            "configMapNames": [
                "phorvex-output-policy-gfx-t0069",
                "phorvex-output-policy-gfx-t0069-001",
                "phorvex-output-policy-gfx-t0069-002",
            ],
        }
    if args.profile == "serving-kv":
        result["phorvex"]["servingSecurity"] = {"mode": "legacy-plaintext"}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(profiles()))
    parser.add_argument("--workload-image", default="")
    parser.add_argument("--phorvex-image", default="")
    parser.add_argument("--agent-image", default="")
    parser.add_argument("--python-image", default=DEFAULT_PYTHON)
    parser.add_argument("--kwok-image", default=DEFAULT_KWOK)
    args = parser.parse_args()
    try:
        values = overlay(args)
    except ValueError as error:
        parser.error(str(error))
    yaml.safe_dump(values, sys.stdout, sort_keys=False, width=120)


if __name__ == "__main__":
    main()
