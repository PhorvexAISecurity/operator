"""Render a guarded, env-only canonical MCP endpoint migration; no API writes."""

import argparse
import json
import os
from pathlib import Path

from render_activation import MCP_URL, UID, require

LEGACY_URL = MCP_URL + "/"


def render(deployment: dict, expected_uid: str, expected_rv: str) -> list[dict]:
    meta = deployment.get("metadata", {})
    require(deployment.get("apiVersion") == "apps/v1" and deployment.get("kind") == "Deployment" and
            meta.get("namespace") == "voice" and meta.get("name") == "voice-bot", "wrong Deployment target")
    require(bool(UID.fullmatch(expected_uid)) and meta.get("uid") == expected_uid, "Deployment UID differs")
    require(isinstance(expected_rv, str) and expected_rv.isdecimal() and meta.get("resourceVersion") == expected_rv,
            "Deployment resourceVersion differs")
    containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    bots = [(i, c) for i, c in enumerate(containers) if c.get("name") == "bot"]
    require(len(bots) == 1, "expected one bot container")
    index, bot = bots[0]
    env = bot.get("env", [])
    endpoints = [(i, e) for i, e in enumerate(env) if e.get("name") == "MCP_URL"]
    require(len(endpoints) == 1, "expected one explicit MCP_URL")
    env_index, old = endpoints[0]
    require(old == {"name": "MCP_URL", "value": LEGACY_URL}, "MCP_URL is not the exact legacy literal")
    prefix = f"/spec/template/spec/containers/{index}"
    path = f"{prefix}/env/{env_index}"
    return [
        {"op": "test", "path": "/metadata/uid", "value": expected_uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": expected_rv},
        {"op": "test", "path": prefix + "/name", "value": "bot"},
        {"op": "test", "path": path, "value": old},
        {"op": "replace", "path": path + "/value", "value": MCP_URL},
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--expected-uid", required=True)
    parser.add_argument("--expected-resource-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    patch = render(json.loads(args.deployment.read_text()), args.expected_uid, args.expected_resource_version)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        json.dump(patch, out, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
