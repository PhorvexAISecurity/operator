"""Render a reviewed, default-off Voice MCP console profile from literal sources.

This program makes local files only. The installation owner reviews the image
and audit identity, pins the generated ConfigMap name/digest in Helm, and then
uses the normal rollout. Fire discovers and binds current Pod UIDs each run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
PROBE_SHA = "137aa9fd6da049964bab29ee15958b3d7ccb8250531000bde881d44d5b9a98ea"
ATTACK_SHA = "843b6fce61bae1a62ab069c889352b55e271bfb32ca23b6bba2d63461ce22b90"
BENIGN_SHA = "6b634936283ce28c2e25b71fa3575d0e23c69839999eed6e917fb52d8d176e37"
GOOD_SHA = "a4b965102419d4a81c4fd23cb3c93891f9932b8560b18bcd17f48aea81a337c8"


def digest(*paths: Path) -> str:
    h = hashlib.sha256()
    for index, path in enumerate(paths):
        if index:
            h.update(b"\0")
        h.update(path.read_bytes())
    return h.hexdigest()


def render(bot: Path, memory: Path, output: Path, mcp: Path, server: Path, probe: Path,
           attack: Path, benign: Path, image: str, deployment_uid: str,
           audit_identity: str) -> dict[str, object]:
    if not IMAGE.fullmatch(image) or not UID.fullmatch(deployment_uid) or not audit_identity or \
            len(audit_identity) > 256 or any(c in audit_identity for c in "\n\r\0"):
        raise ValueError("reviewed image, Deployment UID or audit identity invalid")
    if digest(probe) != PROBE_SHA or digest(attack) != ATTACK_SHA or digest(benign) != BENIGN_SHA:
        raise ValueError("reviewed fixed probe or audio bytes differ")
    source_sha = digest(bot, memory, mcp)
    combined_sha = digest(bot, memory, output, mcp)
    server_sha = digest(server)
    profile = {"version": 1, "sourceSHA256": source_sha, "sourceConfigMapSHA256": combined_sha,
               "mcpSourceSHA256": server_sha, "mcpImage": image, "probeSHA256": PROBE_SHA,
               "attackClipSHA256": ATTACK_SHA, "benignClipSHA256": BENIGN_SHA,
               "goodDescriptorSHA256": GOOD_SHA, "policyName": "voice-defense",
               "eventCreator": "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
               "auditSourceIdentity": audit_identity, "maxRunSeconds": 900}
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    profile_sha = hashlib.sha256(raw).hexdigest()
    cm_name = "phorvex-catalogue-voice-mcp-" + profile_sha[:12]
    configmap = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": cm_name, "namespace": "phorvex-system"},
                 "immutable": True, "data": {"profile.json": raw.decode()}}
    values = {"phorvex": {"console": {"voiceMCPLive": {
        "enabled": True, "configMapName": cm_name, "profileSHA256": profile_sha,
        "deploymentUID": deployment_uid,
        "sourceConfigMapName": "voice-memory-source-" + combined_sha[:12],
        "mcpSourceConfigMapName": "voice-mcp-source-" + server_sha[:12]}}}}
    return {"profile": profile, "profileSHA256": profile_sha,
            "configMap": configmap, "values": values}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("bot", "memory", "output", "mcp", "server", "probe", "attack", "benign"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--mcp-image", required=True)
    parser.add_argument("--deployment-uid", required=True)
    parser.add_argument("--audit-identity", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.out_dir.exists():
        raise SystemExit("output directory already exists")
    result = render(args.bot, args.memory, args.output, args.mcp, args.server, args.probe,
                    args.attack, args.benign, args.mcp_image, args.deployment_uid,
                    args.audit_identity)
    args.out_dir.mkdir(mode=0o700)
    for filename, item in (("profile.json", result["profile"]),
                           ("profile-configmap.json", result["configMap"]),
                           ("helm-values.json", result["values"])):
        (args.out_dir / filename).write_text(json.dumps(item, sort_keys=True, separators=(",", ":")))
    print(result["profileSHA256"])


if __name__ == "__main__":
    main()
