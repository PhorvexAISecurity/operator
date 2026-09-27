"""Render reviewed Voice memory activation objects and an exact Deployment patch.

This program only writes local files. It does not call Kubernetes or print secrets.
The caller must supply fresh, private API snapshots and the observed bot UID.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from voice_memory_policy import canonical_bytes, source_sha256


SOURCE_SHA = "c378d172483887270514f2ead600f7c4b8e1ad4928cdead9348ca11e46a90010"
SOURCE_CONFIGMAP = "voice-memory-source-" + SOURCE_SHA[:12]
POLICY_CONFIGMAP = "voice-memory-policy"
TOKEN_SECRET = "voice-memory-state-token"
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
CREATOR = re.compile(r"system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+\Z")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def object_meta(value: dict, kind: str, name: str, uid: str) -> dict:
    require(value.get("kind") == kind, f"expected {kind}")
    meta = value.get("metadata", {})
    require(meta.get("name") == name and meta.get("namespace") == "voice", f"wrong {kind} target")
    require(meta.get("uid") == uid and bool(UID.fullmatch(uid)), f"wrong {kind} UID")
    require(isinstance(meta.get("resourceVersion"), str) and meta["resourceVersion"], f"missing {kind} resourceVersion")
    return meta


def owner_ref(uid: str) -> list[dict]:
    return [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "voice-bot", "uid": uid,
             "controller": True, "blockOwnerDeletion": False}]


def add_array(patch: list[dict], parent: str, key: str, old: dict, values: list[dict]) -> None:
    if key not in old:
        patch.append({"op": "add", "path": parent + "/" + key, "value": values})
    else:
        require(isinstance(old[key], list), f"{key} is not an array")
        for value in values:
            patch.append({"op": "add", "path": parent + "/" + key + "/-", "value": value})


def render(deployment: dict, policy: dict, token: bytes, expected_deployment_uid: str,
           expected_policy_uid: str, expected_image: str, approved_image: str,
           runtime_image_ids: list[str], bot_uid: int, creator: str) -> dict[str, object]:
    dep_meta = object_meta(deployment, "Deployment", "voice-bot", expected_deployment_uid)
    object_meta(policy, "PhorvexPolicy", "voice-defense", expected_policy_uid)
    require(bool(CREATOR.fullmatch(creator)), "invalid event creator identity")
    require(0 <= bot_uid <= 65535, "bot UID outside reviewed bound")
    require(32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token), "invalid private state token")
    require(policy.get("spec", {}).get("mode") == "active", "Voice policy is not active")
    enabled = policy["spec"].get("actions", {}).get("enabled", [])
    require("voice-memory-note-revoke" in enabled and len(enabled) > 1, "Voice memory action must be a normal alternative")

    template = deployment.get("spec", {}).get("template", {})
    template_meta = template.get("metadata", {})
    spec = template.get("spec", {})
    containers = spec.get("containers", [])
    matches = [(index, value) for index, value in enumerate(containers) if value.get("name") == "bot"]
    require(len(matches) == 1, "exact bot container unavailable")
    index, bot = matches[0]
    require(bot.get("image") == expected_image and bool(expected_image), "bot image changed")
    require("@" in approved_image and IMAGE_DIGEST.fullmatch(approved_image.rsplit("@", 1)[1]) is not None,
            "approved image must have an immutable digest")
    approved_digest = approved_image.rsplit("@", 1)[1]
    require(len(runtime_image_ids) == deployment.get("spec", {}).get("replicas") and len(runtime_image_ids) > 0 and
            all(image_id.endswith("@" + approved_digest) or image_id == approved_digest for image_id in runtime_image_ids),
            "serving image IDs do not match approved digest")
    require(bot.get("readinessProbe", {}).get("httpGet", {}).get("path") == "/healthz", "memory readiness gate is not wired")
    require(bot.get("readinessProbe", {}).get("httpGet", {}).get("port") == 8080, "unexpected readiness port")

    mounts = bot.get("volumeMounts", [])
    volumes = spec.get("volumes", [])
    env = bot.get("env", [])
    init_containers = spec.get("initContainers", [])
    annotations = template_meta.get("annotations", {})
    require(isinstance(mounts, list) and isinstance(volumes, list) and isinstance(env, list) and
            isinstance(init_containers, list) and isinstance(annotations, dict), "Deployment shape invalid")
    names = {"voice-memory-source", "voice-memory-rule", "voice-memory-token", "voice-memory-state"}
    paths = {"/app/bot.py", "/app/voice_memory_policy.py", "/etc/phorvex/voice-memory-policy",
             "/etc/phorvex/voice-memory-state-token", "/var/lib/phorvex-voice-memory"}
    require(not any(v.get("name") in names for v in volumes), "volume name already in use")
    require(not any(m.get("name") in names or m.get("mountPath") in paths for m in mounts), "mount already in use")
    added_env = {"POD_UID", "VOICE_MEMORY_POLICY_REQUIRED"}
    require(not any(e.get("name") in added_env for e in env), "memory environment already configured")
    require(not any(c.get("name") == "voice-memory-state-owner" for c in init_containers), "state init already configured")
    new_annotations = {"phorvex.ai/voice-memory-policy-configmap": POLICY_CONFIGMAP,
                       "phorvex.ai/voice-memory-source-sha256": SOURCE_SHA,
                       "phorvex.ai/voice-memory-event-creator": creator}
    require(not any(k in annotations for k in new_annotations), "memory annotation already configured")
    root = Path(__file__).resolve().parent
    require(source_sha256(root / "bot.py", root / "voice_memory_policy.py") == SOURCE_SHA,
            "source bytes differ from reviewed digest")
    bot_source = (root / "bot.py").read_text(encoding="utf-8")
    policy_source = (root / "voice_memory_policy.py").read_text(encoding="utf-8")
    require(len(bot_source.encode()) + len(policy_source.encode()) < 900_000, "source ConfigMap too large")

    initial_rule = {"version": 1, "deploymentUID": expected_deployment_uid, "policyUID": expected_policy_uid,
                    "sourceSHA256": SOURCE_SHA, "revision": 0, "operationId": "", "entries": []}
    source_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SOURCE_CONFIGMAP,
                 "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
                 "immutable": True, "data": {"bot.py": bot_source, "voice_memory_policy.py": policy_source}}
    rule_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POLICY_CONFIGMAP,
               "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
               "data": {"rule.json": canonical_bytes(initial_rule).decode("utf-8")}}
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": TOKEN_SECRET,
              "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
              "type": "Opaque", "data": {"token": base64.b64encode(token).decode("ascii")}}

    patch: list[dict] = [
        {"op": "test", "path": "/metadata/uid", "value": expected_deployment_uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": dep_meta["resourceVersion"]},
        {"op": "test", "path": f"/spec/template/spec/containers/{index}/name", "value": "bot"},
        {"op": "test", "path": f"/spec/template/spec/containers/{index}/image", "value": expected_image},
    ]
    if approved_image != expected_image:
        patch.append({"op": "replace", "path": f"/spec/template/spec/containers/{index}/image", "value": approved_image})
    annotation_path = "/spec/template/metadata/annotations"
    if "annotations" not in template_meta:
        patch.append({"op": "add", "path": annotation_path, "value": new_annotations})
    else:
        for key, value in new_annotations.items():
            patch.append({"op": "add", "path": annotation_path + "/" + key.replace("~", "~0").replace("/", "~1"), "value": value})
    add_array(patch, "/spec/template/spec", "volumes", spec, [
        {"name": "voice-memory-source", "configMap": {"name": SOURCE_CONFIGMAP}},
        {"name": "voice-memory-rule", "configMap": {"name": POLICY_CONFIGMAP, "optional": True}},
        {"name": "voice-memory-token", "secret": {"secretName": TOKEN_SECRET}},
        {"name": "voice-memory-state", "emptyDir": {}},
    ])
    container_path = f"/spec/template/spec/containers/{index}"
    add_array(patch, container_path, "volumeMounts", bot, [
        {"name": "voice-memory-source", "mountPath": "/app/bot.py", "subPath": "bot.py", "readOnly": True},
        {"name": "voice-memory-source", "mountPath": "/app/voice_memory_policy.py", "subPath": "voice_memory_policy.py", "readOnly": True},
        {"name": "voice-memory-rule", "mountPath": "/etc/phorvex/voice-memory-policy", "readOnly": True},
        {"name": "voice-memory-token", "mountPath": "/etc/phorvex/voice-memory-state-token", "readOnly": True},
        {"name": "voice-memory-state", "mountPath": "/var/lib/phorvex-voice-memory"},
    ])
    add_array(patch, container_path, "env", bot, [
        {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        {"name": "VOICE_MEMORY_POLICY_REQUIRED", "value": "true"},
    ])
    add_array(patch, "/spec/template/spec", "initContainers", spec, [
        {"name": "voice-memory-state-owner", "image": approved_image,
         "command": ["python3", "-B", "-c", "import os; os.chmod('/state', 0o700); os.chown('/state', " + str(bot_uid) + ", -1)"],
         "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"], "add": ["CHOWN"]}},
         "volumeMounts": [{"name": "voice-memory-state", "mountPath": "/state"}]},
    ])
    return {"source-configmap.json": source_cm, "policy-configmap.json": rule_cm,
            "state-token-secret.json": secret, "deployment-patch.json": patch}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-json", type=Path, required=True)
    parser.add_argument("--policy-json", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--expected-deployment-uid", required=True)
    parser.add_argument("--expected-policy-uid", required=True)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--approved-image", required=True)
    parser.add_argument("--runtime-image-ids-json", type=Path, required=True,
                        help="private JSON array of current serving bot container imageIDs")
    parser.add_argument("--bot-uid", type=int, required=True)
    parser.add_argument("--event-creator", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out_dir.exists(), "output directory already exists")
    token_info = args.token_file.lstat()
    require(stat.S_ISREG(token_info.st_mode) and token_info.st_uid == os.getuid() and
            token_info.st_mode & 0o077 == 0, "token file must be owned and private")
    objects = render(json.loads(args.deployment_json.read_text()), json.loads(args.policy_json.read_text()),
                     args.token_file.read_bytes(), args.expected_deployment_uid, args.expected_policy_uid,
                     args.expected_image, args.approved_image, json.loads(args.runtime_image_ids_json.read_text()),
                     args.bot_uid, args.event_creator)
    args.out_dir.mkdir(mode=0o700, parents=False)
    os.chmod(args.out_dir, 0o700)
    for name, value in objects.items():
        path = args.out_dir / name
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
    print("Rendered four private files; source SHA-256:", SOURCE_SHA)


if __name__ == "__main__":
    main()
