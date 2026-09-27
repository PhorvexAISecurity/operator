"""Render a source-pinned, opt-in MCP Deployment update without applying it.

The existing mcp-server Service remains unchanged. A caller must provide fresh
Deployment, Service, and legacy source ConfigMap snapshots plus a reviewed
dependency-preinstalled image digest and private test token.
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


HERE = Path(__file__).resolve().parent
SOURCE_SHA256 = "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252"
LEGACY_SOURCE_SHA256 = "483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5"
SOURCE_CONFIGMAP = "voice-mcp-source-" + SOURCE_SHA256[:12]
TOKEN_SECRET = "voice-mcp-test-token"
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def meta(value: dict, kind: str, name: str, uid: str) -> dict:
    require(value.get("kind") == kind, f"expected {kind}")
    found = value.get("metadata", {})
    require(found.get("name") == name and found.get("namespace") == "mcp" and
            found.get("uid") == uid and UID.fullmatch(uid) is not None and
            isinstance(found.get("resourceVersion"), str) and found["resourceVersion"],
            f"wrong {kind} identity")
    return found


def render(deployment: dict, service: dict, legacy_source: dict, token: bytes,
           deployment_uid: str, service_uid: str, source_uid: str,
           expected_image: str, expected_image_id: str, approved_image: str,
           image_ids: list[str]) -> dict[str, object]:
    dep = meta(deployment, "Deployment", "mcp-server", deployment_uid)
    meta(service, "Service", "mcp-server", service_uid)
    meta(legacy_source, "ConfigMap", "mcp-code", source_uid)
    ports = service.get("spec", {}).get("ports", [])
    require(len(ports) == 1 and ports[0].get("protocol", "TCP") == "TCP" and
            ports[0].get("port") == 8000 and ports[0].get("targetPort") == 8000,
            "MCP Service route changed")
    require(set(legacy_source.get("data", {})) == {"server.py"} and
            hashlib.sha256(legacy_source["data"]["server.py"].encode()).hexdigest() == LEGACY_SOURCE_SHA256,
            "legacy MCP source changed")
    require(hashlib.sha256((HERE / "server.py").read_bytes()).hexdigest() == SOURCE_SHA256,
            "reviewed MCP source changed")
    require(32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token),
            "invalid MCP test token")
    require(IMAGE.fullmatch(approved_image) is not None, "approved MCP image must be immutable")
    template = deployment.get("spec", {}).get("template", {})
    spec = template.get("spec", {})
    containers = spec.get("containers", [])
    matching = [(i, c) for i, c in enumerate(containers) if c.get("name") == "mcp-server"]
    require(len(matching) == 1, "exact MCP container unavailable")
    index, container = matching[0]
    require(container.get("image") == expected_image and expected_image, "MCP image changed")
    require(re.fullmatch(r"(?:.+@)?sha256:[0-9a-f]{64}", expected_image_id) is not None,
            "current MCP image ID is not pinned")
    require(len(image_ids) == deployment.get("spec", {}).get("replicas") and image_ids and
            all(image_id == expected_image_id for image_id in image_ids),
            "serving MCP image IDs differ from current pinned image")
    require(container.get("workingDir") == "/app", "MCP working directory changed")
    require(not container.get("args"), "unexpected MCP container arguments")
    require(any(port.get("containerPort") == 8000 and port.get("protocol", "TCP") == "TCP"
                for port in container.get("ports", [])), "MCP container TCP 8000 missing")
    mounts, volumes, env = container.get("volumeMounts", []), spec.get("volumes", []), container.get("env", [])
    old_mounts = [(i, m) for i, m in enumerate(mounts) if m.get("mountPath") == "/app"]
    require(len(old_mounts) == 1, "legacy MCP source mount changed")
    mount_index, old_mount = old_mounts[0]
    old_volumes = [(i, v) for i, v in enumerate(volumes) if v.get("name") == old_mount.get("name")]
    require(len(old_volumes) == 1 and old_volumes[0][1].get("configMap", {}).get("name") == "mcp-code",
            "legacy MCP source volume changed")
    volume_index, old_volume = old_volumes[0]
    require(not any(m.get("mountPath") in ("/app/server.py", "/etc/phorvex/voice-mcp-test-token")
                    for m in mounts) and not any(v.get("name") == TOKEN_SECRET for v in volumes) and
            not any(e.get("name") in ("VOICE_MCP_TEST_ENABLED", "VOICE_MCP_TEST_TOKEN_FILE") for e in env),
            "MCP test source already configured")
    annotations = template.get("metadata", {}).get("annotations", {})
    require(isinstance(annotations, dict) and
            not any(k in annotations for k in ("phorvex.ai/voice-mcp-source-configmap",
                                               "phorvex.ai/voice-mcp-source-sha256")),
            "MCP source annotations already configured")
    source = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": SOURCE_CONFIGMAP, "namespace": "mcp",
                           "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment",
                                               "name": "mcp-server", "uid": deployment_uid,
                                               "controller": True, "blockOwnerDeletion": False}]},
              "immutable": True, "data": {"server.py": (HERE / "server.py").read_text()}}
    secret = {"apiVersion": "v1", "kind": "Secret",
              "metadata": {"name": TOKEN_SECRET, "namespace": "mcp",
                           "ownerReferences": source["metadata"]["ownerReferences"]},
              "type": "Opaque", "data": {"token": base64.b64encode(token).decode()}}
    base = f"/spec/template/spec/containers/{index}"
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": deployment_uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": dep["resourceVersion"]},
        {"op": "test", "path": base + "/name", "value": "mcp-server"},
        {"op": "test", "path": base + "/image", "value": expected_image},
        {"op": "test", "path": f"{base}/volumeMounts/{mount_index}", "value": old_mount},
        {"op": "test", "path": f"/spec/template/spec/volumes/{volume_index}", "value": old_volume},
        {"op": "replace", "path": base + "/image", "value": approved_image},
        {"op": "replace", "path": base + "/command", "value": ["python3", "-B", "/app/server.py"]},
        {"op": "replace", "path": f"{base}/volumeMounts/{mount_index}",
         "value": {"name": old_mount["name"], "mountPath": "/app/server.py",
                   "subPath": "server.py", "readOnly": True}},
        {"op": "replace", "path": f"/spec/template/spec/volumes/{volume_index}",
         "value": {"name": old_volume["name"], "configMap": {"name": SOURCE_CONFIGMAP}}},
    ]
    annotation_path = "/spec/template/metadata/annotations"
    new_annotations = {"phorvex.ai/voice-mcp-source-configmap": SOURCE_CONFIGMAP,
                       "phorvex.ai/voice-mcp-source-sha256": SOURCE_SHA256}
    if "annotations" not in template.get("metadata", {}):
        patch.append({"op": "add", "path": annotation_path, "value": new_annotations})
    else:
        for key, value in new_annotations.items():
            patch.append({"op": "add", "path": annotation_path + "/" + key.replace("/", "~1"), "value": value})
    patch.extend([
        {"op": "add", "path": "/spec/template/spec/volumes/-",
         "value": {"name": TOKEN_SECRET, "secret": {"secretName": TOKEN_SECRET}}},
        {"op": "add", "path": base + "/volumeMounts/-",
         "value": {"name": TOKEN_SECRET, "mountPath": "/etc/phorvex/voice-mcp-test-token", "readOnly": True}},
    ])
    if "env" in container:
        patch.append({"op": "add", "path": base + "/env/-",
                      "value": {"name": "VOICE_MCP_TEST_ENABLED", "value": "true"}})
    else:
        patch.append({"op": "add", "path": base + "/env",
                      "value": [{"name": "VOICE_MCP_TEST_ENABLED", "value": "true"}]})
    return {"source-configmap.json": source, "test-token-secret.json": secret,
            "deployment-patch.json": patch}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("deployment-json", "service-json", "legacy-source-json", "token-file", "image-ids-json"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("deployment-uid", "service-uid", "source-uid", "expected-image",
                 "expected-image-id", "approved-image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out_dir.exists(), "output directory exists")
    token_info = args.token_file.lstat()
    require(stat.S_ISREG(token_info.st_mode) and token_info.st_uid == os.getuid() and
            token_info.st_mode & 0o077 == 0, "token must be owned and private")
    output = render(json.loads(args.deployment_json.read_text()),
                    json.loads(args.service_json.read_text()), json.loads(args.legacy_source_json.read_text()),
                    args.token_file.read_bytes(), args.deployment_uid, args.service_uid, args.source_uid,
                    args.expected_image, args.expected_image_id, args.approved_image,
                    json.loads(args.image_ids_json.read_text()))
    args.out_dir.mkdir(mode=0o700)
    for name, value in output.items():
        descriptor = os.open(args.out_dir / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
    print("Rendered private MCP activation; source SHA-256:", SOURCE_SHA256)


if __name__ == "__main__":
    main()
