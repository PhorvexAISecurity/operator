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

from voice_memory_policy import canonical_bytes, source_sha256, _unique_object
from voice_mcp_policy import source_sha256 as mcp_source_sha256
from voice_output_policy import output_source_sha256


SOURCE_SHA = "25fd02b6710f1d687a1c71ba4caf142afcbf57d86c662aef66cf39e7ff370f95"
SOURCE_CONFIGMAP = "voice-memory-source-" + SOURCE_SHA[:12]
MCP_SOURCE_SHA = "6adf4d8f2ab46dd723b810a9bbc4a863d32e5fa3f278dfda648f8a46f69fe528"
OUTPUT_SOURCE_SHA = "92e847ac1bdff7e8e50846420bcd6bfada11d79807be79b8e89b1b2b7be28bb0"
JOINT_SOURCE_SHA = "e3cfcb87456b299f2b021bce70fb565e699f81b39d3b7bc3bd985b0f56f1f899"
MCP_SOURCE_CONFIGMAP = "voice-memory-source-" + JOINT_SOURCE_SHA[:12]
MCP_SERVER_SOURCE_SHA = "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252"
POLICY_CONFIGMAP = "voice-memory-policy"
REFUND_CONFIGMAP = "voice-refund-policy"
MCP_POLICY_CONFIGMAP = "voice-mcp-tool-policy"
MCP_TEST_SECRET = "voice-mcp-test-token"
OUTPUT_POLICY_CONFIGMAP = "voice-output-policy"
OUTPUT_TEST_SECRET = "voice-output-test-token"
MCP_URL = "http://mcp-server.mcp.svc.cluster.local:8000/mcp/"
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


def repin_or_create(existing: dict | None, desired: dict, deployment_uid: str) -> tuple[str, dict]:
    """Only an inactive revision-zero rule can be repinned without journal drift."""
    name = desired["metadata"]["name"]
    if existing is None:
        return ("policy-configmap.json" if name == POLICY_CONFIGMAP else
                "refund-policy-configmap.json"), desired
    meta = object_meta(existing, "ConfigMap", name, existing.get("metadata", {}).get("uid", ""))
    require(len(existing.get("metadata", {}).get("ownerReferences", [])) == 1 and
            existing["metadata"]["ownerReferences"][0].get("uid") == deployment_uid and
            existing["metadata"]["ownerReferences"][0].get("controller") is True,
            "existing rule ConfigMap has different Deployment owner")
    require(set(existing.get("data", {})) == {"rule.json"} and not existing.get("binaryData") and
            isinstance(existing["data"]["rule.json"], str), "existing rule ConfigMap shape changed")
    old = existing["data"]["rule.json"]
    try:
        value = json.loads(old, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("existing policy rule is invalid") from exc
    require(isinstance(value, dict) and set(value) == {"version", "deploymentUID", "policyUID",
                                                   "sourceSHA256", "revision", "operationId", "entries"} and
            canonical_bytes(value).decode() == old and value["version"] == 1 and
            value["deploymentUID"] == deployment_uid and value["policyUID"] ==
            json.loads(desired["data"]["rule.json"])["policyUID"] and
            type(value["revision"]) is int and value["revision"] == 0 and
            value["operationId"] == "" and value["entries"] == [],
            "nonzero or unsafe existing rule requires explicit lineage migration")
    return name + "-repin-patch.json", [
        {"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
        {"op": "test", "path": "/data/rule.json", "value": old},
        {"op": "replace", "path": "/data/rule.json", "value": desired["data"]["rule.json"]},
    ]


def bind_output_configmap_uid(created: dict, deployment_uid: str, policy_uid: str) -> list[dict]:
    """Second phase: bind a newly created CM to its actual Kubernetes UID."""
    cm_meta = object_meta(created, "ConfigMap", OUTPUT_POLICY_CONFIGMAP,
                          created.get("metadata", {}).get("uid", ""))
    require(len(cm_meta.get("ownerReferences", [])) == 1 and
            cm_meta["ownerReferences"][0].get("uid") == deployment_uid and
            cm_meta["ownerReferences"][0].get("controller") is True,
            "output CM owner differs")
    require(set(created.get("data", {})) == {"rule.json"} and not created.get("binaryData"),
            "output CM data changed")
    old = created["data"]["rule.json"]
    expected = {"version": 1, "configMapUID": "", "deploymentUID": deployment_uid,
                "policyUID": policy_uid, "sourceSHA256": OUTPUT_SOURCE_SHA,
                "revision": 0, "operationId": "", "entries": []}
    require(old == canonical_bytes(expected).decode(), "output CM bootstrap rule changed")
    desired = dict(expected, configMapUID=cm_meta["uid"])
    return [{"op": "test", "path": "/metadata/uid", "value": cm_meta["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": cm_meta["resourceVersion"]},
            {"op": "test", "path": "/data/rule.json", "value": old},
            {"op": "replace", "path": "/data/rule.json", "value": canonical_bytes(desired).decode()}]


def render(deployment: dict, policy: dict, token: bytes, expected_deployment_uid: str,
           expected_policy_uid: str, expected_image: str, approved_image: str,
           runtime_image_ids: list[str], bot_uid: int, creator: str,
           agency_test_enabled: bool = False, mcp_tool_enabled: bool = False,
           mcp_test_token: bytes | None = None, output_enabled: bool = False,
           output_test_token: bytes | None = None,
           existing_memory_cm: dict | None = None, existing_refund_cm: dict | None = None,
           journal_inventory: list[dict] | None = None,
           existing_mcp_cm: dict | None = None, existing_output_cm: dict | None = None) -> dict[str, object]:
    dep_meta = object_meta(deployment, "Deployment", "voice-bot", expected_deployment_uid)
    object_meta(policy, "PhorvexPolicy", "voice-defense", expected_policy_uid)
    require(bool(CREATOR.fullmatch(creator)), "invalid event creator identity")
    require(type(agency_test_enabled) is bool, "invalid agency test mode")
    require(type(mcp_tool_enabled) is bool, "invalid MCP tool policy mode")
    require(type(output_enabled) is bool, "invalid Voice output policy mode")
    require(mcp_tool_enabled == (mcp_test_token is not None),
            "MCP action requires its private test token")
    require(output_enabled == (output_test_token is not None),
            "output action requires its private test token")
    if mcp_test_token is not None:
        require(mcp_tool_enabled and 32 <= len(mcp_test_token) <= 256 and
                all(33 <= byte <= 126 for byte in mcp_test_token), "invalid MCP test token")
    if output_test_token is not None:
        require(output_enabled and 32 <= len(output_test_token) <= 256 and
                all(33 <= byte <= 126 for byte in output_test_token), "invalid output test token")
    require(0 <= bot_uid <= 65535, "bot UID outside reviewed bound")
    require(32 <= len(token) <= 256 and all(33 <= byte <= 126 for byte in token), "invalid private state token")
    require(policy.get("spec", {}).get("mode") == "active", "Voice policy is not active")
    enabled = policy["spec"].get("actions", {}).get("enabled", [])
    require(("voice-mcp-tool-pin" in enabled) == mcp_tool_enabled and
            ("voice-output-policy-activate" in enabled) == output_enabled,
            "new Voice action and source mount must be enabled together")
    require("voice-memory-note-revoke" in enabled and len(enabled) > 1, "Voice memory action must be a normal alternative")
    require("voice-refund-pair-deny" in enabled, "Voice refund action must be a normal alternative")
    if mcp_tool_enabled:
        require("voice-mcp-tool-pin" in enabled, "Voice MCP action must be a normal alternative")
    if output_enabled:
        require("voice-output-policy-activate" in enabled, "Voice output action must be a normal alternative")
    joint_enabled = mcp_tool_enabled or output_enabled
    if joint_enabled:
        require(journal_inventory is not None, "journal inventory required for source repin")
        require(existing_mcp_cm is None and existing_output_cm is None,
                "existing MCP/output rule requires separate lineage review")
        for journal in journal_inventory:
            try:
                receipt = json.loads(journal.get("data", {}).get("receipt.json", ""))
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError("unreadable protected journal") from exc
            require(receipt.get("phase") == "terminal-full", "pending protected journal blocks source repin")

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
    names = {"voice-memory-source", "voice-memory-rule", "voice-refund-rule", "voice-memory-token", "voice-memory-state"}
    if mcp_tool_enabled:
        names.add("voice-mcp-rule")
    if output_enabled:
        names.add("voice-output-rule")
    if mcp_test_token is not None:
        names.add("voice-mcp-test-token")
    if output_test_token is not None:
        names.add("voice-output-test-token")
    paths = {"/app/bot.py", "/app/voice_memory_policy.py", "/etc/phorvex/voice-memory-policy",
             "/etc/phorvex/voice-refund-policy",
             "/etc/phorvex/voice-memory-state-token", "/var/lib/phorvex-voice-memory"}
    if joint_enabled:
        paths.update({"/app/voice_mcp_policy.py", "/app/voice_output_policy.py"})
    if mcp_tool_enabled:
        paths.add("/etc/phorvex/voice-mcp-tool-policy")
    if output_enabled:
        paths.add("/etc/phorvex/voice-output-policy")
    if mcp_test_token is not None:
        paths.add("/etc/phorvex/voice-mcp-test-token")
    if output_test_token is not None:
        paths.add("/etc/phorvex/voice-output-test-token")
    require(not any(v.get("name") in names for v in volumes), "volume name already in use")
    require(not any(m.get("name") in names or m.get("mountPath") in paths for m in mounts), "mount already in use")
    added_env = {"POD_UID", "VOICE_MEMORY_POLICY_REQUIRED", "VOICE_REFUND_POLICY_REQUIRED", "VOICE_AGENCY_TEST_ENABLED"}
    if mcp_tool_enabled:
        added_env.add("VOICE_MCP_POLICY_REQUIRED")
        added_env.add("MCP_URL")
    if output_enabled:
        added_env.add("VOICE_OUTPUT_POLICY_REQUIRED")
    if mcp_test_token is not None:
        added_env.update({"VOICE_MCP_TEST_ENABLED", "VOICE_MCP_SERVER_SOURCE_SHA256"})
    if output_test_token is not None:
        added_env.add("VOICE_OUTPUT_TEST_ENABLED")
    require(not any(e.get("name") in added_env - {"MCP_URL"} for e in env),
            "memory environment already configured")
    if mcp_tool_enabled:
        targets = [e for e in env if e.get("name") == "MCP_URL"]
        require(len(targets) <= 1 and (not targets or targets[0] == {"name": "MCP_URL", "value": MCP_URL}),
                "MCP_URL differs from reviewed Service")
    require(not any(c.get("name") == "voice-memory-state-owner" for c in init_containers), "state init already configured")
    new_annotations = {"phorvex.ai/voice-memory-policy-configmap": POLICY_CONFIGMAP,
                       "phorvex.ai/voice-memory-source-sha256": SOURCE_SHA,
                       "phorvex.ai/voice-memory-event-creator": creator,
                       "phorvex.ai/voice-refund-policy-configmap": REFUND_CONFIGMAP,
                       "phorvex.ai/voice-refund-source-sha256": SOURCE_SHA,
                       "phorvex.ai/voice-refund-event-creator": creator}
    if mcp_tool_enabled:
        new_annotations.update({"phorvex.ai/voice-mcp-policy-configmap": MCP_POLICY_CONFIGMAP,
                                "phorvex.ai/voice-mcp-source-sha256": MCP_SOURCE_SHA,
                                "phorvex.ai/voice-mcp-source-configmap": MCP_SOURCE_CONFIGMAP,
                                "phorvex.ai/voice-mcp-event-creator": creator})
    if output_enabled:
        new_annotations.update({"phorvex.ai/voice-output-policy-configmap": OUTPUT_POLICY_CONFIGMAP,
                                "phorvex.ai/voice-output-source-sha256": OUTPUT_SOURCE_SHA,
                                "phorvex.ai/voice-output-source-configmap": MCP_SOURCE_CONFIGMAP,
                                "phorvex.ai/voice-output-event-creator": creator})
    require(not any(k in annotations for k in new_annotations), "memory annotation already configured")
    root = Path(__file__).resolve().parent
    require(source_sha256(root / "bot.py", root / "voice_memory_policy.py") == SOURCE_SHA,
            "source bytes differ from reviewed digest")
    if joint_enabled:
        sources = (root / "bot.py", root / "voice_memory_policy.py",
                   root / "voice_output_policy.py", root / "voice_mcp_policy.py")
        digest = hashlib.sha256()
        for source_index, source_file in enumerate(sources):
            if source_index:
                digest.update(b"\x00")
            digest.update(source_file.read_bytes())
        require(digest.hexdigest() == JOINT_SOURCE_SHA, "joint Voice source bytes differ from reviewed digest")
    if mcp_tool_enabled:
        require(mcp_source_sha256(root / "bot.py", root / "voice_memory_policy.py",
                                  root / "voice_mcp_policy.py") == MCP_SOURCE_SHA,
                "MCP source bytes differ from reviewed digest")
    if output_enabled:
        require(output_source_sha256(root / "bot.py", root / "voice_memory_policy.py",
                                     root / "voice_output_policy.py") == OUTPUT_SOURCE_SHA,
                "output source bytes differ from reviewed digest")
    bot_source = (root / "bot.py").read_text(encoding="utf-8")
    policy_source = (root / "voice_memory_policy.py").read_text(encoding="utf-8")
    mcp_source = (root / "voice_mcp_policy.py").read_text(encoding="utf-8") if joint_enabled else ""
    output_source = (root / "voice_output_policy.py").read_text(encoding="utf-8") if joint_enabled else ""
    require(sum(len(item.encode()) for item in (bot_source, policy_source, mcp_source, output_source)) < 900_000,
            "source ConfigMap too large")

    initial_rule = {"version": 1, "deploymentUID": expected_deployment_uid, "policyUID": expected_policy_uid,
                    "sourceSHA256": SOURCE_SHA, "revision": 0, "operationId": "", "entries": []}
    source_name = MCP_SOURCE_CONFIGMAP if joint_enabled else SOURCE_CONFIGMAP
    source_data = {"bot.py": bot_source, "voice_memory_policy.py": policy_source}
    if joint_enabled:
        source_data["voice_mcp_policy.py"] = mcp_source
        source_data["voice_output_policy.py"] = output_source
    source_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": source_name,
                 "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
                 "immutable": True, "data": source_data}
    rule_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POLICY_CONFIGMAP,
               "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
               "data": {"rule.json": canonical_bytes(initial_rule).decode("utf-8")}}
    refund_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": REFUND_CONFIGMAP,
                 "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
                 "data": {"rule.json": canonical_bytes(initial_rule).decode("utf-8")}}
    mcp_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MCP_POLICY_CONFIGMAP,
              "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
              "data": {"rule.json": canonical_bytes(dict(initial_rule, sourceSHA256=MCP_SOURCE_SHA)).decode("utf-8")}}
    output_initial_rule = {"version": 1, "configMapUID": "",
                           "deploymentUID": expected_deployment_uid, "policyUID": expected_policy_uid,
                           "sourceSHA256": OUTPUT_SOURCE_SHA, "revision": 0,
                           "operationId": "", "entries": []}
    output_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": OUTPUT_POLICY_CONFIGMAP,
                 "namespace": "voice", "ownerReferences": owner_ref(expected_deployment_uid)},
                 "data": {"rule.json": canonical_bytes(output_initial_rule).decode("utf-8")}}
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
    if joint_enabled:
        command_path = f"/spec/template/spec/containers/{index}/command"
        args_path = f"/spec/template/spec/containers/{index}/args"
        if "command" in bot:
            patch.extend([{"op": "test", "path": command_path, "value": bot["command"]},
                          {"op": "replace", "path": command_path,
                           "value": ["python3", "-B", "/app/bot.py"]}])
        else:
            patch.append({"op": "add", "path": command_path,
                          "value": ["python3", "-B", "/app/bot.py"]})
        if "args" in bot:
            patch.extend([{"op": "test", "path": args_path, "value": bot["args"]},
                          {"op": "replace", "path": args_path, "value": []}])
        else:
            patch.append({"op": "add", "path": args_path, "value": []})
    annotation_path = "/spec/template/metadata/annotations"
    if "annotations" not in template_meta:
        patch.append({"op": "add", "path": annotation_path, "value": new_annotations})
    else:
        for key, value in new_annotations.items():
            patch.append({"op": "add", "path": annotation_path + "/" + key.replace("~", "~0").replace("/", "~1"), "value": value})
    added_volumes = [
        {"name": "voice-memory-source", "configMap": {"name": source_name}},
        {"name": "voice-memory-rule", "configMap": {"name": POLICY_CONFIGMAP, "optional": True}},
        {"name": "voice-refund-rule", "configMap": {"name": REFUND_CONFIGMAP}},
        {"name": "voice-memory-token", "secret": {"secretName": TOKEN_SECRET}},
        {"name": "voice-memory-state", "emptyDir": {}},
    ]
    if mcp_tool_enabled:
        added_volumes.append({"name": "voice-mcp-rule", "configMap": {"name": MCP_POLICY_CONFIGMAP}})
    if output_enabled:
        added_volumes.append({"name": "voice-output-rule", "configMap": {"name": OUTPUT_POLICY_CONFIGMAP}})
    if mcp_test_token is not None:
        added_volumes.append({"name": "voice-mcp-test-token", "secret": {"secretName": MCP_TEST_SECRET}})
    if output_test_token is not None:
        added_volumes.append({"name": "voice-output-test-token", "secret": {"secretName": OUTPUT_TEST_SECRET}})
    add_array(patch, "/spec/template/spec", "volumes", spec, added_volumes)
    container_path = f"/spec/template/spec/containers/{index}"
    added_mounts = [
        {"name": "voice-memory-source", "mountPath": "/app/bot.py", "subPath": "bot.py", "readOnly": True},
        {"name": "voice-memory-source", "mountPath": "/app/voice_memory_policy.py", "subPath": "voice_memory_policy.py", "readOnly": True},
        {"name": "voice-memory-rule", "mountPath": "/etc/phorvex/voice-memory-policy", "readOnly": True},
        {"name": "voice-refund-rule", "mountPath": "/etc/phorvex/voice-refund-policy", "readOnly": True},
        {"name": "voice-memory-token", "mountPath": "/etc/phorvex/voice-memory-state-token", "readOnly": True},
        {"name": "voice-memory-state", "mountPath": "/var/lib/phorvex-voice-memory"},
    ]
    if joint_enabled:
        added_mounts.extend([
            {"name": "voice-memory-source", "mountPath": "/app/voice_mcp_policy.py", "subPath": "voice_mcp_policy.py", "readOnly": True},
            {"name": "voice-memory-source", "mountPath": "/app/voice_output_policy.py", "subPath": "voice_output_policy.py", "readOnly": True},
        ])
    if mcp_tool_enabled:
        added_mounts.append({"name": "voice-mcp-rule", "mountPath": "/etc/phorvex/voice-mcp-tool-policy", "readOnly": True})
    if output_enabled:
        added_mounts.append({"name": "voice-output-rule", "mountPath": "/etc/phorvex/voice-output-policy", "readOnly": True})
    if mcp_test_token is not None:
        added_mounts.append({"name": "voice-mcp-test-token",
                             "mountPath": "/etc/phorvex/voice-mcp-test-token", "readOnly": True})
    if output_test_token is not None:
        added_mounts.append({"name": "voice-output-test-token",
                             "mountPath": "/etc/phorvex/voice-output-test-token", "readOnly": True})
    add_array(patch, container_path, "volumeMounts", bot, added_mounts)
    agency_env = [{"name": "VOICE_AGENCY_TEST_ENABLED", "value": "true"}] if agency_test_enabled else []
    mcp_env = [{"name": "VOICE_MCP_POLICY_REQUIRED", "value": "true"}] if mcp_tool_enabled else []
    if mcp_tool_enabled and not any(e.get("name") == "MCP_URL" for e in env):
        mcp_env.append({"name": "MCP_URL", "value": MCP_URL})
    output_env = [{"name": "VOICE_OUTPUT_POLICY_REQUIRED", "value": "true"}] if output_enabled else []
    if mcp_test_token is not None:
        server_path = root.parent / "voice-mcp" / "server.py"
        require(hashlib.sha256(server_path.read_bytes()).hexdigest() == MCP_SERVER_SOURCE_SHA,
                "MCP server source bytes differ from reviewed digest")
        mcp_env.extend([{"name": "VOICE_MCP_TEST_ENABLED", "value": "true"},
                        {"name": "VOICE_MCP_SERVER_SOURCE_SHA256", "value": MCP_SERVER_SOURCE_SHA}])
    if output_test_token is not None:
        output_env.append({"name": "VOICE_OUTPUT_TEST_ENABLED", "value": "true"})
    add_array(patch, container_path, "env", bot, [
        {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        {"name": "VOICE_MEMORY_POLICY_REQUIRED", "value": "true"},
        {"name": "VOICE_REFUND_POLICY_REQUIRED", "value": "true"},
    ] + agency_env + mcp_env + output_env)
    add_array(patch, "/spec/template/spec", "initContainers", spec, [
        {"name": "voice-memory-state-owner", "image": approved_image,
         "command": ["python3", "-B", "-c", "import os; os.chmod('/state', 0o700); os.chown('/state', " + str(bot_uid) + ", -1)"],
         "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"], "add": ["CHOWN"]}},
         "volumeMounts": [{"name": "voice-memory-state", "mountPath": "/state"}]},
    ])
    output = {"source-configmap.json": source_cm,
              "state-token-secret.json": secret, "deployment-patch.json": patch}
    if joint_enabled:
        memory_name, memory_object = repin_or_create(existing_memory_cm, rule_cm, expected_deployment_uid)
        refund_name, refund_object = repin_or_create(existing_refund_cm, refund_cm, expected_deployment_uid)
        output[memory_name] = memory_object
        output[refund_name] = refund_object
    else:
        output["policy-configmap.json"] = rule_cm
        output["refund-policy-configmap.json"] = refund_cm
    if mcp_tool_enabled:
        output["mcp-policy-configmap.json"] = mcp_cm
    if output_enabled:
        output["output-policy-bootstrap-configmap.json"] = output_cm
    if mcp_test_token is not None:
        output["mcp-test-token-secret.json"] = {"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": MCP_TEST_SECRET, "namespace": "voice",
                         "ownerReferences": owner_ref(expected_deployment_uid)},
            "type": "Opaque", "data": {"token": base64.b64encode(mcp_test_token).decode("ascii")}}
    if output_test_token is not None:
        output["output-test-token-secret.json"] = {"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": OUTPUT_TEST_SECRET, "namespace": "voice",
                         "ownerReferences": owner_ref(expected_deployment_uid)},
            "type": "Opaque", "data": {"token": base64.b64encode(output_test_token).decode("ascii")}}
    return output


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
    parser.add_argument("--agency-test-enabled", action="store_true", help="enable stable bounded Voice agency test sessions")
    parser.add_argument("--mcp-tool-enabled", action="store_true", help="mount the reviewed Voice MCP descriptor policy")
    parser.add_argument("--mcp-test-token-file", type=Path, help="private shared synthetic MCP session token")
    parser.add_argument("--output-enabled", action="store_true", help="mount the reviewed Voice output policy")
    parser.add_argument("--output-test-token-file", type=Path, help="private output synthetic session token")
    parser.add_argument("--existing-memory-cm-json", type=Path,
                        help="fresh existing Voice memory CM snapshot, or explicit JSON null")
    parser.add_argument("--existing-refund-cm-json", type=Path,
                        help="fresh existing Voice refund CM snapshot, or explicit JSON null")
    parser.add_argument("--existing-mcp-cm-json", type=Path,
                        help="fresh existing Voice MCP CM snapshot, or explicit JSON null")
    parser.add_argument("--existing-output-cm-json", type=Path,
                        help="fresh existing Voice output CM snapshot, or explicit JSON null")
    parser.add_argument("--journal-inventory-json", type=Path,
                        help="fresh protected journal inventory for both Voice policies")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out_dir.exists(), "output directory already exists")
    token_info = args.token_file.lstat()
    require(stat.S_ISREG(token_info.st_mode) and token_info.st_uid == os.getuid() and
            token_info.st_mode & 0o077 == 0, "token file must be owned and private")
    mcp_test_token = None
    if args.mcp_test_token_file is not None:
        mcp_info = args.mcp_test_token_file.lstat()
        require(stat.S_ISREG(mcp_info.st_mode) and mcp_info.st_uid == os.getuid() and
                mcp_info.st_mode & 0o077 == 0, "MCP test token file must be owned and private")
        mcp_test_token = args.mcp_test_token_file.read_bytes()
    output_test_token = None
    if args.output_test_token_file is not None:
        output_info = args.output_test_token_file.lstat()
        require(stat.S_ISREG(output_info.st_mode) and output_info.st_uid == os.getuid() and
                output_info.st_mode & 0o077 == 0, "output test token file must be owned and private")
        output_test_token = args.output_test_token_file.read_bytes()
    joint = args.mcp_tool_enabled or args.output_enabled
    require(not joint or all(path is not None for path in (
        args.existing_memory_cm_json, args.existing_refund_cm_json,
        args.existing_mcp_cm_json, args.existing_output_cm_json, args.journal_inventory_json)),
        "joint activation requires current rule and journal snapshots")
    existing_memory = json.loads(args.existing_memory_cm_json.read_text()) if joint else None
    existing_refund = json.loads(args.existing_refund_cm_json.read_text()) if joint else None
    existing_mcp = json.loads(args.existing_mcp_cm_json.read_text()) if joint else None
    existing_output = json.loads(args.existing_output_cm_json.read_text()) if joint else None
    journals = json.loads(args.journal_inventory_json.read_text()) if joint else None
    require(not joint or isinstance(journals, list), "journal inventory is not a list")
    objects = render(json.loads(args.deployment_json.read_text()), json.loads(args.policy_json.read_text()),
                     args.token_file.read_bytes(), args.expected_deployment_uid, args.expected_policy_uid,
                     args.expected_image, args.approved_image, json.loads(args.runtime_image_ids_json.read_text()),
                     args.bot_uid, args.event_creator, args.agency_test_enabled, args.mcp_tool_enabled,
                     mcp_test_token, args.output_enabled, output_test_token,
                     existing_memory, existing_refund, journals, existing_mcp, existing_output)
    args.out_dir.mkdir(mode=0o700, parents=False)
    os.chmod(args.out_dir, 0o700)
    for name, value in objects.items():
        path = args.out_dir / name
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
    print("Rendered private activation files; source SHA-256:", JOINT_SOURCE_SHA if joint else SOURCE_SHA)


if __name__ == "__main__":
    main()
