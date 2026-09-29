"""Render a SHA-bound, review-only guardrail-effect profile from fresh originals.

No Kubernetes client, Secret read, workload write, or attack call is used here.
The JSON profile bytes are also valid YAML for the existing console parser.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
PROXY = HERE.parents[1] / "test-harness/guardrail/guardrail_proxy.py"
DUAL = HERE / "dual_server.py"
LEASE = HERE / "endpoint_lease.py"
# The installed PR365 four-file closure remains an exact historical pin.
# Future startup-repaired four-file and five-file closures have distinct,
# separately reviewed bytes; a mixed bundle is never accepted.
DRAIN_SOURCE_SHA256 = {
    "drain_v11.py": "c117bfe2928a6b43146fce7aed9fa3df9b1c746d74c9855d3eafb7ba5f6de857",
    "drain_v11_init.py": "4e1a7a00550e8ce980b95114305027729dd5e3dddfdcbb2bca3026cb16b5dd5d",
}
STARTUP_REPAIRED_DRAIN_SOURCE_SHA256 = {
    "drain_v11.py": "73555b7b8226f66c3d2823ba94edbb41bcda8a40f52f61c7869d054f570841f0",
    "drain_v11_init.py": DRAIN_SOURCE_SHA256["drain_v11_init.py"],
}
CAPACITY_REPAIRED_DRAIN_SOURCE_SHA256 = {
    "drain_v11.py": "4ffe402960d3c368d95b137e313a69818b9b33a162fcb76d09585b4d75b9c397",
    "drain_v11_init.py": DRAIN_SOURCE_SHA256["drain_v11_init.py"],
}
LEGACY_SOURCE_SHA256 = {
    "guardrail_proxy.py": "7659d44ef8e637fd74db754e393f65c3e58289cc3be347c716e10e83127076f2",
    "dual_server.py": "c89135124108e7f613f029a0b4bde5c9a6201f73b1b0f0041d2d4379140d2dfd",
}
STARTUP_REPAIRED_LEGACY_SOURCE_SHA256 = {
    "guardrail_proxy.py": LEGACY_SOURCE_SHA256["guardrail_proxy.py"],
    "dual_server.py": "11bbb4f0efb422dec87656cfd7aacb276462f051974fc0c32c1ab8ccd5b7931d",
}
LEASE_SOURCE_FILES = ("guardrail_proxy.py", "dual_server.py", "endpoint_lease.py",
                      "drain_v11.py", "drain_v11_init.py")
LEGACY_COMMAND = ["sh", "-c", "pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && pip install --no-cache-dir fastapi 'uvicorn[standard]' httpx transformers && exec python /src/dual_server.py"]
LEASE_POLICY_KEYS = {"version", "revision", "serviceUID", "proxySourceSHA256", "secretUID",
                     "seedSHA256", "allowedClientHMACs", "revokedClientHMACs", "lastOperationID"}
LEASE_PROFILE_KEYS = {"version", "serviceName", "serviceUID", "policyName", "policyUID",
                      "policyGeneration", "policyConfigMapUID", "journalUID", "tenantSecretUID",
                      "consoleSecretUID", "sourceConfigMapName", "sourceConfigMapUID",
                      "proxySourceSHA256", "proxyImage", "approvedEngineImage", "seedSHA256",
                      "clientASHA256", "clientBSHA256", "clientAHMAC", "clientBHMAC",
                      "eventCreator", "auditSourceIdentity", "modelId", "maxRunSeconds"}
ROLES = ("cluster", "pod", "service", "endpointslices", "source", "policy", "manager",
         "console", "console_replicaset", "console_deployment")
LEASE_ROLE = "lease_policy"
SHA = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")
IMAGE_ID = re.compile(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}\Z")
BARE_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
BARE_DOCKER_HUB_TAG = re.compile(r"[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
MODEL = "Qwen/Qwen2.5-7B-Instruct-AWQ"
DOMAIN = "guardrail-variant-v1"
PHORVEX_IMAGE_REPO = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex"
AUDIT_DNS = "phorvex-phorvex-audit-source.phorvex-system.svc"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_regular_bounded(path: Path, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("original missing or linked") from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "original is not a bounded regular file")
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "original exceeds byte bound")
    return raw


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def meta(obj: dict, kind: str, name: str, namespace: str | None = None) -> dict:
    require(isinstance(obj, dict) and obj.get("kind") == kind, kind + " kind differs")
    m = obj.get("metadata", {})
    require(m.get("name") == name and (namespace is None or m.get("namespace") == namespace), kind + " name/namespace differs")
    require(bool(UID.fullmatch(m.get("uid", ""))) and not m.get("deletionTimestamp"), kind + " UID or deletion differs")
    return m


def owner(obj: dict, kind: str, name: str, uid: str) -> None:
    refs = [x for x in obj.get("metadata", {}).get("ownerReferences", []) if x.get("controller") is True]
    require(len(refs) == 1 and refs[0].get("kind") == kind and refs[0].get("name") == name and refs[0].get("uid") == uid,
            "controller owner UID differs")


def container(pod: dict, name: str) -> tuple[dict, dict]:
    require(pod.get("status", {}).get("phase") == "Running" and
            any(x.get("type") == "Ready" and x.get("status") == "True" for x in pod["status"].get("conditions", [])),
            "Pod is not Ready")
    specs = [x for x in pod.get("spec", {}).get("containers", []) if x.get("name") == name]
    statuses = [x for x in pod["status"].get("containerStatuses", []) if x.get("name") == name]
    require(len(specs) == len(statuses) == 1, name + " container not unique")
    spec, status = specs[0], statuses[0]
    # CRI may report the selected platform manifest as a bare sha256 image
    # while the spec holds an OCI index reference. The immutable imageID below
    # remains the authority captured in the profile.
    image_matches = status.get("image") == spec.get("image") or (
        isinstance(spec.get("image"), str) and
        bool(BARE_DOCKER_HUB_TAG.fullmatch(spec["image"])) and
        status.get("image") == "docker.io/library/" + spec["image"]) or (
        bool(IMAGE_ID.fullmatch(spec.get("image", ""))) and
        bool(BARE_SHA.fullmatch(status.get("image", ""))))
    require(status.get("ready") is True and type(status.get("restartCount")) is int and
            status["restartCount"] >= 0 and
            image_matches and
            bool(IMAGE_ID.fullmatch(status.get("imageID", ""))) and status.get("containerID"),
            name + " runtime incarnation is not stable")
    return spec, status


def one_env(spec: dict, name: str) -> dict:
    rows = [x for x in spec.get("env", []) if x.get("name") == name]
    require(len(rows) == 1, name + " environment authority missing/duplicate")
    return rows[0]


def literal_env(spec: dict, name: str, expected: str) -> None:
    row = one_env(spec, name)
    require(row.get("value") == expected and "valueFrom" not in row,
            name + " literal authority differs")


def unique_json(raw: bytes) -> dict:
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate lease policy key")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError) as error:
        raise ValueError("lease policy JSON invalid") from error
    require(isinstance(value, dict) and
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() == raw,
            "lease policy is not canonical")
    return value


def lease_policy_state(obj: dict, service_uid: str, source_sha: str, policy_uid: str, secret_uid: str) -> dict:
    m = meta(obj, "ConfigMap", "phorvex-endpoint-lease-policy", "vllm")
    require(m["uid"] == policy_uid and bool(m.get("resourceVersion")) and
            set(obj.get("data", {})) == {"state.json"} and not obj.get("binaryData"),
            "lease policy object authority differs")
    raw = obj["data"]["state.json"].encode()
    require(0 < len(raw) <= 16384, "lease policy exceeds bound")
    state = unique_json(raw)
    require(set(state) == LEASE_POLICY_KEYS and type(state["version"]) is int and state["version"] == 1 and
            type(state["revision"]) is int and 0 <= state["revision"] <= (1 << 53) - 1 and
            state["serviceUID"] == service_uid and state["proxySourceSHA256"] == source_sha and
            state["secretUID"] == secret_uid and isinstance(state["seedSHA256"], str) and
            bool(SHA.fullmatch(state["seedSHA256"])), "lease policy source/identity differs")
    allowed, revoked = state["allowedClientHMACs"], state["revokedClientHMACs"]
    require(all(isinstance(rows, list) and all(isinstance(x, str) and SHA.fullmatch(x) for x in rows) and
                rows == sorted(set(rows)) for rows in (allowed, revoked)) and
            bool(allowed) and len(allowed) + len(revoked) == 2 and not set(allowed) & set(revoked),
            "lease policy roster differs")
    op = state["lastOperationID"]
    require(isinstance(op, str) and ((state["revision"] == 0 and not op and not revoked) or
            (state["revision"] > 0 and bool(re.fullmatch(r"[0-9a-f]{32,64}", op)))),
            "lease policy operation differs")
    return state


def retained_lease_profile(raw: bytes, service_uid: str, source_uid: str, source_sha: str,
                           policy_uid: str, policy_generation: int, lease_policy_uid: str,
                           state: dict, guard: dict, vllm: dict) -> dict:
    require(0 < len(raw) <= 8192, "retained caller profile size differs")
    value = unique_json(raw)
    require(set(value) in (LEASE_PROFILE_KEYS, LEASE_PROFILE_KEYS | {"sourceUpgrade"}) and type(value["version"]) is int and value["version"] == 1 and
            type(value["policyGeneration"]) is int and value["policyGeneration"] == policy_generation and
            type(value["maxRunSeconds"]) is int and value["maxRunSeconds"] == 900 and
            value["serviceName"] == "vllm" and value["serviceUID"] == service_uid and
            value["policyName"] == "vllm-defense" and value["policyUID"] == policy_uid and
            value["policyConfigMapUID"] == lease_policy_uid and
            value["tenantSecretUID"] == state["secretUID"] and
            value["sourceConfigMapName"] == "guardrail-proxy" and
            value["sourceConfigMapUID"] == source_uid and
            value["proxySourceSHA256"] == source_sha and
            value["seedSHA256"] == state["seedSHA256"] and
            value["modelId"] == MODEL and
            value["eventCreator"] == "system:serviceaccount:phorvex-system:phorvex-phorvex-console" and
            value["proxyImage"] == guard.get("image") and
            value["approvedEngineImage"] == vllm.get("image"),
            "retained caller profile source/target differs")
    for key in ("journalUID", "consoleSecretUID"):
        require(isinstance(value[key], str) and bool(UID.fullmatch(value[key])),
                key + " retained caller authority invalid")
    for key in ("clientASHA256", "clientBSHA256", "clientAHMAC", "clientBHMAC"):
        require(isinstance(value[key], str) and bool(SHA.fullmatch(value[key])),
                key + " retained caller digest invalid")
    require(value["clientASHA256"] != value["clientBSHA256"] and
            value["clientAHMAC"] != value["clientBHMAC"] and
            sorted(state["allowedClientHMACs"] + state["revokedClientHMACs"]) ==
            sorted([value["clientAHMAC"], value["clientBHMAC"]]) and
            value["clientBHMAC"] in state["allowedClientHMACs"] and
            isinstance(value["eventCreator"], str) and
            isinstance(value["auditSourceIdentity"], str),
            "retained B is not admitted by current lease policy")
    if "sourceUpgrade" in value:
        from endpoint_lease_source_upgrade import validate_upgrade
        validate_upgrade(value, state)
    return value


def secret_ref(spec: dict, name: str, key: str) -> str:
    row = one_env(spec, name)
    ref = row.get("valueFrom", {}).get("secretKeyRef", {})
    require("value" not in row and ref.get("key") == key and bool(DNS.fullmatch(ref.get("name", ""))),
            name + " must use exact Secret key")
    return ref["name"]


def flag(args: list[str], name: str) -> str:
    values = [x[len(name) + 1:] for x in args if isinstance(x, str) and x.startswith(name + "=")]
    require(len(values) == 1 and values[0] != "", name + " flag missing/duplicate")
    return values[0]


def option(args: list[str], name: str) -> str:
    require(args.count(name) == 1 and args.index(name) + 1 < len(args), name + " option missing/duplicate")
    return args[args.index(name) + 1]


def mount(spec: dict, volumes: list[dict], path: str, kind: str, source: str | None = None) -> None:
    rows = [x for x in spec.get("volumeMounts", []) if x.get("mountPath") == path]
    require(len(rows) == 1 and not rows[0].get("subPath") and not rows[0].get("subPathExpr"), path + " mount differs")
    vol = [x for x in volumes if x.get("name") == rows[0].get("name")]
    require(len(vol) == 1 and isinstance(vol[0].get(kind), dict), path + " volume differs")
    if kind == "secret":
        require(rows[0].get("readOnly") is True, path + " private mount is not read-only")
    if source is not None:
        require(vol[0][kind].get("name" if kind == "configMap" else "secretName") == source,
                path + " source differs")


def lease_mounts(spec: dict, volumes: list[dict]) -> None:
    source_volumes = [v for v in volumes if v.get("configMap", {}).get("name") == "guardrail-proxy"]
    require(len(source_volumes) == 1 and source_volumes[0]["configMap"].get("optional") is not True,
            "lease source volume differs")
    source_name = source_volumes[0]["name"]
    for filename in LEASE_SOURCE_FILES:
        rows = [m for m in spec.get("volumeMounts", []) if m.get("mountPath") == "/src/" + filename]
        require(len(rows) == 1 and rows[0].get("name") == source_name and
                rows[0].get("subPath") == filename and rows[0].get("readOnly") is True and
                not rows[0].get("subPathExpr"), "lease source file mount differs")
    require(not any(m.get("mountPath") == "/src" or
                    m.get("mountPath", "").startswith("/src/") and
                    m.get("mountPath") not in {"/src/" + f for f in LEASE_SOURCE_FILES}
                    for m in spec.get("volumeMounts", [])), "mixed lease source mounts")
    mount(spec, volumes, "/etc/phorvex/endpoint-lease-keys", "secret", "phorvex-endpoint-lease-keys")
    secret_volumes = [v for v in volumes if v.get("secret", {}).get("secretName") == "phorvex-endpoint-lease-keys"]
    require(len(secret_volumes) == 1 and secret_volumes[0]["secret"].get("optional") is not True,
            "lease Secret projection differs")


def console_lease_projection(console: dict, rs: dict, deployment: dict, profile_sha: str) -> None:
    name = "phorvex-catalogue-endpoint-lease-" + profile_sha[:12]
    for obj in (console, rs["spec"]["template"], deployment["spec"]["template"]):
        spec = obj["spec"]
        matches = [c for c in spec.get("containers", []) if c.get("name") == "console"]
        require(len(matches) == 1, "lease console container differs")
        c = matches[0]
        literal_env(c, "PHORVEX_CONSOLE_ENDPOINT_LEASE_ENABLED", "true")
        literal_env(c, "PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256", profile_sha)
        mounts = c.get("volumeMounts", [])
        profile_mounts = [m for m in mounts if m.get("mountPath") == "/etc/phorvex-endpoint-lease/profile.json"]
        caller_mounts = [m for m in mounts if m.get("mountPath") == "/etc/phorvex-endpoint-lease-callers"]
        require(len(profile_mounts) == len(caller_mounts) == 1 and
                profile_mounts[0].get("subPath") == "profile.json" and
                profile_mounts[0].get("readOnly") is True and
                caller_mounts[0].get("readOnly") is True and not caller_mounts[0].get("subPath") and
                not caller_mounts[0].get("subPathExpr"), "lease console profile/caller mounts differ")
        profile_volumes = [v for v in spec.get("volumes", []) if v.get("name") == profile_mounts[0].get("name")]
        caller_volumes = [v for v in spec.get("volumes", []) if v.get("name") == caller_mounts[0].get("name")]
        require(len(profile_volumes) == len(caller_volumes) == 1 and
                profile_volumes[0].get("configMap", {}).get("name") == name and
                profile_volumes[0]["configMap"].get("optional") is not True and
                caller_volumes[0].get("secret", {}).get("secretName") == "vllm-endpoint-lease-callers" and
                caller_volumes[0]["secret"].get("optional") is not True,
                "lease console projected authority differs")


def image_id(pod: dict, name: str) -> str:
    return container(pod, name)[1]["imageID"]


def immutable_runtime_image(spec: dict, status: dict) -> bool:
    image = spec.get("image", "")
    runtime = status.get("imageID", "")
    for prefix in ("docker-pullable://", "docker://", "containerd://"):
        if runtime.startswith(prefix):
            runtime = runtime[len(prefix):]
            break
    return bool(IMAGE_ID.fullmatch(image)) and runtime in (image, image[image.rfind("@") + 1:])


def journal_name(pod_uid: str) -> str:
    # phorvex/internal/actuator/operation_journal.go receiptName, v9.
    return "phorvex-serving-effect-" + digest(("serving-effect/" + DOMAIN + "/" + pod_uid).encode())[:40]


def render(objects: dict[str, dict], context: str, retained_lease_profile_bytes: bytes | None = None) -> tuple[bytes, dict, dict]:
    require(set(objects) in (set(ROLES), set(ROLES) | {LEASE_ROLE}), "exact original set required")
    require(context != "in-cluster" and bool(context) and "__SET_" not in context and len(context) <= 256,
            "logical cluster context missing")
    cluster, pod, service, slices, source, policy, manager, console, rs, deployment = (objects[k] for k in ROLES)
    cluster_m = meta(cluster, "Namespace", "kube-system")
    pm = pod.get("metadata", {})
    require(pod.get("kind") == "Pod" and pm.get("namespace") == "vllm" and
            bool(UID.fullmatch(pm.get("uid", ""))) and not pm.get("deletionTimestamp") and
            pm.get("labels", {}).get("app") == "vllm", "target Pod identity differs")
    sm = meta(service, "Service", "vllm", "vllm")
    cm = meta(source, "ConfigMap", "guardrail-proxy", "vllm")
    policy_m = meta(policy, "PhorvexPolicy", "vllm-defense", "vllm")
    mm = manager.get("metadata", {})
    require(manager.get("kind") == "Pod" and mm.get("namespace") == "phorvex-system" and
            bool(UID.fullmatch(mm.get("uid", ""))) and not mm.get("deletionTimestamp"), "manager identity differs")
    manager_owners = [x for x in mm.get("ownerReferences", []) if x.get("controller") is True]
    manager_labels = mm.get("labels", {})
    require(manager_labels.get("app.kubernetes.io/component") == "manager" and
            manager_labels.get("app.kubernetes.io/name") == "phorvex" and
            manager_labels.get("app.kubernetes.io/instance") == "phorvex" and
            manager.get("spec", {}).get("serviceAccountName") == "phorvex-phorvex-manager" and
            mm.get("name", "").startswith("phorvex-phorvex-") and
            len(manager_owners) == 1 and manager_owners[0].get("kind") == "ReplicaSet" and
            manager_owners[0].get("name", "").startswith("phorvex-phorvex-") and
            bool(UID.fullmatch(manager_owners[0].get("uid", ""))),
            "Phorvex manager controller authority differs")
    co = console.get("metadata", {})
    require(console.get("kind") == "Pod" and co.get("namespace") == "phorvex-system" and
            bool(UID.fullmatch(co.get("uid", ""))) and not co.get("deletionTimestamp"), "console identity differs")
    rsm = rs.get("metadata", {})
    dm = deployment.get("metadata", {})
    require(rs.get("kind") == "ReplicaSet" and deployment.get("kind") == "Deployment" and
            rsm.get("namespace") == dm.get("namespace") == "phorvex-system" and
            bool(UID.fullmatch(rsm.get("uid", ""))) and bool(UID.fullmatch(dm.get("uid", ""))) and
            not rsm.get("deletionTimestamp") and not dm.get("deletionTimestamp"), "console owner identity differs")
    owner(console, "ReplicaSet", rsm["name"], rsm["uid"])
    owner(rs, "Deployment", dm["name"], dm["uid"])
    require(deployment.get("status", {}).get("observedGeneration") == dm.get("generation") and
            deployment.get("spec", {}).get("replicas", 1) == 1 and
            deployment["status"].get("availableReplicas", 0) == 1 and
            all(co.get("labels", {}).get(k) == v for k, v in deployment.get("spec", {}).get("selector", {}).get("matchLabels", {}).items()),
            "console Deployment is not the current one-Ready owner")
    vllm, vllm_status = container(pod, "vllm")
    guard, guard_status = container(pod, "guardrail")
    manager_spec, manager_status = container(manager, "manager")
    require(manager_spec.get("image", "").startswith(PHORVEX_IMAGE_REPO + ":") or
            manager_spec.get("image", "").startswith(PHORVEX_IMAGE_REPO + "@sha256:"),
            "Phorvex manager image repository differs")
    require(manager_status["imageID"].startswith(PHORVEX_IMAGE_REPO + "@sha256:"),
            "Phorvex manager runtime image differs")
    console_spec, console_status = container(console, "console")
    dep_containers = [x for x in deployment["spec"]["template"]["spec"].get("containers", []) if x.get("name") == "console"]
    rs_containers = [x for x in rs["spec"]["template"]["spec"].get("containers", []) if x.get("name") == "console"]
    require(len(dep_containers) == len(rs_containers) == 1 and
            dep_containers[0].get("image") == rs_containers[0].get("image") == console_spec.get("image") and
            deployment["spec"]["template"]["spec"].get("serviceAccountName") ==
            rs["spec"]["template"]["spec"].get("serviceAccountName") == console["spec"].get("serviceAccountName"),
            "console image or ServiceAccount owner drift")
    require(console_spec.get("args") == dep_containers[0].get("args") == rs_containers[0].get("args"),
            "console audit arguments differ from owner template")
    require(option(vllm.get("args", []), "--model") == MODEL and option(vllm["args"], "--port") == "8001" and
            option(vllm["args"], "--host") == "127.0.0.1", "reviewed raw model/loopback route differs")
    shared_secret = secret_ref(vllm, "VLLM_API_KEY", "api-key")
    require(secret_ref(guard, "VLLM_API_KEY", "api-key") == shared_secret and
            secret_ref(guard, "PHORVEX_GUARDRAIL_ADMIN_KEY", "admin-bearer") == shared_secret,
            "reviewed private upstream/admin authority differs")
    literal_env(guard, "PHORVEX_ADMIN_TLS_CERT_FILE", "/etc/phorvex/admin-tls/tls.crt")
    literal_env(guard, "PHORVEX_ADMIN_TLS_KEY_FILE", "/etc/phorvex/admin-tls/tls.key")
    mount(guard, pod["spec"].get("volumes", []), "/etc/phorvex/admin-tls", "secret", shared_secret)
    tls_volumes = [v for v in pod["spec"].get("volumes", []) if v.get("secret", {}).get("secretName") == shared_secret]
    require(len(tls_volumes) == 1 and tls_volumes[0]["secret"].get("optional") is not True and
            {r.get("key"): r.get("path") for r in tls_volumes[0]["secret"].get("items", [])} ==
            {"tls.crt": "tls.crt", "tls.key": "tls.key"} and
            len(tls_volumes[0]["secret"].get("items", [])) == 2,
            "private TLS Secret projection differs")
    keys = set(source.get("data", {}))
    legacy = keys == set(LEGACY_SOURCE_SHA256) | set(DRAIN_SOURCE_SHA256)
    lease = keys == set(LEASE_SOURCE_FILES)
    require((legacy or lease) and not source.get("binaryData"),
            "complete reviewed four- or five-file source keys differ")
    files = {key: source["data"][key].encode() for key in keys}
    require(all(0 < len(raw) <= 1 << 20 for raw in files.values()), "source file size differs")
    historical_four = (legacy and all(digest(files[key]) == expected for key, expected in
                                 (LEGACY_SOURCE_SHA256 | DRAIN_SOURCE_SHA256).items()))
    repaired_four = (legacy and all(digest(files[key]) == expected for key, expected in
                               (STARTUP_REPAIRED_LEGACY_SOURCE_SHA256 |
                                STARTUP_REPAIRED_DRAIN_SOURCE_SHA256).items()))
    lease_data = None
    if legacy:
        require(historical_four or repaired_four,
                "legacy source is neither installed PR365 nor reviewed startup repair")
        require(set(objects) == set(ROLES) and retained_lease_profile_bytes is None and
                guard.get("command") == LEGACY_COMMAND and
                not guard.get("args") and source.get("immutable") is not True,
                "legacy dual-listener closure differs")
        require(not any(e.get("name", "").startswith("PHORVEX_ENDPOINT_LEASE_")
                        for e in guard.get("env", [])) and
                not any(k.startswith("phorvex.ai/endpoint-lease-") for k in pm.get("annotations", {})) and
                not any(v.get("secret", {}).get("secretName") == "phorvex-endpoint-lease-keys"
                        for v in pod["spec"].get("volumes", [])),
                "legacy source carries lease-only authority")
        mount(guard, pod["spec"].get("volumes", []), "/src", "configMap", "guardrail-proxy")
        if repaired_four:
            # Four-file closures were installed with the pre-metrics listener; the checked-in
            # dual_server.py has since gained the read-only engine metrics port.
            require(digest(files["dual_server.py"]) == STARTUP_REPAIRED_LEGACY_SOURCE_SHA256["dual_server.py"],
                    "startup-repaired dual listener differs from reviewed source")
    else:
        require(set(objects) == set(ROLES) | {LEASE_ROLE} and retained_lease_profile_bytes is not None and
                guard.get("command") == ["python3", "-B", "/src/dual_server.py"] and
                not guard.get("args") and source.get("immutable") is True and
                immutable_runtime_image(guard, guard_status) and
                immutable_runtime_image(vllm, vllm_status),
                "lease dual-listener closure or retained credential profile differs")
        reviewed = {"guardrail_proxy.py": PROXY, "dual_server.py": DUAL, "endpoint_lease.py": LEASE}
        for key, path in reviewed.items():
            installed = files[key] == read_regular_bounded(path, 1 << 20)
            if key == "dual_server.py" and not installed:
                # Closures c0316931 and 322595a6 carry the reviewed pre-metrics listener.
                installed = digest(files[key]) == STARTUP_REPAIRED_LEGACY_SOURCE_SHA256["dual_server.py"]
            require(installed, key + " installed bytes differ from reviewed lease source")
        lease_mounts(guard, pod["spec"].get("volumes", []))
        require(not any(e.get("name") in {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                                             "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"}
                        for e in guard.get("env", [])), "lease Python source override present")
        composite = digest(b"\0".join(files[key] for key in LEASE_SOURCE_FILES))
        annotations = pm.get("annotations", {})
        policy_uid = annotations.get("phorvex.ai/endpoint-lease-policy-configmap-uid", "")
        secret_uid = one_env(guard, "PHORVEX_ENDPOINT_LEASE_SECRET_UID").get("value", "")
        require(bool(UID.fullmatch(policy_uid)) and bool(UID.fullmatch(secret_uid)) and
                annotations.get("phorvex.ai/endpoint-lease-source-configmap") == "guardrail-proxy" and
                annotations.get("phorvex.ai/endpoint-lease-source-sha256") == composite,
                "lease Pod annotations differ")
        for name, expected in (("PHORVEX_ENDPOINT_LEASE_REQUIRED", "true"),
                               ("PHORVEX_ENDPOINT_LEASE_SECRET_DIR", "/etc/phorvex/endpoint-lease-keys"),
                               ("PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", policy_uid),
                               ("PHORVEX_ENDPOINT_LEASE_SECRET_UID", secret_uid),
                               ("PHORVEX_ENDPOINT_LEASE_SERVICE_UID", sm["uid"]),
                               ("PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", composite)):
            literal_env(guard, name, expected)
        require(one_env(guard, "POD_UID").get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") == "metadata.uid" and
                "value" not in one_env(guard, "POD_UID"), "lease Pod UID Downward API differs")
        state = lease_policy_state(objects[LEASE_ROLE], sm["uid"], composite, policy_uid, secret_uid)
        lease_data = retained_lease_profile(retained_lease_profile_bytes, sm["uid"], cm["uid"], composite,
                                            policy_m["uid"], policy_m["generation"], policy_uid,
                                            state, guard, vllm)
    drain_pins = DRAIN_SOURCE_SHA256 if historical_four else STARTUP_REPAIRED_DRAIN_SOURCE_SHA256
    if lease_data is not None and "sourceUpgrade" in lease_data:
        # 322595a6: drain capacity repair; 870c8709: + read-only engine metrics listener.
        require(composite in ("322595a608b2384f2ed6994886416838fc4e1d1c45c9dadbf1c00f04a5f52691",
                              "870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4"),
                "source upgrade differs from a reviewed maintenance closure")
        drain_pins = CAPACITY_REPAIRED_DRAIN_SOURCE_SHA256
    elif lease_data is not None:
        require(composite == "c031693170c1d21d0a23405af255f83319efa240ce84d9c25d2436388528a3ff",
                "unwitnessed lease source differs from reviewed historical closure")
    for key, expected in drain_pins.items():
        encoded = files[key]
        require(len(encoded) <= 1 << 20 and digest(encoded) == expected,
                key + " installed bytes differ from reviewed drain source")
        checked_in = PROXY.parent / key
        historical_lease = lease_data is not None and "sourceUpgrade" not in lease_data
        # Both four-file historical closures have already matched every exact
        # reviewed file pin. Newer integrated drain bytes must not invalidate
        # those archives; witnessed capacity bytes still require local equality.
        if not historical_four and not repaired_four and not historical_lease and checked_in.exists():
            require(read_regular_bounded(checked_in, 1 << 20) == encoded,
                    key + " installed bytes differ from integrated source")
    annotations = pm.get("annotations", {})
    require(pm.get("labels", {}).get("phorvex.ai/guardrail-tier") == "true" and
            annotations.get("phorvex.ai/guardrail-variant") in {"pgv1", "pgv2"} and
            set(annotations.get("phorvex.ai/guardrail-variants", "").split(",")) == {"pgv1", "pgv2"},
            "guardrail roster/variant differs")
    selector = service.get("spec", {}).get("selector", {})
    require(selector and all(pm.get("labels", {}).get(k) == v for k, v in selector.items()) and
            service["spec"].get("ports") == [{"port": 8000, "protocol": "TCP", "targetPort": 8000}],
            "Service route/port does not select exact target")
    require(slices.get("kind") in {"EndpointSliceList", "List"} and not slices.get("metadata", {}).get("continue") and
            len(slices.get("items", [])) >= 1, "EndpointSlice inventory incomplete")
    endpoints = []
    for row in slices["items"]:
        ports = row.get("ports", [])
        require(row.get("metadata", {}).get("namespace") == "vllm" and
                row["metadata"].get("labels", {}).get("kubernetes.io/service-name") == "vllm" and
                len(ports) == 1 and ports[0].get("port") == 8000 and
                ports[0].get("protocol") == "TCP" and ports[0].get("name", "") == "",
                "EndpointSlice route differs")
        owner(row, "Service", "vllm", sm["uid"])
        endpoints.extend(row.get("endpoints", []))
    require(len(endpoints) == 1 and endpoints[0].get("targetRef", {}).get("uid") == pm["uid"] and
            endpoints[0]["targetRef"].get("name") == pm["name"] and
            endpoints[0].get("conditions", {}).get("ready") is True and
            endpoints[0]["conditions"].get("serving") is True and
            endpoints[0]["conditions"].get("terminating") is False,
            "sole Ready Service endpoint differs")
    ps = policy.get("spec", {})
    require(ps.get("mode") == "active" and "guardrail-rotate" in ps.get("actions", {}).get("enabled", []) and
            ps.get("triggers", {}).get("eventDriven") is True and
            ps.get("selector", {}).get("matchLabels", {}).get("app") == "vllm" and
            all(pm.get("labels", {}).get(k) == v for k, v in ps.get("selector", {}).get("matchLabels", {}).items()) and
            isinstance(policy_m.get("generation"), int) and policy_m["generation"] >= 1 and
            policy.get("status", {}).get("observedGeneration") == policy_m["generation"],
            "policy is not active/current for guardrail-rotate target")
    audit_url = flag(console_spec.get("args", []), "-audit-source-url")
    audit_dns = flag(console_spec["args"], "-audit-source-server-dns")
    u = urlsplit(audit_url)
    require(u.scheme == "https" and u.hostname == audit_dns and u.port == 8445 and not u.username and
            not u.password and not u.path and not u.query and not u.fragment and
            audit_dns == AUDIT_DNS, "authenticated audit source route differs")
    if lease_data is not None:
        require(lease_data["eventCreator"] == "system:serviceaccount:phorvex-system:" +
                console["spec"].get("serviceAccountName", "") and
                lease_data["auditSourceIdentity"] == audit_url + "|" + audit_dns,
                "retained caller console/audit identity differs")
        console_lease_projection(console, rs, deployment, digest(retained_lease_profile_bytes))
    for arg, expected in (("-audit-source-client-cert", "/etc/audit-client/tls.crt"),
                          ("-audit-source-client-key", "/etc/audit-client/tls.key"),
                          ("-audit-source-ca", "/etc/audit-client/ca.crt")):
        require(flag(console_spec["args"], arg) == expected, "audit client mount path differs")
    mount(console_spec, console["spec"].get("volumes", []), "/etc/audit-client", "secret")
    mount(console_spec, console["spec"].get("volumes", []), "/etc/phorvex-catalogue-v1", "secret")
    sa = console["spec"].get("serviceAccountName", "")
    require(bool(DNS.fullmatch(sa)), "console event creator ServiceAccount unavailable")
    fixture = {
        "runID": "run-1", "transport": "in-cluster", "clusterUID": cluster_m["uid"],
        "podName": pm["name"], "podUID": pm["uid"], "podImageID": vllm_status["imageID"],
        "serviceUID": sm["uid"], "sourceConfigMapName": "guardrail-proxy", "sourceUID": cm["uid"],
        "sourceSHA256": digest(files["guardrail_proxy.py"]),
        "boundarySourceSHA256": digest(files["dual_server.py"]),
        "guardrailJournalName": journal_name(pm["uid"]), "guardrailJournalUID": "",
        "journalInitiallyAbsent": False, "captureCurrentJournal": True,
        "managerPodName": mm["name"], "managerPodUID": mm["uid"], "managerImageID": manager_status["imageID"],
        "consoleDeploymentName": dm["name"], "consoleDeploymentUID": dm["uid"],
        "consoleImageID": console_status["imageID"],
        "policyName": "vllm-defense", "policyUID": policy_m["uid"], "policyGeneration": policy_m["generation"],
        "modelID": MODEL, "activeVariant": "",
        "eventCreator": "system:serviceaccount:phorvex-system:" + sa,
        "consoleURL": "http://127.0.0.1:8090", "scopedTokenFile": "/etc/phorvex-catalogue-v1/token",
        "auditURL": audit_url, "auditServerName": audit_dns,
        "auditCAFile": "/etc/audit-client/ca.crt", "auditClientCertFile": "/etc/audit-client/tls.crt",
        "auditClientKeyFile": "/etc/audit-client/tls.key", "maxRunSeconds": 600, "cleanupSeconds": 90,
    }
    if lease:
        fixture["retainedCallerLeaseProfileSHA256"] = digest(retained_lease_profile_bytes)
    profile = {"kubeconfig": "", "context": context, "namespace": "vllm", "ownedAck": True,
               "trialsPerArm": 1, "masterSeed": 1337, "outDir": "out-guardrail-effect",
               "defenderFilter": [], "scenarioFilter": [], "guardrailAvailabilityFixture": fixture}
    raw = (json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= 65536, "profile exceeds chart/console bound")
    profile_sha = digest(raw)
    name = "phorvex-catalogue-guardrail-effect-" + profile_sha[:12]
    cm_candidate = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "phorvex-system"},
                    "immutable": True, "binaryData": {"config.guardrail-effect.yaml": base64.b64encode(raw).decode()}}
    values = {"catalogueProfiles": {"guardrailEffect": {"enabled": True, "configMapName": name,
                  "profileBase64": base64.b64encode(raw).decode()}},
              "phorvex": {"phorvex": {"console": {"guardrailEffect": {
                  "enabled": True, "configMapName": name, "profileSHA256": profile_sha,
                  "sourceConfigMap": "guardrail-proxy", "guardrailJournalName": fixture["guardrailJournalName"]}}}}}
    return raw, cm_candidate, values


def read_manifest(path: Path, expected_sha: str) -> tuple[dict[str, dict], dict[str, str]]:
    require(bool(SHA.fullmatch(expected_sha)), "manifest SHA-256 missing")
    raw = read_regular_bounded(path, 16384)
    require(digest(raw) == expected_sha, "manifest byte/hash drift")
    manifest = json.loads(raw)
    require(isinstance(manifest, dict) and manifest.get("schema") == "guardrail-effect-inputs-v1" and
            isinstance(manifest.get("inputs"), dict) and
            set(manifest["inputs"]) in (set(ROLES), set(ROLES) | {LEASE_ROLE}),
            "manifest role set differs")
    objects, hashes, times = {}, {}, []
    for role in (*ROLES, *((LEASE_ROLE,) if LEASE_ROLE in manifest["inputs"] else ())):
        row = manifest["inputs"][role]
        require(isinstance(row, dict) and set(row) == {"path", "sha256"} and
                isinstance(row["sha256"], str) and bool(SHA.fullmatch(row["sha256"])) and
                isinstance(row["path"], str), role + " input pin differs")
        relative = Path(row["path"])
        require(not relative.is_absolute() and relative.parts and ".." not in relative.parts,
                role + " input must be inside capture directory")
        source = path.parent / relative
        require(source.resolve().is_relative_to(path.parent.resolve()), role + " input escapes capture directory")
        data = read_regular_bounded(source, 4_000_000)
        require(digest(data) == row["sha256"], role + " original byte/hash drift")
        receipt = json.loads(data)
        require(receipt.get("rc") == 0 and receipt.get("dispatch_count") == 1 and
                isinstance(receipt.get("args"), list) and "get" in receipt["args"] and
                not any(x in receipt["args"] for x in ("secret", "secrets", "exec", "patch", "apply")),
                role + " is not one safe successful GET")
        captured = dt.datetime.fromisoformat(receipt["finished_at"].replace("Z", "+00:00"))
        require(captured.tzinfo is not None, role + " capture time lacks timezone")
        times.append(captured)
        objects[role] = json.loads(receipt["stdout"])
        hashes[role] = row["sha256"]
    now = dt.datetime.now(dt.timezone.utc)
    require(max(times) - min(times) <= dt.timedelta(minutes=2) and
            dt.timedelta(0) <= now - max(times) <= dt.timedelta(minutes=15),
            "originals are stale or cross-object capture window differs")
    return objects, hashes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--input-manifest-sha256", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--retained-caller-lease-profile", type=Path)
    parser.add_argument("--retained-caller-lease-profile-sha256")
    args = parser.parse_args()
    inputs, hashes = read_manifest(args.input_manifest, args.input_manifest_sha256)
    lease_profile = None
    if args.retained_caller_lease_profile is not None or args.retained_caller_lease_profile_sha256 is not None:
        require(args.retained_caller_lease_profile is not None and
                isinstance(args.retained_caller_lease_profile_sha256, str) and
                bool(SHA.fullmatch(args.retained_caller_lease_profile_sha256)),
                "retained caller lease profile pin incomplete")
        lease_profile = read_regular_bounded(args.retained_caller_lease_profile, 8192)
        require(digest(lease_profile) == args.retained_caller_lease_profile_sha256,
                "retained caller lease profile byte/hash drift")
    raw, cm, values = render(inputs, args.context, lease_profile)
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(args.out, 0o700)
    files = {"config.guardrail-effect.yaml": raw,
             "configmap.candidate.json": (json.dumps(cm, sort_keys=True, indent=2) + "\n").encode(),
             "values.overlay.yaml": (json.dumps(values, sort_keys=True, indent=2) + "\n").encode(),
             "inputs-sha256.json": (json.dumps(hashes, sort_keys=True, indent=2) + "\n").encode()}
    for name, content in files.items():
        fd = os.open(args.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps({"status": "REVIEW_ONLY", "profileSHA256": digest(raw),
                      "profileConfigMap": cm["metadata"]["name"], "journalName":
                      json.loads(raw)["guardrailAvailabilityFixture"]["guardrailJournalName"],
                      "secretBytesIncluded": False}, sort_keys=True))


if __name__ == "__main__":
    main()
