"""Offline, default-off owner package for vLLM endpoint-lease activation.

No Kubernetes, registry, or HTTP calls occur. Secret bytes are accepted and
written only through private mode-0600 files in an explicit private directory.
The three commands are deliberately separated because Kubernetes UIDs do not
exist until the owner creates the corresponding objects.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat


FILES = ("guardrail_proxy.py", "dual_server.py", "endpoint_lease.py",
         "drain_v11.py", "drain_v11_init.py")
BASE_FILES = ("deployment.candidate.json", "configmap.candidate.json",
              "service.candidate.json", "values.overlay.yaml",
              "secret-contract.json", "publication-join.json")
PROXY_RECIPE_FILES = (".dockerignore", "Dockerfile", "requirements.lock", "wheelhouse.sha256",
                      "verify_wheelhouse.py", "prepare_wheelhouse.py", "verify_runtime.py",
                      "verify_recipe.py", "test_recipe.py", "write_publish_receipt.py", "README.md")
PROXY_BASE_IMAGE = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
PROXY_COMMAND = '["python3", "-B", "/src/dual_server.py"]'
APPROVED_ENGINE_IMAGE = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:3534dec6b97c1b6e4042b3cb2987c6cf8c4d4e4167a833320e2f1b7f4135d050"
TENANT_SECRET = "phorvex-endpoint-lease-keys"
CONSOLE_SECRET = "vllm-endpoint-lease-callers"
SOURCE_CM = "guardrail-proxy"
POLICY_CM = "phorvex-endpoint-lease-policy"
JOURNAL_CM = "phorvex-endpoint-lease-journal"
PROXY_SA = "phorvex-endpoint-lease-proxy"
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"753556437180\.dkr\.ecr\.us-east-2\.amazonaws\.com/phorvex@sha256:[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value or any(key.casefold() == old.casefold() for old in value):
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def parse(raw: bytes):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read_exact(path: Path, expected: str, *, private=False, limit=1_000_000):
    if not isinstance(expected, str) or not HEX.fullmatch(expected):
        raise ValueError("reviewed file SHA-256 required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("input file type or size differs")
    if private and (info.st_mode & 0o077):
        raise ValueError("private input must be mode 0600")
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError("input SHA-256 differs")
    return parse(raw)


def object_meta(obj: dict, kind: str, namespace: str, name: str, *, immutable=None):
    meta = obj.get("metadata", {})
    if (obj.get("kind") != kind or meta.get("namespace") != namespace
            or meta.get("name") != name or not UID.fullmatch(meta.get("uid", ""))
            or not str(meta.get("resourceVersion", "")).isdigit()
            or meta.get("deletionTimestamp")):
        raise ValueError(kind + " exact installed identity unavailable")
    if immutable is not None and obj.get("immutable") is not immutable:
        raise ValueError(kind + " immutable authority differs")
    return meta


def private_output(directory: Path, files: dict[str, bytes]):
    if directory.exists():
        raise ValueError("output directory already exists")
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=False)
    os.chmod(directory, 0o700)
    hashes = {}
    for name, raw in files.items():
        if "/" in name or name in ("", ".", ".."):
            raise ValueError("output name differs")
        path = directory / name
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = sha(raw)
    return hashes


def owner_keys(owner: dict):
    if set(owner) != {"schema", "client-a", "client-b", "seed"} or owner["schema"] != "endpoint-lease-owner-keys-v1":
        raise ValueError("owner key input schema differs")
    raw = {}
    for key in ("client-a", "client-b", "seed"):
        value = owner[key]
        if not isinstance(value, str):
            raise ValueError("owner key input type differs")
        try:
            raw[key] = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("owner key input encoding differs") from exc
        if not 32 <= len(raw[key]) <= 256:
            raise ValueError("owner key input length differs")
    for key in ("client-a", "client-b"):
        if any(byte < 33 or byte > 126 for byte in raw[key]):
            raise ValueError("caller bearer must be printable without whitespace")
    if len(set(raw.values())) != 3:
        raise ValueError("owner key inputs must be distinct")
    return raw


def secret_document(namespace: str, name: str, values: dict[str, bytes]):
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": namespace, "name": name},
            "type": "Opaque", "immutable": True,
            "data": {key: base64.b64encode(value).decode() for key, value in values.items()}}


def provision(owner: dict):
    keys = owner_keys(owner)
    tenant = secret_document("vllm", TENANT_SECRET, keys)
    console = secret_document("phorvex-system", CONSOLE_SECRET,
                              {key: keys[key] for key in ("client-a", "client-b")})
    index = {"schema": "endpoint-lease-provision-v1", "secretBytesIncluded": False,
             "clientASHA256": sha(keys["client-a"]), "clientBSHA256": sha(keys["client-b"]),
             "seedSHA256": sha(keys["seed"]),
             "tenantSecretName": TENANT_SECRET, "consoleSecretName": CONSOLE_SECRET}
    return {"tenant-secret.PRIVATE.json": canonical(tenant),
            "console-secret.PRIVATE.json": canonical(console),
            "PROVISION.json": canonical(index)}


def verify_secret(obj: dict, namespace: str, name: str, expected: dict[str, bytes]):
    meta = object_meta(obj, "Secret", namespace, name, immutable=True)
    if obj.get("type") != "Opaque" or set(obj.get("data", {})) != set(expected):
        raise ValueError("installed Secret keyset/type differs")
    for key, value in expected.items():
        if base64.b64decode(obj["data"][key], validate=True) != value:
            raise ValueError("installed Secret value differs from owner provisioning")
    return meta["uid"]


def source_bundle(source_dir: Path, manifest: dict):
    if (set(manifest) != {"schema", "sourceCommit", "files"}
            or manifest["schema"] != "endpoint-lease-source-v1"
            or not COMMIT.fullmatch(manifest["sourceCommit"])
            or set(manifest["files"]) != set(FILES)):
        raise ValueError("reviewed source manifest differs")
    data = {}
    raw_files = []
    for name in FILES:
        path = source_dir / name
        if not path.exists():
            relative = (Path("build/integrations/vllm-live-runtime") / name
                        if name in ("dual_server.py", "endpoint_lease.py")
                        else Path("build/test-harness/guardrail") / name)
            path = source_dir / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 200_000:
            raise ValueError("source file type or size differs")
        raw = path.read_bytes()
        if sha(raw) != manifest["files"][name]:
            raise ValueError("reviewed source file SHA-256 differs")
        data[name] = raw.decode("utf-8")
        raw_files.append(raw)
    digest = sha(b"\0".join(raw_files))
    return data, digest


def absent(evidence: dict, namespace: str, kind: str, name: str, cluster_uid: str):
    if (set(evidence) != {"schema", "clusterUID", "namespace", "kind", "name", "statusCode", "dispatchCount", "observedAt"}
            or evidence["schema"] != "endpoint-lease-absence-v1"
            or evidence["clusterUID"] != cluster_uid or evidence["namespace"] != namespace
            or evidence["kind"] != kind or evidence["name"] != name
            or type(evidence["statusCode"]) is not int or evidence["statusCode"] != 404
            or type(evidence["dispatchCount"]) is not int or evidence["dispatchCount"] != 1):
        raise ValueError("explicit exact-name absence evidence unavailable")
    try:
        seen = datetime.fromisoformat(evidence["observedAt"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - seen).total_seconds()
    except (TypeError, ValueError) as exc:
        raise ValueError("absence observation time unavailable") from exc
    if seen.tzinfo is None or not 0 <= age <= 900:
        raise ValueError("absence observation is stale or future-dated")


def prepare(owner: dict, tenant: dict, console: dict, source_manifest: dict,
            source_dir: Path, current_source: dict, service: dict,
            policy_absence: dict, journal_absence: dict, cluster_uid: str,
            tenant_create_receipt: dict, console_create_receipt: dict):
    keys = owner_keys(owner)
    tenant_uid = verify_secret(tenant, "vllm", TENANT_SECRET, keys)
    console_uid = verify_secret(console, "phorvex-system", CONSOLE_SECRET,
                                {key: keys[key] for key in ("client-a", "client-b")})
    created(tenant_create_receipt, "Secret", "vllm", TENANT_SECRET,
            sha(canonical(secret_document("vllm", TENANT_SECRET, keys))), tenant, cluster_uid)
    created(console_create_receipt, "Secret", "phorvex-system", CONSOLE_SECRET,
            sha(canonical(secret_document("phorvex-system", CONSOLE_SECRET,
                                      {key: keys[key] for key in ("client-a", "client-b")}))),
            console, cluster_uid)
    source_meta = object_meta(current_source, "ConfigMap", "vllm", SOURCE_CM)
    service_meta = object_meta(service, "Service", "vllm", "vllm")
    absent(policy_absence, "vllm", "ConfigMap", POLICY_CM, cluster_uid)
    absent(journal_absence, "phorvex-system", "ConfigMap", JOURNAL_CM, cluster_uid)
    data, source_sha = source_bundle(source_dir, source_manifest)
    if current_source.get("immutable") is True and current_source.get("data") != data:
        raise ValueError("existing immutable source cannot be rewritten")
    hmac_a = hmac.new(keys["seed"], keys["client-a"], hashlib.sha256).hexdigest()
    hmac_b = hmac.new(keys["seed"], keys["client-b"], hashlib.sha256).hexdigest()
    if hmac_a == hmac_b:
        raise ValueError("client HMAC IDs collide")
    state = {"version": 1, "revision": 0, "serviceUID": service_meta["uid"],
             "proxySourceSHA256": source_sha, "secretUID": tenant_uid,
             "seedSHA256": sha(keys["seed"]), "allowedClientHMACs": sorted((hmac_a, hmac_b)),
             "revokedClientHMACs": [], "lastOperationID": ""}
    state_raw = canonical(state)
    if len(state_raw) > 16 * 1024:
        raise ValueError("initial policy exceeds bound")
    source_candidate = {"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"namespace": "vllm", "name": SOURCE_CM,
                                     "uid": source_meta["uid"],
                                     "resourceVersion": source_meta["resourceVersion"]},
                        "immutable": True, "data": data}
    policy_candidate = {"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"namespace": "vllm", "name": POLICY_CM},
                        "data": {"state.json": state_raw.decode()}}
    journal_raw = canonical({"version": 1, "receipts": []})
    journal_candidate = {"apiVersion": "v1", "kind": "ConfigMap",
                         "metadata": {"namespace": "phorvex-system", "name": JOURNAL_CM,
                                      "labels": {"phorvex.ai/endpoint-lease-journal": "v1"}},
                         "data": {"receipts.json": journal_raw.decode()}}
    policy_candidate_raw = canonical(policy_candidate)
    journal_candidate_raw = canonical(journal_candidate)
    source_candidate_raw = canonical(source_candidate)
    index = {"schema": "endpoint-lease-prepared-v1", "clusterUID": cluster_uid,
             "sourceCommit": source_manifest["sourceCommit"], "sourceSHA256": source_sha,
             "sourceConfigMapUID": source_meta["uid"], "sourceConfigMapRV": source_meta["resourceVersion"],
             "serviceUID": service_meta["uid"], "serviceRV": service_meta["resourceVersion"],
             "tenantSecretUID": tenant_uid, "consoleSecretUID": console_uid,
             "seedSHA256": state["seedSHA256"], "clientASHA256": sha(keys["client-a"]),
             "clientBSHA256": sha(keys["client-b"]), "clientAHMAC": hmac_a,
             "clientBHMAC": hmac_b, "stateSHA256": sha(state_raw),
             "journalSHA256": sha(journal_raw),
             "sourceCandidateSHA256": sha(source_candidate_raw),
             "policyCandidateSHA256": sha(policy_candidate_raw),
             "journalCandidateSHA256": sha(journal_candidate_raw),
             "status": "PREPARED_NOT_APPLIED"}
    return {"source-configmap.candidate.json": source_candidate_raw,
            "policy-configmap.CREATE.json": policy_candidate_raw,
            "journal-configmap.CREATE.json": journal_candidate_raw,
            "PREPARED.json": canonical(index)}


def named_proxy_access():
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"namespace": "vllm", "name": PROXY_SA}}
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"namespace": "vllm", "name": PROXY_SA},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [POLICY_CM], "verbs": ["get"]},
                      {"apiGroups": [""], "resources": ["secrets"], "resourceNames": [TENANT_SECRET], "verbs": ["get"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"namespace": "vllm", "name": PROXY_SA},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": PROXY_SA},
               "subjects": [{"kind": "ServiceAccount", "namespace": "vllm", "name": PROXY_SA}]}
    return {"proxy-serviceaccount.json": canonical(sa), "proxy-role.json": canonical(role),
            "proxy-rolebinding.json": canonical(binding)}


def published_proxy_image(receipt: dict, recipe_dir: Path):
    expected_keys = {"schemaVersion", "sourceSHA", "image", "digest", "imageByDigest",
                     "platform", "baseImage", "command", "wheelCount", "lockedVersions",
                     "recipeSHA256", "classifierWeightsIncluded", "applicationSourceIncluded",
                     "githubRunID", "githubRunAttempt"}
    source = receipt.get("sourceSHA")
    image = receipt.get("image")
    digest = receipt.get("digest")
    if (set(receipt) != expected_keys or receipt.get("schemaVersion") != 1
            or not isinstance(source, str) or not COMMIT.fullmatch(source)
            or image != "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-lease-proxy-" + source
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or receipt.get("imageByDigest") != image.split(":vllm-lease-proxy-", 1)[0] + "@" + digest
            or not IMAGE.fullmatch(receipt["imageByDigest"])
            or receipt.get("platform") != "linux/amd64"
            or receipt.get("baseImage") != PROXY_BASE_IMAGE
            or receipt.get("command") != PROXY_COMMAND
            or receipt.get("classifierWeightsIncluded") is not False
            or receipt.get("applicationSourceIncluded") is not False
            or type(receipt.get("wheelCount")) is not int or receipt["wheelCount"] < 1
            or not isinstance(receipt.get("lockedVersions"), dict) or not receipt["lockedVersions"]
            or not all(isinstance(receipt.get(key), str) and re.fullmatch(r"[1-9][0-9]*", receipt[key])
                       for key in ("githubRunID", "githubRunAttempt"))
            or not isinstance(receipt.get("recipeSHA256"), dict)
            or set(receipt["recipeSHA256"]) != set(PROXY_RECIPE_FILES)):
        raise ValueError("original published proxy image receipt differs")
    for name in PROXY_RECIPE_FILES:
        path = recipe_dir / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 200_000:
            raise ValueError("reviewed proxy recipe file unavailable")
        if sha(path.read_bytes()) != receipt["recipeSHA256"][name]:
            raise ValueError("published proxy recipe SHA-256 differs: " + name)
    dockerfile = (recipe_dir / "Dockerfile").read_text()
    if (not dockerfile.startswith("FROM --platform=linux/amd64 " + PROXY_BASE_IMAGE + "\n")
            or "USER 10001:10001" not in dockerfile
            or "CMD " + PROXY_COMMAND not in dockerfile
            or "--no-index" not in dockerfile or "--require-hashes" not in dockerfile):
        raise ValueError("published proxy Dockerfile runtime contract differs")
    return receipt["imageByDigest"], source


def created(receipt: dict, kind: str, namespace: str, name: str, candidate_hash: str,
            actual: dict, cluster_uid: str):
    meta = actual["metadata"]
    if (set(receipt) != {"schema", "clusterUID", "kind", "namespace", "name",
                         "requestSHA256", "uid", "resourceVersion", "dispatchCount", "operation", "completedAt"}
            or receipt["schema"] != "endpoint-lease-create-receipt-v1"
            or receipt["clusterUID"] != cluster_uid or receipt["kind"] != kind
            or receipt["namespace"] != namespace or receipt["name"] != name
            or receipt["requestSHA256"] != candidate_hash
            or receipt["uid"] != meta["uid"]
            or receipt["resourceVersion"] != meta["resourceVersion"]
            or receipt["dispatchCount"] != 1 or receipt["operation"] != "create"):
        raise ValueError("owner create receipt does not bind installed UID")
    try:
        completed = datetime.fromisoformat(receipt["completedAt"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("owner create receipt completion time unavailable") from exc
    if completed.tzinfo is None or completed > datetime.now(timezone.utc):
        raise ValueError("owner create receipt time differs")
    return completed


def adopt(prepared: dict, source: dict, policy: dict, journal: dict,
          tenant: dict, console: dict, service: dict, base: dict[str, dict],
          proxy_image_receipt: dict, proxy_recipe_dir: Path, policy_create_receipt: dict,
          journal_create_receipt: dict):
    if prepared.get("schema") != "endpoint-lease-prepared-v1" or prepared.get("status") != "PREPARED_NOT_APPLIED":
        raise ValueError("prepared authority unavailable")
    source_meta = object_meta(source, "ConfigMap", "vllm", SOURCE_CM, immutable=True)
    policy_meta = object_meta(policy, "ConfigMap", "vllm", POLICY_CM)
    journal_meta = object_meta(journal, "ConfigMap", "phorvex-system", JOURNAL_CM)
    service_meta = object_meta(service, "Service", "vllm", "vllm")
    tenant_meta = object_meta(tenant, "Secret", "vllm", TENANT_SECRET, immutable=True)
    console_meta = object_meta(console, "Secret", "phorvex-system", CONSOLE_SECRET, immutable=True)
    journal_created = created(journal_create_receipt, "ConfigMap", "phorvex-system", JOURNAL_CM,
                              prepared["journalCandidateSHA256"], journal, prepared["clusterUID"])
    policy_created = created(policy_create_receipt, "ConfigMap", "vllm", POLICY_CM,
                             prepared["policyCandidateSHA256"], policy, prepared["clusterUID"])
    if journal_created >= policy_created:
        raise ValueError("protected journal must be created before durable policy")
    if (source_meta["uid"] != prepared["sourceConfigMapUID"]
            or service_meta["uid"] != prepared["serviceUID"]
            or service_meta["resourceVersion"] != prepared["serviceRV"]
            or tenant_meta["uid"] != prepared["tenantSecretUID"]
            or console_meta["uid"] != prepared["consoleSecretUID"]
            or set(source.get("data", {})) != set(FILES)
            or sha(b"\0".join(source["data"][name].encode() for name in FILES)) != prepared["sourceSHA256"]
            or set(policy.get("data", {})) != {"state.json"}
            or sha(policy["data"]["state.json"].encode()) != prepared["stateSHA256"]
            or set(journal.get("data", {})) != {"receipts.json"}
            or sha(journal["data"]["receipts.json"].encode()) != prepared["journalSHA256"]
            or journal["metadata"].get("labels", {}).get("phorvex.ai/endpoint-lease-journal") != "v1"):
        raise ValueError("installed source/policy/journal identity or initial bytes drift")
    state = parse(policy["data"]["state.json"].encode())
    if (canonical(state) != policy["data"]["state.json"].encode() or state.get("serviceUID") != service_meta["uid"]
            or state.get("secretUID") != tenant_meta["uid"]
            or state.get("proxySourceSHA256") != prepared["sourceSHA256"]
            or state.get("seedSHA256") != prepared["seedSHA256"]):
        raise ValueError("installed canonical policy authority differs")
    proxy_image, proxy_build_commit = published_proxy_image(proxy_image_receipt, proxy_recipe_dir)
    deployment = base["deployment.candidate.json"]
    configmap = base["configmap.candidate.json"]
    base_service = base["service.candidate.json"]
    base_join = base["publication-join.json"]
    if (deployment.get("kind") != "Deployment" or deployment.get("metadata", {}).get("namespace") != "vllm"
            or deployment["metadata"].get("name") != "vllm"
            or configmap.get("metadata", {}).get("name") != SOURCE_CM
            or set(configmap.get("data", {})) != {"guardrail_proxy.py", "dual_server.py", "drain_v11.py", "drain_v11_init.py"}
            or base_join.get("originalServiceUID") != prepared["serviceUID"]
            or base_join.get("originalConfigMapUID") != prepared["sourceConfigMapUID"]
            or base_service.get("metadata", {}).get("name") != "vllm"
            or base_service.get("spec", {}).get("selector") != {
                **service.get("spec", {}).get("selector", {}), "phorvex.ai/serving": "true"}
            or not any(v.get("name") == "guardrail-src" and v.get("configMap", {}).get("name") == SOURCE_CM
                       for v in deployment["spec"]["template"]["spec"].get("volumes", []))):
        raise ValueError("reviewed drain base candidate differs")
    dep = json.loads(canonical(deployment))
    spec = dep["spec"]["template"]["spec"]
    if any(set(row) - {"name", "configMap", "secret", "emptyDir"} or
           sum(key in row for key in ("configMap", "secret", "emptyDir")) != 1
           for row in spec.get("volumes", [])):
        raise ValueError("shared or unreviewed Pod volume prevents proxy fsGroup adoption")
    pod_security = spec.setdefault("securityContext", {})
    if pod_security.get("fsGroup") not in (None, 10001):
        raise ValueError("existing Pod fsGroup differs")
    pod_security["fsGroup"] = 10001
    pod_security["fsGroupChangePolicy"] = "OnRootMismatch"
    containers = {row.get("name"): row for row in spec.get("containers", [])}
    if set(containers) != {"vllm", "guardrail"} or spec.get("serviceAccountName", "default") != "default":
        raise ValueError("reviewed drain Pod containers/ServiceAccount differ")
    engine = containers["vllm"]
    if (engine.get("image") != APPROVED_ENGINE_IMAGE
            or base_join.get("publishedImage") != APPROVED_ENGINE_IMAGE):
        raise ValueError("reviewed drain engine image differs from publication join")
    engine_args = engine.get("args")
    engine_env = [row for row in engine.get("env", []) if row.get("name") == "VLLM_API_KEY"]
    if (not isinstance(engine_args, list) or not all(isinstance(row, str) for row in engine_args)
            or engine_args.count("--host") != 1 or engine_args.count("127.0.0.1") != 1
            or engine_args.count("--port") != 1 or engine_args.count("8001") != 1
            or engine_args[engine_args.index("--host") + 1:engine_args.index("--host") + 2] != ["127.0.0.1"]
            or engine_args[engine_args.index("--port") + 1:engine_args.index("--port") + 2] != ["8001"]
            or len(engine_env) != 1
            or engine_env[0].get("valueFrom") != {"secretKeyRef": {"name": "vllm-control", "key": "api-key"}}):
        raise ValueError("reviewed drain engine loopback or API key authority differs")
    guard = containers["guardrail"]
    old = guard.get("volumeMounts", [])
    if sum(row.get("name") == "guardrail-src" for row in old) != 1:
        raise ValueError("reviewed guardrail source mount differs")
    old[:] = [row for row in old if row.get("name") != "guardrail-src"]
    old.extend({"name": "guardrail-src", "mountPath": "/src/" + name,
                "subPath": name, "readOnly": True} for name in FILES)
    if any(row.get("name") == "endpoint-lease-keys" for row in spec.get("volumes", [])):
        raise ValueError("lease Secret volume already present")
    spec.setdefault("volumes", []).append({"name": "endpoint-lease-keys",
        "secret": {"secretName": TENANT_SECRET, "optional": False, "defaultMode": 288,
                   "items": [{"key": name, "path": name} for name in ("client-a", "client-b", "seed")]}})
    old.append({"name": "endpoint-lease-keys", "mountPath": "/etc/phorvex/endpoint-lease-keys", "readOnly": True})
    if any(row.get("name") == "endpoint-lease-api-auth" for row in spec["volumes"]):
        raise ValueError("lease API token volume already present")
    spec["volumes"].append({"name": "endpoint-lease-api-auth", "projected": {"defaultMode": 288, "sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
        {"configMap": {"name": "kube-root-ca.crt", "optional": False,
                       "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
        {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}},
    ]}})
    old.append({"name": "endpoint-lease-api-auth",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True})
    init = spec.get("initContainers", [])
    if (len(init) != 1 or init[0].get("name") != "phorvex-drain-ledger-init"
            or init[0].get("command") != ["python", "/src/drain_v11_init.py"]):
        raise ValueError("reviewed drain initializer differs")
    init[0]["image"] = proxy_image
    init[0]["command"] = ["python3", "-B", "/src/drain_v11_init.py"]
    if guard.get("securityContext") or init[0].get("securityContext"):
        raise ValueError("existing proxy security context differs")
    proxy_security = {"runAsNonRoot": True, "runAsUser": 10001,
                      "runAsGroup": 10001, "allowPrivilegeEscalation": False}
    guard["securityContext"] = dict(proxy_security)
    init[0]["securityContext"] = dict(proxy_security)
    init[0]["volumeMounts"] = [row for row in init[0].get("volumeMounts", []) if row.get("name") != "guardrail-src"]
    init[0]["volumeMounts"].extend({"name": "guardrail-src", "mountPath": "/src/" + name,
                                     "subPath": name, "readOnly": True} for name in FILES)
    guard["image"] = proxy_image
    guard["command"] = ["python3", "-B", "/src/dual_server.py"]
    guard["args"] = []
    spec["serviceAccountName"] = PROXY_SA
    spec["automountServiceAccountToken"] = False
    env = guard.setdefault("env", [])
    names = {row.get("name") for row in env}
    drain_proxy_rows = [row for row in env if row.get("name") == "PHORVEX_PROXY_SOURCE"]
    if len(drain_proxy_rows) != 1 or set(drain_proxy_rows[0]) != {"name", "value"}:
        raise ValueError("reviewed drain proxy source environment differs")
    drain_proxy_sha = sha(source["data"]["guardrail_proxy.py"].encode())
    drain_proxy_rows[0]["value"] = drain_proxy_sha
    required = {"PHORVEX_ENDPOINT_LEASE_REQUIRED": "true",
                "PHORVEX_ENDPOINT_LEASE_SECRET_DIR": "/etc/phorvex/endpoint-lease-keys",
                "PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID": policy_meta["uid"],
                "PHORVEX_ENDPOINT_LEASE_SECRET_UID": tenant_meta["uid"],
                "PHORVEX_ENDPOINT_LEASE_SERVICE_UID": service_meta["uid"],
                "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256": prepared["sourceSHA256"]}
    if names & set(required):
        raise ValueError("endpoint lease environment already present")
    env.extend({"name": name, "value": value} for name, value in required.items())
    if sum(row.get("name") == "POD_UID" for row in env) != 1:
        raise ValueError("reviewed downward Pod UID authority differs")
    annotations = dep["spec"]["template"]["metadata"].setdefault("annotations", {})
    if not HEX.fullmatch(annotations.get("phorvex.ai/drain-proxy-source", "")):
        raise ValueError("reviewed drain proxy source annotation unavailable")
    annotations["phorvex.ai/drain-proxy-source"] = drain_proxy_sha
    annotations["phorvex.ai/endpoint-lease-source-sha256"] = prepared["sourceSHA256"]
    annotations["phorvex.ai/endpoint-lease-policy-configmap-uid"] = policy_meta["uid"]
    annotations["phorvex.ai/endpoint-lease-source-configmap"] = SOURCE_CM
    annotations["phorvex.ai/endpoint-lease-event-creator"] = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
    authority = {"schema": "endpoint-lease-adoption-v1", "status": "CANDIDATE_NOT_APPLIED",
                 "serviceUID": service_meta["uid"], "sourceConfigMapUID": source_meta["uid"],
                 "policyConfigMapUID": policy_meta["uid"], "journalUID": journal_meta["uid"],
                 "tenantSecretUID": tenant_meta["uid"], "consoleSecretUID": console_meta["uid"],
                 "sourceConfigMapName": SOURCE_CM, "proxySourceSHA256": prepared["sourceSHA256"],
                 "drainProxySourceSHA256": drain_proxy_sha,
                 "engineImage": APPROVED_ENGINE_IMAGE,
                 "proxyImage": proxy_image,
                 "proxyImageBuildCommit": proxy_build_commit,
                 "seedSHA256": prepared["seedSHA256"],
                 "clientASHA256": prepared["clientASHA256"], "clientBSHA256": prepared["clientBSHA256"],
                 "clientAHMAC": prepared["clientAHMAC"], "clientBHMAC": prepared["clientBHMAC"]}
    authority["eventCreator"] = annotations["phorvex.ai/endpoint-lease-event-creator"]
    result = {"deployment.candidate.json": canonical(dep), "ADOPTION.json": canonical(authority)}
    result.update(named_proxy_access())
    return result


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    provision_cmd = commands.add_parser("provision")
    for name in ("owner-input", "owner-input-sha256", "out"):
        provision_cmd.add_argument("--" + name, required=True)
    prepare_cmd = commands.add_parser("prepare")
    for name in ("owner-input", "owner-input-sha256", "tenant-secret", "tenant-secret-sha256",
                 "console-secret", "console-secret-sha256", "source-manifest", "source-manifest-sha256",
                 "source-dir", "current-source", "current-source-sha256", "service", "service-sha256",
                 "policy-absence", "policy-absence-sha256", "journal-absence", "journal-absence-sha256",
                 "tenant-create-receipt", "tenant-create-receipt-sha256",
                 "console-create-receipt", "console-create-receipt-sha256",
                 "cluster-uid", "out"):
        prepare_cmd.add_argument("--" + name, required=True)
    adopt_cmd = commands.add_parser("adopt")
    for name in ("prepared", "prepared-sha256", "source", "source-sha256",
                 "policy", "policy-sha256", "journal", "journal-sha256",
                 "tenant-secret", "tenant-secret-sha256", "console-secret", "console-secret-sha256",
                 "service", "service-sha256", "base-candidate-dir", "base-manifest",
                 "base-manifest-sha256", "proxy-image-receipt", "proxy-image-receipt-sha256",
                 "proxy-recipe-dir",
                 "policy-create-receipt", "policy-create-receipt-sha256",
                 "journal-create-receipt", "journal-create-receipt-sha256", "out"):
        adopt_cmd.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.command == "provision":
        result = provision(read_exact(Path(args.owner_input), args.owner_input_sha256, private=True))
    elif args.command == "prepare":
        result = prepare(
            read_exact(Path(args.owner_input), args.owner_input_sha256, private=True),
            read_exact(Path(args.tenant_secret), args.tenant_secret_sha256, private=True),
            read_exact(Path(args.console_secret), args.console_secret_sha256, private=True),
            read_exact(Path(args.source_manifest), args.source_manifest_sha256), Path(args.source_dir),
            read_exact(Path(args.current_source), args.current_source_sha256),
            read_exact(Path(args.service), args.service_sha256),
            read_exact(Path(args.policy_absence), args.policy_absence_sha256),
            read_exact(Path(args.journal_absence), args.journal_absence_sha256), args.cluster_uid,
            read_exact(Path(args.tenant_create_receipt), args.tenant_create_receipt_sha256),
            read_exact(Path(args.console_create_receipt), args.console_create_receipt_sha256))
    else:
        base_manifest = read_exact(Path(args.base_manifest), args.base_manifest_sha256)
        if (base_manifest.get("schema") != "vllm-drain-base-candidate-v1"
                or set(base_manifest.get("files", {})) != set(BASE_FILES)):
            raise ValueError("reviewed base candidate manifest differs")
        base = {name: read_exact(Path(args.base_candidate_dir) / name, digest)
                for name, digest in base_manifest["files"].items()}
        result = adopt(
            read_exact(Path(args.prepared), args.prepared_sha256),
            read_exact(Path(args.source), args.source_sha256),
            read_exact(Path(args.policy), args.policy_sha256),
            read_exact(Path(args.journal), args.journal_sha256),
            read_exact(Path(args.tenant_secret), args.tenant_secret_sha256, private=True),
            read_exact(Path(args.console_secret), args.console_secret_sha256, private=True),
            read_exact(Path(args.service), args.service_sha256), base,
            read_exact(Path(args.proxy_image_receipt), args.proxy_image_receipt_sha256),
            Path(args.proxy_recipe_dir),
            read_exact(Path(args.policy_create_receipt), args.policy_create_receipt_sha256),
            read_exact(Path(args.journal_create_receipt), args.journal_create_receipt_sha256))
    hashes = private_output(Path(args.out), result)
    print(json.dumps({"status": "PRIVATE_REVIEW_ONLY", "filesSHA256": hashes,
                      "secretBytesPrinted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
