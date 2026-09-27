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
# The owner's reviewed four-key drain candidate is staged on a separate
# branch. Keep its exact source hashes here until the branches are integrated;
# when source files exist locally, compare their full bytes too.
DRAIN_SOURCE_SHA256 = {
    "drain_v11.py": "c117bfe2928a6b43146fce7aed9fa3df9b1c746d74c9855d3eafb7ba5f6de857",
    "drain_v11_init.py": "4e1a7a00550e8ce980b95114305027729dd5e3dddfdcbb2bca3026cb16b5dd5d",
}
ROLES = ("cluster", "pod", "service", "endpointslices", "source", "policy", "manager",
         "console", "console_replicaset", "console_deployment")
SHA = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")
IMAGE_ID = re.compile(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}\Z")
BARE_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
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
        bool(IMAGE_ID.fullmatch(spec.get("image", ""))) and
        bool(BARE_SHA.fullmatch(status.get("image", ""))))
    require(status.get("ready") is True and status.get("restartCount") == 0 and
            image_matches and
            bool(IMAGE_ID.fullmatch(status.get("imageID", ""))) and status.get("containerID"),
            name + " runtime incarnation is not stable")
    return spec, status


def one_env(spec: dict, name: str) -> dict:
    rows = [x for x in spec.get("env", []) if x.get("name") == name]
    require(len(rows) == 1, name + " environment authority missing/duplicate")
    return rows[0]


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


def image_id(pod: dict, name: str) -> str:
    return container(pod, name)[1]["imageID"]


def journal_name(pod_uid: str) -> str:
    # phorvex/internal/actuator/operation_journal.go receiptName, v9.
    return "phorvex-serving-effect-" + digest(("serving-effect/" + DOMAIN + "/" + pod_uid).encode())[:40]


def render(objects: dict[str, dict], context: str, source_files: dict[str, bytes] | None = None) -> tuple[bytes, dict, dict]:
    require(set(objects) == set(ROLES), "exact original set required")
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
    guard, _ = container(pod, "guardrail")
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
    require(guard.get("command", [])[:2] == ["sh", "-c"] and len(guard.get("command", [])) == 3 and
            guard["command"][2].endswith("exec python /src/dual_server.py"), "dual-listener process not installed")
    shared_secret = secret_ref(vllm, "VLLM_API_KEY", "api-key")
    require(secret_ref(guard, "VLLM_API_KEY", "api-key") == shared_secret and
            secret_ref(guard, "PHORVEX_GUARDRAIL_ADMIN_KEY", "admin-bearer") == shared_secret,
            "reviewed private upstream/admin authority differs")
    mount(guard, pod["spec"].get("volumes", []), "/src", "configMap", "guardrail-proxy")
    files = source_files or {"guardrail_proxy.py": PROXY.read_bytes(), "dual_server.py": DUAL.read_bytes()}
    require(set(files) == {"guardrail_proxy.py", "dual_server.py"} and
            set(source.get("data", {})) == set(files) | set(DRAIN_SOURCE_SHA256),
            "complete four-file dual-listener source keys differ")
    for key, raw in files.items():
        require(len(raw) <= 1 << 20 and source["data"][key].encode() == raw,
                key + " installed bytes differ from reviewed source")
    for key, expected in DRAIN_SOURCE_SHA256.items():
        encoded = source["data"][key].encode()
        require(len(encoded) <= 1 << 20 and digest(encoded) == expected,
                key + " installed bytes differ from reviewed drain source")
        checked_in = PROXY.parent / key
        if checked_in.exists():
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
            isinstance(manifest.get("inputs"), dict) and set(manifest["inputs"]) == set(ROLES),
            "manifest role set differs")
    objects, hashes, times = {}, {}, []
    for role in ROLES:
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
    args = parser.parse_args()
    inputs, hashes = read_manifest(args.input_manifest, args.input_manifest_sha256)
    raw, cm, values = render(inputs, args.context)
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
