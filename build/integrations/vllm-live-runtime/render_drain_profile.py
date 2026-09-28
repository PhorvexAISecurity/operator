"""Render one private, exact-incarnation request-drain profile; never calls Kubernetes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re

import render_guardrail_profile as guardrail_profile


HEX = re.compile(r"[0-9a-f]{64}\Z")
COMPLETION_SHA = "30ed34497113131c2749b7091bc4a49b5dd374b23b15bc5c7981c3e90ede804a"
ENGINE_SHA = "35e4419aeb3ca2c1c0153254ac0a179db454cae4a33f7d37b3b9020ebdcfa73e"
MODEL = "Qwen/Qwen2.5-7B-Instruct-AWQ"


def read(path: str) -> tuple[dict, str]:
    raw = Path(path).read_bytes()
    if not raw or len(raw) > 1_000_000:
        raise ValueError("input original absent or oversized")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("input original is not an object")
    return value, hashlib.sha256(raw).hexdigest()


def selected_container(pod: dict, name: str) -> dict:
    rows = [x for x in pod["status"]["containerStatuses"] if x["name"] == name]
    if (len(rows) != 1 or rows[0].get("ready") is not True
            or type(rows[0].get("restartCount")) is not int
            or rows[0]["restartCount"] < 0):
        raise ValueError("container is not one stable Ready incarnation")
    row = rows[0]
    if not row.get("imageID") or not row.get("containerID"):
        raise ValueError("immutable image or container ID missing")
    return row


def render(inputs: dict[str, dict], context: str, audit_identity: str,
           retained_lease_profile: bytes | None = None, *, legacy_v1: bool = False) -> tuple[bytes, dict]:
    cluster, pod, svc, policy = (inputs[key] for key in ("cluster", "pod", "service", "policy"))
    manager, console, console_deployment, sources = (inputs[key] for key in ("manager", "console", "console_deployment", "sources"))
    if not context or context == "in-cluster" or "__SET_" in context or not audit_identity or "__SET_" in audit_identity:
        raise ValueError("context or public audit identity missing")
    if cluster.get("metadata", {}).get("name") != "kube-system" or not cluster["metadata"].get("uid"):
        raise ValueError("cluster witness is not kube-system")
    if pod.get("metadata", {}).get("namespace") != "vllm" or svc.get("metadata", {}).get("namespace") != "vllm":
        raise ValueError("target or Service namespace drift")
    if policy.get("metadata", {}).get("namespace") != "vllm" or policy["metadata"].get("name") != "vllm-defense":
        raise ValueError("reviewed policy identity drift")
    spec = policy.get("spec", {})
    if spec.get("mode") != "active" or "request-drain" not in spec.get("actions", {}).get("enabled", []):
        raise ValueError("request-drain not active")
    if manager.get("metadata", {}).get("namespace") != "phorvex-system" or console.get("metadata", {}).get("namespace") != "phorvex-system":
        raise ValueError("manager or console namespace drift")
    if console_deployment.get("kind") != "Deployment" or console_deployment.get("metadata", {}).get("namespace") != "phorvex-system" or not console_deployment.get("metadata", {}).get("uid"):
        raise ValueError("console Deployment owner identity unavailable")
    labels = pod["metadata"].get("labels", {})
    annotations = pod["metadata"].get("annotations", {})
    leased = "phorvex.ai/endpoint-lease-source-sha256" in annotations
    base_inputs = {"cluster", "pod", "service", "policy", "manager", "console",
                   "console_deployment", "sources"}
    if not legacy_v1:
        base_inputs |= {"manager_deployment", "manager_replicaset"}
    if leased:
        if retained_lease_profile is None or set(inputs) != base_inputs | {
                "endpointslices", "source", "lease_policy", "console_replicaset"}:
            raise ValueError("leased target needs exact retained caller authority originals")
        guardrail_profile.render({key: inputs[key] for key in guardrail_profile.ROLES +
                                  (guardrail_profile.LEASE_ROLE,)}, context, retained_lease_profile)
        lease_data = guardrail_profile.unique_json(retained_lease_profile)
        if lease_data["auditSourceIdentity"] != audit_identity:
            raise ValueError("retained caller audit identity differs")
    elif retained_lease_profile is not None or set(inputs) != base_inputs:
        raise ValueError("nonleased target cannot retain caller authority")
    selector = svc.get("spec", {}).get("selector", {})
    if svc.get("metadata", {}).get("name") != "vllm" or svc.get("spec", {}).get("ports") != [{"port": 8000, "protocol": "TCP", "targetPort": 8000}]:
        raise ValueError("reviewed public Service route or port drift")
    if labels.get("phorvex.ai/serving") != "true" or not selector or not all(labels.get(k) == v for k, v in selector.items()):
        raise ValueError("Service no longer selects the serving Pod")
    if not all(labels.get(k) == v for k, v in spec.get("selector", {}).get("matchLabels", {}).items()):
        raise ValueError("policy no longer selects the serving Pod")
    if sources != {"serving_completion.py": COMPLETION_SHA, "serving_engine.py": ENGINE_SHA}:
        raise ValueError("installed serving source is not reviewed v11-compatible source")
    for key in ("phorvex.ai/drain-proxy-source", "phorvex.ai/drain-engine-source"):
        if not HEX.fullmatch(annotations.get(key, "")):
            raise ValueError("reviewed derivative source annotation absent")
    vllm, proxy = selected_container(pod, "vllm"), selected_container(pod, "guardrail")
    manager_runtime, console_runtime = selected_container(manager, "manager"), selected_container(console, "console")
    owner_fields = {}
    if not legacy_v1:
        dep, rs = inputs["manager_deployment"], inputs["manager_replicaset"]
        dm, rm = dep.get("metadata", {}), rs.get("metadata", {})
        if (dep.get("kind") != "Deployment" or rs.get("kind") != "ReplicaSet"
                or dm.get("namespace") != "phorvex-system" or rm.get("namespace") != "phorvex-system"
                or not guardrail_profile.UID.fullmatch(dm.get("uid", "")) or not guardrail_profile.UID.fullmatch(rm.get("uid", "")) or dm.get("deletionTimestamp")
                or rm.get("deletionTimestamp")):
            raise ValueError("manager stable owner originals missing")
        def owner(obj, kind, name, uid):
            refs = [x for x in obj["metadata"].get("ownerReferences", []) if x.get("controller") is True]
            return len(refs) == 1 and refs[0].get("kind") == kind and refs[0].get("name") == name and refs[0].get("uid") == uid
        if (not owner(manager, "ReplicaSet", rm["name"], rm["uid"])
                or not owner(rs, "Deployment", dm["name"], dm["uid"])
                or dep.get("spec", {}).get("replicas") != 1
                or dep.get("status", {}).get("observedGeneration") != dm.get("generation")
                or any(dep.get("status", {}).get(k) != 1 for k in
                       ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas"))):
            raise ValueError("manager stable owner is not settled and Ready")
        owner_fields = {"managerDeploymentName": dm["name"], "managerDeploymentUID": dm["uid"]}
    profile = {
        "schema": "live-request-drain-v1" if legacy_v1 else "live-request-drain-v2", "context": context, "clusterUID": cluster["metadata"]["uid"],
        "podName": pod["metadata"]["name"], "podUID": pod["metadata"]["uid"],
        "podImageID": vllm["imageID"], "podContainerID": vllm["containerID"],
        "proxyImageID": proxy["imageID"], "proxyContainerID": proxy["containerID"],
        "serviceName": svc["metadata"]["name"], "serviceUID": svc["metadata"]["uid"], "serviceSelector": selector,
        "policyName": policy["metadata"]["name"], "policyUID": policy["metadata"]["uid"],
        "policyGeneration": policy["metadata"]["generation"],
        "managerPodName": manager["metadata"]["name"], "managerPodUID": manager["metadata"]["uid"],
        "managerImageID": manager_runtime["imageID"], "managerContainerID": manager_runtime["containerID"],
        "consoleDeploymentName": console_deployment["metadata"]["name"],
        "consoleDeploymentUID": console_deployment["metadata"]["uid"],
        "consoleImageID": console_runtime["imageID"],
        "modelID": MODEL, "auditSourceIdentity": audit_identity,
        "servingCompletionSHA256": COMPLETION_SHA, "servingEngineSHA256": ENGINE_SHA,
        "drainProxySourceSHA256": annotations["phorvex.ai/drain-proxy-source"],
        "drainEngineSourceSHA256": annotations["phorvex.ai/drain-engine-source"], "maxRunSeconds": 240,
    }
    if not legacy_v1:
        for key in ("managerPodName", "managerPodUID", "managerImageID", "managerContainerID", "consoleImageID"):
            del profile[key]
        profile.update(owner_fields)
    if leased:
        profile["retainedCallerLeaseProfileSHA256"] = hashlib.sha256(retained_lease_profile).hexdigest()
    raw = (json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n").encode()
    sha = hashlib.sha256(raw).hexdigest()
    journal = hashlib.sha256(("request-drain/" + profile["policyUID"] + "/" + profile["podUID"]).encode()).hexdigest()[:40]
    source = {"catalogueProfiles": {"drainLive": {"enabled": True,
        "configMapName": "phorvex-catalogue-drain-live-" + sha[:12],
        "profileBase64": base64.b64encode(raw).decode()}},
        "phorvex": {"phorvex": {"console": {"drainLive": {"enabled": False,
            "configMapName": "phorvex-catalogue-drain-live-" + sha[:12],
            "profileSHA256": sha, "journalName": "phorvex-operation-" + journal}}}}}
    return raw, source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cluster", "pod", "service", "policy", "manager", "console", "console-deployment", "sources", "context", "audit-source-identity", "out"):
        parser.add_argument("--" + name, required=True)
    for name in ("endpointslices", "source", "lease-policy", "console-replicaset", "retained-caller-lease-profile", "retained-caller-lease-profile-sha256"):
        parser.add_argument("--" + name)
    parser.add_argument("--legacy-v1", action="store_true", help="explicit historical exact-incarnation schema")
    parser.add_argument("--manager-deployment")
    parser.add_argument("--manager-replicaset")
    args = parser.parse_args()
    inputs, hashes = {}, {}
    for name in ("cluster", "pod", "service", "policy", "manager", "console", "console_deployment", "sources"):
        inputs[name], hashes[name] = read(getattr(args, name))
    if not args.legacy_v1:
        if not args.manager_deployment or not args.manager_replicaset:
            raise ValueError("v2 needs stable manager Deployment and ReplicaSet originals")
        for name in ("manager_deployment", "manager_replicaset"):
            inputs[name], hashes[name] = read(getattr(args,name))
    retained = None
    optional = ("endpointslices", "source", "lease_policy", "console_replicaset")
    if any(getattr(args, name) is not None for name in optional) or args.retained_caller_lease_profile is not None or args.retained_caller_lease_profile_sha256 is not None:
        if not all(getattr(args, name) is not None for name in optional) or not args.retained_caller_lease_profile or not HEX.fullmatch(args.retained_caller_lease_profile_sha256 or ""):
            raise ValueError("retained caller originals or profile pin incomplete")
        for name in optional:
            inputs[name], hashes[name] = read(getattr(args, name))
        retained = guardrail_profile.read_regular_bounded(Path(args.retained_caller_lease_profile), 8192)
        if hashlib.sha256(retained).hexdigest() != args.retained_caller_lease_profile_sha256:
            raise ValueError("retained caller lease profile byte/hash drift")
        hashes["retained_caller_lease_profile"] = args.retained_caller_lease_profile_sha256
    raw, values = render(inputs, args.context, args.audit_source_identity, retained, legacy_v1=args.legacy_v1)
    output = Path(args.out)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, 0o700)
    files = {"profile.json": raw, "values-candidate.json": (json.dumps(values, sort_keys=True, indent=2) + "\n").encode(),
             "inputs-sha256.json": (json.dumps(hashes, sort_keys=True, indent=2) + "\n").encode()}
    for name, content in files.items():
        fd = os.open(output / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    print(json.dumps({"profileSHA256": hashlib.sha256(raw).hexdigest(), "files": sorted(files)}))


if __name__ == "__main__":
    main()
