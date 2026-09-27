"""Read exact vLLM originals and prepare a review-only drain-v11 candidate.

No Secret reads, Pod exec, registry requests, or Kubernetes writes occur here.
The reviewed renderer owns candidate semantics; this program only obtains and
pins fresh originals, validates their one-Pod owner/Service chain, then calls it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import render as drain_render


PUBLISHED_RECEIPT_SHA256 = "7061940333a1f3924458125a66721f7729ccdd9671af1d2a865c612f763cc40e"
PUBLISHED_SOURCE = "b8cc2e74507b3d26e2c7250269b26c5e040d1873"
PUBLISHED_IMAGE = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:3534dec6b97c1b6e4042b3cb2987c6cf8c4d4e4167a833320e2f1b7f4135d050"
MODEL_REVISION = "b25037543e9394b818fdfca67ab2a00ecc7dd641"
MODEL_CONFIG_SHA256 = "ec0c1f5f875ad8bc1f78c5140c22dbdde1b55478442ad358e7a4d9ecf947a327"
CONTEXT = re.compile(r"[^\x00-\x1f\x7f]{1,256}\Z")
MAX_GET_BYTES = 4 << 20


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def exact_object(obj: dict, kind: str, name: str, namespace: str | None) -> dict:
    meta = obj.get("metadata", {}) if isinstance(obj, dict) else {}
    if (obj.get("kind") != kind or meta.get("name") != name or
            (namespace is not None and meta.get("namespace") != namespace) or
            not isinstance(meta.get("uid"), str) or not meta["uid"] or
            not isinstance(meta.get("resourceVersion"), str) or not meta["resourceVersion"] or
            meta.get("deletionTimestamp")):
        raise ValueError(kind + " exact live identity unavailable")
    return meta


def controller_ref(obj: dict, kind: str, name: str, uid: str) -> None:
    refs = obj.get("metadata", {}).get("ownerReferences", [])
    owners = [ref for ref in refs if ref.get("controller") is True]
    if len(owners) != 1 or owners[0].get("kind") != kind or owners[0].get("name") != name or owners[0].get("uid") != uid:
        raise ValueError("current controller owner chain differs")


def selector_from(deployment: dict) -> str:
    selector = deployment.get("spec", {}).get("selector", {})
    labels = selector.get("matchLabels", {})
    if (not isinstance(labels, dict) or not labels or selector.get("matchExpressions") or
            any(not isinstance(k, str) or not isinstance(v, str) or not k or not v or
                any(ch in k + v for ch in ",=\n\r") for k, v in labels.items())):
        raise ValueError("Deployment exact matchLabels selector required")
    return ",".join(k + "=" + labels[k] for k in sorted(labels))


def select_current(deployment: dict, service: dict, pods: dict, rs: dict, slices: dict) -> dict:
    items = pods.get("items") if isinstance(pods, dict) and pods.get("kind") in ("PodList", "List") else None
    if not isinstance(items, list) or len(items) != 1:
        raise ValueError("one current selected Pod required")
    pod = items[0]
    pod_meta = pod.get("metadata", {})
    exact_object(pod, "Pod", pod_meta.get("name"), "vllm")
    rs_meta = rs.get("metadata", {})
    exact_object(rs, "ReplicaSet", rs_meta.get("name"), "vllm")
    controller_ref(pod, "ReplicaSet", rs_meta["name"], rs_meta["uid"])
    controller_ref(rs, "Deployment", "vllm", deployment["metadata"]["uid"])
    if (pod.get("status", {}).get("phase") != "Running" or
            not any(row.get("type") == "Ready" and row.get("status") == "True"
                    for row in pod.get("status", {}).get("conditions", []))):
        raise ValueError("current owned Pod is not Ready")
    selector = service.get("spec", {}).get("selector", {})
    if not isinstance(selector, dict) or not selector or any(pod_meta.get("labels", {}).get(k) != v for k, v in selector.items()):
        raise ValueError("current Service does not select owned Pod")
    if slices.get("kind") not in ("List", "EndpointSliceList") or not isinstance(slices.get("items"), list) or not slices["items"]:
        raise ValueError("current EndpointSlice list unavailable")
    ready = []
    for item in slices["items"]:
        meta = item.get("metadata", {})
        exact_object(item, "EndpointSlice", meta.get("name"), "vllm")
        controller_ref(item, "Service", "vllm", service["metadata"]["uid"])
        if meta.get("labels", {}).get("kubernetes.io/service-name") != "vllm":
            raise ValueError("foreign EndpointSlice in current route")
        ready.extend(row.get("targetRef", {}) for row in item.get("endpoints", [])
                     if row.get("conditions", {}).get("ready") is True)
    if len(ready) != 1 or any(ready[0].get(k) != v for k, v in
                              {"kind": "Pod", "namespace": "vllm", "name": pod_meta["name"], "uid": pod_meta["uid"]}.items()):
        raise ValueError("current Service lacks one Ready owned Pod target")
    return pod


def run_get(context: str, namespace: str | None, resource: str, name: str | None = None,
            selector: str | None = None, kubectl: str = "kubectl") -> tuple[dict, bytes]:
    argv = [kubectl, "--context", context]
    if namespace:
        argv += ["-n", namespace]
    argv += ["get", resource]
    if name:
        argv.append(name)
    if selector:
        argv += ["-l", selector]
    argv += ["-o", "json"]
    result = subprocess.run(argv, check=False, capture_output=True, timeout=20)
    if result.returncode != 0 or not result.stdout or len(result.stdout) > MAX_GET_BYTES:
        raise ValueError("bounded kubectl GET failed for " + resource)
    try:
        parsed = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("kubectl GET returned invalid JSON for " + resource) from exc
    if not isinstance(parsed, dict):
        raise ValueError("kubectl GET returned non-object for " + resource)
    return parsed, result.stdout


def _unique_pairs(rows: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in rows:
        if key in value:
            raise ValueError("duplicate Kubernetes JSON key")
        value[key] = item
    return value


def publication(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    if sha(raw) != PUBLISHED_RECEIPT_SHA256 or len(raw) > 1 << 20:
        raise ValueError("reviewed publication artifact SHA-256 differs")
    data = json.loads(raw, object_pairs_hook=_unique_pairs)
    image, _ = drain_render.published_image(data)
    if data.get("sourceSHA") != PUBLISHED_SOURCE or image != PUBLISHED_IMAGE:
        raise ValueError("reviewed publication source or image differs")
    return data, raw


def write_private(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(context: str, out: Path, publication_path: Path, kubectl: str = "kubectl") -> dict:
    if not CONTEXT.fullmatch(context) or context.startswith("-"):
        raise ValueError("explicit Kubernetes context required")
    if out.exists() or out.is_symlink():
        raise FileExistsError("private output directory already exists")
    published, published_raw = publication(publication_path)
    originals: dict[str, tuple[dict, bytes]] = {}
    def capture(label: str, namespace: str | None, resource: str, name: str | None = None,
                selector: str | None = None) -> dict:
        value = run_get(context, namespace, resource, name, selector, kubectl)
        originals[label] = value
        return value[0]
    namespace = capture("namespace", None, "namespace", "vllm")
    exact_object(namespace, "Namespace", "vllm", None)
    deployment = capture("deployment", "vllm", "deployment", "vllm")
    exact_object(deployment, "Deployment", "vllm", "vllm")
    cm = capture("configmap", "vllm", "configmap", "guardrail-proxy")
    exact_object(cm, "ConfigMap", "guardrail-proxy", "vllm")
    policy = capture("policy", "vllm", "phorvexpolicy", "vllm-defense")
    exact_object(policy, "PhorvexPolicy", "vllm-defense", "vllm")
    service = capture("service", "vllm", "service", "vllm")
    exact_object(service, "Service", "vllm", "vllm")
    pods = capture("pod-list", "vllm", "pods", selector=selector_from(deployment))
    if not isinstance(pods.get("items"), list) or len(pods["items"]) != 1:
        raise ValueError("one current selected Pod required")
    pod_name = pods["items"][0].get("metadata", {}).get("name")
    if not isinstance(pod_name, str) or not pod_name:
        raise ValueError("current Pod name absent")
    pod = capture("current-pod", "vllm", "pod", pod_name)
    if pods["items"][0].get("metadata", {}).get("uid") != pod.get("metadata", {}).get("uid"):
        raise ValueError("current Pod changed between list and exact read")
    rs_refs = [row for row in pod.get("metadata", {}).get("ownerReferences", []) if row.get("controller") is True]
    if len(rs_refs) != 1 or rs_refs[0].get("kind") != "ReplicaSet" or not rs_refs[0].get("name"):
        raise ValueError("current Pod ReplicaSet owner absent")
    rs = capture("current-replicaset", "vllm", "replicaset", rs_refs[0]["name"])
    slices = capture("current-endpointslices", "vllm", "endpointslices", selector="kubernetes.io/service-name=vllm")
    current = select_current(deployment, service, {"kind": "PodList", "items": [pod]}, rs, slices)
    for label, resource, name in (("deployment", "deployment", "vllm"),
                                  ("configmap", "configmap", "guardrail-proxy"),
                                  ("policy", "phorvexpolicy", "vllm-defense"),
                                  ("service", "service", "vllm")):
        reread, _ = run_get(context, "vllm", resource, name, kubectl=kubectl)
        before = originals[label][0]["metadata"]
        after = reread.get("metadata", {})
        if before.get("uid") != after.get("uid") or before.get("resourceVersion") != after.get("resourceVersion"):
            raise ValueError(label + " changed during read-only snapshot")
    candidates = drain_render.render(deployment, cm, policy, service, published,
                                     "vllm-control", "vllm-serving-admin", "vllm-admin.vllm.svc",
                                     MODEL_REVISION, MODEL_CONFIG_SHA256,
                                     (current, rs, slices))
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = {"status": "REVIEW_ONLY", "context": context,
                "publicationReceiptSHA256": sha(published_raw), "publicationSource": PUBLISHED_SOURCE,
                "originals": {}, "candidates": {},
                "claim": "read-only snapshot and candidate; no installed source or defense result"}
    for label, (obj, raw) in originals.items():
        filename = "original-" + label + ".json"
        write_private(out / filename, raw)
        manifest["originals"][label] = {"file": filename, "sha256": sha(raw),
                                        "uid": obj.get("metadata", {}).get("uid"),
                                        "resourceVersion": obj.get("metadata", {}).get("resourceVersion")}
    write_private(out / "publication.json", published_raw)
    for name, raw in candidates.items():
        write_private(out / name, raw)
        manifest["candidates"][name] = sha(raw)
    write_private(out / "prepare-manifest.json", canonical(manifest) + b"\n")
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--context", required=True)
    p.add_argument("--publication", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    result = prepare(args.context, args.out, args.publication)
    print(json.dumps({"status": result["status"], "out": str(args.out),
                      "originalCount": len(result["originals"]),
                      "candidateCount": len(result["candidates"]),
                      "clusterWrites": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
