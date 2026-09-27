"""Render a review-only drain-v11 rollout from exact source and publication receipts.

No Kubernetes or registry calls occur. The workload owner must review and apply
these manifests in the documented order after a normal source-pinned publish.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE_RENDER_PATH = ROOT / "integrations" / "vllm-live-runtime" / "render.py"
GUARDRAIL = ROOT / "test-harness" / "guardrail"
RECIPE = ROOT / "integrations" / "vllm-0.7.3-drain-v11"
RECIPE_FILES = (
    "Dockerfile", "manifest.json", "base-image-receipt.json",
    "verify_recipe.py", "vllm-0.7.3-drain-v11.patch", "apply_patch.py",
    "test_contract.py", "test_drain_contract.py",
)
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"753556437180\.dkr\.ecr\.us-east-2\.amazonaws\.com/phorvex@sha256:[0-9a-f]{64}\Z")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def base_renderer():
    spec = importlib.util.spec_from_file_location("vllm_reset_review_renderer", BASE_RENDER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("reset rollout renderer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def published_image(receipt: dict) -> tuple[str, str]:
    """Validate the normal CI artifact against every byte used by its recipe."""
    if receipt.get("schemaVersion") != 1 or not COMMIT.fullmatch(receipt.get("sourceSHA", "")):
        raise ValueError("publication source authority invalid")
    source = receipt["sourceSHA"]
    image = receipt.get("image")
    digest = receipt.get("digest")
    by_digest = receipt.get("imageByDigest")
    if (image != f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-drain-v11-{source}"
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or by_digest != image.split(":vllm-drain-v11-", 1)[0] + "@" + digest
            or not IMAGE.fullmatch(by_digest) or receipt.get("platform") != "linux/amd64"):
        raise ValueError("publication image identity invalid")
    manifest = json.loads((RECIPE / "manifest.json").read_bytes())
    if receipt.get("baseImage") != manifest["base_image"]:
        raise ValueError("published base image differs from exact recipe")
    hashes = receipt.get("recipeSHA256")
    if not isinstance(hashes, dict) or set(hashes) != set(RECIPE_FILES):
        raise ValueError("published recipe file set differs")
    for name in RECIPE_FILES:
        if hashes[name] != sha((RECIPE / name).read_bytes()):
            raise ValueError("published recipe bytes differ: " + name)
    return by_digest, manifest["patch_sha256"]


def env_value(container: dict, name: str, value: str):
    rows = container.setdefault("env", [])
    if sum(row.get("name") == name for row in rows) > 1:
        raise ValueError("duplicate environment authority: " + name)
    rows[:] = [row for row in rows if row.get("name") != name]
    rows.append({"name": name, "value": value})


def env_pod_uid(container: dict):
    rows = container.setdefault("env", [])
    if any(row.get("name") == "POD_UID" for row in rows):
        raise ValueError("Pod UID environment authority already present")
    rows.append({"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}})


def render(deployment: dict, configmap: dict, policy: dict, service: dict,
           publication: dict, workload_secret: str, operator_secret: str,
           server_name: str, model_revision: str, model_config_sha256: str) -> dict[str, bytes]:
    if not COMMIT.fullmatch(model_revision) or not HEX.fullmatch(model_config_sha256):
        raise ValueError("reviewed model snapshot revision and config hash required")
    for label, obj in (("Deployment", deployment), ("ConfigMap", configmap),
                       ("policy", policy), ("Service", service)):
        meta = obj.get("metadata", {})
        if not meta.get("uid") or not meta.get("resourceVersion") or meta.get("deletionTimestamp"):
            raise ValueError(label + " original UID/resourceVersion authority unavailable")
    published, engine_source = published_image(publication)
    reset = base_renderer()
    # Reuse the exact original workload/source/policy gates of the reviewed
    # reset-only candidate. No reset-only image is emitted from this renderer.
    base = reset.render(deployment, configmap, policy, reset.PUBLISHED_IMAGE,
                        workload_secret, operator_secret, server_name)
    dep = json.loads(base["deployment.candidate.json"])
    cm = json.loads(base["configmap.candidate.json"])
    svc = copy.deepcopy(service)
    if (svc.get("kind") != "Service" or svc.get("metadata", {}).get("namespace") != "vllm"
            or svc["metadata"].get("name") != "vllm" or not svc["metadata"].get("uid")
            or not any(p.get("port") == 8000 and p.get("targetPort") == 8000
                       for p in svc["spec"].get("ports", []))):
        raise ValueError("existing vLLM Service identity, selector or serving route differs")
    original_selector = copy.deepcopy(svc["spec"].get("selector"))
    original_labels = deployment["spec"]["template"]["metadata"].get("labels", {})
    if (not isinstance(original_selector, dict) or not original_selector
            or any(original_labels.get(key) != value for key, value in original_selector.items())
            or "phorvex.ai/serving" in original_selector):
        raise ValueError("existing Service does not uniquely select the reviewed Pod labels")
    for field in ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"):
        svc["metadata"].pop(field, None)
    svc.pop("status", None)
    svc["spec"]["selector"]["phorvex.ai/serving"] = "true"

    spec = dep["spec"]["template"]["spec"]
    if spec.get("initContainers") or any(v.get("name") == "phorvex-drain-ledger" for v in spec.get("volumes", [])):
        raise ValueError("unreviewed drain initializer or ledger already present")
    containers = {c["name"]: c for c in spec["containers"]}
    engine, guard = containers["vllm"], containers["guardrail"]
    if engine["image"] != reset.PUBLISHED_IMAGE:
        raise ValueError("reset candidate engine identity changed")
    args = engine.get("args", [])
    if (args.count("--model") != 1 or args[args.index("--model") + 1] != "Qwen/Qwen2.5-7B-Instruct-AWQ"
            or "--revision" in args or "--tokenizer-revision" in args):
        raise ValueError("reviewed model identity or revision arguments differ")
    engine["args"] = args + ["--revision", model_revision,
                             "--tokenizer-revision", model_revision]
    model_digest = sha(json.dumps({"model": "Qwen/Qwen2.5-7B-Instruct-AWQ",
                                  "revision": model_revision,
                                  "configSHA256": model_config_sha256},
                                 sort_keys=True, separators=(",", ":")).encode())
    engine["image"] = published
    env_value(engine, "PHORVEX_DRAIN_V11", "1")
    env_value(guard, "PHORVEX_DRAIN_V11", "1")
    env_pod_uid(guard)
    proxy_source = sha((GUARDRAIL / "guardrail_proxy.py").read_bytes())
    env_value(guard, "PHORVEX_PROXY_SOURCE", proxy_source)
    env_value(guard, "PHORVEX_ENGINE_SOURCE", engine_source)
    env_value(guard, "PHORVEX_MODEL_DIGEST", model_digest)
    env_value(guard, "PHORVEX_DRAIN_LEDGER_DIR", "/var/lib/phorvex-drain")
    guard.setdefault("volumeMounts", []).append({"name": "phorvex-drain-ledger", "mountPath": "/var/lib/phorvex-drain"})
    spec.setdefault("volumes", []).append({"name": "phorvex-drain-ledger", "emptyDir": {}})
    spec["initContainers"] = [{
        "name": "phorvex-drain-ledger-init", "image": guard["image"],
        "command": ["python", "/src/drain_v11_init.py"],
        "env": [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                {"name": "PHORVEX_DRAIN_LEDGER_DIR", "value": "/var/lib/phorvex-drain"}],
        "volumeMounts": [{"name": "guardrail-src", "mountPath": "/src", "readOnly": True},
                         {"name": "phorvex-drain-ledger", "mountPath": "/var/lib/phorvex-drain"}],
    }]
    labels = dep["spec"]["template"]["metadata"].setdefault("labels", {})
    labels["phorvex.ai/serving"] = "true"
    annotations = dep["spec"]["template"]["metadata"].setdefault("annotations", {})
    annotations["phorvex.ai/route-service"] = "vllm"
    annotations["phorvex.ai/drain-proxy-source"] = proxy_source
    annotations["phorvex.ai/drain-engine-source"] = engine_source
    cm["data"]["drain_v11.py"] = (GUARDRAIL / "drain_v11.py").read_text()
    cm["data"]["drain_v11_init.py"] = (GUARDRAIL / "drain_v11_init.py").read_text()
    values = json.loads(base["values.overlay.yaml"])
    values["phorvex"]["phorvex"]["servingSecurity"]["bindings"][0]["profileID"] = "vllm-drain-v11"
    result = {
        "deployment.candidate.json": json.dumps(dep, sort_keys=True, separators=(",", ":")).encode(),
        "configmap.candidate.json": json.dumps(cm, sort_keys=True, separators=(",", ":")).encode(),
        "service.candidate.json": json.dumps(svc, sort_keys=True, separators=(",", ":")).encode(),
        "values.overlay.yaml": json.dumps(values, sort_keys=True, indent=2).encode() + b"\n",
        "secret-contract.json": base["secret-contract.json"],
        "publication-join.json": json.dumps({
            "sourceCommit": publication["sourceSHA"], "publishedImage": published,
            "enginePatchSHA256": engine_source, "proxySourceSHA256": proxy_source,
            "modelIdentitySHA256": model_digest, "modelRevision": model_revision,
            "modelConfigSHA256": model_config_sha256,
            "publicationProjectionSHA256": sha(json.dumps(publication, sort_keys=True, separators=(",", ":")).encode()),
            "originalDeploymentUID": deployment["metadata"].get("uid"),
            "originalConfigMapUID": configmap["metadata"].get("uid"),
            "originalPolicyUID": policy["metadata"].get("uid"),
            "originalServiceUID": service["metadata"]["uid"],
            "originalServiceSelector": original_selector,
            "claim": "review-only; no installed source or operation proof",
        }, sort_keys=True, indent=2).encode() + b"\n",
    }
    return result


def main():
    p = argparse.ArgumentParser()
    for name in ("deployment", "deployment-sha256", "configmap", "configmap-sha256",
                 "policy", "policy-sha256", "service", "service-sha256",
                 "publication", "publication-sha256", "workload-secret", "operator-secret",
                 "server-name", "model-revision", "model-config-sha256", "out"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    reset = base_renderer()
    originals = [reset.read_exact(Path(path), expected) for path, expected in (
        (a.deployment, a.deployment_sha256), (a.configmap, a.configmap_sha256),
        (a.policy, a.policy_sha256), (a.service, a.service_sha256),
        (a.publication, a.publication_sha256))]
    result = render(*originals, a.workload_secret, a.operator_secret,
                    a.server_name, a.model_revision, a.model_config_sha256)
    out = Path(a.out)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(out, 0o700)
    hashes = {}
    for name, raw in result.items():
        with (out / name).open("xb") as stream:
            os.chmod(out / name, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = sha(raw)
    print(json.dumps({"status": "REVIEW_ONLY", "filesSHA256": hashes,
                      "secretBytesStored": False}, sort_keys=True))


if __name__ == "__main__":
    main()
