"""Check whether the published source-free Python image can run the LiteLLM gateway.

This is a source/recipe check. The manual workflow also runs the actual
published image by digest with the merged gateway mounted read-only.
"""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def verify():
    contract = json.loads((HERE / "image-contract.json").read_text())
    if set(contract) != {
        "schema", "imageByDigest", "publishedImageSourceCommit", "publishedRunID",
        "publishedReceiptSHA256", "dockerfileSHA256", "baseImage", "platform",
        "python", "user", "gatewaySourceSHA256", "gatewayCommand",
        "gatewaySourcePath", "legacyGatewaySourceSHA256", "publishedReceiptPath",
        "actualImageReceiptPath", "actualImageReceiptSHA256",
    } or contract["schema"] != "phorvex-litellm-gateway-image-reuse-v3":
        raise ValueError("gateway image reuse contract differs")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", contract["imageByDigest"]):
        raise ValueError("published image is not an immutable digest reference")
    for field in ("publishedReceiptSHA256", "dockerfileSHA256", "gatewaySourceSHA256", "actualImageReceiptSHA256"):
        if not re.fullmatch(r"[0-9a-f]{64}", contract[field]):
            raise ValueError(field + " is not SHA-256")
    receipt_path = ROOT / contract["publishedReceiptPath"]
    if contract["publishedReceiptPath"] != "build/integrations/litellm-gateway-runtime/runtime-publication.json":
        raise ValueError("publication receipt path differs")
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    if (hashlib.sha256(receipt_raw).hexdigest() != contract["publishedReceiptSHA256"] or
            receipt.get("schema") != "phorvex-litellm-gateway-runtime-publication-v1" or
            receipt.get("imageByDigest") != contract["imageByDigest"] or
            receipt.get("sourceCommit") != contract["publishedImageSourceCommit"] or
            receipt.get("dockerfileSHA256") != contract["dockerfileSHA256"] or
            receipt.get("applicationSourceIncluded") is not False or
            receipt.get("platform") != "linux/amd64" or receipt.get("user") != "10001:10001" or
            receipt.get("githubRunID") is not None or contract["publishedRunID"] is not None):
        raise ValueError("actual isolated publication provenance differs")
    if contract["actualImageReceiptPath"] != "build/integrations/litellm-gateway-runtime/actual-image-receipt.json":
        raise ValueError("actual-image receipt path differs")
    actual_raw = (ROOT / contract["actualImageReceiptPath"]).read_bytes()
    actual = json.loads(actual_raw)
    if (hashlib.sha256(actual_raw).hexdigest() != contract["actualImageReceiptSHA256"] or
            actual.get("schema") != "phorvex-litellm-gateway-runtime-reuse-receipt-v1" or
            actual.get("result") != "pass-local-and-published-image-protocol" or
            actual.get("imageByDigest") != contract["imageByDigest"] or
            actual.get("sourceCommit") != contract["publishedImageSourceCommit"] or
            actual.get("gatewaySourceSHA256") != contract["gatewaySourceSHA256"] or
            actual.get("legacyGatewaySourceSHA256") != contract["legacyGatewaySourceSHA256"] or
            actual.get("publicationReceiptSHA256") != contract["publishedReceiptSHA256"] or
            actual.get("platform") != contract["platform"] or actual.get("user") != contract["user"]):
        raise ValueError("actual published image old/new protocol evidence differs")
    if contract["gatewaySourcePath"] != "build/test-harness/fixtures/litellm-live/gateway_metrics.py":
        raise ValueError("candidate path differs")
    legacy = (ROOT / "build/test-harness/fixtures/litellm-live/gateway.py").read_bytes()
    active_contract = (ROOT / "phorvex/internal/litellmclient/contract.go").read_text()
    active_sha = re.search(r'ApprovedSourceSHA256\s*=\s*"([0-9a-f]{64})"', active_contract)
    if (active_sha is None or hashlib.sha256(legacy).hexdigest() != active_sha[1] or
            active_sha[1] != contract["legacyGatewaySourceSHA256"]):
        raise ValueError("preserved legacy source or engine approval differs")
    metrics_sha = re.search(r'MetricsSourceSHA256\s*=\s*"([0-9a-f]{64})"', active_contract)
    runtime_image = re.search(r'ApprovedRuntimeImage\s*=\s*"([^"\n]+)"', active_contract)
    if (metrics_sha is None or metrics_sha[1] != contract["gatewaySourceSHA256"] or
            runtime_image is None or runtime_image[1] != contract["imageByDigest"]):
        raise ValueError("compatible engine source/runtime approval differs")
    source = (ROOT / contract["gatewaySourcePath"]).read_bytes()
    if hashlib.sha256(source).hexdigest() != contract["gatewaySourceSHA256"]:
        raise ValueError("merged gateway source moved without a new image/source review")
    workflow = (ROOT / ".github/workflows/verify-litellm-gateway-runtime.yml").read_text()
    if "runs-on: [self-hosted, linux, x64, phorvex-isolated-aws]" not in workflow:
        raise ValueError("actual-image verification requires the isolated AWS executor")
    for key, value in (("IMAGE", contract["imageByDigest"]),
                       ("EXPECTED_SOURCE_SHA", contract["gatewaySourceSHA256"])):
        matches = re.findall(r"^      " + key + r": (\S+)$", workflow, re.MULTILINE)
        if matches != [value]:
            raise ValueError("runtime verification workflow differs from candidate contract: " + key)
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.partition(".")[0])
    if not imported <= sys.stdlib_module_names | {"__future__"}:
        raise ValueError("gateway now requires a dependency absent from the base proof: " +
                         ",".join(sorted(imported - sys.stdlib_module_names - {"__future__"})))
    dockerfile = (ROOT / "build/integrations/vllm-lease-proxy-runtime/Dockerfile").read_bytes()
    if hashlib.sha256(dockerfile).hexdigest() != contract["dockerfileSHA256"]:
        raise ValueError("published image recipe Dockerfile changed")
    docker_text = dockerfile.decode()
    if (not docker_text.startswith("FROM --platform=linux/amd64 " + contract["baseImage"] + "\n") or
            "\nUSER 10001:10001\n" not in docker_text or
            "COPY gateway.py" in docker_text or
            contract["gatewayCommand"] != ["python3", "-B", "/opt/phorvex/gateway.py"] or
            contract["platform"] != "linux/amd64" or contract["python"] != "3.11" or
            contract["user"] != "10001:10001"):
        raise ValueError("published source-free image or sidecar command contract differs")
    renderer = (ROOT / "build/test-harness/fixtures/litellm-live/render.py").read_text()
    if '"command": ["python3", "-B", "/opt/phorvex/gateway.py"]' not in renderer:
        raise ValueError("owner renderer no longer overrides the proxy image CMD")
    print("LiteLLM gateway image/source reuse contract PASS")


if __name__ == "__main__":
    verify()
