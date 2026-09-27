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
    } or contract["schema"] != "phorvex-litellm-gateway-image-reuse-v1":
        raise ValueError("gateway image reuse contract differs")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", contract["imageByDigest"]):
        raise ValueError("published image is not an immutable digest reference")
    for field in ("publishedReceiptSHA256", "dockerfileSHA256", "gatewaySourceSHA256"):
        if not re.fullmatch(r"[0-9a-f]{64}", contract[field]):
            raise ValueError(field + " is not SHA-256")
    source = (ROOT / "build/test-harness/fixtures/litellm-live/gateway.py").read_bytes()
    if hashlib.sha256(source).hexdigest() != contract["gatewaySourceSHA256"]:
        raise ValueError("merged gateway source moved without a new image/source review")
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
