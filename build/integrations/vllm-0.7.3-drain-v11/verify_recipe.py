#!/usr/bin/env python3
"""Verify that the derivative recipe is bound to one observed base manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def verify_raw_registry(receipt, manifest_path: Path, config_path: Path) -> None:
    observed_manifest = load_json(manifest_path)
    observed_config = load_json(config_path)
    manifest = receipt["manifest"]
    config = receipt["config"]

    require(observed_manifest.get("status") == 200, "registry manifest response was not HTTP 200")
    require(observed_manifest.get("content_type") == manifest["media_type"], "registry manifest media type mismatch")
    require(observed_manifest.get("docker_content_digest") == manifest["digest"], "registry manifest response digest mismatch")
    require(observed_manifest.get("body_sha256") == manifest["body_sha256"], "registry manifest body hash mismatch")
    body = observed_manifest.get("body", {})
    require(body.get("mediaType") == MANIFEST_MEDIA_TYPE, "registry manifest body media type mismatch")
    require(body.get("config", {}).get("mediaType") == CONFIG_MEDIA_TYPE, "registry config descriptor media type mismatch")
    require(body.get("config", {}).get("digest") == manifest["config_digest"], "registry config descriptor digest mismatch")

    require(observed_config.get("status") == 200, "registry config response was not HTTP 200")
    require(observed_config.get("digest") == config["digest"], "registry config request digest mismatch")
    require(observed_config.get("body_sha256") == config["body_sha256"], "registry config body hash mismatch")
    config_body = observed_config.get("body", {})
    require(config_body.get("os") == config["os"], "registry config operating system mismatch")
    require(config_body.get("architecture") == config["architecture"], "registry config architecture mismatch")


def verify(recipe_dir: Path, registry_manifest: Path | None = None, registry_config: Path | None = None):
    manifest = load_json(recipe_dir / "manifest.json")
    receipt = load_json(recipe_dir / "base-image-receipt.json")
    dockerfile = (recipe_dir / "Dockerfile").read_text()

    require(receipt.get("schema_version") == 1, "unsupported base-image receipt schema")
    image_reference = f'{receipt["repository"]}:{receipt["tag"]}'
    digest = receipt["manifest"]["digest"]
    require(receipt["manifest"]["status"] == 200, "base manifest receipt was not HTTP 200")
    require(receipt["manifest"]["media_type"] == MANIFEST_MEDIA_TYPE, "base manifest is not a single-platform Docker v2 manifest")
    require(digest == "sha256:" + receipt["manifest"]["body_sha256"], "manifest digest is not its retained body hash")
    require(receipt["manifest"]["config_digest"] == receipt["config"]["digest"], "manifest/config digest link mismatch")
    require(receipt["config"]["status"] == 200, "base config receipt was not HTTP 200")
    require(receipt["config"]["digest"] == "sha256:" + receipt["config"]["body_sha256"], "config digest is not its retained body hash")
    platform = f'{receipt["config"]["os"]}/{receipt["config"]["architecture"]}'
    require(platform == "linux/amd64", f"unsupported base platform {platform!r}")

    base = manifest.get("base_image", {})
    require(base.get("reference") == image_reference, "manifest base reference does not match registry receipt")
    require(base.get("digest") == digest, "manifest base digest does not match registry receipt")
    require(base.get("platform") == platform, "manifest base platform does not match registry config")

    first = next((line.strip() for line in dockerfile.splitlines() if line.strip()), "")
    require(first == f"FROM {image_reference}@{digest}", "Dockerfile FROM does not match manifest and registry receipt")
    base_name = re.search(r'org\.opencontainers\.image\.base\.name="([^"]+)"', dockerfile)
    base_digest = re.search(r'org\.opencontainers\.image\.base\.digest="([^"]+)"', dockerfile)
    require(base_name is not None and base_name.group(1) == image_reference, "Dockerfile base.name label mismatch")
    require(base_digest is not None and base_digest.group(1) == digest, "Dockerfile base.digest label mismatch")

    require((registry_manifest is None) == (registry_config is None), "supply both raw registry receipts or neither")
    if registry_manifest is not None:
        verify_raw_registry(receipt, registry_manifest, registry_config)

    return {
        "base": f"{image_reference}@{digest}",
        "manifestBodySHA256": receipt["manifest"]["body_sha256"],
        "configBodySHA256": receipt["config"]["body_sha256"],
        "platform": platform,
        "rawRegistryEvidence": registry_manifest is not None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipe-dir", type=Path, default=HERE)
    parser.add_argument("--registry-manifest", type=Path)
    parser.add_argument("--registry-config", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.recipe_dir.resolve(), args.registry_manifest, args.registry_config), sort_keys=True))


if __name__ == "__main__":
    main()
