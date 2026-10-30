#!/usr/bin/env python3
"""Fail-closed ECR version-tag gate for one persisted service release batch."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
EXPECTED_COMPONENTS = {"manager", "brain", "sensor", "actuator", "console", "attacks"}
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_batch(path: Path) -> dict[str, Any]:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"{current}: symlinks are not permitted")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise SystemExit(f"{current}: hard-linked release files are not permitted")
    before = absolute.lstat()
    descriptor = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != (before.st_dev, before.st_ino, 1):
            raise SystemExit(f"{path}: identity changed before read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    after = absolute.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    ):
        raise SystemExit(f"{path}: identity changed during read")
    try:
        batch = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"{path}: {error}") from error
    if batch.get("schema") != 2 or not SHA.fullmatch(batch.get("source", "")):
        raise SystemExit(f"{path}: not a schema-v2 batch with an exact source SHA")
    if not isinstance(batch.get("components"), list) or not isinstance(batch.get("releases"), dict):
        raise SystemExit(f"{path}: incomplete component/release objects")
    names = [item.get("component") for item in batch["components"] if isinstance(item, dict)]
    if len(names) != len(batch["components"]) or len(names) != len(set(names)) or set(names) != EXPECTED_COMPONENTS:
        raise SystemExit(f"{path}: batch must contain one exact contract for all six release components")
    return batch


def run(command: list[str], runner: Runner = subprocess.run) -> subprocess.CompletedProcess[str]:
    return runner(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def aws_json(arguments: list[str], runner: Runner = subprocess.run) -> dict[str, Any]:
    result = run(["aws", *arguments, "--output", "json"], runner)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"aws {' '.join(arguments)} failed")
    try:
        return json.loads(result.stdout, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"aws {' '.join(arguments)} returned malformed JSON: {error}") from error


def component_contract(batch: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in batch["components"] if item.get("component") == name]
    if len(matches) != 1:
        raise RuntimeError(f"batch has {len(matches)} contracts for component {name!r}")
    return matches[0]


def repository_state(contract: dict[str, Any], runner: Runner = subprocess.run) -> tuple[str, str, str, str]:
    image = contract.get("image") or {}
    registry = image.get("registry", "")
    repository = image.get("repository", "")
    tag = image.get("tag", "")
    registry_id = registry.partition(".")[0]
    if not re.fullmatch(r"[0-9]{12}", registry_id) or not repository or not tag:
        raise RuntimeError(f"component {contract.get('component')} has malformed ECR image contract")
    response = aws_json(
        ["ecr", "describe-repositories", "--registry-id", registry_id,
         "--repository-names", repository], runner
    )
    repositories = response.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise RuntimeError(f"ECR repository lookup for {repository} was not exact")
    remote = repositories[0]
    if remote.get("repositoryName") != repository or str(remote.get("registryId")) != registry_id:
        raise RuntimeError(f"ECR repository identity for {repository} differs from the batch")
    if remote.get("imageTagMutability") != "IMMUTABLE":
        raise RuntimeError(
            f"ECR repository {repository} tag mutability is {remote.get('imageTagMutability')!r}; "
            "release repositories must already be IMMUTABLE"
        )
    return registry, registry_id, repository, tag


def tagged_digest(contract: dict[str, Any], runner: Runner = subprocess.run) -> str | None:
    _, registry_id, repository, tag = repository_state(contract, runner)
    result = run(
        ["aws", "ecr", "describe-images", "--registry-id", registry_id,
         "--repository-name", repository, "--image-ids", f"imageTag={tag}", "--output", "json"],
        runner,
    )
    if result.returncode != 0:
        if "ImageNotFoundException" in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip() or f"ECR tag lookup for {repository}:{tag} failed")
    try:
        response = json.loads(result.stdout, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"ECR tag lookup for {repository}:{tag} returned malformed JSON") from error
    details = response.get("imageDetails")
    if not isinstance(details, list) or len(details) != 1:
        raise RuntimeError(f"ECR tag lookup for {repository}:{tag} was not exact")
    digest = details[0].get("imageDigest", "")
    tags = details[0].get("imageTags") or []
    if not DIGEST.fullmatch(digest) or tag not in tags:
        raise RuntimeError(f"ECR tag lookup for {repository}:{tag} returned an invalid identity")
    return digest


def probe(batch: dict[str, Any], name: str, runner: Runner = subprocess.run,
          root: Path | None = None) -> dict[str, Any]:
    contract = component_contract(batch, name)
    digest = tagged_digest(contract, runner)
    released = batch["releases"].get(contract["record"]["releaseKey"])
    if digest is None:
        if released is not None:
            raise RuntimeError(f"recorded component {name} has no ECR version tag")
        return {"component": name, "exists": False}
    if released is None:
        raise RuntimeError(
            f"conflicting preexisting ECR tag for pending component {name}; "
            "no persisted batch digest authorizes an idempotent retry"
        )
    expected = released.get("digest", "")
    if digest != expected:
        raise RuntimeError(f"component {name} ECR tag digest {digest} differs from persisted {expected}")
    verify_identity(contract, digest, root or Path(__file__).resolve().parents[1], runner)
    return {"component": name, "exists": True, "digest": digest}


def verify_identity(contract: dict[str, Any], digest: str, root: Path,
                    runner: Runner = subprocess.run) -> None:
    image = contract["image"]
    identity = contract["identity"]
    repository = f"{image['registry']}/{image['repository']}"
    immutable = f"{repository}@{digest}"
    tagged = f"{repository}:{image['tag']}"
    commands = [
        ["docker", "pull", immutable],
        ["docker", "tag", immutable, tagged],
        [sys.executable, str(root / "tools" / "verify_service_image_identity.py"),
         "--image", tagged, "--service", identity["service"],
         "--entrypoint", identity["command"], "--git-sha", contract["source"],
         "--version", contract["version"], "--expected-repository", repository,
         "--expected-tag", image["tag"], "--expected-digest", digest],
        ["docker", "image", "rm", tagged, immutable],
    ]
    for command in commands:
        result = run(command, runner)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"{' '.join(command)} failed")


def verify(batch: dict[str, Any], root: Path, identities: bool,
           runner: Runner = subprocess.run) -> list[dict[str, str]]:
    verified: list[dict[str, str]] = []
    release_keys: set[str] = set()
    for contract in batch["components"]:
        key = contract.get("record", {}).get("releaseKey", "")
        if not key or key in release_keys:
            raise RuntimeError("batch has duplicate or empty release keys")
        release_keys.add(key)
        released = batch["releases"].get(key)
        digest = tagged_digest(contract, runner)
        if released is None:
            if digest is not None:
                raise RuntimeError(
                    f"component {contract['component']} has an ECR version tag but no persisted release"
                )
            continue
        expected = released.get("digest", "")
        expected_repository = f"{contract['image']['registry']}/{contract['image']['repository']}"
        if released.get("repository") != expected_repository:
            raise RuntimeError(f"component {contract['component']} persisted repository differs from its contract")
        if digest != expected or not DIGEST.fullmatch(expected):
            raise RuntimeError(
                f"component {contract['component']} ECR tag digest {digest!r} differs from persisted {expected!r}"
            )
        if identities:
            verify_identity(contract, digest, root, runner)
        verified.append({"component": contract["component"], "digest": digest})
    if set(batch["releases"]) != release_keys.intersection(batch["releases"]):
        raise RuntimeError("batch contains a release without one exact component contract")
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("probe", "verify"))
    parser.add_argument("--batch", type=Path, default=Path("release/batch.json"))
    parser.add_argument("--component")
    parser.add_argument("--verify-identities", action="store_true")
    args = parser.parse_args()
    batch = read_batch(args.batch)
    try:
        if args.command == "probe":
            if not args.component:
                parser.error("probe requires --component")
            result: Any = probe(batch, args.component)
        else:
            if args.component:
                parser.error("verify does not accept --component")
            result = verify(batch, Path(__file__).resolve().parents[1], args.verify_identities)
    except RuntimeError as error:
        raise SystemExit(f"verify-release-ecr: {error}") from error
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
