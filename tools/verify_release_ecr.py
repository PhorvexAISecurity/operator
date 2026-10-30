#!/usr/bin/env python3
"""Fail-closed ECR gate for one persisted, component-scoped release batch."""

from __future__ import annotations

import argparse
import hashlib
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
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
ECR_REGISTRY = re.compile(r"(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com")
RELEASE_REGISTRY = "753556437180.dkr.ecr.us-east-2.amazonaws.com"
CANONICAL_COMPONENTS = ("manager", "brain", "sensor", "actuator", "console", "attacks")
COMPONENT_CONTRACT = {
    "manager": ("phorvex/manager", "/manager"),
    "brain": ("phorvex/brain", "/service"),
    "sensor": ("phorvex/sensor", "/service"),
    "actuator": ("phorvex/actuator", "/service"),
    "console": ("phorvex/console", "/app/console"),
    "attacks": ("phorvex/attacks", "/app/attacks"),
}
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_json_file(path: Path) -> Any:
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
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ):
        raise SystemExit(f"{path}: identity changed during read")
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"{path}: {error}") from error


def _canonical_json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def read_batch(path: Path) -> dict[str, Any]:
    batch = _read_json_file(path)
    source = batch.get("source") if isinstance(batch, dict) else None
    if not isinstance(batch, dict) or batch.get("schema") != 2 or not isinstance(source, str) or not SHA.fullmatch(source):
        raise SystemExit(f"{path}: not a schema-v2 batch with an exact source SHA")
    expected = batch.get("expectedComponents")
    versions = batch.get("versions")
    contracts = batch.get("components")
    releases = batch.get("releases")
    if not isinstance(expected, list) or not isinstance(versions, dict) or not isinstance(contracts, list) or not isinstance(releases, dict):
        raise SystemExit(f"{path}: incomplete expected-component/version/contract/release objects")
    if not 1 <= len(expected) <= len(CANONICAL_COMPONENTS):
        raise SystemExit(f"{path}: expected component set must contain between 1 and {len(CANONICAL_COMPONENTS)} entries")
    if any(not isinstance(name, str) for name in expected) or len(expected) != len(set(expected)):
        raise SystemExit(f"{path}: expected component set contains an empty, duplicate or non-string entry")
    unknown = set(expected).difference(CANONICAL_COMPONENTS)
    canonical = [name for name in CANONICAL_COMPONENTS if name in set(expected)]
    if unknown or expected != canonical:
        raise SystemExit(f"{path}: expected component set is unknown, aliased or not canonical")
    if set(versions) != set(expected) or any(not isinstance(value, str) or not VERSION.fullmatch(value) for value in versions.values()):
        raise SystemExit(f"{path}: versions must exactly match the expected component set")
    names = [item.get("component") for item in contracts if isinstance(item, dict)]
    if len(names) != len(contracts) or names != expected:
        raise SystemExit(f"{path}: component contracts must exactly match the ordered expected component set")
    if not set(releases).issubset(expected):
        raise SystemExit(f"{path}: release records must be a subset of the expected component set")

    image_targets: set[tuple[str, str, str]] = set()
    for contract in contracts:
        name = contract["component"]
        identity = contract.get("identity")
        image = contract.get("image")
        record = contract.get("record")
        if not isinstance(identity, dict) or not isinstance(image, dict) or not isinstance(record, dict):
            raise SystemExit(f"{path}: component {name} has an incomplete identity/image/record contract")
        repository, command = COMPONENT_CONTRACT[name]
        if (contract.get("source") != batch["source"] or contract.get("version") != versions[name]
                or identity.get("service") != name or identity.get("command") != command
                or identity.get("aliases") != []):
            raise SystemExit(f"{path}: component {name} has an aliased or cross-component identity")
        if (image.get("registry") != RELEASE_REGISTRY or image.get("repository") != repository
                or image.get("tag") != versions[name]):
            raise SystemExit(f"{path}: component {name} has an aliased or cross-component ECR target")
        if record.get("releaseKey") != name or record.get("gitTag") != f"{name}-v{versions[name]}":
            raise SystemExit(f"{path}: component {name} has an aliased or cross-component release record")
        target = (image["registry"], image["repository"], image["tag"])
        if target in image_targets:
            raise SystemExit(f"{path}: duplicate ECR repository/tag target")
        image_targets.add(target)
        released = releases.get(name)
        if released is not None:
            expected_repository = f"{image['registry']}/{image['repository']}"
            released_digest = released.get("digest") if isinstance(released, dict) else None
            if (not isinstance(released, dict) or released.get("repository") != expected_repository
                    or not isinstance(released_digest, str) or not DIGEST.fullmatch(released_digest)):
                raise SystemExit(f"{path}: component {name} has malformed persisted image provenance")
    return batch


def run(command: list[str], runner: Runner = subprocess.run) -> subprocess.CompletedProcess[str]:
    return runner(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def aws_json(arguments: list[str], runner: Runner = subprocess.run) -> dict[str, Any]:
    result = run(["aws", *arguments, "--output", "json"], runner)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"aws {' '.join(arguments)} failed")
    try:
        response = json.loads(result.stdout, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"aws {' '.join(arguments)} returned malformed JSON: {error}") from error
    if not isinstance(response, dict):
        raise RuntimeError(f"aws {' '.join(arguments)} did not return an object")
    return response


def component_contract(batch: dict[str, Any], name: str) -> dict[str, Any]:
    if name not in batch["expectedComponents"]:
        raise RuntimeError(f"component {name!r} is not in the persisted expected component set")
    index = batch["expectedComponents"].index(name)
    contract = batch["components"][index]
    if contract.get("component") != name:
        raise RuntimeError(f"component {name!r} contract changed after batch validation")
    return contract


def repository_state(contract: dict[str, Any], runner: Runner = subprocess.run) -> tuple[str, str, str, str, str]:
    image = contract["image"]
    registry = image["registry"]
    repository = image["repository"]
    tag = image["tag"]
    match = ECR_REGISTRY.fullmatch(registry)
    if match is None:
        raise RuntimeError(f"component {contract.get('component')} has a malformed ECR registry")
    registry_id, region = match.group("account"), match.group("region")
    response = aws_json(
        ["ecr", "describe-repositories", "--region", region, "--registry-id", registry_id,
         "--repository-names", repository], runner
    )
    repositories = response.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise RuntimeError(f"ECR repository lookup for {repository} was not exact")
    remote = repositories[0]
    expected_arn = f"arn:aws:ecr:{region}:{registry_id}:repository/{repository}"
    expected_uri = f"{registry}/{repository}"
    if (remote.get("repositoryName") != repository or str(remote.get("registryId")) != registry_id
            or remote.get("repositoryArn") != expected_arn or remote.get("repositoryUri") != expected_uri):
        raise RuntimeError(f"ECR repository identity for {repository} differs from the batch registry/account/region")
    if remote.get("imageTagMutability") != "IMMUTABLE":
        raise RuntimeError(
            f"ECR repository {repository} tag mutability is {remote.get('imageTagMutability')!r}; "
            "release repositories must already be IMMUTABLE"
        )
    return registry, registry_id, region, repository, tag


def tagged_digest(contract: dict[str, Any], runner: Runner = subprocess.run) -> str | None:
    _, registry_id, region, repository, tag = repository_state(contract, runner)
    result = run(
        ["aws", "ecr", "describe-images", "--region", region, "--registry-id", registry_id,
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


def verify_identity(contract: dict[str, Any], digest: str, root: Path,
                    runner: Runner = subprocess.run) -> None:
    image = contract["image"]
    identity = contract["identity"]
    repository = f"{image['registry']}/{image['repository']}"
    immutable = f"{repository}@{digest}"
    tagged = f"{repository}:{image['tag']}"
    setup = [
        ["docker", "pull", immutable],
        ["docker", "tag", immutable, tagged],
    ]
    for command in setup:
        result = run(command, runner)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"{' '.join(command)} failed")
    verification = [
        sys.executable, str(root / "tools" / "verify_service_image_identity.py"),
        "--image", tagged, "--service", identity["service"],
        "--entrypoint", identity["command"], "--git-sha", contract["source"],
        "--version", contract["version"], "--expected-repository", repository,
        "--expected-tag", image["tag"], "--expected-digest", digest,
    ]
    failure: RuntimeError | None = None
    result = run(verification, runner)
    if result.returncode != 0:
        failure = RuntimeError(result.stderr.strip() or f"{' '.join(verification)} failed")
    cleanup = run(["docker", "image", "rm", tagged, immutable], runner)
    if failure is not None:
        raise failure
    if cleanup.returncode != 0:
        raise RuntimeError(cleanup.stderr.strip() or "failed to remove verified ECR image")


def preflight(batch: dict[str, Any], root: Path,
              runner: Runner = subprocess.run) -> dict[str, Any]:
    """Read every target before the first build/push/tag/Git mutation."""
    states: list[dict[str, Any]] = []
    for name in batch["expectedComponents"]:
        contract = component_contract(batch, name)
        digest = tagged_digest(contract, runner)
        released = batch["releases"].get(name)
        if released is not None:
            if digest != released["digest"]:
                raise RuntimeError(f"component {name} ECR tag digest {digest!r} differs from persisted {released['digest']!r}")
            verify_identity(contract, digest, root, runner)
            state = "recorded"
        elif digest is None:
            state = "absent"
        else:
            # A push may have reached ECR immediately before the runner died.
            # Immutability prevents overwrite; exact embedded identity permits
            # this retry to record that observed digest without pushing again.
            verify_identity(contract, digest, root, runner)
            state = "recoverable"
        states.append({
            "component": name,
            "contractDigest": _canonical_json_digest(contract),
            "state": state,
            "digest": digest,
        })
    return {
        "schema": 1,
        "batchSource": batch["source"],
        "batchDigest": _canonical_json_digest(batch),
        "expectedComponents": batch["expectedComponents"],
        "components": states,
    }


def read_preflight(path: Path, batch: dict[str, Any]) -> dict[str, Any]:
    state = _read_json_file(path)
    if not isinstance(state, dict) or state.get("schema") != 1:
        raise RuntimeError("aggregate ECR preflight state is malformed")
    if (state.get("batchSource") != batch["source"]
            or state.get("batchDigest") != _canonical_json_digest(batch)
            or state.get("expectedComponents") != batch["expectedComponents"]):
        raise RuntimeError("aggregate ECR preflight state does not match the exact batch")
    entries = state.get("components")
    names = [entry.get("component") for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []
    if names != batch["expectedComponents"]:
        raise RuntimeError("aggregate ECR preflight state does not cover the exact expected component set")
    for entry in entries:
        contract = component_contract(batch, entry["component"])
        entry_digest = entry.get("digest")
        entry_state = entry.get("state")
        released = batch["releases"].get(entry["component"])
        invalid_state = (
            (entry_state == "absent" and entry_digest is not None)
            or (entry_state in {"recorded", "recoverable"}
                and (not isinstance(entry_digest, str) or not DIGEST.fullmatch(entry_digest)))
            or (entry_state == "recorded" and (released is None or released["digest"] != entry_digest))
            or (entry_state == "recoverable" and released is not None)
        )
        if (entry.get("contractDigest") != _canonical_json_digest(contract)
                or entry_state not in {"absent", "recorded", "recoverable"}
                or invalid_state):
            raise RuntimeError(f"aggregate ECR preflight state for {entry['component']} is invalid")
    return state


def probe(batch: dict[str, Any], name: str, state: dict[str, Any],
          runner: Runner = subprocess.run, root: Path | None = None) -> dict[str, Any]:
    """Requery one target and require it to equal the aggregate snapshot."""
    contract = component_contract(batch, name)
    entry = next(item for item in state["components"] if item["component"] == name)
    digest = tagged_digest(contract, runner)
    if entry["state"] == "absent":
        if digest is not None:
            raise RuntimeError(f"component {name} ECR tag appeared after aggregate preflight")
        return {"component": name, "exists": False, "state": "absent"}
    if digest != entry["digest"]:
        raise RuntimeError(f"component {name} ECR tag changed after aggregate preflight")
    verify_identity(contract, digest, root or Path(__file__).resolve().parents[1], runner)
    return {"component": name, "exists": True, "state": entry["state"], "digest": digest}


def verify(batch: dict[str, Any], root: Path, identities: bool,
           runner: Runner = subprocess.run) -> list[dict[str, str]]:
    """Requery the exact batch; pending tags are forbidden at publication."""
    verified: list[dict[str, str]] = []
    for name in batch["expectedComponents"]:
        contract = component_contract(batch, name)
        released = batch["releases"].get(name)
        digest = tagged_digest(contract, runner)
        if released is None:
            if digest is not None:
                raise RuntimeError(f"component {name} has an ECR version tag but no persisted release")
            continue
        if digest != released["digest"]:
            raise RuntimeError(f"component {name} ECR tag digest {digest!r} differs from persisted {released['digest']!r}")
        if identities:
            verify_identity(contract, digest, root, runner)
        verified.append({"component": name, "digest": digest})
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "probe", "verify"))
    parser.add_argument("--batch", type=Path, default=Path("release/batch.json"))
    parser.add_argument("--component")
    parser.add_argument("--preflight-state", type=Path)
    parser.add_argument("--verify-identities", action="store_true")
    args = parser.parse_args()
    batch = read_batch(args.batch)
    root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "preflight":
            if args.component or args.preflight_state:
                parser.error("preflight does not accept --component or --preflight-state")
            result: Any = preflight(batch, root)
        elif args.command == "probe":
            if not args.component or not args.preflight_state:
                parser.error("probe requires --component and --preflight-state")
            state = read_preflight(args.preflight_state, batch)
            result = probe(batch, args.component, state)
        else:
            if args.component or args.preflight_state:
                parser.error("verify does not accept --component or --preflight-state")
            result = verify(batch, root, args.verify_identities)
    except RuntimeError as error:
        raise SystemExit(f"verify-release-ecr: {error}") from error
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
