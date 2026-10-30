#!/usr/bin/env python3
"""Aggregate immutable-ECR and race gate for the staging-isolated release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

import staging_release as release


ROOT = Path(__file__).resolve().parents[1]
Runner = Callable[..., subprocess.CompletedProcess[str]]


def run(command: list[str], runner: Runner = subprocess.run) -> subprocess.CompletedProcess[str]:
    return runner(command, text=True, capture_output=True)


def aws_json(command: list[str], runner: Runner = subprocess.run) -> dict[str, Any]:
    result = run(["aws", *command, "--output", "json"], runner)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"aws {' '.join(command)} failed")
    try:
        value = json.loads(result.stdout, object_pairs_hook=release.reject_duplicates)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"aws {' '.join(command)} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"aws {' '.join(command)} did not return an object")
    return value


def batch(path: Path, complete: bool | None = None) -> dict[str, Any]:
    return release.validate_batch(release.read_json(path), require_complete=complete)


def component(batch_value: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in batch_value["components"] if item["component"] == name]
    if len(matches) != 1:
        raise RuntimeError(f"component {name!r} is not an exact batch component")
    return matches[0]


def repository_state(contract: dict[str, Any], runner: Runner = subprocess.run) -> dict[str, Any]:
    target = release.expected_target()
    name = contract["component"]
    repository = contract["image"]["repository"]
    if repository != target["repositories"][name]:
        raise RuntimeError(f"component {name} repository escapes the staging target")
    base = ["--region", target["region"], "--registry-id", target["accountId"]]
    response = aws_json(["ecr", "describe-repositories", *base, "--repository-names", repository], runner)
    repositories = response.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise RuntimeError(f"ECR repository lookup for {repository} was not exact")
    remote = repositories[0]
    expected_arn = f"arn:aws:ecr:{target['region']}:{target['accountId']}:repository/{repository}"
    expected_uri = f"{target['registry']}/{repository}"
    controls = target["repositoryControls"]
    if remote.get("repositoryName") != repository or str(remote.get("registryId")) != target["accountId"] or remote.get("repositoryArn") != expected_arn or remote.get("repositoryUri") != expected_uri:
        raise RuntimeError(f"ECR repository identity for {repository} differs from the batch target")
    if remote.get("imageTagMutability") != controls["imageTagMutability"]:
        raise RuntimeError(f"ECR repository {repository} is not IMMUTABLE")
    if remote.get("imageScanningConfiguration", {}).get("scanOnPush") is not True:
        raise RuntimeError(f"ECR repository {repository} does not scan on push")
    encryption = remote.get("encryptionConfiguration", {})
    if encryption.get("encryptionType") != controls["encryptionType"]:
        raise RuntimeError(f"ECR repository {repository} encryption differs from the target")
    tags_response = aws_json(["ecr", "list-tags-for-resource", "--region", target["region"], "--resource-arn", expected_arn], runner)
    tags = {item.get("Key"): item.get("Value") for item in tags_response.get("tags", []) if isinstance(item, dict)}
    if tags != controls["tags"]:
        raise RuntimeError(f"ECR repository {repository} ownership tags differ from the exact staging target")
    lifecycle = aws_json(["ecr", "get-lifecycle-policy", *base, "--repository-name", repository], runner)
    try:
        policy = json.loads(lifecycle.get("lifecyclePolicyText", ""), object_pairs_hook=release.reject_duplicates)
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"ECR repository {repository} lifecycle policy is malformed") from error
    if policy != controls["lifecyclePolicy"]:
        raise RuntimeError(f"ECR repository {repository} lifecycle policy differs from the isolated target")
    resource_policy = run(["aws", "ecr", "get-repository-policy", *base, "--repository-name", repository, "--output", "json"], runner)
    if resource_policy.returncode == 0:
        raise RuntimeError(f"ECR repository {repository} unexpectedly has a resource policy; IAM_ONLY was required")
    if "RepositoryPolicyNotFoundException" not in resource_policy.stderr:
        raise RuntimeError(resource_policy.stderr.strip() or f"cannot prove IAM-only access for {repository}")
    state = {
        "repository": repository,
        "arn": expected_arn,
        "uri": expected_uri,
        "mutability": remote["imageTagMutability"],
        "scanOnPush": True,
        "encryption": encryption,
        "tags": tags,
        "lifecyclePolicy": policy,
        "resourcePolicy": "IAM_ONLY",
    }
    state["digest"] = release.canonical_digest(state)
    return state


def tag_digests(contract: dict[str, Any], runner: Runner = subprocess.run) -> dict[str, str]:
    target = release.expected_target()
    repository = contract["image"]["repository"]
    found: dict[str, str] = {}
    for tag in contract["image"]["tags"]:
        result = run([
            "aws", "ecr", "describe-images", "--region", target["region"], "--registry-id", target["accountId"],
            "--repository-name", repository, "--image-ids", f"imageTag={tag}", "--output", "json",
        ], runner)
        if result.returncode != 0:
            if "ImageNotFoundException" in result.stderr:
                continue
            raise RuntimeError(result.stderr.strip() or f"ECR tag lookup for {repository}:{tag} failed")
        try:
            response = json.loads(result.stdout, object_pairs_hook=release.reject_duplicates)
        except (json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"ECR tag lookup for {repository}:{tag} returned malformed JSON") from error
        details = response.get("imageDetails")
        if not isinstance(details, list) or len(details) != 1:
            raise RuntimeError(f"ECR tag lookup for {repository}:{tag} was not exact")
        digest = details[0].get("imageDigest", "")
        tags = details[0].get("imageTags") or []
        if not release.DIGEST.fullmatch(digest) or tag not in tags:
            raise RuntimeError(f"ECR tag lookup for {repository}:{tag} returned an invalid identity")
        found[tag] = digest
    if len(set(found.values())) > 1:
        raise RuntimeError(f"ECR repository {repository} staging tags resolve to different digests")
    return found


def verify_remote_identity(contract: dict[str, Any], digest: str, runner: Runner = subprocess.run) -> None:
    image = contract["image"]
    repository = f"{image['registry']}/{image['repository']}"
    if contract["kind"] == "fixture":
        if digest != contract["identity"]["oci"]["manifest"]:
            raise RuntimeError(f"fixture {contract['component']} ECR manifest digest differs from the reviewed OCI identity")
        return
    immutable = f"{repository}@{digest}"
    tagged = f"{repository}:{image['tag']}"
    for command in (["docker", "pull", immutable], ["docker", "tag", immutable, tagged]):
        result = run(command, runner)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"{' '.join(command)} failed")
    identity = contract["identity"]
    result = run([
        sys.executable, str(ROOT / "tools/verify_service_image_identity.py"), "--image", tagged,
        "--service", identity["service"], "--entrypoint", identity["command"],
        "--git-sha", contract["source"], "--version", contract["version"],
        "--expected-repository", repository, "--expected-tag", image["tag"], "--expected-digest", digest,
    ], runner)
    cleanup = run(["docker", "image", "rm", tagged, immutable], runner)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"component {contract['component']} embedded identity verification failed")
    if cleanup.returncode != 0:
        raise RuntimeError(cleanup.stderr.strip() or f"component {contract['component']} image cleanup failed")


def preflight(batch_value: dict[str, Any], runner: Runner = subprocess.run) -> dict[str, Any]:
    states = []
    for name in batch_value["expectedComponents"]:
        contract = component(batch_value, name)
        remote = repository_state(contract, runner)
        digests = tag_digests(contract, runner)
        release_record = batch_value["releases"].get(name)
        digest = next(iter(digests.values()), None)
        missing = [tag for tag in contract["image"]["tags"] if tag not in digests]
        if release_record is not None:
            if digest != release_record["digest"] or missing:
                raise RuntimeError(f"component {name} ECR state differs from its complete release record")
            verify_remote_identity(contract, digest, runner)
            state = "recorded"
        elif digest is None:
            state = "absent"
        else:
            verify_remote_identity(contract, digest, runner)
            state = "recoverable"
        states.append({
            "component": name,
            "contractDigest": release.canonical_digest(contract),
            "repositoryStateDigest": remote["digest"],
            "state": state,
            "digest": digest,
            "missingTags": missing,
        })
    result = {
        "schema": 1,
        "target": batch_value["target"],
        "source": batch_value["source"],
        "batchDigest": release.canonical_digest(batch_value),
        "components": states,
    }
    result["stateDigest"] = release.canonical_digest(result)
    return result


def read_preflight(path: Path, batch_value: dict[str, Any]) -> dict[str, Any]:
    state = release.read_json(path)
    if not isinstance(state, dict) or set(state) != {"schema", "target", "source", "batchDigest", "components", "stateDigest"}:
        raise RuntimeError("preflight state has an incomplete or unknown contract")
    digest = state.pop("stateDigest")
    expected_digest = release.canonical_digest(state)
    state["stateDigest"] = digest
    if digest != expected_digest or state["schema"] != 1 or state["target"] != batch_value["target"] or state["source"] != batch_value["source"] or state["batchDigest"] != release.canonical_digest(batch_value):
        raise RuntimeError("preflight state does not match the exact staging batch")
    if [item.get("component") for item in state.get("components", [])] != batch_value["expectedComponents"]:
        raise RuntimeError("preflight state does not cover the exact staging component set")
    for item in state["components"]:
        contract = component(batch_value, item["component"])
        if item.get("contractDigest") != release.canonical_digest(contract) or item.get("state") not in {"absent", "recoverable", "recorded"}:
            raise RuntimeError("preflight component contract/state was changed")
    return state


def probe(batch_value: dict[str, Any], name: str, state: dict[str, Any], runner: Runner = subprocess.run, require_complete: bool = False) -> dict[str, Any]:
    contract = component(batch_value, name)
    saved = next((item for item in state["components"] if item["component"] == name), None)
    if saved is None:
        raise RuntimeError(f"component {name} is absent from preflight state")
    remote = repository_state(contract, runner)
    if remote["digest"] != saved["repositoryStateDigest"]:
        raise RuntimeError(f"component {name} repository controls changed after aggregate preflight")
    digests = tag_digests(contract, runner)
    digest = next(iter(digests.values()), None)
    missing = [tag for tag in contract["image"]["tags"] if tag not in digests]
    if saved["state"] == "absent" and digest is not None:
        raise RuntimeError(f"component {name} immutable tag appeared after aggregate preflight")
    if saved["state"] in {"recoverable", "recorded"} and digest != saved["digest"]:
        raise RuntimeError(f"component {name} immutable digest changed after aggregate preflight")
    if require_complete and (digest is None or missing):
        raise RuntimeError(f"component {name} publication is incomplete; missing tags {missing}")
    if digest is not None:
        verify_remote_identity(contract, digest, runner)
    return {"component": name, "exists": digest is not None, "state": saved["state"], "digest": digest, "missingTags": missing}


def verify_complete(batch_value: dict[str, Any], runner: Runner = subprocess.run) -> list[dict[str, str]]:
    output = []
    for name in batch_value["expectedComponents"]:
        contract = component(batch_value, name)
        repository_state(contract, runner)
        digests = tag_digests(contract, runner)
        if set(digests) != set(contract["image"]["tags"]) or len(set(digests.values())) != 1:
            raise RuntimeError(f"component {name} does not have its exact immutable tag set")
        digest = next(iter(digests.values()))
        if batch_value["releases"][name]["digest"] != digest:
            raise RuntimeError(f"component {name} ECR digest differs from the complete staging batch")
        verify_remote_identity(contract, digest, runner)
        output.append({"component": name, "digest": digest})
    return output


def verify_component(batch_value: dict[str, Any], name: str, runner: Runner = subprocess.run) -> dict[str, str]:
    contract = component(batch_value, name)
    repository_state(contract, runner)
    digests = tag_digests(contract, runner)
    if set(digests) != set(contract["image"]["tags"]) or len(set(digests.values())) != 1:
        raise RuntimeError(f"component {name} does not have its exact immutable tag set")
    digest = next(iter(digests.values()))
    verify_remote_identity(contract, digest, runner)
    return {"component": name, "digest": digest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pre = sub.add_parser("preflight")
    pre.add_argument("--batch", type=Path, required=True)
    probe_parser = sub.add_parser("probe")
    probe_parser.add_argument("--batch", type=Path, required=True)
    probe_parser.add_argument("--preflight-state", type=Path, required=True)
    probe_parser.add_argument("--component", required=True, choices=release.COMPONENTS)
    probe_parser.add_argument("--require-complete", action="store_true")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--batch", type=Path, required=True)
    component_parser = sub.add_parser("verify-component")
    component_parser.add_argument("--batch", type=Path, required=True)
    component_parser.add_argument("--component", required=True, choices=release.COMPONENTS)
    args = parser.parse_args()
    try:
        value = batch(args.batch, complete=True if args.command == "verify" else None)
        if args.command == "preflight":
            output: Any = preflight(value)
        elif args.command == "probe":
            output = probe(value, args.component, read_preflight(args.preflight_state, value), require_complete=args.require_complete)
        elif args.command == "verify":
            output = verify_complete(value)
        else:
            output = verify_component(value, args.component)
        json.dump(output, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    except (RuntimeError, ValueError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
