#!/usr/bin/env python3
"""Create, complete, pin and verify the explicit staging-isolated release contract."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
TARGET_FILE = ROOT / "release/staging-target.json"
FIXTURE_IDENTITIES_FILE = ROOT / "release/staging-fixture-identities.json"
SERVICE_NAMES = ["manager", "brain", "sensor", "actuator", "console", "attacks"]
FIXTURE_NAMES = ["agent-sim", "catalogue-workload"]
COMPONENTS = SERVICE_NAMES + FIXTURE_NAMES
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
EXPECTED_REPOSITORIES = {name: f"phorvex/staging/{name}" for name in COMPONENTS}
SERVICE_COMMANDS = {
    "manager": "/manager",
    "brain": "/service",
    "sensor": "/service",
    "actuator": "/service",
    "console": "/app/console",
    "attacks": "/app/attacks",
}


def fixture_consumer(
    component: str, profile: str, namespace: str, name: str, container: str,
    *, api_version: str = "apps/v1", kind: str = "Deployment",
    field_path: str = "/spec/template/spec/containers/0/image",
) -> dict[str, str]:
    return {
        "profile": profile,
        "apiVersion": api_version,
        "kind": kind,
        "namespace": namespace,
        "name": name,
        "fieldPath": field_path,
        "container": container,
        "component": component,
    }


FIXTURE_SPECS = {
    "agent-sim": {
        "version": "fixture-v1",
        "dockerfile": "farm-fixtures/agentsim/Dockerfile",
        "deploy": {
            "valuesFile": "deploy/environments/staging/catalogue-family.yaml",
            "path": ["phorvex", "console", "attackCatalog", "agentAction", "image"],
            "consumers": [
                fixture_consumer("agent-sim", "agent-action", "p6-demo", "agent-sim", "agent-sim"),
            ],
        },
    },
    "catalogue-workload": {
        "version": "fixture-v1",
        "dockerfile": "farm-fixtures/catalogue-workload/Dockerfile",
        "deploy": {
            "valuesFile": "deploy/environments/staging/phorvex.yaml",
            "path": ["phorvex", "console", "attackCatalog", "familyFixtures", "images", "workload"],
            "consumers": [
                fixture_consumer("catalogue-workload", "controller-stop", "p4-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "credential", "p4-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "identity-sa-rotate", "console-identity-shared", "console-id-fixture", "web"),
                fixture_consumer("catalogue-workload", "image", "p2-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "image", "p3-demo", "demo-api", "web"),
                fixture_consumer(
                    "catalogue-workload", "network-edge", "p2-demo", "c2-sink", "sink",
                    api_version="v1", kind="Pod", field_path="/spec/containers/0/image",
                ),
                fixture_consumer("catalogue-workload", "network-edge", "p2-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "node-recycle", "p3-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "pod-rotate", "p2-demo", "demo-api", "web"),
                fixture_consumer("catalogue-workload", "quarantine", "p1-demo", "demo-api", "web"),
            ],
        },
    },
}

STATIC_PROFILE_CONSUMERS = {
    "node-recycle": [{
        **fixture_consumer("static", "node-recycle", "p3-demo", "kwok-controller-p3", "kwok"),
        "image": "registry.k8s.io/kwok/kwok@sha256:6d25aa8fbdfe78845423160bf125b5513f9522e2770981f0945c2a250c2b26f0",
    }],
}


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{current}: symlinks are not permitted")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError(f"{current}: hard-linked authority files are not permitted")
    raw = absolute.read_bytes()
    return json.loads(raw, object_pairs_hook=reject_duplicates)


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def expected_target() -> dict[str, Any]:
    target = read_json(TARGET_FILE)
    if target.get("schema") != 1 or target.get("name") != "staging-isolated":
        raise ValueError("release/staging-target.json is not the staging-isolated v1 target")
    if target.get("environment") != "staging" or target.get("accountId") != "753556437180" or target.get("region") != "us-east-2":
        raise ValueError("staging target account, region or environment changed")
    if target.get("registry") != "753556437180.dkr.ecr.us-east-2.amazonaws.com":
        raise ValueError("staging target registry changed")
    if target.get("repositoryPrefix") != "phorvex/staging/" or target.get("repositories") != EXPECTED_REPOSITORIES:
        raise ValueError("staging target repository set is not the exact isolated eight-component set")
    controls = target.get("repositoryControls", {})
    if controls.get("imageTagMutability") != "IMMUTABLE" or controls.get("scanOnPush") is not True or controls.get("encryptionType") not in {"AES256", "KMS"}:
        raise ValueError("staging target repository controls are weaker than required")
    if (
        controls.get("resourcePolicy") != "IAM_ONLY"
        or controls.get("registryPolicy") != "ABSENT"
        or controls.get("registryPolicyScope") != "V2"
        or controls.get("basicScanTypeVersion") != "AWS_NATIVE"
        or controls.get("registryScanType") != "BASIC"
        or controls.get("tags") != {
        "campaign": "console-reactive-qa-192",
        "environment": "staging",
        "isolation": "staging-only",
        "managed-by": "PhorvexSecurity/operator-refactored",
        "project": "phorvex",
        }
    ):
        raise ValueError("staging target ownership/access identity changed")
    deployment = target.get("deployment", {})
    if deployment != {
        "applicationManifest": "deploy/argocd/services/applicationset.yaml",
        "valuesRoot": "deploy/environments/staging",
        "releaseName": "staging",
        "namespace": "phorvex-staging",
        "branchPrefix": "release/staging-isolated-",
    }:
        raise ValueError("staging deployment route changed or can fan out")
    return target


def fixture_identities() -> dict[str, Any]:
    value = read_json(FIXTURE_IDENTITIES_FILE)
    if value.get("schema") != 1 or value.get("sourceDateEpoch") != 0 or set(value.get("fixtures", {})) != set(FIXTURE_NAMES):
        raise ValueError("fixture identity authority is incomplete")
    for name, identity in value["fixtures"].items():
        if set(identity) != {"index", "manifest", "config", "applicationLayer"} or not all(DIGEST.fullmatch(item) for item in identity.values()):
            raise ValueError(f"fixture {name} identity is malformed")
    return value["fixtures"]


def validate_service_contracts(contracts: Any, source: str, target: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(contracts, list) or [item.get("component") for item in contracts if isinstance(item, dict)] != SERVICE_NAMES:
        raise ValueError("service contract is not the exact canonical six-component set")
    registry = target["registry"]
    seen_deployments: set[tuple[str, tuple[str, ...]]] = set()
    for contract in contracts:
        name = contract["component"]
        version = contract.get("version")
        image = contract.get("image", {})
        deploy = contract.get("deploy", {})
        identity = contract.get("identity", {})
        build = contract.get("build", {})
        expected_tag = f"{version}-git-{source}"
        if contract.get("source") != source or not isinstance(version, str) or not version:
            raise ValueError(f"service {name} source/version is not exact")
        if identity.get("service") != name or identity.get("command") != SERVICE_COMMANDS[name] or identity.get("aliases") != []:
            raise ValueError(f"service {name} embedded identity contract changed")
        if image != {
            "registry": registry,
            "repository": target["repositories"][name],
            "tag": expected_tag,
            "tags": [expected_tag, f"git-{source}"],
        }:
            raise ValueError(f"service {name} image target/tags are not canonical staging-only values")
        if build.get("context") != "." or not build.get("dockerfile") or f"GIT_SHA={source}" not in build.get("args", []) or f"RELEASE_VERSION={version}" not in build.get("args", []):
            raise ValueError(f"service {name} build identity is incomplete")
        if deploy.get("application") != target["deployment"]["applicationManifest"] or deploy.get("releaseName") != "staging" or deploy.get("namespace") != "phorvex-staging":
            raise ValueError(f"service {name} deployment is not isolated staging")
        values_file = deploy.get("valuesFile", "")
        if not values_file.startswith(target["deployment"]["valuesRoot"] + "/") or not deploy.get("consumers"):
            raise ValueError(f"service {name} has no exact staging values/consumer contract")
        for consumer in deploy["consumers"]:
            if consumer.get("component") != name or consumer.get("expectedRepository") != f"{registry}/{target['repositories'][name]}":
                raise ValueError(f"service {name} rendered consumer escapes its staging repository")
        deployment_key = (values_file, tuple(deploy.get("path", [])))
        if deployment_key in seen_deployments:
            raise ValueError(f"service {name} shares a deployment pin target")
        seen_deployments.add(deployment_key)
    return contracts


def prepare(source: str, services_path: Path) -> dict[str, Any]:
    if not SHA.fullmatch(source):
        raise ValueError("--source must be an exact lowercase 40-character Git SHA")
    target = expected_target()
    verify_argocd(target)
    services = validate_service_contracts(read_json(services_path), source, target)
    identities = fixture_identities()
    components: list[dict[str, Any]] = []
    for service in services:
        item = copy.deepcopy(service)
        item["kind"] = "service"
        components.append(item)
    for name in FIXTURE_NAMES:
        spec = FIXTURE_SPECS[name]
        version = spec["version"]
        deployment_tag = f"{version}-git-{source}"
        components.append({
            "component": name,
            "kind": "fixture",
            "source": source,
            "version": version,
            "build": {
                "dockerfile": spec["dockerfile"],
                "context": ".",
                "target": "",
                "args": ["SOURCE_DATE_EPOCH=0"],
                "platform": "linux/amd64",
                "network": "none",
                "provenance": False,
                "sbom": False,
            },
            "image": {
                "registry": target["registry"],
                "repository": target["repositories"][name],
                "tag": deployment_tag,
                "tags": [deployment_tag, f"git-{source}"],
            },
            "identity": {"oci": identities[name]},
            "deploy": spec["deploy"],
        })
    batch = {
        "schema": 1,
        "status": "prepared",
        "target": target["name"],
        "targetDigest": canonical_digest(target),
        "environment": target["environment"],
        "source": source,
        "sourceTree": git_output(["rev-parse", f"{source}^{{tree}}"]),
        "expectedComponents": COMPONENTS,
        "components": components,
        "releases": {},
    }
    validate_batch(batch, require_complete=False)
    return batch


def validate_batch(
    batch: Any,
    require_complete: bool | None = None,
    canonical_services: Any | None = None,
) -> dict[str, Any]:
    target = expected_target()
    verify_argocd(target)
    if not isinstance(batch, dict) or set(batch) != {
        "schema", "status", "target", "targetDigest", "environment", "source", "sourceTree",
        "expectedComponents", "components", "releases",
    }:
        raise ValueError("staging batch has an incomplete or unknown top-level contract")
    source = batch.get("source", "")
    if batch["schema"] != 1 or batch["target"] != "staging-isolated" or batch["environment"] != "staging" or not SHA.fullmatch(source):
        raise ValueError("staging batch schema/target/environment/source is invalid")
    source_tree = git_output(["rev-parse", f"{source}^{{tree}}"])
    if batch["targetDigest"] != canonical_digest(target) or batch.get("sourceTree") != source_tree:
        raise ValueError("staging batch target or source-tree identity changed")
    if batch.get("expectedComponents") != COMPONENTS or not isinstance(batch.get("components"), list) or len(batch["components"]) != len(COMPONENTS):
        raise ValueError("staging batch does not contain the exact eight-component set")
    if [item.get("component") for item in batch["components"]] != COMPONENTS:
        raise ValueError("staging batch component contracts are missing, extra or reordered")
    services = validate_service_contracts(batch["components"][: len(SERVICE_NAMES)], source, target)
    if canonical_services is not None:
        expected_services = copy.deepcopy(validate_service_contracts(canonical_services, source, target))
        for item in expected_services:
            item["kind"] = "service"
        if services != expected_services:
            raise ValueError("staging service contracts differ from the exact source-derived contracts")
    identities = fixture_identities()
    for item in batch["components"][len(SERVICE_NAMES):]:
        name = item["component"]
        expected = FIXTURE_SPECS[name]
        version = expected["version"]
        tag = f"{version}-git-{source}"
        if item.get("kind") != "fixture" or item.get("source") != source or item.get("version") != version:
            raise ValueError(f"fixture {name} source/version contract changed")
        if item.get("image") != {
            "registry": target["registry"], "repository": target["repositories"][name],
            "tag": tag, "tags": [tag, f"git-{source}"],
        } or item.get("identity") != {"oci": identities[name]} or item.get("deploy") != expected["deploy"]:
            raise ValueError(f"fixture {name} image/OCI/deployment contract changed")
        if item.get("build") != {
            "dockerfile": expected["dockerfile"], "context": ".", "target": "",
            "args": ["SOURCE_DATE_EPOCH=0"], "platform": "linux/amd64", "network": "none",
            "provenance": False, "sbom": False,
        }:
            raise ValueError(f"fixture {name} build contract changed")
    releases = batch.get("releases")
    if not isinstance(releases, dict) or not set(releases).issubset(COMPONENTS):
        raise ValueError("staging releases are not a component-keyed object")
    for item in batch["components"]:
        name = item["component"]
        release = releases.get(name)
        if release is None:
            continue
        expected_repository = f"{target['registry']}/{target['repositories'][name]}"
        if release != {"repository": expected_repository, "digest": release.get("digest")} or not DIGEST.fullmatch(release.get("digest", "")):
            raise ValueError(f"component {name} release repository/digest is invalid")
        if item.get("kind") == "fixture" and release["digest"] != item["identity"]["oci"]["manifest"]:
            raise ValueError(f"fixture {name} release digest differs from its reviewed OCI manifest")
    expected_status = "complete" if len(releases) == len(COMPONENTS) else ("prepared" if not releases else "partial")
    if batch.get("status") != expected_status:
        raise ValueError(f"staging batch status {batch.get('status')!r}, want {expected_status!r}")
    if require_complete is True and expected_status != "complete":
        raise ValueError("staging batch is not complete")
    if require_complete is False and expected_status != "prepared":
        raise ValueError("staging batch is not prepared/empty")
    return batch


def complete(batch: dict[str, Any], results: Any, canonical_services: Any | None = None) -> dict[str, Any]:
    validate_batch(batch, require_complete=False, canonical_services=canonical_services)
    if not isinstance(results, dict) or list(results) != COMPONENTS:
        raise ValueError("publication results must contain the canonical eight components in order")
    candidate = copy.deepcopy(batch)
    candidate["releases"] = results
    candidate["status"] = "complete"
    validate_batch(candidate, require_complete=True, canonical_services=canonical_services)
    return candidate


def nested(root: dict[str, Any], path: list[str]) -> Any:
    value: Any = root
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"missing deployment value {'.'.join(path)}")
        value = value[key]
    return value


def replace_yaml_scalar(path: Path, keys: list[str], value: str) -> None:
    raw = path.read_text(encoding="utf-8")
    before = yaml.safe_load(raw)
    if not isinstance(nested(before, keys), str):
        raise ValueError(f"{path}: {'.'.join(keys)} is not an existing string scalar")
    stack: list[tuple[int, str]] = []
    matches: list[int] = []
    pattern = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+):(?P<rest>.*)$")
    lines = raw.splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = pattern.match(line.rstrip("\n"))
        if not match or line.lstrip().startswith("#"):
            continue
        indent = len(match.group("indent"))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = match.group("key")
        current = [item[1] for item in stack] + [key]
        rest = match.group("rest").strip()
        if current == keys:
            if not rest:
                raise ValueError(f"{path}: {'.'.join(keys)} unexpectedly became a mapping")
            matches.append(index)
        if not rest or rest.startswith("#"):
            stack.append((indent, key))
    if len(matches) != 1:
        raise ValueError(f"{path}: found {len(matches)} textual matches for {'.'.join(keys)}, want one")
    line_index = matches[0]
    indent = " " * (len(lines[line_index]) - len(lines[line_index].lstrip(" ")))
    suffix = "\n" if lines[line_index].endswith("\n") else ""
    lines[line_index] = f'{indent}{keys[-1]}: "{value}"{suffix}'
    output = "".join(lines)
    after = yaml.safe_load(output)
    expected = copy.deepcopy(before)
    current = expected
    for key in keys[:-1]:
        current = current[key]
    current[keys[-1]] = value
    if after != expected:
        raise ValueError(f"{path}: fixture pin update changed values outside {'.'.join(keys)}")
    path.write_text(output, encoding="utf-8")


def pin_fixtures(batch: dict[str, Any]) -> None:
    validate_batch(batch, require_complete=True)
    planned: list[tuple[Path, list[str], str]] = []
    for name in FIXTURE_NAMES:
        item = next(component for component in batch["components"] if component["component"] == name)
        release = batch["releases"][name]
        value = f"{release['repository']}@{release['digest']}"
        path = ROOT / item["deploy"]["valuesFile"]
        keys = item["deploy"]["path"]
        values = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(nested(values, keys), str):
            raise ValueError(f"{path}: {'.'.join(keys)} is not an existing string scalar")
        planned.append((path, keys, value))
    for path, keys, value in planned:
        replace_yaml_scalar(path, keys, value)


def git_output(args: list[str]) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()


def image_values(item: dict[str, Any]) -> dict[str, str]:
    path = ROOT / item["deploy"]["valuesFile"]
    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    node = nested(values, item["deploy"]["path"])
    keys = item["deploy"]
    return {key: node[value] for key, value in {
        "repository": keys["repositoryKey"], "tag": keys["tagKey"], "digest": keys["digestKey"],
        **({"source": keys["sourceKey"]} if keys.get("sourceKey") else {}),
    }.items()}


def expected_service_values(
    values: dict[str, Any], item: dict[str, Any], batch: dict[str, Any]
) -> dict[str, Any]:
    expected = copy.deepcopy(values)
    node = nested(expected, item["deploy"]["path"])
    if not isinstance(node, dict):
        raise ValueError(f"service {item['component']} deployment pin target is not a mapping")
    release = batch["releases"][item["component"]]
    fields = {
        "repositoryKey": release["repository"],
        "tagKey": item["image"]["tag"],
        "digestKey": release["digest"],
    }
    if item["deploy"].get("sourceKey"):
        fields["sourceKey"] = batch["source"]
    for contract_key, value in fields.items():
        key = item["deploy"].get(contract_key)
        if not isinstance(key, str) or key not in node:
            raise ValueError(f"service {item['component']} deployment pin key is absent")
        node[key] = value
    return expected


def expected_fixture_values(
    values: dict[str, Any], batch: dict[str, Any], values_file: str
) -> dict[str, Any]:
    expected = copy.deepcopy(values)
    selected = []
    for name in FIXTURE_NAMES:
        item = next(component for component in batch["components"] if component["component"] == name)
        if item["deploy"]["valuesFile"] != values_file:
            continue
        selected.append(name)
        path = item["deploy"]["path"]
        parent = nested(expected, path[:-1])
        if not isinstance(parent, dict) or path[-1] not in parent or not isinstance(parent[path[-1]], str):
            raise ValueError(f"fixture {name} deployment pin scalar is absent")
        release = batch["releases"][name]
        parent[path[-1]] = f"{release['repository']}@{release['digest']}"
    if not selected:
        raise ValueError(f"{values_file} has no exact fixture pin contract")
    return expected


def git_yaml_at_revision(revision: str, path: str) -> dict[str, Any]:
    if not SHA.fullmatch(revision):
        raise ValueError("staging pin diff base is not an exact Git SHA")
    raw = subprocess.run(
        ["git", "show", f"{revision}:{path}"], cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout
    value = yaml.safe_load(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path} at {revision} is not a values mapping")
    return value


def verify_exact_pin_diffs(batch: dict[str, Any], base: str) -> None:
    if base != batch["source"]:
        raise ValueError("staging pin diff base differs from the exact batch source")
    for item in batch["components"][: len(SERVICE_NAMES)]:
        path = item["deploy"]["valuesFile"]
        before = git_yaml_at_revision(base, path)
        current = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
        if current != expected_service_values(before, item, batch):
            raise ValueError(
                f"service {item['component']} values contain changes outside its exact staging image pin"
            )
    fixture_files = {
        item["deploy"]["valuesFile"] for item in batch["components"][len(SERVICE_NAMES):]
    }
    for fixture_path in fixture_files:
        before = git_yaml_at_revision(base, fixture_path)
        current = yaml.safe_load((ROOT / fixture_path).read_text(encoding="utf-8"))
        if current != expected_fixture_values(before, batch, fixture_path):
            raise ValueError(f"{fixture_path} contains changes outside its exact staging fixture pin")


def verify_argocd(target: dict[str, Any]) -> None:
    manifest = yaml.safe_load((ROOT / target["deployment"]["applicationManifest"]).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"apiVersion", "kind", "metadata", "spec"}:
        raise ValueError("Argo service ApplicationSet has an unsupported top-level shape")
    if manifest["apiVersion"] != "argoproj.io/v1alpha1" or manifest["kind"] != "ApplicationSet" or manifest["metadata"] != {"name": "phorvex-services", "namespace": "argocd"}:
        raise ValueError("Argo service ApplicationSet identity changed")
    spec = manifest["spec"]
    if not isinstance(spec, dict) or "templatePatch" in spec or set(spec) != {"goTemplate", "goTemplateOptions", "generators", "template"}:
        raise ValueError("Argo service ApplicationSet permits an unsupported template override")
    if spec["goTemplate"] is not True or spec["goTemplateOptions"] != ["missingkey=error"]:
        raise ValueError("Argo service ApplicationSet template safety changed")
    generators = spec["generators"]
    if not isinstance(generators, list) or len(generators) != 1 or set(generators[0]) != {"matrix"} or set(generators[0]["matrix"]) != {"generators"}:
        raise ValueError("Argo service ApplicationSet generator shape can fan out")
    matrix = generators[0]["matrix"]["generators"]
    if not isinstance(matrix, list) or len(matrix) != 2 or any(not isinstance(item, dict) or set(item) != {"list"} or set(item["list"]) != {"elements"} for item in matrix):
        raise ValueError("Argo service ApplicationSet generator contains an override")
    environments = matrix[0]["list"]["elements"]
    services = matrix[1]["list"]["elements"]
    if environments != [{"environment": "staging", "server": "https://kubernetes.default.svc", "namespace": "phorvex-staging", "release": "staging"}]:
        raise ValueError("Argo service ApplicationSet can fan out beyond the exact staging destination")
    expected_services = [
        {"service": "manager", "chart": "phorvex/charts/phorvex"},
        {"service": "brain", "chart": "deploy/charts/phorvex-brain"},
        {"service": "sensor", "chart": "deploy/charts/phorvex-sensor"},
        {"service": "actuator", "chart": "deploy/charts/phorvex-actuator"},
        {"service": "attacks", "chart": "deploy/charts/phorvex-attacks"},
        {"service": "console", "chart": "deploy/charts/phorvex-console"},
    ]
    if services != expected_services:
        raise ValueError("Argo service ApplicationSet does not cover exactly six services")
    template = spec["template"]
    if not isinstance(template, dict) or set(template) != {"metadata", "spec"}:
        raise ValueError("Argo service ApplicationSet template has an unsupported override")
    template_spec = template["spec"]
    if not isinstance(template_spec, dict) or set(template_spec) != {"project", "sources", "destination", "syncPolicy", "ignoreDifferences"}:
        raise ValueError("Argo service ApplicationSet application spec has an unsupported route")
    if template_spec["project"] != "phorvex-services" or template_spec["destination"] != {"server": "{{.server}}", "namespace": "{{.namespace}}"}:
        raise ValueError("Argo destination bypasses the staging generator")
    sources = template_spec["sources"]
    repository = "https://github.com/PhorvexSecurity/operator-refactored.git"
    expected_value_files = [
        "$values/deploy/environments/{{.environment}}/phorvex.yaml",
        "$values/deploy/environments/{{.environment}}/{{.service}}.yaml",
        "$values/deploy/environments/{{.environment}}/catalogue-family.yaml",
    ]
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("Argo service ApplicationSet must bind exactly chart and values sources")
    chart_source, values_source = sources
    if set(chart_source) != {"repoURL", "targetRevision", "path", "helm"} or chart_source.get("repoURL") != repository or chart_source.get("targetRevision") != "main" or chart_source.get("path") != "{{.chart}}":
        raise ValueError("Argo chart source is not bound to the reviewed repository/main route")
    helm = chart_source.get("helm")
    if not isinstance(helm, dict) or set(helm) != {"releaseName", "skipCrds", "valueFiles"} or helm.get("releaseName") != "{{.release}}" or helm.get("skipCrds") is not True or helm.get("valueFiles") != expected_value_files:
        raise ValueError("Argo service values are not environment/service bound")
    if values_source != {"repoURL": repository, "targetRevision": "main", "ref": "values"}:
        raise ValueError("Argo values source is not bound to the reviewed repository/main route")


def render_fixture(profile: str, workload: str, agent: str) -> list[dict[str, Any]]:
    command = [
        "python3", str(ROOT / "tools/render_catalogue_staging_values.py"), "--profile", profile,
        "--workload-image", workload, "--agent-image", agent,
    ]
    overlay = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True).stdout
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as handle:
        handle.write(overlay)
        handle.flush()
        rendered = subprocess.run([
            "helm", "template", "staging", str(ROOT / "deploy/charts/phorvex-attacks"),
            "--namespace", "phorvex-staging", "--skip-crds",
            "-f", str(ROOT / "deploy/environments/staging/phorvex.yaml"),
            "-f", str(ROOT / "deploy/environments/staging/attacks.yaml"), "-f", handle.name,
        ], cwd=ROOT, check=True, text=True, capture_output=True).stdout
    return [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]


def json_pointer(value: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise ValueError(f"rendered consumer field path {pointer!r} is not a JSON pointer")
    current = value
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise ValueError(f"rendered consumer field path {pointer!r} is absent")
    return current


def pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def pod_spec_locations(value: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    found = []
    if isinstance(value, dict):
        sections = ("containers", "initContainers", "ephemeralContainers")
        volumes = value.get("volumes")
        has_image_volume = isinstance(volumes, list) and any(
            isinstance(volume, dict) and "image" in volume for volume in volumes
        )
        is_pod_spec = any(section in value for section in sections) or has_image_volume
        if is_pod_spec:
            found.append((path, value))
        for key, child in value.items():
            if is_pod_spec and key in (*sections, "volumes"):
                continue
            found.extend(pod_spec_locations(child, f"{path}/{pointer_token(str(key))}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(pod_spec_locations(child, f"{path}/{index}"))
    return found


def consumer_key(consumer: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        consumer["apiVersion"], consumer["kind"], consumer["namespace"], consumer["name"],
        consumer["fieldPath"], consumer["container"],
    )


def rendered_image_consumers(
    documents: list[dict[str, Any]], label: str,
) -> dict[tuple[str, str, str, str, str, str], str]:
    rendered = {}
    for document in documents:
        metadata = document.get("metadata", {})
        locations = pod_spec_locations(document)
        if locations and (
            not isinstance(document.get("apiVersion"), str)
            or not isinstance(document.get("kind"), str)
            or not isinstance(metadata, dict)
            or not isinstance(metadata.get("name"), str)
        ):
            raise ValueError("rendered pod template has no complete apiVersion/kind/name identity")
        for path, pod in locations:
            volumes = pod.get("volumes", [])
            if not isinstance(volumes, list):
                raise ValueError(
                    f"rendered {document['kind']}/{metadata['name']} volumes must be a list"
                )
            for index, volume in enumerate(volumes):
                if not isinstance(volume, dict) or "image" not in volume:
                    continue
                source = volume["image"]
                reference = source.get("reference") if isinstance(source, dict) else None
                detail = reference if isinstance(reference, str) and reference else "malformed reference"
                raise ValueError(
                    f"{label} rendered {document['kind']}/{metadata['name']} image volume "
                    f"at {path}/volumes/{index}/image/reference is unsupported by the release "
                    f"consumer contract: {detail!r}"
                )
            for section in ("containers", "initContainers", "ephemeralContainers"):
                if section not in pod:
                    continue
                entries = pod[section]
                if not isinstance(entries, list) or not entries:
                    raise ValueError(f"rendered {document['kind']}/{metadata['name']} {section} must be a non-empty list")
                names = set()
                for index, container in enumerate(entries):
                    if (
                        not isinstance(container, dict)
                        or not isinstance(container.get("name"), str)
                        or not container["name"]
                        or not isinstance(container.get("image"), str)
                        or not container["image"]
                    ):
                        raise ValueError(f"rendered {document['kind']}/{metadata['name']} {section} has no name/image")
                    if container["name"] in names:
                        raise ValueError(
                            f"rendered {document['kind']}/{metadata['name']} has duplicate {section} "
                            f"container {container['name']!r}"
                        )
                    names.add(container["name"])
                    key = (
                        document["apiVersion"], document["kind"], metadata.get("namespace") or "default",
                        metadata["name"], f"{path}/{section}/{index}/image", container["name"],
                    )
                    if key in rendered:
                        raise ValueError(f"{label} rendered workload consumer is duplicated or ambiguous")
                    rendered[key] = container["image"]
    return rendered


def verify_service_documents(item: dict[str, Any], release: dict[str, str], documents: list[dict[str, Any]]) -> None:
    expected_image = f"{release['repository']}:{item['image']['tag']}@{release['digest']}"
    consumers = item["deploy"]["consumers"]
    if not consumers:
        raise ValueError(f"service {item['component']} has no rendered consumer contract")
    expected_consumers = {consumer_key(consumer) for consumer in consumers}
    if len(expected_consumers) != len(consumers):
        raise ValueError(f"service {item['component']} rendered consumer contract is duplicated")
    rendered = rendered_image_consumers(documents, f"service {item['component']}")
    if set(rendered) != expected_consumers:
        raise ValueError(
            f"service {item['component']} has unexpected rendered image consumers: "
            f"{sorted(set(rendered) - expected_consumers)}"
        )
    for consumer in consumers:
        if consumer.get("component") != item["component"] or consumer.get("expectedRepository") != release["repository"]:
            raise ValueError(f"service {item['component']} rendered consumer repository contract changed")
        actual = rendered[consumer_key(consumer)]
        if actual != expected_image:
            raise ValueError(
                f"service {item['component']} rendered consumer selects {actual!r}, want {expected_image!r}"
            )


def verify_fixture_documents(
    batch: dict[str, Any], name: str, profile: str, documents: list[dict[str, Any]],
    service_selections: dict[str, tuple[dict[str, Any], dict[str, str]]] | None = None,
) -> None:
    item = next(component for component in batch["components"] if component["component"] == name)
    fixture_image = f"{batch['releases'][name]['repository']}@{batch['releases'][name]['digest']}"
    expected = {
        consumer_key(consumer): fixture_image
        for consumer in item["deploy"]["consumers"]
        if consumer["profile"] == profile
    }
    if not expected:
        raise ValueError(f"fixture {name} has no rendered consumer contract for profile {profile}")
    attacks = next(component for component in batch["components"] if component["component"] == "attacks")
    attacks_release = batch["releases"]["attacks"]
    if service_selections and "attacks" in service_selections:
        attacks, attacks_release = service_selections["attacks"]
    attacks_image = (
        f"{attacks_release['repository']}:{attacks['image']['tag']}@{attacks_release['digest']}"
    )
    for consumer in attacks["deploy"]["consumers"]:
        key = consumer_key(consumer)
        if key in expected:
            raise ValueError(f"fixture {name} profile {profile} consumer contract is ambiguous")
        expected[key] = attacks_image
    for consumer in STATIC_PROFILE_CONSUMERS.get(profile, []):
        key = consumer_key(consumer)
        if key in expected:
            raise ValueError(f"fixture {name} profile {profile} static consumer contract is ambiguous")
        expected[key] = consumer["image"]
    rendered = rendered_image_consumers(documents, f"fixture {name} profile {profile}")
    if set(rendered) != set(expected):
        raise ValueError(
            f"fixture {name} profile {profile} has unexpected rendered image consumers: "
            f"{sorted(set(rendered) - set(expected))}"
        )
    for key, wanted in expected.items():
        if rendered[key] != wanted:
            raise ValueError(
                f"fixture {name} profile {profile} rendered consumer {key} "
                f"selects {rendered[key]!r}, want {wanted!r}"
            )


def verify_rendered_service(item: dict[str, Any], release: dict[str, str]) -> None:
    deploy = item["deploy"]
    command = [
        "helm", "template", deploy["releaseName"], str(ROOT / deploy["chart"]),
        "--namespace", deploy["namespace"], "--skip-crds",
        "--api-versions", "monitoring.coreos.com/v1/PodMonitor",
    ]
    for values_file in deploy["valuesFiles"]:
        command.extend(["--values", str(ROOT / values_file)])
    rendered = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True).stdout
    documents = [document for document in yaml.safe_load_all(rendered) if isinstance(document, dict)]
    verify_service_documents(item, release, documents)


def superseding_shared_services(
    shared: Any, isolated_source: str,
) -> dict[str, tuple[dict[str, Any], dict[str, str]]]:
    if not isinstance(shared, dict) or set(shared) != {
        "schema", "status", "source", "environment", "expectedComponents",
        "versions", "components", "releases",
    }:
        raise ValueError("superseding shared batch has an incomplete or unknown contract")
    source = shared.get("source", "")
    names = shared.get("expectedComponents")
    versions = shared.get("versions")
    components = shared.get("components")
    releases = shared.get("releases")
    if (
        shared.get("schema") != 2 or shared.get("status") != "complete"
        or shared.get("environment") != "staging" or not SHA.fullmatch(source)
        or not isinstance(names, list) or not names or not all(isinstance(name, str) for name in names)
        or not isinstance(versions, dict) or not isinstance(components, list)
        or not all(isinstance(item, dict) for item in components)
        or not isinstance(releases, dict)
    ):
        raise ValueError("superseding shared batch is not a complete staging release")
    if source == isolated_source or subprocess.run(
        ["git", "merge-base", "--is-ancestor", isolated_source, source], cwd=ROOT
    ).returncode != 0:
        raise ValueError("superseding shared batch is not newer than the isolated source")
    if (
        names != [item.get("component") for item in components if isinstance(item, dict)]
        or len(names) != len(set(names)) or not set(names).issubset(SERVICE_NAMES)
        or set(versions) != set(names) or set(releases) != set(names)
    ):
        raise ValueError("superseding shared batch component set is malformed")
    selected = {}
    for item in components:
        name = item["component"]
        version = item.get("version")
        image = item.get("image", {})
        identity = item.get("identity", {})
        deploy = item.get("deploy", {})
        released = releases[name]
        expected_repository = f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/{name}"
        if (
            item.get("source") != source or not isinstance(version, str) or not version
            or versions.get(name) != version or not isinstance(image, dict)
            or set(image) != {"registry", "repository", "tag"}
            or image.get("registry") != "753556437180.dkr.ecr.us-east-2.amazonaws.com"
            or image.get("repository") != f"phorvex/{name}"
            or image.get("tag") != version
            or not isinstance(identity, dict) or identity.get("service") != name
            or identity.get("command") != SERVICE_COMMANDS[name] or identity.get("aliases") != []
            or not isinstance(deploy, dict) or not isinstance(deploy.get("consumers"), list)
            or not deploy["consumers"] or not all(isinstance(consumer, dict) for consumer in deploy["consumers"])
            or not isinstance(released, dict) or set(released) != {"repository", "digest"}
            or released.get("repository") != expected_repository
            or not DIGEST.fullmatch(released.get("digest", ""))
        ):
            raise ValueError(f"superseding shared component {name} identity is malformed")
        for consumer in deploy["consumers"]:
            if consumer.get("component") != name or consumer.get("expectedRepository") != expected_repository:
                raise ValueError(f"superseding shared component {name} consumer escapes its repository")
        selected[name] = (item, released)
    return selected


def verify_deployment(
    batch: dict[str, Any], base: str | None, canonical_services: Any,
    superseding_shared: Any | None = None,
) -> None:
    validate_batch(batch, require_complete=True, canonical_services=canonical_services)
    target = expected_target()
    verify_argocd(target)
    shared_services = (
        superseding_shared_services(superseding_shared, batch["source"])
        if superseding_shared is not None else {}
    )
    for item in batch["components"][: len(SERVICE_NAMES)]:
        if item["component"] in shared_services:
            continue
        release = batch["releases"][item["component"]]
        values = image_values(item)
        expected = {"repository": release["repository"], "tag": item["image"]["tag"], "digest": release["digest"]}
        if item["deploy"].get("sourceKey"):
            expected["source"] = batch["source"]
        if values != expected:
            raise ValueError(f"service {item['component']} committed staging pin differs from its release contract")
        verify_rendered_service(item, release)
    fixture_refs = {}
    for name in FIXTURE_NAMES:
        item = next(component for component in batch["components"] if component["component"] == name)
        expected = f"{batch['releases'][name]['repository']}@{batch['releases'][name]['digest']}"
        values = yaml.safe_load((ROOT / item["deploy"]["valuesFile"]).read_text(encoding="utf-8"))
        if nested(values, item["deploy"]["path"]) != expected:
            raise ValueError(f"fixture {name} committed staging pin differs from its release contract")
        fixture_refs[name] = expected
    for name in FIXTURE_NAMES:
        item = next(component for component in batch["components"] if component["component"] == name)
        profiles = list(dict.fromkeys(consumer["profile"] for consumer in item["deploy"]["consumers"]))
        for profile in profiles:
            documents = render_fixture(
                profile, fixture_refs["catalogue-workload"], fixture_refs["agent-sim"]
            )
            verify_fixture_documents(batch, name, profile, documents, shared_services)
    if base:
        changed = set(filter(None, git_output(["diff", "--name-only", base, "--"]).splitlines()))
        allowed = {"release/staging-batch.json"}
        allowed.update(item["deploy"]["valuesFile"] for item in batch["components"])
        if not changed or not changed.issubset(allowed):
            raise ValueError(f"staging pin diff contains non-staging/production paths: {sorted(changed - allowed)}")
        verify_exact_pin_diffs(batch, base)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--source", required=True)
    prepare_parser.add_argument("--services", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    complete_parser = sub.add_parser("complete")
    complete_parser.add_argument("--batch", type=Path, required=True)
    complete_parser.add_argument("--results", type=Path, required=True)
    complete_parser.add_argument("--services", type=Path, required=True)
    complete_parser.add_argument("--output", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--batch", type=Path, required=True)
    verify_parser.add_argument("--services", type=Path, required=True)
    verify_parser.add_argument("--complete", action="store_true")
    pin_parser = sub.add_parser("pin-fixtures")
    pin_parser.add_argument("--batch", type=Path, required=True)
    deploy_parser = sub.add_parser("verify-deployment")
    deploy_parser.add_argument("--batch", type=Path, required=True)
    deploy_parser.add_argument("--services", type=Path, required=True)
    deploy_parser.add_argument("--base")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            write_json(args.output, prepare(args.source, args.services))
        elif args.command == "complete":
            services = read_json(args.services)
            value = validate_batch(read_json(args.batch), require_complete=False, canonical_services=services)
            write_json(args.output, complete(value, read_json(args.results), services))
        elif args.command == "verify":
            validate_batch(
                read_json(args.batch),
                require_complete=True if args.complete else None,
                canonical_services=read_json(args.services),
            )
        elif args.command == "pin-fixtures":
            pin_fixtures(validate_batch(read_json(args.batch), require_complete=True))
        elif args.command == "verify-deployment":
            services = read_json(args.services)
            value = validate_batch(read_json(args.batch), require_complete=True, canonical_services=services)
            verify_deployment(value, args.base, services)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
