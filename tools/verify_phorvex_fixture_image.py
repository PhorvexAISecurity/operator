#!/usr/bin/env python3
"""Prove the phorvex catalogue fixture image is the exact reviewed, non-root,
reproducible multi-binary artifact the serving-rate/serving-kv/datastore families select.

Two modes:

  inspect   Given one locally built image, assert its embedded identity (labels, user,
            entrypoint, platform) and that it carries exactly the three fixture binaries
            at absolute paths with root:root 0555 permissions. Used by PR validation,
            which builds the image once from candidate source without pushing.

  reproduce Build the image twice from a clean context with a fixed SOURCE_DATE_EPOCH and
            require byte-identical OCI identities (index, manifest, config, application
            layer), the exact three-binary application layer, and the embedded config
            identity. Used by the dedicated publish workflow before anything is pushed.

The image is NEVER part of the locked eight-component staging-isolated-release batch; it
is published to its own immutable repository and consumed only by digest through
`render_catalogue_staging_values.py --phorvex-image` (see release/staging-phorvex-fixture.json).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_FILE = ROOT / "release/staging-phorvex-fixture.json"
SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9A-Za-z.+-]+$")
# The three fixture binaries, at the absolute paths the chart's `command:` selects,
# in the documented command order (ragstore target, admission proxy, load detector).
EXPECTED_BINARIES = ("ragstore-fixture", "cost-admission", "cost-load-detector")
DEFAULT_ENTRYPOINT = ["/ragstore-fixture"]
BUILDKIT_IMAGE = (
    "moby/buildkit:v0.33.1@"
    "sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def blob(layout: Path, value: str) -> Path:
    match = SHA256.fullmatch(value)
    if not match:
        raise ValueError(f"malformed OCI digest: {value!r}")
    return layout / "blobs" / "sha256" / match.group(1)


def checked_blob(layout: Path, descriptor: dict) -> bytes:
    raw = blob(layout, descriptor.get("digest", "")).read_bytes()
    if digest(raw) != descriptor["digest"] or len(raw) != descriptor.get("size"):
        raise ValueError("OCI descriptor does not match its blob")
    return raw


def load_authority() -> dict:
    authority = json.loads(AUTHORITY_FILE.read_text(encoding="utf-8"))
    commands = authority.get("identity", {}).get("commands")
    if authority.get("schema") != 1 or authority.get("name") != "staging-phorvex-fixture":
        raise ValueError("release/staging-phorvex-fixture.json is not the reviewed authority")
    if commands != [f"/{name}" for name in EXPECTED_BINARIES]:
        raise ValueError("fixture command authority does not match the three reviewed binaries")
    if authority.get("identity", {}).get("entrypoint") != DEFAULT_ENTRYPOINT:
        raise ValueError("fixture default entrypoint authority changed")
    return authority


def application_layer_binaries(layout: Path, descriptor: dict, epoch: int) -> list[str]:
    with tarfile.open(blob(layout, descriptor["digest"]), mode="r:*") as archive:
        members = archive.getmembers()
    names = [member.name.removeprefix("./").rstrip("/") for member in members]
    if names != sorted(names):
        raise ValueError("fixture application layer entries are not ordered")
    found = []
    for member, name in zip(members, names, strict=True):
        if member.uid != 0 or member.gid != 0 or int(member.mtime) != epoch:
            raise ValueError(
                f"fixture layer metadata drift for {name}: uid={member.uid} "
                f"gid={member.gid} mtime={member.mtime}"
            )
        if name in EXPECTED_BINARIES:
            if not member.isfile() or member.mode & 0o7777 != 0o555:
                raise ValueError(f"fixture binary is not root:root 0555: {name}")
            found.append(name)
        elif member.isdir() and member.mode & 0o7777 != 0o755:
            raise ValueError(f"fixture directory mode is not 0755: {name}")
        elif member.isfile():
            raise ValueError(f"fixture application layer carries an unexpected file: {name}")
    if sorted(found) != sorted(EXPECTED_BINARIES):
        raise ValueError(
            f"fixture application layer binaries are {sorted(found)}, want {list(EXPECTED_BINARIES)}"
        )
    return sorted(found)


def assert_config_identity(config: dict, git_sha: str, version: str) -> None:
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError(
            f"fixture image platform is {config.get('os')}/{config.get('architecture')}, want linux/amd64"
        )
    cfg = config.get("config", {})
    if cfg.get("User") != "65532:65532":
        raise ValueError(f"fixture image runs as {cfg.get('User')!r}, want 65532:65532")
    if cfg.get("Entrypoint") != DEFAULT_ENTRYPOINT:
        raise ValueError(f"fixture image entrypoint is {cfg.get('Entrypoint')!r}, want {DEFAULT_ENTRYPOINT}")
    labels = cfg.get("Labels") or {}
    expected_labels = {
        "org.opencontainers.image.revision": git_sha,
        "org.opencontainers.image.version": version,
        "ai.phorvex.fixture.commands": ",".join(f"/{name}" for name in EXPECTED_BINARIES),
    }
    for key, want in expected_labels.items():
        if labels.get(key) != want:
            raise ValueError(f"fixture image label {key}={labels.get(key)!r}, want {want!r}")


def oci_identity(layout: Path, epoch: int, git_sha: str, version: str) -> dict:
    if json.loads((layout / "oci-layout").read_text(encoding="utf-8")) != {
        "imageLayoutVersion": "1.0.0"
    }:
        raise ValueError("unexpected OCI layout metadata")
    index_raw = (layout / "index.json").read_bytes()
    index = json.loads(index_raw)
    if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
        raise ValueError("fixture OCI output must contain exactly one image manifest")
    manifest_descriptor = index["manifests"][0]
    manifest = json.loads(checked_blob(layout, manifest_descriptor))
    if manifest.get("schemaVersion") != 2 or not manifest.get("layers"):
        raise ValueError("fixture OCI image has no layers")
    config = json.loads(checked_blob(layout, manifest["config"]))
    expected_created = (
        dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    )
    if config.get("created") != expected_created:
        raise ValueError(f"fixture config created={config.get('created')!r}, want {expected_created!r}")
    for descriptor in manifest["layers"]:
        checked_blob(layout, descriptor)
    assert_config_identity(config, git_sha, version)
    binaries = application_layer_binaries(layout, manifest["layers"][-1], epoch)
    return {
        "index": digest(index_raw),
        "manifest": manifest_descriptor["digest"],
        "config": manifest["config"]["digest"],
        "applicationLayer": manifest["layers"][-1]["digest"],
        "layers": [descriptor["digest"] for descriptor in manifest["layers"]],
        "binaries": binaries,
        "platform": {"architecture": config.get("architecture"), "os": config.get("os")},
    }


def build_oci(workspace: Path, run: int, epoch: int, git_sha: str, version: str, builder: str) -> dict:
    archive = workspace / f"phorvex-fixture-{run}.oci.tar"
    layout = workspace / f"phorvex-fixture-{run}.oci"
    output = ",".join(
        (
            f"type=oci,dest={archive}",
            "oci-mediatypes=true",
            "compression=gzip",
            "compression-level=9",
            "force-compression=true",
            "rewrite-timestamp=true",
        )
    )
    command = [
        "docker", "buildx", "build",
        "--builder", builder,
        "--no-cache", "--pull",
        "--file", str(ROOT / "deploy/docker/phorvex-fixture.Dockerfile"),
        "--platform", "linux/amd64",
        "--provenance=false", "--sbom=false",
        "--build-arg", f"SOURCE_DATE_EPOCH={epoch}",
        "--build-arg", f"GIT_SHA={git_sha}",
        "--build-arg", f"RELEASE_VERSION={version}",
        "--output", output,
        "--tag", "phorvex.invalid/phorvex-fixture:reproducibility-check",
        str(ROOT),
    ]
    print(f"building phorvex fixture clean run {run}", flush=True)
    subprocess.run(command, check=True, env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)})
    layout.mkdir()
    with tarfile.open(archive, mode="r:") as oci_archive:
        oci_archive.extractall(layout, filter="data")
    return oci_identity(layout, epoch, git_sha, version)


def reproduce(args: argparse.Namespace) -> int:
    load_authority()
    epoch = int(args.source_date_epoch)
    with tempfile.TemporaryDirectory(prefix="phorvex-fixture-repro-", dir=ROOT.parent) as tmp:
        workspace = Path(tmp)
        first = build_oci(workspace, 1, epoch, args.git_sha, args.release_version, args.builder)
        second = build_oci(workspace, 2, epoch, args.git_sha, args.release_version, args.builder)
    if first != second:
        print(json.dumps({"first": first, "second": second}, indent=2, sort_keys=True))
        raise SystemExit("phorvex fixture OCI identity drifted between clean builds")
    print(json.dumps({"runs": 2, **first}, sort_keys=True), flush=True)
    return 0


def inspect(args: argparse.Namespace) -> int:
    load_authority()
    inspected = json.loads(subprocess.run(
        ["docker", "image", "inspect", args.image], check=True, text=True, stdout=subprocess.PIPE
    ).stdout)
    if len(inspected) != 1:
        raise SystemExit(f"expected exactly one local image for {args.image}")
    image = inspected[0]
    config = {
        "os": image.get("Os"),
        "architecture": image.get("Architecture"),
        "config": {
            "User": image.get("Config", {}).get("User"),
            "Entrypoint": image.get("Config", {}).get("Entrypoint"),
            "Labels": image.get("Config", {}).get("Labels") or {},
        },
    }
    assert_config_identity(config, args.git_sha, args.release_version)
    found: dict[str, tuple[int, int, int]] = {}
    with tempfile.TemporaryDirectory(prefix="phorvex-fixture-export-") as tmp:
        tar_path = Path(tmp) / "rootfs.tar"
        container = subprocess.run(
            ["docker", "create", args.image], check=True, text=True, stdout=subprocess.PIPE
        ).stdout.strip()
        try:
            with open(tar_path, "wb") as handle:
                subprocess.run(["docker", "export", container], check=True, stdout=handle)
        finally:
            subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
        with tarfile.open(tar_path, mode="r:*") as archive:
            for member in archive.getmembers():
                name = member.name.removeprefix("./").rstrip("/")
                if name in EXPECTED_BINARIES and member.isfile():
                    found[name] = (member.mode & 0o7777, member.uid, member.gid)
    for name in EXPECTED_BINARIES:
        if name not in found:
            raise SystemExit(f"fixture image is missing the /{name} binary")
        mode, uid, gid = found[name]
        if mode != 0o555 or uid != 0 or gid != 0:
            raise SystemExit(f"/{name} is not root:root 0555 (mode={oct(mode)} uid={uid} gid={gid})")
    print(json.dumps({
        "image": args.image,
        "imageID": image.get("Id"),
        "gitSHA": args.git_sha,
        "version": args.release_version,
        "platform": "linux/amd64",
        "user": "65532:65532",
        "binaries": [f"/{name}" for name in EXPECTED_BINARIES],
    }, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect_parser = sub.add_parser("inspect")
    inspect_parser.add_argument("--image", required=True)
    inspect_parser.add_argument("--git-sha", required=True)
    inspect_parser.add_argument("--release-version", required=True)
    reproduce_parser = sub.add_parser("reproduce")
    reproduce_parser.add_argument("--git-sha", required=True)
    reproduce_parser.add_argument("--release-version", required=True)
    reproduce_parser.add_argument("--source-date-epoch", default="0")
    reproduce_parser.add_argument("--builder", default=os.environ.get("BUILDX_BUILDER"))
    args = parser.parse_args()
    if not GIT_SHA.fullmatch(args.git_sha):
        parser.error("--git-sha must be a 40-character lowercase hexadecimal SHA")
    if not VERSION.fullmatch(args.release_version):
        parser.error("--release-version is malformed")
    try:
        if args.command == "reproduce":
            if not re.fullmatch(r"[0-9]+", args.source_date_epoch):
                parser.error("--source-date-epoch must be an unsigned integer")
            if not args.builder:
                parser.error("reproduce requires --builder or $BUILDX_BUILDER")
            return reproduce(args)
        return inspect(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
