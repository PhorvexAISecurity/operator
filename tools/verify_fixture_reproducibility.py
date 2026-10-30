#!/usr/bin/env python3
"""Build fixture images twice and compare their complete OCI identities."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    "agent-sim": {
        "directory": "agentsim",
        "sources": ("Dockerfile", "go.mod", "main.go"),
        "files": {"agent-sim"},
    },
    "catalogue-workload": {
        "directory": "catalogue-workload",
        "sources": ("Dockerfile", "server.py", "curl"),
        "files": {"opt/catalogue/server.py", "usr/local/bin/curl"},
    },
}
SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
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
    path = blob(layout, descriptor.get("digest", ""))
    raw = path.read_bytes()
    if digest(raw) != descriptor["digest"] or len(raw) != descriptor.get("size"):
        raise ValueError(f"OCI descriptor does not match {path}")
    return raw


def image_identity(layout: Path, epoch: int, fixture: str) -> dict:
    layout_doc = json.loads((layout / "oci-layout").read_text(encoding="utf-8"))
    if layout_doc != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError(f"unexpected OCI layout metadata: {layout_doc}")
    index_raw = (layout / "index.json").read_bytes()
    index = json.loads(index_raw)
    if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
        raise ValueError("fixture OCI output must contain exactly one image manifest")
    manifest_descriptor = index["manifests"][0]
    manifest_raw = checked_blob(layout, manifest_descriptor)
    manifest = json.loads(manifest_raw)
    if manifest.get("schemaVersion") != 2 or not manifest.get("layers"):
        raise ValueError("fixture OCI image has no layers")
    config_raw = checked_blob(layout, manifest["config"])
    config = json.loads(config_raw)
    expected_created = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    if config.get("created") != expected_created:
        raise ValueError(
            f"{fixture} config created={config.get('created')!r}, want {expected_created!r}"
        )
    for descriptor in manifest["layers"]:
        checked_blob(layout, descriptor)
    check_application_layer(layout, manifest["layers"][-1], epoch, fixture)
    return {
        "index": digest(index_raw),
        "manifest": manifest_descriptor["digest"],
        "config": manifest["config"]["digest"],
        "layers": [descriptor["digest"] for descriptor in manifest["layers"]],
        "layerMediaTypes": [descriptor["mediaType"] for descriptor in manifest["layers"]],
        "platform": {
            "architecture": config.get("architecture"),
            "os": config.get("os"),
        },
    }


def check_application_layer(
    layout: Path, descriptor: dict, epoch: int, fixture: str
) -> None:
    expected_files = FIXTURES[fixture]["files"]
    with tarfile.open(blob(layout, descriptor["digest"]), mode="r:*") as archive:
        members = archive.getmembers()
    names = [member.name.removeprefix("./").rstrip("/") for member in members]
    if names != sorted(names):
        raise ValueError(f"{fixture} application layer entries are not ordered")
    found = set()
    for member, name in zip(members, names, strict=True):
        if member.uid != 0 or member.gid != 0 or int(member.mtime) != epoch:
            raise ValueError(
                f"{fixture} layer metadata drift for {name}: "
                f"uid={member.uid} gid={member.gid} mtime={member.mtime}"
            )
        if name in expected_files:
            found.add(name)
            if not member.isfile() or member.mode & 0o7777 != 0o555:
                raise ValueError(f"{fixture} file metadata is not root:root 0555: {name}")
        elif member.isdir() and member.mode & 0o7777 != 0o755:
            raise ValueError(f"{fixture} directory mode is not 0755: {name}")
    if found != expected_files:
        raise ValueError(f"{fixture} application files missing: {sorted(expected_files - found)}")


def clean_context(destination: Path, fixture: str, epoch: int) -> Path:
    spec = FIXTURES[fixture]
    source = ROOT / "farm-fixtures" / spec["directory"]
    target = destination / "farm-fixtures" / spec["directory"]
    target.mkdir(parents=True)
    for name in spec["sources"]:
        output = target / name
        shutil.copyfile(source / name, output)
        output.chmod(0o644)
        os.utime(output, (epoch, epoch))
    directory = target
    while directory != destination.parent:
        directory.chmod(0o755)
        os.utime(directory, (epoch, epoch))
        directory = directory.parent
    return target / "Dockerfile"


def build(
    fixture: str, run: int, workspace: Path, epoch: int, builder: str
) -> dict:
    context = workspace / f"{fixture}-context-{run}"
    dockerfile = clean_context(context, fixture, epoch)
    archive = workspace / f"{fixture}-{run}.oci.tar"
    layout = workspace / f"{fixture}-{run}.oci"
    output = ",".join(
        (
            "type=oci",
            f"dest={archive}",
            "oci-mediatypes=true",
            "compression=gzip",
            "compression-level=9",
            "force-compression=true",
        )
    )
    command = [
        "docker",
        "buildx",
        "build",
        "--builder",
        builder,
        "--no-cache",
        "--pull",
        "--file",
        str(dockerfile),
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--provenance=false",
        "--sbom=false",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={epoch}",
        "--output",
        output,
        "--tag",
        f"phorvex.invalid/{fixture}:reproducibility-check",
        str(context),
    ]
    print(f"building {fixture} clean run {run}", flush=True)
    subprocess.run(command, check=True)
    layout.mkdir()
    with tarfile.open(archive, mode="r:") as oci_archive:
        oci_archive.extractall(layout, filter="data")
    return image_identity(layout, epoch, fixture)


def create_builder() -> str:
    name = "phorvex-fixture-repro-" + uuid.uuid4().hex[:12]
    subprocess.run(
        [
            "docker",
            "buildx",
            "create",
            "--name",
            name,
            "--driver",
            "docker-container",
            "--driver-opt",
            f"image={BUILDKIT_IMAGE}",
            "--bootstrap",
        ],
        check=True,
    )
    return name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-date-epoch",
        default=os.environ.get("SOURCE_DATE_EPOCH", "0"),
        help="non-negative timestamp applied to all fixture-owned OCI metadata (default: 0)",
    )
    parser.add_argument("--builder", default=os.environ.get("BUILDX_BUILDER"))
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.source_date_epoch):
        parser.error("--source-date-epoch must be an unsigned integer")
    epoch = int(args.source_date_epoch)
    owned_builder = not args.builder
    builder = args.builder or create_builder()
    try:
        with tempfile.TemporaryDirectory(
            prefix="fixture-reproducibility-", dir=ROOT.parent
        ) as temporary:
            workspace = Path(temporary)
            for fixture in FIXTURES:
                first = build(fixture, 1, workspace, epoch, builder)
                second = build(fixture, 2, workspace, epoch, builder)
                if first != second:
                    print(
                        json.dumps(
                            {"fixture": fixture, "first": first, "second": second},
                            indent=2,
                            sort_keys=True,
                        )
                    )
                    raise SystemExit(
                        f"{fixture} OCI identity drifted between clean builds"
                    )
                print(
                    json.dumps(
                        {"fixture": fixture, "runs": 2, **first},
                        sort_keys=True,
                    ),
                    flush=True,
                )
    finally:
        if owned_builder:
            subprocess.run(["docker", "buildx", "rm", builder], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
