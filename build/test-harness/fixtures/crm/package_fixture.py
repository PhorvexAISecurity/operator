#!/usr/bin/env python3
"""Prepare the fixed CRM image context or its digest-pinned owner manifest.

Preparation never builds an image or contacts a registry or Kubernetes. Only the
explicit --download mode contacts the Python package index.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
REVIEWED_WHEELS = "reviewed-wheelhouse.sha256"
SOURCE_HASHES = {
    "Dockerfile": "59fc1f05abf977496fa97bc3ba5a031599cf2b866b9d3de4b6034cfe6050c314",
    "app.py": "328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350",
    "dependencies.lock.json": "50143dfea339319c70edcc4e37c5d852031446f5e609ef4f538c68a0436f956a",
    "requirements.pinned.txt": "b4799a631bd9963ff3f34b791981931a0c4000e0ee0104a9e0f706339fda8f6b",
    "verify_runtime_closure.py": "b87299b97215ced3a9c89f18c2d350767b2a202cf131fa604deb7f3ffd81b2a2",
    "verify_wheelhouse.py": "a89c3989fdddc3c4d86bb17a6ae90c5cad021a623f0966835b7e7b8962f5d996",
}
WHEEL_MANIFEST_SHA256 = "ae935ca590efe1dbc41fbd81e6f7c79940a1d1a6db6e808d42d834879fc06070"
BASE_IMAGE = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
DEPENDENCIES = {"fastapi": "0.115.14", "pydantic": "2.13.4", "pymongo": "4.17.0", "uvicorn": "0.30.6"}
IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")


class PackageError(Exception):
    pass


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def regular_file(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise PackageError(f"required file missing: {path.name}") from error
    if not stat.S_ISREG(mode):
        raise PackageError(f"required file is not regular: {path.name}")


def reviewed_source():
    hashes = {}
    for name, expected in SOURCE_HASHES.items():
        path = HERE / name
        regular_file(path)
        actual = sha256(path)
        if actual != expected:
            raise PackageError(f"reviewed fixture source differs: {name}")
        hashes[name] = actual
    manifest = HERE / REVIEWED_WHEELS
    regular_file(manifest)
    if sha256(manifest) != WHEEL_MANIFEST_SHA256:
        raise PackageError("reviewed wheel checksum manifest differs")
    return hashes


def wheel_inventory(wheel_dir):
    try:
        mode = wheel_dir.lstat().st_mode
    except FileNotFoundError as error:
        raise PackageError("wheel directory missing") from error
    if not stat.S_ISDIR(mode):
        raise PackageError("wheel input must be a real directory")
    entries = list(wheel_dir.iterdir())
    if len(entries) != 18:
        raise PackageError("wheel input must contain exactly 18 files")
    inventory = {}
    for entry in entries:
        regular_file(entry)
        if not entry.name.endswith(".whl") or entry.stat().st_size > 16 << 20:
            raise PackageError("wheel input name or size invalid")
        inventory[entry.name] = sha256(entry)
    return dict(sorted(inventory.items()))


def verify_wheels(wheel_dir, manifest):
    inventory = wheel_inventory(wheel_dir)
    try:
        completed = subprocess.run(
            [sys.executable, str(HERE / "verify_wheelhouse.py"),
             str(HERE / "requirements.pinned.txt"), str(manifest), str(wheel_dir)],
            check=True, capture_output=True, text=True, timeout=45,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise PackageError("exact 18-wheel verifier refused input") from error
    if completed.stdout.strip() != "verified 18 offline wheel SHA-256 pins":
        raise PackageError("exact 18-wheel verifier returned unexpected receipt")
    return inventory


def download_command(python, wheel_dir):
    return [python, "-m", "pip", "download", "--index-url", "https://pypi.org/simple",
            "--only-binary=:all:", "--no-deps", "--no-cache-dir",
            "--implementation", "cp", "--python-version", "311", "--abi", "cp311",
            "--platform", "manylinux2014_x86_64", "--dest", str(wheel_dir),
            "-r", str(HERE / "requirements.pinned.txt")]


def download_wheels(python, wheel_dir):
    try:
        version = subprocess.run([python, "--version"], check=True, capture_output=True,
                                 text=True, timeout=10)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise PackageError("Python 3.11 download interpreter unavailable") from error
    if not (version.stdout + version.stderr).startswith("Python 3.11."):
        raise PackageError("explicit wheel download requires Python 3.11")
    try:
        subprocess.run(download_command(python, wheel_dir), check=True,
                       capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise PackageError("pinned binary wheel download failed") from error


def new_output(path):
    if not path.is_absolute():
        raise PackageError("output path must be absolute")
    if path.exists() or path.is_symlink():
        raise PackageError("output destination already exists")
    if not path.parent.is_dir():
        raise PackageError("output parent directory does not exist")


def write_exclusive(path, data):
    with path.open("xb") as out:
        os.chmod(path, 0o600)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def canonical_json(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def prepare(output, wheel_dir=None, download=False, python="python3.11"):
    new_output(output)
    source_hashes = reviewed_source()
    if download == (wheel_dir is not None):
        raise PackageError("select exactly one of --wheels or --download")
    with tempfile.TemporaryDirectory(prefix=".crm-wheels-", dir=output.parent) as temporary:
        if download:
            wheel_dir = Path(temporary) / "wheelhouse"
            wheel_dir.mkdir(mode=0o700)
            download_wheels(python, wheel_dir)
        inventory = verify_wheels(wheel_dir, HERE / REVIEWED_WHEELS)
        # mkdir refuses an existing destination even if one appeared during validation.
        try:
            output.mkdir(mode=0o700)
        except FileExistsError as error:
            raise PackageError("output destination already exists") from error
        try:
            os.chmod(output, 0o700)
            for name in SOURCE_HASHES:
                shutil.copyfile(HERE / name, output / name)
            shutil.copyfile(HERE / REVIEWED_WHEELS, output / "wheelhouse.sha256")
            (output / "wheelhouse").mkdir(mode=0o700)
            for name in inventory:
                shutil.copyfile(wheel_dir / name, output / "wheelhouse" / name)
            if reviewed_source() != source_hashes or sha256(output / "wheelhouse.sha256") != WHEEL_MANIFEST_SHA256:
                raise PackageError("source changed while preparing context")
            if verify_wheels(output / "wheelhouse", output / "wheelhouse.sha256") != inventory:
                raise PackageError("wheel input changed while preparing context")
            for name, expected in source_hashes.items():
                if sha256(output / name) != expected:
                    raise PackageError("copied source differs")
            receipt = {
                "schema": "phorvex.crm-build-context.v1",
                "platform": "linux/amd64",
                "python": "3.11",
                "sourceFiles": source_hashes,
                "wheelhouseManifestSHA256": WHEEL_MANIFEST_SHA256,
                "wheelFiles": inventory,
                "wheelCount": 18,
                "imageBuilt": False,
                "registryDigest": None,
            }
            write_exclusive(output / "preparation-receipt.json", canonical_json(receipt))
        except BaseException:
            shutil.rmtree(output)
            raise
    return output / "preparation-receipt.json"


def manifest(output, crm_image, mongo_image):
    if not output.is_absolute():
        raise PackageError("manifest output path must be absolute")
    if not output.parent.is_dir():
        raise PackageError("manifest output parent directory does not exist")
    if not IMAGE_REF.fullmatch(crm_image) or not IMAGE_REF.fullmatch(mongo_image):
        raise PackageError("both images must be immutable repository@sha256 digests")
    reviewed_source()
    document = {
        "schema": "phorvex.crm-fixture.v1",
        "crmImage": crm_image,
        "mongoImage": mongo_image,
        "baseImageDigest": BASE_IMAGE,
        "sourceSHA256": SOURCE_HASHES["app.py"],
        "dependencyLockSHA256": SOURCE_HASHES["dependencies.lock.json"],
        "wheelhouseManifestSHA256": WHEEL_MANIFEST_SHA256,
        "dependencies": DEPENDENCIES,
    }
    raw = canonical_json(document)
    try:
        write_exclusive(output, raw)
    except FileExistsError as error:
        raise PackageError("manifest output already exists") from error
    return sha256(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="prepare an exact private Docker build context")
    prep.add_argument("--out", required=True, type=Path)
    inputs = prep.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--wheels", type=Path)
    inputs.add_argument("--download", action="store_true")
    prep.add_argument("--python", default="python3.11", help="Python 3.11 used only with --download")
    owner = commands.add_parser("manifest", help="write the fixed owner manifest")
    owner.add_argument("--out", required=True, type=Path)
    owner.add_argument("--crm-image", required=True)
    owner.add_argument("--mongo-image", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args.out, args.wheels, args.download, args.python)
            print(f"prepared exact CRM context; receipt: {result}")
        else:
            digest = manifest(args.out, args.crm_image, args.mongo_image)
            print(f"owner manifest SHA-256: {digest}")
    except (PackageError, OSError) as error:
        parser.exit(2, f"CRM package refused: {error}\n")


if __name__ == "__main__":
    main()
