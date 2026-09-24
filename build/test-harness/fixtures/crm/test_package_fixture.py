"""Real filesystem controls for the reviewed CRM build package."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import package_fixture as package


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PackageFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        for name in package.SOURCE_HASHES:
            shutil.copyfile(package.HERE / name, self.fixture / name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        for line in (self.fixture / "requirements.pinned.txt").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, version = line.split("==")
            filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
            (self.wheels / filename).write_bytes(("test wheel " + filename).encode())
        manifest = "".join(
            f"{package.sha256(path)}  {path.name}\n" for path in sorted(self.wheels.iterdir())
        ).encode()
        (self.fixture / package.REVIEWED_WHEELS).write_bytes(manifest)
        self.patches = [
            mock.patch.object(package, "HERE", self.fixture),
            mock.patch.object(package, "WHEEL_MANIFEST_SHA256", digest(manifest)),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_complete_context_is_private_exact_and_has_no_registry_claim(self):
        output = self.root / "context"
        receipt_path = package.prepare(output, wheel_dir=self.wheels)
        self.assertEqual(receipt_path, output / "preparation-receipt.json")
        self.assertEqual(
            {path.name for path in output.iterdir()},
            set(package.SOURCE_HASHES) | {"wheelhouse.sha256", "wheelhouse", "preparation-receipt.json"},
        )
        self.assertEqual({path.name for path in (output / "wheelhouse").iterdir()},
                         {path.name for path in self.wheels.iterdir()})
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["schema"], "phorvex.crm-build-context.v1")
        self.assertEqual(receipt["platform"], "linux/amd64")
        self.assertEqual(receipt["wheelCount"], 18)
        self.assertEqual(receipt["wheelhouseManifestSHA256"], package.WHEEL_MANIFEST_SHA256)
        self.assertEqual(receipt["sourceFiles"], package.SOURCE_HASHES)
        self.assertEqual(receipt["registryDigest"], None)
        self.assertEqual(receipt["imageBuilt"], False)
        self.assertEqual(package.verify_wheels(output / "wheelhouse", output / "wheelhouse.sha256"),
                         receipt["wheelFiles"])

    def test_missing_extra_and_corrupt_wheels_refuse_before_output(self):
        for mutation in ("missing", "extra", "corrupt"):
            with self.subTest(mutation=mutation):
                wheel_dir = self.root / ("wheels-" + mutation)
                shutil.copytree(self.wheels, wheel_dir)
                first = sorted(wheel_dir.iterdir())[0]
                if mutation == "missing":
                    first.unlink()
                elif mutation == "extra":
                    (wheel_dir / "extra-1-py3-none-any.whl").write_bytes(b"extra")
                else:
                    first.write_bytes(b"changed archive bytes")
                output = self.root / ("out-" + mutation)
                with self.assertRaises(package.PackageError):
                    package.prepare(output, wheel_dir=wheel_dir)
                self.assertFalse(output.exists())

    def test_symlink_and_nonregular_wheel_inputs_refuse(self):
        symlink_dir = self.root / "wheel-dir-link"
        symlink_dir.symlink_to(self.wheels, target_is_directory=True)
        with self.assertRaisesRegex(package.PackageError, "real directory"):
            package.prepare(self.root / "out-dir-link", wheel_dir=symlink_dir)
        for mutation in ("symlink", "fifo"):
            with self.subTest(mutation=mutation):
                wheel_dir = self.root / ("wheel-" + mutation)
                shutil.copytree(self.wheels, wheel_dir)
                first = sorted(wheel_dir.iterdir())[0]
                first.unlink()
                if mutation == "symlink":
                    first.symlink_to(sorted(wheel_dir.iterdir())[0])
                else:
                    os.mkfifo(first)
                with self.assertRaises(package.PackageError):
                    package.prepare(self.root / ("out-" + mutation), wheel_dir=wheel_dir)

    def test_existing_destination_is_preserved(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "unrelated.txt"
        sentinel.write_text("preserve me")
        with self.assertRaisesRegex(package.PackageError, "already exists"):
            package.prepare(output, wheel_dir=self.wheels)
        self.assertEqual(sentinel.read_text(), "preserve me")

    def test_source_lock_and_manifest_drift_refuse(self):
        for name in ("app.py", "dependencies.lock.json", package.REVIEWED_WHEELS):
            with self.subTest(name=name):
                path = self.fixture / name
                original = path.read_bytes()
                path.write_bytes(original + b"\nchanged\n")
                try:
                    with self.assertRaises(package.PackageError):
                        package.prepare(self.root / ("out-" + name.replace(".", "-")), wheel_dir=self.wheels)
                finally:
                    path.write_bytes(original)

        source = self.fixture / "app.py"
        original = source.read_bytes()
        source.unlink()
        target = self.root / "app-copy.py"
        target.write_bytes(original)
        source.symlink_to(target)
        with self.assertRaisesRegex(package.PackageError, "not regular"):
            package.prepare(self.root / "out-source-link", wheel_dir=self.wheels)

    def test_explicit_download_branch_uses_same_verifier_without_network(self):
        output = self.root / "download-context"

        def supply_retained_shape(_python, destination):
            for wheel in self.wheels.iterdir():
                shutil.copyfile(wheel, destination / wheel.name)

        with mock.patch.object(package, "download_wheels", side_effect=supply_retained_shape) as download:
            package.prepare(output, download=True)
        download.assert_called_once()
        self.assertEqual(len(list((output / "wheelhouse").iterdir())), 18)

    def test_download_argv_is_binary_only_fixed_platform_and_official_index(self):
        argv = package.download_command("python3.11", self.root / "wheelhouse")
        self.assertEqual(argv[:4], ["python3.11", "-m", "pip", "download"])
        for flag, value in (("--index-url", "https://pypi.org/simple"),
                            ("--implementation", "cp"), ("--python-version", "311"),
                            ("--abi", "cp311"), ("--platform", "manylinux2014_x86_64")):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--only-binary=:all:", argv)
        self.assertIn("--no-deps", argv)
        self.assertNotIn("install", argv)

        with mock.patch.object(package.subprocess, "run",
                               return_value=subprocess.CompletedProcess(["python3.12", "--version"], 0,
                                                                         stdout="Python 3.12.0", stderr="")) as run:
            with self.assertRaisesRegex(package.PackageError, "Python 3.11"):
                package.download_wheels("python3.12", self.root / "unused-wheels")
            run.assert_called_once()

    def test_owner_manifest_is_closed_and_refuses_mutable_or_existing(self):
        crm = "registry.example/crm@sha256:" + "a" * 64
        mongo = "docker.io/library/mongo@sha256:" + "b" * 64
        output = self.root / "owner-manifest.json"
        actual_sha = package.manifest(output, crm, mongo)
        self.assertEqual(actual_sha, package.sha256(output))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        document = json.loads(output.read_text())
        self.assertEqual(set(document), {"schema", "crmImage", "mongoImage", "baseImageDigest",
                                         "sourceSHA256", "dependencyLockSHA256",
                                         "wheelhouseManifestSHA256", "dependencies"})
        self.assertEqual(document["schema"], "phorvex.crm-fixture.v1")
        self.assertEqual(document["crmImage"], crm)
        self.assertEqual(document["mongoImage"], mongo)
        self.assertEqual(document["sourceSHA256"], package.SOURCE_HASHES["app.py"])
        self.assertEqual(document["dependencyLockSHA256"], package.SOURCE_HASHES["dependencies.lock.json"])
        self.assertEqual(document["wheelhouseManifestSHA256"], package.WHEEL_MANIFEST_SHA256)
        with self.assertRaisesRegex(package.PackageError, "already exists"):
            package.manifest(output, crm, mongo)
        for bad in ("registry.example/crm:latest", "sha256:" + "a" * 64,
                    "REPLACE-WITH-IMAGE@sha256:REPLACE", "registry.example/crm@sha256:" + "A" * 64):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(package.PackageError, "immutable repository"):
                    package.manifest(self.root / "bad.json", bad, mongo)
                self.assertFalse((self.root / "bad.json").exists())


if __name__ == "__main__":
    unittest.main()
