"""Offline source, closure and receipt refusal controls for the image recipe."""

from pathlib import Path
import shutil
import tempfile
import unittest

from verify_recipe import HERE, RECIPE_FILES, verify
from verify_wheelhouse import declared, verify as verify_wheels
from write_publish_receipt import receipt


class LeaseProxyRecipeTest(unittest.TestCase):
    def test_exact_recipe_and_locked_cpu_classifier_roots(self):
        result = verify()
        self.assertEqual(result["wheelCount"], 41)
        self.assertEqual(result["rootVersions"]["torch"], "2.14.0+cpu")
        self.assertEqual(result["rootVersions"]["transformers"], "5.17.0")
        self.assertEqual(result["command"], '["python3", "-B", "/src/dual_server.py"]')
        if (HERE / "wheelhouse").exists():
            self.assertEqual(verify_wheels(HERE / "requirements.lock", HERE / "wheelhouse.sha256",
                                           HERE / "wheelhouse"), 41)

    def test_base_and_dependency_mutations_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in RECIPE_FILES:
                shutil.copy2(HERE / name, root / name)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(dockerfile.read_text().replace("USER 10001:10001", "USER 0"))
            with self.assertRaisesRegex(ValueError, "Dockerfile"):
                verify(root)
            shutil.copy2(HERE / "Dockerfile", dockerfile)
            lock = root / "requirements.lock"
            lock.write_text(lock.read_text().replace("torch==2.14.0+cpu", "torch==2.13.0+cpu"))
            with self.assertRaisesRegex(ValueError, "root version"):
                verify(root)

    def test_missing_or_relabelled_wheel_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "requirements.lock"
            manifest = root / "wheelhouse.sha256"
            shutil.copy2(HERE / lock.name, lock)
            shutil.copy2(HERE / manifest.name, manifest)
            manifest.write_text(manifest.read_text().replace("-py3-none-any.whl", "-py3-none-win_amd64.whl", 1))
            with self.assertRaisesRegex(ValueError, "wheel"):
                declared(lock, manifest)
            shutil.copy2(HERE / manifest.name, manifest)
            manifest.write_text("".join(manifest.read_text().splitlines(keepends=True)[:-1]))
            with self.assertRaisesRegex(ValueError, "omits"):
                declared(lock, manifest)

    def test_receipt_requires_source_bound_tag_and_digest(self):
        source = "a" * 40
        image = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-lease-proxy-" + source
        result = receipt(source, image, "sha256:" + "b" * 64, "123", "1")
        self.assertEqual(result["imageByDigest"],
                         "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + "b" * 64)
        self.assertFalse(result["classifierWeightsIncluded"])
        with self.assertRaisesRegex(ValueError, "identity"):
            receipt(source, image[:-1] + "c", "sha256:" + "b" * 64, "123", "1")
        with self.assertRaisesRegex(ValueError, "identity"):
            receipt(source, image, "sha256:bad", "123", "1")


if __name__ == "__main__":
    unittest.main()
