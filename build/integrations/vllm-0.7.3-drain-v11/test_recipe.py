#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
import tempfile
import unittest

import verify_recipe


HERE = Path(__file__).resolve().parent


class RecipeTest(unittest.TestCase):
    def temporary_recipe(self) -> Path:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        return Path(self.temp.name)

    def copy_recipe(self) -> Path:
        root = self.temporary_recipe()
        for name in ("Dockerfile", "manifest.json", "base-image-receipt.json"):
            shutil.copy2(HERE / name, root / name)
        return root

    def docker_copy_sources(self) -> list[str]:
        copies = [line for line in (HERE / "Dockerfile").read_text().splitlines() if line.startswith("COPY ")]
        self.assertEqual(len(copies), 1)
        fields = shlex.split(copies[0])
        self.assertEqual(fields[0], "COPY")
        self.assertEqual(fields[-1], "/opt/phorvex-vllm-drain-v11/")
        return fields[1:-1]

    def stage_docker_copy_context(self, *, omit: str | None = None) -> Path:
        root = self.temporary_recipe()
        sources = self.docker_copy_sources()
        self.assertEqual(
            sources,
            [
                "Dockerfile",
                "manifest.json",
                "base-image-receipt.json",
                "verify_recipe.py",
                "vllm-0.7.3-drain-v11.patch",
                "apply_patch.py",
                "test_contract.py",
                "test_drain_contract.py",
            ],
        )
        for name in sources:
            if name != omit:
                shutil.copy2(HERE / name, root / name)
        return root

    def test_checked_in_recipe_matches_receipt(self):
        result = verify_recipe.verify(HERE)
        self.assertEqual(result["platform"], "linux/amd64")
        self.assertIn("@sha256:4f4037303e8c", result["base"])

    def test_docker_copy_context_can_run_recipe_verifier(self):
        result = verify_recipe.verify(self.stage_docker_copy_context())
        self.assertEqual(result["platform"], "linux/amd64")

    def test_docker_copy_context_without_dockerfile_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            verify_recipe.verify(self.stage_docker_copy_context(omit="Dockerfile"))

    def test_from_manifest_label_and_platform_drift_are_rejected(self):
        for target in ("FROM", "manifest", "label", "platform"):
            with self.subTest(target=target):
                root = self.copy_recipe()
                if target == "FROM":
                    path = root / "Dockerfile"
                    path.write_text(path.read_text().replace("FROM vllm/", "FROM wrong/", 1))
                elif target == "label":
                    path = root / "Dockerfile"
                    path.write_text(path.read_text().replace("org.opencontainers.image.base.digest=\"sha256:", "org.opencontainers.image.base.digest=\"sha256:0", 1))
                elif target == "manifest":
                    path = root / "manifest.json"
                    data = json.loads(path.read_text())
                    data["base_image"]["digest"] = "sha256:" + "0" * 64
                    path.write_text(json.dumps(data))
                else:
                    path = root / "base-image-receipt.json"
                    data = json.loads(path.read_text())
                    data["config"]["architecture"] = "arm64"
                    path.write_text(json.dumps(data))
                with self.assertRaises(RuntimeError):
                    verify_recipe.verify(root)


if __name__ == "__main__":
    unittest.main()
