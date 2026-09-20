#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify_recipe


HERE = Path(__file__).resolve().parent


class RecipeTest(unittest.TestCase):
    def copy_recipe(self) -> Path:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name in ("Dockerfile", "manifest.json", "base-image-receipt.json"):
            shutil.copy2(HERE / name, root / name)
        return root

    def test_checked_in_recipe_matches_receipt(self):
        result = verify_recipe.verify(HERE)
        self.assertEqual(result["platform"], "linux/amd64")
        self.assertIn("@sha256:4f4037303e8c", result["base"])

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
