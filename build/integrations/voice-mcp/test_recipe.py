"""Verify the publication gate refuses source and recipe drift."""

from pathlib import Path
import shutil
import tempfile
import unittest

from verify_recipe import HERE, RECIPE_FILES, verify
from write_publish_receipt import receipt


class MCPRecipeTest(unittest.TestCase):
    def test_current_recipe_has_exact_source_and_closure(self):
        result = verify()
        self.assertEqual(result["wheelCount"], 71)
        self.assertEqual(result["sourceSHA256"], result["recipeSHA256"]["server.py"])

    def test_changed_source_or_base_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in RECIPE_FILES:
                shutil.copy2(HERE / name, root / name)
            (root / "fixtures").mkdir()
            for name in ("attack.ulaw", "benign.ulaw"):
                shutil.copy2(HERE / "fixtures" / name, root / "fixtures" / name)
            server = root / "server.py"
            server.write_bytes(server.read_bytes() + b"\n# drift\n")
            with self.assertRaisesRegex(ValueError, "server source"):
                verify(root)
            shutil.copy2(HERE / "server.py", server)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(dockerfile.read_text().replace("USER 10001:10001", "USER 0"))
            with self.assertRaisesRegex(ValueError, "Dockerfile"):
                verify(root)

    def test_receipt_binds_source_tag_and_digest(self):
        source = "a" * 40
        image = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:voice-mcp-" + source
        result = receipt(source, image, "sha256:" + "b" * 64, "123", "1")
        self.assertEqual(result["imageByDigest"],
                         "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + "b" * 64)
        self.assertEqual(result["wheelCount"], 71)
        with self.assertRaisesRegex(ValueError, "identity"):
            receipt(source, image[:-1] + "c", "sha256:" + "b" * 64, "123", "1")
        with self.assertRaisesRegex(ValueError, "identity"):
            receipt(source, image, "invalid", "123", "1")


if __name__ == "__main__":
    unittest.main()
