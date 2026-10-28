import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_attack_catalog", ROOT / "tools" / "package_attack_catalog.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AttackCatalogPackageTest(unittest.TestCase):
    def test_embedded_document_is_exact_generated_package(self):
        output = ROOT / "phorvex" / "internal" / "attackcatalog" / "catalog.json"
        self.assertEqual(MODULE.encoded_document(), output.read_bytes())

    def test_exact_order_count_uniqueness_and_review_metadata(self):
        document = MODULE.build_document()
        entries = document["entries"]
        ids = MODULE.manifest_ids()
        self.assertEqual(192, document["count"])
        self.assertEqual(ids, [entry["id"] for entry in entries])
        self.assertEqual(list(range(1, 193)), [entry["order"] for entry in entries])
        self.assertEqual(192, len(set(ids)))
        self.assertEqual("AML.T0012", entries[0]["id"])
        for entry in entries:
            self.assertEqual("DEFENDED", entry["expected"])
            self.assertEqual("lane", entry["mode"])
            self.assertTrue(entry["reactiveCompatible"])
            for key in ("description", "family", "expectedAction", "eventType", "lane"):
                self.assertIsInstance(entry[key], str)
                self.assertTrue(entry[key])

    def test_production_document_excludes_operator_execution_material(self):
        document = json.dumps(MODULE.build_document())
        self.assertNotIn("/home/", document)
        self.assertNotIn("recipe", document)
        self.assertNotIn("harness", document)
        self.assertNotIn("oracle", document)


if __name__ == "__main__":
    unittest.main()
