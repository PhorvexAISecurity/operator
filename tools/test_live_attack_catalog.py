import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent / "live-attack-runner"
SPEC = importlib.util.spec_from_file_location("live_attack_catalog", ROOT / "run_catalog.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class LiveAttackCatalogTest(unittest.TestCase):
    def test_complete_spec_catalog_is_valid(self):
        specs = MODULE.load_specs(ROOT / "runner" / "phvx-attack.py")
        self.assertEqual(207, len(specs))
        self.assertEqual({"lane"}, {spec["mode"] for spec in specs.values()})

    def test_pinned_manifest_is_exactly_192_strict_defense_cases(self):
        specs = MODULE.load_specs(ROOT / "runner" / "phvx-attack.py")
        names = MODULE.load_manifest(ROOT / "catalog-192.txt", specs)
        self.assertEqual(192, len(names))
        self.assertEqual({"DEFENDED"}, {specs[name]["expected"] for name in names})
        self.assertNotIn("config-object", {specs[name]["family"] for name in names})
        self.assertNotIn("controller-stop-kinds", {specs[name]["family"] for name in names})

    def test_only_clean_terminal_evidence_is_defended(self):
        self.assertTrue(MODULE.defended({"verdict": "DEFENDED", "postflight_clean": True}))
        self.assertFalse(MODULE.defended({"verdict": "DEFENDED", "postflight_clean": False}))
        self.assertFalse(MODULE.defended({"verdict": "NOT-DEFENDED", "postflight_clean": True}))


if __name__ == "__main__":
    unittest.main()
