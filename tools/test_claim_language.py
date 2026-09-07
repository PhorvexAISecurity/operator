import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-claim-language.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class ClaimLanguageTest(unittest.TestCase):
    def test_rejects_outcome_prose(self):
        for text in ['w("The foothold is contained")', '<p>Threat eliminated</p>', 'why = "Secured the workload"', '"SLO never broken"']:
            self.assertEqual(list(gate.violations(text)), [1])
    def test_legacy_wire_and_scoped_claims(self):
        for text in ['case "contained":', '// self-contained component', '<p>Modeled coverage; security effect unconfirmed.</p>']:
            self.assertEqual(list(gate.violations(text)), [])

if __name__ == '__main__':
    unittest.main()
