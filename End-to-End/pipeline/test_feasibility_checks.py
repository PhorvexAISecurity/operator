import json
import re
from pathlib import Path
from types import SimpleNamespace
import unittest
from checks import f01


class FeasibilityReasonTests(unittest.TestCase):
    def check_reason(self, why):
        cfg = json.loads((Path(__file__).parents[1] / 'config.json').read_text())
        return f01(SimpleNamespace(inv=cfg['invariants'], records=[{
            'feasible': False, 'infeasibleWhy': why, 'pod': 'fixture'}]))

    def test_measured_rbac_denials(self):
        for why in ['denied /pods:delete in voice',
                    'denied networking.k8s.io/networkpolicies:create in voice-prod']:
            with self.subTest(why=why):
                got = self.check_reason(why)
                self.assertEqual(got['status'], 'pass')
                self.assertEqual(got['evidence'], ['capability-rbac: 1'])

    def test_missing_unknown_and_transport_errors_still_fail(self):
        for why in ['', 'denied', 'denied whatever', 'prefix denied /pods:delete in voice',
                    'ssar-error /pods:delete in voice: unavailable', 'unknown gate']:
            with self.subTest(why=why):
                self.assertEqual(self.check_reason(why)['status'], 'fail')

    def test_existing_law_still_passes(self):
        self.assertEqual(self.check_reason('availability: floor')['status'], 'pass')

    def test_proactive_cadence_from_failed_live_run(self):
        # Run 34249621578, artifact 10065634085: the deployed 0.4.97
        # correctly vetoed hygiene motion, but F01 did not know the law.
        why = ('proactive-cadence: podIdentity hygiene-reset 2m40s ago '
               '< floor=15m0s (no evidence)')
        got = self.check_reason(why)
        self.assertEqual(got['status'], 'pass', got)
        self.assertEqual(got['evidence'], ['proactive-cadence: 1'])

    def test_all_production_laws_have_reviewed_reason_prefixes(self):
        root = Path(__file__).resolve().parents[2]
        inv = json.loads((root / 'End-to-End/config.json').read_text())['invariants']
        names = set()
        # Inspect production declarations independently of the JSON allowlist.
        # Non-literal Name implementations fail this check rather than disappearing
        # from the inventory; their parser/contract then needs explicit review.
        method = r'func\s+\([^)]*\)\s+Name\(\)\s+string\s*\{'
        literal = method + r'\s*return\s+"([^"]+)"\s*\}'
        for path in (root / 'phorvex/internal/feasibility').glob('*.go'):
            if path.name.endswith('_test.go'):
                continue
            source = path.read_text()
            declared = re.findall(literal, source)
            self.assertEqual(len(re.findall(method, source)), len(declared),
                             f'{path.name}: review a non-literal law Name')
            names.update(declared)
        self.assertTrue(names, 'production law inventory must not be empty')
        prefixes = inv['law_reason_prefixes']
        self.assertEqual(names - set(inv['known_laws']), set(),
                         'new production law missing from E2E known_laws')
        self.assertEqual(names - set(prefixes), set(),
                         'new production law missing from E2E reason mapping')
        for name in names:
            self.assertTrue(prefixes[name], f'{name}: missing reviewed prefix')
            for prefix in prefixes[name]:
                self.assertTrue(isinstance(prefix, str) and prefix.strip(), name)
                self.assertEqual(self.check_reason(prefix + ' fixture')['status'], 'pass')
