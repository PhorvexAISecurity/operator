import json
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
