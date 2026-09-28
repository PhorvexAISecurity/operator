import copy
import unittest

from policy import PolicyUnavailable
from verify_runtime import verify_preservation


class PreservationTest(unittest.TestCase):
    def test_uid_rule_journal_and_secret_bytes_must_survive_rollout(self):
        items = [
            {"kind": "Deployment", "metadata": {"namespace": "voice", "name": "voice-bot", "uid": "same-deployment"},
             "spec": {"replicas": 3, "strategy": {"maxUnavailable": 0}, "selector": {"app": "voice-bot"}}},
            {"kind": "ConfigMap", "metadata": {"namespace": "voice", "name": "voice-memory-policy", "uid": "same-rule"},
             "data": {"rule.json": '{"revision":2,"entries":["protected"]}'}},
            {"kind": "ConfigMap", "metadata": {"namespace": "phorvex-system", "name": "phorvex-voice-memory-journal", "uid": "same-journal"},
             "data": {"operation.json": '{"phase":"terminal-full"}'}},
            {"kind": "Secret", "metadata": {"namespace": "voice", "name": "voice-secrets", "uid": "same-secret"},
             "data": {"TWILIO_AUTH_TOKEN": "cHJpdmF0ZQ=="}}]
        before = {"kind": "List", "items": items}
        after = copy.deepcopy(before)
        after["items"][0]["spec"]["template"] = {"new-wrapper": "allowed-by-separate-reviewed-patch"}
        self.assertEqual(len(verify_preservation(before, after)), 4)
        for index, field in [(1, "rule.json"), (2, "operation.json"), (3, "TWILIO_AUTH_TOKEN")]:
            changed = copy.deepcopy(after)
            changed["items"][index]["data"][field] += "changed"
            with self.assertRaises(PolicyUnavailable):
                verify_preservation(before, changed)
        changed = copy.deepcopy(after)
        changed["items"][1]["metadata"]["uid"] = "replacement-rule"
        with self.assertRaises(PolicyUnavailable):
            verify_preservation(before, changed)
