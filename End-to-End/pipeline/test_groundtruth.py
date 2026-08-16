import unittest

from groundtruth import verify


class QuarantineGroundTruthTests(unittest.TestCase):
    def verdict(self, state):
        class Cluster:
            def quarantine_state(self, namespace, pod):
                return state

        records = [{"namespace": "nats", "pod": "nats-0", "action": "quarantine"}]
        return verify(Cluster(), records, {})[0]

    def test_confirms_active_deny_all_policy(self):
        got = self.verdict({"active": True, "evidence": "podLabel=nats-nats-0-policy"})
        self.assertEqual("confirmed", got["verdict"])
        self.assertIn("actively selects", got["detail"])

    def test_contradicts_policy_that_selects_no_pod(self):
        got = self.verdict({"active": False, "evidence": "podLabel=<missing>"})
        self.assertEqual("contradicted", got["verdict"])
        self.assertIn("does not select", got["detail"])

    def test_does_not_claim_success_when_cluster_state_is_unreadable(self):
        got = self.verdict(None)
        self.assertEqual("unverifiable", got["verdict"])


if __name__ == "__main__":
    unittest.main()
