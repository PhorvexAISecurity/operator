import json
import unittest

from transport import Cluster


class FakeTransport:
    def __init__(self, pod, policy):
        self.pod = pod
        self.policy = policy

    def run(self, command, timeout=60):
        if " get pod " in command:
            return 0, json.dumps(self.pod), ""
        if " get networkpolicy " in command:
            return 0, json.dumps(self.policy), ""
        return 1, "", "unexpected command"


class RawTransport:
    def __init__(self, output):
        self.output = output

    def run(self, command, timeout=60):
        return 0, self.output, ""


def pod_with_label(value):
    return {"metadata": {"labels": {"amtd.r6security.com/network-policy": value}}}


def deny_all_policy(name):
    return {"spec": {
        "podSelector": {"matchLabels": {"amtd.r6security.com/network-policy": name}},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": [],
    }}


class QuarantineStateTests(unittest.TestCase):
    def test_active_when_deny_all_policy_selects_the_pod(self):
        name = "nats-nats-0-policy"
        state = Cluster(FakeTransport(pod_with_label(name), deny_all_policy(name))).quarantine_state(
            "nats", "nats-0")
        self.assertTrue(state["active"])

    def test_inactive_when_replacement_pod_lost_the_selector_label(self):
        name = "nats-nats-0-policy"
        state = Cluster(FakeTransport(pod_with_label(""), deny_all_policy(name))).quarantine_state(
            "nats", "nats-0")
        self.assertFalse(state["active"])
        self.assertIn("podLabel=<missing>", state["evidence"])


class ControllerPodsTests(unittest.TestCase):
    def test_ignores_completed_and_failed_job_pods(self):
        output = "\n".join([
            "operator-controller-manager-abc|Running|0|ReplicaSet",
            "phorvex-phorvex-abc|Running|0|ReplicaSet",
            "phorvex-epss-feed-old|Succeeded|0|Job",
            "phorvex-epss-feed-bad|Failed|0|Job",
        ])

        pods = Cluster(RawTransport(output)).controller_pods()

        self.assertEqual(set(pods), {
            "operator-controller-manager-abc",
            "phorvex-phorvex-abc",
        })

    def test_keeps_unhealthy_controller_pods_visible(self):
        output = "phorvex-phorvex-abc|Running|12|ReplicaSet"

        pods = Cluster(RawTransport(output)).controller_pods()

        self.assertEqual(pods["phorvex-phorvex-abc"]["restarts"], 12)


if __name__ == "__main__":
    unittest.main()
