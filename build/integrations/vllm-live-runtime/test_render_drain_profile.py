"""The opt-in profile can be rendered before its own console Pod rolls."""

import json
import unittest

from render_drain_profile import COMPLETION_SHA, ENGINE_SHA, render


UID = "11111111-1111-4111-8111-111111111111"
IMAGE = "repo.invalid/image@sha256:" + "a" * 64


def pod(name, namespace, containers):
    return {"metadata": {"name": name, "namespace": namespace, "uid": UID,
                         "labels": {"app": "vllm", "phorvex.ai/serving": "true"},
                         "annotations": {"phorvex.ai/drain-proxy-source": "b" * 64,
                                         "phorvex.ai/drain-engine-source": "c" * 64}},
            "status": {"containerStatuses": [{"name": item, "ready": True, "restartCount": 0,
                                               "imageID": IMAGE, "containerID": "containerd://" + "d" * 64}
                                              for item in containers]}}


def inputs():
    return {"cluster": {"metadata": {"name": "kube-system", "uid": UID}},
            "pod": pod("vllm-0", "vllm", ["vllm", "guardrail"]),
            "service": {"metadata": {"name": "vllm", "namespace": "vllm", "uid": UID},
                        "spec": {"selector": {"app": "vllm"}, "ports": [{"port": 8000, "protocol": "TCP", "targetPort": 8000}]}},
            "policy": {"metadata": {"name": "vllm-defense", "namespace": "vllm", "uid": UID, "generation": 4},
                       "spec": {"mode": "active", "selector": {"matchLabels": {"app": "vllm"}},
                                "actions": {"enabled": ["request-drain"]}}},
            "manager": pod("manager-0", "phorvex-system", ["manager"]),
            "console": pod("console-old", "phorvex-system", ["console"]),
            "console_deployment": {"kind": "Deployment", "metadata": {"name": "phorvex-phorvex-console",
                                                                "namespace": "phorvex-system", "uid": UID}},
            "sources": {"serving_completion.py": COMPLETION_SHA, "serving_engine.py": ENGINE_SHA}}


class DrainProfileRender(unittest.TestCase):
    def test_self_rollout_has_no_future_pod_pin(self):
        raw, values = render(inputs(), "dev-test", "https://audit.invalid|audit.invalid")
        profile = json.loads(raw)
        self.assertNotIn("consolePodUID", profile)
        self.assertNotIn("consoleContainerID", profile)
        self.assertEqual(profile["consoleDeploymentUID"], UID)
        self.assertFalse(values["phorvex"]["phorvex"]["console"]["drainLive"]["enabled"])

    def test_route_or_source_drift_refused(self):
        bad = inputs()
        bad["service"]["spec"]["selector"] = {"missing": "label"}
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")
        bad = inputs()
        bad["service"]["spec"]["ports"][0]["targetPort"] = 8001
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")
        bad = inputs()
        bad["sources"]["serving_engine.py"] = "e" * 64
        with self.assertRaises(ValueError): render(bad, "dev-test", "reviewed-audit")


if __name__ == "__main__":
    unittest.main()
