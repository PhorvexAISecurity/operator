"""Offline identity and route checks for the owned direct Voice forward."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent))
spec = importlib.util.spec_from_file_location("voice_agency_forward_probe", Path(__file__).with_name("forward_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeTransport:
    def __init__(self):
        self.endpoint_uid = "11111111-1111-4111-8111-111111111111"
        self.image_id = "owned-image@sha256:" + "a" * 64
        self.test_enabled = "true"

    def kubectl(self, argv, timeout):
        if "exec" in argv:
            return SimpleNamespace(returncode=0, stdout="b" * 64 + "  /app/bot.py\n")
        kind = argv[argv.index("get") + 1]
        if kind == "namespace":
            data = {"metadata": {"uid": "22222222-2222-4222-8222-222222222222"}}
        elif kind == "pod":
            data = {"metadata": {"uid": "11111111-1111-4111-8111-111111111111", "name": "voice-bot-1", "namespace": "voice"},
                    "spec": {"containers": [{"name": "bot", "env": [{"name": "VOICE_AGENCY_TEST_ENABLED", "value": self.test_enabled}]}]},
                    "status": {"phase": "Running", "podIP": "10.0.0.1", "conditions": [{"type": "Ready", "status": "True"}],
                               "containerStatuses": [{"name": "bot", "ready": True, "restartCount": 0,
                                                      "containerID": "containerd://exact", "imageID": self.image_id}]}}
        elif kind == "service":
            data = {"metadata": {"uid": "33333333-3333-4333-8333-333333333333"},
                    "spec": {"selector": {"app": "voice-bot"}, "ports": [{"port": 8080, "targetPort": 8080, "protocol": "TCP"}]}}
        elif kind == "endpointslices":
            data = {"items": [{"metadata": {"labels": {"kubernetes.io/service-name": "voice-bot"}},
                               "ports": [{"port": 8080, "protocol": "TCP"}],
                               "endpoints": [{"targetRef": {"uid": self.endpoint_uid, "name": "voice-bot-1"},
                                              "conditions": {"ready": True}, "addresses": ["10.0.0.1"]}]}]}
        else:
            raise AssertionError("unexpected Kubernetes read")
        return SimpleNamespace(returncode=0, stdout=json.dumps(data))


class VoiceAgencyForwardTest(unittest.TestCase):
    def test_exact_ready_service_endpoint_and_source(self):
        fake = FakeTransport()
        pins = {"pod": "voice-bot-1", "podUID": "11111111-1111-4111-8111-111111111111",
                "imageID": fake.image_id, "containerID": "containerd://exact", "sourceSHA256": "b" * 64,
                "serviceUID": "33333333-3333-4333-8333-333333333333",
                "clusterUID": "22222222-2222-4222-8222-222222222222", "run": "agencya1"}
        self.assertEqual(probe.authority(fake, pins)["podIP"], "10.0.0.1")
        fake.endpoint_uid = "44444444-4444-4444-8444-444444444444"
        with self.assertRaises(RuntimeError):
            probe.authority(fake, pins)
        fake.endpoint_uid = pins["podUID"]
        fake.image_id = "other-image@sha256:" + "c" * 64
        with self.assertRaises(RuntimeError):
            probe.authority(fake, pins)
        fake.image_id = pins["imageID"]
        fake.test_enabled = "false"
        with self.assertRaises(RuntimeError):
            probe.authority(fake, pins)


if __name__ == "__main__":
    unittest.main()
