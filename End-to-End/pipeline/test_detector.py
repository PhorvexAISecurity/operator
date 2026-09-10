import json
import shlex
import unittest
from contextlib import ExitStack

from detector import DetectorSignal
from transport import TransportError


IDENTITY = "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector"
TARGET = {"namespace": "voice", "detector": {"identity": IDENTITY, "selector": "app=voice"}}


EVENT_UID = "event-uid-9f3c"


def pod(name, ready=True, uid=None, **metadata):
    return {"metadata": dict(name=name, uid=uid or f"uid-{name}", **metadata), "status": {
        "phase": "Running", "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}


class FakeTransport:
    def __init__(self, pods=None, creator=IDENTITY, create_rc=0, delete_rc=0,
                 event_uid=EVENT_UID):
        self.pods = pods if pods is not None else [pod("voice-a")]
        self.creator, self.create_rc, self.delete_rc = creator, create_rc, delete_rc
        self.event_uid = event_uid
        self.commands = []
        self.event = None

    def run(self, command, timeout=60):
        self.commands.append(command)
        if " get pods " in command:
            return 0, json.dumps({"items": self.pods}), ""
        if " create -f " in command:
            self.event = json.loads(shlex.split(command)[2])
            stored = {"metadata": {
                "name": self.event["metadata"]["name"],
                "creationTimestamp": "2026-09-10T18:30:05Z",
                "annotations": {"phorvex.ai/creator-identity": self.creator}}}
            if self.event_uid:
                stored["metadata"]["uid"] = self.event_uid
            return self.create_rc, json.dumps(stored), "create error"
        if " delete securityevent " in command:
            return self.delete_rc, "", "delete error"
        raise AssertionError(command)


class DetectorTests(unittest.TestCase):
    def test_uses_dedicated_identity_without_forging_stamp(self):
        t = FakeTransport()
        s = DetectorSignal(t, TARGET)
        response = s.fire()
        self.assertEqual(response["creatorIdentity"], IDENTITY)
        self.assertNotIn("annotations", t.event["metadata"])
        self.assertNotIn("namespace", t.event["metadata"])  # cluster-scoped CRD
        self.assertEqual(t.event["spec"]["targets"], ["voice/voice-a"])
        self.assertIn("--as=" + IDENTITY, t.commands[1])
        s.clear()
        self.assertIn(s.name, t.commands[-1])
        self.assertIn("--as=" + IDENTITY, t.commands[-1])
        before = len(t.commands)
        s.clear()
        self.assertEqual(len(t.commands), before)

    def test_ignores_unready_terminating_and_quarantined_pods(self):
        t = FakeTransport([pod("a", ready=False), pod("b", deletionTimestamp="now"),
                           pod("c", ownerReferences=[{"kind": "AdaptiveMovingTargetDefense"}]),
                           pod("d")])
        self.assertEqual(DetectorSignal(t, TARGET).fire()["pod"], "d")

    def test_no_ready_target_does_not_mutate(self):
        t = FakeTransport([pod("a", ready=False)])
        s = DetectorSignal(t, TARGET)
        with self.assertRaises(TransportError):
            s.fire()
        s.clear()
        self.assertEqual(len(t.commands), 1)

    def test_cleanup_on_missing_stamp_or_failed_create(self):
        for kwargs in ({"creator": None}, {"creator": "untrusted"}, {"create_rc": 124}):
            with self.subTest(kwargs=kwargs):
                t = FakeTransport(**kwargs)
                s = DetectorSignal(t, TARGET)
                with self.assertRaises(TransportError), ExitStack() as cleanup:
                    cleanup.callback(s.clear)
                    s.fire()
                self.assertIn(" delete securityevent ", t.commands[-1])

    def test_cleanup_on_interrupted_capture(self):
        t = FakeTransport()
        s = DetectorSignal(t, TARGET)
        with self.assertRaises(KeyboardInterrupt), ExitStack() as cleanup:
            cleanup.callback(s.clear)
            s.fire()
            raise KeyboardInterrupt()
        self.assertIn(" delete securityevent ", t.commands[-1])

    def test_failed_cleanup_is_not_reported_as_success(self):
        s = DetectorSignal(FakeTransport(delete_rc=1), TARGET)
        s.fire()
        with self.assertRaises(TransportError):
            s.clear()
        self.assertTrue(s.attempted)

    def test_runs_never_reuse_event_creation_timestamp(self):
        a, b = DetectorSignal(FakeTransport(), TARGET), DetectorSignal(FakeTransport(), TARGET)
        self.assertNotEqual(a.name, b.name)

    def test_every_identity_a_later_attribution_needs_is_kept_from_the_response(self):
        t = FakeTransport()
        s = DetectorSignal(t, TARGET, run_id="run-1")
        response = s.fire()
        self.assertEqual(response["eventUID"], EVENT_UID)
        self.assertEqual(response["eventName"], s.name)
        self.assertEqual(response["eventCreatedAt"], "2026-09-10T18:30:05Z")
        self.assertEqual(response["targetUID"], "uid-voice-a")
        self.assertEqual((response["targetNamespace"], response["targetPod"]),
                         ("voice", "voice-a"))
        self.assertEqual(response["runId"], "run-1")
        self.assertEqual(s.injection_identity(), {
            "kind": "SecurityEvent", "eventName": s.name, "eventUID": EVENT_UID,
            "eventCreatedAt": "2026-09-10T18:30:05Z", "identity": IDENTITY,
            "targetNamespace": "voice", "targetPod": "voice-a", "targetUID": "uid-voice-a",
            "runId": "run-1"})

    def test_a_response_without_an_event_uid_fails_closed(self):
        # An injection nothing can be attributed to must not become a run that reports a
        # defended attack.
        t = FakeTransport(event_uid=None)
        s = DetectorSignal(t, TARGET)
        with self.assertRaisesRegex(TransportError, "no event UID"):
            s.fire()
        self.assertTrue(s.attempted)

    def test_a_target_pod_without_a_uid_is_never_fired_at(self):
        t = FakeTransport([{"metadata": {"name": "voice-a"},
                            "status": {"phase": "Running",
                                       "conditions": [{"type": "Ready", "status": "True"}]}}])
        with self.assertRaisesRegex(TransportError, "no UID"):
            DetectorSignal(t, TARGET).fire()
        self.assertEqual(len(t.commands), 1)  # discovery only; nothing was created


if __name__ == "__main__":
    unittest.main()
