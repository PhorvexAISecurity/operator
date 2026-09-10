"""A whole attack run, end to end, over a kubectl-shaped fake cluster.

This is the integration the individual regressions are pieces of: preflight reads a real
baseline, the detector creates an event and keeps its UID, the capture opens before the
injection fires, ground truth goes back to the cluster, and the verdict is rolled up from
what was actually observed. Nothing below `Console` is stubbed.
"""
import tempfile
import unittest
from pathlib import Path

import fixtures as F

EVENT_UID = "event-uid-fixture"
TARGET_UID = "uid-voice-a"


def cluster(pods=None, **kwargs):
    return F.FakeKubectl(
        pods=pods if pods is not None else [F.pod("voice-a", namespace="voice")],
        inventory=F.deployment_stack("fixture-controller"),
        policies=[F.phorvex_policy(namespace="voice", max_moves=1)],
        create_response=F.security_event_response("phorvex-e2e-fixture", uid=EVENT_UID),
        **kwargs)


class RotatingCluster(F.FakeKubectl):
    """A cluster where the rotation actually happens, after the event is created.

    The baseline read sees `voice-a`; the post-action read sees its Ready successor. That
    ordering is the whole point — a fixture that swaps the pods up front would let a
    verdict pass that never observed a before and an after.
    """

    def __init__(self, successor, **kwargs):
        super().__init__(**kwargs)
        self.successor = successor

    def run(self, command, timeout=60):
        result = super().run(command, timeout)
        if "create -f" in command:
            self.pods = [self.successor]
        return result


def rotating(**kwargs):
    base = cluster(**kwargs)
    # Created now, i.e. inside the observation window — a successor stamped before the
    # action would (correctly) not count as its replacement.
    return RotatingCluster(
        F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1", namespace="voice",
              creation=F._now()),
        pods=base.pods, inventory=base.inventory, policies=base.policies,
        create_response=base.create_response, deny=base.deny)


def caused(**overrides):
    """A reaction carrying the CAUSING event's identity — a hypothetical schema.

    M-18 supplies `phoenix.eventUID` for the event the actuator EMITTED, which is a
    different object; see attribution.HYPOTHETICAL_INJECTED_EVENT_UID_PATHS.
    """
    return F.hypothetical_cause_record(
        overrides.pop("cause", EVENT_UID), target_uid=overrides.pop("target", TARGET_UID),
        **dict(dict(namespace="voice", pod="voice-a", action="rotate", selected=True,
                    feasible=True, actuated=True, dryRun=False, threatPosture=0.9),
               **overrides))


def rotation(**overrides):
    base = dict(namespace="voice", pod="voice-a", action="rotate", selected=True,
                feasible=True, actuated=True, dryRun=False, threatPosture=0.9)
    base.update(overrides)
    return F.record(**base)


def check(doc, cid):
    return next(c for c in doc["checks"] if c["id"] == cid)


class AttackRunTests(unittest.TestCase):
    def run_attack(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        doc, rc = F.run_offline(Path(directory.name), mode="attack", detector=True,
                                cluster=kwargs.pop("cluster", None) or cluster(), **kwargs)
        return doc, rc

    def test_the_injection_identity_is_recorded_from_the_api_response(self):
        doc, _ = self.run_attack(records=[F.record()], post_records=[rotation()])
        injection = doc["injection"]
        self.assertEqual(injection["eventUID"], EVENT_UID)
        self.assertEqual(injection["targetUID"], TARGET_UID)
        self.assertEqual(injection["targetNamespace"], "voice")
        self.assertEqual(injection["runId"], doc["runId"])
        self.assertTrue(injection["createResponseValidated"])
        self.assertEqual(injection["cleanup"], "delete-request-acknowledged")

    def test_a_rotation_the_cluster_confirms_is_reported_without_claiming_a_cause(self):
        # The pod that was actuated is gone; a Ready successor under the same controller is
        # running. The effect is real. Attribution to our event is not available.
        doc, _ = self.run_attack(cluster=rotating(), records=[F.record()],
                                 post_records=[rotation()])
        ground = doc["groundTruth"]
        self.assertEqual([g["verdict"] for g in ground], ["confirmed"])
        self.assertEqual(ground[0]["attribution"], "unsupported")
        self.assertIn("Ready pod created after the action", ground[0]["detail"])
        self.assertIsNotNone(ground[0]["observationWindow"]["intervalSec"])
        self.assertEqual(check(doc, "A03")["coverage"], "partial")

    def test_a05_reports_the_attribution_gap_rather_than_a_defended_attack(self):
        doc, _ = self.run_attack(cluster=rotating(), records=[F.record()],
                                 post_records=[rotation()])
        a05 = check(doc, "A05")
        self.assertEqual((a05["status"], a05["coverage"]), ("warn", "none"))
        self.assertIn("cannot bind any of them", a05["summary"])
        self.assertFalse(doc["attribution"]["supported"])
        # A confirmed effect the run cannot attribute is a WARN, not a green board.
        self.assertEqual(doc["verdict"], "WARN")

    def test_a_hypothetical_cause_field_lets_the_same_run_attribute_the_reaction(self):
        # The forward control. It is HYPOTHETICAL: no inspected producer records the
        # causing event's UID, so this is what such a schema would have to look like, not
        # what M-18 delivers.
        doc, _ = self.run_attack(cluster=rotating(), records=[F.record()],
                                 post_records=[caused()])
        a05 = check(doc, "A05")
        self.assertEqual(a05["status"], "pass")
        self.assertIn("attributable to the injected event", a05["summary"])
        self.assertTrue(doc["attribution"]["supported"])
        self.assertEqual(doc["groundTruth"][0]["attribution"], "correlated")
        self.assertEqual(check(doc, "A03")["coverage"], "full")

    def test_the_m18_emitted_event_uid_does_not_make_the_run_attributable(self):
        doc, _ = self.run_attack(
            cluster=rotating(), records=[F.record()],
            post_records=[rotation(phoenix=F.phoenix_forensics(),
                                   decisionTrace=F.decision_trace(asset_uid=TARGET_UID))])
        self.assertEqual(doc["attribution"]["support"], "output-event-uid")
        self.assertFalse(doc["attribution"]["supported"])
        self.assertEqual(check(doc, "A05")["status"], "warn")

    def test_an_unrelated_event_in_the_same_window_is_not_attributed_to_us(self):
        doc, _ = self.run_attack(
            cluster=rotating(), records=[F.record()],
            post_records=[caused(cause="another-detectors-event")])
        a05 = check(doc, "A05")
        self.assertEqual(a05["status"], "warn")
        self.assertIn("none of them bound to the injected event", a05["summary"])

    def test_the_capture_scope_and_completeness_travel_into_the_document(self):
        doc, _ = self.run_attack(records=[F.record()], post_records=[rotation()])
        capture = doc["capture"]
        self.assertEqual(capture["scope"]["namespaces"], ["voice"])
        self.assertTrue(capture["complete"])
        self.assertEqual(set(capture["windows"]), {"baseline", "live"})
        self.assertGreater(capture["windows"]["live"]["counters"]["accepted"], 0)

    def test_the_owning_policy_identity_is_carried_beside_its_budget(self):
        doc, _ = self.run_attack(records=[F.record()], post_records=[rotation()])
        self.assertEqual(doc["policy"]["uid"], "policy-uid-1")
        self.assertEqual(doc["policy"]["namespace"], "voice")
        self.assertEqual(doc["policy"]["maxMovesPerTick"], 1)
        self.assertTrue(doc["policy"]["budgetDeclared"])

    def test_an_unreadable_baseline_aborts_rather_than_verifying_against_nothing(self):
        denied = cluster(deny={"get pod ": (1, "", F.FORBIDDEN)})
        doc, rc = self.run_attack(cluster=denied, records=[F.record()])
        self.assertEqual((doc["verdict"], rc), ("ABORTED", 2))
        self.assertIn("baseline could not be captured", doc["abort"]["error"])
        self.assertFalse(doc["capture"]["complete"])

    def test_a_contradicted_claim_still_fails_the_run(self):
        # The pod is untouched, so a reported rotation is contradicted by the cluster.
        doc, rc = self.run_attack(records=[F.record()], post_records=[rotation()])
        self.assertEqual([g["verdict"] for g in doc["groundTruth"]], ["contradicted"])
        self.assertEqual(check(doc, "A03")["status"], "fail")
        self.assertEqual((doc["verdict"], rc), ("FAIL", 1))


if __name__ == "__main__":
    unittest.main()
