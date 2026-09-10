"""Causal attribution: A05 must not read "something happened nearby" as "we caused it"."""
import unittest
from types import SimpleNamespace

import fixtures as F
from attribution import Correlator
from checks import a05

EVENT = "event-uid-1111"
TARGET = "pod-uid-2222"
INJECTION = {"kind": "SecurityEvent", "eventName": "phorvex-e2e-abc", "eventUID": EVENT,
             "targetNamespace": "voice", "targetPod": "voice-a", "targetUID": TARGET}


def forensic(**overrides):
    """A record in the shape PR171/M18 supplies: event UID and target Pod UID."""
    base = dict(eventUID=EVENT, podUID=TARGET, actuated=True, selected=True, action="rotate")
    base.update(overrides)
    return F.record(**base)


def named(**overrides):
    """What the deployed phorvex.audit.v2 emits: an event NAME and no UIDs at all."""
    base = dict(events=[{"name": "phorvex-e2e-abc", "targetsPod": True, "weight": 1.0}],
                actuated=True, selected=True, action="rotate")
    base.update(overrides)
    return F.record(**base)


def ctx(post, injection=INJECTION, fired=True):
    correlator = Correlator(injection, post) if fired else None
    return SimpleNamespace(attack_fired=fired, target={"namespace": "voice"},
                           post_records=post, correlator=correlator)


class SupportDetectionTests(unittest.TestCase):
    def test_the_deployed_schema_is_detected_as_name_only(self):
        c = Correlator(INJECTION, [named()])
        self.assertEqual(c.support, "event-name")
        self.assertFalse(c.supported)
        self.assertIn("PR171/M18", c.describe())

    def test_a_forensic_schema_is_detected_as_uid_capable(self):
        c = Correlator(INJECTION, [forensic()])
        self.assertEqual(c.support, "event-uid")
        self.assertTrue(c.supported)

    def test_a_record_set_with_no_identity_at_all_supports_nothing(self):
        c = Correlator(INJECTION, [F.record()])
        self.assertEqual(c.support, "none")
        self.assertFalse(c.supported)

    def test_detection_reads_the_key_not_a_truthy_value(self):
        # An empty UID still means the field exists; the run just has nothing in it.
        c = Correlator(INJECTION, [forensic(eventUID="", podUID="")])
        self.assertEqual(c.support, "event-uid")
        self.assertEqual(c.correlated([forensic(eventUID="", podUID="")]), [])

    def test_a_run_without_its_own_event_uid_cannot_correlate(self):
        c = Correlator(dict(INJECTION, eventUID=None), [forensic()])
        self.assertFalse(c.supported)
        self.assertIn("recorded no event UID", c.describe())


class CorrelationTests(unittest.TestCase):
    def classify(self, record, injection=INJECTION):
        return Correlator(injection, [record]).classify(record)

    def test_the_exact_event_and_target_correlate(self):
        status, detail = self.classify(forensic())
        self.assertEqual(status, "correlated")
        self.assertIn(EVENT[:8], detail)

    def test_an_unrelated_event_on_the_same_target_does_not_correlate(self):
        status, detail = self.classify(forensic(eventUID="someone-elses-event"))
        self.assertEqual(status, "unavailable")
        self.assertIn("not the injected", detail)

    def test_our_event_against_a_different_target_instance_does_not_correlate(self):
        status, detail = self.classify(forensic(podUID="a-recycled-name-new-uid"))
        self.assertEqual(status, "unavailable")
        self.assertIn("not " + TARGET[:8], detail)

    def test_namespace_membership_alone_never_correlates(self):
        status, _ = self.classify(forensic(eventUID="other", namespace="voice", pod="voice-a"))
        self.assertEqual(status, "unavailable")

    def test_events_array_uid_is_read_as_well_as_the_top_level_field(self):
        record = F.record(events=[{"name": "x", "uid": EVENT}], podUID=TARGET)
        self.assertEqual(Correlator(INJECTION, [record]).classify(record)[0], "correlated")


class A05Tests(unittest.TestCase):
    def test_observe_mode_is_not_applicable(self):
        got = a05(ctx([], fired=False))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "not-applicable"))

    def test_no_reaction_at_all_remains_a_failure(self):
        got = a05(ctx([]))
        self.assertEqual(got["status"], "fail")
        self.assertIn("no change in any decision", got["summary"])

    def test_a_correlated_actuation_passes(self):
        got = a05(ctx([forensic()]))
        self.assertEqual(got["status"], "pass")
        self.assertIn("attributable to the injected event", got["summary"])

    def test_an_unrelated_actuation_in_the_namespace_is_not_a_defended_attack(self):
        """The M-155 false positive: a proactive rotation during the window."""
        got = a05(ctx([forensic(eventUID="a-different-detectors-event")]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("none of them bound to the injected event", got["summary"])

    def test_a_name_only_schema_reports_the_gap_rather_than_passing(self):
        got = a05(ctx([named()]))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "none"))
        self.assertIn("cannot bind any of them", got["summary"])
        self.assertTrue(any("a name is not a UID-bound" in e for e in got["evidence"]))

    def test_a_console_injection_with_no_identity_cannot_claim_a_causal_defence(self):
        got = a05(ctx([named()], injection={"kind": "console-signal", "eventUID": None}))
        self.assertEqual(got["status"], "warn")
        self.assertNotIn("attributable", got["summary"])

    def test_a_correlated_selection_that_never_actuated_is_a_warning(self):
        got = a05(ctx([forensic(actuated=False, selected=True)]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("never actuated", got["summary"])

    def test_a_correlated_decision_that_spent_no_move_is_a_warning(self):
        got = a05(ctx([forensic(actuated=False, selected=False, action="noop")]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("no move was spent", got["summary"])

    def test_only_decisions_in_the_target_namespace_are_considered(self):
        got = a05(ctx([forensic(namespace="nats")]))
        self.assertEqual(got["status"], "fail")


if __name__ == "__main__":
    unittest.main()
