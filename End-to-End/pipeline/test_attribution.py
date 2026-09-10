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
REACTION = dict(actuated=True, selected=True, action="rotate", pod="voice-a",
                namespace="voice")


def hypothetical(cause=EVENT, target=TARGET, **overrides):
    """A record carrying the CAUSING event's identity — a shape nothing writes today.

    Named `hypothetical` on purpose. M-18 does not supply this; see `emitted()`.
    """
    return F.hypothetical_cause_record(cause, target_uid=target, **dict(REACTION, **overrides))


def emitted(**overrides):
    """What M-18 really adds: phoenix.eventUID for the event the ACTUATOR CREATED."""
    return F.record(phoenix=F.phoenix_forensics(),
                    decisionTrace=F.decision_trace(asset_uid=TARGET),
                    **dict(REACTION, **overrides))


def named(**overrides):
    """What the currently deployed phorvex.audit.v2 emits: event NAMES and no event UID."""
    return F.record(events=[{"name": "phorvex-e2e-abc", "targetsPod": True, "weight": 1.0}],
                    **dict(REACTION, **overrides))


def ctx(post, injection=INJECTION, fired=True):
    correlator = Correlator(injection, post) if fired else None
    return SimpleNamespace(attack_fired=fired, target={"namespace": "voice"},
                           post_records=post, correlator=correlator)


class SupportDetectionTests(unittest.TestCase):
    def test_the_deployed_schema_is_detected_as_name_only(self):
        c = Correlator(INJECTION, [named()])
        self.assertEqual(c.support, "event-name")
        self.assertFalse(c.supported)
        self.assertIn("not a causal identity", c.describe())

    def test_m18_phoenix_event_uid_is_an_output_identity_not_a_cause(self):
        """The correction: phoenix.eventUID names the event Phorvex EMITTED."""
        c = Correlator(INJECTION, [emitted()])
        self.assertEqual(c.support, "output-event-uid")
        self.assertFalse(c.supported)
        self.assertIn("EMITTED", c.describe())
        self.assertIn("no inspected schema records the causing event", c.describe())

    def test_the_emitted_event_uid_is_never_matched_against_our_injection(self):
        # Even if the emitted event happened to carry our UID, it is read from the output
        # path and cannot satisfy a cause claim.
        record = F.record(phoenix=F.phoenix_forensics(event_uid=EVENT),
                          decisionTrace=F.decision_trace(asset_uid=TARGET), **REACTION)
        c = Correlator(INJECTION, [record])
        self.assertFalse(c.supported)
        self.assertEqual(c.classify(record)[0], "unsupported")

    def test_a_target_uid_alone_does_not_support_a_causal_claim(self):
        record = F.record(decisionTrace=F.decision_trace(asset_uid=TARGET), **REACTION)
        c = Correlator(INJECTION, [record])
        self.assertEqual(c.support, "none")
        self.assertFalse(c.supported)

    def test_a_record_set_with_no_identity_at_all_supports_nothing(self):
        c = Correlator(INJECTION, [F.record()])
        self.assertEqual(c.support, "none")
        self.assertFalse(c.supported)

    def test_a_hypothetical_cause_field_plus_a_real_target_uid_supports_correlation(self):
        c = Correlator(INJECTION, [hypothetical()])
        self.assertEqual(c.support, "injected-event-uid")
        self.assertTrue(c.supported)

    def test_detection_reads_the_key_not_a_truthy_value(self):
        # An empty UID still means the field exists; the run just has nothing in it.
        blank = hypothetical(cause="", target="")
        c = Correlator(INJECTION, [blank])
        self.assertEqual(c.support, "injected-event-uid")
        self.assertEqual(c.correlated([blank]), [])

    def test_a_run_without_its_own_event_uid_cannot_correlate(self):
        c = Correlator(dict(INJECTION, eventUID=None), [hypothetical()])
        self.assertFalse(c.supported)
        self.assertIn("recorded no event UID", c.describe())


class CorrelationTests(unittest.TestCase):
    def classify(self, record, injection=INJECTION):
        return Correlator(injection, [record]).classify(record)

    def test_the_exact_event_and_target_correlate(self):
        status, detail = self.classify(hypothetical())
        self.assertEqual(status, "correlated")
        self.assertIn(EVENT[:8], detail)

    def test_an_unrelated_event_on_the_same_target_does_not_correlate(self):
        status, detail = self.classify(hypothetical(cause="someone-elses-event"))
        self.assertEqual(status, "unavailable")
        self.assertIn("not the injected", detail)

    def test_our_event_against_a_different_target_instance_does_not_correlate(self):
        status, detail = self.classify(hypothetical(target="a-recycled-name-new-uid"))
        self.assertEqual(status, "unavailable")
        self.assertIn("not " + TARGET[:8], detail)

    def test_a_run_that_recorded_no_target_uid_cannot_correlate(self):
        status, detail = self.classify(hypothetical(), dict(INJECTION, targetUID=None))
        self.assertEqual(status, "unavailable")
        self.assertIn("no target Pod UID", detail)

    def test_a_target_uid_match_with_a_disagreeing_pod_name_does_not_correlate(self):
        status, detail = self.classify(hypothetical(pod="some-other-pod"))
        self.assertEqual(status, "unavailable")
        self.assertIn("rather than", detail)

    def test_namespace_membership_alone_never_correlates(self):
        status, _ = self.classify(hypothetical(cause="other"))
        self.assertEqual(status, "unavailable")

    def test_the_target_uid_is_read_from_the_real_decision_trace_path(self):
        record = hypothetical()
        self.assertEqual(record["decisionTrace"]["assetUID"], TARGET)
        self.assertEqual(self.classify(record)[0], "correlated")


class A05Tests(unittest.TestCase):
    def test_observe_mode_is_not_applicable(self):
        got = a05(ctx([], fired=False))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "not-applicable"))

    def test_no_reaction_at_all_remains_a_failure(self):
        got = a05(ctx([]))
        self.assertEqual(got["status"], "fail")
        self.assertIn("no change in any decision", got["summary"])

    def test_a_correlated_actuation_passes(self):
        got = a05(ctx([hypothetical()]))
        self.assertEqual(got["status"], "pass")
        self.assertIn("attributable to the injected event", got["summary"])

    def test_an_unrelated_actuation_in_the_namespace_is_not_a_defended_attack(self):
        """The M-155 false positive: a proactive rotation during the window."""
        got = a05(ctx([hypothetical(cause="a-different-detectors-event")]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("none of them bound to the injected event", got["summary"])

    def test_a_name_only_schema_reports_the_gap_rather_than_passing(self):
        got = a05(ctx([named()]))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "none"))
        self.assertIn("cannot bind any of them", got["summary"])
        self.assertTrue(any("not a causal identity" in e for e in got["evidence"]))

    def test_an_m18_emitted_event_uid_cannot_pass_a05(self):
        """M-18 forensics identify the output. A05 must say so, not pass on it."""
        got = a05(ctx([emitted()]))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "none"))
        self.assertTrue(any("EMITTED" in e and "different objects" in e
                            for e in got["evidence"]), got["evidence"])

    def test_a_console_injection_with_no_identity_cannot_claim_a_causal_defence(self):
        got = a05(ctx([named()], injection={"kind": "console-signal", "eventUID": None}))
        self.assertEqual(got["status"], "warn")
        self.assertNotIn("attributable", got["summary"])

    def test_a_correlated_selection_that_never_actuated_is_a_warning(self):
        got = a05(ctx([hypothetical(actuated=False, selected=True)]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("never actuated", got["summary"])

    def test_a_correlated_decision_that_spent_no_move_is_a_warning(self):
        got = a05(ctx([hypothetical(actuated=False, selected=False, action="noop")]))
        self.assertEqual(got["status"], "warn")
        self.assertIn("no move was spent", got["summary"])

    def test_only_decisions_in_the_target_namespace_are_considered(self):
        got = a05(ctx([hypothetical(namespace="nats")]))
        self.assertEqual(got["status"], "fail")


if __name__ == "__main__":
    unittest.main()
