"""Ground truth drives the real Cluster reads over a kubectl-shaped transport.

Each test pairs the failing observation with the successful one that must still be
confirmed, so a verdict that got stricter is visibly still able to say yes.
"""
import unittest

import fixtures as F
from groundtruth import verify
from transport import Cluster

NS = "voice"
POD = "voice-a"
# 2025-09-04T15:33:20Z. BEFORE/AFTER straddle it, so a successor's creationTimestamp
# decides whether it can be the replacement.
STARTED = 1_757_000_000
DECIDED = "2025-09-04T15:33:30Z"      # the decision's own recorded time, 10s into the run
BEFORE = "2025-09-04T15:00:00Z"       # predates the decision
AFTER = "2025-09-04T15:34:00Z"        # postdates it


def baseline(uid="original-uid", owner="rs-voice-1"):
    return {POD: {"namespace": NS, "name": POD, "uid": uid, "ownerUID": owner,
                  "ownerKind": "ReplicaSet"}}


def run(cluster_kwargs, action="rotate", base=None, namespace=NS, patterns=None,
        started=STARTED, attribution_of=None, decided=DECIDED, trace=None, records=None):
    cluster = Cluster(F.FakeKubectl(**cluster_kwargs))
    if records is None:
        record = {"namespace": namespace, "pod": POD, "action": action, "actuated": True}
        if decided is not None:
            record["time"] = decided
        if trace is not None:
            record["decisionTrace"] = trace
        records = [record]
    got = verify(cluster, records, baseline() if base is None else base,
                 namespace=NS, action_started_at=started,
                 log_patterns=patterns, attribution_of=attribution_of)
    return got[0] if len(got) == 1 else got


class RotationTests(unittest.TestCase):
    def test_a_forbidden_inventory_is_unverifiable_not_a_confirmed_rotation(self):
        """M-165: the read failed, so nothing about the pod was observed."""
        got = run({"deny": {"get pod": (1, "", F.FORBIDDEN)}})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("could not be read", got["detail"])
        self.assertEqual(got["observation"]["reasonCode"], "forbidden")

    def test_a_successfully_empty_namespace_is_observed_but_still_not_a_replacement(self):
        # The control for the case above: this read genuinely succeeded and saw nothing.
        got = run({"pods": []})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("disappearance is not a successful replacement", got["detail"])
        self.assertEqual(got["observation"]["status"], "ok")

    def test_a_ready_new_same_owner_successor_confirms_the_replacement(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]})
        self.assertEqual(got["verdict"], "confirmed")
        self.assertIn("created after the action", got["detail"])
        self.assertIn("original-uid"[:8], got["evidence"])

    def test_same_name_uid_replacement_is_allowed_when_owner_and_readiness_hold(self):
        got = run({"pods": [F.pod(POD, uid="new-uid", owner_uid="rs-voice-1", creation=AFTER)]})
        self.assertEqual(got["verdict"], "confirmed")

    def test_a_surviving_pre_existing_replica_is_not_the_replacement(self):
        """A Deployment with two replicas always has a Ready same-owner sibling."""
        base = dict(baseline(), **{"voice-b": {"namespace": NS, "name": "voice-b",
                                               "uid": "sibling-uid", "ownerUID": "rs-voice-1",
                                               "ownerKind": "ReplicaSet"}})
        got = run({"pods": [F.pod("voice-b", uid="sibling-uid", owner_uid="rs-voice-1")]},
                  base=base)
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no NEW pod under the same controller", got["detail"])
        self.assertIn("1 pre-existing replica(s) survived", got["evidence"])

    def test_a_new_pod_created_before_the_action_is_not_its_replacement(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=BEFORE)]})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("created before this decision was recorded", got["detail"])

    def test_a_successor_with_no_usable_creation_time_cannot_be_placed(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=None)]})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no usable creation time", got["detail"])

    def test_a_decision_with_no_usable_time_cannot_be_placed_on_the_interval(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]}, decided=None)
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no usable time", got["detail"])

    def test_a_successor_predating_this_decision_does_not_confirm_it(self):
        """The run started at 15:33:20, but THIS decision was recorded at 15:35."""
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation="2025-09-04T15:34:00Z")]},
                  decided="2025-09-04T15:35:00Z")
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("created before this decision was recorded", got["detail"])


class PerDecisionIdentityTests(unittest.TestCase):
    """Each decision is about one Pod instance, and the record says which."""

    def trace(self, uid, name=POD):
        return {"assetUID": uid, "assetName": name, "assetNamespace": NS}

    def test_the_decision_trace_asset_uid_selects_the_target(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]}, trace=self.trace("original-uid"))
        self.assertEqual(got["verdict"], "confirmed")
        self.assertEqual(got["targetIdentity"]["resolvedFrom"], "decisionTrace.assetUID")

    def test_a_target_the_baseline_never_saw_is_never_verified_against_another(self):
        """A second rotation targets the replacement, which the snapshot never held."""
        got = run({"pods": [F.pod(POD, uid="replacement", owner_uid="rs-voice-1",
                                  creation=AFTER)]}, trace=self.trace("replacement"))
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("the pre-action snapshot does not contain", got["detail"])

    def test_a_still_present_target_is_contradicted_not_confirmed(self):
        got = run({"pods": [F.pod(POD, uid="original-uid", owner_uid="rs-voice-1"),
                            F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]}, trace=self.trace("original-uid"))
        self.assertEqual(got["verdict"], "contradicted")

    def test_a_trace_naming_a_different_pod_than_the_record_is_a_disagreement(self):
        got = run({"pods": []}, trace=self.trace("original-uid", name="somebody-else"))
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("disagree about what was acted on", got["detail"])

    def test_one_name_snapshot_answers_for_at_most_one_decision(self):
        # Without decisionTrace.assetUID there is no way to tell the instances apart, so
        # the second decision against the same name has no captured identity.
        record = {"namespace": NS, "pod": POD, "action": "rotate", "actuated": True,
                  "time": DECIDED}
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]},
                  records=[dict(record), dict(record)])
        self.assertEqual(got[0]["verdict"], "confirmed")
        self.assertEqual(got[1]["verdict"], "unverifiable")
        self.assertIn("already used by an earlier decision", got[1]["detail"])
        self.assertIn("pod name", got[0]["targetIdentity"]["resolvedFrom"])

    def test_a_successor_owned_by_a_different_controller_is_not_our_replacement(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="some-other-rs",
                                  creation=AFTER)]})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no successor under the same controller", got["detail"])

    def test_an_unready_successor_is_not_yet_a_replacement(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  ready=False, creation=AFTER)]})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("not Ready", got["detail"])

    def test_an_untouched_uid_still_contradicts_the_claim(self):
        got = run({"pods": [F.pod(POD, uid="original-uid", owner_uid="rs-voice-1")]})
        self.assertEqual(got["verdict"], "contradicted")
        self.assertIn("original UID", got["detail"])

    def test_a_terminating_original_is_in_progress_rather_than_contradicted(self):
        got = run({"pods": [F.pod(POD, uid="original-uid",
                                  deletion_timestamp="2026-09-10T18:31:00Z")]})
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("still terminating", got["detail"])

    def test_no_captured_identity_cannot_be_verified(self):
        for base in ({}, {POD: {"uid": None}}):
            with self.subTest(base=base):
                self.assertEqual(run({"pods": []}, base=base)["verdict"], "unverifiable")

    def test_a_captured_pod_with_no_controller_uid_cannot_attribute_a_successor(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid")]}, base=baseline(owner=None))
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no controller UID was captured", got["detail"])

    def test_another_namespace_is_never_verified_against_this_baseline(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1")]},
                  namespace="nats")
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("baseline covers voice only", got["detail"])

    def test_the_observation_interval_is_recorded(self):
        got = run({"pods": []})
        window = got["observationWindow"]
        self.assertTrue(window["actionStartedAt"].startswith("2025-"))
        self.assertIsNotNone(window["observedAt"])
        self.assertGreater(window["intervalSec"], 0)


class QuarantineTests(unittest.TestCase):
    def quarantine(self, pods, policies, base=None):
        return run({"pods": pods, "network_policies": policies}, action="quarantine", base=base)

    def test_a_deny_all_policy_selecting_the_exact_uid_is_confirmed_as_configuration(self):
        pod, policy = F.quarantined(POD, uid="original-uid")
        got = self.quarantine([pod], [policy])
        self.assertEqual(got["verdict"], "confirmed")
        self.assertIn("configuration evidence only", got["detail"])
        self.assertIn("not probed", got["detail"])
        # Structured, not just prose: a consumer reading fields cannot lose the distinction.
        self.assertEqual(got["evidenceLevel"], "configuration")
        self.assertIs(got["effectObserved"], False)

    def test_an_observed_replacement_is_marked_as_a_measured_effect(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1",
                                  creation=AFTER)]})
        self.assertEqual(got["evidenceLevel"], "object-identity")
        self.assertIs(got["effectObserved"], True)

    def test_a_workload_log_confirmation_is_marked_as_a_measured_effect(self):
        got = run({"pods": [F.pod(POD, uid="original-uid")],
                   "logs": {POD: "vLLM reset_prefix_cache done\n"}},
                  action="kv-reset", patterns={"kv-reset": "reset_prefix_cache"})
        self.assertEqual(got["evidenceLevel"], "workload-log")
        self.assertIs(got["effectObserved"], True)

    def test_a_missing_policy_contradicts_the_claim(self):
        pod, _ = F.quarantined(POD, uid="original-uid")
        got = self.quarantine([pod], [])
        self.assertEqual(got["verdict"], "contradicted")
        self.assertIn("does not exist", got["detail"])

    def test_a_policy_that_selects_nothing_contradicts_the_claim(self):
        pod, policy = F.quarantined(POD, uid="original-uid")
        pod["metadata"]["labels"] = {}
        got = self.quarantine([pod], [policy])
        self.assertEqual(got["verdict"], "contradicted")

    def test_an_additive_allow_policy_means_isolation_is_not_established(self):
        pod, policy = F.quarantined(POD, uid="original-uid")
        allow = F.network_policy("allow-metrics", match_labels={}, ingress=[{"from": []}])
        got = self.quarantine([pod], [policy, allow])
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("additively allow", got["detail"])

    def test_a_recycled_pod_name_under_a_new_uid_is_not_our_target(self):
        pod, policy = F.quarantined(POD, uid="a-different-instance")
        got = self.quarantine([pod], [policy])
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("different instance", got["detail"])

    def test_an_unreadable_namespace_is_unverifiable(self):
        pod, policy = F.quarantined(POD, uid="original-uid")
        got = run({"pods": [pod], "network_policies": [policy],
                   "deny": {"get networkpolicy": (1, "", F.FORBIDDEN)}}, action="quarantine")
        self.assertEqual(got["verdict"], "unverifiable")


class ServiceLogTests(unittest.TestCase):
    patterns = {"kv-reset": "reset_prefix_cache"}

    def log(self, text, action="kv-reset", patterns=None, uid="original-uid"):
        return run({"pods": [F.pod(POD, uid=uid)], "logs": {POD: text}},
                   action=action, patterns=self.patterns if patterns is None else patterns)

    def test_a_command_specific_line_in_the_window_confirms_the_action(self):
        got = self.log("INFO vLLM reset_prefix_cache completed in 12ms\n")
        self.assertEqual(got["verdict"], "confirmed")
        self.assertIn("reset_prefix_cache", got["evidence"])

    def test_a_generic_historical_lora_banner_confirms_nothing(self):
        """The old check grepped for 'lora' over five minutes of log."""
        got = self.log("INFO loading lora adapter config at startup\n", action="adapter-rotate")
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no reviewed command-specific log pattern is configured", got["detail"])

    def test_an_absent_line_contradicts_a_claimed_reset(self):
        got = self.log("INFO serving requests\n")
        self.assertEqual(got["verdict"], "contradicted")
        self.assertIn("no line matching the reviewed pattern", got["detail"])

    def test_a_log_from_a_replaced_instance_cannot_answer_for_the_action(self):
        got = self.log("INFO vLLM reset_prefix_cache completed\n", uid="a-new-instance")
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no longer the observed instance", got["evidence"])

    def test_without_a_decision_time_no_log_evidence_is_bounded(self):
        # The log window comes from THIS decision's own time, not the run's start: two
        # kv-resets minutes apart must not share one window.
        got = run({"pods": [F.pod(POD, uid="original-uid")],
                   "logs": {POD: "reset_prefix_cache\n"}},
                  action="kv-reset", patterns=self.patterns, decided=None)
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("no usable time", got["detail"])

    def test_the_log_window_starts_at_this_decision_not_the_run(self):
        transport = F.FakeKubectl(pods=[F.pod(POD, uid="original-uid")],
                                  logs={POD: "reset_prefix_cache\n"})
        verify(Cluster(transport),
               [{"namespace": NS, "pod": POD, "action": "kv-reset", "actuated": True,
                 "time": "2025-09-04T15:40:00Z"}],
               baseline(), namespace=NS, action_started_at=STARTED,
               log_patterns=self.patterns)
        self.assertTrue(any("--since-time=2025-09-04T15:39:58Z" in c
                            for c in transport.commands), transport.commands)


class AttributionTests(unittest.TestCase):
    def test_an_observed_effect_is_reported_without_claiming_a_cause(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1")]})
        self.assertEqual(got["verdict"], "confirmed")
        # The effect is observed; the cause is not. `unsupported` is the stronger statement
        # of the two absences: this schema has no field that could ever carry it.
        self.assertEqual(got["attribution"], "unsupported")
        self.assertIn("no forensic event identity", got["attributionDetail"])

    def test_a_correlated_effect_says_so(self):
        got = run({"pods": [F.pod("voice-b", uid="new-uid", owner_uid="rs-voice-1")]},
                  attribution_of=lambda r: ("correlated", "bound to event abcd1234"))
        self.assertEqual(got["attribution"], "correlated")


class UnknownActionTests(unittest.TestCase):
    def test_an_action_with_no_independent_check_is_never_confirmed(self):
        got = run({"pods": []}, action="warm-swap")
        self.assertEqual(got["verdict"], "unverifiable")
        self.assertIn("deliberately not confirmed", got["detail"])


if __name__ == "__main__":
    unittest.main()
