"""The check-catalogue repairs, each against the record shape the operator really emits.

Every test here is paired: the input that used to produce a false PASS, and the input that
must still produce a real PASS. A check that only got stricter would be a regression of a
different kind.
"""
import json
import math
import unittest
from pathlib import Path
from types import SimpleNamespace

import checks
import e2e
import fixtures as F
import observation as obs

INV = json.loads((Path(__file__).resolve().parents[1] / "config.json").read_text())["invariants"]


def ctx(records=(), **extra):
    base = dict(records=list(records), inv=INV, target=None, baseline_pods={},
                stateful_by_pod={}, ground_truth=[], attack_fired=False,
                controller_pods={}, writer_metrics={}, max_restarts=10, stale_after_sec=180,
                policy=None, policy_observation=None, max_moves_per_tick=None,
                preflight={}, post_records=[], scope=None, parse_time=e2e.Ctx.parse_time)
    base.update(extra)
    return SimpleNamespace(**base)


class NumericSweepTests(unittest.TestCase):
    """PH02 is the global NaN sweep; it was only reading the surface of the record."""

    def test_a_nan_nested_in_a_decision_trace_is_found(self):
        record = F.record(decisionTrace={"inputs": {"vramFraction": {"present": True,
                                                                    "value": float("nan")}}})
        got = checks.ph02(ctx([record]))
        self.assertEqual(got["status"], "fail")
        self.assertIn("decisionTrace.inputs.vramFraction.value", got["evidence"][0])

    def test_a_nan_in_a_nested_list_of_objects_is_found(self):
        record = F.record(pHoldInputs={"terms": [{"weight": 1.0}, {"weight": float("inf")}]})
        self.assertEqual(checks.ph02(ctx([record]))["status"], "fail")

    def test_a_top_level_nan_still_fails(self):
        self.assertEqual(checks.ph02(ctx([F.record(cost=float("nan"))]))["status"], "fail")

    def test_a_deeply_nested_finite_record_still_passes(self):
        record = F.record(decisionTrace={"inputs": {"vramFraction": {"value": 0.25}},
                                         "terms": [{"weight": 1.5}]})
        got = checks.ph02(ctx([record]))
        self.assertEqual(got["status"], "pass")
        self.assertIn("all finite", got["summary"])

    def test_booleans_are_not_swept_as_numbers(self):
        got = checks.ph02(ctx([F.record(nested={"flag": True})]))
        self.assertEqual(got["status"], "pass")


class CompositeTests(unittest.TestCase):
    """C03/C07: an all-absent composite reported PASS."""

    def bare(self):
        # A record with none of the composite's components present.
        return {"namespace": "voice", "pod": "voice-a", "time": "2026-09-10T18:30:00Z"}

    def test_all_absent_components_are_skip_not_pass(self):
        for fn in (checks.c03, checks.c07):
            with self.subTest(fn=fn.__name__):
                got = fn(ctx([self.bare()]))
                self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))

    def test_all_present_and_in_range_passes_at_full_coverage(self):
        for fn in (checks.c03, checks.c07):
            with self.subTest(fn=fn.__name__):
                got = fn(ctx([F.record()]))
                self.assertEqual((got["status"], got["coverage"]), ("pass", "full"))

    def test_one_absent_component_is_partial_coverage(self):
        record = F.record()
        del record["preemptMargin"]
        del record["stageHazard"]
        got = checks.c07(ctx([record]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))

    def test_one_out_of_range_component_fails_the_composite(self):
        got = checks.c03(ctx([F.record(exposure=1.4)]))
        self.assertEqual(got["status"], "fail")

    def test_a_present_but_nonfinite_component_fails_rather_than_skipping(self):
        got = checks.c03(ctx([F.record(exposure=float("nan"))]))
        self.assertEqual(got["status"], "fail")


class BoundedFieldTests(unittest.TestCase):
    def test_a_field_absent_from_every_record_is_unavailable_not_zero(self):
        record = F.record()
        del record["residual"]
        got = checks.ph01(ctx([record]))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))
        self.assertIn("unavailable, not zero", got["summary"])

    def test_a_required_field_missing_from_only_some_records_still_fails(self):
        missing = F.record(pod="voice-b")
        del missing["residual"]
        got = checks.ph01(ctx([F.record(), missing]))
        self.assertEqual(got["status"], "fail")

    def test_an_optional_field_missing_from_some_records_is_partial(self):
        missing = F.record(pod="voice-b")
        del missing["lambda"]
        got = checks.b04(ctx([F.record(), missing]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))


class ReadinessTests(unittest.TestCase):
    """P04 read `phase == Running`, which is scheduling, not serving."""

    def baseline(self, **kwargs):
        pod = F.pod("voice-a", **kwargs)
        from transport import _pod_identity
        return {"voice-a": _pod_identity(pod, "voice")}

    def test_running_but_not_ready_is_a_failure(self):
        got = checks.p04(ctx(baseline_pods=self.baseline(ready=False)))
        self.assertEqual(got["status"], "fail")

    def test_running_and_ready_passes(self):
        got = checks.p04(ctx(baseline_pods=self.baseline()))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "full"))

    def test_a_terminating_ready_pod_is_not_a_serving_target(self):
        got = checks.p04(ctx(baseline_pods=self.baseline(
            deletion_timestamp="2026-09-10T18:31:00Z")))
        self.assertEqual(got["status"], "fail")

    def test_a_pod_with_no_ready_condition_reduces_coverage(self):
        pods = self.baseline()
        pods["voice-b"] = dict(pods["voice-a"], name="voice-b", ready=None, phase="Pending")
        got = checks.p04(ctx(baseline_pods=pods))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))
        self.assertIn("reported no Ready condition", got["summary"])


class NetIdentityTests(unittest.TestCase):
    """B01 checked `risk`, a field phorvex.audit.v2 retired; it skipped on every run."""

    def test_the_identity_is_checked_against_coverage_value(self):
        got = checks.b01(ctx([F.record()]))
        self.assertEqual(got["status"], "pass")
        self.assertNotIn("no record carried", got["summary"])

    def test_a_broken_identity_is_caught(self):
        got = checks.b01(ctx([F.record(net=99.0)]))
        self.assertEqual(got["status"], "fail")
        self.assertIn("coverageValue", got["evidence"][0])

    def test_a_retired_risk_field_does_not_resurrect_the_old_reading(self):
        # A record carrying the retired name cannot be produced by the v2 writer; if one
        # appears it must not be used to satisfy the identity.
        record = F.record(risk=99.0)
        self.assertEqual(checks.b01(ctx([record]))["status"], "pass")
        self.assertEqual(checks.b01(ctx([F.record(risk=99.0, net=99.0)]))["status"], "fail")

    def test_an_absent_lambda_is_read_as_the_documented_zero(self):
        record = F.record(lambda_placeholder=None)
        del record["lambda_placeholder"]
        del record["lambda"]
        record["net"] = record["coverageValue"]
        self.assertEqual(checks.b01(ctx([record]))["status"], "pass")

    def test_an_unknown_engine_is_not_asserted_against_this_identity(self):
        got = checks.b01(ctx([F.record(engine="some-future-engine")]))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))
        got = checks.b01(ctx([F.record(), F.record(pod="b", engine="some-future-engine")]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))


class BudgetOwnerTests(unittest.TestCase):
    """B07 grouped by tenant, attributing other owners' selections to one policy."""

    policy = {"uid": "policy-uid-1", "name": "voice-defense", "namespace": "voice",
              "budgetDeclared": True}

    def selections(self, namespace, count, time="2026-09-10T18:30:00Z"):
        return [F.record(namespace=namespace, tenant="shared", pod=f"p{i}", time=time,
                         selected=True, action="rotate") for i in range(count)]

    def test_a_breach_inside_the_owning_namespace_fails(self):
        got = checks.b07(ctx(self.selections("voice", 3), policy=self.policy,
                             max_moves_per_tick=1))
        self.assertEqual(got["status"], "fail")

    def test_selections_in_another_namespace_are_not_charged_to_this_policy(self):
        got = checks.b07(ctx(self.selections("nats", 3) + self.selections("voice", 1),
                             policy=self.policy, max_moves_per_tick=1))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))
        self.assertIn("outside its namespace", got["summary"])

    def test_without_a_policy_identity_no_owner_wide_budget_is_claimed(self):
        read = obs.Observation.partial(None, "2 PhorvexPolicies govern voice")
        got = checks.b07(ctx(self.selections("voice", 9), policy=None,
                             policy_observation=read, max_moves_per_tick=None))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))
        self.assertIn("no owner-wide budget", got["summary"])

    def test_an_operator_default_budget_is_labelled_as_such(self):
        got = checks.b07(ctx(self.selections("voice", 1),
                             policy=dict(self.policy, budgetDeclared=False),
                             max_moves_per_tick=3))
        self.assertIn("operator default", got["evidence"][0])


class GroundTruthRollupTests(unittest.TestCase):
    """A03 called a half-observed set of claims a pass."""

    @staticmethod
    def gt(verdict, attribution="unsupported", action="rotate", pod="voice-a",
           level="object-identity", observed=True):
        return {"verdict": verdict, "action": action, "namespace": "voice", "pod": pod,
                "detail": "fixture", "attribution": attribution,
                "evidenceLevel": level, "effectObserved": observed}

    def test_a_mix_of_confirmed_and_unverifiable_is_not_a_pass(self):
        got = checks.a03(ctx(ground_truth=[self.gt("confirmed"),
                                           self.gt("unverifiable", pod="voice-b")]))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "partial"))

    def test_all_unverifiable_is_not_a_pass(self):
        got = checks.a03(ctx(ground_truth=[self.gt("unverifiable")]))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "none"))

    def test_all_confirmed_but_unattributed_passes_at_partial_coverage(self):
        got = checks.a03(ctx(ground_truth=[self.gt("confirmed")]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))
        self.assertIn("could not be attributed", got["summary"])

    def test_all_confirmed_and_correlated_is_full_coverage(self):
        got = checks.a03(ctx(ground_truth=[self.gt("confirmed", attribution="correlated")]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "full"))

    def test_a_configuration_only_confirmation_is_never_reported_as_measured(self):
        got = checks.a03(ctx(ground_truth=[
            self.gt("confirmed", attribution="correlated", action="quarantine",
                    level="configuration", observed=False)]))
        self.assertEqual((got["status"], got["coverage"]), ("pass", "partial"))
        self.assertIn("not on measured enforcement", got["summary"])
        self.assertIn("configuration", got["evidence"][0])

    def test_a_contradiction_still_fails(self):
        got = checks.a03(ctx(ground_truth=[self.gt("confirmed"), self.gt("contradicted")]))
        self.assertEqual(got["status"], "fail")


class KillSwitchReadTests(unittest.TestCase):
    """A06/A07 could not tell a failed scrape from an absent gauge."""

    def live(self):
        return [F.record(selected=True, feasible=True, dryRun=False, action="rotate")]

    def test_a_failed_scrape_is_reported_as_the_reason_the_gauge_is_missing(self):
        read = obs.Observation.unavailable("connection refused", source="metrics")
        got = checks.a06(ctx(self.live(), writer_metrics={}, metrics_observation=read))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "none"))
        self.assertIn("connection refused", got["evidence"][0])

    def test_a_successful_scrape_without_the_gauge_says_so(self):
        read = obs.Observation.observed({"other_metric": 1.0})
        got = checks.a06(ctx(self.live(), writer_metrics={"other_metric": 1.0},
                             metrics_observation=read))
        self.assertIn("exposed no phorvex_kill_switch_engaged gauge", got["evidence"][0])

    def test_the_engaged_kill_switch_verdicts_are_unchanged(self):
        metrics = {"phorvex_kill_switch_engaged": 1.0}
        read = obs.Observation.observed(metrics)
        self.assertEqual(checks.a06(ctx(self.live(), writer_metrics=metrics,
                                        metrics_observation=read))["status"], "pass")
        acted = [F.record(selected=True, feasible=True, actuated=True, action="rotate")]
        self.assertEqual(checks.a06(ctx(acted, writer_metrics=metrics,
                                        metrics_observation=read))["status"], "fail")

    def test_a07_skips_with_the_scrape_reason_rather_than_silently(self):
        read = obs.Observation.unavailable("connection refused", source="metrics")
        got = checks.a07(ctx([F.record()], writer_metrics={}, metrics_observation=read))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))
        self.assertIn("connection refused", got["summary"])


class StatefulTests(unittest.TestCase):
    def test_an_unobserved_stateful_status_is_not_read_as_stateless(self):
        got = checks.f03(ctx([F.record(namespace="voice", pod="voice-b", selected=True,
                                       action="rotate")],
                             stateful_by_pod={("voice", "voice-a"): True}))
        self.assertEqual((got["status"], got["coverage"]), ("warn", "partial"))
        self.assertIn("stateful status unobserved", got["evidence"][0])

    def test_a_rotate_against_an_observed_stateful_pod_still_fails(self):
        got = checks.f03(ctx([F.record(selected=True, action="rotate")],
                             stateful_by_pod={("voice", "voice-a"): True}))
        self.assertEqual(got["status"], "fail")

    def test_no_stateful_pod_is_not_applicable_rather_than_a_pass(self):
        got = checks.f03(ctx([F.record()], stateful_by_pod={("voice", "voice-a"): False}))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "not-applicable"))


class HazardIdentityTests(unittest.TestCase):
    def test_a_record_without_a_hazard_is_not_assumed_to_have_hazard_zero(self):
        record = F.record(projectedNextStageSec=-30.0)
        del record["stageHazard"]
        got = checks.c08(ctx([record]))
        self.assertEqual((got["status"], got["coverage"]), ("skip", "none"))

    def test_the_exact_identity_is_still_enforced(self):
        self.assertEqual(
            checks.c08(ctx([F.record(projectedNextStageSec=-30.0, stageHazard=0.2)]))["status"],
            "fail")
        self.assertEqual(
            checks.c08(ctx([F.record(projectedNextStageSec=-30.0, stageHazard=0.8)]))["status"],
            "pass")


class ScopeTests(unittest.TestCase):
    def test_a_scoped_capture_is_never_reported_as_cluster_wide_coverage(self):
        from capture import CaptureScope
        scoped = ctx([F.record(selected=True, action="rotate")], scope=CaptureScope(["voice"]))
        for fn in (checks.ph02, checks.i01, checks.b08):
            with self.subTest(fn=fn.__name__):
                got = fn(scoped)
                self.assertEqual(got["coverage"], "partial")
                self.assertIn("capture scope", got["summary"])
        globally = ctx([F.record()], scope=CaptureScope(None))
        self.assertEqual(checks.ph02(globally)["coverage"], "full")


class DedupeTests(unittest.TestCase):
    def test_another_namespace_sharing_time_pod_and_action_is_kept(self):
        a = F.record(namespace="voice", pod="worker-0", action="rotate")
        b = F.record(namespace="nats", pod="worker-0", action="rotate")
        self.assertEqual(len(e2e.dedupe([a, b])), 2)

    def test_another_tenant_sharing_everything_else_is_kept(self):
        a = F.record(tenant="a")
        b = F.record(tenant="b")
        self.assertEqual(len(e2e.dedupe([a, b])), 2)

    def test_a_genuine_replay_of_the_same_decision_is_collapsed(self):
        self.assertEqual(len(e2e.dedupe([F.record(), F.record()])), 1)


class RegistryTests(unittest.TestCase):
    def test_every_check_declares_the_inputs_its_verdict_rests_on(self):
        for entry in checks.registry():
            with self.subTest(check=entry["id"]):
                self.assertTrue(entry["inputs"], entry["id"])

    def test_every_check_returns_a_declared_coverage(self):
        allowed = {"full", "partial", "none", "not-applicable"}
        empty = ctx()
        for entry in checks.registry():
            with self.subTest(check=entry["id"]):
                try:
                    got = entry["fn"](empty)
                except Exception:            # a check needing more context is fine here
                    continue
                self.assertIn(got["coverage"], allowed)
                self.assertNotEqual((got["status"], got["coverage"]), ("pass", "none"))

    def test_the_documented_catalogue_matches_the_registry(self):
        doc = (Path(__file__).resolve().parents[1] / "CHECKS.md").read_text()
        for entry in checks.registry():
            with self.subTest(check=entry["id"]):
                self.assertIn(f"`{entry['id']}`", doc)


if __name__ == "__main__":
    unittest.main()
