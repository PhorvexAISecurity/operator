import json
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import fixtures as F
import observation as obs
from transport import Cluster, TransportError, selector_matches
from checks import p05
import e2e


class RawTransport:
    def __init__(self, output, rc=0, err=""):
        self.output, self.rc, self.err = output, rc, err

    def run(self, command, timeout=60):
        return self.rc, self.output, self.err


class SelectorTests(unittest.TestCase):
    """matchExpressions are half of a LabelSelector; reading only matchLabels missed them."""

    def test_match_labels_and_expressions(self):
        labels = {"app": "voice", "tier": "edge"}
        self.assertTrue(selector_matches({}, labels))                     # empty selects all
        self.assertTrue(selector_matches({"matchLabels": {"app": "voice"}}, labels))
        self.assertFalse(selector_matches({"matchLabels": {"app": "other"}}, labels))
        for expression, expected in (
                ({"key": "app", "operator": "In", "values": ["voice"]}, True),
                ({"key": "app", "operator": "In", "values": ["other"]}, False),
                ({"key": "app", "operator": "NotIn", "values": ["voice"]}, False),
                ({"key": "app", "operator": "Exists"}, True),
                ({"key": "absent", "operator": "Exists"}, False),
                ({"key": "absent", "operator": "DoesNotExist"}, True),
                ({"key": "app", "operator": "DoesNotExist"}, False)):
            with self.subTest(expression=expression):
                self.assertEqual(
                    selector_matches({"matchExpressions": [expression]}, labels), expected)

    def test_unknown_operator_is_an_error_not_a_silent_non_match(self):
        with self.assertRaises(ValueError):
            selector_matches({"matchExpressions": [{"key": "a", "operator": "Sometimes"}]},
                             {"a": "b"})


class PodInventoryTests(unittest.TestCase):
    def read(self, **kwargs):
        return Cluster(F.FakeKubectl(**kwargs)).pod_uids("voice")

    def test_identity_carries_uid_owner_readiness_and_termination(self):
        got = self.read(pods=[F.pod("voice-a", uid="u1", owner_uid="rs-1"),
                              F.pod("voice-b", uid="u2", ready=False,
                                    deletion_timestamp="2026-09-10T18:31:00Z")])
        self.assertTrue(got.ok)
        self.assertEqual(got.value["voice-a"]["uid"], "u1")
        self.assertEqual(got.value["voice-a"]["ownerUID"], "rs-1")
        self.assertIs(got.value["voice-a"]["ready"], True)
        self.assertIs(got.value["voice-b"]["ready"], False)
        self.assertTrue(got.value["voice-b"]["terminating"])
        self.assertEqual(got.value["voice-a"]["namespace"], "voice")

    def test_absent_ready_condition_is_unknown_not_false(self):
        got = self.read(pods=[F.pod("voice-a", ready=None, phase="Pending")])
        self.assertIsNone(got.value["voice-a"]["ready"])

    def test_empty_namespace_is_observed_not_unavailable(self):
        got = self.read(pods=[])
        self.assertTrue(got.ok)
        self.assertTrue(got.empty)
        self.assertEqual(got.value, {})

    def test_denied_timed_out_and_malformed_reads_are_never_observed(self):
        for answer, code in ((( 1, "", F.FORBIDDEN), obs.FORBIDDEN),
                             ((124, "", "timeout after 25s"), obs.TIMEOUT),
                             ((1, "", "Unable to connect to the server"), obs.UNREACHABLE)):
            with self.subTest(code=code):
                got = self.read(deny={"get pod": answer})
                self.assertFalse(got.usable)
                self.assertEqual(got.reason_code, code)
                self.assertIsNone(got.value)
        for raw in ("not json", '{"items":null}', '{"items":[{"metadata":{}}]}'):
            with self.subTest(raw=raw):
                got = Cluster(RawTransport(raw)).pod_uids("voice")
                self.assertEqual(got.status, obs.MALFORMED)
                self.assertIsNone(got.value)


class QuarantineStateTests(unittest.TestCase):
    def state(self, pods, policies, expect_uid=None):
        return Cluster(F.FakeKubectl(pods=pods, network_policies=policies)).quarantine_state(
            "voice", "voice-a", expect_uid=expect_uid)

    def test_active_when_deny_all_policy_selects_the_pod(self):
        got = self.state(*[[x] for x in F.quarantined("voice-a")])
        self.assertTrue(got.ok)
        self.assertTrue(got.value["active"])
        self.assertIs(got.value["effectiveBlockingProven"], False)

    def test_inactive_when_replacement_pod_lost_the_selector_label(self):
        pod, policy = F.quarantined("voice-a")
        pod["metadata"]["labels"] = {}
        got = self.state([pod], [policy])
        self.assertFalse(got.value["active"])
        self.assertIn("selectsPod=false", got.value["evidence"])

    def test_expression_based_selector_is_honoured(self):
        pod, _ = F.quarantined("voice-a")
        policy = F.network_policy(
            "voice-voice-a-policy",
            match_expressions=[{"key": F.QUARANTINE_LABEL, "operator": "Exists"}])
        self.assertTrue(self.state([pod], [policy]).value["active"])

    def test_additive_allow_policy_is_recorded_beside_the_deny_all(self):
        pod, policy = F.quarantined("voice-a")
        allow = F.network_policy("open-egress", match_labels={}, egress=[{"to": []}])
        got = self.state([pod], [policy, allow])
        self.assertTrue(got.value["active"])
        self.assertEqual(got.value["additiveAllowPolicies"], ["open-egress"])

    def test_a_different_instance_under_the_same_name_does_not_match_the_target(self):
        pod, policy = F.quarantined("voice-a", uid="replacement")
        got = self.state([pod], [policy], expect_uid="original")
        self.assertFalse(got.value["identityMatches"])
        self.assertFalse(got.value["active"])

    def test_unreadable_pod_or_policies_are_unavailable(self):
        pod, policy = F.quarantined("voice-a")
        for deny in ({"get pod": (1, "", F.FORBIDDEN)},
                     {"get networkpolicy": (1, "", F.FORBIDDEN)}):
            with self.subTest(deny=deny):
                got = Cluster(F.FakeKubectl(pods=[pod], network_policies=[policy],
                                            deny=deny)).quarantine_state("voice", "voice-a")
                self.assertFalse(got.usable)

    def test_deleted_pod_is_partial_not_a_selecting_policy(self):
        _, policy = F.quarantined("voice-a")
        got = self.state([], [policy])
        self.assertEqual(got.status, obs.PARTIAL)
        self.assertFalse(got.value["active"])


class ContainerLogTests(unittest.TestCase):
    def read(self, uid="uid-voice-a", pattern="reset_prefix_cache", logs=None, pods=None):
        cluster = Cluster(F.FakeKubectl(
            pods=pods if pods is not None else [F.pod("voice-a")],
            logs=logs if logs is not None else {"voice-a": "vLLM reset_prefix_cache done\n"}))
        return cluster.container_log("voice", "voice-a", uid, 1_757_000_000, pattern)

    def test_matches_are_bound_to_pattern_window_and_instance(self):
        got = self.read()
        self.assertTrue(got.ok)
        self.assertEqual(got.value["matches"], ["vLLM reset_prefix_cache done"])
        self.assertTrue(got.value["sinceTime"].endswith("Z"))

    def test_a_replaced_instance_cannot_answer_for_the_action(self):
        got = self.read(uid="the-original-uid")
        self.assertFalse(got.usable)
        self.assertIn("no longer the observed instance", got.reason)

    def test_since_time_is_passed_to_kubectl(self):
        transport = F.FakeKubectl(pods=[F.pod("voice-a")], logs={"voice-a": ""})
        Cluster(transport).container_log("voice", "voice-a", "uid-voice-a", 1_757_000_000,
                                         "anything")
        self.assertTrue(any("--since-time=2025-" in c for c in transport.commands),
                        transport.commands)

    def test_generic_startup_banner_does_not_match_a_command_pattern(self):
        got = self.read(pattern="reset_prefix_cache",
                        logs={"voice-a": "INFO loading lora adapter config at startup\n"})
        self.assertEqual(got.value["matches"], [])


class PhorvexPolicyTests(unittest.TestCase):
    def read(self, policies, **kwargs):
        return Cluster(F.FakeKubectl(policies=policies, **kwargs)).phorvex_policy("voice")

    def test_identity_and_budget_are_read_together(self):
        got = self.read([F.phorvex_policy(max_moves=2)])
        self.assertEqual(got.value["uid"], "policy-uid-1")
        self.assertEqual(got.value["maxMovesPerTick"], 2)
        self.assertTrue(got.value["budgetDeclared"])

    def test_undeclared_budget_is_marked_rather_than_invented(self):
        got = self.read([F.phorvex_policy(declare_budget=False)])
        self.assertIsNone(got.value["maxMovesPerTick"])
        self.assertFalse(got.value["budgetDeclared"])

    def test_two_policies_have_no_single_owner_for_a_budget(self):
        got = self.read([F.phorvex_policy(uid="a"), F.phorvex_policy(name="second", uid="b")])
        self.assertEqual(got.status, obs.PARTIAL)
        self.assertIsNone(got.value)

    def test_no_policy_and_unreadable_policies_are_different_facts(self):
        empty = self.read([])
        self.assertTrue(empty.ok)
        self.assertIsNone(empty.value)
        self.assertEqual(empty.reason_code, obs.NOT_FOUND)
        denied = self.read([], deny={"get phorvexpolicy": (1, "", F.FORBIDDEN)})
        self.assertFalse(denied.usable)
        self.assertEqual(denied.reason_code, obs.FORBIDDEN)


class ControllerPodsTests(unittest.TestCase):
    expected = ['controller-a', 'controller-b']

    @staticmethod
    def workload(name):
        return F.deployment_stack(name)

    def setUp(self):
        self.items = sum((self.workload(name) for name in self.expected), [])

    def discover(self, items=None):
        return Cluster(RawTransport(json.dumps({'items': self.items if items is None else items}))
                       ).controller_pods(deployments=self.expected)

    def verdict(self, read):
        pods = read.value if hasattr(read, 'value') else read
        return p05(SimpleNamespace(
            controller_pods=pods, max_restarts=10,
            controller_observation=read if hasattr(read, 'value') else None))['status']

    def test_healthy_controllers_ignore_bare_job_and_unrelated_replica_set_helpers(self):
        self.assertEqual(self.verdict(self.discover()), 'pass')
        self.items += self.workload('unrelated-helper')
        for kind in ('', 'Job'):
            for phase in ('Pending', 'Failed', 'Succeeded'):
                self.items.append({'kind': 'Pod', 'metadata': {'name': kind + phase,
                    'ownerReferences': [{'kind': kind, 'uid': 'helper', 'controller': True}]},
                    'status': {'phase': phase}})
        read = self.discover()
        self.assertEqual(set(read.value), {'controller-a-pod', 'controller-b-pod'})
        self.assertEqual(self.verdict(read), 'pass')

    def test_unhealthy_expected_controllers_are_never_filtered_out(self):
        for phase, restarts, ready in [('Pending', 0, 'False'), ('Failed', 0, 'False'),
                                        ('Running', 12, 'True'), ('Running', 0, 'False')]:
            with self.subTest(phase=phase, restarts=restarts, ready=ready):
                self.items[2]['status'] = {'phase': phase,
                    'containerStatuses': [{'name': 'manager', 'restartCount': 0}, {'name': 'sidecar', 'restartCount': restarts}],
                    'conditions': [{'type': 'Ready', 'status': ready}]}
                read = self.discover()
                self.assertIn('controller-a-pod', read.value)
                self.assertEqual(self.verdict(read), 'fail')

    def test_missing_deployment_or_owned_pods_cannot_be_a_pass(self):
        for items in ([], self.items[3:], self.items[:2] + self.items[3:], self.workload('helper')):
            with self.subTest(items=items):
                read = self.discover(items)
                self.assertEqual(read.value['deployment/controller-a']['phase'], 'Missing')
                self.assertEqual(self.verdict(read), 'fail')
        self.assertEqual(self.verdict({}), 'fail')

    def test_uid_and_controller_reference_must_match_at_both_hops(self):
        for index in (1, 2):
            for change in ({'uid': 'recreated-owner'}, {'controller': False}):
                with self.subTest(index=index, change=change):
                    self.setUp()
                    self.items[index]['metadata']['ownerReferences'][0].update(change)
                    self.assertEqual(self.verdict(self.discover()), 'fail')
        self.setUp()
        for index in (1, 2):
            self.items[index]['metadata']['ownerReferences'].insert(0,
                {'kind': 'Other', 'uid': 'not-owner', 'controller': False})
        self.assertEqual(self.verdict(self.discover()), 'pass')

    def test_unready_new_rollout_replica_remains_visible(self):
        pod = json.loads(json.dumps(self.items[2]))
        pod['metadata']['name'] = 'new-replica'
        pod['status'] = {'phase': 'Pending'}
        self.items.append(pod)
        self.assertEqual(self.verdict(self.discover()), 'fail')

    def test_unreadable_and_malformed_inventory_are_unknown_not_missing_or_pass(self):
        for rc, raw in [(1, ''), (0, 'not JSON'), (0, '{"items":null}'), (0, '{}')]:
            read = Cluster(RawTransport(raw, rc=rc, err='read failure')).controller_pods(
                deployments=self.expected)
            self.assertFalse(read.usable)
            self.assertEqual({m['phase'] for m in read.value.values()}, {'Unknown'})
            self.assertEqual(self.verdict(read), 'fail')
        self.items[2]['status']['containerStatuses'][0]['restartCount'] = 'unknown'
        read = self.discover()
        self.assertEqual(read.status, obs.MALFORMED)
        self.assertEqual({m['phase'] for m in read.value.values()}, {'Unknown'})
        self.assertEqual(self.verdict(read), 'fail')

    def test_configuration_is_explicit_and_namespace_shell_quoted(self):
        for names in ([], '', [''], ['a', 'a'], [None]):
            with self.assertRaises(TransportError):
                Cluster(RawTransport('')).controller_pods(deployments=names)
        transport = Mock()
        transport.run.return_value = (0, json.dumps({'items': self.items}), '')
        read = Cluster(transport).controller_pods("test ns'", self.expected)
        self.assertEqual(self.verdict(read), 'pass')
        import shlex
        self.assertEqual(shlex.split(transport.run.call_args.args[0]),
                         ['kubectl', '-n', "test ns'", 'get', 'deployments.apps,replicasets.apps,pods', '-o', 'json'])

    def test_running_pod_with_missing_restart_evidence_cannot_pass(self):
        for containers in ([], [{}], [{'name': 'manager'}], [{'name': 'other', 'restartCount': 0}]):
            self.items[2]['status']['containerStatuses'] = containers
            read = self.discover()
            self.assertEqual(self.verdict(read), 'fail')
            self.assertEqual({m['phase'] for m in read.value.values()}, {'Unknown'})

    def test_preflight_board_uses_the_same_health_verdict_as_p05(self):
        cfg = {'invariants': {}, 'transport': {'kind': 'local'}, 'console': {'mode': 'kubectl-proxy'},
               'capture': {'stream_seconds': 1, 'max_bytes': 1000}, 'targets': [],
               'controller_deployments': self.expected}
        for items in (self.items, self.items[3:], []):
            transport = RawTransport(json.dumps({'items': items}))
            transport.describe = lambda: 'offline fixture'
            notifier = Mock()
            with patch.object(e2e, 'Transport', return_value=transport), \
                 patch.object(e2e.Console, 'wait_preflight', return_value=({'ok': True}, {'operator': 'test'})), \
                 patch.object(e2e.Metrics, 'scrape', return_value=obs.Observation.observed({})), \
                 patch.object(e2e.Console, 'stream_decisions', side_effect=RuntimeError('stop after preflight')), \
                 tempfile.TemporaryDirectory() as directory:
                doc, rc = e2e.run(cfg, 'observe', None, directory, notifier=notifier)
                self.assertEqual(rc, 2)
                self.assertIn('stop after preflight', doc['abort']['error'])
            state = notifier.stage.call_args_list[0].args[1]
            self.assertEqual(state, 'ok' if self.verdict(self.discover(items)) == 'pass' else 'fail')


if __name__ == "__main__":
    unittest.main()
