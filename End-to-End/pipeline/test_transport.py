import json
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from transport import Cluster
from checks import p05
import e2e


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
    expected = ['controller-a', 'controller-b']

    @staticmethod
    def workload(name):
        def ref(kind, uid):
            return [{'kind': kind, 'uid': uid, 'controller': True}]
        return [
            {'kind': 'Deployment', 'metadata': {'name': name, 'uid': name}},
            {'kind': 'ReplicaSet', 'metadata': {'name': name + '-rs', 'uid': name + '-rs',
                'ownerReferences': ref('Deployment', name)}},
            {'kind': 'Pod', 'metadata': {'name': name + '-pod', 'uid': name + '-pod',
                'ownerReferences': ref('ReplicaSet', name + '-rs')},
             'spec': {'containers': [{'name': 'manager'}]},
             'status': {'phase': 'Running', 'containerStatuses': [{'name': 'manager', 'restartCount': 0}],
                        'conditions': [{'type': 'Ready', 'status': 'True'}]}},
        ]

    def setUp(self):
        self.items = sum((self.workload(name) for name in self.expected), [])

    def discover(self, items=None):
        return Cluster(RawTransport(json.dumps({'items': self.items if items is None else items}))).controller_pods(
            deployments=self.expected)

    def verdict(self, pods):
        return p05(SimpleNamespace(controller_pods=pods, max_restarts=10))['status']

    def test_healthy_controllers_ignore_bare_job_and_unrelated_replica_set_helpers(self):
        self.assertEqual(self.verdict(self.discover()), 'pass')
        self.items += self.workload('unrelated-helper')
        for kind in ('', 'Job'):
            for phase in ('Pending', 'Failed', 'Succeeded'):
                self.items.append({'kind': 'Pod', 'metadata': {'name': kind + phase,
                    'ownerReferences': [{'kind': kind, 'uid': 'helper', 'controller': True}]},
                    'status': {'phase': phase}})
        pods = self.discover()
        self.assertEqual(set(pods), {'controller-a-pod', 'controller-b-pod'})
        self.assertEqual(self.verdict(pods), 'pass')

    def test_unhealthy_expected_controllers_are_never_filtered_out(self):
        for phase, restarts, ready in [('Pending', 0, 'False'), ('Failed', 0, 'False'),
                                        ('Running', 12, 'True'), ('Running', 0, 'False')]:
            with self.subTest(phase=phase, restarts=restarts, ready=ready):
                self.items[2]['status'] = {'phase': phase,
                    'containerStatuses': [{'name': 'manager', 'restartCount': 0}, {'name': 'sidecar', 'restartCount': restarts}],
                    'conditions': [{'type': 'Ready', 'status': ready}]}
                pods = self.discover()
                self.assertIn('controller-a-pod', pods)
                self.assertEqual(self.verdict(pods), 'fail')

    def test_missing_deployment_or_owned_pods_cannot_be_a_pass(self):
        for items in ([], self.items[3:], self.items[:2] + self.items[3:], self.workload('helper')):
            with self.subTest(items=items):
                pods = self.discover(items)
                self.assertEqual(pods['deployment/controller-a']['phase'], 'Missing')
                self.assertEqual(self.verdict(pods), 'fail')
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
            transport = Mock()
            transport.run.return_value = (rc, raw, 'read failure')
            pods = Cluster(transport).controller_pods(deployments=self.expected)
            self.assertEqual({m['phase'] for m in pods.values()}, {'Unknown'})
            self.assertEqual(self.verdict(pods), 'fail')
        self.items[2]['status']['containerStatuses'][0]['restartCount'] = 'unknown'
        pods = self.discover()
        self.assertEqual({m['phase'] for m in pods.values()}, {'Unknown'})
        self.assertEqual(self.verdict(pods), 'fail')

    def test_configuration_is_explicit_and_namespace_shell_quoted(self):
        from transport import TransportError
        for names in ([], '', [''], ['a', 'a'], [None]):
            with self.assertRaises(TransportError):
                Cluster(RawTransport('')).controller_pods(deployments=names)
        transport = Mock()
        transport.run.return_value = (0, json.dumps({'items': self.items}), '')
        pods = Cluster(transport).controller_pods("test ns'", self.expected)
        self.assertEqual(self.verdict(pods), 'pass')
        import shlex
        self.assertEqual(shlex.split(transport.run.call_args.args[0]),
                         ['kubectl', '-n', "test ns'", 'get', 'deployments.apps,replicasets.apps,pods', '-o', 'json'])

    def test_running_pod_with_missing_restart_evidence_cannot_pass(self):
        for containers in ([], [{}], [{'name': 'manager'}], [{'name': 'other', 'restartCount': 0}]):
            self.items[2]['status']['containerStatuses'] = containers
            pods = self.discover()
            self.assertEqual(self.verdict(pods), 'fail')
            self.assertEqual({m['phase'] for m in pods.values()}, {'Unknown'})

    def test_preflight_board_uses_the_same_health_verdict_as_p05(self):
        cfg = {'invariants': {}, 'transport': {'kind': 'local'}, 'console': {},
               'capture': {'stream_seconds': 1, 'max_bytes': 1000}, 'targets': [],
               'controller_deployments': self.expected}
        for items in (self.items, self.items[3:], []):
            transport = RawTransport(json.dumps({'items': items}))
            transport.describe = lambda: 'offline fixture'
            notifier = Mock()
            with patch.object(e2e, 'Transport', return_value=transport), \
                 patch.object(e2e.Console, 'wait_preflight', return_value=({'ok': True}, {'operator': 'test'})), \
                 patch.object(e2e.Metrics, 'scrape', return_value={}), \
                 patch.object(e2e.Console, 'stream_decisions', side_effect=RuntimeError('stop after preflight')), \
                 tempfile.TemporaryDirectory() as directory:
                doc, rc = e2e.run(cfg, 'observe', None, directory, notifier=notifier)
                self.assertEqual(rc, 2)
                self.assertIn('stop after preflight', doc['abort']['error'])
            state = notifier.stage.call_args_list[0].args[1]
            self.assertEqual(state, 'ok' if self.verdict(self.discover(items)) == 'pass' else 'fail')


if __name__ == "__main__":
    unittest.main()
