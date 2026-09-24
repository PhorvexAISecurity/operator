"""Network-free producer controls against the actual detector module."""
import copy
import json
import signal
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import detector


NOW = 1790220000.0
LOCK_UID = "00000000-0000-4000-8000-000000000001"
CFG = detector.Config("owned", "models", 8001, "engine", frozenset(), "owned-proof", "adapter-detector", LOCK_UID)


def run(api, cfg, now):
    return detector.run_once(api, cfg, lambda: now)


def models(adapters=("owned-neutral-adapter",)):
    data = [{"id": "base", "parent": None}]
    data += [{"id": name, "parent": "base"} for name in adapters]
    return json.dumps({"data": data}).encode()


class FakeAPI:
    def __init__(self):
        self.now = NOW
        self.service = {"metadata": {"name": "models", "namespace": "owned", "uid": "service-uid", "resourceVersion": "1"},
                        "spec": {"selector": {"phorvex.ai/role": "leader"}, "ports": [{"port": 8001, "targetPort": 8001, "protocol": "TCP"}]}}
        self.pod = {"metadata": {"name": "engine-0", "namespace": "owned", "uid": "pod-uid-1", "resourceVersion": "2",
                                 "labels": {"phorvex.ai/role": "leader"}, "annotations": {"phorvex.ai/serving-port": "8001"}},
                    "spec": {"containers": [{"name": "engine", "ports": [{"containerPort": 8001, "protocol": "TCP"}]}]},
                    "status": {"phase": "Running", "podIP": "10.1.2.3", "conditions": [{"type": "Ready", "status": "True"}],
                               "containerStatuses": [{"name": "engine", "ready": True, "containerID": "containerd://one", "imageID": "image@sha256:one", "restartCount": 0}]}}
        self.slice = {"metadata": {"name": "models-abc", "namespace": "owned", "uid": "slice-uid", "resourceVersion": "3",
                                   "labels": {"kubernetes.io/service-name": "models"},
                                   "ownerReferences": [{"kind": "Service", "name": "models", "uid": "service-uid", "controller": True}]},
                      "addressType": "IPv4", "ports": [{"port": 8001, "protocol": "TCP"}],
                      "endpoints": [{"addresses": ["10.1.2.3"], "conditions": {"ready": True, "terminating": False},
                                     "targetRef": {"kind": "Pod", "namespace": "owned", "name": "engine-0", "uid": "pod-uid-1"}}]}
        self.inventory = models()
        self.events = {}
        self.posts = []
        self.lock = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": detector.lock_name(CFG), "namespace": "owned",
                     "uid": LOCK_UID, "resourceVersion": "4", "labels": {"phorvex.ai/adapter-detector": CFG.instance}}, "data": {}}
        self.lock_updates = []
        self.lock_uncertain = False
        self.bind_uncertain = False
        self.bind_reject_before_write = False
        self.after_models = None
        self.uncertain = False
        self.event_time_offset = 0
        self.replace_after_create = False

    def get(self, kind, namespace, name, allow_missing=False):
        assert namespace == "owned"
        obj = {"service": self.service, "pod": self.pod}[kind]
        if kind == "pod" and name != self.pod["metadata"]["name"]:
            return None if allow_missing else self.fail()
        return copy.deepcopy(obj)

    def fail(self):
        raise AssertionError("unexpected API request")

    def list(self, kind, namespace, selector):
        assert namespace == "owned"
        assert (kind, selector) in (("pods", "phorvex.ai/role=leader"), ("endpointslices", "kubernetes.io/service-name=models"))
        return {"items": [copy.deepcopy(self.pod if kind == "pods" else self.slice)]}

    def models(self, ip, port):
        assert (ip, port) == ("10.1.2.3", 8001)
        if self.after_models:
            self.after_models()
        return self.inventory

    def list_events(self, instance):
        assert instance == CFG.instance
        return [copy.deepcopy(v) for v in self.events.values()]

    def get_event(self, name):
        event = copy.deepcopy(self.events.get(name))
        if event is not None and self.replace_after_create and self.posts:
            event["metadata"]["uid"] = "api-replacement-uid"
        return event

    def get_lock(self):
        return copy.deepcopy(self.lock)

    def update_lock(self, body):
        self.lock_updates.append(copy.deepcopy(body))
        if self.bind_reject_before_write and body["data"]["phase"] == "BOUND":
            raise detector.DispatchUncertain("synthetic bind timeout before commit")
        if (self.lock is None or self.lock.get("immutable") is True
                or body["metadata"]["resourceVersion"] != self.lock["metadata"]["resourceVersion"]):
            raise detector.Conflict()
        previous_rv = self.lock["metadata"]["resourceVersion"]
        self.lock = copy.deepcopy(body)
        self.lock["metadata"]["resourceVersion"] = str(int(previous_rv) + 1)
        if ((self.lock_uncertain and body["data"]["phase"] == "CLAIMED")
                or (self.bind_uncertain and body["data"]["phase"] == "BOUND")):
            raise detector.DispatchUncertain("synthetic uncertain CAS")
        return copy.deepcopy(self.lock)

    def create_event(self, body):
        assert "phorvex.ai/creator-identity" not in body["metadata"]["annotations"]
        self.posts.append(copy.deepcopy(body))
        name = body["metadata"]["name"]
        if name in self.events:
            raise detector.Conflict()
        created = copy.deepcopy(body)
        created["metadata"].update({"uid": "api-uid-" + str(len(self.posts)), "resourceVersion": str(10 + len(self.posts)),
                                    "creationTimestamp": datetime.fromtimestamp(self.now + self.event_time_offset, timezone.utc).isoformat()})
        created["metadata"]["annotations"]["phorvex.ai/creator-identity"] = "system:serviceaccount:owned:adapter-detector"
        self.events[name] = created
        if self.uncertain:
            raise detector.DispatchUncertain("synthetic uncertain create")
        return copy.deepcopy(created)


class DetectorContract(unittest.TestCase):
    def test_slow_drip_body_and_whole_request_have_finite_deadlines(self):
        elapsed = [0.0]
        class Drip:
            calls = 0
            def read1(self, _size):
                self.calls += 1
                elapsed[0] += 2.0
                return b"x"
        reader = Drip()
        with self.assertRaisesRegex(TimeoutError, "body deadline"):
            detector._bounded_body(reader, clock=lambda: elapsed[0])
        self.assertEqual(reader.calls, 4)
        with self.assertRaisesRegex(TimeoutError, "absolute deadline"):
            with detector._http_deadline(0.02):
                time.sleep(0.2)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_saved_consumer_fixture_is_actual_current_producer_output(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        saved = json.loads(Path(__file__).with_name("producer_envelope.json").read_text())
        self.assertEqual(saved["body"], api.posts[0])
        self.assertEqual(saved["admitted"], next(iter(api.events.values())))

    def test_event_time_is_sampled_after_observation_not_at_poll_start(self):
        api = FakeAPI()
        api.after_models = lambda: setattr(api, "now", NOW + 2)
        self.assertEqual(detector.run_once(api, CFG, lambda: api.now)["status"], "created")
        self.assertEqual(api.lock["data"]["phase"], "BOUND")
        self.assertEqual(api.lock["data"]["eventUID"], "api-uid-1")

    def test_real_future_or_stale_api_event_time_refuses_uid_binding(self):
        for offset, reason in ((60, "future"), (-901, "outside manager evidence horizon")):
            with self.subTest(offset=offset):
                api = FakeAPI()
                api.event_time_offset = offset
                with self.assertRaisesRegex(detector.Inconclusive, reason):
                    detector.run_once(api, CFG, lambda: api.now)
                self.assertEqual(len(api.posts), 1)
                self.assertEqual(api.lock["data"]["phase"], "CLAIMED")

    def test_one_exact_target_emits_canonical_uid_bound_event_once(self):
        api = FakeAPI()
        first = run(api, CFG, NOW)
        self.assertEqual(first["status"], "created")
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(len(api.lock_updates), 2)
        self.assertEqual(api.lock["immutable"], True)
        body = api.posts[0]
        self.assertEqual(body["spec"]["rule"]["type"], detector.RULE)
        self.assertEqual(body["spec"]["targets"], ["owned/engine-0"])
        self.assertEqual(body["metadata"]["annotations"]["phorvex.ai/adapter-name"], "owned-neutral-adapter")
        self.assertEqual(body["metadata"]["annotations"]["phorvex.ai/target-pod-uid"], "pod-uid-1")
        self.assertNotIn("phorvex.ai/creator-identity", body["metadata"]["annotations"])
        self.assertEqual(run(api, CFG, NOW + 20)["status"], "retained")
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(len(api.lock_updates), 2)

    def test_clearance_keeps_event_until_protected_terminal_review(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        api.inventory = models(())
        self.assertEqual(run(api, CFG, NOW + 20)["status"], "cleared-await-terminal")
        self.assertEqual(len(api.events), 1)
        self.assertEqual(len(api.posts), 1)

    def test_changed_adapter_and_pod_refuse_new_event(self):
        for change in ("adapter", "pod"):
            with self.subTest(change=change):
                api = FakeAPI()
                run(api, CFG, NOW)
                if change == "adapter":
                    api.inventory = models(("different-neutral",))
                else:
                    api.pod["metadata"]["uid"] = "replacement-uid"
                    api.slice["endpoints"][0]["targetRef"]["uid"] = "replacement-uid"
                with self.assertRaises(detector.Inconclusive):
                    run(api, CFG, NOW + 20)
                self.assertEqual(len(api.posts), 1)

    def test_expiry_refuses_renewal_and_duplicate_mitigation(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        with self.assertRaisesRegex(detector.Inconclusive, "expired"):
            run(api, CFG, NOW + 901)
        self.assertEqual(len(api.posts), 1)

    def test_route_and_incarnation_ambiguity_prevents_event(self):
        for change in ("owner", "port", "targetUID", "container", "drift", "podPopulation", "modelsPath", "servingPort", "podLabel"):
            with self.subTest(change=change):
                api = FakeAPI()
                if change == "owner":
                    api.slice["metadata"]["ownerReferences"][0]["uid"] = "wrong"
                elif change == "port":
                    api.slice["ports"][0]["port"] = 8002
                elif change == "targetUID":
                    api.slice["endpoints"][0]["targetRef"]["uid"] = "wrong"
                elif change == "container":
                    api.pod["status"]["containerStatuses"][0]["ready"] = False
                elif change == "drift":
                    api.after_models = lambda: api.pod["metadata"].update(resourceVersion="changed")
                elif change == "modelsPath":
                    api.pod["metadata"]["annotations"]["phorvex.ai/models-path"] = "/other"
                elif change == "servingPort":
                    api.pod["metadata"]["annotations"]["phorvex.ai/serving-port"] = "8000"
                elif change == "podLabel":
                    api.pod["metadata"]["labels"]["phorvex.ai/role"] = "other"
                else:
                    original_list = api.list
                    api.list = lambda kind, ns, selector: {"items": [api.pod, api.pod]} if kind == "pods" else original_list(kind, ns, selector)
                with self.assertRaises(detector.Inconclusive):
                    run(api, CFG, NOW)
                self.assertEqual(api.posts, [])

    def test_inventory_ambiguity_prevents_event(self):
        for inventory in (b"{", b"{}", models(("a", "b")),
                          b'{"data":[{"id":"base"},{"id":"a","parent":"base"},{"id":"a","parent":"base"}]}',
                          b'{"data":[{"id":"base"},{"id":"a","parent":"missing"}]}',
                          b'{"data":[{"id":"base"},{"id":"a/b","parent":"base"}]}',
                          b'{"data":[],"data":[{"id":"base"}]}',
                          b'{"Data":[{"id":"base"}],"data":[{"id":"base"}]}',
                          b'{"data":[{"id":"base","ID":"shadow"}]}',
                          b'{"data":[{"id":"base","parent":null,"Parent":"shadow"}]}',
                          b'{"data":[{"id":"base"}]} {}',
                          b'{"data":[{"id":"base","score":NaN}]}',
                          b" " * (detector.MAX_BODY + 1)):
            with self.subTest(inventory=inventory[:30]):
                api = FakeAPI()
                api.inventory = inventory
                with self.assertRaises(detector.Inconclusive):
                    run(api, CFG, NOW)
                self.assertEqual(api.posts, [])

    def test_multiple_path_shaped_base_ids_still_bind_one_adapter(self):
        api = FakeAPI()
        api.inventory = json.dumps({"data": [
            {"id": "org/model", "parent": None},
            {"id": "/models/another-base", "parent": None},
            {"id": "owned-neutral-adapter", "parent": "org/model"}]}).encode()
        self.assertEqual(run(api, CFG, NOW)["status"], "created")
        self.assertEqual(api.posts[0]["metadata"]["annotations"]["phorvex.ai/adapter-name"], "owned-neutral-adapter")

    def test_explicit_expected_adapter_is_clean_without_claim(self):
        api = FakeAPI()
        expected_cfg = detector.Config("owned", "models", 8001, "engine", frozenset({"owned-neutral-adapter"}),
                                       "owned-proof", "adapter-detector", LOCK_UID)
        self.assertEqual(run(api, expected_cfg, NOW)["status"], "clean")
        self.assertEqual(api.posts, [])
        self.assertEqual(api.lock_updates, [])

    def test_create_uncertainty_never_reposts_within_process(self):
        api = FakeAPI()
        api.uncertain = True
        with self.assertRaises(detector.DispatchUncertain):
            run(api, CFG, NOW)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(len(api.events), 1)
        self.assertEqual(len(api.lock_updates), 1)
        api.uncertain = False
        with self.assertRaisesRegex(detector.Inconclusive, "CLAIMED"):
            run(api, CFG, NOW + 10)
        self.assertEqual(len(api.posts), 1)

    def test_missing_or_foreign_operator_lock_refuses_event(self):
        for change in ("missing", "wrong_uid", "recreated_uid", "foreign_label", "mutable_claim"):
            with self.subTest(change=change):
                api = FakeAPI()
                if change == "missing":
                    api.lock = None
                elif change == "wrong_uid":
                    api.lock["metadata"]["uid"] = ""
                elif change == "recreated_uid":
                    api.lock["metadata"]["uid"] = "00000000-0000-4000-8000-000000000002"
                elif change == "foreign_label":
                    api.lock["metadata"]["labels"] = {}
                else:
                    api.lock["data"] = {"unexpected": "claim"}
                with self.assertRaises(detector.Inconclusive):
                    run(api, CFG, NOW)
                self.assertEqual(api.posts, [])
                self.assertEqual(api.lock_updates, [])

    def test_claim_uncertainty_and_restart_fail_closed(self):
        api = FakeAPI()
        api.lock_uncertain = True
        with self.assertRaises(detector.DispatchUncertain):
            run(api, CFG, NOW)
        self.assertEqual(len(api.lock_updates), 1)
        self.assertEqual(api.posts, [])
        with self.assertRaisesRegex(detector.Inconclusive, "CLAIMED"):
            run(api, CFG, NOW + 10)
        self.assertEqual(api.posts, [])

    def test_event_deleted_after_claim_cannot_rearm_on_restart(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        api.events.clear()
        with self.assertRaisesRegex(detector.Inconclusive, "without event"):
            run(api, CFG, NOW + 10)
        self.assertEqual(len(api.lock_updates), 2)
        self.assertEqual(len(api.posts), 1)

    def test_post_before_final_uid_bind_refuses_after_restart(self):
        api = FakeAPI()
        api.bind_reject_before_write = True
        with self.assertRaises(detector.DispatchUncertain):
            run(api, CFG, NOW)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.lock["data"]["phase"], "CLAIMED")
        api.bind_reject_before_write = False
        with self.assertRaisesRegex(detector.Inconclusive, "CLAIMED"):
            run(api, CFG, NOW + 10)
        self.assertEqual(len(api.posts), 1)

    def test_successful_post_uid_replaced_before_readback_refuses(self):
        api = FakeAPI()
        api.replace_after_create = True
        with self.assertRaisesRegex(detector.DispatchUncertain, "readback identity"):
            run(api, CFG, NOW)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.lock["data"]["phase"], "CLAIMED")
        self.assertEqual(len(api.lock_updates), 1)
        with self.assertRaisesRegex(detector.Inconclusive, "CLAIMED"):
            run(api, CFG, NOW + 10)
        self.assertEqual(len(api.posts), 1)

    def test_same_name_new_uid_cannot_replace_bound_event(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        event = next(iter(api.events.values()))
        event["metadata"]["uid"] = "api-replacement-uid"
        event["metadata"]["creationTimestamp"] = datetime.fromtimestamp(NOW + 10, timezone.utc).isoformat()
        with self.assertRaisesRegex(detector.Inconclusive, "UID differs"):
            run(api, CFG, NOW + 20)
        self.assertEqual(len(api.posts), 1)

    def test_second_cas_ambiguous_stops_even_if_server_bound_it(self):
        api = FakeAPI()
        api.bind_uncertain = True
        with self.assertRaises(detector.DispatchUncertain):
            run(api, CFG, NOW)
        self.assertEqual(api.lock["data"]["phase"], "BOUND")
        self.assertEqual(api.lock["data"]["eventUID"], "api-uid-1")
        api.bind_uncertain = False
        self.assertEqual(run(api, CFG, NOW + 10)["status"], "retained")
        self.assertEqual(len(api.posts), 1)

    def test_conflicting_own_event_cannot_be_deleted_or_overridden(self):
        api = FakeAPI()
        run(api, CFG, NOW)
        event = next(iter(api.events.values()))
        event["metadata"]["annotations"]["phorvex.ai/target-pod-uid"] = "forged-uid"
        with self.assertRaises(detector.Inconclusive):
            run(api, CFG, NOW + 10)
        self.assertEqual(len(api.posts), 1)


if __name__ == "__main__":
    unittest.main()
