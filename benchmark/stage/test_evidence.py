import copy
import json
from pathlib import Path
import tempfile
import threading
import tracemalloc
import unittest
from unittest import mock

from .evidence import EvidenceError, Journal, Reducer, STREAMS, SCOPE_SCHEMA, sealed_sessions
from .normalize import normalize, install


def scope():
    return {"schema": SCOPE_SCHEMA, "repository": "PhorvexSecurity/operator-refactored", "source_revision": "a" * 40,
            "image_digest": "sha256:" + "b" * 64, "context": "test-stage", "namespace": "phorvex-staging-demo",
            "policy_name": "stage-bench-defense", "policy_uid": "policy-uid", "deployment_name": "stage-bench-api",
            "workload_uid": "deployment-uid", "service_name": "stage-bench-api", "service_uid": "service-uid",
            "selector": {"app": "stage-bench"}, "measurement": "watch-observed-service-ready-backends", "mode": "isolated-calibration"}


def meta(name, uid, **extra):
    return {"name": name, "uid": uid, "namespace": "phorvex-staging-demo", "resourceVersion": "1", **extra}


def pod(uid):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta(uid, uid, labels={"app": "stage-bench"},
            ownerReferences=[{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs", "uid": "rs-uid", "controller": True}]),
            "spec": {"containers": [{"name": "web", "image": "nginx"}]}, "status": {"phase": "Running"}}


def endpoint_slice(uids):
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": meta("es", "es-uid",
            labels={"kubernetes.io/service-name": "stage-bench-api"}, ownerReferences=[{"kind": "Service", "uid": "service-uid"}]),
            "addressType": "IPv4", "ports": [{"port": 8080}], "endpoints": [
                {"addresses": ["10.0.0." + str(i + 1)], "conditions": {"ready": True},
                 "targetRef": {"kind": "Pod", "namespace": "phorvex-staging-demo", "name": uid, "uid": uid}}
                for i, uid in enumerate(uids)]}


def inventory():
    return {
        "deployment": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta("stage-bench-api", "deployment-uid", generation=1),
                        "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "stage-bench"}}, "template": {"spec": {"containers": [{"name": "web"}]}}}}],
        "replicasets": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": meta("rs", "rs-uid",
                         ownerReferences=[{"kind": "Deployment", "uid": "deployment-uid", "controller": True}])}],
        "pods": [pod("p1"), pod("p2"), pod("p3")],
        "service": [{"apiVersion": "v1", "kind": "Service", "metadata": meta("stage-bench-api", "service-uid"), "spec": {"selector": {"app": "stage-bench"}}}],
        "endpointslices": [endpoint_slice(["p1", "p2", "p3"])],
        "policy": [{"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy", "metadata": meta("stage-bench-defense", "policy-uid", generation=1),
                    "spec": {"mode": "dryRun", "selector": {"matchLabels": {"app": "stage-bench"}}, "budget": {"maxMovesPerTick": 1}}}],
    }


def seed(journal, at=10, session="session-1", objects=None):
    journal.append("session", {"id": session}, at=at)
    for stream, items in (objects or inventory()).items():
        journal.append("list", {"session": session, "stream": stream, "resource_version": "1", "items": items}, at=at)


def watch(journal, stream, kind, obj, at, session="session-1"):
    journal.append("watch", {"session": session, "stream": stream, "resource_version": str(at), "type": kind, "object": obj}, at=at)


def seal(journal, at, session="session-1"):
    for stream in STREAMS:
        watch(journal, stream, "BOOKMARK", {"metadata": {"resourceVersion": str(at)}}, at, session)


def intent():
    return {"id": "calibration-1", "origin": "controlled-stage-calibration", "action": "rotate", "pod_name": "p1", "pod_uid": "p1",
            "workload_uid": "deployment-uid", "policy_uid": "policy-uid", "reservation": 159, "deadline": 100}


def receipt():
    return {"id": "calibration-1", "pod_uid": "p1", "operation": "uid-preconditioned-delete", "acknowledged": True,
            "http_status": 200, "returned_uid": "p1"}


def rotate(journal):
    journal.append("intent", intent(), at=20)
    journal.append("receipt", receipt(), at=21)
    watch(journal, "pods", "DELETED", pod("p1"), 22)
    watch(journal, "endpointslices", "MODIFIED", endpoint_slice(["p2", "p3"]), 23)
    watch(journal, "pods", "ADDED", pod("p4"), 25)
    watch(journal, "endpointslices", "MODIFIED", endpoint_slice(["p2", "p3", "p4"]), 30)


def asof(journal, at):
    records = list(journal.records())
    reducer = Reducer(journal.scope)
    for event in records:
        if event["at"] <= at:
            reducer.apply(event)
    return reducer.snapshot(at, sealed_sessions(records).get(reducer.session))


def export(at=350, pod_uid="p2"):
    return {"schema": "math-lab.study-candidates.v1", "source_revision": "a" * 40, "snapshot_source_revision": "a" * 40,
            "cross_version": False, "observational": False, "namespace": "phorvex-staging-demo",
            "policy_name": "stage-bench-defense", "policy_uid": "policy-uid", "policy_generation": 1,
            "tick_id": "original-tick", "snapshot_digest": "d" * 64, "at": at, "workload_uid": "deployment-uid", "spec_replicas": 3,
            "max_moves_per_tick": 1, "candidate_set_complete": True, "missing": [], "mandatory_id": "", "baseline_reproduced": True,
            "final_decisions": [], "candidates": [{"id": "candidate-1", "pod_uid": pod_uid, "action": "rotate",
                "facts": [{"id": "fact-real", "weight": 0.25}], "facts_known": True, "gates": [], "gates_known": True,
                "worth_threshold": None, "containment": False, "k": None, "class": "stateless", "history_known": False,
                "samples": [], "hold_cap": None}]}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = Journal(Path(self.temp.name) / "evidence.db", scope())
        self.addCleanup(self.journal.close)

    def test_rotation_joins_real_kubernetes_uids_and_transfers_once(self):
        seed(self.journal)
        rotate(self.journal)
        seal(self.journal, 40)
        opened = asof(self.journal, 24)
        self.assertEqual(opened["complete_from"], 10)
        self.assertEqual(len(opened["moves"]), 1)
        self.assertEqual(opened["moves"][0]["state"], "open")
        self.assertEqual(opened["moves"][0]["reservation"], 159)
        self.assertEqual(opened["moves"][0]["intervals"][0]["end"], 24)
        settled = asof(self.journal, 31)
        self.assertEqual(len(settled["moves"]), 1)
        self.assertEqual(settled["moves"][0]["state"], "settled")
        self.assertIsNone(settled["moves"][0]["reservation"])
        self.assertEqual(settled["moves"][0]["intervals"], [{"endpoint_uid": "service-uid:p1", "start": 23, "end": 30}])
        self.assertEqual(settled["samples"][0]["duration"], 10)
        self.assertFalse(settled["authoritative"])

    def test_unrelated_rollout_is_never_a_measured_move(self):
        seed(self.journal)
        watch(self.journal, "pods", "DELETED", pod("p1"), 20)
        watch(self.journal, "endpointslices", "MODIFIED", endpoint_slice(["p2", "p3"]), 21)
        seal(self.journal, 40)
        snap = asof(self.journal, 30)
        self.assertIsNone(snap["complete_from"])
        self.assertIn("UNATTRIBUTED_READY_ENDPOINT_DEFICIT", snap["reasons"])
        self.assertEqual(snap["moves"], [])

    def test_other_pod_readiness_loss_is_not_attributed_to_open_calibration(self):
        seed(self.journal)
        self.journal.append("intent", intent(), at=20)
        self.journal.append("receipt", receipt(), at=21)
        endpoints = endpoint_slice(["p1", "p2", "p3"])
        endpoints["endpoints"][1]["conditions"]["ready"] = False
        watch(self.journal, "endpointslices", "MODIFIED", endpoints, 22)
        seal(self.journal, 40)
        snap = asof(self.journal, 25)
        self.assertIsNone(snap["complete_from"])
        self.assertIn("UNRELATED_BASELINE_ENDPOINT_LOSS_DURING_ROTATION", snap["reasons"])
        self.assertEqual(snap["moves"], [])
        self.assertTrue(snap["samples"][0]["suspect"])

    def test_restart_does_not_backdate_history(self):
        seed(self.journal)
        seal(self.journal, 90)
        self.journal.append("stopped", {"reason": "restart"}, at=100)
        seed(self.journal, at=110, session="session-2")
        seal(self.journal, 400, session="session-2")
        trace, meta = normalize(self.journal.scope, list(self.journal.records()), [export(350)], .9, 300, 300, 0)
        self.assertEqual(trace["ticks"][0]["ledger"]["complete_from"], 110)
        self.assertEqual(meta["state"], "BLOCKED")
        with self.assertRaisesRegex(EvidenceError, "incomplete"):
            install(trace, meta, Path(self.temp.name) / "data", "test")

    def test_watch_gap_censors_open_move_and_does_not_credit_duration(self):
        seed(self.journal)
        self.journal.append("intent", intent(), at=20)
        self.journal.append("receipt", receipt(), at=21)
        self.journal.append("gap", {"reason": "WATCH_API_ERROR:410"}, at=22)
        snap = asof(self.journal, 22)
        self.assertIsNone(snap["complete_from"])
        self.assertEqual(snap["moves"], [])
        self.assertIsNone(snap["samples"][0]["duration"])
        self.assertTrue(snap["samples"][0]["censored"])
        self.assertTrue(snap["samples"][0]["suspect"])

    def test_future_receipt_never_qualifies_prior_tick(self):
        seed(self.journal)
        self.journal.append("intent", intent(), at=20)
        self.journal.append("receipt", receipt(), at=30)
        seal(self.journal, 40)
        snap = asof(self.journal, 25)
        self.assertIsNone(snap["complete_from"])
        self.assertIn("MOVE_ACKNOWLEDGEMENT_MISSING", snap["reasons"])

    def test_atomic_second_intent_is_rejected_before_a_second_action(self):
        seed(self.journal)
        self.journal.append("intent", intent(), at=20)
        other = {**intent(), "id": "calibration-2", "pod_uid": "p2", "pod_name": "p2"}
        with self.assertRaisesRegex(EvidenceError, "already open"):
            self.journal.append("intent", other, at=21)
        self.assertEqual(sum(r["kind"] == "intent" for r in self.journal.records()), 1)

    def test_missing_or_wrong_uid_and_active_policy_fail_closed(self):
        for mode in ("active", "wrong-uid", "wrong-service", "foreign-namespace"):
            with self.subTest(mode=mode):
                objects = inventory()
                if mode == "active": objects["policy"][0]["spec"]["mode"] = "active"
                if mode == "wrong-uid": objects["deployment"][0]["metadata"]["uid"] = "another-uid"
                if mode == "wrong-service": objects["endpointslices"][0]["metadata"]["ownerReferences"][0]["uid"] = "other-service"
                if mode == "foreign-namespace": objects["pods"][0]["metadata"]["namespace"] = "production"
                reducer = Reducer(scope())
                reducer.apply({"at": 10, "kind": "session", "data": {"id": "test"}})
                for stream, items in objects.items():
                    reducer.apply({"at": 10, "kind": "list", "data": {"session": "test", "stream": stream, "items": items}})
                self.assertIsNone(reducer.coverage_from)

    def test_disk_bound_and_clock_failure_never_advance_watermark(self):
        seed(self.journal)
        before = list(self.journal.records())
        self.journal.max_bytes = 1
        with self.assertRaisesRegex(EvidenceError, "capacity exhausted"):
            seal(self.journal, 100)
        self.assertEqual(list(self.journal.records()), before)
        self.assertIn("API_WATCH_WATERMARK_BEHIND_TICK", asof(self.journal, 50)["reasons"])
        self.journal.max_bytes = 256 << 20
        with self.assertRaisesRegex(EvidenceError, "clock regressed"):
            self.journal.append("checkpoint", {}, at=9)

    def test_concurrent_writers_allocate_clock_after_serialization(self):
        from . import evidence
        original = evidence.canonical
        slow_ready, fast_done = threading.Event(), threading.Event()
        failures = []
        def delayed(value):
            if isinstance(value, dict) and value.get("kind") == "slow":
                slow_ready.set()
                if not fast_done.wait(3):
                    raise AssertionError("fast writer did not finish")
            return original(value)
        def slow():
            try:
                self.journal.append("slow", {})
            except BaseException as exc:
                failures.append(exc)
        with mock.patch.object(evidence, "canonical", delayed), mock.patch.object(evidence.time, "time", side_effect=[10, 20]):
            worker = threading.Thread(target=slow)
            worker.start()
            self.assertTrue(slow_ready.wait(3))
            self.journal.append("fast", {})
            fast_done.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual([(r["kind"], r["at"]) for r in self.journal.records()], [("fast", 10), ("slow", 20)])

    def test_size_cache_is_transactional_utf8_and_verified_on_reopen(self):
        self.journal.append("checkpoint", {"label": "مشاهده"}, at=10)
        expected = self.journal.db.execute("SELECT SUM(length(CAST(body AS BLOB))+128) FROM events").fetchone()[0]
        cached = int(self.journal.db.execute("SELECT value FROM meta WHERE key='logical_bytes'").fetchone()[0])
        self.assertEqual(cached, expected)
        reopened = Journal(self.journal.path)
        reopened.close()
        self.journal.db.execute("UPDATE meta SET value='0' WHERE key='logical_bytes'")
        self.journal.db.commit()
        with self.assertRaisesRegex(EvidenceError, "logical-size cache"):
            Journal(self.journal.path)

    def test_reopen_validates_chain_even_when_size_cache_matches(self):
        seed(self.journal)
        self.journal.db.execute("UPDATE events SET hash=? WHERE seq=2", ("0" * 64,))
        self.journal.db.commit()
        with self.assertRaisesRegex(EvidenceError, "hash chain"):
            Journal(self.journal.path)

    def test_frozen_read_prefix_excludes_concurrent_appends_in_both_passes(self):
        seed(self.journal)
        seal(self.journal, 400)
        writer = Journal(self.journal.path)
        self.addCleanup(writer.close)
        with self.journal.read_snapshot() as prefix:
            before = list(self.journal.records(cutoff=prefix["seq"]))
            seal(writer, 600)
            after = list(self.journal.records(cutoff=prefix["seq"]))
            self.assertEqual(before, after)
            _, metadata = normalize(self.journal.scope, lambda: self.journal.records(cutoff=prefix["seq"]),
                                    [export(450)], .9, 300, 300, 0)
            self.assertEqual(metadata["journal_prefix"], prefix)
            self.assertEqual(metadata["state"], "BLOCKED")
        self.assertGreater(len(list(self.journal.records())), len(before))

    def test_large_journal_normalizes_with_bounded_streaming_memory(self):
        seed(self.journal)
        # 6.4 MiB is enough to discriminate materialization without creating a
        # large test artifact or requiring a memory-heavy test process.
        for index in range(400):
            self.journal.append("checkpoint", {"padding": "x" * 16384}, at=11 + index)
        seal(self.journal, 1000)
        tracemalloc.start()
        try:
            with self.journal.read_snapshot() as prefix:
                _, metadata = normalize(self.journal.scope, lambda: self.journal.records(cutoff=prefix["seq"]),
                                        [export(450)], .9, 300, 300, 0)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(metadata["state"], "READY")
        self.assertLess(peak, 2 << 20)

    def test_hash_chain_detects_tampering(self):
        seed(self.journal)
        self.journal.db.execute("UPDATE events SET body=? WHERE seq=1", ('{"kind":"fake"}',))
        self.journal.db.commit()
        with self.assertRaisesRegex(EvidenceError, "hash chain"):
            list(self.journal.records())

    def test_process_heartbeat_cannot_create_api_coverage(self):
        seed(self.journal)
        self.journal.append("checkpoint", {"watch_processes_alive": True}, at=400)
        self.assertIsNone(asof(self.journal, 350)["complete_from"])

    def test_normalizer_preserves_source_fields_and_installs_exact_cohort(self):
        seed(self.journal)
        rotate(self.journal)
        seal(self.journal, 400)
        source = export()
        trace, meta = normalize(self.journal.scope, list(self.journal.records()), [source], .9, 300, 300, 0)
        self.assertEqual(meta["state"], "READY")
        enriched = trace["ticks"][0]["candidates"][0]
        for key in ("id", "pod_uid", "action", "facts", "facts_known", "gates", "gates_known", "containment", "class"):
            self.assertEqual(enriched[key], source["candidates"][0][key])
        self.assertEqual(enriched["k"], 1)
        self.assertTrue(enriched["history_known"])
        self.assertFalse(trace["ticks"][0]["slo"]["accepted"])
        self.assertEqual(trace["ticks"][0]["id"], source["snapshot_digest"])
        result = install(trace, meta, Path(self.temp.name) / "data", "real-producer-test")
        self.assertEqual(result["snapshot_digests"], [source["snapshot_digest"]])
        self.assertEqual(result["normalization"]["move_origin"], "controlled-stage-calibration")
        self.assertIsNone(result["normalization"]["counterfactual_actual_charges"])

    def test_quarantine_requires_explicit_cap_only_when_price_is_required(self):
        seed(self.journal)
        seal(self.journal, 400)
        row = export()
        row["candidates"][0]["action"] = "quarantine"
        trace, metadata = normalize(self.journal.scope, list(self.journal.records()), [row], .9, 300, 300, 0)
        self.assertEqual(metadata["state"], "BLOCKED")
        self.assertIn("candidates[candidate-1].hold_cap: QUARANTINE_HOLD_CAP_NOT_CONFIGURED", metadata["missing"][row["snapshot_digest"]])
        with self.assertRaisesRegex(EvidenceError, "incomplete"):
            install(trace, metadata, Path(self.temp.name) / "blocked", "test")
        for adjustment in ({"hold_cap": 0}, {"hold_cap": 10}, {"gates": ["PDB"]}, {"facts": []}):
            with self.subTest(adjustment=adjustment):
                modified = copy.deepcopy(row)
                modified["candidates"][0].update(adjustment)
                _, metadata = normalize(self.journal.scope, list(self.journal.records()), [modified], .9, 300, 300, 0)
                self.assertEqual(metadata["state"], "READY")
        for cap in (-1, True, None):
            with self.subTest(cap=cap):
                modified = copy.deepcopy(row)
                modified['candidates'][0]['hold_cap'] = cap
                _, metadata = normalize(self.journal.scope, self.journal.records, [modified], .9, 300, 300, 0)
                self.assertEqual(metadata['state'], 'BLOCKED')
        for cap in (float('nan'), float('inf')):
            with self.subTest(cap=cap), self.assertRaisesRegex(ValueError, 'JSON compliant'):
                modified = copy.deepcopy(row)
                modified['candidates'][0]['hold_cap'] = cap
                normalize(self.journal.scope, self.journal.records, [modified], .9, 300, 300, 0)

    def test_immutable_generations_keep_prior_readers_and_last_good_pointer(self):
        seed(self.journal)
        seal(self.journal, 1000)
        data = Path(self.temp.name)/"data"
        trace, metadata = normalize(self.journal.scope, self.journal.records, [export(650)], .9, 300, 300, 0)
        first = install(trace, metadata, data, "test")
        pointer = data/"mathlab/endpoint-traces/phorvex-staging-demo/stage-bench-defense.manifest.json"
        original = pointer.parent/first["trace_file"]
        saved = original.read_bytes(), pointer.read_bytes()
        other, second_meta = normalize(self.journal.scope, self.journal.records, [export(750)], .9, 300, 300, 0)
        def changed_pin():
            raise EvidenceError("source pin changed")
        with self.assertRaisesRegex(EvidenceError, "source pin changed"):
            install(other, second_meta, data, "test", before_publish=changed_pin)
        self.assertEqual(saved, (original.read_bytes(), pointer.read_bytes()))
        second = install(other, second_meta, data, "test")
        self.assertNotEqual(first["trace_file"], second["trace_file"])
        self.assertEqual(original.read_bytes(), saved[0])
        self.assertEqual(json.loads(pointer.read_text()), second)
        self.assertFalse(pointer.with_suffix(".json").with_name("stage-bench-defense.json").exists())

    def test_generation_corruption_and_capacity_fail_without_replacing_pointer(self):
        seed(self.journal)
        seal(self.journal, 1000)
        data = Path(self.temp.name)/"data"
        trace, metadata = normalize(self.journal.scope, self.journal.records, [export(650)], .9, 300, 300, 0)
        first = install(trace, metadata, data, "test")
        pointer = data/"mathlab/endpoint-traces/phorvex-staging-demo/stage-bench-defense.manifest.json"
        before = pointer.read_bytes()
        original = pointer.parent/first["trace_file"]
        original.write_bytes(original.read_bytes()+b" ")
        with self.assertRaisesRegex(EvidenceError, "immutable"):
            install(trace, metadata, data, "test")
        self.assertEqual(pointer.read_bytes(), before)
        (pointer.parent/("stage-bench-defense."+"f"*64+".trace.json")).write_bytes(b"x"*(1 << 20))
        other, second_meta = normalize(self.journal.scope, self.journal.records, [export(750)], .9, 300, 300, 0)
        with self.assertRaisesRegex(EvidenceError, "capacity"):
            install(other, second_meta, data, "test", max_generation_bytes=1 << 20)
        self.assertEqual(pointer.read_bytes(), before)

    def test_retained_history_contract_keeps_moves_samples_and_untrimmed_intervals(self):
        seed(self.journal)
        rotate(self.journal)
        seal(self.journal, 1000)
        trace, metadata = normalize(self.journal.scope, self.journal.records, [export(650)], .9, 300, 300, 0)
        self.assertEqual(metadata['state'], 'READY')
        self.assertEqual(metadata['retention'], {'schema': 'phorvex-stage.retained-history.v1',
            'moves': 'all-observed', 'samples': 'all-observed', 'interval_clipping': False})
        tick = trace['ticks'][0]
        # The physical move predates the declared 300s window. It must still be
        # retained so a later request can recompute a covered 600s W/L window.
        self.assertLess(tick['ledger']['moves'][0]['intervals'][0]['start'], 350)
        self.assertEqual(tick['ledger']['moves'][0]['intervals'],
                         [{'endpoint_uid': 'service-uid:p1', 'start': 23, 'end': 30}])
        self.assertEqual(tick['candidates'][0]['samples'][0]['at'], 30)
        self.assertEqual(tick['ledger']['complete_from'], 10)
        self.assertGreaterEqual(metadata['bindings'][0]['sealed_until'], tick['at'])

    def test_normalizer_rejects_cross_source_and_cross_policy(self):
        seed(self.journal)
        seal(self.journal, 400)
        for key, wrong in (("snapshot_source_revision", "b" * 40), ("policy_uid", "wrong"), ("namespace", "vllm"), ("baseline_reproduced", False)):
            with self.subTest(key=key), self.assertRaisesRegex(EvidenceError, "export mismatch"):
                normalize(self.journal.scope, list(self.journal.records()), [{**export(), key: wrong}], .9, 300, 300, 0)

    def test_cross_source_replay_retains_both_source_pins(self):
        seed(self.journal)
        seal(self.journal, 400)
        row = {**export(), "source_revision": "c" * 40, "cross_version": True, "observational": True}
        trace, meta = normalize(self.journal.scope, list(self.journal.records()), [row], .9, 300, 300, 0)
        self.assertEqual(trace["source_revision"], "c" * 40)
        self.assertEqual(meta["snapshot_source_revision"], "a" * 40)
        manifest = install(trace, meta, Path(self.temp.name) / "data", "test-producer")
        self.assertEqual(manifest["source_revision"], "c" * 40)
        self.assertEqual(manifest["snapshot_source_revision"], "a" * 40)
        row["observational"] = False
        with self.assertRaisesRegex(EvidenceError, "observational provenance"):
            normalize(self.journal.scope, list(self.journal.records()), [row], .9, 300, 300, 0)

    def test_no_assumed_30_day_history(self):
        seed(self.journal)
        seal(self.journal, 400)
        trace, meta = normalize(self.journal.scope, list(self.journal.records()), [export()], .999, 2592000, 86400, 0)
        self.assertEqual(meta["state"], "BLOCKED")
        self.assertFalse(trace["ticks"][0]["candidates"][0]["history_known"])

    def test_same_pod_multiple_slices_are_one_logical_backend(self):
        objects = inventory()
        duplicate = copy.deepcopy(objects["endpointslices"][0])
        duplicate["metadata"]["uid"] = "es-ipv6"
        duplicate["addressType"] = "IPv6"
        objects["endpointslices"].append(duplicate)
        seed(self.journal, objects=objects)
        self.assertEqual(asof(self.journal, 10)["ready_pod_uids"], ["p1", "p2", "p3"])


if __name__ == "__main__":
    unittest.main()
