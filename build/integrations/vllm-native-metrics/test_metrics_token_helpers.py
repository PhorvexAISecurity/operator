"""Offline mocked API, metadata, bounded bootstrap and guarded cleanup controls."""
import base64
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import Mock, patch
import generate_metrics_token as generate
import provision_metrics_token as provision


def make_metadata_fixture(closure=None):
    pair_id = "1" * 32
    records = [{"namespace": namespace, "name": generate.NAME, "uid": "secret-" + namespace,
        "resourceVersion": "42", "pairID": pair_id, "provenance": generate.PROVENANCE,
        "ready": True, "lastAppliedPresent": False, "immutable": True} for namespace in generate.NAMESPACES]
    value = {"schema": provision.SCHEMA, "utc": generate.utc(), "generator": {
        "jobUID": "generator-job-uid", "sourceSHA256": hashlib.sha256((provision.ROOT / "generate_metrics_token.py").read_bytes()).hexdigest(),
        "imageByDigest": generate.IMAGE, "pairID": pair_id, "records": records},
        "secrets": [{key: value for key, value in record.items() if key != "immutable"} for record in records]}
    provision.validate_metadata(value, closure)
    return value



class TokenHelpers(unittest.TestCase):
    def setUp(self):
        self.pair = "1" * 32
        self.slots = [{"namespace": namespace, "name": generate.NAME, "uid": "uid-" + namespace, "resourceVersion": "4",
            "pairID": self.pair, "provenance": generate.PROVENANCE, "ready": False, "lastAppliedPresent": False}
            for namespace in generate.NAMESPACES]
        self.inputs = {"schema": "phorvex-vllm-native-metrics-token-inputs-v1", "pairID": self.pair, "slots": self.slots}
        self.token = "a" * 64

    def response(self, namespace, patch_body):
        data = next(item["value"] for item in patch_body if item["path"] == "/data")
        return {"apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": namespace, "name": generate.NAME,
            "uid": "uid-" + namespace, "resourceVersion": "5", "labels": generate.labels(self.pair, True)},
            "immutable": True, "data": data}

    def test_single_random_value_same_two_patches_and_only_sanitized_output(self):
        patcher = Mock()
        patcher.patch.side_effect = self.response
        factory = Mock(return_value=self.token)
        report = generate.generate(self.inputs, patcher, factory)
        factory.assert_called_once_with(32)
        self.assertEqual(report["result"], "complete")
        calls = patcher.patch.call_args_list
        self.assertEqual(len(calls), 2)
        data = [next(item["value"] for item in call.args[1] if item["path"] == "/data") for call in calls]
        self.assertEqual(data[0], data[1])
        for call, slot in zip(calls, self.slots):
            self.assertEqual(call.args[1][:2], [{"op": "test", "path": "/metadata/uid", "value": slot["uid"]},
                {"op": "test", "path": "/metadata/resourceVersion", "value": slot["resourceVersion"]}])
        serialized = json.dumps(report)
        self.assertNotIn(self.token, serialized)
        self.assertNotIn(base64.b64encode(self.token.encode()).decode(), serialized)
        self.assertTrue(all(set(record) == generate.SAFE_KEYS | {"immutable"} for record in report["records"]))

    def test_partial_write_stops_and_retains_only_successful_anchor(self):
        patcher = Mock()
        patcher.patch.side_effect = [self.response("vllm", generate.patch_for(self.slots[0], self.pair, self.token)),
                                    RuntimeError("SECRET " + self.token)]
        report = generate.generate(self.inputs, patcher, Mock(return_value=self.token))
        self.assertEqual(report["result"], "partial")
        self.assertEqual([r["namespace"] for r in report["records"]], ["vllm"])
        self.assertNotIn(self.token, json.dumps(report))
        self.assertEqual(report["error"], "credential generation incomplete")

    def test_uid_conflict_no_second_patch_or_overwrite(self):
        patcher = Mock()
        bad = self.response("vllm", generate.patch_for(self.slots[0], self.pair, self.token))
        bad["metadata"]["uid"] = "replacement"
        patcher.patch.return_value = bad
        report = generate.generate(self.inputs, patcher, Mock(return_value=self.token))
        self.assertEqual(report["result"], "partial")
        self.assertEqual(report["records"], [])
        self.assertEqual(patcher.patch.call_count, 1)

    def test_patch_only_exact_name_namespaced_rbac_and_bounded_pod(self):
        objects = provision.bootstrap_objects(self.pair, self.slots)
        roles = [obj for obj in objects if obj["kind"] == "Role"]
        self.assertEqual({obj["metadata"]["namespace"] for obj in roles}, set(generate.NAMESPACES))
        for role in roles:
            self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["secrets"],
                "resourceNames": [generate.NAME], "verbs": ["patch"]}])
        job = objects[-1]
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 120)
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]["image"], generate.IMAGE)
        self.assertTrue(all(not obj.get("metadata", {}).get("ownerReferences") for obj in objects))

    def test_metadata_transport_requires_exact_kind_and_accept_no_fallback(self):
        api = provision.ProxyAPI()
        obj = {"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": {
            "namespace": "vllm", "name": generate.NAME, "uid": "uid-vllm", "resourceVersion": "5",
            "labels": generate.labels(self.pair, True)}}
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        captured = []
        def opened(request, timeout):
            captured.append(request)
            return Response(json.dumps(obj).encode())
        api.opener.open = opened
        record = api.metadata("vllm", self.pair, True)
        self.assertEqual(record["resourceVersion"], "5")
        self.assertEqual(captured[0].get_header("Accept"), generate.PARTIAL_ACCEPT)
        self.assertNotIn("immutable", record)
        with self.assertRaises(generate.SafeFailure):
            api.get(generate.secret_path("vllm"))
        obj["kind"] = "Secret"
        with self.assertRaises(generate.SafeFailure):
            api.metadata("vllm", self.pair, True)
        self.assertEqual(len(captured), 2)

    def test_metadata_uid_rv_provenance_last_applied_and_freshness_fail(self):
        good = make_metadata_fixture()
        for key, value in (("uid", "recreated"), ("resourceVersion", "99"), ("provenance", "wrong"),
                           ("lastAppliedPresent", True), ("ready", False)):
            changed = copy.deepcopy(good)
            changed["secrets"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                provision.validate_metadata(changed)
        changed = copy.deepcopy(good)
        changed["secrets"][0]["tokenDigest"] = "forbidden"
        with self.assertRaises(ValueError): provision.validate_metadata(changed)
        changed = copy.deepcopy(good)
        changed["utc"] = "2099-01-01T00:00:00Z"
        with self.assertRaises(ValueError): provision.validate_metadata(changed)

    def test_last_applied_and_owner_cascade_forbidden(self):
        response = self.response("vllm", generate.patch_for(self.slots[0], self.pair, self.token))
        response["metadata"]["annotations"] = {generate.LAST_APPLIED: self.token}
        with self.assertRaises(ValueError): generate.safe_record(response, "vllm", self.pair, immutable=True)
        response["metadata"].pop("annotations")
        response["metadata"]["ownerReferences"] = [{"uid": "temporary-job"}]
        with self.assertRaises(ValueError): generate.safe_record(response, "vllm", self.pair, immutable=True)

    def baseline(self):
        return {"spec": {"template": {"metadata": {"labels": {"app": "vllm"}}, "spec": {"containers": [
            {"name": "vllm", "env": [], "ports": [{"containerPort": 8001}]},
            {"name": "guardrail", "ports": [{"containerPort": 8000}, {"containerPort": 8443}]}],
            "initContainers": [{"name": "phorvex-drain-ledger-init"}]}}}}

    def test_fixed_workload_name_and_enabled_label_gate(self):
        api = Mock()
        baseline = self.baseline()
        api.get.side_effect = lambda path: baseline if path.endswith("deployments/vllm") else {"items": []}
        provision.no_consumers(api)
        baseline["spec"]["template"]["metadata"]["labels"]["phorvex.ai/vllm-native-metrics"] = "enabled"
        with self.assertRaises(ValueError): provision.no_consumers(api)

    def test_existing_consumer_and_collision_prevent_any_create(self):
        api = Mock()
        api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/vllm") else {
            "items": [{"spec": {"volumes": [{"secret": {"secretName": generate.NAME}}]}}]}
        with self.assertRaises(ValueError): provision.no_consumers(api)
        api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/vllm") else {"items": []}
        api.request.return_value = {"kind": "PartialObjectMetadata"}
        state = {"pairID": self.pair, "slots": [], "objects": []}
        with self.assertRaises(ValueError): provision.provision(api, state, Mock())
        api.create.assert_not_called()

    def test_cleanup_requires_exact_uid_and_rv_preconditions(self):
        api = Mock()
        api.get.side_effect = lambda path, **kw: self.baseline() if path.endswith("deployments/vllm") else {"items": []}
        api.metadata.return_value = dict(self.slots[0])
        state = {"pairID": self.pair, "slots": [dict(self.slots[0])], "objects": []}
        provision.cleanup_slots(api, state, Mock())
        api.delete.assert_called_once_with(generate.secret_path("vllm"), "uid-vllm", "4", secret=True)
        state["slots"] = [dict(self.slots[0])]
        api.metadata.return_value = dict(self.slots[0], resourceVersion="5")
        with self.assertRaises(ValueError): provision.cleanup_slots(api, state, Mock())
        self.assertEqual(api.delete.call_count, 1)

    def test_fresh_generator_job_uid_and_full_reviewed_spec_are_required(self):
        expected = provision.bootstrap_objects(self.pair, self.slots)[-1]
        job = copy.deepcopy(expected)
        job["metadata"].update(uid="created-generator-job", resourceVersion="23")
        job["status"] = {"succeeded": 1}
        state = {"jobUID": "created-generator-job"}
        provision.check_generator_job(job, state, expected)
        changed = copy.deepcopy(job)
        changed["metadata"]["uid"] = "same-name-replacement"
        with self.assertRaises(ValueError): provision.check_generator_job(changed, state, expected)
        changed = copy.deepcopy(job)
        changed["spec"]["template"]["spec"]["containers"][0]["image"] = "other-runtime"
        with self.assertRaises(ValueError): provision.check_generator_job(changed, state, expected)
        changed = copy.deepcopy(job)
        changed["spec"]["template"]["spec"]["containers"][0]["command"] = ["python3", "unreviewed.py"]
        with self.assertRaises(ValueError): provision.check_generator_job(changed, state, expected)

    def test_cleanup_real_own_prefix_uid_rv_anchor_and_unsafe_paths_refused(self):
        body = provision.bootstrap_objects(self.pair, self.slots)[0]
        path = provision.resource_path(body)
        current = copy.deepcopy(body)
        current["metadata"].update(uid="own-sa-uid", resourceVersion="18")
        record = {"path": path, "uid": "own-sa-uid", "body": body}
        state = {"pairID": self.pair, "slots": [], "objects": [copy.deepcopy(record)]}
        api = Mock()
        api.get.return_value = current
        provision.cleanup_objects(api, state, Mock())
        api.delete.assert_called_once_with(path, "own-sa-uid", "18")
        self.assertEqual(state["objects"], [])
        state["objects"] = [copy.deepcopy(record)]
        current["metadata"]["uid"] = "recreated-sa"
        with self.assertRaises(ValueError): provision.cleanup_objects(api, state, Mock())
        self.assertEqual(api.delete.call_count, 1)
        for mutate in (lambda r: r.update(path="/api/v1/namespaces/other/serviceaccounts/unrelated"),
                       lambda r: r["body"]["metadata"].update(name="unrelated"),
                       lambda r: r["body"]["metadata"].update(namespace="other"),
                       lambda r: r["body"].update(kind="Secret"),
                       lambda r: r["body"]["metadata"]["labels"].update({generate.PAIR_LABEL: "9" * 32})):
            unsafe = copy.deepcopy(record)
            mutate(unsafe)
            state["objects"] = [unsafe]
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                provision.cleanup_objects(api, state, Mock())
        self.assertEqual(api.delete.call_count, 1)
        run_id = "2" * 32
        witness_body = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "monitoring",
            "name": "phorvex-metrics-proof-" + run_id[:12] + "-helper",
            "labels": {"phorvex.ai/metrics-auth-proof": run_id}}, "immutable": True, "data": {"verify_metrics_auth.py": "# synthetic reviewed helper\n"}}
        witness_current = copy.deepcopy(witness_body)
        witness_current["metadata"].update(uid="own-witness-helper", resourceVersion="29")
        witness_record = {"path": provision.resource_path(witness_body), "uid": "own-witness-helper", "body": witness_body}
        witness_state = {"runID": run_id, "objects": [copy.deepcopy(witness_record)]}
        api.get.side_effect = None
        api.get.return_value = witness_current
        provision.cleanup_objects(api, witness_state, Mock())
        api.delete.assert_called_with(witness_record["path"], "own-witness-helper", "29")
        witness_state["objects"] = [copy.deepcopy(witness_record)]
        witness_state["objects"][0]["body"]["metadata"]["labels"]["phorvex.ai/metrics-auth-proof"] = "9" * 32
        with self.assertRaises(ValueError): provision.cleanup_objects(api, witness_state, Mock())
        self.assertEqual(api.delete.call_count, 2)

    def test_partial_secret_never_complete_and_rerun_never_generates(self):
        api = Mock()
        state = {"pairID": self.pair, "slots": self.slots, "objects": []}
        with self.assertRaises(ValueError): provision.provision(api, state, Mock())
        api.create.assert_not_called()
        metadata = make_metadata_fixture()
        metadata["generator"]["records"].pop()
        with self.assertRaises(ValueError): provision.validate_metadata(metadata)

    def test_fixed_workload_closure_tuple_and_parent_bytes_are_preserved(self):
        closure = {"metricsProtection": {"mode": "bearerToken", "secretName": generate.NAME,
            "secretKey": "token", "workloadNamespace": "vllm", "monitorNamespace": "monitoring"}}
        metadata = make_metadata_fixture(closure)
        for key, wrong in (("workloadNamespace", "litellm"), ("monitorNamespace", "vllm"),
                           ("secretName", "other"), ("secretKey", "other"), ("mode", "open")):
            bad = copy.deepcopy(closure)
            bad["metricsProtection"][key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                provision.validate_metadata(metadata, bad)
        bad = copy.deepcopy(closure)
        bad["metricsProtection"]["gatewayNamespace"] = bad["metricsProtection"].pop("workloadNamespace")
        with self.assertRaises(ValueError): provision.validate_metadata(metadata, bad)
        for module, filename in ((generate, "generate_metrics_token.py"), (provision, "provision_metrics_token.py")):
            source = (provision.ROOT / filename).read_text().split("\n# Stage6 parent provenance", 1)[0]
            # Reverse only the fixed identities/namespace/schema/closure tuple.
            source = source.replace('c["name"] == "vllm"', 'c["name"] == "litellm-admission-gateway"')
            for old, new in (
                ("phorvex-vllm-native-metrics-token-v1", "phorvex-litellm-gateway-metrics-token-v1"),
                ("phorvex-vllm-native-metrics", "phorvex-litellm-metrics"),
                ("stage6-v1", "stage5-v1"), ("workloadNamespace", "gatewayNamespace"),
                ('"vllm"', '"litellm"'), ("namespaces/vllm", "namespaces/litellm"),
                ("deployments/vllm", "deployments/litellm"),
                ("PHORVEX_VLLM_METRICS_ENABLED", "PHORVEX_LITELLM_METRICS_ENABLED"),
                ("phorvex.ai/vllm-native-metrics", "phorvex.ai/litellm-gateway-metrics"),
                ("== 9102", "== 4003")):
                source = source.replace(old, new)
            raw = source.encode()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), module.PARENT_PROVENANCE["sha256"])
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                             module.PARENT_PROVENANCE["blob"])
            self.assertEqual(module.PARENT_PROVENANCE["commit"], "ea70951ccf871b58bd60f71202f52228b70c83bc")

    def test_consumers_cover_native_init_projected_env_and_monitor_refs(self):
        references = [
            {"spec": {"initContainers": [{"name": "phorvex-vllm-metrics", "envFrom": [{"secretRef": {"name": generate.NAME}}]}]}},
            {"spec": {"volumes": [{"projected": {"sources": [{"secret": {"name": generate.NAME}}]}}]}},
            {"spec": {"template": {"spec": {"containers": [{"env": [{"valueFrom": {"secretKeyRef": {
                "name": generate.NAME, "key": "token"}}}]}]}}}},
            {"spec": {"endpoints": [{"authorization": {"credentials": {"name": generate.NAME, "key": "token"}}}]}}]
        for consumer in references:
            api = Mock()
            api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/vllm") else {"items": [consumer]}
            with self.subTest(consumer=consumer), self.assertRaises(ValueError): provision.no_consumers(api)
        self.assertFalse(provision.credential_reference({"spec": {"volumes": [{"secret": {"secretName": "unrelated"}}]}}))

    def test_invalid_pair_names_namespaces_and_duplicates_refuse_before_generation(self):
        for mutate in (lambda x: x["slots"][0].update(namespace="other"),
                       lambda x: x["slots"][0].update(name="arbitrary-token"),
                       lambda x: x["slots"].__setitem__(1, dict(x["slots"][0])),
                       lambda x: x.update(pairID="not-a-generation")):
            value = copy.deepcopy(self.inputs)
            mutate(value)
            factory, patcher = Mock(), Mock()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): generate.generate(value, patcher, factory)
            factory.assert_not_called()
            patcher.patch.assert_not_called()
        self.assertEqual(generate.NAMESPACES, ("vllm", "monitoring"))
        self.assertEqual(generate.NAME, "phorvex-vllm-native-metrics-token-v1")
        with self.assertRaises(ValueError): generate.secret_path("litellm")

    def test_complete_pair_cleanup_requires_fresh_reconciled_consumer_absence(self):
        metadata = make_metadata_fixture()
        filled = metadata["generator"]["records"]
        state = {"pairID": self.pair, "slots": copy.deepcopy(self.slots), "objects": [],
                 "report": {"result": "complete", "records": filled}}
        api = Mock()
        api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/vllm") else {"items": []}
        api.metadata.side_effect = lambda namespace, *_args, **_kw: next(r for r in metadata["secrets"] if r["namespace"] == namespace)
        with self.assertRaises(ValueError): provision.cleanup_slots(api, state, Mock())
        api.delete.assert_not_called()
        absent = {"utc": generate.utc(), "prometheusReconciled": True, "targetAbsent": True, "evidenceSHA256": "f" * 64}
        provision.cleanup_slots(api, state, Mock(), absent)
        self.assertEqual(api.delete.call_args_list, [unittest.mock.call(generate.secret_path(namespace), "secret-" + namespace, "42", secret=True)
                                                   for namespace in generate.NAMESPACES])

    def test_generator_evidence_failure_revokes_exact_roles_before_other_cleanup(self):
        inventory, events = {}, []
        api = Mock()
        def create(path, body):
            actual = copy.deepcopy(body)
            actual["metadata"].update(uid="created-" + str(len(inventory)), resourceVersion="11")
            inventory[path + "/" + body["metadata"]["name"] if body["kind"] == "Secret" else provision.resource_path(body)] = actual
            return actual
        def get(path, **_kw):
            if path.endswith("deployments/vllm"): return self.baseline()
            if path in inventory:
                actual = copy.deepcopy(inventory[path])
                if actual["kind"] == "Job": actual["status"] = {"failed": 1}
                return actual
            return {"items": []}
        def metadata(namespace, pair_id, filled, **_kw):
            return generate.safe_record(inventory[generate.secret_path(namespace)], namespace, pair_id, immutable=filled)
        def delete(path, uid, rv, **_kw):
            self.assertEqual((uid, rv), (inventory[path]["metadata"]["uid"], "11"))
            events.append(inventory[path]["kind"])
            del inventory[path]
        api.create.side_effect, api.get.side_effect = create, get
        api.metadata.side_effect, api.delete.side_effect = metadata, delete
        api.request.return_value = None
        state = {"pairID": self.pair, "slots": [], "objects": []}
        with self.assertRaises(ValueError): provision.provision(api, state, Mock())
        self.assertEqual(events[:4], ["RoleBinding", "Role", "RoleBinding", "Role"])
        self.assertEqual(state["objects"], [])
        self.assertEqual(len(state["slots"]), 2)
        self.assertNotIn("report", state)
        self.assertTrue(all(value["kind"] == "Secret" and value["data"] == {} for value in inventory.values()))


if __name__ == "__main__":
    unittest.main()
