"""Mocked API, receipt and disposable-source controls; run on isolated executor."""
import base64
import copy
import hashlib
import io
import http.client
import tempfile
import threading
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request
import unittest
from unittest.mock import Mock, patch
import generate_metrics_token as generate
import provision_metrics_token as provision
import verify_metrics_auth as auth


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


def make_auth_fixture(closure, metadata, source):
    """Test-only nonsecret API readbacks; never usable as a live proof collector."""
    plan = auth.prepare(closure, metadata, source, "2" * 32)
    def identified(body, uid):
        value = copy.deepcopy(body)
        value["metadata"].update(uid=uid, resourceVersion="17")
        return value
    witness = identified(plan["witnessPod"], "witness-pod-uid")
    witness["spec"]["nodeName"] = "witness-node"
    witness["status"] = {"phase": "Running", "podIP": "10.1.2.3", "conditions": [{"type": "Ready", "status": "True"}],
                          "containerStatuses": [{"name": "witness", "imageID": "docker-pullable://" + generate.IMAGE}]}
    targets = [{"name": "witness", "host": "10.1.2.3", "port": 4003, "podUID": witness["metadata"]["uid"]}]
    job = identified(auth.probe_job(plan, targets), "probe-job-uid")
    job["status"] = {"succeeded": 1}
    probe = {"apiVersion": "v1", "kind": "Pod", "metadata": {"namespace": "monitoring", "name": "actual-probe-pod",
        "uid": "probe-pod-uid", "resourceVersion": "21", "ownerReferences": [{"apiVersion": "batch/v1", "kind": "Job", "name": job["metadata"]["name"], "uid": job["metadata"]["uid"], "controller": True, "blockOwnerDeletion": True}]},
        "spec": copy.deepcopy(job["spec"]["template"]["spec"])}
    probe["spec"]["nodeName"] = "probe-node"
    probe["status"] = {"phase": "Succeeded", "containerStatuses": [{"name": "probe", "imageID": "docker-pullable://" + generate.IMAGE}]}
    checks = [{"name": name, "status": status, "bodyLength": 123 if name == "valid-token" else 0,
               "verdict": "pass"} for name, status in auth.CHECK_STATUS.items()]
    report = {"schema": "phorvex-litellm-metrics-probe-report-v1", "utc": generate.utc(),
              "targets": [{"target": targets[0], "checks": checks}], "modelCalls": 0, "upstreamConfigured": False}
    evidence = {"sourceConfigMap": identified(plan["sourceConfigMap"], "source-cm-uid"),
        "helperConfigMaps": [identified(body, "helper-" + body["metadata"]["namespace"]) for body in plan["helperConfigMaps"]],
        "witnessPod": witness, "probeJob": job, "probePod": probe, "probeReport": report}
    return auth.proof_from_evidence(plan, evidence, metadata)


class TokenHelpers(unittest.TestCase):
    def setUp(self):
        self.pair = "1" * 32
        self.slots = [{"namespace": namespace, "name": generate.NAME, "uid": "uid-" + namespace, "resourceVersion": "4",
            "pairID": self.pair, "provenance": generate.PROVENANCE, "ready": False, "lastAppliedPresent": False}
            for namespace in generate.NAMESPACES]
        self.inputs = {"schema": "phorvex-litellm-metrics-token-inputs-v1", "pairID": self.pair, "slots": self.slots}
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
        patcher.patch.side_effect = [self.response("litellm", generate.patch_for(self.slots[0], self.pair, self.token)),
                                    RuntimeError("SECRET " + self.token)]
        report = generate.generate(self.inputs, patcher, Mock(return_value=self.token))
        self.assertEqual(report["result"], "partial")
        self.assertEqual([r["namespace"] for r in report["records"]], ["litellm"])
        self.assertNotIn(self.token, json.dumps(report))
        self.assertEqual(report["error"], "credential generation incomplete")

    def test_uid_conflict_no_second_patch_or_overwrite(self):
        patcher = Mock()
        bad = self.response("litellm", generate.patch_for(self.slots[0], self.pair, self.token))
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
            "namespace": "litellm", "name": generate.NAME, "uid": "uid-litellm", "resourceVersion": "5",
            "labels": generate.labels(self.pair, True)}}
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        captured = []
        def opened(request, timeout):
            captured.append(request)
            return Response(json.dumps(obj).encode())
        api.opener.open = opened
        record = api.metadata("litellm", self.pair, True)
        self.assertEqual(record["resourceVersion"], "5")
        self.assertEqual(captured[0].get_header("Accept"), generate.PARTIAL_ACCEPT)
        self.assertNotIn("immutable", record)
        with self.assertRaises(generate.SafeFailure):
            api.get(generate.secret_path("litellm"))
        obj["kind"] = "Secret"
        with self.assertRaises(generate.SafeFailure):
            api.metadata("litellm", self.pair, True)
        self.assertEqual(len(captured), 2)

    def test_helper_logs_negotiate_api_json_before_plain_text_stream(self):
        # Real cluster NOOP control: text/plain produced 406 NotAcceptable;
        # application/json produced 200 with this same plain-text JSON line.
        api = provision.ProxyAPI()
        payload = b'{"diagnostic":"ok"}\n'
        class Response(io.BytesIO):
            headers = {"Content-Type": "text/plain"}
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        def negotiated(request, timeout):
            self.assertEqual(timeout, 10)
            if request.get_header("Accept") not in ("application/json", "*/*"):
                raise HTTPError(request.full_url, 406, "NotAcceptable", {}, None)
            return Response(payload)
        api.opener.open = Mock(side_effect=negotiated)
        output = api.logs("litellm", "reviewed-helper-pod")
        self.assertEqual(output, payload.decode("ascii"))
        self.assertEqual(json.loads(output), {"diagnostic": "ok"})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(request.full_url,
                         "http://127.0.0.1:18081/api/v1/namespaces/litellm/pods/reviewed-helper-pod/log?limitBytes=65536")
        # The former header is a discriminating negative control, rather than
        # accepting every mock request and concealing negotiation failures.
        with self.assertRaises(HTTPError) as rejected:
            negotiated(Request(request.full_url, headers={"Accept": "text/plain"}), 10)
        self.assertEqual(rejected.exception.code, 406)

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
        response = self.response("litellm", generate.patch_for(self.slots[0], self.pair, self.token))
        response["metadata"]["annotations"] = {generate.LAST_APPLIED: self.token}
        with self.assertRaises(ValueError): generate.safe_record(response, "litellm", self.pair, immutable=True)
        response["metadata"].pop("annotations")
        response["metadata"]["ownerReferences"] = [{"uid": "temporary-job"}]
        with self.assertRaises(ValueError): generate.safe_record(response, "litellm", self.pair, immutable=True)

    def baseline(self):
        return {"spec": {"template": {"metadata": {"labels": {"app": "litellm"}}, "spec": {"containers": [
            {"name": "litellm", "ports": [{"containerPort": 4000}]},
            {"name": "litellm-admission-gateway", "env": [], "ports": [{"containerPort": 4001}, {"containerPort": 4002}]}]}}}}

    def test_real_gateway_name_and_enabled_label_gate(self):
        api = Mock()
        baseline = self.baseline()
        api.get.side_effect = lambda path: baseline if path.endswith("deployments/litellm") else {"items": []}
        provision.no_consumers(api)
        baseline["spec"]["template"]["metadata"]["labels"]["phorvex.ai/litellm-gateway-metrics"] = "enabled"
        with self.assertRaises(ValueError): provision.no_consumers(api)

    def test_existing_consumer_and_collision_prevent_any_create(self):
        api = Mock()
        api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/litellm") else {
            "items": [{"spec": {"volumes": [{"secret": {"secretName": generate.NAME}}]}}]}
        with self.assertRaises(ValueError): provision.no_consumers(api)
        api.get.side_effect = lambda path: self.baseline() if path.endswith("deployments/litellm") else {"items": []}
        api.request.return_value = {"kind": "PartialObjectMetadata"}
        state = {"pairID": self.pair, "slots": [], "objects": []}
        with self.assertRaises(ValueError): provision.provision(api, state, Mock())
        api.create.assert_not_called()

    def test_cleanup_requires_exact_uid_and_rv_preconditions(self):
        api = Mock()
        api.get.side_effect = lambda path, **kw: self.baseline() if path.endswith("deployments/litellm") else {"items": []}
        api.metadata.return_value = dict(self.slots[0])
        state = {"pairID": self.pair, "slots": [dict(self.slots[0])], "objects": []}
        provision.cleanup_slots(api, state, Mock())
        api.delete.assert_called_once_with(generate.secret_path("litellm"), "uid-litellm", "4", secret=True)
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
            "labels": {"phorvex.ai/metrics-auth-proof": run_id}}, "immutable": True, "data": auth.helper_data()}
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


class AuthProof(unittest.TestCase):
    def setUp(self):
        self.source = (provision.ROOT / "gateway_metrics.py").read_text()
        digest = hashlib.sha256(self.source.encode()).hexdigest()
        self.closure = {"schema": "phorvex-litellm-metrics-candidate-v2", "gatewaySourceSHA256": digest,
            "gatewayImageByDigest": generate.IMAGE, "candidateTemplateSHA256": "d" * 64,
            "monitoringSpecsSHA256": {"Service": "e" * 64}, "metricsProtection": {
                "mode": "bearerToken", "authenticatedSourceSHA256": digest, "secretName": generate.NAME,
                "secretKey": "token", "gatewayNamespace": "litellm", "monitorNamespace": "monitoring", "tokenFile": auth.TOKEN_FILE}}
        self.metadata = make_metadata_fixture(self.closure)
        self.proof = make_auth_fixture(self.closure, self.metadata, self.source)

    def test_actual_source_helpers_specs_image_and_complete_controls_validate(self):
        auth.validate_auth_proof(self.proof, self.closure, self.metadata)
        self.assertEqual(len(self.proof["checks"]), 20)
        witness = self.proof["evidence"]["witnessPod"]["spec"]
        self.assertFalse(witness["automountServiceAccountToken"])
        self.assertEqual(witness["containers"][0]["ports"], [{"name": "metrics", "containerPort": 4003, "protocol": "TCP"}])
        self.assertNotIn("phorvex.ai/litellm-gateway-metrics", self.proof["evidence"]["witnessPod"]["metadata"]["labels"])
        credential = next(volume for volume in witness["volumes"] if volume["name"] == "credential")
        self.assertEqual(credential["secret"]["defaultMode"], 288)
        self.assertEqual(witness["securityContext"]["fsGroup"], 10001)

    def test_api_omits_false_host_booleans_but_true_and_missing_tokenless_flag_fail(self):
        value = copy.deepcopy(self.proof)
        for pod in (value["evidence"]["witnessPod"], value["evidence"]["probePod"]):
            for key in ("hostNetwork", "hostPID", "hostIPC"):
                pod["spec"].pop(key)
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            value["evidence"]["probeJob"]["spec"]["template"]["spec"].pop(key)
        plan = auth.prepare(self.closure, self.metadata, self.source, "2" * 32)
        value = auth.proof_from_evidence(plan, value["evidence"], self.metadata)
        auth.validate_auth_proof(value, self.closure, self.metadata)
        value["evidence"]["witnessPod"]["spec"]["hostNetwork"] = True
        with self.assertRaises(ValueError): auth.validate_auth_proof(value, self.closure, self.metadata)
        value = copy.deepcopy(self.proof)
        value["evidence"]["witnessPod"]["spec"].pop("automountServiceAccountToken")
        with self.assertRaises(ValueError): auth.validate_auth_proof(value, self.closure, self.metadata)

    def test_collect_reads_named_pod_when_list_items_omit_type_meta(self):
        evidence = copy.deepcopy(self.proof["evidence"])
        plan = auth.prepare(self.closure, self.metadata, self.source, "2" * 32)
        plan["probeJob"] = copy.deepcopy(evidence["probeJob"])
        objects = [evidence["sourceConfigMap"], *evidence["helperConfigMaps"], evidence["witnessPod"], evidence["probeJob"]]
        plan["objects"] = [{"path": provision.resource_path(obj), "uid": obj["metadata"]["uid"]} for obj in objects]
        named = evidence["probePod"]
        listed = copy.deepcopy(named)
        listed.pop("kind")
        listed.pop("apiVersion")
        responses = {provision.resource_path(obj): obj for obj in [*objects, named]}
        responses["/api/v1/namespaces/monitoring/pods"] = {"apiVersion": "v1", "kind": "PodList", "items": [listed]}
        api = Mock()
        api.get.side_effect = lambda path: copy.deepcopy(responses[path])
        api.logs.return_value = generate.canonical(evidence["probeReport"])
        api.metadata.side_effect = lambda namespace, pair_id, filled: next(
            record for record in self.metadata["secrets"] if record["namespace"] == namespace)
        bundle = auth.collect(api, plan)
        actual = bundle["authProof"]["evidence"]["probePod"]
        self.assertEqual((actual["kind"], actual["apiVersion"]), ("Pod", "v1"))
        self.assertEqual(actual["metadata"]["uid"], listed["metadata"]["uid"])
        auth.validate_auth_proof(bundle["authProof"], self.closure, bundle["secretMetadata"])
        api.get.assert_any_call(provision.resource_path(named))

    def test_named_probe_rejects_uid_owner_and_gvk_recreation(self):
        job = copy.deepcopy(self.proof["evidence"]["probeJob"])
        named = copy.deepcopy(self.proof["evidence"]["probePod"])
        listed = copy.deepcopy(named)
        listed.pop("kind")
        listed.pop("apiVersion")
        api = Mock()
        for mutate in (lambda p: p["metadata"].update(uid="same-name-replacement"),
                       lambda p: p["metadata"]["ownerReferences"][0].update(uid="recreated-job"),
                       lambda p: p["metadata"]["ownerReferences"][0].update(name="different-job"),
                       lambda p: p.update(kind="PartialObjectMetadata"),
                       lambda p: p.pop("apiVersion")):
            changed = copy.deepcopy(named)
            mutate(changed)
            api.get.side_effect = [{"items": [listed]}, changed]
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): auth.named_probe_pod(api, job)

    def test_stable_binding_survives_only_deployment_resource_version_refresh(self):
        closure = copy.deepcopy(self.closure)
        closure["artifactsSHA256"] = {"patch": "f" * 64}
        closure["baseline"] = {"deploymentResourceVersion": "999"}
        self.assertEqual(auth.auth_closure_hash(closure), auth.auth_closure_hash(self.closure))
        auth.validate_auth_proof(self.proof, closure, self.metadata)
        closure["candidateTemplateSHA256"] = "f" * 64
        with self.assertRaises(ValueError): auth.validate_auth_proof(self.proof, closure, self.metadata)

    def test_receipt_and_underlying_source_image_uid_rv_mutations_fail(self):
        mutations = [lambda p: p.update(modelCalls=1), lambda p: p.update(scope="live-two-replica-clusterip"),
            lambda p: p["secretPair"]["secrets"][0].update(resourceVersion="99"),
            lambda p: p["evidence"]["sourceConfigMap"]["data"].update({"gateway.py": "different"}),
            lambda p: p["evidence"]["witnessPod"]["spec"].update(automountServiceAccountToken=True),
            lambda p: p["evidence"]["probePod"]["status"]["containerStatuses"][0].update(imageID="wrong-image"),
            lambda p: p["evidence"]["helperConfigMaps"][0]["data"].update({"verify_metrics_auth.py": "fabricated"}),
            lambda p: p["checks"][0].update(status=200),
            lambda p: p["evidence"]["witnessPod"]["spec"]["containers"].append({"name": "upstream"})]
        for mutate in mutations:
            value = copy.deepcopy(self.proof)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                auth.validate_auth_proof(value, self.closure, self.metadata)

    def test_projection_shadow_and_token_bearing_evidence_fail(self):
        value = copy.deepcopy(self.proof)
        value["evidence"]["witnessPod"]["spec"]["containers"][0]["volumeMounts"].append({"name": "credential", "mountPath": "/tmp/token"})
        with self.assertRaises(ValueError): auth.validate_auth_proof(value, self.closure, self.metadata)
        value = copy.deepcopy(self.proof)
        value["checks"][0]["Authorization"] = "forbidden"
        with self.assertRaises(ValueError): auth.validate_auth_proof(value, self.closure, self.metadata)

    def production_fixture(self):
        # Use the actual renderer's complete healthy candidate; do not invent
        # gateway container, env, Secret projection or source binding shapes.
        from test_render_metrics import auth_render, originals, patched
        baseline, profiles, policies, labels = originals()
        objects = auth_render(baseline, profiles, policies, labels, enabled=True)
        candidate = patched(baseline, objects["deployment-metrics-json-patch.json"])
        closure = objects["metrics-closure.json"]
        metadata = make_metadata_fixture(closure)
        plan = auth.prepare(closure, metadata, self.source, "3" * 32)
        pods = []
        for index in (1, 2):
            pod = {"apiVersion": "v1", "kind": "Pod", "metadata": copy.deepcopy(candidate["spec"]["template"]["metadata"]),
                   "spec": copy.deepcopy(candidate["spec"]["template"]["spec"])}
            pod["metadata"].update(namespace="litellm", name="candidate-replica-" + str(index),
                                   uid="replica-uid-" + str(index), resourceVersion="25")
            pod["spec"]["nodeName"] = "actual-node-" + str(index)
            pod["status"] = {"phase": "Running", "podIP": "10.2.3." + str(index),
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"name": "litellm-admission-gateway", "imageID": "docker-pullable://" + generate.IMAGE}]}
            pods.append(pod)
        service = copy.deepcopy(objects["metrics-service.json"])
        service["metadata"].update(uid="metrics-service-uid", resourceVersion="26")
        service["spec"]["clusterIP"] = "10.4.5.6"
        source_cm = copy.deepcopy(objects["gateway-metrics-source-configmap.json"])
        source_cm["metadata"].update(uid="actual-production-source-uid", resourceVersion="27")
        return plan, pods, service, source_cm

    def test_live_preparation_binds_healthy_generated_two_replicas_and_clusterip(self):
        plan, pods, service, source_cm = self.production_fixture()
        live = auth.prepare_live(plan, pods, service)
        self.assertEqual([target["name"] for target in live["targets"]], ["replica-1", "replica-2", "clusterip"])
        self.assertEqual([target["podUID"] for target in live["targets"][:2]], [pod["metadata"]["uid"] for pod in pods])
        self.assertEqual(live["probeJob"]["spec"]["activeDeadlineSeconds"], 120)
        inventory = {"/api/v1/namespaces/litellm/pods/" + pod["metadata"]["name"]: pod for pod in pods}
        inventory["/api/v1/namespaces/litellm/configmaps/" + source_cm["metadata"]["name"]] = source_cm
        inventory["/api/v1/namespaces/litellm/services/phorvex-litellm-gateway-metrics"] = service
        api = Mock()
        api.get.side_effect = lambda path: copy.deepcopy(inventory[path])
        auth.live_inputs_current(api, live)
        self.assertEqual(live["sourceConfigMapIdentity"]["uid"], source_cm["metadata"]["uid"])
        inventory["/api/v1/namespaces/litellm/configmaps/" + source_cm["metadata"]["name"]]["metadata"]["uid"] = "recreated-source"
        with self.assertRaises(ValueError): auth.live_inputs_current(api, live)

    def test_live_collect_reads_named_pod_when_list_items_omit_type_meta(self):
        plan, pods, service, source_cm = self.production_fixture()
        live = auth.prepare_live(plan, pods, service)
        helper = copy.deepcopy(live["helperConfigMaps"][0])
        helper["metadata"].update(uid="live-helper-uid", resourceVersion="30")
        job = copy.deepcopy(live["probeJob"])
        job["metadata"].update(uid="live-job-uid", resourceVersion="31")
        job["status"] = {"succeeded": 1}
        named = {"apiVersion": "v1", "kind": "Pod", "metadata": {
            "namespace": "monitoring", "name": "actual-live-probe-pod", "uid": "live-probe-uid", "resourceVersion": "32",
            "ownerReferences": [{"apiVersion": "batch/v1", "kind": "Job", "name": job["metadata"]["name"],
                "uid": job["metadata"]["uid"], "controller": True, "blockOwnerDeletion": True}]},
            "spec": copy.deepcopy(job["spec"]["template"]["spec"]), "status": {"phase": "Succeeded",
                "containerStatuses": [{"name": "probe", "imageID": "docker-pullable://" + generate.IMAGE}]}}
        named["spec"]["nodeName"] = "actual-probe-node"
        listed = copy.deepcopy(named)
        listed.pop("kind")
        listed.pop("apiVersion")
        live["objects"] = [{"path": provision.resource_path(obj), "uid": obj["metadata"]["uid"]} for obj in (helper, job)]
        responses = {provision.resource_path(obj): obj for obj in [*pods, source_cm, helper, job, named]}
        responses["/api/v1/namespaces/litellm/services/" + service["metadata"]["name"]] = service
        responses["/api/v1/namespaces/monitoring/pods"] = {"apiVersion": "v1", "kind": "PodList", "items": [listed]}
        report = {"schema": "phorvex-litellm-metrics-probe-report-v1", "utc": auth.utc(), "modelCalls": 0,
            "upstreamConfigured": False, "targets": [{"target": target, "checks": copy.deepcopy(self.proof["checks"])} for target in live["targets"]]}
        api = Mock()
        api.get.side_effect = lambda path: copy.deepcopy(responses[path])
        api.logs.return_value = generate.canonical(report)
        api.metadata.side_effect = lambda namespace, pair_id, filled: next(
            record for record in live["metadata"]["secrets"] if record["namespace"] == namespace)
        proof = auth.collect_live(api, live)
        actual = proof["evidence"]["probePod"]
        self.assertEqual((actual["kind"], actual["apiVersion"]), ("Pod", "v1"))
        self.assertEqual(actual["metadata"]["uid"], listed["metadata"]["uid"])
        self.assertEqual(len(proof["targets"]), 3)
        api.get.assert_any_call(provision.resource_path(named))

    def test_live_mount_image_source_and_uid_drift_fail_before_probe(self):
        plan, pods, service, source_cm = self.production_fixture()
        mutations = [lambda p: p["spec"]["containers"][1]["volumeMounts"][-1].update(readOnly=False),
            lambda p: p["status"]["containerStatuses"][0].update(imageID="sha256:" + "f" * 64),
            lambda p: p["spec"]["containers"][1]["env"].append({"name": "PHORVEX_LITELLM_METRICS_ENABLED", "value": "1"}),
            lambda p: p["spec"]["volumes"][-1]["secret"].update(optional=True),
            lambda p: p["metadata"]["annotations"].update({"phorvex.ai/litellm-gateway-source-sha256": "f" * 64})]
        for mutate in mutations:
            changed = copy.deepcopy(pods)
            mutate(changed[0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): auth.prepare_live(plan, changed, service)
        live = auth.prepare_live(plan, pods, service)
        inventory = {"/api/v1/namespaces/litellm/pods/" + pod["metadata"]["name"]: copy.deepcopy(pod) for pod in pods}
        inventory["/api/v1/namespaces/litellm/configmaps/" + source_cm["metadata"]["name"]] = copy.deepcopy(source_cm)
        inventory["/api/v1/namespaces/litellm/services/phorvex-litellm-gateway-metrics"] = copy.deepcopy(service)
        api = Mock()
        api.get.side_effect = lambda path: copy.deepcopy(inventory[path])
        pod_path = "/api/v1/namespaces/litellm/pods/" + pods[0]["metadata"]["name"]
        inventory[pod_path]["metadata"]["uid"] = "recreated-replica"
        with self.assertRaises(ValueError): auth.live_inputs_current(api, live)
        inventory[pod_path] = copy.deepcopy(pods[0])
        source_path = "/api/v1/namespaces/litellm/configmaps/" + source_cm["metadata"]["name"]
        inventory[source_path]["data"]["gateway.py"] = "unreviewed-source"
        with self.assertRaises(ValueError): auth.live_inputs_current(api, live)

    def test_disposable_probe_runs_all_controls_against_actual_candidate_handler(self):
        # A synthetic file credential and loopback ephemeral listener only. This
        # executes production probe logic; no mocked status/booleans authorize it.
        import gateway_metrics as candidate
        token = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_bytes(token.encode())
            path.chmod(0o440)
            loaded = candidate.configured_metrics_token({"PHORVEX_LITELLM_METRICS_ENABLED": "1",
                "PHORVEX_LITELLM_METRICS_TOKEN_FILE": str(path)})
            metrics = candidate.RequestMetrics("litellm", "disposable-witness")
            metrics.observe("GET", "/v1/models", 200, "completed", .01)
            handler = type("DisposableReviewedHandler", (candidate.MetricsHandler,),
                           {"metrics": metrics, "metrics_token": loaded})
            server = candidate.MetricsHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            original = http.client.HTTPConnection
            try:
                with patch.object(auth.http.client, "HTTPConnection",
                        side_effect=lambda host, port, timeout: original(host, server.server_port, timeout=timeout)):
                    report = auth.probe_target({"name": "witness", "host": "127.0.0.1", "port": 4003, "podUID": "disposable-uid"}, token)
                self.assertEqual(len(report["checks"]), 20)
                self.assertNotIn(token, json.dumps(report))
                self.assertEqual(len(metrics.series), 1)  # Scrapes never count as application calls.
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_probe_controls_use_no_redirect_and_exact_paths_and_no_body_export(self):
        controls = list(auth.controls("a" * 64))
        self.assertEqual({item[0] for item in controls}, set(auth.CHECK_STATUS))
        self.assertEqual(next(item for item in controls if item[0] == "absolute-target")[2], "http://example.invalid/metrics")
        self.assertEqual(next(item for item in controls if item[0] == "duplicate-auth")[3][0],
                         next(item for item in controls if item[0] == "duplicate-auth")[3][1])


if __name__ == "__main__":
    unittest.main()
