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
        "uid": "probe-pod-uid", "resourceVersion": "21", "ownerReferences": [{"kind": "Job", "uid": job["metadata"]["uid"]}]},
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
