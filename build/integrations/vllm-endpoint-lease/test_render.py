import base64
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lease_activation", HERE / "render.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


U = {
    "cluster": "77777777-7777-4777-8777-777777777777",
    "source": "11111111-1111-4111-8111-111111111111",
    "service": "22222222-2222-4222-8222-222222222222",
    "tenant": "33333333-3333-4333-8333-333333333333",
    "console": "44444444-4444-4444-8444-444444444444",
    "policy": "55555555-5555-4555-8555-555555555555",
    "journal": "66666666-6666-4666-8666-666666666666",
}


class LeaseActivationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.keys = {"client-a": b"A1" * 24, "client-b": b"B2" * 24, "seed": b"S3" * 24}
        self.owner = {"schema": "endpoint-lease-owner-keys-v1",
                      **{key: base64.b64encode(raw).decode() for key, raw in self.keys.items()}}
        self.tenant = renderer.secret_document("vllm", renderer.TENANT_SECRET, self.keys)
        self.console = renderer.secret_document("phorvex-system", renderer.CONSOLE_SECRET,
                                                {key: self.keys[key] for key in ("client-a", "client-b")})
        for obj, uid in ((self.tenant, U["tenant"]), (self.console, U["console"])):
            obj["metadata"].update(uid=uid, resourceVersion="7")
        self.source = {"kind": "ConfigMap", "metadata": {"name": renderer.SOURCE_CM,
                       "namespace": "vllm", "uid": U["source"], "resourceVersion": "8"},
                       "data": {"guardrail_proxy.py": "old"}}
        self.service = {"kind": "Service", "metadata": {"name": "vllm", "namespace": "vllm",
                        "uid": U["service"], "resourceVersion": "9"},
                        "spec": {"selector": {"phorvex.ai/role": "leader"}}}
        self.absent_policy = self.absence("vllm", renderer.POLICY_CM)
        self.absent_journal = self.absence("phorvex-system", renderer.JOURNAL_CM)
        for name in renderer.FILES:
            (self.folder / name).write_text("# synthetic " + name + "\n")
        self.source_manifest = {"schema": "endpoint-lease-source-v1", "sourceCommit": "a" * 40,
                                "files": {name: renderer.sha((self.folder / name).read_bytes())
                                          for name in renderer.FILES}}
        self.recipe_dir = self.folder / "proxy-recipe"
        self.recipe_dir.mkdir()
        for name in renderer.PROXY_RECIPE_FILES:
            raw = ("FROM --platform=linux/amd64 " + renderer.PROXY_BASE_IMAGE + "\n"
                   "RUN pip install --no-index --require-hashes\n"
                   "USER 10001:10001\nCMD " + renderer.PROXY_COMMAND + "\n"
                   if name == "Dockerfile" else "# synthetic " + name + "\n")
            (self.recipe_dir / name).write_text(raw)
        self.tenant_receipt = self.create_receipt(None, self.tenant,
            renderer.sha(renderer.canonical(renderer.secret_document("vllm", renderer.TENANT_SECRET, self.keys))))
        self.console_receipt = self.create_receipt(None, self.console,
            renderer.sha(renderer.canonical(renderer.secret_document("phorvex-system", renderer.CONSOLE_SECRET,
                                      {key: self.keys[key] for key in ("client-a", "client-b")}))))

    def absence(self, namespace, name):
        return {"schema": "endpoint-lease-absence-v1", "clusterUID": U["cluster"],
                "namespace": namespace, "kind": "ConfigMap", "name": name,
                "statusCode": 404, "dispatchCount": 1,
                "observedAt": datetime.now(timezone.utc).isoformat()}

    def prepared(self):
        result = renderer.prepare(self.owner, self.tenant, self.console,
                                  self.source_manifest, self.folder, self.source, self.service,
                                  self.absent_policy, self.absent_journal, U["cluster"],
                                  self.tenant_receipt, self.console_receipt)
        return {name: json.loads(raw) for name, raw in result.items()}

    def installed(self):
        p = self.prepared()
        source = p["source-configmap.candidate.json"]
        policy = p["policy-configmap.CREATE.json"]
        journal = p["journal-configmap.CREATE.json"]
        for obj, uid in ((policy, U["policy"]), (journal, U["journal"])):
            obj["metadata"].update(uid=uid, resourceVersion="10")
        return p["PREPARED.json"], source, policy, journal

    def create_receipt(self, prepared, obj, candidate_field, completed_at=None):
        meta = obj["metadata"]
        return {"schema": "endpoint-lease-create-receipt-v1", "clusterUID": U["cluster"],
                "kind": obj["kind"], "namespace": meta["namespace"], "name": meta["name"],
                "requestSHA256": prepared[candidate_field] if prepared is not None else candidate_field,
                "uid": meta["uid"],
                "resourceVersion": meta["resourceVersion"], "dispatchCount": 1,
                "operation": "create", "completedAt": (completed_at or datetime.now(timezone.utc)).isoformat()}

    def base(self):
        return {"deployment.candidate.json": {"kind": "Deployment",
                "metadata": {"namespace": "vllm", "name": "vllm"},
                "spec": {"template": {"metadata": {"annotations": {"phorvex.ai/drain-proxy-source": "0" * 64}},
                         "spec": {"containers": [
                             {"name": "vllm", "image": renderer.APPROVED_ENGINE_IMAGE,
                              "args": ["--model", "Qwen/Qwen2.5-7B-Instruct-AWQ", "--port", "8001",
                                       "--host", "127.0.0.1"],
                              "env": [{"name": "VLLM_API_KEY", "valueFrom": {
                                  "secretKeyRef": {"name": "vllm-control", "key": "api-key"}}}]},
                             {"name": "guardrail", "image": "python:3.11-slim",
                              "command": ["sh", "-c", "exec python /src/dual_server.py"],
                              "env": [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                                      {"name": "PHORVEX_PROXY_SOURCE", "value": "0" * 64}],
                              "volumeMounts": [{"name": "guardrail-src", "mountPath": "/src"}]}],
                          "initContainers": [{"name": "phorvex-drain-ledger-init", "image": "python:3.11-slim",
                              "command": ["python", "/src/drain_v11_init.py"],
                              "volumeMounts": [{"name": "guardrail-src", "mountPath": "/src"}]}],
                          "volumes": [{"name": "guardrail-src", "configMap": {"name": renderer.SOURCE_CM}}]}}}},
                "configmap.candidate.json": {"kind": "ConfigMap", "metadata": {"name": renderer.SOURCE_CM},
                  "data": {"guardrail_proxy.py": "proxy", "dual_server.py": "dual",
                           "drain_v11.py": "drain", "drain_v11_init.py": "init"}},
                "service.candidate.json": {"kind": "Service", "metadata": {"name": "vllm"},
                  "spec": {"selector": {"phorvex.ai/role": "leader", "phorvex.ai/serving": "true"}}},
                "values.overlay.yaml": {}, "secret-contract.json": {},
                "publication-join.json": {"originalServiceUID": U["service"],
                  "originalConfigMapUID": U["source"],
                  "publishedImage": renderer.APPROVED_ENGINE_IMAGE}}

    def image_receipt(self, prepared):
        source = "b" * 40
        image = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-lease-proxy-" + source
        return {"schemaVersion": 1, "sourceSHA": source, "image": image,
                "digest": "sha256:" + "c" * 64,
                "imageByDigest": "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + "c" * 64,
                "platform": "linux/amd64", "baseImage": renderer.PROXY_BASE_IMAGE,
                "command": renderer.PROXY_COMMAND, "wheelCount": 1,
                "lockedVersions": {"fastapi": "1.0.0"},
                "recipeSHA256": {name: renderer.sha((self.recipe_dir / name).read_bytes())
                                 for name in renderer.PROXY_RECIPE_FILES},
                "classifierWeightsIncluded": False, "applicationSourceIncluded": False,
                "githubRunID": "1", "githubRunAttempt": "1"}

    def test_provision_emits_only_private_immutable_secret_files(self):
        result = renderer.provision(self.owner)
        self.assertEqual(set(result), {"tenant-secret.PRIVATE.json", "console-secret.PRIVATE.json", "PROVISION.json"})
        self.assertEqual(json.loads(result["tenant-secret.PRIVATE.json"])["immutable"], True)
        self.assertEqual(set(json.loads(result["console-secret.PRIVATE.json"])["data"]), {"client-a", "client-b"})
        self.assertNotIn(self.keys["seed"].decode(), result["PROVISION.json"].decode())
        target = self.folder / "private"
        renderer.private_output(target, result)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((target / name).stat().st_mode & 0o777 == 0o600 for name in result))

    def test_prepare_requires_exact_absence_and_source_and_never_invents_uids(self):
        p = self.prepared()
        state_raw = p["policy-configmap.CREATE.json"]["data"]["state.json"].encode()
        state = json.loads(state_raw)
        self.assertEqual(renderer.canonical(state), state_raw)
        self.assertEqual(state["revision"], 0)
        self.assertEqual(len(state["allowedClientHMACs"]), 2)
        self.assertEqual(p["journal-configmap.CREATE.json"]["data"], {"receipts.json": '{"receipts":[],"version":1}'})
        self.assertEqual(set(p["source-configmap.candidate.json"]["data"]), set(renderer.FILES))
        self.assertTrue(p["source-configmap.candidate.json"]["immutable"])
        for row in (p["policy-configmap.CREATE.json"], p["journal-configmap.CREATE.json"]):
            self.assertNotIn("uid", row["metadata"])
        bad = copy.deepcopy(self.absent_journal)
        bad["statusCode"] = 200
        with self.assertRaisesRegex(ValueError, "absence"):
            renderer.prepare(self.owner, self.tenant, self.console,
                             self.source_manifest, self.folder, self.source, self.service,
                             self.absent_policy, bad, U["cluster"],
                             self.tenant_receipt, self.console_receipt)
        bad_source = copy.deepcopy(self.source_manifest)
        bad_source["files"]["endpoint_lease.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source file SHA"):
            renderer.prepare(self.owner, self.tenant, self.console,
                             bad_source, self.folder, self.source, self.service,
                             self.absent_policy, self.absent_journal, U["cluster"],
                             self.tenant_receipt, self.console_receipt)
        self.source["immutable"] = True
        with self.assertRaisesRegex(ValueError, "existing immutable"):
            self.prepared()

    def test_adoption_binds_created_uids_and_read_only_named_proxy_grants(self):
        prepared, source, policy, journal = self.installed()
        journal_receipt = self.create_receipt(prepared, journal, "journalCandidateSHA256",
                                              datetime.now(timezone.utc) - timedelta(seconds=1))
        policy_receipt = self.create_receipt(prepared, policy, "policyCandidateSHA256")
        result = renderer.adopt(prepared, source, policy, journal, self.tenant,
                                self.console, self.service, self.base(), self.image_receipt(prepared), self.recipe_dir,
                                policy_receipt, journal_receipt)
        p = {name: json.loads(raw) for name, raw in result.items()}
        dep = p["deployment.candidate.json"]
        guard = next(row for row in dep["spec"]["template"]["spec"]["containers"] if row["name"] == "guardrail")
        self.assertEqual(guard["command"], ["python3", "-B", "/src/dual_server.py"])
        self.assertEqual(guard["args"], [])
        self.assertEqual({row["subPath"] for row in guard["volumeMounts"] if row["name"] == "guardrail-src"}, set(renderer.FILES))
        self.assertTrue(all(row["readOnly"] for row in guard["volumeMounts"]))
        self.assertEqual(dep["spec"]["template"]["spec"]["serviceAccountName"], renderer.PROXY_SA)
        self.assertFalse(dep["spec"]["template"]["spec"]["automountServiceAccountToken"])
        self.assertEqual(dep["spec"]["template"]["spec"]["securityContext"]["fsGroup"], 10001)
        self.assertEqual(guard["securityContext"]["runAsUser"], 10001)
        self.assertEqual(dep["spec"]["template"]["spec"]["initContainers"][0]["securityContext"]["runAsUser"], 10001)
        self.assertEqual(dep["spec"]["template"]["spec"]["initContainers"][0]["command"],
                         ["python3", "-B", "/src/drain_v11_init.py"])
        self.assertIn("endpoint-lease-api-auth", {row["name"] for row in guard["volumeMounts"]})
        self.assertNotIn("endpoint-lease-api-auth", {row["name"] for row in
                         dep["spec"]["template"]["spec"]["containers"][0].get("volumeMounts", [])})
        self.assertEqual(set(p["proxy-role.json"]["rules"][0]["verbs"]), {"get"})
        self.assertEqual(p["proxy-role.json"]["rules"][1]["resourceNames"], [renderer.TENANT_SECRET])
        self.assertEqual(p["ADOPTION.json"]["journalUID"], U["journal"])
        self.assertEqual(p["ADOPTION.json"]["engineImage"], renderer.APPROVED_ENGINE_IMAGE)
        self.assertEqual(p["ADOPTION.json"]["eventCreator"],
                         "system:serviceaccount:phorvex-system:phorvex-phorvex-console")
        self.assertEqual(p["ADOPTION.json"]["drainProxySourceSHA256"],
                         renderer.sha(source["data"]["guardrail_proxy.py"].encode()))
        self.assertEqual(dep["spec"]["template"]["metadata"]["annotations"]["phorvex.ai/drain-proxy-source"],
                         p["ADOPTION.json"]["drainProxySourceSHA256"])
        self.assertNotIn("client-a", result["ADOPTION.json"].decode())
        for bad in ("policy", "journal", "source"):
            inputs = [prepared, source, policy, journal, self.tenant, self.console, self.service]
            index = {"source": 1, "policy": 2, "journal": 3}[bad]
            inputs[index] = copy.deepcopy(inputs[index])
            inputs[index]["metadata"]["uid"] = U["tenant"]
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                renderer.adopt(*inputs, self.base(), self.image_receipt(prepared), self.recipe_dir,
                               policy_receipt, journal_receipt)
        bad_image = self.image_receipt(prepared)
        bad_image["recipeSHA256"]["Dockerfile"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "recipe SHA"):
            renderer.adopt(prepared, source, policy, journal, self.tenant,
                           self.console, self.service, self.base(), bad_image, self.recipe_dir,
                           policy_receipt, journal_receipt)
        wrong_receipt = copy.deepcopy(policy_receipt)
        wrong_receipt["requestSHA256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "create receipt"):
            renderer.adopt(prepared, source, policy, journal, self.tenant,
                           self.console, self.service, self.base(), self.image_receipt(prepared), self.recipe_dir,
                           wrong_receipt, journal_receipt)
        late_journal = copy.deepcopy(journal_receipt)
        late_journal["completedAt"] = policy_receipt["completedAt"]
        with self.assertRaisesRegex(ValueError, "journal must be created before"):
            renderer.adopt(prepared, source, policy, journal, self.tenant,
                           self.console, self.service, self.base(), self.image_receipt(prepared), self.recipe_dir,
                           policy_receipt, late_journal)
        shared_volume = self.base()
        shared_volume["deployment.candidate.json"]["spec"]["template"]["spec"]["volumes"].append(
            {"name": "shared-model", "persistentVolumeClaim": {"claimName": "business-model"}})
        with self.assertRaisesRegex(ValueError, "shared or unreviewed Pod volume"):
            renderer.adopt(prepared, source, policy, journal, self.tenant,
                           self.console, self.service, shared_volume, self.image_receipt(prepared), self.recipe_dir,
                           policy_receipt, journal_receipt)
        for field, value in (("image", "phorvex@sha256:" + "a" * 64),
                             ("args", ["--port", "8000", "--host", "0.0.0.0"])):
            wrong_engine = self.base()
            wrong_engine["deployment.candidate.json"]["spec"]["template"]["spec"]["containers"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "engine"):
                renderer.adopt(prepared, source, policy, journal, self.tenant,
                               self.console, self.service, wrong_engine, self.image_receipt(prepared), self.recipe_dir,
                               policy_receipt, journal_receipt)
        wrong_key = self.base()
        wrong_key["deployment.candidate.json"]["spec"]["template"]["spec"]["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]["name"] = "other-key"
        with self.assertRaisesRegex(ValueError, "engine loopback or API key"):
            renderer.adopt(prepared, source, policy, journal, self.tenant,
                           self.console, self.service, wrong_key, self.image_receipt(prepared), self.recipe_dir,
                           policy_receipt, journal_receipt)


if __name__ == "__main__":
    unittest.main()
