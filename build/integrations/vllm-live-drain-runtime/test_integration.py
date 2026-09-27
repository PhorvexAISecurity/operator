import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("drain_review_renderer", HERE / "render.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class CandidateTest(unittest.TestCase):
    def publication(self):
        source = "a" * 40
        tag = f"753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-drain-v11-{source}"
        digest = "sha256:" + "b" * 64
        manifest = json.loads((renderer.RECIPE / "manifest.json").read_bytes())
        return {"schemaVersion": 1, "sourceSHA": source, "image": tag,
                "digest": digest, "imageByDigest": tag.split(":vllm-drain-v11-", 1)[0] + "@" + digest,
                "platform": "linux/amd64", "baseImage": manifest["base_image"],
                "recipeSHA256": {name: renderer.sha((renderer.RECIPE / name).read_bytes())
                                    for name in renderer.RECIPE_FILES}}

    def inputs(self):
        dep = {"kind": "Deployment", "metadata": {"name": "vllm", "namespace": "vllm", "uid": "deployment-uid", "resourceVersion": "7"},
               "spec": {"template": {"metadata": {"labels": {"app": "vllm", "phorvex.ai/role": "leader"},
                                                   "annotations": {}},
                                     "spec": {"containers": [{"name": "vllm", "image": "reset-image", "args": ["--model", "Qwen/Qwen2.5-7B-Instruct-AWQ"]},
                                                             {"name": "guardrail", "image": "python:3.11-slim", "env": []}],
                                              "volumes": []}}}}
        cm = {"kind": "ConfigMap", "metadata": {"name": "guardrail-proxy", "namespace": "vllm", "uid": "configmap-uid", "resourceVersion": "7"},
              "data": {"guardrail_proxy.py": "proxy", "dual_server.py": "boundary"}}
        policy = {"metadata": {"name": "vllm-defense", "namespace": "vllm", "uid": "policy-uid", "resourceVersion": "7"}}
        svc = {"kind": "Service", "metadata": {"name": "vllm", "namespace": "vllm", "uid": "service-uid", "resourceVersion": "7"},
               "spec": {"selector": {"phorvex.ai/role": "leader"},
                        "ports": [{"port": 8000, "targetPort": 8000}]}}
        return dep, cm, policy, svc

    def render(self, dep, cm, policy, svc, receipt):
        class Base:
            PUBLISHED_IMAGE = "reset-image"
            @staticmethod
            def render(deployment, configmap, _policy, image, *_):
                assert image == "reset-image"
                return {"deployment.candidate.json": json.dumps(deployment).encode(),
                        "configmap.candidate.json": json.dumps(configmap).encode(),
                        "values.overlay.yaml": json.dumps({"phorvex": {"phorvex": {"servingSecurity": {
                            "bindings": [{"profileID": "vllm-reset-ack-v1"}]}}}}).encode(),
                        "secret-contract.json": b'{"credentialBytesIncluded":false}'}
        with mock.patch.object(renderer, "base_renderer", return_value=Base):
            return renderer.render(dep, cm, policy, svc, receipt, "vllm-control", "vllm-serving-admin",
                                   "vllm-admin.vllm.svc", "b25037543e9394b818fdfca67ab2a00ecc7dd641",
                                   "ec0c1f5f875ad8bc1f78c5140c22dbdde1b55478442ad358e7a4d9ecf947a327")

    def test_current_service_selector_and_ledger_are_bound(self):
        dep, cm, policy, svc = self.inputs()
        publication = self.publication()
        outputs = self.render(dep, cm, policy, svc, publication)
        candidate = json.loads(outputs["deployment.candidate.json"])
        service = json.loads(outputs["service.candidate.json"])
        source = json.loads(outputs["configmap.candidate.json"])
        spec = candidate["spec"]["template"]["spec"]
        labels = candidate["spec"]["template"]["metadata"]["labels"]
        self.assertEqual(labels["phorvex.ai/serving"], "true")
        self.assertEqual(service["spec"]["selector"], {"phorvex.ai/role": "leader", "phorvex.ai/serving": "true"})
        self.assertEqual(spec["containers"][0]["image"], publication["imageByDigest"])
        self.assertEqual(spec["containers"][0]["args"][-4:], ["--revision", "b25037543e9394b818fdfca67ab2a00ecc7dd641", "--tokenizer-revision", "b25037543e9394b818fdfca67ab2a00ecc7dd641"])
        self.assertEqual(spec["initContainers"][0]["command"], ["python", "/src/drain_v11_init.py"])
        self.assertEqual(spec["volumes"][-1], {"name": "phorvex-drain-ledger", "emptyDir": {}})
        self.assertIn("drain_v11.py", source["data"])
        self.assertIn("drain_v11_init.py", source["data"])
        self.assertEqual(json.loads(outputs["values.overlay.yaml"])["phorvex"]["phorvex"]["servingSecurity"]["bindings"][0]["profileID"], "vllm-drain-v11")
        self.assertNotIn("api-key-value", b"".join(outputs.values()).decode())

    def test_publication_recipe_drift_and_wrong_service_refused(self):
        dep, cm, policy, svc = self.inputs()
        good = self.publication()
        for mutate in (lambda r: r.update(platform="linux/arm64"),
                       lambda r: r["recipeSHA256"].update(Dockerfile="0" * 64),
                       lambda r: r.update(imageByDigest="other@sha256:" + "b" * 64)):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.assertRaises(ValueError):
                renderer.published_image(bad)
        svc["spec"]["selector"] = {"phorvex.ai/role": "follower"}
        with self.assertRaises(ValueError):
            self.render(dep, cm, policy, svc, good)
        svc["spec"]["selector"] = {"phorvex.ai/role": "leader"}
        svc["metadata"]["uid"] = ""
        with self.assertRaises(ValueError):
            self.render(dep, cm, policy, svc, good)

    def test_initializer_runs_without_http_dependency(self):
        import subprocess
        script = "import sys,tempfile;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from drain_v11 import initialize_ledger,Ledger;d=Path(tempfile.mkdtemp())/'ledger';initialize_ledger(d,'pod-uid','a'*32);assert Ledger(d,'pod-uid').ledger_id=='a'*32"
        result = subprocess.run(["python3", "-S", "-c", script, str(renderer.GUARDRAIL)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr[:500])


if __name__ == "__main__":
    unittest.main()
