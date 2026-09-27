"""No-cluster tests for exact read-only vLLM rollout preparation."""

import json
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import prepare


class PrepareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "calls.jsonl"
        self.data = self.root / "objects.json"
        self.kubectl = self.root / "kubectl"
        self.kubectl.write_text("""#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['FAKE_KUBE_LOG']).open('a') as log: log.write(json.dumps(args)+'\\n')
if len(args)<7 or args[:2]!=['--context','reviewed-dev'] or args.count('get')!=1 or args[-2:]!=['-o','json'] or 'secret' in ' '.join(args).lower(): sys.exit(4)
key=' '.join(args[args.index('get')+1:-2])
obj=json.loads(Path(os.environ['FAKE_KUBE_DATA']).read_text()).get(key)
if obj is None: sys.exit(5)
if key=='pod vllm-1' and os.environ.get('FAKE_KUBE_POD_REREAD')=='changed':
    calls=[json.loads(line) for line in Path(os.environ['FAKE_KUBE_LOG']).read_text().splitlines()]
    if sum(' '.join(row[row.index('get')+1:-2])==key for row in calls)>=2:
        obj['metadata']['resourceVersion']='8'
print(json.dumps(obj,separators=(',',':')))
""")
        self.kubectl.chmod(self.kubectl.stat().st_mode | stat.S_IXUSR)
        self.env = mock.patch.dict(os.environ, FAKE_KUBE_LOG=str(self.log), FAKE_KUBE_DATA=str(self.data))
        self.env.start()
        self.addCleanup(self.env.stop)
        self.objects = self.fixture()
        self.data.write_text(json.dumps(self.objects))
        self.receipt = self.root / "publication.json"
        self.source = "a" * 40
        tag = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:vllm-drain-v11-" + self.source
        self.image = tag.split(":vllm-drain-v11-", 1)[0] + "@sha256:" + "b" * 64
        manifest = json.loads((prepare.drain_render.RECIPE / "manifest.json").read_bytes())
        publication = {"schemaVersion": 1, "sourceSHA": self.source, "image": tag,
                       "digest": "sha256:" + "b" * 64, "imageByDigest": self.image,
                       "platform": "linux/amd64", "baseImage": manifest["base_image"],
                       "recipeSHA256": {name: prepare.sha((prepare.drain_render.RECIPE / name).read_bytes())
                                        for name in prepare.drain_render.RECIPE_FILES}}
        self.receipt.write_bytes(json.dumps(publication, sort_keys=True).encode())
        self.pins = mock.patch.multiple(prepare,
            PUBLISHED_RECEIPT_SHA256=prepare.sha(self.receipt.read_bytes()),
            PUBLISHED_SOURCE=self.source, PUBLISHED_IMAGE=self.image)
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def fixture(self):
        meta = lambda kind, name, uid: {"kind": kind, "metadata": {"name": name, "namespace": "vllm",
                                                       "uid": uid, "resourceVersion": "7"}}
        dep = meta("Deployment", "vllm", "deployment-uid")
        dep["spec"] = {"selector": {"matchLabels": {"app": "vllm"}},
                       "template": {"metadata": {"labels": {"app": "vllm", "phorvex.ai/role": "leader"}},
                                    "spec": {"containers": [{"name": "vllm", "image": "reset-image"},
                                                            {"name": "guardrail", "image": "python:3.11-slim"}],
                                             "volumes": [{"name": "guardrail-src", "configMap": {"name": "guardrail-proxy"}}]}}}
        cm = meta("ConfigMap", "guardrail-proxy", "source-uid")
        policy = meta("PhorvexPolicy", "vllm-defense", "policy-uid")
        service = meta("Service", "vllm", "service-uid")
        service["spec"] = {"selector": {"phorvex.ai/role": "leader"}}
        pod = meta("Pod", "vllm-1", "pod-uid")
        pod["metadata"]["labels"] = {"app": "vllm", "phorvex.ai/role": "leader"}
        pod["metadata"]["ownerReferences"] = [{"controller": True, "kind": "ReplicaSet", "name": "vllm-rs", "uid": "rs-uid"}]
        pod["spec"] = copy.deepcopy(dep["spec"]["template"]["spec"])
        pod["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
        rs = meta("ReplicaSet", "vllm-rs", "rs-uid")
        rs["metadata"]["ownerReferences"] = [{"controller": True, "kind": "Deployment", "name": "vllm", "uid": "deployment-uid"}]
        sl = meta("EndpointSlice", "vllm-slice", "slice-uid")
        sl["metadata"]["labels"] = {"kubernetes.io/service-name": "vllm"}
        sl["metadata"]["ownerReferences"] = [{"controller": True, "kind": "Service", "name": "vllm", "uid": "service-uid"}]
        sl["endpoints"] = [{"conditions": {"ready": True}, "targetRef":
                           {"kind": "Pod", "namespace": "vllm", "name": "vllm-1", "uid": "pod-uid"}}]
        namespace = {"kind": "Namespace", "metadata": {"name": "vllm", "uid": "ns-uid", "resourceVersion": "7"}}
        return {"namespace vllm": namespace, "deployment vllm": dep,
                "configmap guardrail-proxy": cm, "phorvexpolicy vllm-defense": policy,
                "service vllm": service, "pods -l app=vllm": {"kind": "PodList", "items": [pod]},
                "pod vllm-1": pod, "replicaset vllm-rs": rs,
                "endpointslices -l kubernetes.io/service-name=vllm": {"kind": "List", "items": [sl]}}

    def test_exact_get_protocol_and_private_candidate(self):
        seen = []
        def renderer(*args):
            seen.append(args)
            self.assertEqual(args[0]["metadata"]["uid"], "deployment-uid")
            self.assertIsNone(args[-1], "template-aligned route must not pass Pod-only mismatch evidence")
            return {"deployment.candidate.json": b'{"reviewOnly":true}',
                    "secret-contract.json": b'{"secretBytesIncluded":false}'}
        out = self.root / "review"
        with mock.patch.object(prepare.drain_render, "render", side_effect=renderer):
            manifest = prepare.prepare("reviewed-dev", out, self.receipt, str(self.kubectl))
        calls = [json.loads(row) for row in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 14)
        self.assertTrue(all(row[0:2] == ["--context", "reviewed-dev"] and row.count("get") == 1 for row in calls))
        self.assertTrue(all("secret" not in " ".join(row).lower() and "exec" not in row for row in calls))
        self.assertEqual(manifest["status"], "REVIEW_ONLY")
        self.assertEqual(len(manifest["originals"]), 9)
        self.assertEqual(len(seen), 1)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((out / "original-current-pod.json").stat().st_mode), 0o600)
        self.assertEqual(prepare.sha((out / "publication.json").read_bytes()), manifest["publicationReceiptSHA256"])

    def test_template_aligned_service_reaches_real_drain_renderer(self):
        dep = self.objects["deployment vllm"]
        dep["spec"]["template"]["spec"] = {"containers": [
            {"name": "vllm", "image": "reset-image", "args": ["--model", "Qwen/Qwen2.5-7B-Instruct-AWQ"]},
            {"name": "guardrail", "image": "python:3.11-slim", "env": []}],
            "volumes": [{"name": "guardrail-src", "configMap": {"name": "guardrail-proxy"}}]}
        cm = self.objects["configmap guardrail-proxy"]
        cm["data"] = {"guardrail_proxy.py": "public proxy", "dual_server.py": "private control"}
        self.objects["service vllm"]["spec"]["ports"] = [{"port": 8000, "targetPort": 8000}]
        self.data.write_text(json.dumps(self.objects))
        class Base:
            PUBLISHED_IMAGE = "reset-image"
            @staticmethod
            def render(deployment, configmap, _policy, image, *_):
                if image != "reset-image":
                    raise ValueError("unexpected base image")
                return {"deployment.candidate.json": json.dumps(copy.deepcopy(deployment)).encode(),
                        "configmap.candidate.json": json.dumps(copy.deepcopy(configmap)).encode(),
                        "values.overlay.yaml": json.dumps({"phorvex": {"phorvex": {"servingSecurity": {
                            "bindings": [{"profileID": "vllm-reset-ack-v1"}]}}}}).encode(),
                        "secret-contract.json": b'{"credentialBytesIncluded":false}'}
        out = self.root / "real-render"
        with mock.patch.object(prepare.drain_render, "base_renderer", return_value=Base):
            manifest = prepare.prepare("reviewed-dev", out, self.receipt, str(self.kubectl))
        candidate = json.loads((out / "deployment.candidate.json").read_bytes())
        join = json.loads((out / "publication-join.json").read_bytes())
        self.assertEqual(candidate["spec"]["template"]["spec"]["containers"][0]["image"], self.image)
        self.assertNotIn("currentRouteAuthority", join)
        self.assertEqual(len(manifest["candidates"]), 6)

    def test_reviewed_pod_only_route_key_passes_route_originals(self):
        route = "current-route"
        self.objects["service vllm"]["spec"]["selector"]["phorvex.ai/route-key"] = route
        for key in ("pods -l app=vllm", "pod vllm-1"):
            pod = self.objects[key]["items"][0] if key.startswith("pods") else self.objects[key]
            pod["metadata"]["labels"]["phorvex.ai/route-key"] = route
        self.data.write_text(json.dumps(self.objects))
        seen = []
        with mock.patch.object(prepare.drain_render, "render", side_effect=lambda *args: (seen.append(args[-1]) or {"candidate.json": b"{}"})):
            prepare.prepare("reviewed-dev", self.root / "route-key", self.receipt, str(self.kubectl))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0]["metadata"]["uid"], "pod-uid")
        self.assertEqual(seen[0][1]["metadata"]["uid"], "rs-uid")

    def test_unsafe_context_existing_output_and_wrong_publication_do_not_read_cluster(self):
        with self.assertRaises(ValueError):
            prepare.prepare("--other", self.root / "unsafe", self.receipt, str(self.kubectl))
        with self.assertRaises(FileExistsError):
            prepare.prepare("reviewed-dev", self.root, self.receipt, str(self.kubectl))
        self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "artifact SHA"):
            prepare.prepare("reviewed-dev", self.root / "wrong-publication", self.receipt, str(self.kubectl))
        self.assertFalse(self.log.exists())

    def test_get_error_or_ambiguous_owner_leaves_no_candidate(self):
        out = self.root / "ambiguous"
        self.objects["pods -l app=vllm"]["items"].append(self.objects["pod vllm-1"])
        self.data.write_text(json.dumps(self.objects))
        with self.assertRaisesRegex(ValueError, "one current selected Pod"):
            prepare.prepare("reviewed-dev", out, self.receipt, str(self.kubectl))
        self.assertFalse(out.exists())
        self.objects["pods -l app=vllm"]["items"].pop()
        self.objects.pop("endpointslices -l kubernetes.io/service-name=vllm")
        self.data.write_text(json.dumps(self.objects))
        with self.assertRaisesRegex(ValueError, "bounded kubectl GET failed"):
            prepare.prepare("reviewed-dev", out, self.receipt, str(self.kubectl))
        self.assertFalse(out.exists())

    def test_foreign_owner_or_endpoint_cannot_reach_renderer(self):
        for mutate in (
            lambda objects: objects["replicaset vllm-rs"]["metadata"]["ownerReferences"][0].update(uid="foreign-deployment"),
            lambda objects: objects["endpointslices -l kubernetes.io/service-name=vllm"]["items"][0]["endpoints"][0]["targetRef"].update(uid="foreign-pod"),
            lambda objects: objects["pod vllm-1"]["spec"]["containers"][0].update(image="older-vllm-image"),
            lambda objects: objects["pod vllm-1"]["spec"]["volumes"][0]["configMap"].update(name="foreign-source"),
        ):
            objects = self.fixture()
            mutate(objects)
            self.data.write_text(json.dumps(objects))
            out = self.root / "foreign"
            with mock.patch.object(prepare.drain_render, "render") as renderer:
                with self.assertRaises(ValueError):
                    prepare.prepare("reviewed-dev", out, self.receipt, str(self.kubectl))
                renderer.assert_not_called()
            self.assertFalse(out.exists())

    def test_contradictory_ready_route_and_interleaved_pod_change_refuse(self):
        for contradiction in ({"terminating": True}, {"serving": False}):
            objects = self.fixture()
            conditions = objects["endpointslices -l kubernetes.io/service-name=vllm"]["items"][0]["endpoints"][0]["conditions"]
            conditions.update(contradiction)
            self.data.write_text(json.dumps(objects))
            with self.assertRaisesRegex(ValueError, "contradictory Ready"):
                prepare.prepare("reviewed-dev", self.root / "contradictory", self.receipt, str(self.kubectl))
            self.assertFalse((self.root / "contradictory").exists())
        objects = self.fixture()
        objects["service vllm"]["spec"]["selector"]["other-label"] = "wrong"
        objects["pod vllm-1"]["metadata"]["labels"]["other-label"] = "wrong"
        objects["pods -l app=vllm"]["items"][0]["metadata"]["labels"]["other-label"] = "wrong"
        self.data.write_text(json.dumps(objects))
        with self.assertRaisesRegex(ValueError, "unreviewed current Service selector mismatch"):
            prepare.prepare("reviewed-dev", self.root / "other-mismatch", self.receipt, str(self.kubectl))
        self.assertFalse((self.root / "other-mismatch").exists())
        self.data.write_text(json.dumps(self.fixture()))
        self.log.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, FAKE_KUBE_POD_REREAD="changed"):
            with self.assertRaisesRegex(ValueError, "current Pod changed"):
                prepare.prepare("reviewed-dev", self.root / "pod-changed", self.receipt, str(self.kubectl))
        self.assertFalse((self.root / "pod-changed").exists())


if __name__ == "__main__":
    unittest.main()
