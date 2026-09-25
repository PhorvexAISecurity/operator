"""Offline .166 Mongo package controls using synthetic original-format receipts.

No Kubernetes originals, credentials, or live calls are included in this fixture.
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

if __package__:
    from . import package_fixed_catalogue_profiles as pack
else:
    import package_fixed_catalogue_profiles as pack


SOURCE = "0316a578624a1d19662c87bfa8d0fea08d1b3729"
RELEASE = "24c6e0965a6958d5dc353393b3441bbd0c92cdc9"
CLUSTER = "11111111-1111-4111-8111-111111111111"
NODE = "ip-172-27-11-9.us-east-2.compute.internal"
PREFIX = "753556437180.dkr.ecr.us-east-2.amazonaws.com/"
MANAGER = PREFIX + "phorvex@sha256:" + "b" * 64
CONSOLE = PREFIX + "phorvex-console@sha256:" + "c" * 64
MONGO = "docker.io/library/mongo@sha256:" + "a" * 64
UIDS = {
    "manager-deploy": "22222222-2222-4222-8222-222222222222",
    "manager-rs": "33333333-3333-4333-8333-333333333333",
    "manager-pod": "44444444-4444-4444-8444-444444444444",
    "console-deploy": "55555555-5555-4555-8555-555555555555",
    "console-rs": "66666666-6666-4666-8666-666666666666",
    "console-pod": "77777777-7777-4777-8777-777777777777",
    "mongo-pod": "88888888-8888-4888-8888-888888888888",
    "mongo-service": "99999999-9999-4999-8999-999999999999",
    "mongo-pvc": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "mongo-policy": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "document-store": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "node": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Mongo166OriginalEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input"
        self.evidence = self.source / "evidence"
        (self.evidence / "mongo").mkdir(parents=True)
        self.pins = {}
        self.make_fixture()

    def write(self, relative, value):
        path = self.source / relative
        raw = value if isinstance(value, bytes) else json_bytes(value)
        path.write_bytes(raw)
        return raw

    def pin(self, key, relative):
        self.pins[key] = pack.digest((self.source / relative).read_bytes())

    def arguments(self):
        return SimpleNamespace(input=self.source, overlay="values-overlay.reviewed.yaml",
                               profile=["mongo"], namespace="phorvex-system",
                               allow_enabled=True, output=self.root / "output",
                               expect_mongo166_source_sha256=self.pins["source"],
                               expect_mongo166_review_sha256=self.pins["review"],
                               expect_mongo166_rollout_sha256=self.pins["rollout"],
                               expect_mongo166_target_sha256=self.pins["target"],
                               expect_mongo166_node_sha256=self.pins["node"])

    def make_fixture(self):
        template = (Path(__file__).resolve().parents[1] /
                    "build/test-harness/config.mongo-exposure-baseline.yaml").read_text()
        profile = (template.replace("__SET_LOGICAL_CLUSTER_TARGET__", "synthetic-reviewed-context")
                   .replace("__SET_KUBE_SYSTEM_UID__", CLUSTER)
                   .replace("__SET_MONGO_IMAGE_DIGEST__", MONGO)
                   .replace("__SET_MANAGER_IMAGE_DIGEST__", MANAGER)
                   .replace("__SET_REVIEWED_CPU_NODE_NAME__", NODE))
        self.write("config.mongo-exposure-baseline.yaml", profile.encode())
        overlay = {"phorvex": {"phorvex": {"image": {"tag": "0.4.166"},
                    "console": {"image": {"tag": "0.4.166"}, "mongoExposure": {
                        "enabled": True, "configMapName": "", "profileSHA256": ""}}}}}
        self.write("values-overlay.reviewed.yaml", yaml.safe_dump(overlay).encode())

        jobs = {}
        for component, image, digest in (("manager", "phorvex", "b" * 64),
                                          ("console", "phorvex-console", "c" * 64)):
            log = (f"pushing manifest for {PREFIX}{image}:sha-{SOURCE}@sha256:{digest} 0.6s done\n").encode()
            self.write(f"evidence/{component}-build.original", log)
            jobs[component] = {"conclusion": "success", "sourceTag": "sha-" + SOURCE,
                               "manifestListDigest": digest, "logSHA256": pack.digest(log),
                               "logBytes": len(log)}
        build = {"schema": "catalogue-release-0.4.166-source-build-v1",
                 "releaseCommit": RELEASE, "releaseParentBuildSource": SOURCE,
                 "run": {"conclusion": "success", "headSHA": SOURCE, "jobs": jobs}}
        self.write("evidence/SOURCE-BUILD-166.json", build)
        self.pin("source", "evidence/SOURCE-BUILD-166.json")
        review = {"approved": True, "sourceCommit": SOURCE,
                  "buildEvidenceSHA256": self.pins["source"], "managerImageID": MANAGER,
                  "consoleImageID": CONSOLE,
                  "components": {c: {"logSHA256": jobs[c]["logSHA256"]}
                                 for c in ("manager", "console")}}
        self.write("evidence/source-review.json", review)
        self.pin("review", "evidence/source-review.json")

        after = {"after-cluster.json": {"metadata": {"uid": CLUSTER}},
                 "after-projection.json": {"clusterUID": CLUSTER, "sourceCommit": SOURCE}}
        for component, image in (("manager", MANAGER), ("console", CONSOLE)):
            name = "phorvex-phorvex" + ("-console" if component == "console" else "")
            after[f"after-{component}-deploy.json"] = {
                "metadata": {"name": name, "namespace": "phorvex-system",
                             "uid": UIDS[component + "-deploy"], "generation": 1},
                "spec": {"replicas": 1, "template": {"spec": {"containers": [{
                    "image": PREFIX + ("phorvex" if component == "manager" else "phorvex-console") + ":0.4.166"}]}}},
                "status": {"readyReplicas": 1, "observedGeneration": 1}}
            after[f"after-{component}-rs.json"] = {
                "kind": "ReplicaSet", "metadata": {"namespace": "phorvex-system",
                    "uid": UIDS[component + "-rs"], "ownerReferences": [{
                        "kind": "Deployment", "uid": UIDS[component + "-deploy"]}]},
                "spec": {"replicas": 1}, "status": {"readyReplicas": 1}}
            after[f"after-{component}-pods.json"] = {"items": [{
                "metadata": {"namespace": "phorvex-system", "uid": UIDS[component + "-pod"],
                    "ownerReferences": [{"kind": "ReplicaSet", "uid": UIDS[component + "-rs"]}]},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                           "containerStatuses": [{"imageID": image, "ready": True}]}}]}
            after["after-projection.json"][component + "PodUID"] = UIDS[component + "-pod"]
            after["after-projection.json"][component + "ImageID"] = image
            after["after-projection.json"][component + "Deployment"] = {"uid": UIDS[component + "-deploy"]}
        receipts = []
        for name, body in after.items():
            raw = self.write("evidence/" + name, body)
            receipts.append({"file": name, "sha256": pack.digest(raw), "bytes": len(raw)})
        self.write("evidence/CPU-TERMINAL.json", {"schema": "cpu-console-once-v1",
                   "consolePOSTs": 0, "postSourceComparison": "STABLE", "forwardClose": "CONFIRMED",
                   "receipts": receipts})
        self.pin("rollout", "evidence/CPU-TERMINAL.json")

        ready = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
        targets = {
            "kube-system-namespace": {"metadata": {"uid": CLUSTER}},
            "document-store-namespace": {"metadata": {"name": "document-store", "uid": UIDS["document-store"]}},
            "mongo-deployment": {"metadata": {"name": "mongo", "generation": 1},
                                 "spec": {"replicas": 1}, "status": {"readyReplicas": 1, "observedGeneration": 1}},
            "mongo-pods": {"items": [{"metadata": {"uid": UIDS["mongo-pod"]},
                                      "status": {**ready, "containerStatuses": [{"imageID": MONGO, "ready": True}]}}]},
            "manager-deployment": {}, "manager-pods": {}, "console-deployment": {}, "console-pods": {},
            "mongo-service": {"metadata": {"name": "mongo", "uid": UIDS["mongo-service"]},
                              "spec": {"selector": {"app": "mongo"}, "ports": [{"port": 27017}]}},
            "mongo-endpointslices": {"items": [{"metadata": {"ownerReferences": [{"uid": UIDS["mongo-service"]}]},
                "endpoints": [{"targetRef": {"uid": UIDS["mongo-pod"]}, "conditions": {"ready": True}}]}]},
            "mongo-pvc": {"metadata": {"uid": UIDS["mongo-pvc"]}, "status": {"phase": "Bound"}},
            "mongo-policy": {"metadata": {"name": "mongo-defense", "uid": UIDS["mongo-policy"],
                                           "generation": 1}, "spec": {"tenant": "mongo", "mode": "active",
                    "selector": {"matchLabels": {"app": "mongo"}}, "triggers": {"reactiveOnly": True}}},
            "mongo-cpu-node": {},
        }
        receipt_rows = []
        for index, (label, body) in enumerate(targets.items(), 1):
            name = f"{index:02d}-{label}.original.json"
            raw = self.write("evidence/mongo/" + name, body)
            receipt_rows.append({"label": label, "originalFile": name,
                                 "argv": ["--context=synthetic-reviewed-context", "get", label, "-o", "json"],
                                 "dispatchCount": 1, "exitCode": 0,
                                 "stdoutSHA256": pack.digest(raw), "stdoutBytes": len(raw)})
        self.write("evidence/mongo/RECEIPT.json", {
            "status": "READ_ONLY_CURRENT_PROJECTION", "callCount": len(receipt_rows),
            "context": "synthetic-reviewed-context", "projection": {"clusterUID": CLUSTER},
            "receipts": receipt_rows})
        self.pin("target", "evidence/mongo/RECEIPT.json")
        node = {"metadata": {"name": NODE, "uid": UIDS["node"]}, "spec": {"unschedulable": False},
                "status": {"allocatable": {"cpu": "2", "memory": "4Gi", "pods": "20"},
                           "conditions": [{"type": "Ready", "status": "True"}]}}
        raw = self.write("evidence/mongo/17-eligible-node.original.json", node)
        self.write("evidence/mongo/ELIGIBLE-NODES.json", {"status": "READ_ONLY_COMPLETE", "rows": [{
            "name": NODE, "uid": UIDS["node"], "stdoutSHA256": pack.digest(raw)}]})
        self.pin("node", "evidence/mongo/ELIGIBLE-NODES.json")

    def test_original_format_package_and_exact_configmap_bytes(self):
        result = pack.package(self.arguments())
        profile = (self.source / "config.mongo-exposure-baseline.yaml").read_bytes()
        item = result["profiles"]["mongo"]
        self.assertEqual(result["evidenceSchema"], "mongo-166-originals-v1")
        self.assertEqual(item["sha256"], pack.digest(profile))
        self.assertEqual(item["configMapName"], "phorvex-catalogue-mongo-" + pack.digest(profile)[:12])
        maps = list(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(len(maps), 1)
        self.assertTrue(maps[0]["immutable"])
        self.assertEqual(maps[0]["data"]["config.mongo-exposure-baseline.yaml"].encode(), profile)
        self.assertEqual((self.root / "output/evidence/mongo/RECEIPT.json").read_bytes(),
                         (self.evidence / "mongo/RECEIPT.json").read_bytes())

    def test_original_bytes_and_independent_pin_tampering_refuse(self):
        path = self.evidence / "mongo/10-mongo-endpointslices.original.json"
        path.write_bytes(path.read_bytes().replace(b'"ready":true', b'"ready":false'))
        with self.assertRaisesRegex(ValueError, "original GET bytes differ"):
            pack.package(self.arguments())
        self.assertFalse((self.root / "output").exists())

    def test_build_log_change_refuses_without_rewritten_source_proof(self):
        path = self.evidence / "manager-build.original"
        path.write_bytes(path.read_bytes() + b"changed\n")
        with self.assertRaisesRegex(ValueError, "original build push/image differs"):
            pack.package(self.arguments())

    def test_semantic_node_and_image_drift_refuse_even_with_rehashed_receipts(self):
        node_path = self.evidence / "mongo/17-eligible-node.original.json"
        node = json.loads(node_path.read_bytes())
        node["spec"]["taints"] = [{"key": "reserved", "effect": "NoSchedule"}]
        raw = self.write("evidence/mongo/17-eligible-node.original.json", node)
        receipt = json.loads((self.evidence / "mongo/ELIGIBLE-NODES.json").read_bytes())
        receipt["rows"][0]["stdoutSHA256"] = pack.digest(raw)
        self.write("evidence/mongo/ELIGIBLE-NODES.json", receipt)
        self.pin("node", "evidence/mongo/ELIGIBLE-NODES.json")
        with self.assertRaisesRegex(ValueError, "CPU node or manager image differs"):
            pack.package(self.arguments())
        node["spec"].pop("taints")
        raw = self.write("evidence/mongo/17-eligible-node.original.json", node)
        receipt["rows"][0]["stdoutSHA256"] = pack.digest(raw)
        self.write("evidence/mongo/ELIGIBLE-NODES.json", receipt)
        self.pin("node", "evidence/mongo/ELIGIBLE-NODES.json")
        path = self.evidence / "after-manager-pods.json"
        body = json.loads(path.read_bytes())
        body["items"][0]["status"]["containerStatuses"][0]["imageID"] = MONGO
        raw = self.write("evidence/after-manager-pods.json", body)
        terminal = json.loads((self.evidence / "CPU-TERMINAL.json").read_bytes())
        next(row for row in terminal["receipts"] if row["file"] == path.name).update(
            sha256=pack.digest(raw), bytes=len(raw))
        self.write("evidence/CPU-TERMINAL.json", terminal)
        self.pin("rollout", "evidence/CPU-TERMINAL.json")
        with self.assertRaisesRegex(ValueError, "Pod/ReplicaSet/image original differs"):
            pack.package(self.arguments())

    def test_wrong_separately_reviewed_pin_refuses(self):
        self.pins["target"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "target read original SHA differs"):
            pack.package(self.arguments())
