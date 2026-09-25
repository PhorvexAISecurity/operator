"""Release-aware Mongo packaging controls over synthetic .167 original formats."""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

if __package__:
    from . import package_fixed_catalogue_profiles as pack
    from . import test_mongo166_profile_evidence as base
else:
    import package_fixed_catalogue_profiles as pack
    import test_mongo166_profile_evidence as base


SOURCE = "52dfc166efd06e4d0e635a0590cc225e6c985278"
RELEASE = "e081058e0b5daa83cfd3abc364e4532089943d4b"
TAG = "e" * 40


class Mongo167Evidence(unittest.TestCase):
    def setUp(self):
        self.fixture = base.Mongo166OriginalEvidence("test_original_format_package_and_exact_configmap_bytes")
        self.fixture.setUp()
        self.addCleanup(self.fixture.temp.cleanup)
        self.root = self.fixture.root
        self.source = self.fixture.source
        self.evidence = self.fixture.evidence
        self.write = self.fixture.write
        self.pin = self.fixture.pin
        profile_path = self.source / "config.mongo-exposure-baseline.yaml"
        profile_path.write_text(profile_path.read_text().replace("0.4.166", "0.4.167"))
        overlay_path = self.source / "values-overlay.reviewed.yaml"
        overlay_path.write_text(overlay_path.read_text().replace("0.4.166", "0.4.167"))
        self.make_source()
        self.make_rollout()
        self.make_later_target()

    def arguments(self):
        p = self.fixture.pins
        return SimpleNamespace(input=self.source, overlay="values-overlay.reviewed.yaml",
                               profile=["mongo"], namespace="phorvex-system", allow_enabled=True,
                               output=self.root / "output", expect_mongo_current_source_sha256=p["source"],
                               expect_mongo_current_review_sha256=p["review"],
                               expect_mongo_current_rollout_sha256=p["rollout"],
                               expect_mongo_current_target_sha256=p["target"],
                               expect_mongo_current_node_sha256=p["node"])

    def make_source(self):
        prefix = "source-current/"
        names = {"buildRun": "build-run.json", "buildJobs": "build-jobs.json",
                 "releaseCommit": "release-commit.json", "tagObject": "tag-object.json",
                 "tagRef": "tag-ref.json"}
        values = {
            "buildRun": {"id": 1, "head_sha": SOURCE, "conclusion": "success"},
            "buildJobs": {"jobs": [{"id": 2, "name": "build-operator", "conclusion": "success"},
                                    {"id": 3, "name": "build-console", "conclusion": "success"}]},
            "releaseCommit": {"sha": RELEASE, "parents": [{"sha": SOURCE}]},
            "tagObject": {"sha": TAG, "object": {"sha": RELEASE}},
            "tagRef": {"object": {"sha": TAG}},
        }
        metadata = {}
        for label, filename in names.items():
            path = self.evidence / prefix / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = self.write("evidence/" + prefix + filename, values[label])
            metadata[label] = {"file": filename, "SHA256": pack.digest(raw), "bytes": len(raw)}
        builds = {}
        for component, image, uid, job_id in (("manager", "phorvex", base.UIDS["manager-pod"], 2),
                                               ("console", "phorvex-console", base.UIDS["console-pod"], 3)):
            digest = "b" * 64 if component == "manager" else "c" * 64
            filename = "build-operator.log" if component == "manager" else "build-console.log"
            log = (f"pushing manifest for {base.PREFIX}{image}:sha-{SOURCE}@sha256:{digest} 0.6s done\n").encode()
            self.write("evidence/" + prefix + filename, log)
            builds[component] = {"buildLogFile": filename, "buildLogSHA256": pack.digest(log),
                "buildLogBytes": len(log), "buildManifestDigest": "sha256:" + digest,
                "installedImageID": base.PREFIX + image + "@sha256:" + digest,
                "installedDigestEqualsBuild": True, "jobConclusion": "success",
                "jobID": job_id, "podUID": uid, "sourceTag": "sha-" + SOURCE}
        self.build = {"schema": "catalogue-release-0.4.167-source-build-installed-join-v1",
            "releaseCommit": RELEASE, "releaseParentBuildSource": SOURCE,
            "releaseTag": "v0.4.167", "annotatedTagObjectSHA": TAG,
            "buildRun": {"id": 1, "headSHA": SOURCE, "conclusion": "success"},
            "builds": builds, "originalGitHubMetadata": metadata,
            "installedRead": {"argoSyncRevision": RELEASE, "argoSyncStatus": "Synced"}}

    def make_rollout(self):
        projection = {"context": {"context": "synthetic-reviewed-context"},
                      "cluster": {"identity": {"uid": base.CLUSTER}},
                      "stackApplication": {"syncRevision": RELEASE, "syncStatus": "Synced"},
                      "cpuSource": {}, "consoleGrants": {}}
        assessments = {}
        for component, image in (("manager", base.MANAGER), ("console", base.CONSOLE)):
            name = "phorvex-phorvex" + ("-console" if component == "console" else "")
            dep_uid, rs_uid, pod_uid = (base.UIDS[component + "-" + kind]
                                        for kind in ("deploy", "rs", "pod"))
            projection[component + "Deployment"] = {
                "identity": {"name": name, "namespace": "phorvex-system", "uid": dep_uid, "generation": 1},
                "status": {"replicas": 1, "readyReplicas": 1, "observedGeneration": 1},
                "containers": [{"image": base.PREFIX +
                    ("phorvex" if component == "manager" else "phorvex-console") + ":0.4.167"}]}
            pod = {"identity": {"uid": pod_uid}, "phase": "Running", "ready": True,
                   "deleting": False, "containers": [{"imageID": image, "ready": True}],
                   "owners": [{"uid": rs_uid, "controller": True}]}
            projection[component + "Pods"] = [pod]
            projection[component + "ReplicaSet"] = {"identity": {"uid": rs_uid}, "readyReplicas": 1,
                "owners": [{"uid": dep_uid}]}
            assessments[component] = {"status": "EXACT_ACTIVE_READY_SELECTED",
                                      "validationErrors": [], "selectedActiveReady": pod}
        originals, commands = {}, []
        for label, value in projection.items():
            filename = "evidence/rollout-current/" + label + ".json"
            (self.source / filename).parent.mkdir(parents=True, exist_ok=True)
            raw = self.write(filename, value)
            originals[label] = {"file": "responses/" + label + ".json", "SHA256": pack.digest(raw)}
            commands.append({"label": label, "stdoutSHA256": pack.digest(raw), "rc": 0,
                             "dispatches": 1, "retry": False})
        receipt = {"schema": "cpu-activation-current-rollout-read-v1",
                   "status": "READ_COMPLETE_DEPLOYMENT_METADATA", "kubernetesGETs": 10,
                   "applicationRequests": 0, "tokenRequests": 0, "execs": 0, "writes": 0,
                   "projection": projection, "originalProjectedResponses": originals,
                   "commands": commands, "podAssessments": assessments}
        self.write("evidence/rollout-current/RECEIPT.json", receipt)
        self.pin("rollout", "evidence/rollout-current/RECEIPT.json")
        self.build["installedRead"]["receiptSHA256"] = self.fixture.pins["rollout"]
        self.write("evidence/source-current/SOURCE-BUILD.json", self.build)
        self.pin("source", "evidence/source-current/SOURCE-BUILD.json")
        review = {"schema": "mongo-167-source-review-v1", "approved": True,
                  "sourceCommit": SOURCE, "sourceBuildSHA256": self.fixture.pins["source"],
                  "rolloutReceiptSHA256": self.fixture.pins["rollout"],
                  "managerImageID": base.MANAGER, "consoleImageID": base.CONSOLE}
        self.write("evidence/source-current/SOURCE-REVIEW.json", review)
        self.pin("review", "evidence/source-current/SOURCE-REVIEW.json")

    def make_later_target(self):
        receipt_path = self.evidence / "mongo/RECEIPT.json"
        receipt = json.loads(receipt_path.read_bytes())
        for component, image in (("manager", base.MANAGER), ("console", base.CONSOLE)):
            label = component + "-pods"
            row = next(r for r in receipt["receipts"] if r["label"] == label)
            raw = self.write("evidence/mongo/" + row["originalFile"], {"items": [{
                "metadata": {"uid": base.UIDS[component + "-pod"]},
                "status": {"containerStatuses": [{"imageID": image}]}}]})
            row["stdoutSHA256"], row["stdoutBytes"] = pack.digest(raw), len(raw)
        self.write("evidence/mongo/RECEIPT.json", receipt)
        self.pin("target", "evidence/mongo/RECEIPT.json")

    def test_reviewed_release_and_original_format_package(self):
        result = pack.package(self.arguments())
        item = result["profiles"]["mongo"]
        profile = (self.source / "config.mongo-exposure-baseline.yaml").read_bytes()
        self.assertEqual(result["evidenceSchema"], "mongo-current-originals-v1")
        self.assertEqual(item["sha256"], pack.digest(profile))
        self.assertEqual(result["originalJoin"]["sourceCommit"], SOURCE)
        maps = list(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(maps[0]["data"]["config.mongo-exposure-baseline.yaml"].encode(), profile)

    def test_replacement_pod_without_reviewed_uid_refuses(self):
        receipt_path = self.evidence / "mongo/RECEIPT.json"
        receipt = json.loads(receipt_path.read_bytes())
        row = next(r for r in receipt["receipts"] if r["label"] == "console-pods")
        raw = self.write("evidence/mongo/" + row["originalFile"], {"items": [{
            "metadata": {"uid": base.UIDS["manager-pod"]},
            "status": {"containerStatuses": [{"imageID": base.CONSOLE}]}}]})
        row["stdoutSHA256"], row["stdoutBytes"] = pack.digest(raw), len(raw)
        self.write("evidence/mongo/RECEIPT.json", receipt)
        self.pin("target", "evidence/mongo/RECEIPT.json")
        with self.assertRaisesRegex(ValueError, "later original manager/console Pod source differs"):
            pack.package(self.arguments())

    def test_mutated_projected_response_refuses(self):
        path = self.evidence / "rollout-current/consolePods.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "projected original bytes differ"):
            pack.package(self.arguments())
