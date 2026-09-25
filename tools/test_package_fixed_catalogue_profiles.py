"""Offline adverse and positive controls for fixed profile packaging."""

import hashlib
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


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


MANAGER = "registry.example/manager@sha256:" + "a" * 64
CONSOLE = "registry.example/console@sha256:" + "b" * 64
CLUSTER = "11111111-1111-4111-8111-111111111111"
COMMIT = "c" * 40


class PackageProfiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        (self.input / "evidence").mkdir(parents=True)
        self.build = {"schema": "catalogue-pr330-source-build-v1",
                      "release": {"sha": "d" * 40, "messageSubject": "release: v0.4.162 [skip ci]"},
                      "run": {"headSHA": COMMIT, "deployJob": {"conclusion": "success"}, "jobs": {
                          "manager": {"sourceTagAndManifestListPushConfirmed": True, "manifestListDigest": "a" * 64},
                          "console": {"manifestListDigest": "b" * 64}}}}
        self.build_raw = (json.dumps(self.build, sort_keys=True) + "\n").encode()
        (self.input / "evidence/SOURCE-BUILD.json").write_bytes(self.build_raw)
        self.join = {"schema": "reviewed-rollout-join-v1", "clusterUID": CLUSTER,
                     "releaseSHA": "d" * 40, "sourceSHA256": sha(self.build_raw),
                     "components": {kind: {"allPodsReady": True, "allImageIDsMatchSourceBuild": True,
                                          "podCount": 1, "readyReplicas": 1, "podImageIDs": [image],
                                          "podUIDs": ["22222222-2222-4222-8222-222222222222"],
                                          "deploymentUID": "33333333-3333-4333-8333-333333333333",
                                          "deploymentGeneration": 1}
                                    for kind, image in (("manager", MANAGER), ("console", CONSOLE))}}
        self.join["readWindow"] = ["2026-09-24T19:57:35Z", "2026-09-24T19:57:42Z"]
        self.join_raw = (json.dumps(self.join, sort_keys=True) + "\n").encode()
        (self.input / "evidence/JOIN.json").write_bytes(self.join_raw)

    def write_overlay(self, console, **others):
        console.setdefault("image", {"tag": "0.4.162"})
        inner = {"image": {"tag": "0.4.162"}, "console": console, **others}
        values = {"phorvex": {"phorvex": inner}}
        (self.input / "values-overlay.reviewed.yaml").write_text(yaml.safe_dump(values, sort_keys=False))

    def args(self, *kinds, enabled=False):
        return SimpleNamespace(input=self.input, overlay="values-overlay.reviewed.yaml",
                               rollout_join="evidence/JOIN.json", output=self.root / "output",
                               namespace="phorvex-system", profile=list(kinds), allow_enabled=enabled)

    def test_guardrail_static_exact_current_variant(self):
        profile = {"kubeconfig": "", "context": "reviewed-cluster", "namespace": "vllm",
                   "ownedAck": True, "trialsPerArm": 1,
                   "guardrailStaticFixture": {"runID": "run-1", "transport": "in-cluster",
                                              "variant": "pgv2", "clusterUID": CLUSTER,
                                              "podName": "reviewed-vllm", "podUID": "44444444-4444-4444-8444-444444444444",
                                              "serviceUID": "55555555-5555-4555-8555-555555555555",
                                              "sourceSHA256": "f" * 64,
                                              "guardrailJournalName": "reviewed-gj",
                                              "guardrailJournalUID": "66666666-6666-4666-8666-666666666666",
                                              "kvJournalName": "reviewed-kj",
                                              "kvJournalUID": "77777777-7777-4777-8777-777777777777",
                                              "maxRunSeconds": 600}}
        path = self.input / "config.guardrail-confidentiality-static.yaml"
        self.write_overlay({"guardrailStatic": {"enabled": True, "sourceConfigMap": "guardrail-proxy",
                                                "guardrailJournalName": "reviewed-gj", "kvJournalName": "reviewed-kj"}})
        for variant in ("pgv1", "pgv2"):
            profile["guardrailStaticFixture"]["variant"] = variant
            path.write_text(yaml.safe_dump(profile, sort_keys=False))
            receipt = pack.package(self.args("guardrail-static", enabled=True))
            self.assertEqual(receipt["profiles"]["guardrail-static"]["sha256"], sha(path.read_bytes()))
            (self.root / "output").rename(self.root / ("accepted-" + variant))
        for variant in ("pgv3", ""):
            profile["guardrailStaticFixture"]["variant"] = variant
            path.write_text(yaml.safe_dump(profile, sort_keys=False))
            with self.assertRaisesRegex(ValueError, "one exact reviewed pgv1 or pgv2"):
                pack.package(self.args("guardrail-static", enabled=True))
            self.assertFalse((self.root / "output").exists())

    def test_guardrail_availability_exact_reviewed_profile(self):
        fixture = {
            "runID": "run-1", "transport": "in-cluster", "clusterUID": CLUSTER,
            "podName": "reviewed-vllm", "podUID": "44444444-4444-4444-8444-444444444444",
            "podImageID": "registry.example/vllm@sha256:" + "e" * 64,
            "serviceUID": "55555555-5555-4555-8555-555555555555",
            "sourceConfigMapName": "guardrail-proxy", "sourceUID": "66666666-6666-4666-8666-666666666666",
            "sourceSHA256": "f" * 64, "guardrailJournalName": "reviewed-journal",
            "guardrailJournalUID": "77777777-7777-4777-8777-777777777777",
            "managerPodName": "reviewed-manager", "managerPodUID": "88888888-8888-4888-8888-888888888888",
            "managerImageID": MANAGER, "consoleDeploymentName": "reviewed-console",
            "consoleDeploymentUID": "99999999-9999-4999-8999-999999999999", "consoleImageID": CONSOLE,
            "policyName": "vllm-defense", "policyUID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "policyGeneration": 1, "modelID": "Qwen/Qwen2.5-7B-Instruct-AWQ",
            "eventCreator": "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
            "consoleURL": "http://127.0.0.1:8090", "scopedTokenFile": "/etc/phorvex-catalogue-v1/token",
            "auditURL": "https://phorvex-stack-phorvex-audit-source.phorvex-system.svc:8445",
            "auditServerName": "phorvex-stack-phorvex-audit-source.phorvex-system.svc",
            "auditCAFile": "/etc/audit-client/ca.crt",
            "auditClientCertFile": "/etc/audit-client/tls.crt",
            "auditClientKeyFile": "/etc/audit-client/tls.key",
            "maxRunSeconds": 600, "cleanupSeconds": 90,
        }
        profile = {"kubeconfig": "", "context": "reviewed-cluster", "namespace": "vllm",
                   "ownedAck": True, "trialsPerArm": 1, "guardrailAvailabilityFixture": fixture}
        path = self.input / "config.guardrail-availability-recovery.yaml"
        path.write_text(yaml.safe_dump(profile, sort_keys=False))
        self.write_overlay({"guardrailAvailability": {"enabled": True,
                           "sourceConfigMap": "guardrail-proxy",
                           "guardrailJournalName": "reviewed-journal"}})
        with self.assertRaisesRegex(ValueError, "enabled delivery requires explicit"):
            pack.package(self.args("guardrail-availability"))
        receipt = pack.package(self.args("guardrail-availability", enabled=True))
        item = receipt["profiles"]["guardrail-availability"]
        self.assertEqual(item["sha256"], sha(path.read_bytes()))
        cm = next(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(cm["immutable"], True)
        self.assertEqual(cm["data"][path.name].encode(), path.read_bytes())
        (self.root / "output").rename(self.root / "accepted")
        fixture["consoleImageID"] = "registry.example/console@sha256:" + "0" * 64
        path.write_text(yaml.safe_dump(profile, sort_keys=False))
        with self.assertRaisesRegex(ValueError, "rollout differs"):
            pack.package(self.args("guardrail-availability", enabled=True))
        self.assertFalse((self.root / "output").exists())
        fixture["consoleImageID"] = CONSOLE
        fixture["consolePodName"] = "stale-console-pod"
        path.write_text(yaml.safe_dump(profile, sort_keys=False))
        with self.assertRaisesRegex(ValueError, "installed source/identity pin is incomplete"):
            pack.package(self.args("guardrail-availability", enabled=True))
        self.assertFalse((self.root / "output").exists())
        del fixture["consolePodName"]
        fixture["auditURL"] = "https://source.phorvex-system.svc:invalid"
        path.write_text(yaml.safe_dump(profile, sort_keys=False))
        with self.assertRaisesRegex(ValueError, "audit URL is malformed"):
            pack.package(self.args("guardrail-availability", enabled=True))
        self.assertFalse((self.root / "output").exists())
        fixture["auditURL"] = "https://phorvex-stack-phorvex-audit-source.phorvex-system.svc:8445"
        fixture["eventCreator"] = "system:serviceaccount:other:admin"
        path.write_text(yaml.safe_dump(profile, sort_keys=False))
        with self.assertRaisesRegex(ValueError, "fixed route, journal or bounds differ"):
            pack.package(self.args("guardrail-availability", enabled=True))
        self.assertFalse((self.root / "output").exists())

    def test_nats_exact_bytes_and_disabled_default(self):
        raw = ("context: reviewed-cluster\nnamespace: phorvex-nats-exposure-fixture\n"
               "kubeconfig: ''\nownedAck: true\ntrialsPerArm: 1\nnatsExposureFixture:\n"
               f"  transport: in-cluster\n  clusterUID: {CLUSTER}\n  observerImage: {CONSOLE}\n").encode()
        (self.input / "config.nats-exposure-baseline.yaml").write_bytes(raw)
        self.write_overlay({"natsExposure": {"enabled": False, "clientResponse": {"enabled": False}}},
                           image={"tag": "0.4.160"})
        with self.assertRaisesRegex(ValueError, "desired tags differ"):
            pack.package(self.args("nats-baseline"))
        self.write_overlay({"natsExposure": {"enabled": False, "clientResponse": {"enabled": False}}})
        pack.package(self.args("nats-baseline"))
        cm = next(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(cm["data"]["config.nats-exposure-baseline.yaml"].encode(), raw)
        values = yaml.safe_load((self.root / "output/values-overlay.yaml").read_text())
        block = values["phorvex"]["phorvex"]["console"]["natsExposure"]
        self.assertFalse(block["enabled"])
        self.assertEqual(block["profileSHA256"], sha(raw))
        self.assertEqual((self.root / "output/evidence/JOIN.json").read_bytes(), self.join_raw)
        self.assertEqual((self.root / "output/evidence/SOURCE-BUILD.json").read_bytes(), self.build_raw)
        with self.assertRaisesRegex(ValueError, "input/output directory unavailable"):
            pack.package(self.args("nats-baseline"))

    def test_enabled_profile_requires_explicit_ack_and_complete_bytes(self):
        self.write_overlay({"natsExposure": {"enabled": True}})
        with self.assertRaisesRegex(ValueError, "enabled delivery requires explicit"):
            pack.package(self.args("nats-baseline"))
        with self.assertRaises((ValueError, FileNotFoundError)):
            pack.package(self.args("nats-baseline", enabled=True))
        self.assertFalse((self.root / "output").exists())

    def test_nats_response_template_comment_with_filled_scalars(self):
        base = ("context: reviewed-cluster\nnamespace: phorvex-nats-exposure-fixture\n"
                "kubeconfig: ''\nownedAck: true\ntrialsPerArm: 1\nnatsExposureFixture:\n"
                f"  transport: in-cluster\n  clusterUID: {CLUSTER}\n  observerImage: {CONSOLE}\n")
        (self.input / "config.nats-exposure-baseline.yaml").write_text(base)
        response = ("# Replace __SET_OBSERVER_IMAGE__ in the value below; this instruction is a comment.\n"
                    + base)
        path = self.input / "config.nats-client-response.yaml"
        path.write_text(response)
        self.write_overlay({"natsExposure": {"enabled": False, "clientResponse": {"enabled": False}}})
        pack.package(self.args("nats-baseline", "nats-response"))
        maps = list(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(maps[1]["data"]["config.nats-client-response.yaml"], response)
        (self.root / "output").rename(self.root / "accepted")
        path.write_text(response.replace(f"observerImage: {CONSOLE}", "observerImage: __SET_OBSERVER_IMAGE__"))
        with self.assertRaisesRegex(ValueError, "unfilled profile scalar"):
            pack.package(self.args("nats-baseline", "nats-response"))
        self.assertFalse((self.root / "output").exists())

    def test_duplicate_yaml_and_changed_or_symlink_evidence_refuse(self):
        self.write_overlay({"natsExposure": {"enabled": False}})
        values = self.input / "values-overlay.reviewed.yaml"
        values.write_text(values.read_text().replace("    image:\n", "    IMAGE:\n      tag: 0.4.162\n    image:\n", 1))
        with self.assertRaisesRegex(ValueError, "duplicate YAML field"):
            pack.package(self.args("nats-baseline"))
        self.write_overlay({"natsExposure": {"enabled": False}})
        join = self.input / "evidence/JOIN.json"
        join.unlink()
        join.symlink_to(self.input / "evidence/SOURCE-BUILD.json")
        with self.assertRaisesRegex(ValueError, "symlink"):
            pack.package(self.args("nats-baseline"))
        join.unlink()
        join.write_bytes(self.join_raw.replace(sha(self.build_raw).encode(), ("0" * 64).encode()))
        with self.assertRaisesRegex(ValueError, "rollout/build receipt join differs"):
            pack.package(self.args("nats-baseline"))
        join.unlink()
        with self.assertRaises(FileNotFoundError):
            pack.package(self.args("nats-baseline"))
        self.assertFalse((self.root / "output").exists())

    def test_pod_source_review_and_release_tags(self):
        projection = {"cluster": {"uid": CLUSTER}}
        for component, image in (("manager", MANAGER), ("console", CONSOLE)):
            projection[component + "Deployment"] = {
                "namespace": "phorvex-system", "uid": "33333333-3333-4333-8333-333333333333",
                "generation": 1, "replicas": 1, "readyReplicas": 1,
                "containers": [{"name": component, "image": image.split("@sha256:")[0] + ":0.4.162"}]}
            projection[component + "Pods"] = [{
                "namespace": "phorvex-system", "uid": "22222222-2222-4222-8222-222222222222",
                "ready": True, "phase": "Running", "deleting": False,
                "containers": [{"name": component, "imageID": image, "ready": True}]}]
        pods_raw = (json.dumps({"schema": "catalogue-pr330-rollout-read-v1", "status": "COMPLETE",
                                "startedAtUTC": self.join["readWindow"][0],
                                "finishedAtUTC": self.join["readWindow"][1],
                                "projection": projection}, sort_keys=True) + "\n").encode()
        pods_path = self.input / "evidence/PODS.json"
        pods_path.write_bytes(pods_raw)
        review = {"approved": True, "sourceCommit": COMMIT, "managerImageID": MANAGER,
                  "consoleImageID": CONSOLE, "buildEvidenceSHA256": sha(self.build_raw),
                  "rolloutJoinSHA256": sha(self.join_raw), "rolloutPodReadSHA256": sha(pods_raw),
                  "reviewer": "independent-reviewer",
                  "reviewedAtUTC": "2026-09-24T20:26:54Z"}
        review_raw = (json.dumps(review, sort_keys=True) + "\n").encode()
        (self.input / "evidence/source-review.json").write_bytes(review_raw)
        manifest = {"schema": "phorvex.manager-source-image.v1", "sourceCommit": COMMIT,
                    "managerImageID": MANAGER, "buildEvidenceRef": "evidence/SOURCE-BUILD.json",
                    "buildEvidenceSHA256": sha(self.build_raw), "reviewRecordRef": "evidence/source-review.json",
                    "reviewRecordSHA256": sha(review_raw)}
        manifest_raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        (self.input / "manifest.json").write_bytes(manifest_raw)
        profile = ("context: reviewed-cluster\nnamespace: voice\nkubeconfig: ''\n"
                   "ownedAck: true\ntrialsPerArm: 1\npodBoundTokenFixture:\n"
                   f"  transport: in-cluster\n  clusterUID: {CLUSTER}\n  managerImageID: {MANAGER}\n"
                   "  prometheusURL: http://prometheus.example\n"
                   "  sourceManifestPath: /etc/phorvex-catalogue-pod-bound-token/manifest.json\n"
                   f"  sourceManifestSHA256: {pack.PLACEHOLDER}\n")
        (self.input / "config.pod-bound-api-auth-response.yaml").write_text(profile)
        console = {"image": {"tag": "0.4.162"}, "podBoundToken": {"enabled": True, "scrapeApproved": True}}
        self.write_overlay(console, image={"tag": "0.4.160"}, prometheusUrl="http://prometheus.example",
                           eventIdentityPolicy={"enabled": True}, e2eDetector={"enabled": True, "targetNamespace": "voice"})
        with self.assertRaisesRegex(ValueError, "desired tags differ"):
            pack.package(self.args("pod-token", enabled=True))
        self.write_overlay(console, image={"tag": "0.4.162"}, prometheusUrl="http://prometheus.example",
                           eventIdentityPolicy={"enabled": True}, e2eDetector={"enabled": True, "targetNamespace": "voice"})
        pack.package(self.args("pod-token", enabled=True))
        cm = next(yaml.safe_load_all((self.root / "output/configmaps.yaml").read_text()))
        self.assertEqual(cm["data"]["manifest.json"].encode(), manifest_raw)
        self.assertIn(sha(manifest_raw), cm["data"]["config.pod-bound-api-auth-response.yaml"])
        self.assertEqual((self.root / "output/evidence/source-review.json").read_bytes(), review_raw)
        self.assertEqual((self.root / "output/evidence/PODS.json").read_bytes(), pods_raw)
        console["podBoundToken"]["enabled"] = False
        self.write_overlay(console, prometheusUrl="http://prometheus.example",
                           eventIdentityPolicy={"enabled": True}, e2eDetector={"enabled": True, "targetNamespace": "voice"})
        disabled = self.args("pod-token")
        disabled.output = self.root / "valid-disabled"
        self.assertFalse(pack.package(disabled)["profiles"]["pod-token"]["enabledInProposal"])
        (self.root / "output").rename(self.root / "valid-enabled")
        for enabled in (False, True):
            console["podBoundToken"]["enabled"] = enabled
            self.write_overlay(console, prometheusUrl="http://prometheus.example",
                               eventIdentityPolicy={"enabled": True}, e2eDetector={"enabled": True, "targetNamespace": "voice"})
            for label, value in (("absent", None), ("blank", ""), ("different", "http://other-prometheus.example")):
                with self.subTest(enabled=enabled, fixtureURL=label):
                    if value is None:
                        changed = profile.replace("  prometheusURL: http://prometheus.example\n", "")
                    else:
                        changed = profile.replace("  prometheusURL: http://prometheus.example",
                                                  "  prometheusURL: " + value)
                    (self.input / "config.pod-bound-api-auth-response.yaml").write_text(changed)
                    bad = self.args("pod-token", enabled=enabled)
                    bad.output = self.root / ("invalid-url-" + str(enabled).lower() + "-" + label)
                    with self.assertRaisesRegex(ValueError, "Prometheus URL differs"):
                        pack.package(bad)
                    self.assertFalse(bad.output.exists())
        (self.input / "config.pod-bound-api-auth-response.yaml").write_text(profile)
        console["podBoundToken"]["enabled"] = True
        self.write_overlay(console, prometheusUrl="http://prometheus.example",
                           eventIdentityPolicy={"enabled": True}, e2eDetector={"enabled": True, "targetNamespace": "voice"})
        pods_path.write_bytes(pods_raw.replace(b'"ready": true', b'"ready": false', 1))
        bad = self.args("pod-token", enabled=True)
        bad.output = self.root / "changed-pods"
        with self.assertRaisesRegex(ValueError, "Pod read"):  # join or signed hash must fail
            pack.package(bad)
        self.assertFalse(bad.output.exists())
        pods_path.unlink()
        bad.output = self.root / "missing-pods"
        with self.assertRaises(FileNotFoundError):
            pack.package(bad)
        self.assertFalse(bad.output.exists())
        pods_path.write_bytes(pods_raw)
        for ref in ("receipt.json", "../escape.json"):
            manifest["reviewRecordRef"] = ref
            (self.input / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            args = self.args("pod-token", enabled=True)
            args.output = self.root / ("collision-" + ref.replace("/", "-"))
            with self.assertRaisesRegex(ValueError, "fixed portable paths"):
                pack.package(args)
            self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
