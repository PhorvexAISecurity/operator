"""Render the optional immutable Mongo profile source in the real umbrella chart."""

import base64
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from inherited_drift import inherited_drift

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/phorvex-stack"
HELM = os.environ.get("HELM_BIN", "helm")
KEY = "config.mongo-exposure-baseline.yaml"
PREFIX = "phorvex-catalogue-mongo-"


def profile_bytes():
    raw = (ROOT / "build/test-harness" / KEY).read_text()
    replacements = {
        "__SET_LOGICAL_CLUSTER_TARGET__": "reviewed-cluster-target",
        "__SET_KUBE_SYSTEM_UID__": "11111111-1111-4111-8111-111111111111",
        "__SET_MONGO_IMAGE_DIGEST__": "docker.io/library/mongo@sha256:" + "a" * 64,
        "__SET_MANAGER_IMAGE_DIGEST__": "registry.example.test/phorvex@sha256:" + "b" * 64,
        "__SET_REVIEWED_CPU_NODE_NAME__": "ip-172-27-11-9.us-east-2.compute.internal",
    }
    for old, new in replacements.items():
        if raw.count(old) != 1:
            raise AssertionError("Mongo template placeholder differs: " + old)
        raw = raw.replace(old, new)
    if "__SET_" in raw:
        raise AssertionError("Mongo test profile retains a placeholder")
    return raw.encode()


def options(profile=None, console=False):
    profile = profile_bytes() if profile is None else profile
    digest = hashlib.sha256(profile).hexdigest()
    name = PREFIX + digest[:12]
    overlay = {"catalogueProfiles": {"mongoExposure": {
        "enabled": True, "configMapName": name,
        "profileBase64": base64.b64encode(profile).decode()}}}
    if console:
        overlay["phorvex"] = {"phorvex": {"console": {"mongoExposure": {
            "enabled": True, "configMapName": name, "profileSHA256": digest}}}}
    return overlay, name, digest


def render(overlay=None):
    with tempfile.TemporaryDirectory(prefix="mongo-profile-cm-chart-") as tmp:
        argv = [HELM, "template", "phorvex", str(CHART), "--namespace", "phorvex-system",
                "-f", str(CHART / "values-eks.yaml"),
                "--api-versions", "monitoring.coreos.com/v1/PodMonitor"]
        if overlay is not None:
            path = Path(tmp) / "overlay.yaml"
            path.write_text(yaml.safe_dump(overlay, sort_keys=False))
            argv.extend(["-f", str(path)])
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    return result, [x for x in yaml.safe_load_all(result.stdout) if x] if result.returncode == 0 else []


def mongo_source(docs):
    return [x for x in docs if x.get("kind") == "ConfigMap" and
            x.get("metadata", {}).get("name", "").startswith(PREFIX)]


def console_projection(docs):
    return [x for x in docs if
            (x.get("kind") == "Deployment" and x.get("metadata", {}).get("name") == "phorvex-phorvex-console") or
            "console-mongo-exposure" in x.get("metadata", {}).get("name", "")]


class MongoExposureProfileCMChart(unittest.TestCase):
    @inherited_drift("values-eks.yaml now ships the Mongo profile ConfigMap")
    def test_default_off_and_source_only(self):
        result, docs = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(mongo_source(docs), [])
        overlay, name, _ = options()
        result, docs = render(overlay)
        self.assertEqual(result.returncode, 0, result.stderr)
        cm, = mongo_source(docs)
        self.assertEqual(cm["metadata"], {"name": name, "namespace": "phorvex-system"})
        self.assertIs(cm["immutable"], True)
        self.assertEqual(set(cm), {"apiVersion", "kind", "metadata", "immutable", "binaryData"})
        self.assertEqual(set(cm["binaryData"]), {KEY})
        self.assertEqual(base64.b64decode(cm["binaryData"][KEY]), profile_bytes())
        self.assertFalse([x for x in docs if "console-mongo-exposure" in x.get("metadata", {}).get("name", "")])

    def test_enabled_exact_mount_and_external_source(self):
        overlay, name, digest = options(console=True)
        result, managed = render(overlay)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(mongo_source(managed)), 1)
        deployment = next(x for x in managed if x.get("kind") == "Deployment" and
                          x["metadata"]["name"] == "phorvex-phorvex-console")
        pod = deployment["spec"]["template"]["spec"]
        container = next(x for x in pod["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256"], digest)
        volume = next(x for x in pod["volumes"] if x["name"] == "mongo-exposure-reviewed-profile")
        self.assertEqual(volume["configMap"]["name"], name)
        self.assertEqual(volume["configMap"]["items"], [{"key": KEY, "path": KEY}])
        mount = next(x for x in container["volumeMounts"] if x["name"] == "mongo-exposure-reviewed-profile")
        self.assertEqual(mount["mountPath"], "/data/build/test-harness/" + KEY)
        self.assertIs(mount["readOnly"], True)
        roles = [x for x in managed if x.get("kind") == "Role" and
                 "console-mongo-exposure" in x.get("metadata", {}).get("name", "")]
        self.assertEqual(len(roles), 1)
        external = copy.deepcopy(overlay)
        external["catalogueProfiles"]["mongoExposure"]["enabled"] = False
        result, external_docs = render(external)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(mongo_source(external_docs), [])
        self.assertEqual(console_projection(external_docs), console_projection(managed))

    def test_wrong_name_digest_and_noncanonical_bytes_refuse(self):
        base, _, _ = options(console=True)
        controls = [
            (lambda x: x["catalogueProfiles"]["mongoExposure"].update(configMapName="arbitrary"), "must match decoded profile SHA prefix"),
            (lambda x: x["phorvex"]["phorvex"]["console"]["mongoExposure"].update(configMapName="other-source"), "must match catalogueProfiles.mongoExposure.configMapName"),
            (lambda x: x["phorvex"]["phorvex"]["console"]["mongoExposure"].update(profileSHA256="0" * 64), "must match decoded catalogue profile"),
            (lambda x: x["catalogueProfiles"]["mongoExposure"].update(profileBase64="not base64!"), "canonical bounded nonempty base64"),
            (lambda x: x["catalogueProfiles"]["mongoExposure"].update(profileBase64=base["catalogueProfiles"]["mongoExposure"]["profileBase64"] + "="), "canonical bounded nonempty base64"),
        ]
        for mutate, expected in controls:
            with self.subTest(expected=expected):
                overlay = copy.deepcopy(base)
                mutate(overlay)
                result, _ = render(overlay)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
