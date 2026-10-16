"""Render the umbrella-owned, default-off static guardrail profile source."""

import base64
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
KEY = "config.guardrail-confidentiality-static.yaml"


def fixed_profile():
    raw = (ROOT / "build/test-harness" / KEY).read_text()
    replacements = {
        "__SET_LOGICAL_CLUSTER_TARGET__": "reviewed-cluster-target",
        "__SET_REVIEWED_KUBE_SYSTEM_UID__": "11111111-1111-4111-8111-111111111111",
        "__SET_REVIEWED_VLLM_POD_NAME__": "reviewed-vllm",
        "__SET_REVIEWED_VLLM_POD_UID__": "22222222-2222-4222-8222-222222222222",
        "__SET_REVIEWED_VLLM_SERVICE_UID__": "33333333-3333-4333-8333-333333333333",
        "__SET_REVIEWED_GUARDRAIL_SOURCE_SHA256__": "a" * 64,
        "__SET_REVIEWED_GUARDRAIL_JOURNAL_NAME__": "reviewed-gj",
        "__SET_REVIEWED_GUARDRAIL_JOURNAL_UID__": "44444444-4444-4444-8444-444444444444",
        "__SET_REVIEWED_KV_JOURNAL_NAME__": "reviewed-kj",
        "__SET_REVIEWED_KV_JOURNAL_UID__": "55555555-5555-4555-8555-555555555555",
    }
    for old, new in replacements.items():
        if raw.count(old) != 1:
            raise AssertionError("tracked static profile placeholder differs: " + old)
        raw = raw.replace(old, new)
    if "__SET_" in raw:
        raise AssertionError("tracked static profile retains placeholder")
    return raw.encode()


def options(profile=None, console=False):
    profile = fixed_profile() if profile is None else profile
    digest = hashlib.sha256(profile).hexdigest()
    name = "phorvex-catalogue-guardrail-static-" + digest[:12]
    source = {"catalogueProfiles": {"guardrailStatic": {
        "enabled": True, "configMapName": name,
        "profileBase64": base64.b64encode(profile).decode()}}}
    if console:
        source["phorvex"] = {"phorvex": {"console": {"guardrailStatic": {
            "enabled": True, "configMapName": name, "profileSHA256": digest,
            "sourceConfigMap": "guardrail-proxy",
            "guardrailJournalName": "reviewed-gj", "kvJournalName": "reviewed-kj"}}}}
    return source, name, digest


def render(overlay=None):
    with tempfile.TemporaryDirectory(prefix="guardrail-static-cm-chart-") as tmp:
        argv = [HELM, "template", "phorvex", str(CHART), "--namespace", "phorvex-system",
                "-f", str(CHART / "values-eks.yaml"),
                "--api-versions", "monitoring.coreos.com/v1/PodMonitor"]
        if overlay is not None:
            path = Path(tmp) / "overlay.yaml"
            path.write_text(yaml.safe_dump(overlay, sort_keys=False))
            argv.extend(["-f", str(path)])
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    return result, [x for x in yaml.safe_load_all(result.stdout) if x] if result.returncode == 0 else []


def static_source(docs):
    return [x for x in docs if x.get("kind") == "ConfigMap" and
            x.get("metadata", {}).get("name", "").startswith("phorvex-catalogue-guardrail-static-")]


class GuardrailStaticProfileCMChart(unittest.TestCase):
    @inherited_drift("values-eks.yaml now ships the guardrail-static profile ConfigMap")
    def test_default_off_and_stage_a_source_only(self):
        result, docs = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(static_source(docs), [])
        self.assertFalse([x for x in docs if "console-guardrail-static" in x.get("metadata", {}).get("name", "")])
        overlay, name, _ = options()
        result, docs = render(overlay)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(static_source(docs)), 1)
        cm = static_source(docs)[0]
        self.assertEqual(cm["metadata"], {"name": name, "namespace": "phorvex-system"})
        self.assertIs(cm["immutable"], True)
        self.assertEqual(set(cm), {"apiVersion", "kind", "metadata", "immutable", "binaryData"})
        self.assertEqual(set(cm["binaryData"]), {KEY})
        self.assertEqual(base64.b64decode(cm["binaryData"][KEY]), fixed_profile())
        self.assertFalse([x for x in docs if "console-guardrail-static" in x.get("metadata", {}).get("name", "")])

    def test_stage_b_exact_child_mount_and_digest_join(self):
        overlay, name, digest = options(console=True)
        result, docs = render(overlay)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(static_source(docs)), 1)
        roles = [x for x in docs if x.get("kind") == "Role" and
                 "console-guardrail-static" in x.get("metadata", {}).get("name", "")]
        self.assertEqual(len(roles), 2)
        deployment = next(x for x in docs if x.get("kind") == "Deployment" and
                          x["metadata"]["name"] == "phorvex-phorvex-console")
        pod = deployment["spec"]["template"]["spec"]
        console = next(x for x in pod["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in console["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_STATIC_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256"], digest)
        volume = next(x for x in pod["volumes"] if x["name"] == "guardrail-static-reviewed-profile")
        self.assertEqual(volume["configMap"]["name"], name)
        self.assertEqual(volume["configMap"]["items"], [{"key": KEY, "path": KEY}])
        mount = next(x for x in console["volumeMounts"] if x["name"] == "guardrail-static-reviewed-profile")
        self.assertEqual(mount["mountPath"], "/data/build/test-harness/" + KEY)
        self.assertIs(mount["readOnly"], True)

    def test_existing_external_configmap_path_preserves_console_projection(self):
        managed, name, digest = options(console=True)
        managed_result, managed_docs = render(managed)
        self.assertEqual(managed_result.returncode, 0, managed_result.stderr)
        external = yaml.safe_load(yaml.safe_dump(managed))
        external["catalogueProfiles"]["guardrailStatic"]["enabled"] = False
        external_result, external_docs = render(external)
        self.assertEqual(external_result.returncode, 0, external_result.stderr)
        self.assertEqual(static_source(external_docs), [])
        def console_projection(docs):
            return [x for x in docs if
                    (x.get("kind") == "Deployment" and
                     x.get("metadata", {}).get("name") == "phorvex-phorvex-console") or
                    "console-guardrail-static" in x.get("metadata", {}).get("name", "")]
        self.assertEqual(console_projection(external_docs), console_projection(managed_docs))
        deployment = next(x for x in external_docs if x.get("kind") == "Deployment" and
                          x["metadata"]["name"] == "phorvex-phorvex-console")
        pod = deployment["spec"]["template"]["spec"]
        volume = next(x for x in pod["volumes"] if x["name"] == "guardrail-static-reviewed-profile")
        self.assertEqual(volume["configMap"]["name"], name)
        console = next(x for x in pod["containers"] if x["name"] == "console")
        env = {x["name"]: x.get("value") for x in console["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256"], digest)

    def test_source_and_child_mismatches_refuse(self):
        base, _, _ = options(console=True)
        controls = [
            ("wrong source name", lambda x: x["catalogueProfiles"]["guardrailStatic"].update(configMapName="arbitrary-source"),
             "must match decoded profile SHA prefix"),
            ("wrong child name", lambda x: x["phorvex"]["phorvex"]["console"]["guardrailStatic"].update(configMapName="other-source"),
             "must match catalogueProfiles.guardrailStatic.configMapName"),
            ("wrong child hash", lambda x: x["phorvex"]["phorvex"]["console"]["guardrailStatic"].update(profileSHA256="0" * 64),
             "must match decoded catalogue profile"),
            ("invalid base64", lambda x: x["catalogueProfiles"]["guardrailStatic"].update(profileBase64="not base64!"),
             "canonical bounded nonempty base64"),
            ("noncanonical base64", lambda x: x["catalogueProfiles"]["guardrailStatic"].update(profileBase64=base["catalogueProfiles"]["guardrailStatic"]["profileBase64"] + "="),
             "canonical bounded nonempty base64"),
        ]
        for label, mutate, expected in controls:
            with self.subTest(label=label):
                overlay = yaml.safe_load(yaml.safe_dump(base))
                mutate(overlay)
                result, _ = render(overlay)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
