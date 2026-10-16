"""Render controls for scoped serving TLS configuration and Secret RBAC."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "phorvex/charts/phorvex"
HELM = os.environ.get("HELM_BIN", "helm")


def render(values=None, expect_success=True):
    command = [HELM, "template", "m093", str(CHART), "--namespace", "operator"]
    temp = None
    if values is not None:
        temp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        yaml.safe_dump(values, temp)
        temp.close()
        command.extend(["-f", temp.name])
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    finally:
        if temp is not None:
            Path(temp.name).unlink()
    if expect_success:
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    if result.returncode == 0:
        raise AssertionError("render unexpectedly succeeded")
    return result.stderr


def one(docs, kind, suffix):
    matches = [doc for doc in docs if doc["kind"] == kind and doc["metadata"]["name"].endswith(suffix)]
    assert len(matches) == 1, (kind, suffix, matches)
    return matches[0]


def binding():
    return {
        "namespace": "tenant-a", "policyName": "models", "policyUID": "policy-uid",
        "serviceAccount": "model-runtime", "profileID": "models-v1",
        "secretName": "models-serving-admin", "bearerKey": "bearer",
        "caKey": "ca.crt", "serverName": "models-admin.tenant-a.svc",
    }


class M093ChartTest(unittest.TestCase):
    def test_default_secure_mode_grants_no_secret_without_binding(self):
        docs = render()
        deployment = one(docs, "Deployment", "-phorvex")
        args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--serving-security-mode=secure-required", args)
        self.assertFalse(any(doc["kind"] == "ConfigMap" and doc["metadata"]["name"].endswith("-serving-security") for doc in docs))
        journal = one(docs, "Role", "-operation-journal")
        self.assertFalse(any("secrets" in rule["resources"] for rule in journal["rules"]))

    def test_native_binding_mounts_exact_document_and_resource_name(self):
        values = {"phorvex": {"actuator": "native", "servingSecurity": {"mode": "secure-required", "bindings": [binding()]}}}
        docs = render(values)
        config = one(docs, "ConfigMap", "-serving-security")
        self.assertEqual(json.loads(config["data"]["security.json"]), {"version": 1, "bindings": [binding()]})
        journal = one(docs, "Role", "-operation-journal")
        secret_rules = [rule for rule in journal["rules"] if "secrets" in rule["resources"]]
        self.assertEqual(secret_rules, [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["models-serving-admin"], "verbs": ["get"]}])
        deployment = one(docs, "Deployment", "-phorvex")
        manager = deployment["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("--serving-security-file=/etc/phorvex-serving/security.json", manager["args"])
        self.assertIn("serving-security", {mount["name"] for mount in manager["volumeMounts"]})

    def test_explicit_legacy_has_no_secret_or_configuration_mount(self):
        docs = render({"phorvex": {"actuator": "native", "servingSecurity": {"mode": "legacy-plaintext", "bindings": []}}})
        deployment = one(docs, "Deployment", "-phorvex")
        manager = deployment["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("--serving-security-mode=legacy-plaintext", manager["args"])
        self.assertFalse(any(arg.startswith("--serving-security-file=") for arg in manager["args"]))
        self.assertNotIn("serving-security", {mount["name"] for mount in manager.get("volumeMounts", [])})
        journal = one(docs, "Role", "-operation-journal")
        self.assertFalse(any("secrets" in rule["resources"] for rule in journal["rules"]))

    def test_invalid_mode_binding_combinations_are_rejected(self):
        legacy_error = render({"phorvex": {"actuator": "native", "servingSecurity": {"mode": "legacy-plaintext", "bindings": [binding()]}}}, False)
        self.assertIn("legacy-plaintext does not accept", legacy_error)
        phoenix_error = render({"phorvex": {"actuator": "phoenix", "servingSecurity": {"mode": "secure-required", "bindings": [binding()]}}}, False)
        self.assertIn("require phorvex.actuator=native or hybrid", phoenix_error)


if __name__ == "__main__":
    unittest.main()
