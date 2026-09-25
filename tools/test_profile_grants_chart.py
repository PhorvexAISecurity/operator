"""Exercise the release grant scope and restart trigger through real Helm renders."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
STACK = ROOT / "deploy/helm/phorvex-stack"
CHART = ROOT / "phorvex/charts/phorvex"
SA = "system:serviceaccount:phorvex-system:phorvex-phorvex-console-e2e"
EKS_ISSUER = "https://oidc.eks.us-east-2.amazonaws.com/id/B4E80A6F4AB1E51169435AFFDC706401"
COGNITO_ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_JfwlBPRbB"
COGNITO_SUBJECT = "71fb8550-3041-702a-5735-a33baf8836c8"
GRANT_KEY = "checksum/console-grants"


def render(chart, *args):
    result = subprocess.run(
        [HELM, "template", "phorvex", str(chart), "-n", "phorvex-system", *map(str, args)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def stack(*args):
    return render(STACK, "-f", STACK / "values.yaml", "-f", STACK / "values-eks.yaml", *args)


def resource(docs, kind, name):
    return next(d for d in docs if d.get("kind") == kind and d["metadata"]["name"] == name)


def grant_data(docs):
    return resource(docs, "ConfigMap", "phorvex-phorvex-console-grants")["data"]["grants.json"]


def checksum(docs):
    return resource(docs, "Deployment", "phorvex-phorvex-console")["spec"]["template"]["metadata"].get("annotations", {}).get(GRANT_KEY)


class ProfileGrantChart(unittest.TestCase):
    def test_eks_scope_is_exact_same_subject_and_startup_checksum(self):
        docs = stack()
        raw = grant_data(docs)
        subjects = json.loads(raw)["subjects"]
        self.assertEqual(len(subjects), 2)
        self.assertEqual(subjects[0], {
            "issuer": COGNITO_ISSUER,
            "subject": COGNITO_SUBJECT,
            "roles": ["operator"], "tenants": ["*"], "targets": ["default"],
            "note": "Operator access approved by the deployment owner on 2026-09-16",
        })
        campaign = subjects[1]
        self.assertEqual(campaign["issuer"], EKS_ISSUER)
        self.assertEqual(campaign["subject"], SA)
        self.assertEqual(campaign["roles"], ["operator"])
        self.assertEqual(campaign["targets"], ["default"])
        self.assertEqual(campaign["tenants"], ["voice", "nats", "vllm", "document-store", "litellm", "mcp"])
        self.assertEqual(checksum(docs), hashlib.sha256(raw.encode()).hexdigest())

    def test_only_grant_data_changes_checksum(self):
        original = stack()
        data = json.loads(grant_data(original))
        data["subjects"][1]["tenants"].remove("mcp")
        changed_raw = json.dumps(data)
        with tempfile.TemporaryDirectory() as directory:
            override = Path(directory) / "grants.json"
            override.write_text(changed_raw)
            changed = stack("--set-file", f"phorvex.phorvex.console.auth.grants.data={override}")
        self.assertNotEqual(checksum(original), checksum(changed))
        self.assertEqual(checksum(changed), hashlib.sha256(changed_raw.encode()).hexdigest())
        self.assertEqual(checksum(original), checksum(stack("--set", "phorvex.phorvex.prometheusUrl=http://irrelevant.invalid")))

    def test_external_grants_and_generic_default_do_not_gain_checksum(self):
        external = stack("--set", "phorvex.phorvex.console.auth.grants.create=false", "--set", "phorvex.phorvex.console.auth.grants.configMapName=external-grants")
        self.assertIsNone(checksum(external))
        self.assertFalse(any(d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "phorvex-phorvex-console-grants" for d in external))
        generic = render(CHART, "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
                         "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
                         "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
                         "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
                         "--set", "phorvex.console.auditTransport.serverDNSName=source.example")
        self.assertIsNone(checksum(generic))
        self.assertFalse(any(d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "phorvex-phorvex-console-grants" for d in generic))


if __name__ == "__main__":
    unittest.main()
