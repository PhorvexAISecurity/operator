#!/usr/bin/env python3
"""Render the fixed, default-off Pod-bound bearer case authority."""
import os
from pathlib import Path
import subprocess
import unittest

import yaml


CHART = Path(__file__).resolve().parents[1] / "phorvex/charts/phorvex"
HELM = os.environ.get("HELM", "helm")
LEDGER = "phorvex-quarantine-capacity-" + "a" * 40
BASE = [HELM, "template", "phorvex", str(CHART), "--namespace", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example"]
OPT_IN = ["--set", "phorvex.console.podBoundToken.enabled=true",
          "--set", "phorvex.console.podBoundToken.configMapName=reviewed-pod-bound-token-source",
          "--set-string", "phorvex.console.podBoundToken.profileSHA256=" + "a" * 64,
          "--set", "phorvex.console.podBoundToken.scrapeApproved=true",
          "--set", "phorvex.e2eDetector.enabled=true",
          "--set", "phorvex.e2eDetector.targetNamespace=voice",
          "--set", "phorvex.prometheusUrl=http://prometheus.monitoring.svc:9090",
          "--set-string", "phorvex.console.podBoundToken.quarantineCapacityLedgerName=" + LEDGER,
          "--api-versions", "monitoring.coreos.com/v1/PodMonitor"]


def render(*extra):
    return subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)


def object_named(docs, kind, name):
    matches = [d for d in docs if d.get("kind") == kind and d["metadata"]["name"] == name]
    if len(matches) != 1:
        raise AssertionError((kind, name, len(matches)))
    return matches[0]


class PodBoundTokenChart(unittest.TestCase):
    def test_default_off_grants_nothing_for_case(self):
        result = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        self.assertFalse([d for d in docs if "pod-bound-token" in d["metadata"]["name"]])
        self.assertFalse([d for d in docs if d.get("kind") in {"ClusterRole", "ClusterRoleBinding"}
                          and "creator-policy-read" in d["metadata"]["name"]])
        console = object_named(docs, "Deployment", "phorvex-phorvex-console")
        env = {v["name"]: v["value"] for v in console["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_ENABLED"], "false")
        self.assertNotIn("PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256", env)
        self.assertFalse([v for v in console["spec"]["template"]["spec"]["volumes"]
                          if v["name"] == "pod-bound-token-reviewed-source"])
        self.assertFalse([v for v in console["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
                          if v["name"] == "pod-bound-token-reviewed-source"])

    def test_opt_in_has_voice_fixture_and_exact_creator_token_authority(self):
        result = render(*OPT_IN)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        fixture = object_named(docs, "Role", "phorvex-phorvex-pod-bound-token-fixture")
        creator = object_named(docs, "Role", "phorvex-phorvex-pod-bound-token-creator")
        creator_policy = object_named(docs, "ClusterRole", "phorvex-phorvex-pod-bound-token-creator-policy-read")
        self.assertEqual(creator_policy["rules"], [
            {"apiGroups": ["admissionregistration.k8s.io"],
             "resources": ["validatingadmissionpolicies", "validatingadmissionpolicybindings"],
             "resourceNames": ["phorvex-phorvex-e2e-detector"], "verbs": ["get"]},
        ])
        policy_binding = object_named(docs, "ClusterRoleBinding", "phorvex-phorvex-pod-bound-token-creator-policy-read")
        self.assertEqual(policy_binding["roleRef"], {
            "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
            "name": "phorvex-phorvex-pod-bound-token-creator-policy-read"})
        self.assertEqual(policy_binding["subjects"], [{
            "kind": "ServiceAccount", "name": "phorvex-phorvex-console", "namespace": "phorvex-system"}])
        ledger = object_named(docs, "Role", "phorvex-phorvex-pod-bound-token-capacity-ledger")
        self.assertEqual(fixture["metadata"]["namespace"], "voice")
        self.assertEqual(creator["metadata"]["namespace"], "phorvex-system")
        self.assertIn({"apiGroups": [""], "resources": ["pods"],
                       "verbs": ["get", "list", "watch", "update", "delete"]}, fixture["rules"])
        self.assertIn({"apiGroups": ["monitoring.coreos.com"], "resources": ["podmonitors"],
                       "verbs": ["create", "get", "delete"]}, fixture["rules"])
        self.assertEqual(creator["rules"], [
            {"apiGroups": [""], "resources": ["serviceaccounts"],
             "resourceNames": ["phorvex-phorvex-e2e-detector"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["serviceaccounts/token"],
             "resourceNames": ["phorvex-phorvex-e2e-detector"], "verbs": ["create"]}])
        self.assertEqual(ledger["metadata"]["namespace"], "phorvex-system")
        self.assertEqual(ledger["rules"], [{"apiGroups": [""], "resources": ["configmaps"],
                                          "resourceNames": [LEDGER], "verbs": ["get"]}])
        for role in [fixture, creator, ledger]:
            self.assertFalse([r for r in role["rules"] if "impersonate" in r["verbs"] or
                              "securityevents" in r["resources"] or "secrets" in r["resources"]])
        for name, namespace in [("fixture", "voice"), ("creator", "phorvex-system"),
                                ("capacity-ledger", "phorvex-system")]:
            binding = object_named(docs, "RoleBinding", "phorvex-phorvex-pod-bound-token-" + name)
            self.assertEqual(binding["metadata"]["namespace"], namespace)
            self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount",
                             "name": "phorvex-phorvex-console", "namespace": "phorvex-system"}])
        detector = object_named(docs, "ValidatingAdmissionPolicy", "phorvex-phorvex-e2e-detector")
        self.assertEqual(detector["spec"]["failurePolicy"], "Fail")
        self.assertIn("system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector",
                      detector["spec"]["matchConditions"][0]["expression"])
        console = object_named(docs, "Deployment", "phorvex-phorvex-console")
        env = {v["name"]: v["value"] for v in console["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256"], "a" * 64)
        volume = next(v for v in console["spec"]["template"]["spec"]["volumes"]
                      if v["name"] == "pod-bound-token-reviewed-source")
        self.assertEqual(volume["configMap"], {
            "name": "reviewed-pod-bound-token-source", "defaultMode": 0o440,
            "items": [
                {"key": "config.pod-bound-api-auth-response.yaml", "path": "config.pod-bound-api-auth-response.yaml"},
                {"key": "manifest.json", "path": "manifest.json"},
            ],
        })
        mounts = [v for v in console["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
                  if v["name"] == "pod-bound-token-reviewed-source"]
        self.assertEqual(mounts, [
            {"name": "pod-bound-token-reviewed-source",
             "mountPath": "/data/build/test-harness/config.pod-bound-api-auth-response.yaml",
             "subPath": "config.pod-bound-api-auth-response.yaml", "readOnly": True},
            {"name": "pod-bound-token-reviewed-source",
             "mountPath": "/etc/phorvex-catalogue-pod-bound-token/manifest.json",
             "subPath": "manifest.json", "readOnly": True},
        ])

    def test_incomplete_authority_fails_closed(self):
        for name, args, expected in [
            ("scrape", ["--set", "phorvex.console.podBoundToken.scrapeApproved=false"], "scrape approval"),
            ("configmap missing", ["--set", "phorvex.console.podBoundToken.configMapName="], "configMapName is required"),
            ("configmap invalid", ["--set", "phorvex.console.podBoundToken.configMapName=INVALID"], "DNS subdomain name"),
            ("profile hash missing", ["--set-string", "phorvex.console.podBoundToken.profileSHA256="], "profileSHA256 is required"),
            ("profile hash malformed", ["--set-string", "phorvex.console.podBoundToken.profileSHA256=" + "A" * 64], "64 lowercase hex"),
            ("creator", ["--set", "phorvex.e2eDetector.enabled=false"], "e2eDetector identity"),
            ("target", ["--set", "phorvex.e2eDetector.targetNamespace=other"], "target voice"),
            ("selector", ["--set", "phorvex.console.podBoundToken.podSelectorLabel=other"], "fixed nonce label"),
            ("metrics", ["--set", "phorvex.prometheusUrl="], "Prometheus URL"),
            ("ledger missing", ["--set-string", "phorvex.console.podBoundToken.quarantineCapacityLedgerName="], "quarantineCapacityLedgerName"),
            ("ledger arbitrary", ["--set-string", "phorvex.console.podBoundToken.quarantineCapacityLedgerName=some-configmap"], "quarantineCapacityLedgerName"),
            ("ledger uppercase", ["--set-string", "phorvex.console.podBoundToken.quarantineCapacityLedgerName=phorvex-quarantine-capacity-" + "A" * 40], "quarantineCapacityLedgerName"),
            ("ledger short", ["--set-string", "phorvex.console.podBoundToken.quarantineCapacityLedgerName=phorvex-quarantine-capacity-" + "a" * 39], "quarantineCapacityLedgerName"),
        ]:
            with self.subTest(name=name):
                result = render(*OPT_IN, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
        result = render(*OPT_IN[:-2])  # omit the PodMonitor API capability
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed PodMonitor API", result.stderr)
        result = subprocess.run([*BASE[:2], "other", *BASE[3:], *OPT_IN],
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release name phorvex", result.stderr)


if __name__ == "__main__":
    unittest.main()
