"""Verify M-4 identities and routes from real standalone and stack Helm renders."""

import os
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "/opt/phorvex-tools/helm")


def render(chart, *flags):
    result = subprocess.run(
        [HELM, "template", "phorvex-stack", str(chart), "--namespace", "phorvex-system",
         "--kube-version", "1.30.0", *flags],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def obj(docs, kind, suffix):
    matches = [d for d in docs if d["kind"] == kind and d["metadata"]["name"].endswith(suffix)]
    assert len(matches) == 1, (kind, suffix, [x["metadata"]["name"] for x in matches])
    return matches[0]


def allowed(role, group, resource, verb):
    return any(group in r["apiGroups"] and resource in r["resources"] and verb in r["verbs"]
               for r in role["rules"])


class M004ChartTest(unittest.TestCase):
    def test_eks_audit_identity_provisioner_matches_live_values(self):
        overlay = yaml.safe_load(
            (ROOT / "deploy/helm/phorvex-stack/values-eks.yaml").read_text()
        )
        transport = overlay["phorvex"]["phorvex"]["console"]["auditTransport"]
        script_path = ROOT / "deploy/eks/provision-audit-mtls.sh"
        script = script_path.read_text()
        syntax = subprocess.run(
            ["bash", "-n", str(script_path)], cwd=ROOT, text=True,
            capture_output=True
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        defaults = {
            "SERVER_SECRET": "serverSecretName",
            "CLIENT_SECRET": "clientSecretName",
            "SERVER_DNS": "serverDNSName",
            "CLIENT_DNS": "clientDNSName",
        }
        for variable, value_key in defaults.items():
            self.assertIn(f'{variable}="${{{variable}:-{transport[value_key]}}}"', script)
        self.assertIn('--from-file=ca.crt=', script)
        self.assertNotIn('--from-file=ca.key=', script)
        self.assertIn('openssl verify -purpose "$purpose"', script)
        self.assertIn('cmp -s "$tmp/stored-server/ca.crt"', script)

    def test_standalone_enabled_isolation(self):
        docs = render(ROOT / "phorvex/charts/phorvex",
                      "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
                      "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
                      "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
                      "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
                      "--set", "phorvex.console.auditTransport.serverDNSName=source.example")
        manager = obj(docs, "Deployment", "-phorvex")
        console = obj(docs, "Deployment", "-phorvex-console")
        manager_pod, console_pod = (x["spec"]["template"]["spec"] for x in (manager, console))
        self.assertEqual([c["name"] for c in manager_pod["containers"]], ["manager"])
        self.assertEqual([c["name"] for c in console_pod["containers"]], ["console"])
        self.assertNotEqual(manager_pod["serviceAccountName"], console_pod["serviceAccountName"])
        manager_pvcs = {v["name"]: v["persistentVolumeClaim"]["claimName"]
                        for v in manager_pod["volumes"] if "persistentVolumeClaim" in v}
        console_pvcs = {v["name"]: v["persistentVolumeClaim"]["claimName"]
                        for v in console_pod["volumes"] if "persistentVolumeClaim" in v}
        self.assertEqual(manager_pvcs, {"audit": "phorvex-stack-phorvex-audit"})
        self.assertEqual(console_pvcs, {"console-state": "phorvex-stack-phorvex-console-state"})
        self.assertTrue(set(manager_pvcs.values()).isdisjoint(console_pvcs.values()))
        manager_mounts = {v["name"] for v in manager_pod["containers"][0].get("volumeMounts", [])}
        console_mounts = {v["name"] for v in console_pod["containers"][0].get("volumeMounts", [])}
        self.assertIn("audit", manager_mounts)
        self.assertNotIn("console-state", manager_mounts)
        self.assertIn("console-state", console_mounts)
        self.assertNotIn("audit", console_mounts)
        self.assertFalse(any(v["name"] == "webhook-cert" for v in console_pod["volumes"]))
        manager_role = obj(docs, "ClusterRole", "-manager-role")
        console_role = obj(docs, "ClusterRole", "-console-role")
        for group, resource, verb in (("", "pods/exec", "create"), ("", "pods/log", "get"),
                                      ("amtd.r6security.com", "securityevents", "delete"),
                                      ("amtd.r6security.com", "securityevents", "patch"),
                                      ("phorvex.ai", "phorvexpolicies", "patch")):
            self.assertFalse(allowed(manager_role, group, resource, verb), (group, resource, verb))
            self.assertTrue(allowed(console_role, group, resource, verb), (group, resource, verb))
        self.assertTrue(allowed(manager_role, "amtd.r6security.com", "securityevents", "create"))
        self.assertTrue(allowed(manager_role, "phorvex.ai", "phorvexpolicies/status", "patch"))
        self.assertFalse(allowed(console_role, "", "configmaps", "update"))
        for suffix, role_suffix, sa in (("-manager-rolebinding", "-manager-role", manager_pod["serviceAccountName"]),
                                        ("-console-rolebinding", "-console-role", console_pod["serviceAccountName"])):
            binding = obj(docs, "ClusterRoleBinding", suffix)
            self.assertTrue(binding["roleRef"]["name"].endswith(role_suffix))
            self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": sa, "namespace": "phorvex-system"}])

    def test_disabled_positive(self):
        docs = render(ROOT / "phorvex/charts/phorvex")
        manager = obj(docs, "Deployment", "-phorvex")
        role = obj(docs, "ClusterRole", "-manager-role")
        self.assertEqual([c["name"] for c in manager["spec"]["template"]["spec"]["containers"]], ["manager"])
        self.assertFalse(any(d["kind"] == "Deployment" and d["metadata"]["name"].endswith("-console") for d in docs))
        self.assertTrue(allowed(role, "amtd.r6security.com", "securityevents", "create"))
        self.assertTrue(allowed(role, "phorvex.ai", "phorvexpolicies/status", "update"))

    def test_stack_selector_and_guard(self):
        docs = render(ROOT / "deploy/helm/phorvex-stack", "-f", str(ROOT / "deploy/helm/phorvex-stack/values.yaml"),
                      "-f", str(ROOT / "deploy/helm/phorvex-stack/values-eks.yaml"))
        dashboard = obj(docs, "Service", "-console")
        source = obj(docs, "Service", "-audit-source")
        self.assertEqual(dashboard["spec"]["selector"]["app.kubernetes.io/name"], "phorvex-console")
        self.assertEqual(source["spec"]["selector"]["app.kubernetes.io/component"], "manager")
        guard = next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicy" and
                     d["metadata"]["labels"].get("phorvex.ai/policy") == "audit-volume-guard")
        rules = " ".join(v["expression"] for v in guard["spec"]["validations"])
        self.assertIn("serviceAccountName == \"phorvex-stack-phorvex-manager\"", rules)
        self.assertIn("c.name == 'manager'", rules)


if __name__ == "__main__":
    unittest.main()
