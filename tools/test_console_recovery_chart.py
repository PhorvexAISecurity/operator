"""Console deployment recovery contract, verified against real Helm renders."""
import unittest

from test_m004_chart import ROOT, obj, render
from inherited_drift import inherited_drift


class ConsoleRecoveryChartTest(unittest.TestCase):
    @inherited_drift("values-eks.yaml now needs release name phorvex and the PodMonitor API")
    def test_live_stack_migration_and_explicit_production_trust(self):
        docs = render(ROOT / "deploy/helm/phorvex-stack", "-f",
                      str(ROOT / "deploy/helm/phorvex-stack/values-eks.yaml"))
        console = obj(docs, "Deployment", "-phorvex-console")
        self.assertEqual(console["spec"]["strategy"],
                         {"type": "Recreate", "rollingUpdate": None})
        pod = console["spec"]["template"]["spec"]
        env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_ALB_ADDITIONAL_SIGNER_ARNS"],
                         "arn:aws:elasticloadbalancing:us-east-2:753556437180:loadbalancer/app/phorvex-prd-console/41c2083aa2e1ebba")
        self.assertEqual(set(env["PHORVEX_CONSOLE_TRUSTED_ORIGINS"].split(",")),
                         {"https://console.phorvex.ai", "https://console-prd.phorvex.ai"})
        role = obj(docs, "ClusterRole", "-console-scan-role")
        resources = set()
        for rule in role["rules"]:
            self.assertEqual(set(rule["verbs"]), {"get", "list"})
            for group in rule["apiGroups"]:
                resources.update((group, name) for name in rule["resources"])
        self.assertEqual(resources, {
            ("networking.k8s.io", "networkpolicies"),
            ("policy", "poddisruptionbudgets"),
            *(("rbac.authorization.k8s.io", name) for name in
              ("roles", "clusterroles", "rolebindings", "clusterrolebindings")),
        })
        binding = obj(docs, "ClusterRoleBinding", "-console-scan-rolebinding")
        self.assertEqual(binding["roleRef"]["name"], role["metadata"]["name"])
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount",
                         "name": pod["serviceAccountName"], "namespace": "phorvex-system"}])

    def test_default_chart_has_no_additional_trust(self):
        docs = render(ROOT / "phorvex/charts/phorvex", "--set", "phorvex.console.enabled=true",
                      "--set", "phorvex.audit.enabled=true",
                      "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
                      "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
                      "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
                      "--set", "phorvex.console.auditTransport.serverDNSName=source.example")
        pod = obj(docs, "Deployment", "-phorvex-console")["spec"]["template"]["spec"]
        env = {e["name"] for e in pod["containers"][0].get("env", [])}
        self.assertNotIn("PHORVEX_CONSOLE_ALB_ADDITIONAL_SIGNER_ARNS", env)


if __name__ == "__main__":
    unittest.main()
