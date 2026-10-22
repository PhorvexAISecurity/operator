"""Staging isolation, actual RBAC verbs, trust and console wiring contracts."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
HELM = shutil.which("helm")
CHARTS = {"manager": "phorvex/charts/phorvex", **{s: "deploy/charts/phorvex-" + s for s in ("brain", "sensor", "actuator", "attacks")}}


def render(service, namespace="phorvex-staging", staging=True, sets=()):
    cmd = [HELM, "template", "staging", str(ROOT / CHARTS[service]), "-n", namespace, "--kube-version", "1.31.0", "--api-versions", "monitoring.coreos.com/v1/PodMonitor", "--api-versions", "monitoring.coreos.com/v1/PrometheusRule"]
    if staging:
        cmd += ["-f", str(ROOT / "deploy/environments/staging/phorvex.yaml"), "-f", str(ROOT / f"deploy/environments/staging/{service}.yaml")]
    for value in sets:
        cmd += ["--set", value]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(result.stderr)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


@unittest.skipUnless(HELM, "helm required")
class NewstackChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = {service: render(service) for service in CHARTS}

    def test_all_namespaced_resources_stay_in_staging(self):
        for service, docs in self.docs.items():
            for doc in docs:
                self.assertEqual(doc["metadata"].get("namespace", "phorvex-staging"), "phorvex-staging", (service, doc))
                self.assertNotIn(doc["kind"], ("ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"))
                for subject in doc.get("subjects", []):
                    self.assertEqual(subject.get("namespace"), "phorvex-staging")

    def test_only_actuator_receives_routine_pod_mutations(self):
        for service in ("manager", "sensor", "actuator"):
            roles = [d for d in self.docs[service] if d["kind"] == "Role" and d["metadata"]["name"].endswith("actuator-routine")]
            self.assertEqual(len(roles), 1)
            rules = roles[0]["rules"]
            pod = next(r for r in rules if r["resources"] == ["pods"])
            self.assertEqual("delete" in pod["verbs"], service == "actuator")
            self.assertEqual(any("pods/eviction" in r["resources"] and "create" in r["verbs"] for r in rules), service == "actuator")

    def test_refund_guard_access_is_exact_and_staging_scoped(self):
        for service in ("manager", "sensor", "actuator"):
            role = next(d for d in self.docs[service] if d["kind"] == "Role" and d["metadata"]["name"].endswith("crm-refund-revoke"))
            self.assertEqual(role["rules"], [{"apiGroups": [""], "resourceNames": ["crm-refund-guard"], "resources": ["configmaps"], "verbs": ["get", "update"] if service == "actuator" else ["get"]}])

    def test_real_creator_and_native_backend_agree(self):
        for service, container_name in (("manager", "manager"), ("sensor", "sensor"), ("actuator", "actuator")):
            container = next(c for d in self.docs[service] if d["kind"] == "Deployment" for c in d["spec"]["template"]["spec"]["containers"] if c["name"] == container_name)
            self.assertIn("--trusted-detectors=phorvex-staging/staging-attacks", container["args"])
            self.assertIn("--policy-namespaces=phorvex-staging", container["args"])
            self.assertNotIn("--global-kill-switch=true", container["args"])
            env = {e["name"]: e.get("value") for e in container["env"]}
            self.assertEqual(env["PHORVEX_INJECTOR_IDENTITY"], "phorvex-staging/staging-attacks")
            self.assertEqual(env["PHORVEX_CRM_REFUND_NAMESPACE"], "phorvex-staging")
            if service in ("manager", "actuator"):
                self.assertEqual(env["PHORVEX_ACTUATOR"], "native")

    def test_fixture_producer_cannot_enact_rotation(self):
        role = next(d for d in self.docs["attacks"] if d["kind"] == "Role")
        for rule in role["rules"]:
            self.assertFalse(set(rule["resources"]) & {"secrets", "roles", "rolebindings", "namespaces", "pods/eviction"})
            if "pods" in rule["resources"]:
                self.assertTrue(set(rule["verbs"]) <= {"get", "list", "watch"})
        self.assertTrue(any(r["resources"] == ["deployments"] and "create" in r["verbs"] for r in role["rules"]))

    def test_console_is_remote_authenticated_and_audit_backed(self):
        console = next(d for d in self.docs["manager"] if d["kind"] == "Deployment" and d["metadata"]["name"] == "staging-phorvex-console")
        container = console["spec"]["template"]["spec"]["containers"][0]
        env = {e["name"]: e.get("value") for e in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_ATTACKS_URL"], "http://staging-attacks:8090")
        self.assertEqual(env["PHORVEX_NEWSTACK_LOOPS_ENABLED"], "true")
        service = next(d for d in self.docs["manager"] if d["kind"] == "Service" and d["metadata"]["name"] == "staging-phorvex-console")
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"][0]["port"], 80)
        self.assertFalse(any(d["kind"] == "Ingress" for d in self.docs["manager"]))
        self.assertTrue(any(a.startswith("-audit-source-url=https://staging-phorvex-audit-source.") for a in container["args"]))
        grants = next(d for d in self.docs["manager"] if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("console-grants"))
        subject = json.loads(grants["data"]["grants.json"])["subjects"][0]
        self.assertEqual(subject["tenants"], ["phorvex-staging"])
        self.assertEqual(subject["targets"], ["default"])
        self.assertEqual(subject["subject"], "system:serviceaccount:phorvex-staging:staging-phorvex-console-e2e")

    def test_opt_in_is_rejected_in_another_namespace(self):
        for service in ("manager", "sensor", "actuator", "attacks"):
            with self.assertRaisesRegex(ValueError, "phorvex-staging"):
                render(service, namespace="elsewhere")

    def test_other_environment_defaults_remain_off(self):
        for service in CHARTS:
            docs = render(service, namespace="other", staging=False)
            for doc in docs:
                self.assertNotIn("newstack", doc["metadata"]["name"])
                if doc["kind"] == "Deployment":
                    for c in doc["spec"]["template"]["spec"]["containers"]:
                        self.assertFalse(any(e["name"] in ("PHORVEX_NEWSTACK_LOOPS_ENABLED", "PHORVEX_CRM_REFUND_NAMESPACE") for e in c.get("env", [])))
            if service == "attacks":
                self.assertEqual(docs, [])


if __name__ == "__main__":
    unittest.main()
