"""Render real chart authority for reviewed named YAML projections."""

import base64
import hashlib
import json
import os
import subprocess
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[1] / "phorvex/charts/phorvex"
STACK = Path(__file__).resolve().parents[1] / "deploy/helm/phorvex-stack"
# Byte-identical copy of the reviewed grant overlay from the archived campaign package
# operator@65af1c99:workflow/campaigns/2026-09-23-catalogue-coverage/deployment/existing22-cpu-166/.
CPU_PACKAGE = Path(__file__).resolve().parent / "fixtures/catalogue-existing22-cpu-166"
HELM = os.environ.get("HELM_BIN", "helm")
BASE = [HELM, "template", "phorvex", str(CHART), "-n", "phorvex-system",
        "--set", "phorvex.console.enabled=true", "--set", "phorvex.audit.enabled=true",
        "--set", "phorvex.console.auditTransport.serverSecretName=audit-server",
        "--set", "phorvex.console.auditTransport.clientSecretName=audit-client",
        "--set", "phorvex.console.auditTransport.clientDNSName=console.example",
        "--set", "phorvex.console.auditTransport.serverDNSName=source.example"]
MONGO = ["--set", "phorvex.console.mongoExposure.enabled=true",
         "--set", "phorvex.console.mongoExposure.configMapName=reviewed-mongo",
         "--set-string", "phorvex.console.mongoExposure.profileSHA256=" + "a" * 64]
STATIC = ["--set", "phorvex.console.guardrailStatic.enabled=true",
          "--set", "phorvex.console.guardrailStatic.configMapName=reviewed-guardrail",
          "--set-string", "phorvex.console.guardrailStatic.profileSHA256=" + "b" * 64,
          "--set", "phorvex.console.guardrailStatic.guardrailJournalName=guardrail-journal",
          "--set", "phorvex.console.guardrailStatic.kvJournalName=kv-journal"]
NATS = ["--set", "phorvex.console.natsExposure.enabled=true",
        "--set", "phorvex.console.natsExposure.configMapName=reviewed-nats-baseline",
        "--set-string", "phorvex.console.natsExposure.profileSHA256=" + "c" * 64]
NATS_RESPONSE = ["--set", "phorvex.console.natsExposure.clientResponse.enabled=true",
                 "--set", "phorvex.console.natsExposure.clientResponse.configMapName=reviewed-nats-response",
                 "--set-string", "phorvex.console.natsExposure.clientResponse.profileSHA256=" + "d" * 64]
CPU_PROFILE = b"context: owned-cpu-test\nfixture: harmless\n"
CPU_MANIFEST = b'{"schema":"owned-cpu-test"}\n'
CPU_NAME = "reviewed-cpu-source"
CPU_FILENAME = "config.pod-bound-api-auth-response-cpu.yaml"
CPU_LEDGER = "phorvex-quarantine-capacity-" + "a" * 40
STACK_BASE = [HELM, "template", "phorvex", str(STACK), "-n", "phorvex-system",
              # The webhook generates a fresh certificate per offline render; disabling
              # it in this chart-diff test keeps unrelated resources comparable.
              "--set", "phorvex.phorvex.admissionWebhook.enabled=false"]
CPU_SOURCE = ["--set", "catalogueProfiles.podBoundTokenCPU.enabled=true",
              "--set", "catalogueProfiles.podBoundTokenCPU.configMapName=" + CPU_NAME,
              "--set-string", "catalogueProfiles.podBoundTokenCPU.profileBase64=" + base64.b64encode(CPU_PROFILE).decode(),
              "--set-string", "catalogueProfiles.podBoundTokenCPU.manifestBase64=" + base64.b64encode(CPU_MANIFEST).decode()]
CPU_CONSOLE = ["--set", "phorvex.phorvex.console.enabled=true",
               "--set", "phorvex.phorvex.audit.enabled=true",
               "--set", "phorvex.phorvex.console.auditTransport.serverSecretName=audit-server",
               "--set", "phorvex.phorvex.console.auditTransport.clientSecretName=audit-client",
               "--set", "phorvex.phorvex.console.auditTransport.clientDNSName=console.example",
               "--set", "phorvex.phorvex.console.auditTransport.serverDNSName=source.example",
               "--set", "phorvex.phorvex.console.podBoundTokenCPU.enabled=true",
               "--set", "phorvex.phorvex.console.podBoundTokenCPU.configMapName=" + CPU_NAME,
               "--set-string", "phorvex.phorvex.console.podBoundTokenCPU.profileSHA256=" + hashlib.sha256(CPU_PROFILE).hexdigest(),
               "--set", "phorvex.phorvex.console.podBoundTokenCPU.scrapeApproved=true",
               "--set", "phorvex.phorvex.prometheusUrl=http://prometheus.monitoring.svc:9090",
               "--set-string", "phorvex.phorvex.console.podBoundTokenCPU.quarantineCapacityLedgerName=" + CPU_LEDGER,
               "--api-versions", "monitoring.coreos.com/v1/PodMonitor"]


def render(*extra):
    return subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)


def render_stack(*extra):
    return subprocess.run([*STACK_BASE, *extra], capture_output=True, text=True, timeout=30)


def rendered_objects(result):
    if result.returncode:
        raise AssertionError(result.stderr)
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    return {(d["apiVersion"], d["kind"], d["metadata"].get("namespace", ""),
             d["metadata"]["name"]): d for d in docs}


def console_doc(docs):
    return next(d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "phorvex-phorvex-console")


class ProfileMountChart(unittest.TestCase):
    def test_guardrail_output_alone_receives_console_pod_identity(self):
        result = render(
            "--set", "phorvex.console.catalogueV1.enabled=true",
            "--set", "phorvex.console.catalogueV1.scopedToken.existingSecret=reviewed-token",
            "--set", "phorvex.trustedDetectors[0]=phorvex-system/phorvex-phorvex-console",
            "--set", "phorvex.console.guardrailOutput.enabled=true",
            "--set", "phorvex.console.guardrailOutput.configMapName=reviewed-output",
            "--set-string", "phorvex.console.guardrailOutput.profileSHA256=" + "a" * 64,
            "--set", "phorvex.console.guardrailOutput.outputPolicyConfigMapName=phorvex-output-policy-fixture",
            "--set", "phorvex.console.guardrailOutput.outputPolicyJournalName=phorvex-output-" + "b" * 32,
        )
        docs = list(rendered_objects(result).values())
        dep = console_doc(docs)
        container = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "console")
        env = {item["name"]: item for item in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_ENABLED"]["value"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED"]["value"], "false")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED"]["value"], "false")
        for name, field in (("PHORVEX_CONSOLE_POD_NAME", "metadata.name"),
                            ("PHORVEX_CONSOLE_POD_UID", "metadata.uid")):
            self.assertEqual(env[name], {"name": name, "valueFrom": {"fieldRef": {"fieldPath": field}}})

    def test_eks_cpu_activation_uses_reviewed_source_and_exact_authority(self):
        eks_values = yaml.safe_load((STACK / "values-eks.yaml").read_text())
        reviewed = eks_values["catalogueProfiles"]["podBoundTokenCPU"]
        profile = base64.b64decode(reviewed["profileBase64"], validate=True)
        manifest = base64.b64decode(reviewed["manifestBase64"], validate=True)
        reviewed_files = {CPU_FILENAME: profile, "manifest.json": manifest}
        reviewed_sha = hashlib.sha256(profile).hexdigest()
        result = render_stack("-f", str(STACK / "values-eks.yaml"),
                              "--api-versions", "monitoring.coreos.com/v1/PodMonitor")
        docs = list(rendered_objects(result).values())
        source = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == reviewed["configMapName"])
        self.assertEqual(source["metadata"]["namespace"], "phorvex-system")
        self.assertIs(source["immutable"], True)
        self.assertEqual(set(source["binaryData"]), set(reviewed_files))
        for filename, encoded in source["binaryData"].items():
            raw = base64.b64decode(encoded, validate=True)
            self.assertEqual(raw, reviewed_files[filename])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), reviewed_sha if filename == CPU_FILENAME else hashlib.sha256(manifest).hexdigest())

        console = console_doc(docs)["spec"]["template"]["spec"]
        container = console["containers"][0]
        env = {e["name"]: e["value"] for e in container["env"] if "value" in e}
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_PROFILE_SHA256"], reviewed_sha)
        volume = next(v for v in console["volumes"] if v["name"] == "pod-bound-token-cpu-reviewed-source")
        self.assertEqual(volume["configMap"]["name"], source["metadata"]["name"])
        self.assertEqual({i["key"] for i in volume["configMap"]["items"]}, set(source["binaryData"]))
        mounts = [m for m in container["volumeMounts"] if m["name"] == volume["name"]]
        self.assertEqual({m["subPath"] for m in mounts}, set(source["binaryData"]))
        self.assertTrue(all(m["readOnly"] for m in mounts))

        manager = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "phorvex-phorvex")
        args = manager["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--prometheus-url=http://kube-prom-stack-kube-prome-prometheus.monitoring.svc.cluster.local:9090", args)
        trusted = next(a for a in args if a.startswith("--trusted-detectors="))
        self.assertIn("phorvex-system/phorvex-phorvex-e2e-detector-cpu", trusted.split("=", 1)[1].split(","))
        def object_named(kind, name, namespace=None):
            return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name
                        and (namespace is None or d["metadata"].get("namespace") == namespace))
        object_named("ServiceAccount", "phorvex-phorvex-e2e-detector-cpu", "phorvex-system")
        object_named("ValidatingAdmissionPolicy", "phorvex-phorvex-e2e-detector-cpu")
        object_named("ValidatingAdmissionPolicyBinding", "phorvex-phorvex-e2e-detector-cpu")
        object_named("Role", "phorvex-phorvex-pod-bound-token-cpu-fixture", "phorvex-catalogue-cpu")
        object_named("RoleBinding", "phorvex-phorvex-pod-bound-token-cpu-fixture", "phorvex-catalogue-cpu")
        object_named("Role", "phorvex-phorvex-actuator-routine", "phorvex-catalogue-cpu")
        object_named("RoleBinding", "phorvex-phorvex-actuator-routine", "phorvex-catalogue-cpu")
        ledger = object_named("Role", "phorvex-phorvex-pod-bound-token-cpu-capacity-ledger", "phorvex-system")
        self.assertEqual(ledger["rules"], [{"apiGroups": [""], "resources": ["configmaps"],
                                            "resourceNames": ["phorvex-quarantine-capacity-d9372a8fb610e8aac611abf95dbad3f8874f09e4"], "verbs": ["get"]}])
        grants = json.loads(object_named("ConfigMap", "phorvex-phorvex-console-grants")["data"]["grants.json"])
        reviewed_grants = json.loads(yaml.safe_load((CPU_PACKAGE / "grant-overlay-proposed.yaml").read_text())["phorvex"]["phorvex"]["console"]["auth"]["grants"]["data"])
        # Preserve the original CPU-only receipt. Later reviewed activations add
        # exact journal access, the isolated CRM fixture tenant and the live CRM tenant
        # (CRM refund Live attack) to this caller.
        e2e = next(subject for subject in reviewed_grants["subjects"]
                   if subject["subject"] == "system:serviceaccount:phorvex-system:phorvex-phorvex-console-e2e")
        e2e["tenants"].extend(["phorvex-system", "phorvex-catalogue-crm", "crm"])
        self.assertEqual(grants, reviewed_grants)

    def test_umbrella_cpu_profile_is_default_off_and_adds_only_exact_source(self):
        before = rendered_objects(render_stack())
        after = rendered_objects(render_stack(*CPU_SOURCE))
        key = ("v1", "ConfigMap", "phorvex-system", CPU_NAME)
        self.assertNotIn(key, before)
        self.assertEqual(set(after) - set(before), {key})
        self.assertEqual(set(before) - set(after), set())
        self.assertEqual({k: after[k] for k in before}, before)
        source = after[key]
        self.assertEqual(set(source), {"apiVersion", "kind", "metadata", "immutable", "binaryData"})
        self.assertIs(source["immutable"], True)
        self.assertEqual(set(source["binaryData"]), {CPU_FILENAME, "manifest.json"})
        self.assertEqual(base64.b64decode(source["binaryData"][CPU_FILENAME], validate=True), CPU_PROFILE)
        self.assertEqual(base64.b64decode(source["binaryData"]["manifest.json"], validate=True), CPU_MANIFEST)

    def test_umbrella_cpu_source_matches_existing_console_mount_and_hash(self):
        before = rendered_objects(render_stack(*CPU_CONSOLE))
        after = rendered_objects(render_stack(*CPU_CONSOLE, *CPU_SOURCE))
        key = ("v1", "ConfigMap", "phorvex-system", CPU_NAME)
        self.assertEqual(set(after) - set(before), {key})
        self.assertEqual({k: after[k] for k in before}, before)
        console = console_doc(after.values())["spec"]["template"]["spec"]
        container = console["containers"][0]
        env = {e["name"]: e["value"] for e in container["env"] if "value" in e}
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_ENABLED"], "true")
        self.assertEqual(env["PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_PROFILE_SHA256"], hashlib.sha256(CPU_PROFILE).hexdigest())
        volume = next(v for v in console["volumes"] if v["name"] == "pod-bound-token-cpu-reviewed-source")
        self.assertEqual(volume["configMap"], {"name": CPU_NAME, "defaultMode": 0o440,
            "items": [{"key": CPU_FILENAME, "path": CPU_FILENAME}, {"key": "manifest.json", "path": "manifest.json"}]})
        mount = next(v for v in container["volumeMounts"] if v["name"] == volume["name"])
        self.assertTrue(mount["readOnly"])

    def test_umbrella_cpu_source_requires_exact_inputs_and_console_join(self):
        cases = [
            (CPU_SOURCE[:2], "configMapName is required"),
            ([*CPU_SOURCE[:2], "--set", "catalogueProfiles.podBoundTokenCPU.configMapName=Bad_Name"], "must be a DNS subdomain"),
            (CPU_SOURCE[:4], "profileBase64 is required"),
            ([*CPU_SOURCE[:4], "--set-string", "catalogueProfiles.podBoundTokenCPU.profileBase64=not-base64", *CPU_SOURCE[6:]], "canonical nonempty base64"),
            (CPU_SOURCE[:6], "manifestBase64 is required"),
            ([*CPU_SOURCE[:6], "--set-string", "catalogueProfiles.podBoundTokenCPU.manifestBase64=not-base64"], "canonical nonempty base64"),
            ([*CPU_SOURCE, *CPU_CONSOLE, "--set", "phorvex.phorvex.console.podBoundTokenCPU.configMapName=other-source"], "configMapName must match"),
            ([*CPU_SOURCE, *CPU_CONSOLE, "--set-string", "phorvex.phorvex.console.podBoundTokenCPU.profileSHA256=" + "b" * 64], "profileSHA256 must match"),
        ]
        for args, expected in cases:
            with self.subTest(expected=expected):
                result = render_stack(*args)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stderr)

    def test_default_off_adds_no_projection(self):
        result = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        spec = console_doc(docs)["spec"]["template"]["spec"]
        container = spec["containers"][0]
        env = {x["name"]: x["value"] for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED"], "false")
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_STATIC_ENABLED"], "false")
        self.assertEqual(env["PHORVEX_CONSOLE_NATS_EXPOSURE_ENABLED"], "false")
        self.assertEqual(env["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_ENABLED"], "false")
        for name in ("PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256", "PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256", "PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256", "PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256"):
            self.assertNotIn(name, env)
        for item in [*spec["volumes"], *container["volumeMounts"]]:
            self.assertNotIn(item["name"], {"mongo-exposure-reviewed-profile", "guardrail-static-reviewed-profile", "nats-exposure-reviewed-profile", "nats-client-response-reviewed-profile"})

    def test_enabled_projects_only_fixed_readonly_keys(self):
        result = render(*MONGO, *STATIC, *NATS, *NATS_RESPONSE)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        spec = console_doc(docs)["spec"]["template"]["spec"]
        container = spec["containers"][0]
        env = {x["name"]: x["value"] for x in container["env"]}
        self.assertEqual(env["PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256"], "a" * 64)
        self.assertEqual(env["PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256"], "b" * 64)
        self.assertEqual(env["PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256"], "c" * 64)
        self.assertEqual(env["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256"], "d" * 64)
        for slug, filename, cm in (("mongo-exposure-reviewed-profile", "config.mongo-exposure-baseline.yaml", "reviewed-mongo"),
                                    ("guardrail-static-reviewed-profile", "config.guardrail-confidentiality-static.yaml", "reviewed-guardrail"),
                                    ("nats-exposure-reviewed-profile", "config.nats-exposure-baseline.yaml", "reviewed-nats-baseline"),
                                    ("nats-client-response-reviewed-profile", "config.nats-client-response.yaml", "reviewed-nats-response")):
            volume = next(v for v in spec["volumes"] if v["name"] == slug)
            self.assertEqual(volume["configMap"], {"name": cm, "defaultMode": 0o440,
                "items": [{"key": filename, "path": filename}]})
            mount = next(v for v in container["volumeMounts"] if v["name"] == slug)
            self.assertEqual(mount, {"name": slug, "mountPath": "/data/build/test-harness/" + filename,
                                     "subPath": filename, "readOnly": True})

    def test_enabled_requires_reviewed_map_and_hash(self):
        static_journals = STATIC[-4:]
        cases = [
            (MONGO[:2], "console.mongoExposure.configMapName is required"),
            ([*MONGO[:2], "--set", "phorvex.console.mongoExposure.configMapName=Bad_Name"], "must be a DNS subdomain"),
            ([*MONGO[:2], "--set", "phorvex.console.mongoExposure.configMapName=" + "a" * 64], "DNS label exceeds 63"),
            ([*MONGO[:4]], "console.mongoExposure.profileSHA256 is required"),
            ([*MONGO[:4], "--set-string", "phorvex.console.mongoExposure.profileSHA256=" + "A" * 64], "must be 64 lowercase hex"),
            ([*STATIC[:2], *static_journals], "console.guardrailStatic.configMapName is required"),
            ([*STATIC[:2], *static_journals, "--set", "phorvex.console.guardrailStatic.configMapName=bad..name"], "must be a DNS subdomain"),
            ([*STATIC[:2], *static_journals, "--set", "phorvex.console.guardrailStatic.configMapName=" + "b" * 64], "DNS label exceeds 63"),
            ([*STATIC[:4], *static_journals], "console.guardrailStatic.profileSHA256 is required"),
            ([*STATIC[:4], *static_journals, "--set-string", "phorvex.console.guardrailStatic.profileSHA256=bad"], "must be 64 lowercase hex"),
            (NATS[:2], "console.natsExposure.configMapName is required"),
            ([*NATS[:2], "--set", "phorvex.console.natsExposure.configMapName=Bad_Name"], "must be a DNS subdomain"),
            (NATS[:4], "console.natsExposure.profileSHA256 is required"),
            ([*NATS[:4], "--set-string", "phorvex.console.natsExposure.profileSHA256=bad"], "must be 64 lowercase hex"),
            (NATS_RESPONSE, "natsExposure.clientResponse requires console.enabled and natsExposure.enabled"),
            ([*NATS, *NATS_RESPONSE[:2]], "console.natsExposure.clientResponse.configMapName is required"),
            ([*NATS, *NATS_RESPONSE[:2], "--set", "phorvex.console.natsExposure.clientResponse.configMapName=Bad_Name"], "must be a DNS subdomain"),
            ([*NATS, *NATS_RESPONSE[:4]], "console.natsExposure.clientResponse.profileSHA256 is required"),
            ([*NATS, *NATS_RESPONSE[:4], "--set-string", "phorvex.console.natsExposure.clientResponse.profileSHA256=bad"], "must be 64 lowercase hex"),
        ]
        for args, expected in cases:
            with self.subTest(expected=expected):
                result = render(*args)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
