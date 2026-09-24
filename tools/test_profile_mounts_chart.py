"""Render real chart authority for the four reviewed named YAML projections."""

import os
import subprocess
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[1] / "phorvex/charts/phorvex"
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


def render(*extra):
    return subprocess.run([*BASE, *extra], capture_output=True, text=True, timeout=30)


def console_doc(docs):
    return next(d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "phorvex-phorvex-console")


class ProfileMountChart(unittest.TestCase):
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
