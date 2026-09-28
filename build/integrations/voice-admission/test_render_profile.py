import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import render_profile as renderer


class ProfileBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dep = "11111111-1111-1111-1111-111111111111"
        self.owner = {"apiVersion": "apps/v1", "kind": "Deployment", "name": "voice-bot", "uid": self.dep, "controller": True}
        for directory in ("build/integrations/voice-admission", "build/integrations/voice-memory", "phorvex/internal/console"):
            (self.root / directory).mkdir(parents=True)
        app = self.root / "build/integrations/voice-admission"
        (app / "entry.py").write_text("# reviewed offline fixture entry\n")
        (app / "policy.py").write_text("# reviewed offline fixture policy\n")
        for name in ("bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"):
            shutil.copyfile(renderer.ROOT / "build/integrations/voice-memory" / name, self.root / "build/integrations/voice-memory" / name)
        for name in ("voice_admission_probe.py", "voice_mcp_benign.ulaw"):
            shutil.copyfile(renderer.ROOT / "phorvex/internal/console" / name, self.root / "phorvex/internal/console" / name)
        profile = {"version": 1, "deploymentUID": self.dep, "publicHost": "voicebot.phorvex.ai", "websocketSigningURLs": ["wss://voicebot.phorvex.ai/ws"],
                   "webhookSigningURL": "https://voicebot.phorvex.ai/", "twilioSecretName": "voice-secrets", "authTokenSHA256": "a" * 64}
        data = {"entry.py": (app / "entry.py").read_text(), "policy.py": (app / "policy.py").read_text(), "auth-profile.json": renderer.canonical(profile).decode()}
        source_sha = renderer.sha((data["entry.py"] + "\0" + data["policy.py"] + "\0" + data["auth-profile.json"]).encode())
        self.wrapper = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True, "metadata": {
            "namespace": "voice", "name": "voice-admission-source-" + source_sha[:12], "uid": "22222222-2222-2222-2222-222222222222", "resourceVersion": "1", "ownerReferences": [self.owner]}, "data": data}
        legacy = self.root / "build/integrations/voice-memory"
        legacy_sha = renderer.sha(b"\0".join((legacy / name).read_bytes() for name in ("bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py")))
        rule = {"version": 1, "deploymentUID": self.dep, "securityPolicyUID": "33333333-3333-3333-3333-333333333333", "wrapperCMUID": self.wrapper["metadata"]["uid"],
                "admissionSourceSHA256": renderer.sha((data["entry.py"] + "\0" + data["policy.py"]).encode()), "legacyBundleSHA256": legacy_sha,
                "authProfileSHA256": renderer.sha(data["auth-profile.json"].encode()), "revision": 0, "mode": "observe", "operationId": ""}
        self.policy = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "voice", "name": "voice-session-admission-policy",
            "uid": "44444444-4444-4444-4444-444444444444", "resourceVersion": "2", "ownerReferences": [self.owner]}, "data": {"rule.json": renderer.canonical(rule).decode()}}

    def render(self, wrapper=None, policy=None):
        return renderer.render(wrapper or self.wrapper, policy or self.policy, "https://audit.invalid:8445", "audit.invalid", self.root)

    def test_only_new_console_profile_and_pins_emitted(self):
        original = copy.deepcopy(self.policy)
        raw, cm, values = self.render()
        profile = json.loads(raw)
        self.assertEqual(profile["policyCMUID"], self.policy["metadata"]["uid"])
        self.assertEqual(profile["probeSHA256"], renderer.sha((self.root / "phorvex/internal/console/voice_admission_probe.py").read_bytes()))
        self.assertEqual(cm["data"]["profile.json"], raw.decode())
        self.assertTrue(cm["immutable"])
        self.assertEqual(set(values["phorvex"]), {"voiceAdmission", "console"})
        self.assertEqual(self.policy, original)
        self.assertNotIn("TWILIO_AUTH_TOKEN", raw.decode())

    def test_tampered_wrapper_and_legacy_rejected(self):
        changed = copy.deepcopy(self.wrapper); changed["data"]["entry.py"] += "# changed\n"
        with self.assertRaises(ValueError): self.render(wrapper=changed)
        (self.root / "build/integrations/voice-memory/bot.py").write_text("# changed\n")
        with self.assertRaises(ValueError): self.render()

    def test_owner_rule_and_canonical_identity_mismatch_rejected(self):
        for mutate in (lambda p: p["metadata"].update(uid=""), lambda p: p["metadata"].update(ownerReferences=[]),
                       lambda p: p["data"].update({"rule.json": p["data"]["rule.json"] + "\n"})):
            changed = copy.deepcopy(self.policy); mutate(changed)
            with self.assertRaises(ValueError): self.render(policy=changed)
        changed = copy.deepcopy(self.policy); rule = json.loads(changed["data"]["rule.json"])
        rule.update(mode="require-twilio-signature", revision=1, operationId="f" * 64)
        changed["data"]["rule.json"] = renderer.canonical(rule).decode()
        with self.assertRaises(ValueError): self.render(policy=changed)


class ChartBoundaries(unittest.TestCase):
    def test_opt_in_scoped_roles_and_feature_off_default(self):
        helm = Path("/opt/phorvex-tools/helm")
        if not helm.is_file(): self.skipTest("Helm unavailable")
        args = [str(helm), "template", "phorvex", str(renderer.ROOT / "phorvex/charts/phorvex"), "--namespace", "phorvex-system"]
        default = subprocess.run(args, check=True, capture_output=True, text=True).stdout
        self.assertNotIn("name: phorvex-phorvex-voice-admission\n", default)
        values = {"phorvex.actuator": "native", "phorvex.voiceAdmission.enabled": "true", "phorvex.voiceAdmission.sourceConfigMapName": "voice-admission-source-aaaaaaaaaaaa",
                  "phorvex.voiceAdmission.legacyConfigMapName": "voice-memory-source-bbbbbbbbbbbb", "phorvex.console.enabled": "true", "phorvex.audit.enabled": "true",
                  "phorvex.console.auditTransport.serverDNSName": "phorvex-phorvex-audit-source.phorvex-system.svc", "phorvex.console.state.allowEphemeral": "true", "phorvex.console.auditTransport.clientDNSName": "phorvex-console.test.invalid",
                  "phorvex.console.auditTransport.serverSecretName": "audit-server-test", "phorvex.console.auditTransport.clientSecretName": "audit-client-test"}
        extra = sum((["--set", key + "=" + value] for key, value in values.items()), [])
        enabled = subprocess.run(args + extra, check=True, capture_output=True, text=True).stdout
        self.assertIn("name: phorvex-phorvex-voice-admission\n", enabled)
        self.assertIn('resourceNames: ["voice-session-admission-policy"]\n  verbs: ["get", "update"]', enabled)
        self.assertIn('resourceNames: ["voice-memory-state-token"]', enabled)
        self.assertNotIn('resourceNames: ["voice-secrets"]', enabled)
        # Native enabled also gives legacy Console snapshot authority while the
        # new trial remains disabled until its reviewed profile is installed.
        self.assertIn("name: phorvex-phorvex-console-voice-admission\n", enabled)
        trial_values = {
            "phorvex.console.voiceAdmissionLive.enabled": "true",
            "phorvex.console.voiceAdmissionLive.sourceConfigMapName": values["phorvex.voiceAdmission.sourceConfigMapName"],
            "phorvex.console.voiceAdmissionLive.legacyConfigMapName": values["phorvex.voiceAdmission.legacyConfigMapName"],
            "phorvex.console.voiceAdmissionLive.configMapName": "phorvex-voice-admission-profile-cccccccccccc",
            "phorvex.console.voiceAdmissionLive.profileSHA256": "c" * 64,
            "phorvex.trustedDetectors[0]": renderer.CREATOR,
        }
        trial = sum((["--set-string", key + "=" + value] if key.endswith("SHA256") or "trustedDetectors" in key else ["--set", key + "=" + value]
                     for key, value in trial_values.items()), [])
        active = subprocess.run(args + extra + trial, check=True, capture_output=True, text=True).stdout
        self.assertIn("PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_PROFILE_SHA256", active)
        self.assertIn("mountPath: /etc/phorvex-voice-admission/profile.json", active)
        mismatched = subprocess.run(args + extra + trial + ["--set", "phorvex.console.voiceAdmissionLive.sourceConfigMapName=other-source"], capture_output=True, text=True)
        self.assertNotEqual(mismatched.returncode, 0)
        missing = subprocess.run(args + ["--set", "phorvex.voiceAdmission.enabled=true"], capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)


if __name__ == "__main__":
    unittest.main()
