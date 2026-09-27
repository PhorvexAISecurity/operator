"""Offline tests for the exact Voice output console delivery profile."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from render_output_profile import ROOT, render


AUDIT_URL = "https://phorvex-phorvex-audit-source.phorvex-system.svc:8445"
AUDIT_DNS = "phorvex-phorvex-audit-source.phorvex-system.svc"


class VoiceOutputProfileTest(unittest.TestCase):
    def test_exact_source_probe_audio_and_audit_identity(self):
        raw, cm, digest = render(AUDIT_URL, AUDIT_DNS)
        profile = json.loads(raw)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(profile["auditSourceIdentity"], AUDIT_URL + "|" + AUDIT_DNS)
        self.assertEqual(profile["maxRunSeconds"], 900)
        self.assertEqual(cm["metadata"]["namespace"], "phorvex-system")
        self.assertEqual(cm["data"]["profile.json"], raw.decode())
        self.assertTrue(cm["immutable"])
        self.assertEqual(profile["probeSHA256"], hashlib.sha256(
            (ROOT / "phorvex/internal/console/voice_output_probe.py").read_bytes()).hexdigest())

    def test_changed_source_or_clip_and_bad_audit_refuse(self):
        for url, dns in (("http://phorvex.example:8445", AUDIT_DNS),
                         (AUDIT_URL + "/unreviewed", AUDIT_DNS), (AUDIT_URL, "")):
            with self.assertRaises(ValueError):
                render(url, dns)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for rel in ("build/integrations/voice-memory/bot.py",
                        "build/integrations/voice-memory/voice_memory_policy.py",
                        "build/integrations/voice-memory/voice_output_policy.py",
                        "phorvex/internal/console/voice_output_probe.py",
                        "phorvex/internal/console/voice_output_attack.ulaw",
                        "phorvex/internal/console/voice_output_benign.ulaw"):
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / rel, target)
            source = root / "build/integrations/voice-memory/bot.py"
            source.write_bytes(source.read_bytes() + b"\n# changed\n")
            with self.assertRaisesRegex(ValueError, "source differs"):
                render(AUDIT_URL, AUDIT_DNS, root)
            shutil.copy2(ROOT / "build/integrations/voice-memory/bot.py", source)
            clip = root / "phorvex/internal/console/voice_output_benign.ulaw"
            clip.write_bytes(clip.read_bytes() + b"x")
            with self.assertRaisesRegex(ValueError, "clip differs"):
                render(AUDIT_URL, AUDIT_DNS, root)


if __name__ == "__main__":
    unittest.main()
