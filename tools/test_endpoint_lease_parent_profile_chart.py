"""Focused default-off and digest-join checks for the parent chart source."""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/phorvex-stack"
HELM = os.environ.get("HELM_BIN", "helm")
PROFILE = b'{"version":1}'
DIGEST = hashlib.sha256(PROFILE).hexdigest()
NAME = "phorvex-catalogue-endpoint-lease-" + DIGEST[:12]


def render(values):
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory) / "overlay.json"
        overlay.write_text(json.dumps(values, sort_keys=True))
        return subprocess.run([str(HELM), "template", "profile-test", str(CHART),
                               "--values", str(overlay)], capture_output=True, text=True)


def values():
    return {
        "phoenix": {"enabled": False},
        "phorvex": {"enabled": False, "phorvex": {"console": {"endpointLease": {
            "enabled": True, "configMapName": NAME, "profileSHA256": DIGEST,
        }}}},
        "catalogueProfiles": {"endpointLease": {"enabled": True,
            "configMapName": NAME, "profileBase64": base64.b64encode(PROFILE).decode()}},
    }


class ParentProfileChartTests(unittest.TestCase):
    def test_default_off_does_not_render_profile(self):
        result = render({"phoenix": {"enabled": False}, "phorvex": {"enabled": False}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("phorvex-catalogue-endpoint-lease-", result.stdout)

    def test_positive_immutable_exact_bytes(self):
        result = render(values())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("name: \"" + NAME + "\"", result.stdout)
        self.assertIn("immutable: true", result.stdout)
        self.assertIn("profile.json: \"" + base64.b64encode(PROFILE).decode() + "\"", result.stdout)

    def test_missing_profile_bytes_refused(self):
        config = values()
        config["catalogueProfiles"]["endpointLease"]["profileBase64"] = ""
        result = render(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profileBase64 is required", result.stderr)

    def test_wrong_profile_digest_or_console_join_refused(self):
        config = values()
        config["catalogueProfiles"]["endpointLease"]["configMapName"] = NAME[:-1] + "0"
        result = render(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("name must match decoded profile SHA", result.stderr)
        config = values()
        config["phorvex"]["phorvex"]["console"]["endpointLease"]["profileSHA256"] = "0" * 64
        result = render(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profileSHA256 must match source", result.stderr)


if __name__ == "__main__":
    unittest.main()
