"""Real renderer/prepare to frozen guardrail-profile source join, without Kubernetes."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import prepare
import test_prepare


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LegacyFourSourceJoinTest(unittest.TestCase):
    def setUp(self):
        self.fixture = test_prepare.PrepareTest("test_exact_get_protocol_and_private_candidate")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.reset = load_module("real_reset_renderer", prepare.drain_render.BASE_RENDER_PATH)
        self.profile = load_module("real_guardrail_profile_renderer",
                                   prepare.drain_render.ROOT / "integrations/vllm-live-runtime/render_guardrail_profile.py")
        objects = self.fixture.objects
        dep = objects["deployment vllm"]
        dep["spec"]["template"]["spec"] = {
            "serviceAccountName": "default",
            "containers": [
                {"name": "vllm", "image": self.reset.LIVE_BASE_IMAGE,
                 "args": ["--model", "Qwen/Qwen2.5-7B-Instruct-AWQ", "--enable-lora", "--port", "8001"],
                 "env": [{"name": "VLLM_SERVER_DEV_MODE", "value": "1"},
                         {"name": "VLLM_ALLOW_RUNTIME_LORA_UPDATING", "value": "1"}],
                 **{name: {"httpGet": {"path": "/health", "port": 8001}}
                    for name in ("startupProbe", "readinessProbe", "livenessProbe")}},
                {"name": "guardrail", "image": "python:3.11-slim",
                 "command": ["sh", "-c", "pip install stuff && exec python /src/guardrail_proxy.py"],
                 "ports": [{"containerPort": 8000}],
                 "volumeMounts": [{"name": "guardrail-src", "mountPath": "/src"}]},
            ],
            "volumes": [{"name": "guardrail-src", "configMap": {"name": "guardrail-proxy"}}],
        }
        objects["pod vllm-1"]["spec"] = copy.deepcopy(dep["spec"]["template"]["spec"])
        objects["configmap guardrail-proxy"]["data"] = {"guardrail_proxy.py": "old"}
        objects["service vllm"]["spec"]["ports"] = [{"port": 8000, "targetPort": 8000}]
        self.fixture.data.write_text(json.dumps(objects))

    def run_prepare(self, out: Path, source_root: Path | None = None):
        patches = [mock.patch.object(prepare.drain_render, "base_renderer", return_value=self.reset),
                   mock.patch.object(self.reset, "ORIGINAL_PROXY_SHA256", hashlib.sha256(b"old").hexdigest())]
        if source_root is not None:
            patches += [mock.patch.object(self.reset, "PROXY", source_root / "build/test-harness/guardrail/guardrail_proxy.py"),
                        mock.patch.object(self.reset, "DUAL", source_root / "build/integrations/vllm-live-runtime/dual_server.py"),
                        mock.patch.object(prepare.drain_render, "GUARDRAIL", source_root / "build/test-harness/guardrail")]
        with patches[0], patches[1]:
            if source_root is None:
                return prepare.prepare("reviewed-dev", out, self.fixture.receipt, str(self.fixture.kubectl))
            with patches[2], patches[3], patches[4]:
                return prepare.prepare("reviewed-dev", out, self.fixture.receipt, str(self.fixture.kubectl))

    def test_current_main_hybrid_four_source_fails_before_candidate(self):
        self.assertNotEqual(self.reset.sha(self.reset.PROXY.read_bytes()), self.reset.LEGACY_PROXY_SHA256)
        self.assertNotEqual(self.reset.sha(self.reset.DUAL.read_bytes()), self.reset.LEGACY_DUAL_SHA256)
        out = self.fixture.root / "hybrid-refused"
        with self.assertRaisesRegex(ValueError, "reviewed checkout 440da58d"):
            self.run_prepare(out)
        self.assertFalse(out.exists())

    def test_reviewed_440_checkout_prepares_four_source_profile_join(self):
        # Opt-in local, read-only positive: the retained PR365 checkout supplies
        # real historical source bytes without requiring git history/network in CI.
        root_text = os.environ.get("PHORVEX_LEGACY_SOURCE_ROOT", "")
        if not root_text:
            self.skipTest("set PHORVEX_LEGACY_SOURCE_ROOT to a reviewed PR365 checkout")
        root = Path(root_text).resolve(strict=True)
        proxy = root / "build/test-harness/guardrail/guardrail_proxy.py"
        dual = root / "build/integrations/vllm-live-runtime/dual_server.py"
        self.assertEqual(self.reset.sha(proxy.read_bytes()), self.reset.LEGACY_PROXY_SHA256)
        self.assertEqual(self.reset.sha(dual.read_bytes()), self.reset.LEGACY_DUAL_SHA256)
        out = self.fixture.root / "reviewed-candidate"
        self.run_prepare(out, root)
        candidate = json.loads((out / "configmap.candidate.json").read_bytes())
        self.assertEqual(set(candidate["data"]), set(self.profile.LEGACY_SOURCE_SHA256) | set(self.profile.DRAIN_SOURCE_SHA256))
        with mock.patch.object(self.profile, "PROXY", proxy), mock.patch.object(self.profile, "DUAL", dual):
            profile_test = load_module("real_profile_fixture",
                prepare.drain_render.ROOT / "integrations/vllm-live-runtime/test_render_guardrail_profile.py")
            objects = profile_test.fixture()
            objects["source"]["data"] = candidate["data"]
            rendered, _, _ = self.profile.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test")
        fixture = json.loads(rendered)["guardrailAvailabilityFixture"]
        self.assertEqual(fixture["sourceSHA256"], self.profile.LEGACY_SOURCE_SHA256["guardrail_proxy.py"])
        self.assertEqual(fixture["boundarySourceSHA256"], self.profile.LEGACY_SOURCE_SHA256["dual_server.py"])
        self.assertNotIn("retainedCallerLeaseProfileSHA256", fixture)


if __name__ == "__main__":
    unittest.main()
