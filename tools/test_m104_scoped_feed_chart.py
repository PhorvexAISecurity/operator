"""Render controls for bounded scoped EPSS producer and authoritative consumer."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "phorvex/charts/phorvex"
HELM = os.environ.get("HELM_BIN", "helm")
DIGEST = "registry.example/public@sha256:" + "a" * 64


def render(values, success=True):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        result = subprocess.run([HELM, "template", "m104", str(CHART), "-n", "operator", "-f", f.name], cwd=ROOT, text=True, capture_output=True)
    if success and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    if not success:
        if not result.returncode:
            raise AssertionError("invalid M104 values rendered")
        return result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


class M104ScopedFeedChartTest(unittest.TestCase):
    def test_scoped_authority_uses_namespaced_roles_and_exact_args(self):
        values = {"phorvex": {"epss": {"enabled": True, "authoritative": True, "feed": {
            "enabled": True, "scopeNamespaces": ["fixture-a", "fixture-b"], "scopeDigests": [DIGEST]}}}}
        docs = render(values)
        pod_roles = [d for d in docs if d["kind"] == "Role" and "epss-feed-pods" in d["metadata"]["name"]]
        self.assertEqual({d["metadata"]["namespace"] for d in pod_roles}, {"fixture-a", "fixture-b"})
        feed_clusters = [d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"].endswith("epss-feed")]
        self.assertEqual(feed_clusters, [])
        deployment = next(d for d in docs if d["kind"] == "Deployment")
        args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--epss-authoritative=true", args)
        self.assertIn("--epss-authoritative-scope-digests=" + DIGEST, args)
        cron = next(d for d in docs if d["kind"] == "CronJob")
        feed_args = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--epss-feed-scope-namespaces=fixture-a,fixture-b", feed_args)
        self.assertIn("--epss-feed-scope-digests=" + DIGEST, feed_args)

    def test_authoritative_or_half_scope_refuses_render(self):
        err = render({"phorvex": {"epss": {"enabled": True, "authoritative": True}}}, False)
        self.assertIn("authoritative EPSS requires", err)
        err = render({"phorvex": {"epss": {"enabled": True, "feed": {"enabled": True, "scopeNamespaces": ["fixture"]}}}}, False)
        self.assertIn("requires both", err)


if __name__ == "__main__":
    unittest.main()
