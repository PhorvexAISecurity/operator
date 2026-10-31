"""Render the three phorvex-image catalogue families and prove every rendered fixture
container selects the EXACT supplied image digest and a valid command/probe.

These tests drive the real operator render path (tools/render_catalogue_staging_values.py)
and `helm template deploy/charts/phorvex-attacks`, exactly as the staging window switch
does, so they prove the datastore, serving-rate and serving-kv family manifests consume
the phorvex fixture image the way the campaign needs.
"""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RENDER = ROOT / "tools/render_catalogue_staging_values.py"
CHART = ROOT / "deploy/charts/phorvex-attacks"
HELM = os.environ.get("HELM_BIN") or shutil.which("helm")

REGISTRY = "753556437180.dkr.ecr.us-east-2.amazonaws.com"
PHORVEX_SHA = "b" * 64
PHORVEX_IMAGE = f"{REGISTRY}/phorvex/staging/phorvex-fixture@sha256:{PHORVEX_SHA}"
PYTHON_IMAGE = f"{REGISTRY}/phorvex/staging/catalogue-workload@sha256:{'c' * 64}"
FIXTURE_COMMANDS = {"/ragstore-fixture", "/cost-admission", "/cost-load-detector"}


def render_overlay(profile: str, phorvex_image: str, python_image: str | None = None) -> str:
    command = ["python3", str(RENDER), "--profile", profile, "--phorvex-image", phorvex_image]
    if python_image is not None:
        command += ["--python-image", python_image]
    return subprocess.run(command, check=True, text=True, capture_output=True, cwd=ROOT).stdout


def helm_template(overlay_yaml: str) -> list[dict]:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as overlay:
        overlay.write(overlay_yaml)
        overlay.flush()
        rendered = subprocess.run(
            [
                HELM, "template", "staging", str(CHART),
                "--namespace", "phorvex-staging", "--skip-crds",
                "-f", str(ROOT / "deploy/environments/staging/phorvex.yaml"),
                "-f", str(ROOT / "deploy/environments/staging/attacks.yaml"),
                "-f", overlay.name,
            ],
            check=True, text=True, capture_output=True, cwd=ROOT,
        ).stdout
    return [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]


def pod_containers(docs: list[dict]):
    """Yield (namespace, workload-name, replicas, container) for every pod container."""
    for doc in docs:
        kind = doc.get("kind")
        meta = doc.get("metadata", {})
        spec = doc.get("spec", {})
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            pod = spec.get("template", {}).get("spec", {})
            replicas = spec.get("replicas")
        elif kind == "Pod":
            pod = spec
            replicas = None
        else:
            continue
        for container in pod.get("containers", []):
            yield meta.get("namespace"), meta.get("name"), replicas, container


@unittest.skipUnless(HELM, "helm is not installed (set HELM_BIN)")
class PhorvexFixtureRenderTests(unittest.TestCase):
    def _render(self, profile, python_image=None):
        return helm_template(render_overlay(profile, PHORVEX_IMAGE, python_image))

    def test_every_phorvex_container_uses_the_exact_digest_and_a_valid_command(self):
        # Across all three families, any container that runs on the phorvex fixture image
        # must carry the EXACT supplied digest, and any container running one of the three
        # fixture commands must be on that exact image.
        for profile, python_image in (
            ("datastore", None),
            ("serving-rate", None),
            ("serving-kv", PYTHON_IMAGE),
        ):
            with self.subTest(profile=profile):
                docs = self._render(profile, python_image)
                phorvex_users = 0
                for _, name, _, container in pod_containers(docs):
                    command = container.get("command") or []
                    image = container.get("image")
                    if image == PHORVEX_IMAGE:
                        phorvex_users += 1
                        # Either an explicit fixture command, or the serving-kv witness
                        # that inherits the image's default entrypoint with a legacy arg.
                        if command:
                            self.assertEqual(len(command), 1, (name, command))
                            self.assertIn(command[0], FIXTURE_COMMANDS, (name, command))
                    if command and command[0] in FIXTURE_COMMANDS:
                        self.assertEqual(
                            image, PHORVEX_IMAGE,
                            f"{profile}/{name} runs {command[0]} off the wrong image {image!r}",
                        )
                self.assertGreater(phorvex_users, 0, f"{profile} rendered no phorvex container")

    def test_datastore_rag_store_command_probe_and_hardening(self):
        docs = self._render("datastore")
        store = next(
            c for ns, name, _, c in pod_containers(docs)
            if ns == "p2-demo" and name == "rag-store"
        )
        self.assertEqual(store["image"], PHORVEX_IMAGE)
        self.assertEqual(store["command"], ["/ragstore-fixture"])
        self.assertEqual(store["readinessProbe"]["httpGet"], {"path": "/healthz", "port": "http"})
        self.assertEqual(store["ports"][0]["containerPort"], 8080)
        self.assertTrue(store["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(store["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(store["securityContext"]["capabilities"]["drop"], ["ALL"])

    def test_serving_rate_three_roles_and_proxy_image_wiring(self):
        docs = self._render("serving-rate")
        by_name = {
            name: c for ns, name, _, c in pod_containers(docs)
            if ns == "p5-demo" and name in {"rate-target", "rate-admission", "rate-detector"}
        }
        self.assertEqual(by_name["rate-target"]["command"], ["/ragstore-fixture"])
        self.assertEqual(by_name["rate-admission"]["command"], ["/cost-admission"])
        self.assertEqual(by_name["rate-detector"]["command"], ["/cost-load-detector"])
        for container in by_name.values():
            self.assertEqual(container["image"], PHORVEX_IMAGE)
        detector_env = {e["name"]: e.get("value") for e in by_name["rate-detector"].get("env", [])}
        self.assertEqual(detector_env["PHORVEX_THROTTLE_PROXY_IMAGE"], PHORVEX_IMAGE)
        self.assertEqual(detector_env["PHORVEX_THROTTLE_SOURCE_SHA256"], PHORVEX_SHA)
        # The budget ConfigMap must carry the same source sha and proxy image.
        budget = next(
            d for d in self._render_docs("serving-rate")
            if d.get("kind") == "ConfigMap" and d.get("metadata", {}).get("name") == "phorvex-serving-rate-budget"
        )
        state = yaml.safe_load(budget["data"]["state.json"])
        self.assertEqual(state["sourceSHA256"], PHORVEX_SHA)
        self.assertEqual(state["proxyImage"], PHORVEX_IMAGE)

    def test_serving_rate_admission_env_and_command_match_the_parameterized_contract(self):
        # The admission proxy must receive its namespace and Pod UID from the downward API
        # and forward to the p5-demo rate-target backend — the exact env the parameterized
        # /cost-admission binary resolves, with the backend in its own namespace so the
        # binary's cross-namespace guard accepts it.
        docs = self._render("serving-rate")
        admission = next(
            c for ns, name, _, c in pod_containers(docs)
            if ns == "p5-demo" and name == "rate-admission"
        )
        self.assertEqual(admission["command"], ["/cost-admission"])
        self.assertEqual(admission["image"], PHORVEX_IMAGE)
        env = {e["name"]: e for e in admission.get("env", [])}
        self.assertEqual(
            env["POD_NAMESPACE"].get("valueFrom", {}).get("fieldRef", {}).get("fieldPath"),
            "metadata.namespace",
        )
        self.assertEqual(
            env["POD_UID"].get("valueFrom", {}).get("fieldRef", {}).get("fieldPath"),
            "metadata.uid",
        )
        backend = env["PHORVEX_THROTTLE_BACKEND"].get("value")
        self.assertEqual(backend, "http://rate-target-backend.p5-demo.svc:8080")
        # Backend host is <service>.<namespace>.svc inside the admission pod's own namespace.
        self.assertEqual(backend.split("//", 1)[1].split(":")[0].split("."), ["rate-target-backend", "p5-demo", "svc"])
        # The backend workload (rate-target) runs the fixture HTTP server off the same image.
        target = next(
            c for ns, name, _, c in pod_containers(docs)
            if ns == "p5-demo" and name == "rate-target"
        )
        self.assertEqual(target["command"], ["/ragstore-fixture"])
        self.assertEqual(target["image"], PHORVEX_IMAGE)

    def _render_docs(self, profile, python_image=None):
        return self._render(profile, python_image)

    def test_serving_kv_witness_pins_phorvex_and_server_stays_python(self):
        docs = self._render("serving-kv", PYTHON_IMAGE)
        witness = None
        kv_server = None
        for ns, name, replicas, container in pod_containers(docs):
            if name == "p6-actuator":
                witness = (replicas, container)
            if ns == "p6-demo" and name == "kv-serving":
                kv_server = container
        self.assertIsNotNone(witness, "serving-kv rendered no p6-actuator witness")
        replicas, container = witness
        self.assertEqual(replicas, 0)
        self.assertEqual(container["image"], PHORVEX_IMAGE)
        self.assertEqual(container.get("args"), ["--serving-security-mode=legacy-plaintext"])
        self.assertIsNone(container.get("command"))
        self.assertIsNotNone(kv_server, "serving-kv rendered no kv-serving server")
        # The KV serving workload itself stays on the python fixture image, not phorvex.
        self.assertEqual(kv_server["image"], PYTHON_IMAGE)
        self.assertEqual(kv_server["command"][0], "python3")

    def test_render_requires_a_valid_phorvex_digest(self):
        for profile in ("datastore", "serving-rate", "serving-kv"):
            with self.subTest(profile=profile):
                missing = subprocess.run(
                    ["python3", str(RENDER), "--profile", profile, "--python-image", PYTHON_IMAGE],
                    text=True, capture_output=True, cwd=ROOT,
                )
                self.assertNotEqual(missing.returncode, 0, missing.stdout)
                self.assertIn("phorvex-image", missing.stderr)
                malformed = subprocess.run(
                    [
                        "python3", str(RENDER), "--profile", profile,
                        "--phorvex-image", f"{REGISTRY}/phorvex/staging/phorvex-fixture:mutable-tag",
                        "--python-image", PYTHON_IMAGE,
                    ],
                    text=True, capture_output=True, cwd=ROOT,
                )
                self.assertNotEqual(malformed.returncode, 0, malformed.stdout)
                self.assertIn("repository@sha256", malformed.stderr)


if __name__ == "__main__":
    unittest.main()
