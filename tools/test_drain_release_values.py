import json
import os
import subprocess
import sys
import tempfile
import shutil
import yaml
from unittest.mock import patch
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_values", ROOT / "deploy/ci/update-release-values.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A, B = "sha256:" + "a" * 64, "sha256:" + "b" * 64
S, T = "1" * 40, "2" * 40
SOURCE = '''manager:
  tag: "old" # ci:phorvex-tag
  releaseDigest: "sha256:''' + "a" * 64 + '''" # ci:phorvex-digest
  releaseSourceSHA: "''' + S + '''" # ci:phorvex-source
console:
  tag: "old" # ci:console-tag
  releaseDigest: "sha256:''' + "b" * 64 + '''" # ci:console-digest
  releaseSourceSHA: "''' + T + '''" # ci:console-source
'''

class ReleaseValues(unittest.TestCase):
    def update(self, markers, **kwargs):
        values = dict(source_mode="digest", source_sha=S, release_from="",
                      digests={"ci:phorvex-tag": A, "ci:console-tag": B},
                      resolve=lambda ref: (A if "/phorvex:" in ref else B, S))
        values.update(kwargs)
        return m.update(SOURCE, "next", "registry.invalid", markers, **values)

    def test_single_component_preserves_other_source_and_digest_exactly(self):
        result = self.update(["ci:phorvex-tag"])
        self.assertEqual(result.split("console:")[1], SOURCE.split("console:")[1])
        self.assertIn('tag: "next" # ci:phorvex-tag', result)
        self.assertIn('"' + A + '" # ci:phorvex-digest', result)

    def test_both_success_and_actual_source_not_current_release_tag(self):
        result = self.update(list(m.COMPONENTS))
        self.assertEqual(result.count('tag: "next"'), 2)
        self.assertEqual(result.count('"' + S + '" # ci:'), 2)

    def test_forced_tag_uses_artifact_build_source_for_each_component(self):
        calls = []
        def resolve(ref):
            calls.append(ref)
            return (A, S) if "/phorvex:" in ref else (B, T)
        result = self.update(list(m.COMPONENTS), source_mode="tag", source_sha="9"*40,
                             release_from="source-tag", resolve=resolve)
        self.assertEqual(result.count('"' + T + '" # ci:console-source'), 1)
        self.assertEqual(len(calls), 4)

    def test_missing_wrong_digest_or_build_source_refuses(self):
        for values in ({"digests": {}}, {"resolve": lambda ref: (B, S)},
                       {"resolve": lambda ref: (A, T)}, {"source_sha": ""}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.update(["ci:phorvex-tag"], **values)

    def test_second_component_failure_never_returns_partial_values(self):
        def resolve(ref):
            if "/phorvex-console:" in ref:
                raise ValueError("missing second manifest")
            return A, S
        with self.assertRaises(ValueError):
            self.update(list(m.COMPONENTS), resolve=resolve)
        self.assertIn('tag: "old"', SOURCE)

    def test_bad_marker_or_duplicate_or_absent_authority_marker_refuses(self):
        for markers in ([], ["foreign"], ["ci:console-tag"]*2):
            with self.assertRaises(ValueError): self.update(markers)
        for src in (SOURCE.replace("ci:phorvex-digest", "foreign"), SOURCE + SOURCE):
            with self.assertRaises(ValueError):
                m.update(src, "next", "registry.invalid", ["ci:phorvex-tag"], "digest", S, "",
                         {"ci:phorvex-tag": A}, lambda ref: (A, S))

    def test_actual_values_contains_one_marker_per_component(self):
        src = (ROOT / "deploy/helm/phorvex-stack/values-eks.yaml").read_text()
        result = m.update(src, "next", "registry.invalid", list(m.COMPONENTS), "digest", S, "",
                          {"ci:phorvex-tag": A, "ci:console-tag": B},
                          lambda ref: (A if "/phorvex:" in ref else B, S))
        self.assertEqual(result.count('tag: "next"'), 2)

    def test_config_fetched_at_immutable_digest_and_registry_port_preserved(self):
        calls = []
        def docker_json(ref, field):
            calls.append((ref, field))
            if field == "Manifest":
                return {"digest": A}
            self.assertEqual(ref, "registry.invalid:5000/phorvex@" + A)
            return {"architecture": "amd64", "os": "linux", "config": {"Labels": {"org.opencontainers.image.revision": S}}}
        with patch.object(m, "docker_json", docker_json):
            self.assertEqual(m.artifact("registry.invalid:5000/phorvex:moving-tag"), (A, S))
        self.assertEqual(calls, [("registry.invalid:5000/phorvex:moving-tag", "Manifest"),
                                 ("registry.invalid:5000/phorvex@" + A, "Image")])

    def run_script(self, *, wrong_source=False, docker_fail=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = root / "values.yaml"
            values.write_text(SOURCE)
            docker = root / "docker"
            docker.write_text("#!" + sys.executable + "\n" +
                "import json,os,sys\n" +
                "if os.environ.get('DOCKER_FAIL')=='true':\n print('Authorization: Bearer private-token',file=sys.stderr);sys.exit(1)\n" +
                "ref=sys.argv[4];field=sys.argv[-1]\n" +
                "if field=='{{json .Manifest}}': print(json.dumps({'digest':os.environ['DRAIN_TEST_DIGEST']}))\n" +
                "else:\n assert '@sha256:' in ref;print(json.dumps({'architecture':'amd64','os':'linux','config':{'Labels':{'org.opencontainers.image.revision':os.environ['DRAIN_TEST_SOURCE']}}}))\n")
            docker.chmod(0o700)
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'], V="next",
                       REG="registry.invalid", SOURCE_MODE="digest", SOURCE_SHA=S, RELEASE_FROM="",
                       OPERATOR_DIGEST=A, CONSOLE_DIGEST=B, DRAIN_TEST_DIGEST=A,
                       DRAIN_TEST_SOURCE=T if wrong_source else S,
                       DOCKER_FAIL="true" if docker_fail else "false")
            result = subprocess.run([sys.executable, str(ROOT/'deploy/ci/update-release-values.py'),
                                     str(values), 'ci:phorvex-tag'],env=env,capture_output=True,text=True,timeout=10)
            return result, values.read_text()

    def test_actual_script_atomic_write_and_failed_metadata_preserves_file(self):
        result, values = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tag: "next" # ci:phorvex-tag', values)
        self.assertEqual(values.split('console:')[1], SOURCE.split('console:')[1])
        for options in ({"wrong_source": True}, {"docker_fail": True}):
            result, values = self.run_script(**options)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(values, SOURCE)
            self.assertNotIn('private-token', result.stdout + result.stderr)

    def test_docker_descriptor_and_platform_config_fail_closed(self):
        for config in ({}, {"linux/arm64": {}}, {"architecture": "arm64", "os": "linux"},
                       {"architecture": "amd64", "os": "linux", "config": {"Labels": {"org.opencontainers.image.revision": "latest"}}}):
            with patch.object(m, "docker_json", side_effect=[{"digest": A}, config]), self.assertRaises(ValueError):
                m.artifact('registry.invalid/phorvex:next')
        with patch.object(m, "docker_json", return_value={"digest": "tag"}), self.assertRaises(ValueError):
            m.artifact('registry.invalid/phorvex:next')

    def test_helm_authority_env_default_and_independent_component_sources(self):
        helm = os.environ.get("HELM") or shutil.which("helm") or "/opt/phorvex-tools/helm"
        self.assertTrue(Path(helm).is_file(), "Helm must be installed for release authority controls")
        command = [helm, "template", "phorvex", str(ROOT/"deploy/helm/phorvex-stack"), "-n", "phorvex-system",
                   "-f", str(ROOT/"deploy/helm/phorvex-stack/values.yaml"), "-f", str(ROOT/"deploy/helm/phorvex-stack/values-eks.yaml"),
                   "--api-versions", "monitoring.coreos.com/v1/PodMonitor", "--api-versions", "monitoring.coreos.com/v1/ServiceMonitor"]
        def envs(args):
            raw = subprocess.run(command+args,capture_output=True,text=True,check=True,timeout=30).stdout
            docs = list(yaml.safe_load_all(raw))
            dep = next(d for d in docs if d and d.get("kind")=="Deployment" and d["metadata"]["name"]=="phorvex-phorvex-console")
            return {v["name"]:v.get("value") for v in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        disabled = envs(["--set", "phorvex.phorvex.console.drainLive.enabled=false"])
        self.assertFalse(any(k.startswith("PHORVEX_CONSOLE_DRAIN_MANAGER_") or k.startswith("PHORVEX_CONSOLE_DRAIN_CONSOLE_") for k in disabled))
        configured = yaml.safe_load((ROOT/"deploy/helm/phorvex-stack/values-eks.yaml").read_text())["phorvex"]["phorvex"]
        manager_template = configured["image"]["repository"] + ":" + configured["image"]["tag"]
        console_template = configured["console"]["image"]["repository"] + ":" + configured["console"]["image"]["tag"]
        default = envs([])
        self.assertEqual(default["PHORVEX_CONSOLE_DRAIN_MANAGER_IMAGE"], "")
        self.assertEqual(default["PHORVEX_CONSOLE_DRAIN_CONSOLE_IMAGE"], "")
        values = envs(["--set", "phorvex.phorvex.image.releaseDigest="+A,
                       "--set", "phorvex.phorvex.image.releaseSourceSHA="+S,
                       "--set", "phorvex.phorvex.console.image.releaseDigest="+B,
                       "--set", "phorvex.phorvex.console.image.releaseSourceSHA="+T])
        reg = "753556437180.dkr.ecr.us-east-2.amazonaws.com/"
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_MANAGER_TEMPLATE_IMAGE"], manager_template)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_CONSOLE_TEMPLATE_IMAGE"], console_template)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_MANAGER_IMAGE"], reg+"phorvex@"+A)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_CONSOLE_IMAGE"], reg+"phorvex-console@"+B)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_MANAGER_SOURCE_SHA"], S)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_CONSOLE_SOURCE_SHA"], T)
        self.assertEqual(values["PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256"], default["PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256"])

if __name__ == "__main__": unittest.main()
