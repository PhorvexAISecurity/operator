"""Static and (opt-in) Docker tests for the phorvex catalogue fixture image.

The static tests need no container runtime: they pin the Dockerfile, the reviewed
provenance authority (release/staging-phorvex-fixture.json), the three fixture command
sources and the CI/publish wiring against each other. The Docker test actually builds the
image and runs the identity verifier; it is opt-in (PHORVEX_FIXTURE_IMAGE_DOCKER_TEST=1)
because a module image build is slow.
"""

from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/docker/phorvex-fixture.Dockerfile"
AUTHORITY = ROOT / "release/staging-phorvex-fixture.json"
PR_VALIDATION = ROOT / ".github/workflows/pr-validation.yml"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/staging-phorvex-fixture.yml"
VERIFIER = ROOT / "tools/verify_phorvex_fixture_image.py"
COMMANDS = ["/ragstore-fixture", "/cost-admission", "/cost-load-detector"]
COMMAND_SOURCES = {
    "/ragstore-fixture": "phorvex/cmd/ragstore-fixture",
    "/cost-admission": "phorvex/cmd/cost-admission",
    "/cost-load-detector": "phorvex/cmd/cost-load-detector",
}


class PhorvexFixtureDockerfileTests(unittest.TestCase):
    def setUp(self):
        self.text = DOCKERFILE.read_text(encoding="utf-8")

    def test_two_stage_build_from_pinned_bases(self):
        from_lines = [line for line in self.text.splitlines() if line.startswith("FROM ")]
        self.assertEqual(len(from_lines), 2, from_lines)
        self.assertTrue(all("@sha256:" in line for line in from_lines), from_lines)
        self.assertIn("docker.io/library/golang:1.26@sha256:", from_lines[0])
        self.assertIn("gcr.io/distroless/static:nonroot@sha256:", from_lines[1])

    def test_builds_exactly_the_three_fixture_binaries_reproducibly(self):
        for target in ("./cmd/ragstore-fixture", "./cmd/cost-admission", "./cmd/cost-load-detector"):
            self.assertIn(target, self.text)
        # No other ./cmd/<x> target may leak into the fixture image.
        built = set(re.findall(r"\./cmd/[a-z0-9-]+", self.text))
        self.assertEqual(
            built,
            {"./cmd/ragstore-fixture", "./cmd/cost-admission", "./cmd/cost-load-detector", "./cmd/pendingcheck"},
            built,
        )
        self.assertIn("-trimpath", self.text)
        self.assertIn("-buildid=", self.text)
        self.assertIn("CGO_ENABLED=0", self.text)
        # Reproducible application layer: explicit file sources with copy-time
        # ownership/permissions (the agentsim idiom), not a builder-fs directory walk.
        self.assertIn("COPY --from=builder --chown=0:0 --chmod=0555", self.text)
        self.assertIn(
            "/out/ragstore-fixture /out/cost-admission /out/cost-load-detector /",
            self.text,
        )
        self.assertNotIn("COPY --from=builder /rootfs/ /", self.text)

    def test_unfinished_work_gate_and_replace_targets_present(self):
        self.assertIn("go run ./cmd/pendingcheck -root . -inventory PENDING-INVENTORY.md", self.text)
        for replace_target in ("build/phoenix-extended/", "build/metricvalidity/", "libs/logging/"):
            self.assertIn(f"COPY {replace_target} {replace_target}", self.text)

    def test_runs_non_root_with_fixed_entrypoint_and_validates_build_args(self):
        self.assertIn("USER 65532:65532", self.text)
        self.assertIn('ENTRYPOINT ["/ragstore-fixture"]', self.text)
        self.assertIn("EXPOSE 8080", self.text)
        self.assertIn('[ "${#GIT_SHA}" -eq 40 ]', self.text)
        self.assertIn("SOURCE_DATE_EPOCH must be an unsigned integer", self.text)
        self.assertIn(
            'ai.phorvex.fixture.commands="/ragstore-fixture,/cost-admission,/cost-load-detector"',
            self.text,
        )


class PhorvexFixtureAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))

    def test_authority_is_an_immutable_separate_repository(self):
        a = self.authority
        self.assertEqual(a["schema"], 1)
        self.assertEqual(a["name"], "staging-phorvex-fixture")
        self.assertEqual(a["registry"], "753556437180.dkr.ecr.us-east-2.amazonaws.com")
        self.assertEqual(a["repository"], "phorvex/staging/phorvex-fixture")
        controls = a["repositoryControls"]
        self.assertEqual(controls["imageTagMutability"], "IMMUTABLE")
        self.assertTrue(controls["scanOnPush"])
        self.assertIn(controls["encryptionType"], {"AES256", "KMS"})
        self.assertEqual(a["tagScheme"]["pinnedBy"], "digest")
        self.assertTrue(a["tagScheme"]["immutable"])

    def test_authority_does_not_overlap_the_eight_component_batch(self):
        # The isolated-release repositories are phorvex/staging/<component> for the exact
        # eight components; the fixture repo must be a DIFFERENT name so it never collides.
        target = json.loads((ROOT / "release/staging-target.json").read_text(encoding="utf-8"))
        self.assertNotIn(self.authority["repository"], set(target["repositories"].values()))
        # The isolated-release authority file set must not mention this new artifact, so the
        # locked consumer/authority contract is unchanged.
        staging_release = (ROOT / "tools/staging_release.py").read_text(encoding="utf-8")
        self.assertNotIn("staging-phorvex-fixture", staging_release)
        self.assertNotIn("phorvex-fixture", staging_release)

    def test_build_and_identity_contract_matches_the_dockerfile(self):
        build = self.authority["build"]
        self.assertEqual(build["dockerfile"], "deploy/docker/phorvex-fixture.Dockerfile")
        self.assertTrue((ROOT / build["dockerfile"]).is_file())
        self.assertEqual(build["context"], ".")
        self.assertEqual(build["sourceDateEpoch"], 0)
        identity = self.authority["identity"]
        self.assertEqual(identity["user"], "65532:65532")
        self.assertEqual(identity["platform"], "linux/amd64")
        self.assertEqual(identity["entrypoint"], ["/ragstore-fixture"])
        self.assertEqual(identity["commands"], COMMANDS)

    def test_command_sources_exist_and_are_package_main(self):
        self.assertEqual(self.authority["identity"]["commandSources"], COMMAND_SOURCES)
        for command, source in COMMAND_SOURCES.items():
            main_go = ROOT / source / "main.go"
            with self.subTest(command=command):
                self.assertTrue(main_go.is_file(), main_go)
                self.assertRegex(main_go.read_text(encoding="utf-8"), r"(?m)^package main$")

    def test_consumers_cover_exactly_the_three_phorvex_families(self):
        consumers = self.authority["consumers"]
        self.assertEqual(consumers["renderFlag"], "--phorvex-image")
        self.assertEqual(consumers["renderTool"], "tools/render_catalogue_staging_values.py")
        self.assertEqual(
            consumers["valuesPath"],
            ["phorvex", "console", "attackCatalog", "familyFixtures", "images", "phorvex"],
        )
        self.assertEqual(set(consumers["families"]), {"datastore", "serving-rate", "serving-kv"})
        # The render tool's own PHORVEX_FAMILIES set must agree with this authority.
        render = (ROOT / "tools/render_catalogue_staging_values.py").read_text(encoding="utf-8")
        self.assertIn('PHORVEX_FAMILIES = {"datastore", "serving-kv", "serving-rate"}', render)


class PhorvexFixtureWiringTests(unittest.TestCase):
    def test_pr_validation_builds_and_verifies_the_fixture_image(self):
        text = PR_VALIDATION.read_text(encoding="utf-8")
        self.assertIn("phorvex-fixture", text)
        self.assertIn("deploy/docker/phorvex-fixture.Dockerfile", text)
        self.assertIn("tools/verify_phorvex_fixture_image.py inspect", text)

    def test_publish_workflow_is_isolated_and_reproducible(self):
        text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("release/staging-phorvex-fixture.json", text)
        self.assertIn("verify_phorvex_fixture_image.py reproduce", text)
        self.assertIn("verify_phorvex_fixture_image.py inspect", text)
        self.assertIn("--phorvex-image", text)
        # It must not write the batch, open a deployment PR, or drive staging_release.py:
        # the fixture image is consumed only by digest, so the eight-component contract
        # and its deployment proposal path are never exercised here.
        self.assertNotIn("staging_release.py", text)
        self.assertNotIn("pin-fixtures", text)
        self.assertNotIn("git commit", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("pull-request", text)


@unittest.skipUnless(
    os.environ.get("PHORVEX_FIXTURE_IMAGE_DOCKER_TEST") == "1" and shutil.which("docker"),
    "set PHORVEX_FIXTURE_IMAGE_DOCKER_TEST=1 with docker available to build the image",
)
class PhorvexFixtureDockerBuildTest(unittest.TestCase):
    def test_image_builds_and_passes_identity_inspection(self):
        git_sha = "0" * 40
        tag = "phorvex-fixture:static-test"
        subprocess.run(
            [
                "docker", "build", "--file", str(DOCKERFILE),
                "--build-arg", f"GIT_SHA={git_sha}",
                "--build-arg", "RELEASE_VERSION=staging-fixture-v1",
                "--build-arg", "SOURCE_DATE_EPOCH=0",
                "--tag", tag, str(ROOT),
            ],
            check=True,
        )
        try:
            subprocess.run(
                [
                    "python3", str(VERIFIER), "inspect", "--image", tag,
                    "--git-sha", git_sha, "--release-version", "staging-fixture-v1",
                ],
                check=True,
            )
        finally:
            subprocess.run(["docker", "image", "rm", tag], check=False)


if __name__ == "__main__":
    unittest.main()
