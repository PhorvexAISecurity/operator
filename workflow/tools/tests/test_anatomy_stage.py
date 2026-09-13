"""Tests for `anatomy-refresh --stage`, the candidate-edition mode.

`--check` and `--publish` both speak about the DEPLOYED source: check fails on any drift and
publish refuses a SHA that is not deployed. Neither can produce a reviewable anatomy for a
source the canonical pin must not move to, which is what an assessment needs. `--stage` fills
that gap, and the property that matters is what it does NOT do: it must never write inside
`workflow/anatomy/`.

The pipeline itself is exercised by its own audit and mutation suites against real source.
What is asserted here is the wiring: where the candidate is generated, which environment the
generators see, and that the canonical edition is left alone.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "workflow.py"
SPEC = importlib.util.spec_from_file_location("phorvex_anatomy_stage_tool", TOOL)
assert SPEC and SPEC.loader
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)
SOURCE_ROOT = TOOL.parents[1]

PATHS = SOURCE_ROOT / "anatomy" / "pipeline" / "paths.py"


def load_paths(env: dict[str, str], workflow_root: Path):
    """Import the pipeline's paths.py under a given environment."""
    spec = importlib.util.spec_from_file_location(f"phorvex_paths_{id(env)}", PATHS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    saved = dict(os.environ)
    os.environ.update(env)
    try:
        spec.loader.exec_module(module)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return module


class PathOverrideTests(unittest.TestCase):
    def test_defaults_are_unchanged_without_overrides(self) -> None:
        module = load_paths({"PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent)}, SOURCE_ROOT)
        self.assertEqual(module.ANATOMY_DIR, (SOURCE_ROOT / "anatomy").resolve())
        self.assertEqual(module.ANATOMY_DOC.name, "ANATOMY.md")
        self.assertEqual(module.MMD_PATH.name, "ANATOMY.mmd")
        self.assertEqual(module.SVG_PATH.name, "ANATOMY.svg")
        self.assertEqual(module.GENERATED_DIR, (SOURCE_ROOT / "anatomy" / "generated").resolve())

    def test_overrides_move_every_output_together(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            module = load_paths(
                {
                    "PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent),
                    "PHORVEX_ANATOMY_DIR": str(stage),
                    "PHORVEX_ANATOMY_DOC": "ANATOMY_V3.md",
                    "PHORVEX_ANATOMY_STEM": "ANATOMY_V3",
                },
                SOURCE_ROOT,
            )
            self.assertEqual(module.ANATOMY_DOC, stage / "ANATOMY_V3.md")
            self.assertEqual(module.MMD_PATH, stage / "generated" / "ANATOMY_V3.mmd")
            self.assertEqual(module.SVG_PATH, stage / "generated" / "ANATOMY_V3.svg")
            # the code repository is a SEPARATE override; staging must not move it
            self.assertEqual(module.REPO_PATH, SOURCE_ROOT.parent.resolve())


class StageModeTests(unittest.TestCase):
    def args(self, stage: Path, **over) -> argparse.Namespace:
        base = dict(
            repo=None,
            source_ref="HEAD",
            check=False,
            publish=False,
            stage=str(stage),
            stage_doc="ANATOMY_V3.md",
            stage_stem="ANATOMY_V3",
        )
        base.update(over)
        base.setdefault("stage_regen_anchors", False)
        return argparse.Namespace(**base)

    def test_stage_is_mutually_exclusive_with_publish(self) -> None:
        parser = workflow.build_parser()
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            parser.parse_args(
                ["anatomy-refresh", "--source-ref", "HEAD", "--stage", "x", "--publish"]
            )

    def test_stage_refuses_the_canonical_anatomy_directory(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = workflow.cmd_anatomy_refresh(
                self.args(SOURCE_ROOT / "anatomy" / "candidate")
            )
        self.assertEqual(code, 1)
        self.assertIn("refusing to stage inside the canonical anatomy", buf.getvalue())

    def test_stage_seeds_the_pipeline_and_leaves_the_canonical_edition_alone(self) -> None:
        recorded: list[tuple[list[str], dict[str, str]]] = []

        def fake_run(command, **kwargs):
            recorded.append((list(command), dict(kwargs.get("env") or {})))
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        canonical_doc = SOURCE_ROOT / "anatomy" / "ANATOMY.md"
        canonical_pin = SOURCE_ROOT / "anatomy" / "PIN.yaml"
        before = (canonical_doc.read_bytes(), canonical_pin.read_bytes())

        original = workflow.run_checked
        workflow.run_checked = fake_run
        try:
            with tempfile.TemporaryDirectory() as raw:
                stage = Path(raw) / "candidate"
                out = io.StringIO()
                with redirect_stdout(out):
                    code = workflow._stage_anatomy(
                        self.args(stage), stage, Path(raw) / "source", "0" * 40
                    )
                self.assertEqual(code, 0)
                self.assertTrue((stage / "pipeline" / "run_full_suite.sh").is_file())
                self.assertTrue((stage / "generated").is_dir())
                self.assertIn("pipeline seeded", out.getvalue())
        finally:
            workflow.run_checked = original

        self.assertEqual(before, (canonical_doc.read_bytes(), canonical_pin.read_bytes()))
        self.assertEqual(
            [Path(c[-1]).name for c, _ in recorded],
            ["run_full_suite.sh", "build_diagram_v2.py", "build_svg.py", "build_anatomy_doc.py"],
        )
        for _command, env in recorded:
            self.assertEqual(env["PHORVEX_ANATOMY_DOC"], "ANATOMY_V3.md")
            self.assertEqual(env["PHORVEX_ANATOMY_STEM"], "ANATOMY_V3")
            self.assertTrue(env["PHORVEX_ANATOMY_DIR"].endswith("candidate"))
            self.assertTrue(env["PHORVEX_CODE_REPO"].endswith("source"))
            # the generators must never be pointed back at the canonical outputs
            self.assertNotEqual(
                Path(env["PHORVEX_ANATOMY_DIR"]).resolve(), (SOURCE_ROOT / "anatomy").resolve()
            )

    def test_stage_pins_the_candidate_source_without_touching_the_canonical_pin(self) -> None:
        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        canonical_pin = SOURCE_ROOT / "anatomy" / "pipeline" / "SOURCE_PIN.json"
        before = canonical_pin.read_bytes()
        target = "a" * 40
        original = workflow.run_checked
        workflow.run_checked = fake_run
        try:
            with tempfile.TemporaryDirectory() as raw:
                stage = Path(raw) / "candidate"
                with redirect_stdout(io.StringIO()):
                    workflow._stage_anatomy(
                        self.args(stage), stage, Path(raw) / "source", target
                    )
                staged = workflow.json.loads(
                    (stage / "pipeline" / "SOURCE_PIN.json").read_text(encoding="utf-8")
                )
                self.assertEqual(staged["commit"], target)
                self.assertEqual(staged["frozen_at"], "staged-candidate")
        finally:
            workflow.run_checked = original
        self.assertEqual(before, canonical_pin.read_bytes())


if __name__ == "__main__":
    unittest.main()



class StagedTreeEscapeTests(unittest.TestCase):
    """The reproduction from R2, driven through the code that actually writes.

    `stage/pipeline/SOURCE_PIN.json` as a symlink to a file outside the stage passed every
    fixed-destination check — `stage/pipeline` itself is a real directory — and `_stage_anatomy`
    then wrote the target pin straight through it. These tests plant the link, run the real
    write path with a sentinel outside, and assert the sentinel is byte-unchanged. Asserting
    only that the helper returns a string would not have caught the original bug: the helper
    was returning None and the write was happening anyway.
    """

    SENTINEL = "outside sentinel — must never be written\n"

    def args(self, stage: Path, doc="ANATOMY_V3.md", stem="ANATOMY_V3"):
        return argparse.Namespace(
            repo=None, source_ref="HEAD", check=False, publish=False,
            stage=str(stage), stage_doc=doc, stage_stem=stem, stage_regen_anchors=False,
        )

    def stage_with(self, raw: Path, plant):
        """A stage whose pipeline/ already exists, plus an outside sentinel file."""
        stage = raw / "candidate"
        (stage / "pipeline").mkdir(parents=True)
        (stage / "generated").mkdir()
        sentinel = raw / "outside" / "sentinel.json"
        sentinel.parent.mkdir()
        sentinel.write_text(self.SENTINEL, encoding="utf-8")
        plant(stage, sentinel)
        return stage, sentinel

    def run_stage(self, stage: Path):
        """The real `_stage_anatomy`, with only the subprocess boundary stubbed."""
        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        original = workflow.run_checked
        workflow.run_checked = fake_run
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                code = workflow._stage_anatomy(
                    self.args(stage), stage.resolve(), stage.parent / "source", "b" * 40
                )
            return code, err.getvalue()
        finally:
            workflow.run_checked = original

    def test_artifact_file_symlink_out_of_stage_does_not_get_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage, sentinel = self.stage_with(
                Path(raw),
                lambda s, t: (s / "pipeline" / "SOURCE_PIN.json").symlink_to(t),
            )
            code, err = self.run_stage(stage)
            self.assertEqual(code, 1)
            self.assertIn("outside", err)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), self.SENTINEL)

    def test_generated_tsv_symlink_is_caught_only_by_the_descendant_scan(self) -> None:
        # NODES.tsv is not one of the named destinations. Nothing but a scan of the whole
        # staged tree can refuse it, and a generator writes it by relative name.
        with tempfile.TemporaryDirectory() as raw:
            stage, sentinel = self.stage_with(
                Path(raw),
                lambda s, t: (s / "pipeline" / "NODES.tsv").symlink_to(t),
            )
            (stage / "pipeline" / "SOURCE_PIN.json").write_text('{"commit": "x"}\n', encoding="utf-8")
            code, err = self.run_stage(stage)
            self.assertEqual(code, 1)
            self.assertIn("point outside it", err)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), self.SENTINEL)
            self.assertEqual(
                (stage / "pipeline" / "SOURCE_PIN.json").read_text(encoding="utf-8"),
                '{"commit": "x"}\n',
            )

    def test_nested_directory_symlink_out_of_stage_does_not_get_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            outside_dir = Path(raw) / "elsewhere"
            outside_dir.mkdir()
            marker = outside_dir / "keep.txt"
            marker.write_text(self.SENTINEL, encoding="utf-8")

            stage, sentinel = self.stage_with(
                Path(raw),
                lambda s, t: (s / "pipeline" / "nested").symlink_to(
                    outside_dir, target_is_directory=True
                ),
            )
            # the pin itself is a normal file here: only the nested directory escapes
            (stage / "pipeline" / "SOURCE_PIN.json").write_text('{"commit": "x"}\n', encoding="utf-8")
            code, err = self.run_stage(stage)
            self.assertEqual(code, 1)
            self.assertIn("point outside it", err)
            self.assertEqual(marker.read_text(encoding="utf-8"), self.SENTINEL)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), self.SENTINEL)
            # the pin was NOT updated either: the refusal precedes every write
            self.assertEqual(
                (stage / "pipeline" / "SOURCE_PIN.json").read_text(encoding="utf-8"),
                '{"commit": "x"}\n',
            )

    def test_a_link_that_stays_inside_the_stage_is_allowed(self) -> None:
        # The check refuses ESCAPE, not symlinks. A link within the stage is not an escape,
        # and refusing it would be a different promise than the one that was made.
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            (stage / "pipeline").mkdir(parents=True)
            (stage / "generated").mkdir()
            (stage / "pipeline" / "SOURCE_PIN.json").write_text('{"commit": "x"}\n', encoding="utf-8")
            (stage / "pipeline" / "alias.json").symlink_to(stage / "pipeline" / "SOURCE_PIN.json")
            self.assertIsNone(
                workflow.stage_destination_problem(stage.resolve(), "ANATOMY_V3.md", "ANATOMY_V3")
            )

    def test_the_escape_is_refused_before_seeding_too(self) -> None:
        # A stage with no pipeline/ yet, but an escaping link already planted elsewhere in it.
        # The refusal must come before the seeding copytree, not after.
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            (stage / "generated").mkdir(parents=True)
            outside = Path(raw) / "outside.txt"
            outside.write_text(self.SENTINEL, encoding="utf-8")
            (stage / "generated" / "ANATOMY_V3.svg").symlink_to(outside)
            code, err = self.run_stage(stage)
            self.assertEqual(code, 1)
            self.assertIn("outside", err)
            self.assertFalse((stage / "pipeline").exists(), "seeding must not have run")
            self.assertEqual(outside.read_text(encoding="utf-8"), self.SENTINEL)


class PathsEscapeTests(unittest.TestCase):
    """The same refusal at the generator invocation boundary.

    Every generator imports `paths`, and the generators write by relative name into their own
    directory — so the check that matters for a direct script run is the one that happens on
    import. It is a precondition, not a sandbox: a script that never imports `paths`, or
    anything the process does after import, is outside what this can promise.
    """

    def test_import_refuses_an_escaping_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            (stage / "pipeline").mkdir(parents=True)
            outside = Path(raw) / "outside.json"
            outside.write_text("keep\n", encoding="utf-8")
            (stage / "pipeline" / "NODES.tsv").symlink_to(outside)
            with self.assertRaises(SystemExit) as caught:
                load_paths(
                    {
                        "PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent),
                        "PHORVEX_ANATOMY_DIR": str(stage),
                    },
                    SOURCE_ROOT,
                )
            self.assertIn("point outside it", str(caught.exception))
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_import_allows_a_tree_with_no_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            (stage / "pipeline").mkdir(parents=True)
            (stage / "pipeline" / "NODES.tsv").write_text("id\n", encoding="utf-8")
            module = load_paths(
                {
                    "PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent),
                    "PHORVEX_ANATOMY_DIR": str(stage),
                },
                SOURCE_ROOT,
            )
            self.assertEqual(module.ANATOMY_DIR, stage.resolve())

    def test_the_canonical_tree_has_no_escaping_descendants(self) -> None:
        module = load_paths({"PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent)}, SOURCE_ROOT)
        self.assertEqual(module.escaping_descendants(SOURCE_ROOT / "anatomy"), [])


class GuardModuleTests(unittest.TestCase):
    """The same refusal for the pipeline scripts that do NOT import `paths`.

    R3 finding: `paths.py` claimed to be THE generator invocation boundary, and it was not.
    `build_effect_matrix.py` writes `EFFECT_MATRIX.tsv` by bare relative name and imports
    neither `paths` nor anything that does, so a direct invocation followed a symlink planted
    at that name while every CLI-layer check passed. `guard.py` is what those scripts import.
    """

    GUARD = SOURCE_ROOT / "anatomy" / "pipeline" / "guard.py"

    def load_guard(self, directory: Path, cwd: Path | None = None):
        """Import a COPY of guard.py placed in `directory`, optionally from another CWD."""
        planted = directory / "guard.py"
        planted.write_bytes(self.GUARD.read_bytes())
        spec = importlib.util.spec_from_file_location(f"phorvex_guard_{id(directory)}", planted)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        saved = Path.cwd()
        if cwd is not None:
            os.chdir(cwd)
        try:
            spec.loader.exec_module(module)
        finally:
            os.chdir(saved)
        return module

    def test_import_refuses_an_escaping_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            pipeline = Path(raw) / "pipeline"
            pipeline.mkdir()
            outside = Path(raw) / "outside.tsv"
            outside.write_text("keep\n", encoding="utf-8")
            (pipeline / "EFFECT_MATRIX.tsv").symlink_to(outside)
            with self.assertRaises(SystemExit) as caught:
                self.load_guard(pipeline)
            self.assertIn("point outside it", str(caught.exception))
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_import_allows_a_tree_with_no_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            pipeline = Path(raw) / "pipeline"
            pipeline.mkdir()
            (pipeline / "EFFECT_MATRIX.tsv").write_text("action\n", encoding="utf-8")
            module = self.load_guard(pipeline)
            self.assertEqual(module.HERE, pipeline.resolve())

    def test_import_refuses_an_escape_in_a_cwd_that_is_not_the_script_directory(self) -> None:
        # R3 second probe: the bare-relative-name writers land in CWD, not in the script's own
        # directory. Supply their inputs elsewhere and they run there — so a scan of the module
        # directory alone looks at the wrong tree.
        with tempfile.TemporaryDirectory() as raw:
            pipeline = Path(raw) / "pipeline"
            pipeline.mkdir()
            work = Path(raw) / "work"
            work.mkdir()
            outside = Path(raw) / "outside.tsv"
            outside.write_text("keep\n", encoding="utf-8")
            (work / "EFFECT_MATRIX.tsv").symlink_to(outside)
            with self.assertRaises(SystemExit) as caught:
                self.load_guard(pipeline, cwd=work)
            self.assertIn(str(work.resolve()), str(caught.exception))
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_every_writer_that_skips_paths_imports_the_guard(self) -> None:
        # The list is not maintained by hand: any pipeline script that opens a file for
        # writing and does not import `paths` must import `guard`, or this fails when the
        # next one is added.
        pipeline = SOURCE_ROOT / "anatomy" / "pipeline"
        unguarded = []
        for script in sorted(pipeline.glob("*.py")):
            if script.name in ("paths.py", "guard.py"):
                continue
            text = script.read_text(encoding="utf-8")
            writes = "'w'" in text or '"w"' in text or "write_text(" in text
            if not writes:
                continue
            if "import paths" in text or "from paths import" in text:
                continue
            if "import guard" not in text:
                unguarded.append(script.name)
        self.assertEqual(unguarded, [], "these write without either containment guard")


class StageDestinationSafetyTests(unittest.TestCase):
    """`--stage` promises it never writes inside `workflow/anatomy/`.

    The directory check alone did not keep that promise: `--stage-doc` and `--stage-stem` are
    joined onto the staging directory, so an absolute or traversing value wrote wherever it
    liked, and a symlinked `stage/generated` pointed the diagram at whatever it referenced.
    """

    canonical = (SOURCE_ROOT / "anatomy").resolve()

    def problem(self, stage: Path, doc="ANATOMY_V3.md", stem="ANATOMY_V3"):
        return workflow.stage_destination_problem(stage.resolve(), doc, stem)

    def test_a_plain_staged_directory_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertIsNone(self.problem(Path(raw) / "candidate"))

    def test_repeated_generation_into_the_same_directory_stays_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            (stage / "generated").mkdir(parents=True)
            (stage / "pipeline").mkdir()
            (stage / "ANATOMY_V3.md").write_text("first pass\n", encoding="utf-8")
            self.assertIsNone(self.problem(stage))

    def test_absolute_doc_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            problem = self.problem(Path(raw) / "candidate",
                                   doc=str(self.canonical / "ANATOMY.md"))
            self.assertIsNotNone(problem)
            self.assertIn("single file name", problem)

    def test_parent_traversal_in_doc_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            problem = self.problem(Path(raw) / "candidate", doc="../../ANATOMY.md")
            self.assertIsNotNone(problem)
            self.assertIn("single file name", problem)

    def test_nested_path_in_stem_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            problem = self.problem(Path(raw) / "candidate", stem="generated/../../ANATOMY")
            self.assertIsNotNone(problem)
            self.assertIn("single file name", problem)

    def test_traversal_that_would_reach_the_canonical_reader_is_refused(self) -> None:
        # The path a real escape would take: from workflow/assessments/<x>/anatomy-v3 back up
        # into workflow/anatomy. It must be refused as a name, before any resolution.
        stage = SOURCE_ROOT / "assessments" / "20260910-readiness" / "anatomy-v3"
        problem = self.problem(stage, doc="../../../anatomy/ANATOMY.md")
        self.assertIsNotNone(problem)
        self.assertIn("single file name", problem)

    def test_symlinked_generated_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            stage.mkdir()
            outside = Path(raw) / "elsewhere"
            outside.mkdir()
            (stage / "generated").symlink_to(outside, target_is_directory=True)
            problem = self.problem(stage)
            self.assertIsNotNone(problem)
            self.assertIn("outside --stage", problem)

    def test_generated_symlinked_into_the_canonical_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            stage.mkdir()
            (stage / "generated").symlink_to(self.canonical / "generated",
                                             target_is_directory=True)
            problem = self.problem(stage)
            self.assertIsNotNone(problem)
            self.assertIn("outside --stage", problem)

    def test_symlinked_pipeline_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            stage.mkdir()
            (stage / "pipeline").symlink_to(self.canonical / "pipeline",
                                            target_is_directory=True)
            problem = self.problem(stage)
            self.assertIsNotNone(problem)
            self.assertIn("outside --stage", problem)

    def test_stage_that_contains_the_canonical_directory_is_refused(self) -> None:
        # R3 finding: the containment test was one-directional. A stage INSIDE the canonical
        # directory was refused; a stage that ENCLOSES it was not, so `--stage workflow`
        # passed every check while `workflow/anatomy` sat underneath it.
        for stage in (SOURCE_ROOT, SOURCE_ROOT.parent):
            problem = self.problem(stage)
            self.assertIsNotNone(problem, f"{stage} encloses the canonical directory")
            self.assertIn("CONTAINS the canonical anatomy directory", problem)

    def test_a_sibling_of_the_canonical_directory_is_still_accepted(self) -> None:
        # The refusal must be containment, not "anywhere near". The real staging directory
        # lives under the same workflow root and has to keep working.
        stage = SOURCE_ROOT / "assessments" / "20260910-readiness" / "anatomy-v3"
        self.assertIsNone(self.problem(stage))

    def test_stage_that_is_a_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "candidate"
            target.write_text("not a directory\n", encoding="utf-8")
            problem = self.problem(target)
            self.assertIsNotNone(problem)
            self.assertIn("not a directory", problem)

    def test_the_canonical_edition_is_untouched_by_every_refusal(self) -> None:
        doc = self.canonical / "ANATOMY.md"
        pin = self.canonical / "PIN.yaml"
        before = (doc.read_bytes(), pin.read_bytes())
        with tempfile.TemporaryDirectory() as raw:
            for kwargs in (
                {"doc": str(doc)},
                {"doc": "../../../anatomy/ANATOMY.md"},
                {"stem": "../../anatomy/generated/ANATOMY"},
            ):
                with redirect_stderr(io.StringIO()):
                    code = workflow.cmd_anatomy_refresh(
                        self.args_for(Path(raw) / "candidate", **kwargs)
                    )
                self.assertEqual(code, 1)
        self.assertEqual(before, (doc.read_bytes(), pin.read_bytes()))

    def args_for(self, stage: Path, doc="ANATOMY_V3.md", stem="ANATOMY_V3"):
        return argparse.Namespace(
            repo=None, source_ref="HEAD", check=False, publish=False,
            stage=str(stage), stage_doc=doc, stage_stem=stem, stage_regen_anchors=False,
        )


class PathsContainmentTests(unittest.TestCase):
    """The same guarantee at the layer every generator actually uses.

    The CLI is not the only caller: the pipeline scripts read `paths.py`, so an escaping
    environment variable has to be refused there too, or a direct invocation bypasses the
    whole check.
    """

    def load(self, stage: Path, **over):
        env = {
            "PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent),
            "PHORVEX_ANATOMY_DIR": str(stage),
        }
        env.update(over)
        return load_paths(env, SOURCE_ROOT)

    def test_absolute_doc_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(SystemExit):
                self.load(Path(raw), PHORVEX_ANATOMY_DOC="/etc/passwd")

    def test_traversing_doc_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(SystemExit):
                self.load(Path(raw), PHORVEX_ANATOMY_DOC="../ANATOMY.md")

    def test_nested_stem_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(SystemExit):
                self.load(Path(raw), PHORVEX_ANATOMY_STEM="sub/ANATOMY")

    def test_symlinked_generated_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw) / "candidate"
            stage.mkdir()
            (stage / "generated").symlink_to(Path(raw), target_is_directory=True)
            with self.assertRaises(SystemExit):
                self.load(stage)

    def test_unknown_edition_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(SystemExit):
                self.load(Path(raw), PHORVEX_ANATOMY_EDITION="published")

    def test_candidate_edition_is_recognised(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            module = self.load(Path(raw), PHORVEX_ANATOMY_EDITION="candidate")
            self.assertTrue(module.IS_CANDIDATE)

    def test_default_edition_is_canonical(self) -> None:
        module = load_paths({"PHORVEX_CODE_REPO": str(SOURCE_ROOT.parent)}, SOURCE_ROOT)
        self.assertFalse(module.IS_CANDIDATE)
        self.assertEqual(module.EDITION, "canonical")
