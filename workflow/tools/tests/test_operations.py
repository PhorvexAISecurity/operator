from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from pathlib import Path

import yaml


TOOL = Path(__file__).resolve().parents[1] / "workflow.py"
SPEC = importlib.util.spec_from_file_location("phorvex_operations_tool", TOOL)
assert SPEC and SPEC.loader
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)
SOURCE_ROOT = TOOL.parents[1]


def run(command: list[str], cwd: Path) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


@contextmanager
def sandbox():
    names = (
        "ROOT",
        "ISSUES",
        "FIXES",
        "INTAKE",
        "RELEASES",
        "CAMPAIGNS",
        "OPERATIONS",
        "WORKFLOW_LOCK",
    )
    originals = {name: getattr(workflow, name) for name in names}
    with tempfile.TemporaryDirectory(prefix="workflow-operations-test-") as raw:
        repo = Path(raw) / "repo"
        root = repo / "workflow"
        for directory in (
            root / "issues" / "entries",
            root / "fixes",
            root / "intake",
            root / "releases",
            root / "campaigns",
            root / "anatomy",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SOURCE_ROOT / "fixes" / "_template", root / "fixes" / "_template")
        shutil.copytree(SOURCE_ROOT / "intake" / "_template", root / "intake" / "_template")
        shutil.copytree(
            SOURCE_ROOT / "campaigns" / "_template", root / "campaigns" / "_template"
        )
        shutil.copytree(
            SOURCE_ROOT / "releases" / "_template", root / "releases" / "_template"
        )
        shutil.copytree(SOURCE_ROOT / "operations", root / "operations")
        shutil.copytree(SOURCE_ROOT / "schemas", root / "schemas")
        shutil.copy2(SOURCE_ROOT / "OPERATIONS.md", root / "OPERATIONS.md")

        workflow.ROOT = root
        workflow.ISSUES = root / "issues"
        workflow.FIXES = root / "fixes"
        workflow.INTAKE = root / "intake"
        workflow.RELEASES = root / "releases"
        workflow.CAMPAIGNS = root / "campaigns"
        workflow.OPERATIONS = root / "operations"
        workflow.WORKFLOW_LOCK = root / ".workflow.lock"

        body = (
            "### M-1 · Widget drops signals · **HIGH** · NEW · `SENSING`\n\n"
            "**What:** Widget telemetry drops active signals.\n"
        )
        metadata = {
            "schema_version": 1,
            "id": "M-1",
            "title": "Widget drops signals",
            "severity": "HIGH",
            "register_label": "NEW",
            "workflow_state": "OPEN",
            "workflow_state_source": "test",
            "anatomy_tag": "SENSING",
            "kind": "BUG",
            "source_body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "migration_body_sha256": None,
            "migration_review": "not-applicable",
            "fixes": [],
            "dependencies": [],
            "blockers": [],
            "verdicts": [],
        }
        workflow.write_entry(root / "issues" / "entries" / "M-001.md", metadata, body)
        (root / "issues" / "layout.md").write_text(
            "# Test register\n\n{{ISSUE:M-1}}\n\n"
            "## Workflow-filed\n\n<!-- WORKFLOW_NEW_ISSUES -->\n",
            encoding="utf-8",
        )
        workflow.write_yaml(
            root / "issues" / "joins.yaml",
            {"schema_version": 1, "anatomy_pin": "baseline", "joins": {}},
        )
        (root / "issues" / "NEXT_ID").write_text("2\n", encoding="utf-8")
        workflow.write_yaml(
            root / "fixes" / "INDEX.yaml", {"schema_version": 1, "fixes": {}}
        )
        workflow.write_yaml(
            root / "intake" / "INDEX.yaml", {"schema_version": 1, "intakes": {}}
        )
        workflow.write_yaml(
            root / "campaigns" / "INDEX.yaml",
            {"schema_version": 1, "campaigns": {}},
        )
        workflow.write_yaml(
            root / "anatomy" / "PIN.yaml",
            {
                "schema_version": 1,
                "anatomy": {"source_commit": "baseline"},
                "currency": {"status": "test"},
            },
        )
        workflow.write_yaml(
            root / "releases" / "CURRENT.yaml",
            {
                "schema_version": 1,
                "recorded_at": "2026-09-07T00:00:00+00:00",
                "status": "test",
                "code_repository": {
                    "canonical_branch": "main",
                    "origin_main_sha": "baseline",
                    "source_release": "test",
                },
                "deployed": {
                    "image": "phorvex:test",
                    "release_commit": "baseline",
                    "embedded_git_sha": "baseline",
                    "digest": "sha256:test",
                    "observed_by": "fixture",
                    "observed_at": "2026-09-07T00:00:00+00:00",
                    "must_reverify_before_next_live_claim": False,
                },
                "anatomy": {
                    "source_commit": "baseline",
                    "current_for_deployed_release": True,
                    "refresh_status": "PASS",
                },
                "pending_release_fixes": [],
                "main_pending_deploy_issues": [],
                "notes": [],
            },
        )
        workflow.write_text(
            root / "issues" / "MASTER_ISSUES.md", workflow.render_master()
        )

        run(["git", "init", "-b", "main"], repo)
        run(["git", "config", "user.name", "Workflow Test"], repo)
        run(["git", "config", "user.email", "workflow@example.invalid"], repo)
        run(["git", "add", "workflow"], repo)
        run(["git", "commit", "-m", "baseline"], repo)
        baseline = run(["git", "rev-parse", "HEAD"], repo)
        run(["git", "update-ref", "refs/remotes/origin/main", baseline], repo)
        run(["git", "checkout", "-b", "docs/workflow"], repo)
        current_path = root / "releases" / "CURRENT.yaml"
        current = workflow.load_yaml(current_path)
        current["code_repository"]["origin_main_sha"] = baseline
        current["deployed"]["release_commit"] = baseline
        current["deployed"]["embedded_git_sha"] = baseline
        current["anatomy"]["source_commit"] = baseline
        workflow.write_yaml(current_path, current)
        pin = workflow.load_yaml(root / "anatomy" / "PIN.yaml")
        pin["anatomy"]["source_commit"] = baseline
        workflow.write_yaml(root / "anatomy" / "PIN.yaml", pin)
        try:
            yield repo, root, baseline
        finally:
            for name, value in originals.items():
                setattr(workflow, name, value)


def intake_args(intake_id: str, title: str = "Widget drops signals") -> argparse.Namespace:
    return argparse.Namespace(
        intake_id=intake_id,
        title=title,
        kind="BUG",
        reporter="investigator",
        approval_ref="request:test",
        claim="Widget telemetry drops active signals.",
        report_file=None,
        source_main_sha="baseline",
        source_release="test",
        deployed_image="phorvex:test",
        deployed_digest="sha256:test",
        deployed_git_sha="baseline",
        environment="fixture",
        investigator="investigator",
        coordinator="coordinator",
    )


def intake_transition(
    intake_id: str,
    target: str,
    *,
    verification_result: str | None = None,
    positive_control: str | None = None,
) -> int:
    return workflow.cmd_intake_transition(
        argparse.Namespace(
            intake_id=intake_id,
            target=target,
            by="investigator",
            next_owner="investigator",
            next_action=f"Continue from {target}.",
            artifact=None,
            note=None,
            approval_ref=None,
            verification_result=verification_result,
            positive_control=positive_control,
            force=False,
        )
    )


def prepare_fix_evidence(fix_id: str, repo: Path) -> None:
    """Build a fully attested synthetic snapshot for reconciliation tests."""
    fix = workflow.FIXES / fix_id
    path = fix / 'STATUS.yaml'
    status = workflow.load_yaml(path)
    status['change_class'] = 'A'
    status['baseline']['code_sha'] = run(['git', 'rev-parse', 'HEAD^'], repo)
    status['implementation']['base_sha'] = status['baseline']['code_sha']
    status['verification'].update({'live_required': True, 'soak_required': False})
    for name in ['00-intake.md', '01-proposal.md', '02A-blind-derivation.md', '02B-critique.md',
                 '03-decision.md', '05-evidence.md', 'evidence/incident.md',
                 'evidence/p3/verdict.md', '06-verdict.md']:
        dest = fix / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text('Verdict: PASS\nSynthetic widget invariant and independent counterexample review.\n')
    (fix/'04-diff.patch').write_bytes(subprocess.check_output(
        ['git', 'diff', '--binary', status['implementation']['base_sha'], status['implementation']['head_sha']], cwd=repo))
    (fix/'verify.sh').write_text('#!/usr/bin/env bash\nexit 0\n')
    status['synchronization']['permanent_tests'] = f'PASS:fixes/{fix_id}/verify.sh'
    blind = fix/'02A-blind-derivation.md'
    status['blind_derivation'] = {'status': 'sealed', 'by': status['roles']['skeptic'],
                                  'source_sha': status['baseline']['code_sha'],
                                  'sha256': workflow.sha256(blind), 'sealed_at': workflow.utcnow()}
    workflow.write_yaml(path, status)
    for key, role in workflow.gates.CHECK_ROLES.items():
        if key == 'patch_equivalence':
            continue
        artifact = workflow.gates.REVIEW_FILES.get(key, f'evidence/{key}.txt')
        target = fix/artifact
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f'{key}: PASS\nSynthetic recorded instrument output.\n')
        current = workflow.load_yaml(path)
        waiver = key == 'l4'
        args = argparse.Namespace(fix_id=fix_id, check=key,
             by=current['roles']['human_owner' if waiver else role], artifact=artifact,
             result='NOT_REQUIRED' if waiver else 'PASS', command='synthetic fixture review',
             approval_ref='fixture:waiver' if waiver else None,
             rationale='Stateless toy change needs no soak.' if waiver else None,
             expect_revision=current.get('revision',0))
        result = workflow.cmd_record_check(args)
        if result:
            raise AssertionError(f'could not attest fixture {key}')


class AgentOperationsTests(unittest.TestCase):
    def test_every_declared_state_edge_targets_a_known_state(self) -> None:
        for states, transitions in (
            (workflow.ISSUE_STATES, workflow.ISSUE_TRANSITIONS),
            (workflow.INTAKE_STATES, workflow.INTAKE_TRANSITIONS),
            (workflow.CAMPAIGN_STATES, workflow.CAMPAIGN_TRANSITIONS),
        ):
            self.assertEqual(set(transitions), states)
            for targets in transitions.values():
                self.assertLessEqual(targets, states)

    def test_transaction_restores_files_and_new_directories(self) -> None:
        with sandbox() as (_, root, _):
            path = root / "record.txt"
            path.write_text("before\n", encoding="utf-8")
            new_dir = root / "new-record"
            with self.assertRaises(RuntimeError):
                with workflow.workflow_transaction([path], [new_dir]):
                    path.write_text("after\n", encoding="utf-8")
                    new_dir.mkdir()
                    raise RuntimeError("fail")
            self.assertEqual(path.read_text(encoding="utf-8"), "before\n")
            self.assertFalse(new_dir.exists())

    def test_issue_allocator_skips_existing_number(self) -> None:
        with sandbox() as (_, root, _):
            (root / "issues" / "entries" / "M-002.md").write_text(
                "collision\n", encoding="utf-8"
            )
            self.assertEqual(workflow.next_issue_number(), 3)

    def test_verified_duplicate_bug_stops_at_existing_issue(self) -> None:
        with sandbox():
            intake_id = "RPT-20260907-000001-widget-signals"
            self.assertEqual(workflow.cmd_new_intake(intake_args(intake_id)), 0)
            self.assertEqual(intake_transition(intake_id, "TRIAGED"), 0)
            self.assertEqual(intake_transition(intake_id, "VERIFYING"), 0)
            self.assertEqual(
                intake_transition(
                    intake_id,
                    "VERIFIED",
                    verification_result="PASS",
                    positive_control="PASS",
                ),
                0,
            )
            self.assertEqual(
                workflow.cmd_dedup_intake(
                    argparse.Namespace(
                        intake_id=intake_id,
                        limit=5,
                        record=True,
                        determination="DUPLICATE",
                        issue="M-1",
                        human_ruling_ref=None,
                    )
                ),
                0,
            )
            self.assertEqual(intake_transition(intake_id, "DEDUP_REVIEW"), 0)
            self.assertEqual(intake_transition(intake_id, "DUPLICATE"), 0)
            status = workflow.load_yaml(workflow.INTAKE / intake_id / "STATUS.yaml")
            self.assertEqual(status["state"], "DUPLICATE")
            self.assertEqual(status["dedup"]["issue_id"], "M-1")
            self.assertEqual(workflow.next_issue_number(), 2)

    def test_verified_new_bug_promotes_atomically_and_starts_fix(self) -> None:
        with sandbox() as (repo, _, _):
            intake_id = "RPT-20260907-000002-new-root-cause"
            self.assertEqual(
                workflow.cmd_new_intake(
                    intake_args(intake_id, "New scheduler root cause")
                ),
                0,
            )
            status_path = workflow.INTAKE / intake_id / "STATUS.yaml"
            status = workflow.load_yaml(status_path)
            status["state"] = "DEDUP_REVIEW"
            status["verification"]["result"] = "PASS"
            status["verification"]["positive_control"] = "PASS"
            status["dedup"]["status"] = "reviewed"
            status["dedup"]["determination"] = "NEW"
            workflow.write_yaml(status_path, status)
            result = workflow.cmd_promote_intake(
                argparse.Namespace(
                    intake_id=intake_id,
                    repo=str(repo),
                    source_ref="origin/main",
                    severity="HIGH",
                    anatomy_tag="CHOICE",
                    approval_ref="owner:file-and-fix",
                    human_ruling_ref=None,
                    by="coordinator",
                    claim="A distinct scheduler mechanism violates the contract.",
                    evidence=f"intake/{intake_id}/VERIFICATION.md",
                    required_correction="Restore the scheduler invariant.",
                    start_fix="T1-M002",
                    fix_title="Restore scheduler invariant",
                )
            )
            self.assertEqual(result, 0)
            promoted = workflow.load_yaml(status_path)
            self.assertEqual(promoted["state"], "FILED")
            self.assertEqual(promoted["promotion"]["issue_id"], "M-2")
            self.assertTrue((workflow.ISSUES / "entries" / "M-002.md").is_file())
            self.assertTrue((workflow.FIXES / "T1-M002" / "STATUS.yaml").is_file())
            issue, _ = workflow.parse_entry(
                workflow.ISSUES / "entries" / "M-002.md"
            )
            self.assertEqual(issue["fixes"], ["T1-M002"])

    def test_ambiguous_dedup_cannot_allocate_an_issue(self) -> None:
        with sandbox() as (repo, _, _):
            intake_id = "RPT-20260907-000004-ambiguous"
            self.assertEqual(workflow.cmd_new_intake(intake_args(intake_id)), 0)
            status_path = workflow.INTAKE / intake_id / "STATUS.yaml"
            status = workflow.load_yaml(status_path)
            status["state"] = "NEEDS_DEDUP_RULING"
            status["verification"]["result"] = "PASS"
            status["dedup"]["determination"] = "AMBIGUOUS"
            workflow.write_yaml(status_path, status)
            before = workflow.next_issue_number()
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_promote_intake(
                    argparse.Namespace(
                        intake_id=intake_id,
                        repo=str(repo),
                        source_ref="origin/main",
                        severity="HIGH",
                        anatomy_tag="CHOICE",
                        approval_ref="owner:file",
                        human_ruling_ref=None,
                        by="coordinator",
                        claim=None,
                        evidence=None,
                        required_correction=None,
                        start_fix=None,
                        fix_title=None,
                    )
                )
            self.assertEqual(result, 1)
            self.assertEqual(workflow.next_issue_number(), before)

    def test_main_scan_finds_referenced_and_unattributed_work(self) -> None:
        with sandbox() as (repo, _, baseline):
            (repo / "known.txt").write_text("known\n", encoding="utf-8")
            run(["git", "add", "known.txt"], repo)
            run(["git", "commit", "-m", "fix: restore widget contract (M-1)"], repo)
            (repo / "other.txt").write_text("other\n", encoding="utf-8")
            run(["git", "add", "other.txt"], repo)
            run(["git", "commit", "-m", "refactor helper"], repo)
            latest = run(["git", "rev-parse", "HEAD"], repo)
            run(["git", "update-ref", "refs/remotes/origin/main", latest], repo)
            scan = workflow.scan_main(repo, "origin/main")
            self.assertEqual(scan["commit_range"]["from"], baseline)
            self.assertIn("M-1", scan["referenced_issues"])
            self.assertEqual(len(scan["unattributed_commits"]), 1)

    def test_main_to_deployment_to_verdict_reconciliation(self) -> None:
        with sandbox() as (repo, _, _):
            (repo / "fix.txt").write_text("fixed\n", encoding="utf-8")
            run(["git", "add", "fix.txt"], repo)
            run(["git", "commit", "-m", "fix: widget contract M-1"], repo)
            deployed_sha = run(["git", "rev-parse", "HEAD"], repo)
            run(["git", "update-ref", "refs/remotes/origin/main", deployed_sha], repo)
            sync_result = workflow.cmd_sync_main(
                argparse.Namespace(
                    repo=str(repo),
                    source_ref="origin/main",
                    check=False,
                    publish=True,
                    issue=["M-1"],
                    ignore_issue=[],
                    unattributed_reviewed=False,
                    approval_ref="owner:main-sync",
                    by="release-synchronizer",
                )
            )
            self.assertEqual(sync_result, 0)
            issue, _ = workflow.parse_entry(
                workflow.ISSUES / "entries" / "M-001.md"
            )
            self.assertEqual(issue["workflow_state"], "MAIN_PENDING_DEPLOY")
            workflow.create_fix_record(
                "T1-M001", ["M-1"], "Restore widget contract"
            )
            fix_status_path = workflow.FIXES / "T1-M001" / "STATUS.yaml"
            fix_status = workflow.load_yaml(fix_status_path)
            fix_status["state"] = "MERGED"
            fix_status["roles"].update(
                {
                    "human_owner": "owner",
                    "proposer": "proposer",
                    "implementer": "implementer",
                    "skeptic": "reviewer",
                    "live_verifier": "reviewer",
                    "coordinator": "coordinator",
                }
            )
            fix_status["implementation"].update(
                {"branch": "fix/m1", "base_sha": deployed_sha, "head_sha": deployed_sha}
            )
            fix_status["pull_request"].update(
                {
                    "url": "https://example.invalid/pr/1",
                    "reviewed_head": deployed_sha,
                    "merge_sha": deployed_sha,
                    "checks": "PASS",
                    "patch_equivalence": "PASS",
                }
            )
            fix_status["verification"].update(
                {
                    "required": ["L0", "L1", "L2", "L3"],
                    "p3": "PASS",
                    "l0": "PASS",
                    "l1": "PASS",
                    "l2": "PASS",
                    "l3": "PASS",
                    "positive_control": "PASS",
                }
            )
            fix_status["synchronization"]["permanent_tests"] = "PASS"
            workflow.write_yaml(fix_status_path, fix_status)
            (workflow.FIXES / "T1-M001" / "06-verdict.md").write_text(
                "Verdict: PASS\n", encoding="utf-8"
            )
            (workflow.FIXES / "T1-M001" / "verify.sh").write_text(
                "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
            )

            deploy_result = workflow.cmd_release_sync(
                argparse.Namespace(
                    finalize=False,
                    check=False,
                    publish=True,
                    record=None,
                    repo=str(repo),
                    image="phorvex:test2",
                    digest="sha256:test2",
                    git_sha=deployed_sha,
                    release_commit=deployed_sha,
                    source_release="vtest2",
                    observed_at="2026-09-07T01:00:00+00:00",
                    observed_by="fixture-observer",
                    environment="fixture",
                    issue=["M-1"],
                    fix=["T1-M001"],
                    pass_issue=[],
                    fail_issue=[],
                    defer_issue=[],
                    approval_ref="owner:deploy",
                    by="release-synchronizer",
                )
            )
            self.assertEqual(deploy_result, 0)
            current_path = workflow.RELEASES / "CURRENT.yaml"
            current = workflow.load_yaml(current_path)
            record = Path(current["deployed"]["sync_record"]).parent.name
            current["anatomy"] = {
                "source_commit": deployed_sha,
                "current_for_deployed_release": True,
                "refresh_status": "PASS",
            }
            workflow.write_yaml(current_path, current)
            pin_path = workflow.ROOT / "anatomy" / "PIN.yaml"
            pin = workflow.load_yaml(pin_path)
            pin["anatomy"]["source_commit"] = deployed_sha
            workflow.write_yaml(pin_path, pin)
            verdict = workflow.RELEASES / record / "evidence" / "l3.md"
            verdict.write_text("L3 PASS\n", encoding="utf-8")
            manifest_path = (
                workflow.RELEASES / record / "evidence" / "manifest.yaml"
            )
            manifest = workflow.load_yaml(manifest_path)
            manifest["artifacts"].append(
                {
                    "id": "m1-l3",
                    "path": "evidence/l3.md",
                    "bytes": verdict.stat().st_size,
                    "sha256": workflow.sha256(verdict),
                    "producer": "fixture",
                    "created_at": "2026-09-07T01:00:00+00:00",
                    "evidence_class": "L3",
                    "retention": "git",
                    "positive_control_for": None,
                    "sensitivity": None,
                }
            )
            workflow.write_yaml(manifest_path, manifest)
            prepare_fix_evidence("T1-M001", repo)
            final_result = workflow.cmd_release_sync(
                argparse.Namespace(
                    finalize=True,
                    record=record,
                    repo=str(repo),
                    approval_ref="owner:finalize",
                    pass_issue=[f"M-1=releases/{record}/evidence/l3.md"],
                    fail_issue=[],
                    defer_issue=[],
                    by="release-synchronizer",
                )
            )
            self.assertEqual(final_result, 0)
            issue, _ = workflow.parse_entry(
                workflow.ISSUES / "entries" / "M-001.md"
            )
            self.assertEqual(issue["workflow_state"], "CLOSED")
            release_status = workflow.load_yaml(
                workflow.RELEASES / record / "STATUS.yaml"
            )
            self.assertEqual(release_status["state"], "RECONCILED")
            closed_fix = workflow.load_yaml(fix_status_path)
            self.assertEqual(closed_fix["state"], "CLOSED")

    def test_anatomy_publish_rejects_latest_main_when_deploy_is_older(self) -> None:
        with sandbox() as (repo, _, _):
            (repo / "new.txt").write_text("new\n", encoding="utf-8")
            run(["git", "add", "new.txt"], repo)
            run(["git", "commit", "-m", "new main"], repo)
            latest = run(["git", "rev-parse", "HEAD"], repo)
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_anatomy_refresh(
                    argparse.Namespace(
                        repo=str(repo),
                        source_ref=latest,
                        check=False,
                        publish=True,
                    )
                )
            self.assertEqual(result, 1)

    def test_campaign_can_link_only_a_tracked_intake_finding(self) -> None:
        with sandbox():
            intake_id = "RPT-20260907-000003-campaign-finding"
            self.assertEqual(workflow.cmd_new_intake(intake_args(intake_id)), 0)
            campaign_id = "2026-09-07-cross-fix-study"
            result = workflow.cmd_new_campaign(
                argparse.Namespace(
                    campaign_id=campaign_id,
                    question="Do the fixes interact safely?",
                    owner="human-owner",
                    approval_ref="owner:campaign",
                    environment="fixture",
                    source_release=None,
                    fix=[],
                    duration_ceiling="1h",
                    cost_ceiling="none",
                    permission="read-only",
                    image=None,
                    digest=None,
                    git_sha=None,
                    stop_condition=["unknown build"],
                    campaign_lead="campaign-lead",
                    independent_reviewer="reviewer",
                    coordinator="coordinator",
                )
            )
            self.assertEqual(result, 0)
            hypotheses_path = workflow.CAMPAIGNS / campaign_id / "hypotheses.yaml"
            workflow.write_yaml(
                hypotheses_path,
                {
                    "schema_version": 1,
                    "hypotheses": [
                        {
                            "id": "H1",
                            "claim": "No unsafe interaction.",
                            "falsifier": "Any unsafe transition.",
                            "sample_unit": "decision",
                            "minimum_observations": 1,
                            "positive_control": "known decision",
                            "acceptance_threshold": "zero unsafe transitions",
                        }
                    ],
                },
            )
            transition = workflow.cmd_campaign_transition(
                argparse.Namespace(
                    campaign_id=campaign_id,
                    target="APPROVED",
                    by="campaign-lead",
                    next_owner="campaign-lead",
                    next_action="Capture baseline.",
                    artifact="hypotheses.yaml",
                    note=None,
                    approval_ref="owner:campaign",
                    phase_approval_ref=None,
                    image=None,
                    digest=None,
                    git_sha=None,
                    positive_control=None,
                    cleanup=None,
                    verdict=None,
                    reviewer=None,
                    round_state=[],
                    finding=[intake_id],
                    force=False,
                )
            )
            self.assertEqual(transition, 0)
            status = workflow.load_yaml(
                workflow.CAMPAIGNS / campaign_id / "STATUS.yaml"
            )
            self.assertEqual(status["findings"], [intake_id])

    def test_v1_and_v2_evidence_schemas_are_both_valid(self) -> None:
        errors: list[str] = []
        v1 = workflow.load_yaml(SOURCE_ROOT / "fixes" / "_template" / "evidence" / "manifest.yaml")
        workflow.validate_schema_instance(
            "evidence-manifest.schema.json", v1, "v1", errors
        )
        v2 = {
            "schema_version": 2,
            "subject": {"kind": "intake", "id": "RPT-20260907-000001-test"},
            "artifacts": [],
        }
        workflow.validate_schema_instance(
            "evidence-manifest.schema.json", v2, "v2", errors
        )
        self.assertEqual(errors, [])

    def test_fresh_agent_matrix_covers_every_operation(self) -> None:
        scenarios = (SOURCE_ROOT / "acceptance" / "SCENARIOS.md").read_text(
            encoding="utf-8"
        )
        policy = workflow.load_yaml(SOURCE_ROOT / "operations" / "POLICY.yaml")
        for operation, record in policy["operations"].items():
            self.assertIn(f"`{operation}`", scenarios)
            self.assertTrue((SOURCE_ROOT / record["runbook"]).is_file())

    def test_issue_transition_cannot_close_or_mark_deployed(self) -> None:
        with sandbox() as (_, _, _):
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_issue_transition(
                    argparse.Namespace(
                        issue_id="M-1",
                        target="CLOSED",
                        by="coordinator",
                        source="spoof",
                        artifact="issues/entries/M-001.md",
                        note=None,
                        approval_ref="owner:spoof",
                        force=False,
                    )
                )
            self.assertEqual(result, 1)
            issue, _ = workflow.parse_entry(workflow.ISSUES / "entries" / "M-001.md")
            self.assertEqual(issue["workflow_state"], "OPEN")

    def test_promote_intake_requires_positive_control(self) -> None:
        with sandbox() as (repo, _, _):
            intake_id = "RPT-20260907-000005-no-control"
            self.assertEqual(workflow.cmd_new_intake(intake_args(intake_id)), 0)
            status_path = workflow.INTAKE / intake_id / "STATUS.yaml"
            status = workflow.load_yaml(status_path)
            status["state"] = "DEDUP_REVIEW"
            status["verification"]["result"] = "PASS"
            status["verification"]["positive_control"] = "pending"
            status["dedup"]["determination"] = "NEW"
            workflow.write_yaml(status_path, status)
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_promote_intake(
                    argparse.Namespace(
                        intake_id=intake_id,
                        repo=str(repo),
                        source_ref="origin/main",
                        severity="HIGH",
                        anatomy_tag="CHOICE",
                        approval_ref="owner:file",
                        human_ruling_ref=None,
                        by="coordinator",
                        claim=None,
                        evidence=None,
                        required_correction=None,
                        start_fix=None,
                        fix_title=None,
                    )
                )
            self.assertEqual(result, 1)
            self.assertEqual(workflow.next_issue_number(), 2)

    def test_force_cannot_skip_fix_closure_prerequisites(self) -> None:
        with sandbox() as (_, _, _):
            workflow.create_fix_record("T1-M001", ["M-1"], "Restore widget")
            status_path = workflow.FIXES / "T1-M001" / "STATUS.yaml"
            status = workflow.load_yaml(status_path)
            status["state"] = "DEPLOYED"
            workflow.write_yaml(status_path, status)
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_transition(
                    argparse.Namespace(
                        fix_id="T1-M001",
                        target="CLOSED",
                        by="coordinator",
                        next_owner="coordinator",
                        next_action="done",
                        artifact=None,
                        note=None,
                        approval_ref="owner:force",
                        force=True,
                    )
                )
            self.assertEqual(result, 1)
            status = workflow.load_yaml(status_path)
            self.assertEqual(status["state"], "DEPLOYED")

    def test_report_file_must_stay_inside_workflow_tree(self) -> None:
        with sandbox() as (_, _, _):
            outside = Path("/tmp/workflow-outside-report.md")
            outside.write_text("secret\n", encoding="utf-8")
            args = intake_args("RPT-20260907-000006-outside")
            args.report_file = str(outside)
            with redirect_stderr(io.StringIO()):
                result = workflow.cmd_new_intake(args)
            self.assertEqual(result, 1)
            self.assertFalse(
                (workflow.INTAKE / "RPT-20260907-000006-outside").exists()
            )

    def test_triage_guide_is_read_only(self) -> None:
        policy_path = SOURCE_ROOT / "operations" / "POLICY.yaml"
        before = policy_path.read_bytes()
        self.assertEqual(
            workflow.cmd_guide(argparse.Namespace(operation="triage", show=False)),
            0,
        )
        self.assertEqual(policy_path.read_bytes(), before)


class BusCompatibilityTests(unittest.TestCase):
    def test_bus_parser_accepts_legacy_fix_and_typed_subject(self) -> None:
        bus_path = SOURCE_ROOT / "coordination" / "bus.py"
        spec = importlib.util.spec_from_file_location("workflow_bus", bus_path)
        assert spec and spec.loader
        bus = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bus)
        common = [
            "send",
            "--from",
            "claude",
            "--to",
            "k3",
            "--role",
            "skeptic",
            "--state-from",
            "TRIAGED",
            "--request",
            "review",
            "--subject",
            "test",
        ]
        legacy = bus.parser().parse_args(common + ["--fix", "T1-M160"])
        typed = bus.parser().parse_args(
            common + ["--subject-kind", "campaign", "--subject-id", "2026-09-07-test"]
        )
        self.assertEqual(legacy.fix_id, "T1-M160")
        self.assertEqual(typed.subject_kind, "campaign")

    def test_bus_send_preserves_typed_subject(self) -> None:
        bus_path = SOURCE_ROOT / "coordination" / "bus.py"
        spec = importlib.util.spec_from_file_location("workflow_bus_roundtrip", bus_path)
        assert spec and spec.loader
        bus = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bus)
        with tempfile.TemporaryDirectory(prefix="workflow-bus-test-") as raw:
            root = Path(raw)
            bus.ROOT = root
            bus.INBOX = root / "inbox"
            bus.ARCHIVE = root / "archive"
            bus.LOCK = root / ".bus.lock"
            bus.SEQUENCE = root / "sequence.txt"
            (root / "AGENTS.yaml").write_text(
                "agents:\n"
                "  - id: claude\n    active: true\n"
                "  - id: k3\n    active: true\n",
                encoding="utf-8",
            )
            args = bus.parser().parse_args(
                [
                    "send",
                    "--from",
                    "claude",
                    "--to",
                    "k3",
                    "--subject-kind",
                    "campaign",
                    "--subject-id",
                    "2026-09-07-test",
                    "--role",
                    "reviewer",
                    "--state-from",
                    "ANALYZING",
                    "--request",
                    "REVIEWED",
                    "--subject",
                    "Review campaign",
                ]
            )
            bus.cmd_send(args)
            message = next((root / "inbox" / "k3").glob("*.md"))
            text = message.read_text(encoding="utf-8")
            end = text.find("\n---\n", 4)
            metadata = yaml.safe_load(text[4:end])
            self.assertEqual(
                metadata["subject"],
                {"kind": "campaign", "id": "2026-09-07-test"},
            )
            self.assertEqual(metadata["subject_line"], "Review campaign")


if __name__ == "__main__":
    unittest.main()
