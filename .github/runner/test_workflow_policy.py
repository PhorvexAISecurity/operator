"""Review checks for runner workflow changes; no Docker, API or host mutations."""

import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASELINE = os.environ.get("RUNNER_WORKFLOW_BASELINE", "origin/main")
HELPER = "/usr/local/libexec/phvx-disk-hygiene"
REFRESH = "Refresh completed runner build leases"
REGISTER = "Register exact runner builder"
VERIFICATION = "runner-hardening-verification.yml"
PR_PREFIXES = {
    "benchmark-dashboard.yml": "benchmark-dashboard",
    "e2e-contract.yml": "e2e-contract",
    "litellm-gateway-metrics.yml": "litellm-metrics-source",
    "native-rbac.yml": "native-rbac",
    "pr-validation.yml": "pr-validation",
    "publish-epss-ecr-auth-runtime.yml": "epss-ecr-auth",
    "workflow-harness.yml": "workflow-harness",
    VERIFICATION: "runner-hardening-verification",
}
CI_SAFE_JOBS = ("changes", "build-operator", "build-console", "build-phoenix")
PUBLISH_QUEUES = {
    "publish-vllm-drain-v11.yml": "vllm-drain-v11-${{ github.sha }}",
    "publish-vllm-lease-proxy-runtime.yml": "vllm-lease-proxy-${{ github.sha }}",
    "publish-vllm-reset-ack.yml": "vllm-reset-ack-${{ github.sha }}",
    "publish-voice-admission-runtime.yml": "voice-admission-runtime-${{ github.sha }}",
    "publish-voice-mcp-runtime.yml": "voice-mcp-runtime-${{ github.sha }}",
    "verify-litellm-gateway-runtime.yml": "litellm-gateway-runtime-${{ github.sha }}",
    "runner-disk-cleanup.yml": "runner-disk-cleanup",
}


class WorkflowLoader(yaml.SafeLoader):
    """Keep GitHub's literal 'on' key and reject duplicate keys."""

    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate YAML mapping key")
        return super().construct_mapping(node, deep=deep)


WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    WorkflowLoader.yaml_implicit_resolvers
)
for initial, resolvers in WorkflowLoader.yaml_implicit_resolvers.items():
    WorkflowLoader.yaml_implicit_resolvers[initial] = [
        (tag, pattern) for tag, pattern in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF")
)


def load(text):
    return yaml.load(text, Loader=WorkflowLoader)


def shared(job):
    labels = job["runs-on"]
    labels = [labels] if isinstance(labels, str) else labels
    return "self-hosted" in labels and "phorvex-isolated-aws" not in labels


def normalize(document, candidate=False):
    """Remove only the authorized policy/bookkeeping differences for comparison."""
    result = copy.deepcopy(document)
    result.pop("concurrency", None)
    has_shared = any(shared(job) for job in result["jobs"].values())
    if candidate and has_shared:
        result["permissions"].pop("actions", None)
    for name, job in result["jobs"].items():
        if candidate and name in ("build-operator", "build-console"):
            remove_capacity(job, name)
        job.pop("concurrency", None)
        if candidate and shared(job):
            job["steps"] = [step for step in job["steps"]
                            if step.get("name") not in (REFRESH, REGISTER)]
            for step in job["steps"]:
                if step.get("uses") == "docker/setup-buildx-action@v3":
                    step.pop("id", None)
    return result


CAPACITY_NAME = "Read runner build capacity"
CAPACITY_REF = "BUILD_JOBS=${{ steps.capacity.outputs.build_jobs }}"


def remove_capacity(job, name):
    """Remove this task's exact plumbing; separate tests validate its values."""
    job['steps'] = [step for step in job['steps'] if step.get('name') != CAPACITY_NAME]
    for step in job['steps']:
        if step.get('uses') == 'docker/build-push-action@v6':
            args = step['with'].get('build-args', '')
            if name == 'build-operator' and args == CAPACITY_REF:
                step['with'].pop('build-args')
            elif name == 'build-console':
                step['with']['build-args'] = args.replace(CAPACITY_REF + '\n', '')


def workflow_key(group, event, ref, run_id, pr):
    """Evaluate only the exact, checked GitHub expression grammar used here."""
    compact = "".join(group.split())
    suffix = ("-${{github.event_name=='pull_request'"
              "&&format('pr-{0}',github.event.pull_request.number)"
              "||format('{0}-{1}-{2}',github.event_name,github.ref,github.run_id)}}")
    unique = "-${{github.event_name}}-${{github.ref}}-${{github.run_id}}"
    if compact.endswith(suffix):
        prefix = compact[:-len(suffix)]
        key = f"pr-{pr}" if event == "pull_request" else f"{event}-{ref}-{run_id}"
    elif compact.endswith(unique):
        prefix = compact[:-len(unique)]
        key = f"{event}-{ref}-{run_id}"
    else:
        raise ValueError("unsupported group expression")
    return (prefix + "-" + key).lower()


def cancels_previous(policy, previous, incoming):
    """Check supersession from exact group/flag values, without simulating GitHub."""
    flag = policy["cancel-in-progress"]
    if flag == "${{ github.event_name == 'pull_request' }}":
        enabled = incoming[0] == "pull_request"
    elif flag is False:
        enabled = False
    else:
        raise ValueError("unsupported cancellation expression")
    return enabled and workflow_key(policy["group"], *previous) == workflow_key(
        policy["group"], *incoming)


class RunnerWorkflowPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = {path.name: load(path.read_text())
                         for path in sorted((ROOT / ".github/workflows").glob("*.yml"))}
        names = subprocess.check_output(
            ["git", "ls-tree", "--name-only", BASELINE, ".github/workflows/"],
            cwd=ROOT, text=True,
        ).splitlines()
        cls.baseline = {
            Path(name).name: load(subprocess.check_output(
                ["git", "show", f"{BASELINE}:{name}"], cwd=ROOT, text=True
            )) for name in names if name.endswith(".yml")
        }

    def test_yaml_inventory_and_duplicate_guard(self):
        self.assertEqual(set(self.baseline) | {VERIFICATION}, set(self.candidate))
        self.assertNotIn(VERIFICATION, self.baseline)
        self.assertEqual(set(PR_PREFIXES) | set(PUBLISH_QUEUES) | {"ci.yml"},
                         set(self.candidate))
        with self.assertRaises(ValueError):
            load("jobs: {}\njobs: {}\n")
        for document in self.candidate.values():
            self.assertIn("on", document)

    def test_same_pr_only_cancellation_and_nonpr_key_matrix(self):
        workflow_keys = set()
        for filename, prefix in PR_PREFIXES.items():
            with self.subTest(workflow=filename):
                policy = self.candidate[filename]["concurrency"]
                self.assertEqual(set(policy), {"group", "cancel-in-progress"})
                self.assertEqual(policy["cancel-in-progress"],
                                 "${{ github.event_name == 'pull_request' }}")
                group = policy["group"]
                first = workflow_key(group, "pull_request", "refs/pull/12/merge", 1, 12)
                self.assertEqual(first, prefix + "-pr-12")
                self.assertEqual(first, workflow_key(
                    group, "pull_request", "refs/pull/12/merge", 2, 12))
                self.assertNotEqual(first, workflow_key(
                    group, "pull_request", "refs/pull/13/merge", 2, 13))
                workflow_keys.add(first)
                for event, ref in (("push", "refs/heads/main"),
                                   ("push", "refs/tags/v0.4.227"),
                                   ("workflow_dispatch", "refs/heads/main"),
                                   ("workflow_dispatch", "refs/heads/topic")):
                    keys = {workflow_key(group, event, ref, run, 12) for run in (1, 2, 3)}
                    self.assertEqual(len(keys), 3)
                    self.assertNotIn(first, keys)
        self.assertEqual(len(workflow_keys), len(PR_PREFIXES))

    def test_ci_parent_exception_preserves_live_jobs_on_pr_supersession(self):
        document = self.candidate["ci.yml"]
        parent = document["concurrency"]
        self.assertEqual(parent, {
            "group": "operator-ci-${{ github.event_name }}-${{ github.ref }}-${{ github.run_id }}",
            "cancel-in-progress": False,
        })
        cases = (("pull_request", "refs/pull/12/merge", 12),
                 ("pull_request", "refs/pull/13/merge", 13),
                 ("push", "refs/heads/main", None),
                 ("push", "refs/tags/v0.4.227", None),
                 ("workflow_dispatch", "refs/heads/main", None),
                 ("workflow_dispatch", "refs/heads/topic", None))
        keys = set()
        for event, ref, pr in cases:
            previous, incoming = (event, ref, 1, pr), (event, ref, 2, pr)
            with self.subTest(event=event, ref=ref):
                for case in (previous, incoming):
                    key = workflow_key(parent["group"], *case)
                    self.assertEqual(key, f"operator-ci-{event}-{ref}-{case[2]}")
                    self.assertNotIn(key, keys)
                    keys.add(key)
                self.assertFalse(cancels_previous(parent, previous, incoming))
        # A newer PR's safe job can supersede the older job without a parent
        # cancellation reaching an already running independent shared E2E job.
        previous = ("pull_request", "refs/pull/12/merge", 1, 12)
        incoming = ("pull_request", "refs/pull/12/merge", 2, 12)
        for job in CI_SAFE_JOBS:
            self.assertTrue(cancels_previous(document["jobs"][job]["concurrency"],
                                             previous, incoming))
        for job in ("chart-sync", "e2e", "e2e-main", "deploy"):
            policy = document["jobs"][job].get("concurrency")
            if policy is not None:
                self.assertIs(policy["cancel-in-progress"], False)
            self.assertFalse(cancels_previous(parent, previous, incoming))

    def test_safe_ci_job_same_pr_cancellation_and_nonpr_key_matrix(self):
        jobs = self.candidate["ci.yml"]["jobs"]
        all_keys = set()
        events = (("push", "refs/heads/main"),
                  ("push", "refs/tags/v0.4.227"),
                  ("workflow_dispatch", "refs/heads/main"),
                  ("workflow_dispatch", "refs/heads/topic"))
        parent = self.candidate["ci.yml"]["concurrency"]
        other_pr_keys = {workflow_key(doc["concurrency"]["group"],
                                     "pull_request", "refs/pull/12/merge", 1, 12)
                         for name, doc in self.candidate.items() if name in PR_PREFIXES}
        for job in CI_SAFE_JOBS:
            with self.subTest(job=job):
                policy = jobs[job]["concurrency"]
                self.assertEqual(set(policy), {"group", "cancel-in-progress"})
                self.assertEqual(policy["cancel-in-progress"],
                                 "${{ github.event_name == 'pull_request' }}")
                previous = ("pull_request", "refs/pull/12/merge", 1, 12)
                incoming = ("pull_request", "refs/pull/12/merge", 2, 12)
                key = workflow_key(policy["group"], *previous)
                self.assertEqual(key, f"operator-ci-{job}-pr-12")
                self.assertEqual(key, workflow_key(policy["group"], *incoming))
                self.assertNotIn(key, all_keys | other_pr_keys)
                all_keys.add(key)
                self.assertTrue(cancels_previous(policy, previous, incoming))
                different_pr = ("pull_request", "refs/pull/13/merge", 3, 13)
                self.assertFalse(cancels_previous(policy, previous, different_pr))
                for event, ref in events:
                    for run in (1, 2, 3):
                        case = (event, ref, run, None)
                        key = workflow_key(policy["group"], *case)
                        self.assertEqual(key, f"operator-ci-{job}-{event}-{ref}-{run}")
                        self.assertNotIn(key, all_keys)
                        all_keys.add(key)
                        self.assertNotEqual(key, workflow_key(parent["group"], *case))
                        self.assertFalse(cancels_previous(policy, previous, case))
                        self.assertFalse(cancels_previous(policy, case, case))
                        self.assertFalse(cancels_previous(policy, case, (event, ref, run+1, None)))
                if job != "changes":
                    builds = [step for step in jobs[job]["steps"]
                              if step.get("uses") == "docker/build-push-action@v6"]
                    self.assertEqual(len(builds), 1)
                    self.assertEqual(builds[0]["with"]["push"],
                                     "${{ github.event_name != 'pull_request' }}")

    def test_concurrency_job_scope_is_exact(self):
        actual = {(filename, name) for filename, doc in self.candidate.items()
                  for name, job in doc["jobs"].items() if "concurrency" in job}
        expected = {("ci.yml", name) for name in
                    (*CI_SAFE_JOBS, "e2e", "e2e-main", "deploy")}
        expected.add(("publish-epss-ecr-auth-runtime.yml", "publish"))
        self.assertEqual(actual, expected)
        self.assertNotIn("concurrency", self.candidate["ci.yml"]["jobs"]["chart-sync"])
        self.assertNotIn("concurrency", self.baseline["ci.yml"]["jobs"]["chart-sync"])
        # Release publication is a step inside the protected deploy job.
        self.assertTrue(any(step.get("run") == "bash deploy/ci/publish-release.sh"
                            for step in self.candidate["ci.yml"]["jobs"]["deploy"]["steps"]))

    def test_protected_queues_preserve_serialization(self):
        for filename, group in PUBLISH_QUEUES.items():
            with self.subTest(workflow=filename):
                self.assertEqual(self.candidate[filename]["concurrency"], {
                    "group": group, "cancel-in-progress": False, "queue": "max",
                })
                self.assertEqual(group, self.baseline[filename]["concurrency"]["group"])
        jobs = self.candidate["ci.yml"]["jobs"]
        for name, group in (("e2e", "phorvex-e2e-live"),
                            ("e2e-main", "phorvex-e2e-live"),
                            ("deploy", "phorvex-deploy-main")):
            self.assertEqual(jobs[name]["concurrency"], {
                "group": group, "cancel-in-progress": False, "queue": "max",
            })
            self.assertEqual(group, self.baseline["ci.yml"]["jobs"][name]["concurrency"]["group"])
        epss = self.candidate["publish-epss-ecr-auth-runtime.yml"]["jobs"]
        self.assertEqual(epss["publish"]["concurrency"], {
            "group": "epss-ecr-auth-publish-${{ github.sha }}",
            "cancel-in-progress": False, "queue": "max",
        })
        self.assertEqual(epss["publish"]["if"],
                         "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'")
        self.assertEqual(epss["test"]["runs-on"], "ubuntu-latest")
        self.assertEqual(epss["publish"]["needs"], ["test", "isolated-tests"])
        queues = [doc["concurrency"] for doc in self.candidate.values()
                  if doc["concurrency"].get("queue") == "max"]
        queues += [job["concurrency"] for doc in self.candidate.values()
                   for job in doc["jobs"].values()
                   if job.get("concurrency", {}).get("queue") == "max"]
        self.assertEqual(len(queues), 11)
        self.assertTrue(all(queue["cancel-in-progress"] is False for queue in queues))

    def test_baseline_equivalence_outside_authorized_changes(self):
        for filename, baseline in self.baseline.items():
            with self.subTest(workflow=filename):
                before = normalize(baseline)
                after = normalize(self.candidate[filename], candidate=True)
                if filename == "runner-disk-cleanup.yml":
                    before["jobs"]["cleanup"].pop("steps")
                    after["jobs"]["cleanup"].pop("steps")
                self.assertEqual(before, after)

    def test_refresh_policy_and_step_only_automatic_token(self):
        refresh_count = 0
        best_effort_count = 0
        for filename, document in self.candidate.items():
            before = self.baseline.get(filename)
            self.assertNotIn("GH_TOKEN", document.get("env", {}))
            expected_permissions = (copy.deepcopy(before["permissions"]) if before
                                    else {"contents": "read", "actions": "read"})
            if any(shared(job) for job in document["jobs"].values()):
                expected_permissions["actions"] = "read"
            self.assertEqual(document["permissions"], expected_permissions)
            for name, job in document["jobs"].items():
                with self.subTest(workflow=filename, job=name):
                    self.assertNotIn("GH_TOKEN", job.get("env", {}))
                    refresh_steps = [step for step in job["steps"]
                                     if step.get("name") == REFRESH]
                    if shared(job):
                        refresh_count += 1
                        self.assertEqual(len(refresh_steps), 1)
                        self.assertEqual(job["steps"][0], refresh_steps[0])
                        self.assertNotIn("if", refresh_steps[0])
                        if filename == "runner-disk-cleanup.yml":
                            self.assertNotIn("continue-on-error", refresh_steps[0])
                        else:
                            self.assertIs(refresh_steps[0].get("continue-on-error"), True)
                            best_effort_count += 1
                        self.assertEqual(refresh_steps[0]["env"], {
                            "GH_TOKEN": "${{ github.token }}",
                        })
                    else:
                        self.assertEqual(refresh_steps, [])
                    for step in job["steps"]:
                        if step.get("name") != REFRESH:
                            self.assertNotIn("GH_TOKEN", step.get("env", {}))
        self.assertEqual(refresh_count, 16)
        self.assertEqual(best_effort_count, 15)
        # These jobs still refresh when path filtering skips all three builds.
        for name in ("changes", "chart-sync", "deploy", "e2e-main"):
            self.assertEqual(self.candidate["ci.yml"]["jobs"][name]["steps"][0]["name"], REFRESH)

    def test_exact_builder_registration_before_work_and_aws_unchanged(self):
        builders = 0
        for filename, document in self.candidate.items():
            for name, job in document["jobs"].items():
                with self.subTest(workflow=filename, job=name):
                    if not shared(job):
                        self.assertFalse(any(step.get("name") == REGISTER for step in job["steps"]))
                        self.assertEqual(job["steps"], self.baseline[filename]["jobs"][name]["steps"])
                        continue
                    setup_count = 0
                    for index, step in enumerate(job["steps"]):
                        if step.get("uses") != "docker/setup-buildx-action@v3":
                            continue
                        builders += 1
                        setup_count += 1
                        self.assertEqual(step["id"], "buildx")
                        registration = job["steps"][index + 1]
                        self.assertEqual(registration["name"], REGISTER)
                        self.assertEqual(registration.get("if"), step.get("if"))
                        self.assertEqual(registration["env"], {
                            "BUILDER_NAME": "${{ steps.buildx.outputs.name }}",
                        })
                        self.assertNotIn("continue-on-error", registration)
                        self.assertFalse(job.get("continue-on-error", False))
                        builds = [i for i, following in enumerate(job["steps"])
                                  if following.get("uses") == "docker/build-push-action@v6"
                                  or re.search(r"\bdocker\s+buildx\s+build\b",
                                               following.get("run", ""))]
                        self.assertTrue(builds)
                        self.assertTrue(all(i > index + 1 for i in builds))
                        for i in builds:
                            self.assertNotRegex(job["steps"][i].get("if", ""),
                                                r"\b(?:always|failure|cancelled)\s*\(")
                        if filename == VERIFICATION:
                            self.assertEqual(step["with"], {"cleanup": True, "keep-state": False, "driver-opts": "image=moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"})
                        else:
                            original = next(original for original in
                                            self.baseline[filename]["jobs"][name]["steps"]
                                            if original.get("uses") == step["uses"])
                            self.assertEqual({key: value for key, value in step.items() if key != "id"}, original)
                    self.assertEqual(setup_count, sum(
                        step.get("name") == REGISTER for step in job["steps"]))
        self.assertEqual(builders, 9)

    def execute(self, step, directory, exit_code=0, missing=False, builder="builder-exact",
                exit_codes=None):
        helper = directory / "helper"
        log = directory / "calls.jsonl"
        helper.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ['TEST_HELPER_LOG'], 'a') as log:
    log.write(json.dumps({'args': sys.argv[1:], 'token_present': 'GH_TOKEN' in os.environ}) + '\\n')
codes = json.loads(os.environ['TEST_HELPER_EXIT_CODES'])
sys.exit(codes.get(sys.argv[1], int(os.environ['TEST_HELPER_EXIT'])))
""")
        helper.chmod(0o700)
        if missing:
            helper.unlink()
        env = os.environ.copy()
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_TOKEN", None)
        env.update({"GITHUB_REPOSITORY": "PhorvexSecurity/operator",
                    "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2",
                    "BUILDER_NAME": builder,
                    "TEST_HELPER_LOG": str(log), "TEST_HELPER_EXIT": str(exit_code),
                    "TEST_HELPER_EXIT_CODES": json.dumps(exit_codes or {})})
        if "GH_TOKEN" in step.get("env", {}):
            env["GH_TOKEN"] = "synthetic-test-token"
        script = step["run"].replace(HELPER, shlex.quote(str(helper)))
        result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
                                input=script, text=True, capture_output=True, env=env,
                                cwd=directory, timeout=10)
        records = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, records

    def test_actual_refresh_scripts_report_errors_and_pass_exact_repository(self):
        for filename, doc in self.candidate.items():
            for name, job in doc["jobs"].items():
                if not shared(job):
                    continue
                with self.subTest(workflow=filename, job=name), tempfile.TemporaryDirectory() as temp:
                    directory = Path(temp)
                    result, records = self.execute(job["steps"][0], directory)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(records, [{"args": ["refresh", "--repository", "PhorvexSecurity/operator"],
                                                "token_present": True}])
                    (directory / "calls.jsonl").unlink()
                    result, records = self.execute(job["steps"][0], directory, exit_code=23)
                    self.assertEqual(result.returncode, 23)
                    (directory / "calls.jsonl").unlink()
                    result, records = self.execute(job["steps"][0], directory, missing=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("helper is not installed", result.stderr)
                    self.assertEqual(records, [])

    def execute_before_work(self, steps, directory, **kwargs):
        """Run real snippets with literal continue-on-error handling at step boundaries.

        The disposable work marker stands in for a later build/publication step.
        This checks the shell failures and checked YAML policy, not GitHub hosting.
        """
        outcomes, records = [], []
        for step in steps:
            result, records = self.execute(step, directory, **kwargs)
            outcomes.append(result.returncode)
            if result.returncode and step.get("continue-on-error") is not True:
                return result.returncode, outcomes, records
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
             "printf 'work reached\\n' > work-reached"],
            cwd=directory, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.returncode, outcomes, records

    def test_refresh_failure_stops_only_manual_hygiene(self):
        for filename, doc in self.candidate.items():
            for name, job in doc["jobs"].items():
                if not shared(job):
                    continue
                manual = filename == "runner-disk-cleanup.yml"
                steps = job["steps"] if manual else [job["steps"][0]]
                for missing in (False, True):
                    with self.subTest(workflow=filename, job=name, missing=missing), \
                            tempfile.TemporaryDirectory() as temp:
                        directory = Path(temp)
                        code, outcomes, records = self.execute_before_work(
                            steps, directory, exit_codes={"refresh": 23}, missing=missing,
                        )
                        self.assertNotEqual(outcomes[0], 0)
                        self.assertEqual((directory / "work-reached").exists(), not manual)
                        if manual:
                            self.assertNotEqual(code, 0)
                            self.assertEqual(len(outcomes), 1)
                        else:
                            self.assertEqual(code, 0)
                        self.assertEqual([record["args"][0] for record in records],
                                         [] if missing else ["refresh"])

    def test_registration_failure_stops_before_build_or_publication(self):
        for filename, doc in self.candidate.items():
            for name, job in doc["jobs"].items():
                registration = [step for step in job["steps"]
                                if step.get("name") == REGISTER]
                if not registration:
                    continue
                steps = [job["steps"][0], *registration]
                # Refresh can fail while registration succeeds; registration failure
                # or helper removal must still stop the later build/publication.
                for refresh_code, registration_code, missing in (
                        (0, 0, False), (23, 0, False),
                        (0, 24, False), (23, 24, False), (0, 0, True)):
                    with self.subTest(workflow=filename, job=name, refresh=refresh_code,
                                      registration=registration_code, missing=missing), \
                            tempfile.TemporaryDirectory() as temp:
                        directory = Path(temp)
                        code, outcomes, records = self.execute_before_work(
                            steps, directory, missing=missing,
                            exit_codes={"refresh": refresh_code, "register": registration_code},
                        )
                        succeeds = not missing and registration_code == 0
                        self.assertEqual(code == 0, succeeds)
                        self.assertEqual((directory / "work-reached").exists(), succeeds)
                        self.assertEqual(len(outcomes), 2)
                        self.assertEqual([record["args"][0] for record in records],
                                         [] if missing else ["refresh", "register"])
                        self.assertEqual([record["token_present"] for record in records],
                                         [] if missing else [True, False])

    def test_actual_registration_scripts_keep_arguments_and_propagate_failure(self):
        for filename, doc in self.candidate.items():
            for name, job in doc["jobs"].items():
                for step in job["steps"]:
                    if step.get("name") != REGISTER:
                        continue
                    with self.subTest(workflow=filename, job=name), tempfile.TemporaryDirectory() as temp:
                        directory = Path(temp)
                        builder = "builder-one; touch injected"
                        result, records = self.execute(step, directory, builder=builder)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(records, [{"args": [
                            "register", "--repository", "PhorvexSecurity/operator",
                            "--run-id", "12345", "--run-attempt", "2", "--builder", builder,
                        ], "token_present": False}])
                        self.assertFalse((directory / "injected").exists())
                        result, _ = self.execute(step, directory, exit_code=24)
                        self.assertEqual(result.returncode, 24)
                        result, _ = self.execute(step, directory, missing=True)
                        self.assertNotEqual(result.returncode, 0)

    def test_manual_cleanup_uses_only_installed_helper_inventory_and_request(self):
        steps = self.candidate["runner-disk-cleanup.yml"]["jobs"]["cleanup"]["steps"]
        self.assertEqual([step["run"] for step in steps[1:]], [
            HELPER + " report", HELPER + " request", HELPER + " report",
        ])
        for step in steps:
            self.assertNotIn("continue-on-error", step)
            self.assertNotRegex(step["run"], r"\bdocker\b|\brm\b|\bprune\b|RUNNER_TEMP|sudo")
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            records = []
            for step in steps:
                result, records = self.execute(step, directory)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([record["args"][0] for record in records],
                             ["refresh", "report", "request", "report"])
            self.assertEqual([record["token_present"] for record in records],
                             [True, False, False, False])
            result, _ = self.execute(steps[2], directory, exit_code=25)
            self.assertEqual(result.returncode, 25)

    def test_verification_is_narrow_draft_safe_and_never_publishes(self):
        document = self.candidate[VERIFICATION]
        self.assertEqual(set(document), {"name", "on", "permissions", "concurrency", "jobs"})
        # Default opened/synchronize/reopened PR events include drafts; no draft gate.
        self.assertEqual(document["on"], {"pull_request": {"paths": [
            ".github/workflows/**", ".github/runner/**",
        ]}})
        self.assertEqual(document["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(set(document["jobs"]), {"verify"})
        job = document["jobs"]["verify"]
        self.assertEqual(set(job), {"runs-on", "timeout-minutes", "steps"})
        self.assertEqual(job["runs-on"], "self-hosted")
        self.assertEqual(job["timeout-minutes"], 10)
        steps = job["steps"]
        self.assertEqual([step.get("uses") or step.get("name") for step in steps], [
            REFRESH, "actions/checkout@v4", "docker/setup-buildx-action@v3", REGISTER,
            "Create isolated verification fixture",
            "Build verification fixture without exporting an image",
        ])
        self.assertEqual(steps[1], {"uses": "actions/checkout@v4",
                                   "with": {"persist-credentials": False}})
        self.assertEqual(steps[2], {"uses": "docker/setup-buildx-action@v3", "id": "buildx",
                                   "with": {"cleanup": True, "keep-state": False, "driver-opts": "image=moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"}})
        self.assertEqual(set(steps[4]), {"name", "id", "run"})
        self.assertEqual(steps[4]["id"], "fixture")
        self.assertEqual(steps[5]["env"], {
            "BUILDER_NAME": "${{ steps.buildx.outputs.name }}",
            "FIXTURE_DIR": "${{ steps.fixture.outputs.context }}",
        })
        encoded = json.dumps(document)
        self.assertNotRegex(encoded, r"secrets\.|github\.event\.pull_request\.draft|\b(?:sudo|ssh|telegram|prune)\b")
        for index, step in enumerate(steps):
            self.assertNotIn("if", step)
            if index:
                self.assertNotIn("continue-on-error", step)
            body = step.get("run", "")
            self.assertNotRegex(body, r"\b(?:rm|trap)\b|--(?:push|load|tag|output|cache-to|attest|provenance|ssh|secret|pull)\b")
        self.assertIn('--builder "$BUILDER_NAME" --no-cache --progress=plain "$FIXTURE_DIR"', steps[5]["run"])

    def test_actual_verification_fixture_and_build_are_bounded(self):
        steps = self.candidate[VERIFICATION]["jobs"]["verify"]["steps"]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            runner_temp = directory / "runner temp"
            runner_temp.mkdir()
            sentinel = runner_temp / "other-job-data"
            sentinel.write_text("preserve")
            output = directory / "step-output"
            env = os.environ.copy()
            env.update({"RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output),
                        "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"})

            def execute_body(step):
                return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
                                      input=step["run"], text=True, capture_output=True,
                                      cwd=directory, env=env, timeout=10)

            result = execute_body(steps[4])
            self.assertEqual(result.returncode, 0, result.stderr)
            line, = output.read_text().splitlines()
            self.assertTrue(line.startswith("context="))
            fixture = Path(line.split("=", 1)[1])
            self.assertEqual(fixture.parent, runner_temp)
            self.assertTrue(fixture.name.startswith("runner-hardening-verification."))
            self.assertEqual([path.name for path in fixture.iterdir()], ["Dockerfile"])
            self.assertEqual((fixture / "Dockerfile").read_text(),
                             "FROM alpine:3.21\nRUN echo verification && sleep 12\n")
            # Capture actual CLI argv rather than contacting Docker or running a build.
            bin_dir = directory / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                              "with open(os.environ['TEST_DOCKER_LOG'], 'a') as log:\n"
                              "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                              "sys.exit(int(os.environ['TEST_DOCKER_EXIT']))\n")
            docker.chmod(0o700)
            log = directory / "docker-calls"
            builder = "builder-one; touch injected"
            env.update({"PATH": str(bin_dir) + os.pathsep + env["PATH"],
                        "FIXTURE_DIR": str(fixture), "BUILDER_NAME": builder,
                        "TEST_DOCKER_LOG": str(log), "TEST_DOCKER_EXIT": "0"})
            result = execute_body(steps[5])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], [[
                "buildx", "build", "--builder", builder, "--no-cache", "--progress=plain", str(fixture),
            ]])
            self.assertFalse((directory / "injected").exists())
            env["TEST_DOCKER_EXIT"] = "29"
            result = execute_body(steps[5])
            self.assertEqual(result.returncode, 29)
            log.unlink()
            env["FIXTURE_DIR"] = str(directory)
            result = execute_body(steps[5])
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(log.exists(), "unexpected context reached Docker")
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertTrue((fixture / "Dockerfile").exists(), "job body deleted fixture/RUNNER_TEMP")


class RunnerSpeedPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = os.environ.get('RUNNER_SPEED_BASELINE', '9fd64966de5b93162da59f1a21cedafd11ff9ce0')
        cls.candidate = {path.name: load(path.read_text()) for path in (ROOT / '.github/workflows').glob('*.yml')}
        names = subprocess.check_output(['git', 'ls-tree', '--name-only', cls.pin, '.github/workflows/'], cwd=ROOT, text=True).splitlines()
        cls.baseline = {Path(name).name: load(subprocess.check_output(['git', 'show', f'{cls.pin}:{name}'], cwd=ROOT, text=True)) for name in names if name.endswith('.yml')}

    def test_only_two_exact_capacity_differences_against_pinned_main(self):
        self.assertEqual(set(self.candidate), set(self.baseline))
        for name, before in self.baseline.items():
            after = copy.deepcopy(self.candidate[name])
            if name == 'ci.yml':
                for job_name in ('build-operator', 'build-console'):
                    job = after['jobs'][job_name]
                    capacity = [step for step in job['steps'] if step.get('name') == CAPACITY_NAME]
                    self.assertEqual(len(capacity), 1)
                    step = capacity[0]
                    self.assertEqual(set(step), {'name', 'id', 'run'})
                    self.assertEqual(step['id'], 'capacity')
                    index = job['steps'].index(step)
                    self.assertEqual(job['steps'][index - 1]['uses'], 'actions/checkout@v4')
                    self.assertLess(index, next(i for i, item in enumerate(job['steps']) if item.get('uses') == 'docker/setup-buildx-action@v3'))
                    build = next(item for item in job['steps'] if item.get('uses') == 'docker/build-push-action@v6')
                    expected = CAPACITY_REF if job_name == 'build-operator' else 'CONSOLE_VERSION=${{ steps.meta.outputs.version }}\n' + CAPACITY_REF + '\n'
                    self.assertEqual(build['with']['build-args'], expected)
                    self.assertEqual(step['run'], self.candidate['ci.yml']['jobs']['build-operator']['steps'][index]['run'])
                    remove_capacity(job, job_name)
            with self.subTest(workflow=name):
                self.assertEqual(before, after)

    def test_capacity_shell_validation_and_fallback_without_eval(self):
        steps = self.candidate['ci.yml']['jobs']['build-operator']['steps']
        body = next(step['run'] for step in steps if step.get('id') == 'capacity')
        self.assertNotRegex(body, r'\b(?:source|eval)\b')
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'capacity.env'
            output = Path(directory) / 'output'
            body = body.replace('/run/phvx-runner-capacity.env', str(file))
            for value, expected in [(None, '2'), ('P=7\nGOMAXPROCS=7\n', '7'), ('P=0\n', '2'), ('P=2;touch injected\n', '2'), ('P=7\nP=8\n', '2'), ('P=-1\n', '2')]:
                if value is None: file.unlink(missing_ok=True)
                else: file.write_text(value)
                output.write_text('')
                result = subprocess.run(['bash', '-e', '-o', 'pipefail'], input=body, text=True, capture_output=True, cwd=directory, env={**os.environ, 'GITHUB_OUTPUT': str(output)})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), 'build_jobs=' + expected + '\n')
                self.assertFalse((Path(directory) / 'injected').exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
