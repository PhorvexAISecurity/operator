"""Guard the actual all-base candidate-source workflow and its fail-closed gate."""
from pathlib import Path
import json
import os
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / '.github/workflows/pr-validation.yml').read_text()
# A fresh GitHub-hosted runner for every job. It holds no cluster or AWS credentials;
# the isolated AWS runner (label phorvex-isolated-aws) must never run this repo's jobs.
BUILD_RUNNER = 'ubuntu-24.04'
DOC = yaml.load(RAW, Loader=yaml.BaseLoader)


class PRValidationTests(unittest.TestCase):
    def test_all_pr_bases_and_drafts_get_unprivileged_checks(self):
        self.assertEqual(DOC['on']['pull_request'], '')
        self.assertEqual(DOC['permissions'], {'contents': 'read'})
        for forbidden in ('secrets.', 'id-token:', 'phorvex-isolated-aws', 'pull_request_target',
                          'aws-actions/', 'ssh ', 'kubectl ', 'pipeline/e2e.py',
                          'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, RAW)
        for name, job in DOC['jobs'].items():
            self.assertEqual(job['runs-on'], BUILD_RUNNER)
            if name != 'pr-validation':
                self.assertNotIn('if', job)
            for step in job['steps']:
                if step.get('uses', '').startswith('actions/checkout@'):
                    self.assertEqual(step['with'].get('persist-credentials'), 'false')
                    self.assertLessEqual(set(step['with']), {'persist-credentials', 'fetch-depth'})

    def test_jobs_running_evidence_tests_fetch_full_history(self):
        for workflow, job in (('pr-validation.yml', 'charts'), ('e2e-contract.yml', 'e2e-contract')):
            doc = yaml.load((ROOT / '.github/workflows' / workflow).read_text(), Loader=yaml.BaseLoader)
            checkout = next(s for s in doc['jobs'][job]['steps']
                            if s.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with'].get('fetch-depth'), '0', workflow)

    def test_real_source_checks_are_wired_without_masking_failures(self):
        jobs = DOC['jobs']
        runs = {k: '\n'.join(s.get('run', '') for s in v['steps'])
                for k, v in jobs.items()}
        self.assertIn('diff -u phorvex/config/crd/bases/', runs['charts'])
        self.assertIn('bash tools/check-vendored-chart.sh', runs['charts'])
        self.assertIn('helm template phorvex deploy/helm/phorvex-stack', runs['charts'])
        self.assertIn('for chart in deploy/charts/*/; do helm lint --strict "$chart"; done', runs['charts'])
        self.assertIn('python tools/verify_committed_staging_batch.py', runs['charts'])
        committed_verifier = (ROOT / 'tools/verify_committed_staging_batch.py').read_text()
        self.assertIn('release.verify_deployment(value, None, canonical)', committed_verifier)
        self.assertIn('selection = isolated_selection_commit(source)', committed_verifier)
        self.assertIn('"--services", str(services), "--base", source', committed_verifier)
        self.assertLess(
            committed_verifier.index('selection = isolated_selection_commit(source)'),
            committed_verifier.index('if shared_source:'),
        )
        self.assertLess(
            committed_verifier.index('"--services", str(services), "--base", source'),
            committed_verifier.index('if shared_source:'),
        )
        self.assertIn('source_root / "tools/staging_release.py"', committed_verifier)
        self.assertIn('run(str(shared_helper), "pending", "--json", cwd=ROOT)', committed_verifier)
        self.assertIn('superseding_shared=release.read_json(SHARED_BATCH)', committed_verifier)
        self.assertLess(
            committed_verifier.index('run(str(shared_helper), "pending", "--json", cwd=ROOT)'),
            committed_verifier.index('superseding_shared=release.read_json(SHARED_BATCH)'),
        )
        self.assertIn(
            'cleanup_worktrees(temporary, [selection_root, shared_root, source_root])',
            committed_verifier,
        )
        self.assertNotIn('check=False', committed_verifier)
        self.assertNotIn('ignore_errors=True', committed_verifier)
        self.assertIn('python tools/check-path-case-collisions.py', runs['charts'])
        self.assertIn('go -C phorvex test -mod=readonly -count=1 -timeout=15m ./...', runs['go-unit'])
        self.assertEqual(jobs['go-unit']['env']['KUBECONFIG'], '/dev/null')
        self.assertEqual(jobs['go-unit']['env']['USE_EXISTING_CLUSTER'], 'false')
        self.assertTrue(any(s.get('uses') == 'azure/setup-helm@v4'
                            and s.get('with', {}).get('version') == 'v3.16.4'
                            for s in jobs['go-unit']['steps']))
        # Separate modules are executed, not merely compiled as dependencies.
        for module, minutes in (('build/metricvalidity', 5), ('build/test-harness', 15),
                                ('build/phoenix-extended', 15), ('libs/logging', 5),
                                ('build/integrations/epss-ecr-auth-runtime', 5),
                                ('farm-fixtures/agentsim', 5)):
            self.assertIn(f'go -C {module} test -mod=readonly -count=1 -timeout={minutes}m ./...', runs['go-unit'])
        for command in ('npm ci', 'npx --no-install tsc --noEmit --incremental false', 'npm run build'):
            self.assertIn(command, runs['frontend'])
        self.assertIn('python build/integrations/epss-ecr-auth-runtime/verify_recipe.py', runs['charts'])
        self.assertIn('python3 tools/check-go-format.py "$BASE"', runs['lint'])
        self.assertIn('go -C "$module" vet ./...', runs['lint'])
        self.assertEqual(jobs['images']['strategy']['matrix']['image'], ['operator', 'console', 'brain', 'sensor', 'actuator', 'attacks'])
        self.assertIn('docker build --file "deploy/docker/$IMAGE.Dockerfile"', runs['images'])
        self.assertIn('docker build --file deploy/docker/service.Dockerfile --build-arg "SERVICE=$IMAGE"', runs['images'])
        self.assertIn('docker build --file deploy/docker/console.Dockerfile --target attacks', runs['images'])
        self.assertIn('tools/verify-git-build-identity.sh "$GITHUB_SHA"', runs['images'])
        self.assertIn('--build-arg "GIT_SHA=$reviewed_sha"', runs['images'])
        self.assertIn('tools/verify_service_image_identity.py', runs['images'])
        self.assertIn('tools/verify_fixture_reproducibility.py --source-date-epoch 0',
                      runs['fixture-images'])
        for forbidden in ('docker push', 'docker login', '--push'):
            self.assertNotIn(forbidden, runs['images'])

    def test_every_go_module_is_tested_and_vetted(self):
        # A new module must join go-unit and lint, or it would compile without its
        # own tests ever running.
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '*go.mod'], check=True,
                                 capture_output=True, text=True).stdout.split()
        modules = sorted(str(Path(p).parent) for p in tracked if not p.startswith('workflow/'))
        runs = {k: '\n'.join(s.get('run', '') for s in v['steps']) for k, v in DOC['jobs'].items()}
        vetted = re.search(r'for module in (.*?); do', runs['lint'], re.S).group(1).replace('\\', ' ').split()
        self.assertIn('phorvex', modules)
        self.assertEqual(sorted(vetted), modules)
        for module in modules:
            with self.subTest(module=module):
                self.assertIn(f'go -C {module} test -mod=readonly', runs['go-unit'])

    def test_envtest_job_runs_required_api_and_controller_tests_on_pinned_local_binaries(self):
        job = DOC['jobs']['go-envtest']
        self.assertEqual(job['env']['KUBECONFIG'], '/dev/null')
        self.assertEqual(job['env']['USE_EXISTING_CLUSTER'], 'false')
        self.assertNotIn('KUBEBUILDER_ASSETS', job['env'])  # provisioned, never blanked
        self.assertIn('timeout-minutes', job)
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        self.assertIn('bash tools/provision-envtest.sh', runs)
        self.assertIn('echo "KUBEBUILDER_ASSETS=$assets" >> "$GITHUB_ENV"', runs)
        self.assertIn('bash tools/provision-kube-controller-manager.sh', runs)
        self.assertIn('echo "KUBE_CONTROLLER_MANAGER=$controller_manager" >> "$GITHUB_ENV"', runs)
        self.assertIn('python3 tools/envtest_gate.py run --raw-output envtest-evidence/go-test.jsonl '
                      '--summary envtest-evidence/summary.json --timeout 10m', runs)
        # The full actuator suite renders the Helm chart; without helm those tests skip and
        # the gate fails, so the job pins the same Helm as go-unit.
        self.assertTrue(any(s.get('uses') == 'azure/setup-helm@v4'
                            and s.get('with', {}).get('version') == 'v3.16.4'
                            for s in job['steps']))
        uploads = [s for s in job['steps'] if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]['if'], 'always()')
        self.assertEqual(uploads[0]['with']['path'], 'envtest-evidence/')
        self.assertEqual(uploads[0]['with']['if-no-files-found'], 'error')
        # The same Go selection as go-unit: highest module go directive, local toolchain.
        setup = [s for s in job['steps'] if s.get('uses', '').startswith('actions/setup-go@')]
        self.assertEqual(setup[0]['with']['go-version-file'], 'build/test-harness/go.mod')
        self.assertEqual(job['env']['GOTOOLCHAIN'], 'local')
        script = (ROOT / 'tools/provision-envtest.sh').read_text()
        self.assertIn('VERSION=1.34.0', script)
        self.assertIn('SHA256=9c45e40aa56971b105e596ebb3e84af6742e8709cc0523733baf8d9bb725e69c', script)
        self.assertIn('releases/download/envtest-v${VERSION}/envtest-v${VERSION}-linux-amd64.tar.gz', script)
        self.assertIn('sha256sum -c -', script)
        self.assertIn('kube_version="$("$assets/kube-apiserver" --version 2>&1)"', script)
        self.assertIn('etcd_version="$("$assets/etcd" --version 2>&1)"', script)
        self.assertNotIn('grep -q', script)
        self.assertNotIn('| head', script)
        self.assertNotIn('${ENVTEST', script)  # no environment override of version, URL or digest
        self.assertIn('set -euo pipefail', script)
        controller_script = (ROOT / 'tools/provision-kube-controller-manager.sh').read_text()
        self.assertIn('VERSION=1.34.0', controller_script)
        self.assertIn('SHA256=dd49fc2991df033c1eef6c12574795d64633a95e665d1b369afe0760472c24d1',
                      controller_script)
        self.assertIn('https://dl.k8s.io/release/v${VERSION}/bin/linux/amd64/kube-controller-manager',
                      controller_script)
        self.assertIn('sha256sum -c -', controller_script)
        self.assertIn('version="$("$binary" --version 2>&1)"', controller_script)
        self.assertNotIn('${KUBE_CONTROLLER_MANAGER', controller_script)
        self.assertIn('set -euo pipefail', controller_script)

    def test_required_gate_rejects_failure_skip_and_cancellation(self):
        job = DOC['jobs']['pr-validation']
        self.assertEqual(job['name'], 'PR validation')
        self.assertEqual(job['if'], 'always()')
        self.assertEqual(set(job['needs']),
                         {'charts', 'go-unit', 'go-envtest', 'frontend', 'lint', 'fixture-images', 'images'})
        script = job['steps'][0]['run']
        good = dict(CHARTS='success', GO_UNIT='success', GO_ENVTEST='success', FRONTEND='success',
                    LINT='success', FIXTURE_IMAGES='success', IMAGES='success')
        def check(env):
            return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                                  env=dict(os.environ, **env), timeout=5).returncode
        self.assertEqual(check(good), 0)
        for key in good:
            for state in ('failure', 'skipped', 'cancelled', ''):
                with self.subTest(key=key, state=state):
                    self.assertNotEqual(check(dict(good, **{key: state})), 0)

    def test_the_services_a_change_affects_are_reported(self):
        steps = DOC['jobs']['go-unit']['steps']
        self.assertEqual(steps[0]['with']['fetch-depth'], '2')
        step = next(s for s in steps if s.get('name') == 'Services this change affects')
        self.assertIn('./tools/servicerelease affected --base HEAD^1 --markdown', step['run'])
        self.assertIn('$GITHUB_STEP_SUMMARY', step['run'])

    def test_no_workflow_reaches_live_infrastructure(self):
        # This repository is not a deployer: the legacy pipeline stays in
        # PhorvexSecurity/operator. A deploy workflow lands only with its own reviewed change;
        # the two that have, release.yml and staging-isolated-release.yml, are held
        # to their exact shapes by their dedicated workflow test classes.
        # Every job runs on a GitHub-hosted runner, never on a runner with live access.
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            if path.name in {'release.yml', 'staging-isolated-release.yml'}:
                continue
            raw = path.read_text()
            doc = yaml.load(raw, Loader=yaml.BaseLoader)
            with self.subTest(workflow=path.name):
                for forbidden in ('phorvex-isolated-aws', 'secrets.', 'id-token: write', 'aws-actions/'):
                    self.assertNotIn(forbidden, raw)
                for name, job in doc['jobs'].items():
                    self.assertEqual(job['runs-on'], BUILD_RUNNER, name)
                    self.assertNotIn('container', job, name)

    def test_images_are_built_under_a_per_run_tag_and_removed(self):
        step = next(s for s in DOC['jobs']['images']['steps'] if 'docker build' in s.get('run', ''))
        self.assertEqual(step['env']['TAG'],
                         'operator-refactored-${{ matrix.image }}:ci-${{ github.run_id }}-${{ github.run_attempt }}')
        self.assertIn('--tag "$TAG"', step['run'])
        self.assertIn('docker image rm "$TAG"', step['run'])

    def test_every_service_contract_has_an_image_and_current_generated_code(self):
        # ADR-0001: each service with a contract is its own binary and image, and its
        # generated code is checked against the proto. A new service must join both.
        services = sorted(p.name for p in (ROOT / 'phorvex/api/proto/phorvex').iterdir() if p.is_dir())
        self.assertEqual(services, ['actuator', 'brain', 'sensor'])
        for service in services:
            self.assertTrue((ROOT / 'phorvex/cmd' / service / 'main.go').is_file(), service)
            self.assertTrue((ROOT / 'phorvex/internal' / (service + 'pb')).is_dir(), service)
            self.assertIn(service, DOC['jobs']['images']['strategy']['matrix']['image'])
        contract = next(s['run'] for s in DOC['jobs']['lint']['steps'] if 'generate-proto.sh' in s.get('run', ''))
        self.assertIn("git diff --exit-code -- 'phorvex/internal/*pb'", contract)
        self.assertIn("git status --porcelain -- 'phorvex/internal/*pb'", contract)

    def test_service_images_build_only_a_known_service(self):
        dockerfile = (ROOT / 'deploy/docker/service.Dockerfile').read_text()
        self.assertIn('brain|sensor|actuator) ;;', dockerfile)
        self.assertIn('-o /service ./cmd/${SERVICE}', dockerfile)
        self.assertIn('FROM gcr.io/distroless/static:nonroot', dockerfile)
        self.assertIn('USER 65532:65532', dockerfile)
        for path in (ROOT / 'deploy/docker').glob('*.Dockerfile'):
            with self.subTest(path=path.name):
                from_lines = [line for line in path.read_text().splitlines() if line.startswith('FROM ')]
                self.assertTrue(from_lines)
                self.assertTrue(all('@sha256:' in line for line in from_lines))



RELEASE_RAW = (ROOT / '.github/workflows/release.yml').read_text()
RELEASE = yaml.load(RELEASE_RAW, Loader=yaml.BaseLoader)
AWS_ACTIONS = {'aws-actions/configure-aws-credentials@7474bc4690e29a8392af63c5b98e7449536d5c3a',
               'aws-actions/amazon-ecr-login@03f1aad4c6c7ffd436567f42f9384779290529bd'}
RELEASE_ACTIONS = {
    'actions/checkout': '11bd71901bbe5b1630ceea73d27597364c9af683',
    'actions/setup-go': 'd35c59abb061a4a6fb18e82ac0862c26744d6ab5',
    'azure/setup-helm': '1a275c3b69536ee54be43f2070a358922e12c8d4',
    'aws-actions/configure-aws-credentials': '7474bc4690e29a8392af63c5b98e7449536d5c3a',
    'aws-actions/amazon-ecr-login': '03f1aad4c6c7ffd436567f42f9384779290529bd',
}

STAGING_RELEASE_PATH = ROOT / '.github/workflows/staging-isolated-release.yml'
STAGING_RELEASE_RAW = STAGING_RELEASE_PATH.read_text()
STAGING_RELEASE = yaml.load(STAGING_RELEASE_RAW, Loader=yaml.BaseLoader)


class StagingIsolatedReleaseWorkflowTests(unittest.TestCase):
    def test_lane_is_manual_source_pinned_and_staging_scoped(self):
        self.assertEqual(set(STAGING_RELEASE['on']), {'workflow_dispatch'})
        source = STAGING_RELEASE['on']['workflow_dispatch']['inputs']['source']
        self.assertEqual(source['required'], 'true')
        self.assertEqual(source['type'], 'string')
        self.assertEqual(STAGING_RELEASE['permissions'], {'contents': 'read'})
        self.assertEqual(STAGING_RELEASE['env']['TARGET'], 'staging-isolated')
        self.assertEqual(STAGING_RELEASE['concurrency'], {
            'group': 'staging-isolated-release', 'cancel-in-progress': 'false',
        })
        job = STAGING_RELEASE['jobs']['publish']
        self.assertEqual(job['environment'], 'staging-release')
        self.assertEqual(job['permissions'], {
            'actions': 'write', 'contents': 'write', 'pull-requests': 'write', 'id-token': 'write',
        })
        checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], 'main')
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        runs = '\n'.join(step.get('run', '') for step in job['steps'])
        self.assertIn('tools/verify-git-build-identity.sh "$REQUESTED_SOURCE"', runs)
        self.assertIn('[ "$(git rev-parse HEAD)" = "$REQUESTED_SOURCE" ]', runs)
        self.assertNotIn('git fetch', runs)
        self.assertIn('staging-contract --target "$TARGET" --source "$SOURCE"', runs)
        self.assertNotIn('$GITHUB_SHA', runs)
        for forbidden in ('kubectl ', 'argocd ', 'git push origin main', 'refs/heads/main',
                          'phorvex/manager:', 'phorvex/brain:', 'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, STAGING_RELEASE_RAW)

    def test_aggregate_gate_and_reviewed_identities_precede_every_push(self):
        runs = '\n'.join(step.get('run', '') for step in STAGING_RELEASE['jobs']['publish']['steps'])
        preflight = runs.index('verify_staging_ecr.py preflight')
        fixture = runs.index('--expected-identities release/staging-fixture-identities.json')
        service_push = runs.index('docker push "$image"')
        fixture_push = runs.index('type=image,push=true')
        self.assertLess(preflight, fixture)
        self.assertLess(fixture, service_push)
        self.assertLess(fixture, fixture_push)
        self.assertIn('image=moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea', runs)
        self.assertIn('--builder "$FIXTURE_BUILDER" --no-cache --pull', runs)
        self.assertIn('--source-date-epoch 0 --builder "$FIXTURE_BUILDER"', runs)
        self.assertIn('--preflight-state "$RUNNER_TEMP/ecr-preflight.json"', runs)
        self.assertGreaterEqual(runs.count('verify_staging_ecr.py probe'), 3)
        self.assertIn('verify_service_image_identity.py', runs)
        self.assertIn('verify_staging_ecr.py verify-component', runs)
        self.assertIn('verify_staging_ecr.py ensure-tags', runs)
        self.assertIn('verify_staging_ecr.py verify --batch "$RUNNER_TEMP/staging-complete.json"', runs)
        cleanup = next(
            step['run'] for step in STAGING_RELEASE['jobs']['publish']['steps']
            if step.get('name') == 'Remove the fixture builder'
        )
        self.assertIn('docker buildx rm "$FIXTURE_BUILDER"', cleanup)
        self.assertNotIn('docker buildx inspect', cleanup)

    def test_publication_only_opens_an_allowlisted_staging_pin_pr(self):
        runs = '\n'.join(step.get('run', '') for step in STAGING_RELEASE['jobs']['publish']['steps'])
        self.assertIn('staging-pin --contracts "$RUNNER_TEMP/service-contracts.json"', runs)
        self.assertIn('pin-fixtures --batch "$RUNNER_TEMP/staging-complete.json"', runs)
        self.assertIn('verify-deployment --batch release/staging-batch.json', runs)
        self.assertIn('git diff --cached --name-only "$SOURCE" -- | sort', runs)
        self.assertIn('comm -23 "$RUNNER_TEMP/actual-files" "$allowed"', runs)
        self.assertIn('grep -Fxq release/staging-batch.json', runs)
        self.assertLess(runs.index('git add -- release/staging-batch.json'),
                        runs.index('git diff --cached --name-only "$SOURCE"'))
        self.assertIn('pull-request --require-open --head "$branch" --base main', runs)
        self.assertIn('dispatch --ref "$branch" --workflows pr-validation.yml', runs)
        self.assertNotIn('gh pr merge', runs)
        self.assertNotIn('git merge --', runs)
        for path in ('manager.yaml', 'brain.yaml', 'sensor.yaml', 'actuator.yaml',
                     'console.yaml', 'attacks.yaml', 'phorvex.yaml', 'catalogue-family.yaml'):
            self.assertIn(f'deploy/environments/staging/{path}', runs)
        self.assertNotIn('deploy/helm/phorvex-stack', runs)
        self.assertNotIn('deploy/argocd/apps', runs)

    def test_every_privileged_action_is_commit_pinned(self):
        references = re.findall(r'^\s*- uses: ([^\s#]+)(?:\s+#\s*([^\s]+))?$', STAGING_RELEASE_RAW, re.M)
        self.assertTrue(references)
        for reference, version_comment in references:
            owner, sha = reference.split('@', 1)
            self.assertEqual(sha, RELEASE_ACTIONS[owner])
            self.assertRegex(version_comment, r'^v[0-9]')


class ReleaseWorkflowTests(unittest.TestCase):
    """The one workflow that writes and reaches AWS (docs/services/releasing.md), held to its shape."""

    def git(self, root, *args, check=True):
        return subprocess.run(
            ['git', '-C', str(root), *args], check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def release_main_repository(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.git(root, 'init', '-q', '-b', 'main')
        self.git(root, 'config', 'user.name', 'Release Test')
        self.git(root, 'config', 'user.email', 'release@example.invalid')

        # The shell binding is exercised against real detached Git worktrees,
        # while a tiny fixture compiler keeps these orchestration tests focused.
        # The production transition semantics are covered by the Go helper's
        # source-pinned endpoint/transition suite.
        (root / 'release').mkdir()
        (root / 'release/versions.json').write_text('{"manager":"1.0.0"}\n')
        (root / 'phorvex/tools/servicerelease').mkdir(parents=True)
        (root / 'phorvex/tools/servicerelease/batch.go').write_text('const batchSchema = 2\n')
        (root / 'tools').mkdir()
        identity = root / 'tools/verify-git-build-identity.sh'
        identity.write_text('#!/bin/sh\nset -eu\n[ "$(git rev-parse HEAD)" = "$1" ]\n')
        identity.chmod(0o755)
        helper = root / 'tools/fake-servicerelease.py'
        helper.write_text('''#!/usr/bin/env python3
import json
from pathlib import Path
import sys

def die(message):
    print('servicerelease:', message, file=sys.stderr)
    raise SystemExit(1)

def load(root):
    try:
        value = json.loads((Path(root) / 'release/batch.json').read_text())
    except Exception as exc:
        die(str(exc))
    required = {'schema', 'status', 'environment', 'source', 'expectedComponents',
                'versions', 'components', 'releases'}
    if set(value) != required or value['schema'] != 2 or value['environment'] != 'staging':
        die('batch object is semantically invalid')
    if value['status'] != ('complete' if len(value['releases']) == len(value['expectedComponents'])
                           else 'partial' if value['releases'] else 'prepared'):
        die('batch status is semantically invalid')
    return value

if sys.argv[1] == 'bootstrap-source':
    try:
        pointer = json.loads(Path('release/batch.json').read_text())
        source = pointer['source']
        schema = pointer['schema']
    except Exception as exc:
        die(str(exc))
    if schema != 2:
        die('invalid schema pointer')
    if len(source) != 40 or any(c not in '0123456789abcdef' for c in source):
        die('invalid source pointer')
    print(source)
elif sys.argv[1] == 'validate-transition':
    args = dict(zip(sys.argv[2::2], sys.argv[3::2]))
    previous = load(args['--from-root'])
    latest = load(args['--to-root'])
    for key in ('schema', 'environment', 'source', 'expectedComponents', 'versions', 'components'):
        if previous[key] != latest[key]:
            die('immutable batch contract changed')
    for name, record in previous['releases'].items():
        if latest['releases'].get(name) != record:
            die('release record was deleted or replaced')
    print(previous['status'], latest['status'], len(previous['releases']), len(latest['releases']))
else:
    die('unexpected command')
''')
        helper.chmod(0o755)
        fake_bin = root / '.fake-bin'
        fake_bin.mkdir()
        fake_go = fake_bin / 'go'
        fake_go.write_text('''#!/usr/bin/env python3
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
module = Path(args[args.index('-C') + 1])
output = Path(args[args.index('-o') + 1])
shutil.copy2(module.parent / 'tools/fake-servicerelease.py', output)
output.chmod(0o755)
''')
        fake_go.chmod(0o755)
        (root / 'trigger').write_text('trigger\n')
        self.git(root, 'add', '-A')
        self.git(root, 'commit', '-qm', 'trigger')
        trigger = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        batch = {
            'schema': 2,
            'status': 'prepared',
            'environment': 'staging',
            'source': trigger,
            'expectedComponents': ['manager'],
            'versions': {'manager': '1.0.0'},
            'components': [{'component': 'manager', 'source': trigger}],
            'releases': {},
        }
        (root / 'release/batch.json').write_text(json.dumps(batch, sort_keys=True) + '\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'publish batch')
        publication = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        return root, trigger, publication, fake_bin

    def run_main_binding(self, root, *, pending, publish='', result='skipped'):
        step = next(s for s in RELEASE['jobs']['release-pr']['steps']
                    if s.get('name') == 'Bind latest main to the upstream publication')
        output = root / 'github-output'
        fake_bin = root / '.fake-bin'
        runner = tempfile.TemporaryDirectory(prefix='release-binding-')
        self.addCleanup(runner.cleanup)
        runner_temp = Path(runner.name)
        completed = subprocess.run(
            ['bash', '-c', step['run']], cwd=root, text=True, capture_output=True,
            env=dict(os.environ, GITHUB_OUTPUT=str(output), PENDING_MAIN_SHA=pending,
                     PUBLISH_MAIN_SHA=publish, PUBLISH_RESULT=result,
                     RUNNER_TEMP=str(runner_temp),
                     PATH=str(fake_bin) + os.pathsep + os.environ['PATH']),
        )
        return completed, output.read_text() if output.exists() else ''

    def test_it_runs_only_for_main(self):
        self.assertEqual(set(RELEASE['on']), {'push', 'workflow_dispatch'})
        self.assertEqual(RELEASE['on']['push'], {'branches': ['main']})
        self.assertEqual(RELEASE['permissions'], {'contents': 'read'})
        self.assertEqual(RELEASE['concurrency'], {'group': 'release', 'cancel-in-progress': 'false'})
        for job in RELEASE['jobs'].values():
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        for forbidden in ('secrets.', 'pull_request', 'phorvex-isolated-aws', 'ssh ', 'kubectl ', 'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, RELEASE_RAW)

    def test_only_the_publish_job_reaches_aws(self):
        jobs = RELEASE['jobs']
        self.assertEqual(set(jobs), {'pending', 'publish', 'release-pr'})
        for name, job in jobs.items():
            with self.subTest(job=name):
                self.assertEqual(job['runs-on'], BUILD_RUNNER)
                self.assertNotIn('container', job)
                uses = {s['uses'] for s in job['steps'] if 'uses' in s}
                if name == 'publish':
                    self.assertEqual(job['environment'], 'release')
                    self.assertEqual(job['permissions'], {'contents': 'write', 'id-token': 'write'})
                    self.assertLessEqual(AWS_ACTIONS, uses)
                    role = next(s for s in job['steps'] if s.get('uses', '').startswith('aws-actions/configure-aws-credentials@'))
                    self.assertEqual(role['with']['role-to-assume'], '${{ vars.PHORVEX_RELEASE_ROLE_ARN }}')
                else:
                    self.assertNotIn('environment', job)
                    self.assertFalse({u for u in uses if u.startswith('aws-actions/')})
                    self.assertNotIn('id-token', job.get('permissions', {}))
                self.assertLessEqual({u.split('@')[0] for u in uses},
                                     {'actions/checkout', 'actions/setup-go', 'azure/setup-helm',
                                      'aws-actions/configure-aws-credentials', 'aws-actions/amazon-ecr-login'})
                helm = [s for s in job['steps'] if s.get('uses', '').startswith('azure/setup-helm@')]
                self.assertEqual([s.get('with') for s in helm], [{'version': 'v3.16.4'}])
        self.assertEqual(jobs['pending']['permissions'], {'contents': 'write'})
        self.assertEqual(jobs['release-pr']['permissions'], {'contents': 'write', 'pull-requests': 'write', 'actions': 'write'})
        pending_checkout = next(s for s in jobs['pending']['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(pending_checkout['with']['ref'], 'main')
        release_pr_checkout = next(s for s in jobs['release-pr']['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(release_pr_checkout['with']['ref'], 'main')
        self.assertEqual(release_pr_checkout['with']['persist-credentials'], 'false')

    def test_every_privileged_action_is_reviewed_and_commit_pinned(self):
        references = re.findall(r'^\s*- uses: ([^\s#]+)(?:\s+#\s*([^\s]+))?$', RELEASE_RAW, re.M)
        self.assertTrue(references)
        for reference, version_comment in references:
            owner, sha = reference.split('@', 1)
            self.assertIn(owner, RELEASE_ACTIONS)
            self.assertRegex(sha, r'^[0-9a-f]{40}$')
            self.assertEqual(sha, RELEASE_ACTIONS[owner])
            self.assertRegex(version_comment, r'^v[0-9]')
        for job in RELEASE['jobs'].values():
            checkout = next(s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with'].get('persist-credentials'), 'false')

    def test_the_role_is_checked_before_it_is_assumed(self):
        steps = RELEASE['jobs']['publish']['steps']
        names = [s.get('name') or s.get('uses', '') for s in steps]
        check = names.index('Require the release role')
        assume = next(i for i, n in enumerate(names) if n.startswith('aws-actions/configure-aws-credentials@'))
        self.assertLess(check, assume)
        self.assertIn('PHORVEX_RELEASE_ROLE_ARN', steps[check]['run'])

    def test_publication_waits_for_reproducibility_and_embedded_identity(self):
        steps = RELEASE['jobs']['publish']['steps']
        runs = '\n'.join(step.get('run', '') for step in steps)
        names = [step.get('name', '') for step in steps]
        self.assertIn('Rebuild each fixture twice and compare complete OCI identities', names)
        self.assertIn('tools/verify-git-build-identity.sh "$BATCH_SOURCE_SHA"', runs)
        self.assertIn('git switch --detach "$BATCH_SOURCE_SHA"', runs)
        self.assertNotIn('$GITHUB_SHA', runs)
        self.assertIn('"${docker_args[@]}"', runs)
        self.assertIn('--entrypoint "$command"', runs)
        self.assertIn('tools/verify_service_image_identity.py', runs)
        self.assertLess(runs.index('git switch --detach "$BATCH_SOURCE_SHA"'),
                        runs.index('tools/verify_fixture_reproducibility.py'))
        self.assertLess(runs.index('verify_release_ecr.py preflight'),
                        runs.index('tools/verify_fixture_reproducibility.py'))
        self.assertLess(runs.index('tools/verify_service_image_identity.py'),
                        runs.index('docker push "$image"'))

    def test_batch_source_is_committed_before_build_and_survives_reruns(self):
        jobs = RELEASE['jobs']
        pending = '\n'.join(s.get('run', '') for s in jobs['pending']['steps'])
        publish = '\n'.join(s.get('run', '') for s in jobs['publish']['steps'])
        self.assertIn('"$tool" batch --environment "$ENVIRONMENT"', pending)
        self.assertIn('git status --porcelain -- release/batch.json', pending)
        self.assertIn('git add -- "${release_files[@]}"', pending)
        self.assertIn('"$tool" verify-staged', pending)
        self.assertIn('git_push --atomic origin HEAD:main', pending)
        self.assertIn('A remote advance fails this exact push', pending)
        self.assertNotIn('remote-batch.json', pending)
        self.assertIn('echo "source=$source" >> "$GITHUB_OUTPUT"', pending)
        self.assertIn('echo "main=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"', pending)
        self.assertIn("git show \"$source:phorvex/tools/servicerelease/batch.go\"", pending)
        self.assertIn('"$tool" import-terminal-batch --environment "$ENVIRONMENT"', pending)
        self.assertIn('cannot\n  # produce pending work', pending)
        self.assertLess(pending.index('git commit -m "release: pin batch source'),
                        pending.index('"$tool" batch-source'))
        self.assertEqual(jobs['publish']['env']['BATCH_SOURCE_SHA'], '${{ needs.pending.outputs.source }}')
        self.assertIn('[ "$("$tool" batch-source)" = "$BATCH_SOURCE_SHA" ]', publish)
        self.assertEqual(jobs['pending']['outputs']['main'], '${{ steps.pending.outputs.main }}')
        self.assertEqual(jobs['publish']['outputs']['main'], '${{ steps.record.outputs.main }}')
        self.assertIn('echo "main=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"', publish)
        for run in (pending, publish):
            self.assertIn('bootstrap-servicerelease" bootstrap-source', run)
            self.assertIn('git switch --detach', run)
            self.assertIn('tools/verify-git-build-identity.sh', run)
            self.assertIn('pinned-servicerelease', run)
            self.assertLess(run.index('bootstrap-source'), run.index('pinned-servicerelease'))
            self.assertLess(run.index('git switch --detach'),
                            run.index('tools/verify-git-build-identity.sh'))
            self.assertLess(run.index('tools/verify-git-build-identity.sh'),
                            run.index('go -C phorvex build -o "$RUNNER_TEMP/pinned-servicerelease"'))
        self.assertIn('"$tool" pending --json', pending)
        self.assertIn('"$tool" pending --json', publish)
        for name in ('pending', 'publish'):
            checkout = next(s for s in jobs[name]['steps'] if s.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with']['ref'], 'main', name)

    def test_git_publication_uses_exact_staging_and_clean_detached_head_proof(self):
        pending = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['pending']['steps'])
        publish = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['publish']['steps'])
        for run, push_call in ((pending, 'git_push --atomic origin HEAD:main'),
                               (publish, 'git_push --atomic origin HEAD:main')):
            self.assertIn('git worktree add --detach', run)
            self.assertIn('"$tool" verify-committed', run)
            self.assertLess(run.index('verify-committed'), run.index(push_call))
        self.assertIn('"$tool" release-files --components "$component_list"', publish)
        self.assertIn('"$tool" verify-staged --components "$component_list"', publish)
        self.assertNotIn('git add release/batch.json deploy/environments', publish)
        self.assertIn('[ -z "$(git diff --name-only)" ]', '\n'.join(
            s.get('run', '') for s in RELEASE['jobs']['release-pr']['steps']))

    def test_every_docker_context_is_clean_and_revalidated_at_the_build_boundary(self):
        publish = RELEASE['jobs']['publish']['steps']
        load = next(s['run'] for s in publish if s.get('name') == 'Load the record and checkout its exact clean source')
        for dockerfile in ('farm-fixtures/agentsim/Dockerfile',
                           'farm-fixtures/catalogue-workload/Dockerfile'):
            self.assertIn(f'verify-build-paths --dockerfile {dockerfile} --context .', load)
        build = next(s['run'] for s in publish if s.get('name') == 'Build, push, tag and pin each release')
        self.assertIn('git status --porcelain --untracked-files=all', build)
        self.assertLess(build.index('verify_release_ecr.py probe'),
                        build.index('verify-build-paths --dockerfile "$dockerfile"'))
        self.assertLess(build.index('verify-build-paths --dockerfile "$dockerfile"'),
                        build.index('docker build --file "$dockerfile"'))

    def test_staging_is_pinned_by_digest_and_releases_are_tagged(self):
        run = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['publish']['steps'])
        self.assertIn('"$tool" pending', run)
        self.assertIn('"$tool" record --environment "$ENVIRONMENT"', run)
        self.assertIn('--digest "$digest" --source "$BATCH_SOURCE_SHA"', run)
        self.assertIn('git tag "$git_tag" "$BATCH_SOURCE_SHA"', run)
        self.assertIn('aws ecr describe-images', run)
        self.assertIn('--image-ids "imageTag=$tag"', run)
        self.assertIn('for attempt in 1 2 3 4 5 6; do', run)
        self.assertIn('sleep 5', run)
        self.assertIn('--expected-repository "$registry/$repository"', run)
        self.assertIn('--expected-tag "$tag" --expected-digest "$digest"', run)
        self.assertLess(run.index('aws ecr describe-images'),
                        run.index('"$tool" record --environment "$ENVIRONMENT"'))
        self.assertIn('git add -- "${release_files[@]}"', run)
        self.assertIn('git_push --atomic origin HEAD:main "${refs[@]}"', run)
        self.assertNotIn('xargs git push', run)
        self.assertEqual(RELEASE['env']['ENVIRONMENT'], 'staging')
        pr = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['release-pr']['steps'])
        self.assertIn('git_push --atomic --force origin release/next', pr)
        # A built binary, not `go run`, which reports prepare's exit 3 as 1.
        self.assertIn('go -C phorvex build -o "$RUNNER_TEMP/servicerelease" ./tools/servicerelease', pr)
        self.assertNotIn('servicerelease prepare', pr.replace('"$tool" prepare', ''))
        self.assertIn('"$tool" prepare --title-file', pr)
        # A release still to publish is left to its own run, and nothing to release
        # closes a release PR left open.
        self.assertIn('"$batch_tool" pending --json', pr)
        self.assertLess(pr.index('"$batch_tool" pending'), pr.index('"$tool" prepare'))
        self.assertIn('"$tool" close-pull-request --head release/next --base main', pr)
        self.assertIn('"$tool" pull-request --head release/next --base main', pr)

    def test_ecr_is_immutable_and_requeried_at_both_publication_boundaries(self):
        steps = RELEASE['jobs']['publish']['steps']
        runs = '\n'.join(s.get('run', '') for s in steps)
        names = [s.get('name', '') for s in steps]
        self.assertIn('Preflight the exact release batch in ECR', names)
        self.assertEqual(runs.count('verify_release_ecr.py preflight'), 1)
        self.assertIn('--preflight-state "$RUNNER_TEMP/ecr-preflight.json"', runs)
        self.assertIn('chmod 0400 "$RUNNER_TEMP/ecr-preflight.json"', runs)
        self.assertIn('verify_release_ecr.py probe', runs)
        self.assertGreaterEqual(runs.count('verify_release_ecr.py probe'), 2)
        self.assertIn('verify_release_ecr.py verify --batch release/batch.json --verify-identities', runs)
        self.assertGreaterEqual(runs.count('verify_release_ecr.py verify --batch release/batch.json'), 2)
        self.assertLess(runs.index('verify_release_ecr.py probe'), runs.index('docker push "$image"'))
        self.assertLess(runs.rindex('verify_release_ecr.py probe'), runs.index('docker push "$image"'))
        self.assertLess(runs.index('verify_release_ecr.py preflight'),
                        runs.index('docker build --file "$dockerfile"'))
        self.assertLess(runs.index('tools/verify_service_image_identity.py'),
                        runs.rindex('verify_release_ecr.py probe'))
        self.assertLess(runs.index('verify_release_ecr.py verify --batch release/batch.json --verify-identities'),
                        runs.index('git commit -m "deploy($ENVIRONMENT)'))
        final_check = runs.rindex('verify_release_ecr.py verify --batch release/batch.json')
        self.assertLess(final_check, runs.rindex('git_push --atomic'))

    def test_git_credentials_exist_only_in_the_push_process_environment(self):
        for name in ('pending', 'publish', 'release-pr'):
            credential_steps = [s for s in RELEASE['jobs'][name]['steps']
                                if s.get('env', {}).get('GIT_PUSH_TOKEN') == '${{ github.token }}']
            self.assertEqual(len(credential_steps), 1, name)
            run = credential_steps[0]['run']
            self.assertIn('GIT_CONFIG_COUNT=2', run)
            self.assertIn('git_push_token="$GIT_PUSH_TOKEN"\nunset GIT_PUSH_TOKEN', run)
            self.assertLess(run.index('unset GIT_PUSH_TOKEN'), run.index('git_push()'))
            self.assertIn('GIT_CONFIG_KEY_0=http.https://github.com/.extraheader', run)
            self.assertIn('GIT_CONFIG_KEY_1=core.hooksPath', run)
            self.assertIn('GIT_CONFIG_VALUE_1=/dev/null', run)
            self.assertIn("trap 'git_push_token=; unset git_push_token GIT_PUSH_TOKEN' EXIT", run)
            self.assertNotIn('export git_push_token', run)
            self.assertIn("git config --local --get-regexp '(extraheader|credential|token)'", run)
            self.assertIn('git remote get-url --all origin', run)
            self.assertNotIn('git remote set-url', run)
            self.assertNotRegex(run, r'git push[^\n]*(x-access-token|github_pat_|gh[pousr]_)')
            self.assertNotRegex(run, r'https://[^\s]*(x-access-token|github_pat_|gh[pousr]_)')
        self.assertNotIn('git_fetch()', RELEASE_RAW)
        self.assertNotIn('git fetch', RELEASE_RAW)
        self.assertNotIn('git rebase', RELEASE_RAW)
        self.assertNotRegex(RELEASE_RAW, r'GIT_CONFIG_VALUE_0="AUTHORIZATION:[^\n]+"\s+git fetch')
        release_pr_step = next(s for s in RELEASE['jobs']['release-pr']['steps']
                               if s.get('name') == 'Publish the prepared release PR state')
        self.assertNotIn('GITHUB_TOKEN', release_pr_step.get('env', {}))
        self.assertEqual(release_pr_step['run'].count('GITHUB_TOKEN="$git_push_token"'), 3)

        for name in ('Bind latest main to the upstream publication',
                     'Prepare the release PR from bound main'):
            step = next(s for s in RELEASE['jobs']['release-pr']['steps'] if s.get('name') == name)
            self.assertNotIn('GIT_PUSH_TOKEN', step.get('env', {}), name)
            self.assertNotIn('github.token', str(step), name)

    def test_release_pr_uses_published_main_when_trigger_sha_lacks_batch(self):
        root, trigger, publication, _ = self.release_main_repository()
        missing = self.git(root, 'cat-file', '-e', f'{trigger}:release/batch.json', check=False)
        self.assertNotEqual(missing.returncode, 0)

        completed, output = self.run_main_binding(root, pending=publication)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(output, f'sha={publication}\n')

        checkout = next(s for s in RELEASE['jobs']['release-pr']['steps']
                        if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], 'main')
        prepare = next(s for s in RELEASE['jobs']['release-pr']['steps']
                       if s.get('name') == 'Prepare the release PR from bound main')['run']
        self.assertIn('git switch --force-create release/next "$AUTHORITATIVE_MAIN_SHA"', prepare)
        self.assertLess(prepare.index('[ "$(git rev-parse HEAD)" = "$AUTHORITATIVE_MAIN_SHA" ]'),
                        prepare.index('bootstrap-servicerelease" bootstrap-source'))
        self.assertLess(prepare.index('bootstrap-servicerelease" bootstrap-source'),
                        prepare.index('"$batch_tool" pending --json'))

    def test_release_pr_accepts_unrelated_main_advance_after_publication(self):
        root, _, publication, _ = self.release_main_repository()
        (root / 'unrelated').write_text('later main work\n')
        self.git(root, 'add', 'unrelated')
        self.git(root, 'commit', '-qm', 'unrelated main advance')
        latest = self.git(root, 'rev-parse', 'HEAD').stdout.strip()

        completed, output = self.run_main_binding(
            root, pending=publication, publish=publication, result='success')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(output, f'sha={latest}\n')
        self.assertNotEqual(latest, publication)

    def test_release_pr_rejects_malformed_expected_even_when_descendant_repairs_it(self):
        root, _, _, _ = self.release_main_repository()
        batch_path = root / 'release/batch.json'
        valid = batch_path.read_text()
        batch_path.write_text('{ definitely-not-json\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'malformed authoritative publication')
        expected = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        batch_path.write_text(valid)
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'repair descendant batch')

        completed, output = self.run_main_binding(root, pending=expected)
        self.assertEqual(completed.returncode, 75)
        self.assertIn('authoritative upstream batch pointer', completed.stdout)
        self.assertEqual(output, '')

    def test_release_pr_rejects_semantically_invalid_expected_even_when_descendant_repairs_it(self):
        root, _, _, _ = self.release_main_repository()
        batch_path = root / 'release/batch.json'
        valid = json.loads(batch_path.read_text())
        invalid = dict(valid, status='complete')
        batch_path.write_text(json.dumps(invalid, sort_keys=True) + '\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'semantically invalid authoritative publication')
        expected = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        batch_path.write_text(json.dumps(valid, sort_keys=True) + '\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'repair descendant semantics')

        completed, output = self.run_main_binding(root, pending=expected)
        self.assertEqual(completed.returncode, 75)
        self.assertIn('expected-to-latest release state transition is invalid', completed.stdout)
        self.assertIn('batch status is semantically invalid', completed.stderr)
        self.assertEqual(output, '')

    def test_release_pr_rejects_malformed_latest_endpoint(self):
        root, _, publication, _ = self.release_main_repository()
        (root / 'release/batch.json').write_text('{\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'malformed latest batch')

        completed, output = self.run_main_binding(root, pending=publication)
        self.assertEqual(completed.returncode, 75)
        self.assertIn('expected-to-latest release state transition is invalid', completed.stdout)
        self.assertEqual(output, '')

    def test_release_pr_publish_output_precedes_pending_and_skipped_uses_pending(self):
        root, _, publication, _ = self.release_main_repository()
        batch_path = root / 'release/batch.json'
        valid = json.loads(batch_path.read_text())
        batch_path.write_text(json.dumps(dict(valid, status='complete'), sort_keys=True) + '\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'invalid pending output state')
        pending = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        batch_path.write_text(json.dumps(valid, sort_keys=True) + '\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'valid publish output state')
        published = self.git(root, 'rev-parse', 'HEAD').stdout.strip()

        completed, output = self.run_main_binding(
            root, pending=pending, publish=published, result='success')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(output, f'sha={published}\n')

        root, _, pending, _ = self.release_main_repository()
        completed, output = self.run_main_binding(
            root, pending=pending, publish='', result='skipped')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(output, f'sha={pending}\n')

    def test_release_pr_never_falls_back_after_failed_publish(self):
        root, _, pending, _ = self.release_main_repository()
        completed, output = self.run_main_binding(
            root, pending=pending, publish='', result='failure')
        self.assertEqual(completed.returncode, 75)
        self.assertIn('publish result is failure', completed.stdout)
        self.assertEqual(output, '')

    def test_release_pr_fails_closed_when_publication_is_missing_or_not_ancestor(self):
        root, trigger, publication, _ = self.release_main_repository()
        completed, output = self.run_main_binding(
            root, pending=publication, publish='', result='success')
        self.assertEqual(completed.returncode, 75)
        self.assertIn('upstream publication SHA is missing or malformed', completed.stdout)
        self.assertEqual(output, '')

        completed, output = self.run_main_binding(
            root, pending=publication, publish='f' * 40, result='success')
        self.assertEqual(completed.returncode, 75)
        self.assertIn('commit ' + 'f' * 40 + ' is unavailable', completed.stdout)
        self.assertEqual(output, '')

        completed, output = self.run_main_binding(
            root, pending=publication, publish=trigger, result='success')
        self.assertEqual(completed.returncode, 75)
        self.assertIn(f'commit {trigger} lacks release/batch.json', completed.stdout)
        self.assertEqual(output, '')

        self.git(root, 'switch', '-q', '-c', 'unpublished', trigger)
        (root / 'release/batch.json').write_text('{"schema":2,"side":true}\n')
        self.git(root, 'add', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'unpublished release state')
        unpublished = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        self.git(root, 'switch', '-q', 'main')

        completed, output = self.run_main_binding(
            root, pending=publication, publish=unpublished, result='success')
        self.assertEqual(completed.returncode, 75)
        self.assertIn('is not an ancestor of main', completed.stdout)
        self.assertEqual(output, '')

        (root / 'release/batch.json').unlink()
        self.git(root, 'add', '-u', 'release/batch.json')
        self.git(root, 'commit', '-qm', 'remove published release state')
        latest = self.git(root, 'rev-parse', 'HEAD').stdout.strip()
        completed, output = self.run_main_binding(root, pending=publication)
        self.assertEqual(completed.returncode, 75)
        self.assertIn(f'latest main {latest} lacks release/batch.json', completed.stdout)
        self.assertEqual(output, '')

    def test_release_workflow_does_not_assume_token_push_recursion(self):
        self.assertIn('GITHUB_TOKEN pushes do not trigger one.', RELEASE_RAW)
        self.assertNotIn('queued/fresh workflow', RELEASE_RAW)
        binding = next(s for s in RELEASE['jobs']['release-pr']['steps']
                       if s.get('name') == 'Bind latest main to the upstream publication')
        self.assertEqual(binding['env'], {
            'PENDING_MAIN_SHA': '${{ needs.pending.outputs.main }}',
            'PUBLISH_MAIN_SHA': '${{ needs.publish.outputs.main }}',
            'PUBLISH_RESULT': '${{ needs.publish.result }}',
        })
        self.assertIn('git merge-base --is-ancestor "$expected" "$main_sha"', binding['run'])
        self.assertIn('"$expected:release/batch.json"', binding['run'])
        self.assertNotIn('$GITHUB_SHA', binding['run'])

    def test_release_pr_validates_both_immutable_endpoints_and_transition_before_binding(self):
        binding = next(s for s in RELEASE['jobs']['release-pr']['steps']
                       if s.get('name') == 'Bind latest main to the upstream publication')
        run = binding['run']
        self.assertIn('git worktree add --detach "$expected_tree" "$expected"', run)
        self.assertIn('git worktree add --detach "$latest_tree" "$main_sha"', run)
        self.assertIn('bootstrap-source --head "$expected"', run)
        self.assertIn('git worktree add --detach "$source_tree" "$source"', run)
        self.assertIn('tools/verify-git-build-identity.sh "$tool_head"', run)
        self.assertIn('release-pr-pinned-servicerelease', run)
        self.assertIn('"$pinned_tool" validate-transition', run)
        self.assertIn('--from-root "$expected_tree" --from-head "$expected"', run)
        self.assertIn('--to-root "$latest_tree" --to-head "$main_sha"', run)
        self.assertLess(run.index('validate-transition'), run.index('echo "sha=$main_sha"'))
        self.assertNotIn('GIT_PUSH_TOKEN', run)
        self.assertNotIn('github.token', str(binding))

    def test_the_release_pr_gets_its_checks(self):
        # GitHub starts no pull_request run for a PR the workflow's token opened or
        # updated, so release-pr starts the PR checks on the branch itself.
        pr = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['release-pr']['steps'])
        line = next(l for l in pr.splitlines() if '--workflows ' in l)
        dispatched = line.split('--workflows ')[1].split()[0].split(',')
        self.assertIn('"$tool" dispatch --ref release/next', pr)
        self.assertEqual(sorted(dispatched), ['e2e-contract.yml', 'native-rbac.yml', 'pr-validation.yml'])
        for workflow in dispatched:
            doc = yaml.load((ROOT / '.github/workflows' / workflow).read_text(), Loader=yaml.BaseLoader)
            self.assertIn('workflow_dispatch', doc['on'], workflow)
            self.assertIn('pull_request', doc['on'], workflow)


if __name__ == '__main__':
    unittest.main()
