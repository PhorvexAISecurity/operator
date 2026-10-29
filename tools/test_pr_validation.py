"""Guard the actual all-base candidate-source workflow and its fail-closed gate."""
from pathlib import Path
import os
import re
import subprocess
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
        self.assertEqual(set(job['needs']), {'charts', 'go-unit', 'go-envtest', 'frontend', 'lint', 'images'})
        script = job['steps'][0]['run']
        good = dict(CHARTS='success', GO_UNIT='success', GO_ENVTEST='success', FRONTEND='success',
                    LINT='success', IMAGES='success')
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
        # the one that has, release.yml, is held to its exact shape by ReleaseWorkflowTests.
        # Every job runs on a GitHub-hosted runner, never on a runner with live access.
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            if path.name == 'release.yml':
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



RELEASE_RAW = (ROOT / '.github/workflows/release.yml').read_text()
RELEASE = yaml.load(RELEASE_RAW, Loader=yaml.BaseLoader)
AWS_ACTIONS = {'aws-actions/configure-aws-credentials@7474bc4690e29a8392af63c5b98e7449536d5c3a',
               'aws-actions/amazon-ecr-login@03f1aad4c6c7ffd436567f42f9384779290529bd'}


class ReleaseWorkflowTests(unittest.TestCase):
    """The one workflow that writes and reaches AWS (docs/services/releasing.md), held to its shape."""

    def test_it_runs_only_for_main(self):
        self.assertEqual(set(RELEASE['on']), {'push', 'workflow_dispatch'})
        self.assertEqual(RELEASE['on']['push'], {'branches': ['main']})
        self.assertEqual(RELEASE['permissions'], {'contents': 'read'})
        self.assertEqual(RELEASE['concurrency'], {'group': 'release', 'cancel-in-progress': 'false'})
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
                                     {'actions/checkout', 'actions/setup-go', 'aws-actions/configure-aws-credentials', 'aws-actions/amazon-ecr-login'})
        self.assertEqual(jobs['pending'].get('permissions'), None)
        self.assertEqual(jobs['release-pr']['permissions'], {'contents': 'write', 'pull-requests': 'write', 'actions': 'write'})
        pending_checkout = next(s for s in jobs['pending']['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(pending_checkout['with']['persist-credentials'], 'false')

    def test_the_role_is_checked_before_it_is_assumed(self):
        steps = RELEASE['jobs']['publish']['steps']
        names = [s.get('name') or s.get('uses', '') for s in steps]
        check = names.index('Require the release role')
        assume = next(i for i, n in enumerate(names) if n.startswith('aws-actions/configure-aws-credentials@'))
        self.assertLess(check, assume)
        self.assertIn('PHORVEX_RELEASE_ROLE_ARN', steps[check]['run'])

    def test_staging_is_pinned_by_digest_and_releases_are_tagged(self):
        run = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['publish']['steps'])
        self.assertIn('./tools/servicerelease pending', run)
        self.assertIn('servicerelease deploy --environment "$ENVIRONMENT"', run)
        self.assertIn('--digest "${digest#*@}"', run)
        self.assertIn('git tag "$component-v$version" "$GITHUB_SHA"', run)
        self.assertEqual(RELEASE['env']['ENVIRONMENT'], 'staging')
        pr = '\n'.join(s.get('run', '') for s in RELEASE['jobs']['release-pr']['steps'])
        # A built binary, not `go run`, which reports prepare's exit 3 as 1.
        self.assertIn('go -C phorvex build -o "$RUNNER_TEMP/servicerelease" ./tools/servicerelease', pr)
        self.assertNotIn('servicerelease prepare', pr.replace('"$tool" prepare', ''))
        self.assertIn('"$tool" prepare --title-file', pr)
        # A release still to publish is left to its own run, and nothing to release
        # closes a release PR left open.
        self.assertIn('if [ -n "$("$tool" pending)" ]; then', pr)
        self.assertLess(pr.index('"$tool" pending'), pr.index('"$tool" prepare'))
        self.assertIn('"$tool" close-pull-request --head release/next --base main', pr)
        self.assertIn('"$tool" pull-request --head release/next --base main', pr)

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
