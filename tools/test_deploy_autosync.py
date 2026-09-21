"""Exercise the real remote waiter with isolated kubectl transport responses."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WAITER = ROOT / 'deploy/argocd/wait-for-rollout.sh'
OLD = 'example.invalid/phorvex:0.4.101'
WANTED = 'example.invalid/phorvex:0.4.104'
FAKE = r'''
import json, os, pathlib, sys
p = pathlib.Path(os.environ['FAKE_STATE'])
state = json.loads(p.read_text())
args = sys.argv[1:]
with pathlib.Path(os.environ['FAKE_CALLS']).open('a') as stream:
    stream.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + '\n')
if pathlib.Path(sys.argv[0]).name == 'sleep':
    sys.exit(0)
if args[:5] == ['-n', 'argocd', 'get', 'application', 'phorvex-stack']:
    state['poll'] += 1
    p.write_text(json.dumps(state))
    if state.get('app_error'):
        sys.exit('Application read failed: forbidden or not found')
    index = min(state['poll'] - 1, len(state['apps']) - 1)
    value = state['apps'][index]
    print(value if isinstance(value, str) else json.dumps(value))
elif args[:5] == ['-n', 'phorvex-system', 'get', 'deploy', 'phorvex-phorvex']:
    if state.get('deploy_error'):
        sys.exit('Deployment read failed: forbidden or not found')
    index = min(state['poll'] - 1, len(state['images']) - 1)
    print(state['images'][index])
elif args[:5] == ['-n', 'phorvex-system', 'rollout', 'status', 'deploy/phorvex-phorvex']:
    if state.get('rollout_error'):
        sys.exit('Deployment unavailable: rollout timeout')
    print('deployment phorvex-phorvex successfully rolled out')
else:
    sys.exit('Unexpected or mutating kubectl command: ' + repr(args))
'''


def app(automated):
    return {'spec': {'syncPolicy': {'automated': automated}}}


class DeployAutosyncTests(unittest.TestCase):
    def run_wait(self, apps=None, images=None, env=None, **faults):
        with tempfile.TemporaryDirectory(prefix='deploy-autosync-test-') as raw:
            tmp = Path(raw)
            state = tmp / 'state.json'
            calls = tmp / 'calls.jsonl'
            state.write_text(json.dumps(dict(poll=0, apps=apps or [app({'enabled': True})],
                                            images=images or [OLD, WANTED], **faults)))
            for name in ('kubectl', 'sleep'):
                target = tmp / name
                target.write_text('#!' + sys.executable + '\n' + FAKE)
                target.chmod(0o700)
            # Use the executing test environment, not an arbitrary system Python.
            (tmp / 'python3').symlink_to(sys.executable)
            run_env = dict(os.environ, PATH=str(tmp) + os.pathsep + os.environ['PATH'],
                           V='0.4.104', WAIT_ATTEMPTS='3', WAIT_INTERVAL_SECONDS='1',
                           FAKE_STATE=str(state), FAKE_CALLS=str(calls), KUBECONFIG='/dev/null')
            run_env.update(env or {})
            result = subprocess.run(['bash', str(WAITER)], env=run_env, text=True,
                                    capture_output=True, timeout=5)
            actual = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        # Check every exercised branch remains inside the read-only transport boundary.
        for call in actual:
            if call[0] == 'kubectl':
                self.assertIn(call[3], ('get', 'rollout'))
                if call[3] == 'rollout':
                    self.assertEqual(call[4], 'status')
                    self.assertIn('--timeout=180s', call)
                else:
                    self.assertIn('--request-timeout=10s', call)
        return result, actual

    def assert_early_failure(self, result, calls, diagnosis):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(diagnosis, result.stderr)
        self.assertFalse(any(call[0] == 'sleep' for call in calls))
        self.assertFalse(any(call[3:5] == ['rollout', 'status'] for call in calls))

    def test_manifest_explicitly_enables_sync_without_pruning(self):
        source = yaml.safe_load((ROOT / 'deploy/argocd/apps/phorvex-stack.yaml').read_text())
        self.assertEqual(source['metadata']['name'], 'phorvex-stack')
        spec = source['spec']
        self.assertEqual(spec['source']['path'], 'deploy/helm/phorvex-stack')
        self.assertEqual(spec['syncPolicy']['automated'],
                         {'enabled': True, 'prune': False, 'selfHeal': True})
        self.assertIs(spec['syncPolicy']['automated']['enabled'], True)
        self.assertIs(spec['syncPolicy']['automated']['prune'], False)
        self.assertIs(spec['syncPolicy']['automated']['selfHeal'], True)
        self.assertIn('RespectIgnoreDifferences=true', spec['syncPolicy']['syncOptions'])

    def test_actual_waiter_is_streamed_by_ci_and_tested_in_isolated_jobs(self):
        ci = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        step = next(s for s in ci['jobs']['deploy']['steps']
                    if s.get('name') == 'Wait for ArgoCD to roll it out')
        self.assertEqual(step['if'], "steps.publish.outputs.released == 'true'")
        self.assertIn('< deploy/argocd/wait-for-rollout.sh', step['run'])
        # Direct read-only cluster access first; the SSH jump host is the fallback. Both
        # carry MARKERS so the waiter checks only the components this release re-tagged.
        self.assertIn('V="$V" MARKERS="$MARKERS" bash deploy/argocd/wait-for-rollout.sh', step['run'])
        self.assertIn("V=$V MARKERS='$MARKERS' bash -s", step['run'])
        self.assertLess(step['run'].index('[[ "$V" =~'), step['run'].index('sshpass -e ssh'))
        # The waiter logs in with the shared jump-host password, so it verifies the same
        # pinned host identity as the E2E transport (T1-E2E-AUTH) and never accepts an
        # unknown or changed key.
        self.assertIn('StrictHostKeyChecking=yes', step['run'])
        self.assertIn('UserKnownHostsFile=$PHORVEX_SSH_KNOWN_HOSTS', step['run'])
        self.assertNotIn('StrictHostKeyChecking=no', step['run'])
        self.assertNotIn('UserKnownHostsFile=/dev/null', step['run'])
        steps = ci['jobs']['deploy']['steps']
        provisioning = next(s for s in steps if s.get('name') == 'Provision the SSH host identity')
        self.assertEqual(provisioning['if'], step['if'])
        self.assertLess(steps.index(provisioning), steps.index(step))
        chart = '\n'.join(s.get('run', '') for s in ci['jobs']['chart-sync']['steps'])
        self.assertIn('python3 tools/test_deploy_autosync.py', chart)
        self.assertIn('bash -n deploy/argocd/wait-for-rollout.sh', chart)
        for workflow, job in (('pr-validation.yml', 'charts'), ('e2e-contract.yml', 'e2e-contract')):
            isolated = yaml.load((ROOT / '.github/workflows' / workflow).read_text(), Loader=yaml.BaseLoader)
            self.assertEqual(isolated['permissions'], {'contents': 'read'})
            self.assertIn('unittest discover -s tools', '\n'.join(
                s.get('run', '') for s in isolated['jobs'][job]['steps']))

    def test_explicitly_disabled_is_immediate_and_does_not_sleep(self):
        result, calls = self.run_wait(apps=[app({'enabled': False, 'selfHeal': True})])
        self.assert_early_failure(result, calls, 'automated.enabled=false')
        self.assertIn('expected :0.4.104', result.stderr)

    def test_missing_policy_is_disabled_but_not_misreported_as_explicit_false(self):
        for value in ({'spec': {}}, {'spec': {'syncPolicy': None}},
                      {'spec': {'syncPolicy': {}}}, app(None)):
            with self.subTest(value=value):
                result, calls = self.run_wait(apps=[value])
                self.assert_early_failure(result, calls, 'no automated sync policy')

    def test_true_empty_and_null_enabled_follow_argocd_semantics(self):
        for value in ({'enabled': True}, {}, {'selfHeal': True}, {'enabled': None}):
            with self.subTest(value=value):
                result, calls = self.run_wait(apps=[app(value)])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('ready at 0.4.104', result.stdout)
                self.assertEqual(sum(c[0] == 'sleep' for c in calls), 1)
                self.assertEqual(sum(c[3:5] == ['rollout', 'status'] for c in calls), 1)

    def test_already_desired_image_still_checks_readiness_when_paused(self):
        for value in (app({'enabled': False}), {'spec': {}}):
            with self.subTest(value=value):
                result, calls = self.run_wait(apps=[value], images=[WANTED])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('automated sync: enabled', result.stdout)
                self.assertFalse(any(c[0] == 'sleep' for c in calls))
                self.assertEqual(sum(c[3:5] == ['rollout', 'status'] for c in calls), 1)

    def test_already_desired_does_not_bypass_invalid_or_unreadable_application(self):
        for kwargs in ({'app_error': True}, {'apps': ['not json']}):
            with self.subTest(kwargs=kwargs):
                result, calls = self.run_wait(images=[WANTED], **kwargs)
                self.assert_early_failure(result, calls, '::error::')

    def test_pause_during_wait_is_detected_on_next_poll(self):
        result, calls = self.run_wait(apps=[app({}), app({'enabled': False})], images=[OLD])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('automated.enabled=false', result.stderr)
        self.assertEqual(sum(c[0] == 'sleep' for c in calls), 1)

    def test_application_read_error_is_not_masked_as_old_image(self):
        result, calls = self.run_wait(app_error=True)
        self.assert_early_failure(result, calls, 'Cannot read argocd/phorvex-stack')
        self.assertEqual(len(calls), 1)

    def test_deployment_read_error_and_missing_manager_fail_explicitly(self):
        for kwargs, diagnosis in (({'deploy_error': True}, 'Cannot read phorvex-system'),
                                  ({'images': ['']}, 'has no manager image')):
            result, calls = self.run_wait(**kwargs)
            self.assert_early_failure(result, calls, diagnosis)

    def test_malformed_policy_fails_closed(self):
        values = ['not json', [], {}, {'spec': []}, {'spec': {'syncPolicy': False}},
                  app(False), app([]), app({'enabled': 'false'}), app({'enabled': 0})]
        for value in values:
            with self.subTest(value=value):
                result, calls = self.run_wait(apps=[value])
                self.assert_early_failure(result, calls, 'Cannot determine automated sync policy')

    def test_rollout_failure_is_never_success(self):
        for value in ({'enabled': True}, {'enabled': False}):
            result, calls = self.run_wait(apps=[app(value)], images=[WANTED], rollout_error=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('rollout readiness failed', result.stderr)
            self.assertNotIn('ready at', result.stdout)

    def test_wrong_or_superseding_version_times_out_with_finite_poll_count(self):
        for image in (OLD, WANTED + '0', 'example.invalid/phorvex:0.4.105'):
            with self.subTest(image=image):
                result, calls = self.run_wait(images=[image])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('after 3 polls', result.stderr)
                self.assertEqual(sum(c[0] == 'sleep' for c in calls), 2)
                self.assertEqual(sum(c[3:5] == ['get', 'application'] for c in calls), 3)
                self.assertFalse(any(c[3:5] == ['rollout', 'status'] for c in calls))

    def test_bad_inputs_are_rejected_before_kubectl(self):
        for key, values in {'V': ['', 'x;touch bad', 'x y', 'x' * 129],
                            'WAIT_ATTEMPTS': ['0', '61', '01', '-1', 'x'],
                            'WAIT_INTERVAL_SECONDS': ['0', '16', '01', 'x']}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    result, calls = self.run_wait(env={key: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(calls)


if __name__ == '__main__':
    unittest.main()
