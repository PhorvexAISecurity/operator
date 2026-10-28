"""Tests for benchmark/lab/shims (ticket Part 2 TP-3, DR-37).

The shims run as they would inside run.sh's lab environment: a RUN_DIR with
run.json naming the real tools (here fakes that log their argv), a lab
kubeconfig, and the LAB_* variables. A refusal must exit 97, be recorded in
COMMANDS.log, and never reach the real tool.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SHIMS = TESTS.parent / 'shims'
FAKE_BIN, FAKE_AWS = TESTS / 'fake_bin', TESTS / 'fake_aws'
LAB_SERVER, DEV_SERVER = 'https://LAB.eks.example', 'https://127.0.0.1:9'


def kubeconfig(server, context='lab-ctx'):
    return {'apiVersion': 'v1', 'kind': 'Config', 'current-context': context,
            'clusters': [{'name': 'c', 'cluster': {'server': server}}],
            'contexts': [{'name': context, 'context': {'cluster': 'c', 'user': 'u'}}],
            'users': [{'name': 'u', 'user': {}}]}


class ShimTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='shim-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.run_dir = self.tmp / 'run'
        self.run_dir.mkdir()
        self.lab_kc = self.run_dir / 'kubeconfig'
        self.lab_kc.write_text(json.dumps(kubeconfig(LAB_SERVER)))
        self.dev_kc = self.tmp / 'dev-kubeconfig'
        self.dev_kc.write_text(json.dumps(kubeconfig(DEV_SERVER, 'lab-ctx')))
        (self.run_dir / 'run.json').write_text(json.dumps({'runId': 'abc123', 'real': {'tools': {
            'kubectl': str(FAKE_BIN / 'kubectl'), 'helm': str(FAKE_BIN / 'helm'), 'aws': str(FAKE_AWS / 'aws')}}}))
        self.world = self.tmp / 'world.json'
        self.world.write_text(json.dumps({'account': '753556437180', 'items': []}))
        self.log = self.tmp / 'stub.log'
        self.home = self.tmp / 'home'
        (self.home / '.kube').mkdir(parents=True)
        (self.home / '.kube' / 'config').write_text('real kubeconfig sentinel\n')
        self.env = {
            'PATH': f'{SHIMS}:/usr/bin:/bin', 'HOME': str(self.home), 'RUN_DIR': str(self.run_dir),
            'KUBECONFIG': str(self.lab_kc), 'LAB_KUBECONFIG': str(self.lab_kc), 'LAB_CONTEXT': 'lab-ctx',
            'LAB_EXPECTED_SERVER': LAB_SERVER, 'LAB_FORBIDDEN_SERVERS': DEV_SERVER,
            'BENCH_DEV_CLUSTER': 'phorvex-dev-eks', 'AWS_REGION': 'us-east-2',
            'STUB_LOG': str(self.log), 'STUB_WORLD': str(self.world)}

    def shim(self, tool, *args, **env):
        merged = {**self.env, **env}
        for k in [k for k, v in merged.items() if v is None]:
            del merged[k]
        return subprocess.run([str(SHIMS / tool), *args], text=True, capture_output=True, env=merged)

    def commands(self):
        path = self.run_dir / 'COMMANDS.log'
        return [l.split('\t') for l in path.read_text().splitlines()] if path.exists() else []

    def real_calls(self, tool):
        if not self.log.exists():
            return []
        return [l.split('\t')[1:] for l in self.log.read_text().splitlines() if l.split('\t')[0] == tool]

    def assert_refused(self, result, tool, needle):
        self.assertEqual(result.returncode, 97, result.stderr)
        self.assertIn(needle, result.stderr)
        self.assertEqual(self.commands()[-1][2], 'refused')
        # The real tool was not run; the kubectl fake may only have been asked to read the lab kubeconfig.
        reached = [c for c in self.real_calls(tool) if 'config' not in c or tool != 'kubectl']
        self.assertEqual(reached, [], f'{tool} was reached despite the refusal')

    def test_kubectl_refusals(self):
        cases = [
            ({'LAB_EXPECTED_SERVER': ''}, ['get', 'pods'], 'LAB_EXPECTED_SERVER is empty'),
            ({'KUBECONFIG': str(self.dev_kc), 'LAB_KUBECONFIG': str(self.dev_kc)}, ['get', 'pods'], 'forbidden server'),
            ({'LAB_EXPECTED_SERVER': 'https://OTHER.eks.example'}, ['get', 'pods'], 'not the lab'),
            ({}, ['--server', 'https://x', 'get', 'pods'], 'another server'),
            ({}, ['-s', 'https://x', 'get', 'pods'], 'another server'),
            ({}, ['--token=SECRET-TOKEN', 'get', 'pods'], 'another server or identity'),
            ({}, ['--user', 'admin', 'get', 'pods'], 'another server'),
            ({}, ['--insecure-skip-tls-verify', 'get', 'pods'], 'another server'),
            ({}, ['--kubeconfig', str(self.dev_kc), 'get', 'pods'], 'not the lab kubeconfig'),
            ({}, ['--context=dev', 'get', 'pods'], 'not the lab context'),
            ({'HELM_KUBECONTEXT': 'dev'}, ['get', 'pods'], 'HELM_KUBECONTEXT is set'),
            ({'KUBECONFIG': f'{self.lab_kc}:{self.dev_kc}'}, ['get', 'pods'], 'one file'),
            ({}, ['config', 'use-context', 'dev'], 'would change a kubeconfig'),
            ({}, ['config', 'set-context', 'x'], 'would change a kubeconfig'),
            ({}, ['ctx', 'dev'], 'plugins are refused'),
            ({}, ['-n', 'x'], 'no kubectl subcommand'),
            ({'RUN_DIR': str(self.tmp / 'nowhere')}, ['get', 'pods'], 'run.json is missing'),
        ]
        for env, args, needle in cases:
            with self.subTest(args=args, env=env):
                self.assert_refused(self.shim('kubectl', *args, **env), 'kubectl', needle)

    def test_kubectl_secret_is_redacted_in_the_log(self):
        self.shim('kubectl', '--token=SECRET-TOKEN', 'get', 'pods')
        text = (self.run_dir / 'COMMANDS.log').read_text()
        self.assertNotIn('SECRET-TOKEN', text)
        self.assertIn('--token=<redacted>', text)
        self.shim('kubectl', 'create', 'secret', 'generic', 's', '--from-literal=KEY=hunter2')
        self.assertNotIn('hunter2', (self.run_dir / 'COMMANDS.log').read_text())

    def test_refusal_reason_is_scrubbed_even_if_a_message_quotes_a_secret(self):
        script = (f'source {SHIMS}/shim-lib.sh; BENCH_TOOL=kubectl; BENCH_ARGS=(get pods); '
                  'bench_refuse "--token=TOK1 and --password PW2 and --kube-token=TOK3 and --from-literal=K=LIT4"')
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True, env=self.env)
        self.assertEqual(result.returncode, 97)
        logged = (self.run_dir / 'COMMANDS.log').read_text()
        for secret in ('TOK1', 'PW2', 'TOK3', 'LIT4'):
            self.assertNotIn(secret, logged)
            self.assertNotIn(secret, result.stderr)
        self.assertIn('--from-literal=K=<redacted>', logged)

    def test_kubectl_accepted_calls_target_the_lab_explicitly(self):
        for args, access in ((['get', 'pods', '-n', 'voice'], 'read'),
                             (['--kubeconfig', str(self.lab_kc), '--context', 'lab-ctx', 'delete', 'pod', 'x'], 'write'),
                             (['config', 'current-context'], 'read')):
            with self.subTest(args=args):
                result = self.shim('kubectl', *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                last = self.real_calls('kubectl')[-1]
                self.assertEqual(last[:4], ['--kubeconfig', str(self.lab_kc), '--context', 'lab-ctx'])
                self.assertEqual(last[4:], args)
                self.assertEqual(self.commands()[-1][1:4], ['shim', access, 'lab'])

    def test_helm_refusals_and_accepted_call(self):
        cases = [
            ({'LAB_EXPECTED_SERVER': ''}, ['list'], 'LAB_EXPECTED_SERVER is empty'),
            ({'HELM_KUBEAPISERVER': 'https://x'}, ['list'], 'HELM_KUBEAPISERVER is set'),
            ({}, ['list', '--kube-apiserver', 'https://x'], 'another server'),
            ({}, ['list', '--kube-token=t'], 'another server'),
            ({}, ['list', '--kube-context', 'dev'], 'not the lab context'),
            ({}, ['list', '--kubeconfig', str(self.dev_kc)], 'not the lab kubeconfig'),
            ({}, ['dependency', 'build', 'chart'], 'dependency are refused'),
            ({}, ['diff', 'upgrade', 'x'], 'plugins and dependency are refused'),
            ({'KUBECONFIG': str(self.dev_kc), 'LAB_KUBECONFIG': str(self.dev_kc)}, ['list'], 'forbidden server'),
        ]
        for env, args, needle in cases:
            with self.subTest(args=args, env=env):
                self.assert_refused(self.shim('helm', *args, **env), 'helm', needle)
        args = ['upgrade', '--install', 'phorvex', 'chart', '-n', 'phorvex-system', '-f', 'values.yaml']
        result = self.shim('helm', *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.real_calls('helm')[-1], [*args, '--kubeconfig', str(self.lab_kc), '--kube-context', 'lab-ctx'])
        self.assertEqual(self.commands()[-1][1:4], ['shim', 'write', 'lab'])

    def test_aws_refusals(self):
        cases = [
            (['eks', 'update-kubeconfig', '--name', 'phorvex-281-lab-abc123'], {}, 'would write a kubeconfig'),
            (['--endpoint-url', 'http://evil', 'sts', 'get-caller-identity'], {}, '--endpoint-url'),
            (['--region', 'us-west-2', 'sts', 'get-caller-identity'], {}, 'not the lab region'),
            (['--profile', 'prod', 'sts', 'get-caller-identity'], {}, 'not the run'),
            (['eks', 'delete-cluster', '--name', 'phorvex-dev-eks'], {}, 'dev is read-only'),
            (['ec2', 'delete-volume', '--volume-id', 'vol-1', '--cli-input-json', DEV_SERVER], {}, 'dev is read-only'),
        ]
        for args, env, needle in cases:
            with self.subTest(args=args):
                self.assert_refused(self.shim('aws', *args, **env), 'aws', needle)

    def test_aws_reads_of_dev_and_lab_calls_pass_and_are_logged(self):
        result = self.shim('aws', '--region', 'us-east-2', 'eks', 'describe-cluster', '--name', 'phorvex-dev-eks')
        self.assertEqual(result.returncode, 254, 'reached the fake account, which has no such cluster')
        self.assertEqual(self.commands()[-1][1:4], ['shim', 'read', 'dev'])
        result = self.shim('aws', 'sts', 'get-caller-identity')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands()[-1][1:4], ['shim', 'read', 'lab'])
        self.assertEqual(self.real_calls('aws')[-1], ['sts', 'get-caller-identity'])

    def test_real_kubeconfig_is_never_touched(self):
        self.shim('kubectl', 'config', 'use-context', 'dev')
        self.shim('kubectl', 'get', 'pods')
        self.shim('aws', 'eks', 'update-kubeconfig', '--name', 'x')
        self.assertEqual((self.home / '.kube' / 'config').read_text(), 'real kubeconfig sentinel\n')

    def test_shim_lib_is_not_a_command(self):
        self.assertFalse(os.access(SHIMS / 'shim-lib.sh', os.X_OK))
        for tool in ('kubectl', 'helm', 'aws'):
            self.assertTrue(os.access(SHIMS / tool, os.X_OK), tool)
            subprocess.run(['bash', '-n', str(SHIMS / tool)], check=True)


if __name__ == '__main__':
    unittest.main()
