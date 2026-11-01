"""Render the actual staging values, including the final catalogue overlay."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

import staging_release

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / 'deploy/environments/staging'
HELM = shutil.which('helm')
POLICIES = ['phorvex-staging-demo/demo-api-defense', 'phorvex-staging-demo/stage-bench-defense']
SUBJECT = 'system:serviceaccount:phorvex-staging:staging-brain-benchmark'


def render(component, override=None, common=None, family=True):
    chart = ROOT / ('phorvex/charts/phorvex' if component == 'manager'
                    else 'deploy/charts/phorvex-' + component)
    command = [HELM, 'template', 'staging', str(chart), '-n', 'phorvex-staging',
               '--api-versions', 'monitoring.coreos.com/v1/PodMonitor', '-f', str(common or STAGE / 'phorvex.yaml'),
               '-f', str(override or STAGE / (component + '.yaml'))]
    if family:
        command += ['-f', str(STAGE / 'catalogue-family.yaml')]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def deployment(docs, container):
    return next(d for d in docs if d['kind'] == 'Deployment'
                and any(c['name'] == container for c in d['spec']['template']['spec']['containers']))


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class StageBenchmarkCaptureTests(unittest.TestCase):
    def console_with(self, data=None, additions=None, family=False):
        with tempfile.TemporaryDirectory() as directory:
            override = yaml.safe_load((STAGE / 'console.yaml').read_text())
            grants = override['phorvex']['console'].setdefault('auth', {}).setdefault('grants', {})
            grants['extraSubjects'] = additions if additions is not None else []
            if data is not None:
                grants['data'] = data
            path = Path(directory) / 'console.yaml'
            path.write_text(yaml.safe_dump(override))
            return render('console', path, family=family)

    def grant_output(self, docs):
        config = next(d for d in docs if d['kind'] == 'ConfigMap' and 'grants.json' in d.get('data', {}))
        checksum = deployment(docs, 'console')['spec']['template']['metadata']['annotations']['checksum/console-grants']
        return config['data']['grants.json'], checksum

    def assert_capture(self, component, docs):
        pod = deployment(docs, component)['spec']['template']['spec']
        container = next(c for c in pod['containers'] if c['name'] == component)
        if component == 'brain':
            self.assertIn('--math-lab-capture-policies=' + ','.join(POLICIES), container['args'])
            self.assertIn('--math-lab-capture-max-bytes=1073741824', container['args'])
            self.assertIn('--math-lab-capture-dir=/var/lib/phorvex/math-lab', container['args'])
            self.assertIn({'name': 'math-lab', 'persistentVolumeClaim': {'claimName': 'staging-brain-mathlab'}}, pod['volumes'])
            self.assertEqual(pod['securityContext']['fsGroup'], 65532)
            self.assertEqual(next(v['value'] for v in container['env'] if v['name'] == 'PHORVEX_BRAIN_IMAGE'), container['image'])
        elif component == 'manager':
            self.assertIn('--math-lab-capture-cost-evidence=true', container['args'])
            self.assertIn('--brain-endpoint=staging-brain:9090', container['args'])
            self.assertFalse(any(arg.startswith('--math-lab-capture-policies=') for arg in container['args']))
        else:
            config = next(d for d in docs if d['kind'] == 'ConfigMap' and 'grants.json' in d.get('data', {}))
            grants = json.loads(config['data']['grants.json'])
            binding = [g for g in grants['subjects'] if g['subject'] == SUBJECT]
            self.assertEqual(len(binding), 1)
            self.assertEqual(binding[0]['roles'], ['investor'])
            self.assertEqual(binding[0]['tenants'], ['phorvex-staging-demo'])
            self.assertEqual(binding[0]['targets'], ['default'])
            original = json.loads(yaml.safe_load((STAGE / 'catalogue-family.yaml').read_text())['phorvex']['console']['auth']['grants']['data'])
            self.assertEqual([g for g in grants['subjects'] if g['subject'] != SUBJECT], original['subjects'])
            annotation = deployment(docs, 'console')['spec']['template']['metadata']['annotations']['checksum/console-grants']
            self.assertEqual(annotation, hashlib.sha256(config['data']['grants.json'].rstrip('\n').encode()).hexdigest())

    def test_actual_stage_brain_records_both_policies_on_existing_pvc(self):
        self.assert_capture('brain', render('brain'))

    def test_actual_stage_manager_exports_cost_observations_to_remote_brain(self):
        self.assert_capture('manager', render('manager'))

    def test_actual_final_family_overlay_keeps_separate_read_only_benchmark_subject(self):
        self.assert_capture('console', render('console'))

    def test_official_next_release_pin_preserves_all_capture_and_reader_settings(self):
        batch = json.loads((ROOT / 'release/staging-batch.json').read_text())
        for component in ('brain', 'manager', 'console'):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as directory:
                item = copy.deepcopy(next(c for c in batch['components'] if c['component'] == component))
                future = copy.deepcopy(batch)
                future['source'] = 'a' * 40
                future['releases'][component]['digest'] = 'sha256:' + 'b' * 64
                item['image']['tag'] = 'staging-next-git-' + future['source']
                before = yaml.safe_load((STAGE / (component + '.yaml')).read_text())
                after = staging_release.expected_service_values(before, item, future)
                self.assertNotEqual(staging_release.nested(before, item['deploy']['path']), staging_release.nested(after, item['deploy']['path']))
                path = Path(directory) / 'values.yaml'
                path.write_text(yaml.safe_dump(after, sort_keys=False))
                docs = render(component, path)
                self.assert_capture(component, docs)
                container = next(c for c in deployment(docs, component)['spec']['template']['spec']['containers'] if c['name'] == component)
                self.assertIn('staging-next-git-' + 'a' * 40, container['image'])
                self.assertIn('sha256:' + 'b' * 64, container['image'])

    def test_default_empty_additions_preserve_grant_bytes_and_checksum(self):
        raw = json.dumps({'version': 1, 'subjects': []}, indent=2) + '\n'
        actual, checksum = self.grant_output(self.console_with(data=raw))
        self.assertEqual(actual, raw)
        self.assertEqual(checksum, hashlib.sha256(raw.encode()).hexdigest())
        raw = yaml.safe_load((STAGE / 'catalogue-family.yaml').read_text())['phorvex']['console']['auth']['grants']['data']
        actual, checksum = self.grant_output(self.console_with(family=True))
        self.assertEqual(actual, raw)
        self.assertEqual(checksum, hashlib.sha256(raw.encode()).hexdigest())

    def test_addition_update_changes_pod_checksum_and_does_not_add_kubernetes_grants(self):
        addition = {'issuer': 'https://issuer', 'subject': 'reader', 'roles': ['investor'], 'tenants': ['stage-demo'], 'targets': ['default']}
        raw = '{"version":1,"subjects":[]}'
        before = self.console_with(data=raw)
        after = self.console_with(data=raw, additions=[addition])
        self.assertNotEqual(self.grant_output(before)[1], self.grant_output(after)[1])
        kinds = ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding')
        self.assertEqual([d for d in before if d['kind'] in kinds], [d for d in after if d['kind'] in kinds])
        addition['tenants'] = ['stage-other']
        changed = self.console_with(data=raw, additions=[addition])
        self.assertNotEqual(self.grant_output(after)[1], self.grant_output(changed)[1])

    def test_invalid_or_ambiguous_additions_fail_closed(self):
        good = {'issuer': 'https://issuer', 'subject': 'reader', 'roles': ['investor'], 'tenants': ['stage-demo'], 'targets': ['default']}
        raw = json.dumps({'version': 1, 'subjects': [good]})
        invalid = [({}, [good]), ('{bad', [good]),
                   (json.dumps({'version': 2, 'subjects': []}), [good]),
                   (json.dumps({'version': '1', 'subjects': []}), [good]),
                   (json.dumps({'version': True, 'subjects': []}), [good]),
                   (raw, [good]), (raw, [{**good, 'subject': ' reader '}]),
                   (raw, {}), (raw, ['reader']),
                   (raw, [{**good, 'subject': '*'}]),
                   (raw, [{**good, 'subject': 12}]),
                   (raw, [{**good, 'subject': 'other', 'roles': ['execute']}]),
                   (raw, [{**good, 'subject': 'other', 'tenants': ['']}]),
                   (raw, [{**good, 'subject': 'other', 'unknown': True}])]
        for data, additions in invalid:
            with self.subTest(data=data, additions=additions), self.assertRaises(subprocess.CalledProcessError):
                self.console_with(data=data, additions=additions)


if __name__ == '__main__':
    unittest.main()
