"""Render the per-service charts (ADR-0001) and check what each may do."""
from pathlib import Path
import os
import shutil
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHARTS = ROOT / 'deploy/charts'
HELM = shutil.which('helm')


def render(chart, *sets):
    args = [HELM, 'template', 'phorvex', str(CHARTS / chart), '-n', 'phorvex-system']
    for s in sets:
        args += ['--set', s]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def by_kind(docs):
    out = {}
    for d in docs:
        out.setdefault(d['kind'], []).append(d)
    return out


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class BrainChartTests(unittest.TestCase):
    def test_the_brain_holds_no_kubernetes_credentials(self):
        kinds = by_kind(render('phorvex-brain'))
        self.assertEqual(sorted(kinds), ['Deployment', 'NetworkPolicy', 'Service', 'ServiceAccount'])
        for rbac in ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding'):
            self.assertNotIn(rbac, kinds)
        self.assertIs(kinds['ServiceAccount'][0]['automountServiceAccountToken'], False)
        pod = kinds['Deployment'][0]['spec']['template']['spec']
        self.assertIs(pod['automountServiceAccountToken'], False)

    def test_one_brain_runs_hardened(self):
        deployment = by_kind(render('phorvex-brain'))['Deployment'][0]
        self.assertEqual(deployment['spec']['replicas'], 1)
        self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
        pod = deployment['spec']['template']['spec']
        self.assertIs(pod['securityContext']['runAsNonRoot'], True)
        container = pod['containers'][0]
        self.assertEqual(container['image'], 'phorvex-brain:0.1.0')
        self.assertEqual(container['securityContext'],
                         {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}})
        self.assertIn('--engine=p1', container['args'])
        self.assertIn('--gpu-envelope-max=1', container['args'])
        self.assertFalse([a for a in container['args'] if a.startswith('--math-lab')])
        self.assertNotIn('volumes', pod)

    def test_math_lab_capture_gets_a_volume(self):
        pod = by_kind(render('phorvex-brain', 'mathLab.capturePolicies=vllm/defense', 'mathLab.existingClaim=brain-math-lab'))['Deployment'][0]['spec']['template']['spec']
        args = pod['containers'][0]['args']
        self.assertIn('--math-lab-capture-policies=vllm/defense', args)
        self.assertIn('--math-lab-capture-dir=/var/lib/phorvex/math-lab', args)
        self.assertIn('--math-lab-capture-max-bytes=1073741824', args)
        self.assertEqual(pod['volumes'], [{'name': 'math-lab', 'persistentVolumeClaim': {'claimName': 'brain-math-lab'}}])

    def test_only_the_manager_reaches_the_brain(self):
        policy = by_kind(render('phorvex-brain', 'metricsScraperNamespaces={monitoring}'))['NetworkPolicy'][0]['spec']
        self.assertEqual(policy['policyTypes'], ['Ingress', 'Egress'])
        self.assertEqual(policy['egress'], [])
        grpc, health, metrics = policy['ingress']
        self.assertEqual(grpc['ports'], [{'port': 'grpc'}])
        self.assertEqual(grpc['from'], [{
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'phorvex-system'}},
            'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'phorvex', 'app.kubernetes.io/component': 'manager'}}}])
        self.assertEqual(health, {'ports': [{'port': 'health'}]})
        self.assertEqual(metrics['ports'], [{'port': 'metrics'}])
        self.assertEqual(metrics['from'], [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'monitoring'}}}])


if __name__ == '__main__':
    unittest.main()
