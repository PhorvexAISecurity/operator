"""The Argo CD manifests of the split services (deploy/argocd/services) against the charts and environments."""
from pathlib import Path
import os
import shutil
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / 'deploy/argocd/services'
ENVIRONMENTS = ROOT / 'deploy/environments'
REPO = 'git@github.com:PhorvexSecurity/operator-refactored.git'
HELM = shutil.which('helm')
# Rendered by `helm template --include-crds`, as Argo CD renders a chart.
CLUSTER_SCOPED = {'Namespace', 'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding', 'MutatingWebhookConfiguration',
                  'ValidatingWebhookConfiguration', 'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding',
                  'PriorityClass', 'StorageClass', 'PersistentVolume', 'APIService'}


def load(path):
    return yaml.safe_load(path.read_text())


APPLICATION_SET = load(SERVICES / 'applicationset.yaml')
PROJECT = load(SERVICES / 'project.yaml')
MATRIX = APPLICATION_SET['spec']['generators'][0]['matrix']['generators']
ELEMENTS = MATRIX[1]['list']['elements']
ENVIRONMENT_NAMES = MATRIX[0]['clusters']['selector']['matchExpressions'][0]['values']
TEMPLATE = APPLICATION_SET['spec']['template']


def value_files(environment, service):
    env = '{{index .metadata.labels "phorvex.ai/environment"}}'
    files = TEMPLATE['spec']['sources'][0]['helm']['valueFiles']
    return [ROOT / f.replace('$values/', '').replace(env, environment).replace('{{.service}}', service) for f in files]


def render(environment, element):
    args = [HELM, 'template', TEMPLATE['spec']['sources'][0]['helm']['releaseName'], str(ROOT / element['chart']),
            '-n', TEMPLATE['spec']['destination']['namespace'], '--include-crds']
    for path in value_files(environment, element['service']):
        args += ['-f', str(path)]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


class ManifestTests(unittest.TestCase):
    def test_every_service_chart_has_an_application(self):
        charts = {e['chart'] for e in ELEMENTS}
        services = {str(p.parent.relative_to(ROOT)) for p in (ROOT / 'deploy/charts').glob('*/Chart.yaml')
                    if load(p).get('type') != 'library'}
        self.assertEqual(charts, services | {'phorvex/charts/phorvex'})
        self.assertEqual(len({e['service'] for e in ELEMENTS}), len(ELEMENTS))
        for element in ELEMENTS:
            self.assertTrue((ROOT / element['chart'] / 'Chart.yaml').exists(), element)

    def test_only_this_repository_is_deployed(self):
        self.assertEqual(PROJECT['spec']['sourceRepos'], [REPO])
        self.assertEqual({s['repoURL'] for s in TEMPLATE['spec']['sources']}, {REPO})
        self.assertEqual(TEMPLATE['spec']['project'], PROJECT['metadata']['name'])
        self.assertEqual([d['namespace'] for d in PROJECT['spec']['destinations']], [TEMPLATE['spec']['destination']['namespace']])

    def test_nothing_applies_these_manifests(self):
        root = load(ROOT / 'deploy/argocd/root.yaml')
        self.assertEqual(root['spec']['source']['path'], 'deploy/argocd/apps')
        for app in (ROOT / 'deploy/argocd/apps').glob('*.yaml'):
            self.assertNotIn('operator-refactored', app.read_text(), app.name)
            self.assertNotIn('deploy/argocd/services', app.read_text(), app.name)

    def test_every_environment_has_its_value_files(self):
        self.assertEqual(sorted(ENVIRONMENT_NAMES), sorted(p.name for p in ENVIRONMENTS.iterdir() if p.is_dir()))
        for environment in ENVIRONMENT_NAMES:
            want = {'phorvex.yaml'} | {e['service'] + '.yaml' for e in ELEMENTS}
            self.assertEqual({p.name for p in (ENVIRONMENTS / environment).iterdir()}, want, environment)

    def test_the_webhook_certificate_is_kept(self):
        self.assertIn('RespectIgnoreDifferences=true', TEMPLATE['spec']['syncPolicy']['syncOptions'])
        ignored = {(i.get('group', ''), i['kind']) for i in TEMPLATE['spec']['ignoreDifferences']}
        self.assertLessEqual({('', 'Secret'), ('admissionregistration.k8s.io', 'MutatingWebhookConfiguration'),
                              ('admissionregistration.k8s.io', 'ValidatingWebhookConfiguration')}, ignored)


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class EnvironmentRenderTests(unittest.TestCase):
    def test_every_environment_renders_within_the_project(self):
        allowed = {(k['group'], k['kind']) for k in PROJECT['spec']['clusterResourceWhitelist']}
        namespace = TEMPLATE['spec']['destination']['namespace']
        for environment in ENVIRONMENT_NAMES:
            cluster = set()
            for element in ELEMENTS:
                with self.subTest(environment=environment, service=element['service']):
                    for d in render(environment, element):
                        group = d['apiVersion'].rpartition('/')[0]
                        if d['kind'] in CLUSTER_SCOPED:
                            cluster.add((group, d['kind']))
                        else:
                            self.assertEqual(d['metadata'].get('namespace', namespace), namespace, (d['kind'], d['metadata']['name']))
            # Exactly what the charts need, and the namespace CreateNamespace creates.
            self.assertEqual(allowed, cluster | {('', 'Namespace')}, environment)

    def test_the_manager_reaches_each_services_grpc_port(self):
        for environment in ENVIRONMENT_NAMES:
            endpoints = load(ENVIRONMENTS / environment / 'phorvex.yaml')['phorvex']['services']
            by_service = {e['service']: e for e in ELEMENTS}
            self.assertEqual(set(endpoints), set(by_service) - {'manager'})
            manager = next(d for d in render(environment, by_service['manager']) if d['kind'] == 'Deployment')
            args = manager['spec']['template']['spec']['containers'][0]['args']
            for service, value in endpoints.items():
                with self.subTest(environment=environment, service=service):
                    docs = render(environment, by_service[service])
                    svc = next(d for d in docs if d['kind'] == 'Service')
                    port = next(p['port'] for p in svc['spec']['ports'] if p['name'] == 'grpc')
                    self.assertEqual(value['endpoint'], f"{svc['metadata']['name']}:{port}")
                    self.assertIn(f"--{service}-endpoint={value['endpoint']}", args)


if __name__ == '__main__':
    unittest.main()
