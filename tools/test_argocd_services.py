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
REPO = 'https://github.com/PhorvexSecurity/operator-refactored.git'
HELM = shutil.which('helm')
# Argo CD renders each chart without its CRDs (skipCrds).
CLUSTER_SCOPED = {'Namespace', 'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding', 'MutatingWebhookConfiguration',
                  'ValidatingWebhookConfiguration', 'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding',
                  'PriorityClass', 'StorageClass', 'PersistentVolume', 'APIService'}


def load(path):
    return yaml.safe_load(path.read_text())


APPLICATION_SET = load(SERVICES / 'applicationset.yaml')
PROJECT = load(SERVICES / 'project.yaml')
MATRIX = APPLICATION_SET['spec']['generators'][0]['matrix']['generators']
ENVIRONMENTS_LISTED = MATRIX[0]['list']['elements']
ELEMENTS = MATRIX[1]['list']['elements']
ENVIRONMENT_NAMES = [e['environment'] for e in ENVIRONMENTS_LISTED]
TEMPLATE = APPLICATION_SET['spec']['template']
IN_CLUSTER = 'https://kubernetes.default.svc'


def value_files(environment, service):
    files = TEMPLATE['spec']['sources'][0]['helm']['valueFiles']
    return [ROOT / f.replace('$values/', '').replace('{{.environment}}', environment).replace('{{.service}}', service) for f in files]


def render(environment, element):
    # As the template releases it: the environment's release name and namespace, no CRDs.
    args = [HELM, 'template', environment['release'], str(ROOT / element['chart']), '-n', environment['namespace']]
    for path in value_files(environment['environment'], element['service']):
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
        self.assertEqual(TEMPLATE['spec']['destination'], {'server': '{{.server}}', 'namespace': '{{.namespace}}'})
        self.assertEqual(PROJECT['spec']['destinations'], [{'server': e['server'], 'namespace': e['namespace']} for e in ENVIRONMENTS_LISTED])
        self.assertIs(TEMPLATE['spec']['sources'][0]['helm']['skipCrds'], True)

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
        for environment in ENVIRONMENTS_LISTED:
            namespace = environment['namespace']
            cluster = set()
            for element in ELEMENTS:
                with self.subTest(environment=environment['environment'], service=element['service']):
                    for d in render(environment, element):
                        group = d['apiVersion'].rpartition('/')[0]
                        if d['kind'] in CLUSTER_SCOPED:
                            cluster.add((group, d['kind']))
                        else:
                            self.assertEqual(d['metadata'].get('namespace', namespace), namespace, (d['kind'], d['metadata']['name']))
            # Exactly what the charts need, and the namespace CreateNamespace creates.
            self.assertEqual(allowed, cluster | {('', 'Namespace')}, environment['environment'])

    def test_the_manager_reaches_each_services_grpc_port(self):
        for environment in ENVIRONMENTS_LISTED:
            endpoints = load(ENVIRONMENTS / environment['environment'] / 'phorvex.yaml')['phorvex']['services']
            by_service = {e['service']: e for e in ELEMENTS}
            self.assertEqual(set(endpoints), set(by_service) - {'manager'})
            manager = next(d for d in render(environment, by_service['manager']) if d['kind'] == 'Deployment')
            args = manager['spec']['template']['spec']['containers'][0]['args']
            for service, value in endpoints.items():
                with self.subTest(environment=environment['environment'], service=service):
                    docs = render(environment, by_service[service])
                    svc = next(d for d in docs if d['kind'] == 'Service')
                    port = next(p['port'] for p in svc['spec']['ports'] if p['name'] == 'grpc')
                    self.assertEqual(value['endpoint'], f"{svc['metadata']['name']}:{port}")
                    self.assertIn(f"--{service}-endpoint={value['endpoint']}", args)



    def test_an_environment_beside_production_leaves_it_alone(self):
        # On the production cluster the manager, sensor and actuator share the API
        # server with the production stack, which reconciles every policy and whose
        # Phoenix acts on every SecurityEvent.
        by_service = {e['service']: e for e in ELEMENTS}
        for environment in [e for e in ENVIRONMENTS_LISTED if e['server'] == IN_CLUSTER]:
            with self.subTest(environment=environment['environment']):
                namespace, release = environment['namespace'], environment['release']
                self.assertNotEqual(namespace, 'phorvex-system')
                self.assertNotEqual(release, 'phorvex')
                values = load(ENVIRONMENTS / environment['environment'] / 'phorvex.yaml')['phorvex']
                self.assertEqual(values['policyNamespaces'], [namespace])
                self.assertIs(values['globalKillSwitch'], True)
                self.assertIs(values['admissionWebhook']['enabled'], False)
                self.assertIs(values['eventIdentityPolicy']['enabled'], False)
                for service, element in by_service.items():
                    docs = render(environment, element)
                    for d in docs:
                        if d['kind'] in CLUSTER_SCOPED:
                            self.assertTrue(d['metadata']['name'].startswith(release + '-'), (service, d['kind'], d['metadata']['name']))
                    if service in ('manager', 'sensor', 'actuator'):
                        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
                        args = pod['containers'][0]['args']
                        self.assertIn(f'--policy-namespaces={namespace}', args, service)
                        if service == 'manager':
                            self.assertIn('--global-kill-switch=true', args)

if __name__ == '__main__':
    unittest.main()
