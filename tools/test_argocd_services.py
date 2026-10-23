"""The Argo CD manifests of the split services (deploy/argocd/services) against the charts and environments."""
from pathlib import Path
import json
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


# The cluster's APIs Argo CD renders the charts against, beyond the built-in ones.
CLUSTER_APIS = ['--api-versions', 'monitoring.coreos.com/v1/PodMonitor', '--api-versions', 'monitoring.coreos.com/v1/PrometheusRule']


def service_pod(docs, service):
    """The pod spec of the Deployment whose first container is the service's."""
    return next(d['spec']['template']['spec'] for d in docs
                if d['kind'] == 'Deployment' and d['spec']['template']['spec']['containers'][0]['name'] == service)


def render(environment, element):
    # As the template releases it: the environment's release name and namespace, no CRDs.
    args = [HELM, 'template', environment['release'], str(ROOT / element['chart']), '-n', environment['namespace'], *CLUSTER_APIS]
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
        demo = load(SERVICES / 'demo-staging.yaml')['spec']['destination']
        self.assertEqual(PROJECT['spec']['destinations'], [{'server': e['server'], 'namespace': e['namespace']} for e in ENVIRONMENTS_LISTED] + [demo])
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
            # The services' own namespace, and the defended namespaces their Roles name.
            destinations = {d['namespace'] for d in PROJECT['spec']['destinations'] if d['server'] == environment['server']}
            cluster = set()
            for element in ELEMENTS:
                with self.subTest(environment=environment['environment'], service=element['service']):
                    for d in render(environment, element):
                        group = d['apiVersion'].rpartition('/')[0]
                        if d['kind'] in CLUSTER_SCOPED:
                            cluster.add((group, d['kind']))
                        else:
                            self.assertIn(d['metadata'].get('namespace', namespace), destinations, (d['kind'], d['metadata']['name']))
            # Exactly what the charts need, and the namespace CreateNamespace creates.
            self.assertEqual(allowed, cluster | {('', 'Namespace')}, environment['environment'])

    def test_the_manager_reaches_each_services_grpc_port(self):
        # The attacks service is the console's, over HTTP (the test below); the manager
        # calls no console.
        for environment in ENVIRONMENTS_LISTED:
            endpoints = load(ENVIRONMENTS / environment['environment'] / 'phorvex.yaml')['phorvex']['services']
            endpoints = {k: v for k, v in endpoints.items() if k != 'attacks'}
            by_service = {e['service']: e for e in ELEMENTS}
            self.assertEqual(set(endpoints), set(by_service) - {'manager', 'attacks', 'console'})
            manager = service_pod(render(environment, by_service['manager']), 'manager')
            args = manager['containers'][0]['args']
            for service, value in endpoints.items():
                with self.subTest(environment=environment['environment'], service=service):
                    docs = render(environment, by_service[service])
                    svc = next(d for d in docs if d['kind'] == 'Service')
                    port = next(p['port'] for p in svc['spec']['ports'] if p['name'] == 'grpc')
                    self.assertEqual(value['endpoint'], f"{svc['metadata']['name']}:{port}")
                    self.assertIn(f"--{service}-endpoint={value['endpoint']}", args)



    def test_the_console_reaches_the_attacks_services_http_port(self):
        by_service = {e['service']: e for e in ELEMENTS}
        for environment in ENVIRONMENTS_LISTED:
            services = load(ENVIRONMENTS / environment['environment'] / 'phorvex.yaml')['phorvex']['services']
            endpoint = services.get('attacks', {}).get('endpoint')
            docs = render(environment, by_service['attacks'])
            with self.subTest(environment=environment['environment']):
                if not endpoint:
                    # The console serves the attack routes itself, and no attacks service runs.
                    self.assertEqual([d for d in docs if d['kind'] == 'Deployment'], [])
                    continue
                svc = next(d for d in docs if d['kind'] == 'Service')
                port = next(p['port'] for p in svc['spec']['ports'] if p['name'] == 'http')
                self.assertEqual(endpoint, f"{svc['metadata']['name']}:{port}")
                # The console chart deploys the console where it is separate, the manager chart elsewhere.
                rendered = render(environment, by_service['manager']) + render(environment, by_service['console'])
                console = next(d for d in rendered if d['kind'] == 'Deployment' and d['metadata']['name'].endswith('-console'))
                env = {e['name']: e.get('value') for e in console['spec']['template']['spec']['containers'][0]['env']}
                self.assertEqual(env['PHORVEX_CONSOLE_ATTACKS_URL'], 'http://' + endpoint)

    def test_the_audit_history_fits_its_volume(self):
        # A full volume stops the decision history: the manager keeps deciding, but
        # records nothing the console or an investigation can read. Whole records can
        # overrun a segment, so the nominal budget gets at most half the volume.
        units = {'Ki': 2**10, 'Mi': 2**20, 'Gi': 2**30, 'Ti': 2**40}
        by_service = {e['service']: e for e in ELEMENTS}
        for environment in ENVIRONMENTS_LISTED:
            docs = render(environment, by_service['manager'])
            args = service_pod(docs, 'manager')['containers'][0]['args']
            flags = dict(a[2:].split('=', 1) for a in args if a.startswith('--audit-max-'))
            volume = next((d for d in docs if d['kind'] == 'PersistentVolumeClaim' and d['metadata']['name'].endswith('-audit')), None)
            if volume is None:
                continue
            with self.subTest(environment=environment['environment']):
                size = volume['spec']['resources']['requests']['storage']
                capacity = int(size[:-2]) * units[size[-2:]]
                segment = int(flags['audit-max-bytes'])
                self.assertGreater(segment, 0, 'an unbounded audit fills any volume')
                self.assertLessEqual(segment * (int(flags['audit-max-backups']) + 1), capacity // 2, size)

    def test_an_end_to_end_identity_reaches_only_its_environment(self):
        # Its tokens are console credentials, never Kubernetes ones. The audience is the
        # environment's own, so another console's e2e token is refused, and the grant is
        # the namespaces the environment attacks.
        production = load(ROOT / 'deploy/helm/phorvex-stack/values-eks.yaml')['phorvex']['phorvex']['console']['auth']['oidc']
        by_service = {e['service']: e for e in ELEMENTS}
        for environment in ENVIRONMENTS_LISTED:
            console = load(ENVIRONMENTS / environment['environment'] / 'phorvex.yaml')['phorvex']['console']
            auth = console.get('auth', {})
            if not auth.get('e2eIdentity', {}).get('enabled'):
                continue
            with self.subTest(environment=environment['environment']):
                namespace, name = environment['namespace'], environment['release'] + '-phorvex-console-e2e'
                self.assertNotEqual(auth['oidc']['audience'], production['audience'])
                subjects = [s for s in json.loads(auth['grants']['data'])['subjects']
                            if s['subject'] == f'system:serviceaccount:{namespace}:{name}']
                self.assertEqual([(s['issuer'], s['tenants'], s['targets']) for s in subjects],
                                 [(auth['oidc']['issuer'], console['attackNamespaces'], ['default'])])
                rendered = {service: render(environment, element) for service, element in by_service.items()}
                account = next(d for docs in rendered.values() for d in docs if d['kind'] == 'ServiceAccount' and d['metadata']['name'] == name)
                self.assertIs(account['automountServiceAccountToken'], False)
                for service, docs in rendered.items():
                    for d in docs:
                        if d['kind'] in ('RoleBinding', 'ClusterRoleBinding'):
                            self.assertNotIn(name, [s['name'] for s in d.get('subjects') or []], (service, d['metadata']['name']))
                # The console and the attacks service both verify its tokens.
                consoles = [d for docs in rendered.values() for d in docs if d['kind'] == 'Deployment'
                            and d['metadata']['name'] in (environment['release'] + '-phorvex-console', environment['release'] + '-attacks')]
                self.assertEqual(len(consoles), 2)
                for console in consoles:
                    env = {e['name']: e.get('value') for e in console['spec']['template']['spec']['containers'][0]['env']}
                    self.assertEqual(env['PHORVEX_CONSOLE_OIDC_AUDIENCE'], auth['oidc']['audience'], console['metadata']['name'])

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
                # Its own namespaces only, and never the one the services run in: the
                # actuator refuses to quarantine there.
                scope = values['policyNamespaces']
                self.assertTrue(scope)
                for policy_namespace in scope:
                    self.assertTrue(policy_namespace.startswith(namespace + '-'), policy_namespace)
                # It acts, if at all, with its own hands in its own namespaces.
                acts = not values['globalKillSwitch']
                if acts:
                    self.assertEqual(values['actuator'], 'native')
                    self.assertTrue(values['actuatorNamespaces'])
                    for actuator_namespace in values['actuatorNamespaces']:
                        self.assertTrue(actuator_namespace.startswith(namespace + '-'), actuator_namespace)
                self.assertIs(values['admissionWebhook']['enabled'], False)
                self.assertIs(values['eventIdentityPolicy']['enabled'], False)
                for service, element in by_service.items():
                    docs = render(environment, element)
                    for d in docs:
                        if d['kind'] in CLUSTER_SCOPED:
                            self.assertTrue(d['metadata']['name'].startswith(release + '-'), (service, d['kind'], d['metadata']['name']))
                    if service in ('manager', 'sensor', 'actuator'):
                        pod = service_pod(docs, service)
                        args = pod['containers'][0]['args']
                        self.assertIn(f"--policy-namespaces={','.join(scope)}", args, service)
                        if service == 'manager':
                            self.assertEqual('--global-kill-switch=true' in args, not acts)



DEMO = load(SERVICES / 'demo-staging.yaml')


def demo_manifests():
    return [d for f in sorted((ROOT / DEMO['spec']['source']['path']).glob('*.yaml')) for d in yaml.safe_load_all(f.read_text()) if d]


class DemoTests(unittest.TestCase):
    """The workload staging's services defend (deploy/demo)."""
    staging = next(e for e in ENVIRONMENTS_LISTED if e['environment'] == 'staging')

    def test_it_deploys_into_the_environment_only(self):
        spec = DEMO['spec']
        self.assertEqual(spec['project'], PROJECT['metadata']['name'])
        self.assertEqual(spec['source']['repoURL'], REPO)
        # Its own namespace, beside the services' and never theirs.
        self.assertEqual(spec['destination'], {'server': self.staging['server'], 'namespace': self.staging['namespace'] + '-demo'})
        self.assertIn('CreateNamespace=true', spec['syncPolicy']['syncOptions'])
        for d in demo_manifests():
            # Argo CD places every object in the destination; none is cluster-scoped.
            self.assertNotIn('namespace', d['metadata'], d['metadata']['name'])
            self.assertNotIn(d['kind'], CLUSTER_SCOPED)

    def test_the_policy_defends_only_the_demo_with_the_native_backend(self):
        docs = demo_manifests()
        policy = next(d for d in docs if d['kind'] == 'PhorvexPolicy')['spec']
        workloads = {d['metadata']['name']: d['spec']['template']['metadata']['labels'] for d in docs if d['kind'] == 'Deployment'}
        selector = policy['selector']['matchLabels'].items()
        self.assertLessEqual(selector, workloads['demo-api'].items())
        # The console's workload attack picks a rotation target before any other Pod;
        # the load generator is neither a target nor defended.
        self.assertEqual(workloads['demo-api']['r6th.io/rotation-target'], 'true')
        self.assertNotIn('r6th.io/rotation-target', workloads['demo-load'])
        self.assertFalse(selector <= workloads['demo-load'].items())
        self.assertLessEqual(set(policy['actions']['enabled']), {'rotate', 'quarantine'})
        # One namespace is the demo's tenant, the services' scope, their hands, the
        # attacks' targets and every console grant.
        namespace = DEMO['spec']['destination']['namespace']
        self.assertEqual(policy['tenant'], namespace)
        env = load(ENVIRONMENTS / 'staging' / 'phorvex.yaml')['phorvex']
        self.assertEqual(env['actuator'], 'native')
        for scope in (env['policyNamespaces'], env['actuatorNamespaces'], env['console']['attackNamespaces']):
            self.assertEqual(scope, [namespace])
        for subject in json.loads(env['console']['auth']['grants']['data'])['subjects']:
            self.assertEqual(subject['tenants'], [namespace], subject['subject'])

    def test_its_load_is_measured(self):
        # Without a per-Pod http_requests_total the brain prices every rotation at its
        # conservative bound, above the policy's cost ceiling (cost/action_flow.go).
        docs = demo_manifests()
        monitor = next(d for d in docs if d['kind'] == 'PodMonitor')['spec']
        api = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == 'demo-api')['spec']['template']
        self.assertLessEqual(monitor['selector']['matchLabels'].items(), api['metadata']['labels'].items())
        endpoint = monitor['podMetricsEndpoints'][0]
        ports = {p['name'] for c in api['spec']['containers'] for p in c.get('ports', [])}
        self.assertIn(endpoint['port'], ports)
        renamed = [r for r in endpoint['metricRelabelings'] if r['action'] == 'replace' and r['targetLabel'] == '__name__']
        self.assertEqual([r['replacement'] for r in renamed], ['http_requests_total'])


if __name__ == '__main__':
    unittest.main()
