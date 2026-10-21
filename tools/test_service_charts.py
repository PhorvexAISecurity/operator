"""Render the per-service charts (ADR-0001) and check what each may do."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
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
        self.assertIn('--gpu-envelope-max=0.2925', container['args'])
        self.assertFalse([a for a in container['args'] if a.startswith(('--math-lab', '--engine', '--flow-residual-classes'))])
        self.assertNotIn('volumes', pod)

    def test_math_lab_capture_gets_a_volume(self):
        pod = by_kind(render('phorvex-brain', 'phorvex.mathLab.capturePolicies={vllm/defense}', 'mathLabStore.existingClaim=brain-math-lab'))['Deployment'][0]['spec']['template']['spec']
        args = pod['containers'][0]['args']
        self.assertIn('--math-lab-capture-policies=vllm/defense', args)
        self.assertIn('--math-lab-capture-dir=/var/lib/phorvex/math-lab', args)
        self.assertIn('--math-lab-capture-max-bytes=1073741824', args)
        self.assertEqual(pod['volumes'], [{'name': 'math-lab', 'persistentVolumeClaim': {'claimName': 'brain-math-lab'}}])

    def decision_flags(self, chart, container, *sets):
        args = [HELM, 'template', 'phorvex', str(chart), '-n', 'phorvex-system']
        for value in sets:
            args += ['--set', value]
        docs = [d for d in yaml.safe_load_all(subprocess.run(args, check=True, capture_output=True, text=True).stdout) if d]
        pod = next(d['spec']['template']['spec'] for d in docs if d['kind'] == 'Deployment'
                   and container in [c['name'] for c in d['spec']['template']['spec']['containers']])
        args = next(c for c in pod['containers'] if c['name'] == container)['args']
        return sorted(a for a in args if a.startswith(('--engine=', '--gpu-envelope-max=', '--flow-residual-classes=')))

    def test_the_brain_decides_as_the_manager_configures_it(self):
        manager = ROOT / 'phorvex/charts/phorvex'
        for sets in ([], ['phorvex.gpuEnvelopeMax=0.5', 'phorvex.flowResidualClasses={vllm,voice}']):
            with self.subTest(values=sets):
                want = self.decision_flags(manager, 'manager', *sets)
                self.assertTrue(want)
                self.assertEqual(self.decision_flags(CHARTS / 'phorvex-brain', 'brain', *sets), want)

    def test_the_brain_defaults_are_the_managers(self):
        manager = yaml.safe_load((ROOT / 'phorvex/charts/phorvex/values.yaml').read_text())['phorvex']
        brain = yaml.safe_load((CHARTS / 'phorvex-brain/values.yaml').read_text())['phorvex']
        self.assertEqual(brain['gpuEnvelopeMax'], manager['gpuEnvelopeMax'])
        self.assertEqual(brain['flowResidualClasses'], manager['flowResidualClasses'])
        for key in ('capturePolicies', 'captureMaxBytes'):
            self.assertEqual(brain['mathLab'][key], manager['mathLab'][key], key)

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


MANAGER_CHART = ROOT / 'phorvex/charts/phorvex'
MANAGER_VALUES = MANAGER_CHART / 'values.yaml'
ALL_FEATURES = ROOT / 'tools/testdata/charts/rbac-all-features.yaml'
PROBE = ROOT / 'tools/testdata/charts/rbac-probe'
LIBRARY = CHARTS / 'phorvex-common'
MANAGER_SA = {'kind': 'ServiceAccount', 'name': 'phorvex-phorvex-manager', 'namespace': 'phorvex-system'}
READS = {'get', 'list', 'watch'}
VALUE_SETS = {'defaults': [], 'all features': ['-f', str(ALL_FEATURES)]}


def helm_template(chart, *args):
    out = subprocess.run([HELM, 'template', 'phorvex', str(chart), '-n', 'phorvex-system', *args],
                         check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def rbac_key(d):
    return (d['kind'], d['metadata'].get('namespace'), d['metadata']['name'])


def manager_rbac(values):
    """The RBAC bound to the manager's ServiceAccount, as the manager chart renders it today."""
    docs = helm_template(MANAGER_CHART, *values)
    bindings = [d for d in docs if d['kind'] in ('RoleBinding', 'ClusterRoleBinding') and MANAGER_SA in d.get('subjects', [])]
    refs = {(b['roleRef']['kind'], b['metadata'].get('namespace') if b['kind'] == 'RoleBinding' else None, b['roleRef']['name'])
            for b in bindings}
    return bindings + [d for d in docs if d['kind'] in ('Role', 'ClusterRole') and rbac_key(d) in refs]


def library_rbac(service, values):
    """One service's share of the library, rendered with the manager chart's values and names."""
    with tempfile.TemporaryDirectory() as tmp:
        chart = Path(tmp) / 'probe'
        shutil.copytree(PROBE, chart)
        for template in (LIBRARY / 'templates').glob('*.tpl'):
            shutil.copy(template, chart / 'templates' / template.name)
        return helm_template(chart, '-f', str(MANAGER_VALUES), *values, '--set', 'service=' + service)


def normal(d):
    m = d['metadata']
    return {'labels': m.get('labels'), 'rules': d.get('rules'), 'roleRef': d.get('roleRef'), 'subjects': d.get('subjects')}


def grants(docs):
    """(namespace, apiGroup, resource, resourceName, verb) for every granted permission."""
    out = set()
    for d in docs:
        if d['kind'] not in ('Role', 'ClusterRole'):
            continue
        namespace = d['metadata'].get('namespace', '*cluster*')
        for rule in d['rules']:
            for group in rule['apiGroups']:
                for resource in rule['resources']:
                    for name in rule.get('resourceNames') or ['*']:
                        for verb in rule['verbs']:
                            out.add((namespace, group, resource, name, verb))
    return out


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class RBACLibraryTests(unittest.TestCase):
    def test_all_mode_renders_the_managers_rbac_unchanged(self):
        for name, values in VALUE_SETS.items():
            with self.subTest(values=name):
                want = {rbac_key(d): normal(d) for d in manager_rbac(values)}
                # Guards the comparison itself: the manager chart's RBAC was found.
                self.assertGreaterEqual(len(want), 30 if values else 6)
                got = {rbac_key(d): normal(d) for d in library_rbac('all', values)}
                self.assertEqual(sorted(got), sorted(want))
                for key in want:
                    self.assertEqual(got[key], want[key], key)

    def test_the_services_together_hold_exactly_the_managers_access(self):
        for name, values in VALUE_SETS.items():
            with self.subTest(values=name):
                manager = grants(manager_rbac(values))
                split = set()
                for service in ('dispatcher', 'sensor', 'actuator'):
                    split |= grants(library_rbac(service, values))
                self.assertEqual(split - manager, set(), 'a split service gained access the manager never had')
                self.assertEqual(manager - split, set(), 'access the manager had is held by no service')

    def test_every_split_role_is_bound(self):
        for service in ('dispatcher', 'sensor', 'actuator'):
            docs = library_rbac(service, VALUE_SETS['all features'])
            roles = {rbac_key(d) for d in docs if d['kind'] in ('Role', 'ClusterRole')}
            bound = {(b['roleRef']['kind'], b['metadata'].get('namespace') if b['kind'] == 'RoleBinding' else None, b['roleRef']['name'])
                     for b in docs if b['kind'] in ('RoleBinding', 'ClusterRoleBinding') and MANAGER_SA in b['subjects']}
            self.assertEqual(roles, bound, service)

    def test_the_sensor_only_reads(self):
        access = grants(library_rbac('sensor', VALUE_SETS['all features']))
        self.assertTrue(access)
        self.assertEqual({g for g in access if g[4] not in READS}, set())
        secrets = {(g[0], g[3]) for g in access if g[2] == 'secrets'}
        self.assertEqual(secrets, {('litellm', 'phorvex-litellm-output-document'), ('litellm', 'phorvex-litellm-output-prompt')})

    def test_workload_writes_stay_with_the_actuator(self):
        dispatcher = grants(library_rbac('dispatcher', VALUE_SETS['all features']))
        actuator = grants(library_rbac('actuator', VALUE_SETS['all features']))
        workload = {('pods', 'delete'), ('pods', 'update'), ('pods', 'patch'), ('pods/eviction', 'create'), ('pods/exec', 'create'),
                    ('networkpolicies', 'create'), ('services', 'update'), ('securityevents', 'create'),
                    ('adaptivemovingtargetdefenses', 'update')}
        self.assertEqual({(g[2], g[4]) for g in dispatcher} & workload, set())
        self.assertEqual({(g[2], g[4]) for g in actuator} & workload, workload)
        self.assertEqual({g for g in dispatcher if g[2] == 'secrets'}, set(), 'the dispatcher reads no Secret')

    def test_policy_status_and_leadership_stay_with_the_dispatcher(self):
        dispatcher = {(g[2], g[4]) for g in grants(library_rbac('dispatcher', VALUE_SETS['all features']))}
        actuator = {(g[2], g[4]) for g in grants(library_rbac('actuator', VALUE_SETS['all features']))}
        own = {('phorvexpolicies/status', 'update'), ('phorvexpolicies/finalizers', 'update'), ('events', 'create'), ('leases', 'create')}
        self.assertEqual(dispatcher & own, own)
        self.assertEqual(actuator & own, set())


if __name__ == '__main__':
    unittest.main()
