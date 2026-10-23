"""Render the per-service charts (ADR-0001) and check what each may do."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tarfile
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
VALUE_SETS = {'defaults': [], 'all features': ['-f', str(ALL_FEATURES)],
              # The native backend drives no Phoenix, so it creates no SecurityEvent or AMTD.
              'native': ['--set', 'phorvex.actuator=native']}


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
                self.assertGreaterEqual(len(want), 30 if name == 'all features' else 6)
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



FEATURES = ROOT / 'tools/testdata/charts'
# Every value that changes a split service's flags, merged over the access features.
SERVICE_FEATURES = ['-f', str(ALL_FEATURES), '-f', str(FEATURES / 'sensor-features.yaml'), '-f', str(FEATURES / 'actuator-features.yaml')]
PODMONITOR = ['--api-versions', 'monitoring.coreos.com/v1/PodMonitor']
LEASE_FLAGS = {'endpoint-lease-approved-source-sha256', 'endpoint-lease-approved-proxy-image', 'endpoint-lease-approved-engine-image'}
LEASE_ENV = {'PHORVEX_' + f.upper().replace('-', '_') for f in LEASE_FLAGS}
# The trust both charts pass as the environment its flags default from.
TRUST_ENV_FLAGS = LEASE_FLAGS | {'injector-identity'}
TRUST_ENV = {'PHORVEX_' + f.upper().replace('-', '_') for f in TRUST_ENV_FLAGS}
# The service's own listener, probes and shutdown, not the manager's.
OWN_FLAGS = {'listen', 'metrics-bind-address', 'health-probe-bind-address', 'shutdown-grace'}


def source_names(*paths):
    """The flags and environment variables a Go configuration registers, read from its source."""
    flags, env = set(), set()
    for path in paths:
        text = (ROOT / 'phorvex' / path).read_text()
        flags |= set(re.findall(r'(?:fs|flag(?:\.CommandLine)?)\.\w+Var\(&[^,]+, "([a-z0-9-]+)"', text))
        env |= set(re.findall(r'os\.(?:Getenv|LookupEnv)\("([A-Z0-9_]+)"\)', text))
        env |= set(re.findall(r'EnvVar = "([A-Z0-9_]+)"', text))
    return flags - OWN_FLAGS, env


def reading(docs, container, flags, env, volumes):
    """What a container reads of its configuration: the named flags and environment, and the files the named volumes mount."""
    pod = next(d['spec']['template']['spec'] for d in docs
               if d['kind'] == 'Deployment' and container in [c['name'] for c in d['spec']['template']['spec']['containers']])
    c = next(c for c in pod['containers'] if c['name'] == container)
    config_maps = {d['metadata']['name']: d.get('data') for d in docs if d['kind'] == 'ConfigMap'}
    sources = {v['name']: v for v in pod.get('volumes', [])}
    files = {}
    for mount in c.get('volumeMounts', []):
        if mount['name'] not in volumes:
            continue
        volume = sources[mount['name']]
        if 'configMap' in volume:
            # Compared by content: each chart names its own ConfigMap. None is one no chart renders.
            source = {'items': volume['configMap'].get('items'), 'data': config_maps.get(volume['configMap']['name'])}
        else:
            source = {k: v for k, v in volume.items() if k != 'name'}
        files[mount['mountPath']] = {'subPath': mount.get('subPath'), 'readOnly': mount.get('readOnly'), 'source': source}
    return {'flags': dict(a[2:].split('=', 1) for a in c['args'] if '=' in a and a[2:].split('=', 1)[0] in flags),
            'env': [e for e in c.get('env', []) if e['name'] in env],
            'files': files}


def leaves(tree, path=()):
    for key, value in tree.items():
        if isinstance(value, dict) and value:
            yield from leaves(value, path + (key,))
        else:
            yield path + (key,), value


class SplitServiceChart:
    """What every split service chart must hold; a subclass names the service."""
    service = sources = volumes = expected_env = None
    # Flags whose value both charts pass as the environment the flag defaults from.
    env_flags = TRUST_ENV_FLAGS

    @property
    def chart(self):
        return CHARTS / ('phorvex-' + self.service)

    @property
    def account(self):
        return {'kind': 'ServiceAccount', 'name': 'phorvex-' + self.service, 'namespace': 'phorvex-system'}

    def read(self, docs, container):
        flags, env = source_names(*self.sources)
        return reading(docs, container, flags, env, self.volumes)

    def test_it_reads_as_the_manager_configures_it(self):
        flags, env = source_names(*self.sources)
        # Guards the source scan the comparison relies on.
        self.assertGreaterEqual(len(flags), 10)
        self.assertIn('POD_NAMESPACE', env)
        for name, values in {'defaults': [], 'all features': SERVICE_FEATURES}.items():
            with self.subTest(values=name):
                manager = self.read(helm_template(MANAGER_CHART, *PODMONITOR, *values), 'manager')
                self.assertEqual(self.read(helm_template(self.chart, *values), self.service), manager)
        # The fixture reaches every flag, environment variable and file.
        got = self.read(helm_template(self.chart, *SERVICE_FEATURES), self.service)
        self.assertEqual(flags - set(got['flags']), self.env_flags)
        self.assertEqual({e['name'] for e in got['env']}, self.expected_env)
        self.assertEqual(len(got['files']), len(self.volumes))

    def test_its_defaults_are_the_managers(self):
        manager = yaml.safe_load(MANAGER_VALUES.read_text())['phorvex']
        for path, value in leaves(yaml.safe_load((self.chart / 'values.yaml').read_text())['phorvex']):
            want = manager
            for key in path:
                want = want[key]
            self.assertEqual(value, want, '.'.join(path))

    def test_it_holds_exactly_its_share_of_the_access(self):
        for name, values in VALUE_SETS.items():
            with self.subTest(values=name):
                docs = helm_template(self.chart, *values)
                self.assertEqual(grants(docs), grants(library_rbac(self.service, values)))
                roles = {rbac_key(d) for d in docs if d['kind'] in ('Role', 'ClusterRole')}
                bindings = [d for d in docs if d['kind'] in ('RoleBinding', 'ClusterRoleBinding')]
                self.assertEqual({(b['roleRef']['kind'], b['metadata'].get('namespace') if b['kind'] == 'RoleBinding' else None, b['roleRef']['name'])
                                  for b in bindings}, roles)
                for b in bindings:
                    self.assertEqual(b['subjects'], [self.account])

    def test_one_replica_runs_hardened(self):
        deployment = by_kind(helm_template(self.chart))['Deployment'][0]
        self.assertEqual(deployment['spec']['replicas'], 1)
        self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
        pod = deployment['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], self.account['name'])
        self.assertIs(pod['automountServiceAccountToken'], True)
        self.assertIs(pod['securityContext']['runAsNonRoot'], True)
        container = pod['containers'][0]
        self.assertEqual(container['image'], f'phorvex-{self.service}:0.1.0')
        self.assertEqual(container['securityContext'],
                         {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}})
        self.assertNotIn('volumes', pod)

    def test_only_the_manager_reaches_it(self):
        policy = by_kind(helm_template(self.chart, '--set', 'metricsScraperNamespaces={monitoring}'))['NetworkPolicy'][0]['spec']
        self.assertEqual(policy['policyTypes'], ['Ingress'])
        grpc, health, metrics = policy['ingress']
        self.assertEqual(grpc['ports'], [{'port': 'grpc'}])
        self.assertEqual(grpc['from'], [{
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'phorvex-system'}},
            'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'phorvex', 'app.kubernetes.io/component': 'manager'}}}])
        self.assertEqual(health, {'ports': [{'port': 'health'}]})
        self.assertEqual(metrics['from'], [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'monitoring'}}}])

    def test_the_cpu_fixture_detector_is_trusted_by_the_managers_name(self):
        # The manager chart renders this fixture only with the console; the name is its e2e-detector-cpu ServiceAccount.
        got = self.read(helm_template(self.chart, '--set', 'phorvex.console.podBoundTokenCPU.enabled=true'), self.service)
        self.assertEqual(got['flags']['trusted-detectors'].split(',')[-1], 'phorvex-system/phorvex-phorvex-e2e-detector-cpu')
        renamed = self.read(helm_template(self.chart, '--set', 'phorvex.e2eDetector.enabled=true', '--set', 'managerFullname=stack-phorvex'), self.service)
        self.assertEqual(renamed['flags']['trusted-detectors'].split(',')[-1], 'phorvex-system/stack-phorvex-e2e-detector')


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class SensorChartTests(SplitServiceChart, unittest.TestCase):
    service = 'sensor'
    sources = ['cmd/internal/sensorconfig/sensorconfig.go', 'cmd/internal/trustconfig/trustconfig.go', 'cmd/internal/policyscope/policyscope.go']
    volumes = {'epss'}
    expected_env = {'POD_NAMESPACE', 'PHORVEX_EVENT_IDENTITY_POLICY'} | TRUST_ENV
    # The sensor verifies the creator-identity guard another release installs.
    env_flags = TRUST_ENV_FLAGS | {'event-identity-policy'}

    def test_the_sensor_only_reads(self):
        access = grants(helm_template(self.chart, *VALUE_SETS['all features']))
        self.assertTrue(access)
        self.assertEqual({g for g in access if g[4] not in READS}, set())


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ActuatorChartTests(SplitServiceChart, unittest.TestCase):
    service = 'actuator'
    sources = ['cmd/actuator/main.go', 'cmd/internal/actuatorconfig/actuatorconfig.go', 'cmd/internal/trustconfig/trustconfig.go',
               'cmd/internal/policyscope/policyscope.go', 'internal/actuator/backend.go']
    volumes = {'litellm-client-revoke-status', 'lora-clean-sources', 'mig-profiles', 'serving-security'}
    expected_env = {'POD_NAMESPACE', 'PHORVEX_ACTUATOR', 'PHORVEX_VOICE_ADMISSION_ENABLED', 'PHORVEX_VOICE_MCP_APPROVED_IMAGE'} | TRUST_ENV
    env_flags = TRUST_ENV_FLAGS | {'voice-mcp-approved-image'}

    def test_the_actuator_holds_the_workload_writes(self):
        access = {(g[2], g[4]) for g in grants(helm_template(self.chart, *VALUE_SETS['all features']))}
        self.assertTrue({('pods', 'delete'), ('pods/eviction', 'create'), ('pods/exec', 'create'), ('networkpolicies', 'create'),
                         ('securityevents', 'create'), ('adaptivemovingtargetdefenses', 'update')} <= access)
        self.assertEqual(access & {('phorvexpolicies/status', 'update'), ('leases', 'create'), ('events', 'create')}, set())

    def test_the_actuator_refuses_what_the_manager_refuses(self):
        binding = 'phorvex.servingSecurity.bindings=[{"policyName":"p","namespace":"n","workload":"w","secretName":"s"}]'
        for invalid in (['--set', 'phorvex.maxRetainedQuarantinesPerNamespace=129'],
                        ['--set', 'phorvex.maxRetainedQuarantinesPerNamespace=1.5'],
                        ['--set', 'phorvex.servingSecurity.mode=plaintext'],
                        ['--set-json', binding],
                        ['--set', 'phorvex.servingSecurity.mode=legacy-plaintext', '--set', 'phorvex.actuator=native', '--set-json', binding],
                        ['--set', 'phorvex.actuator=native', '--set', 'phorvex.mig.nodeExec.enabled=true'],
                        ['--set', 'phorvex.actuator=native', '--set', 'phorvex.voiceMCP.enabled=true'],
                        ['--set', 'phorvex.endpointLease.enabled=true', '--set', 'phorvex.actuator=native', '--set', 'phorvex.endpointLease.approvedSourceSHA256=abc']):
            with self.subTest(values=invalid):
                for chart in (MANAGER_CHART, self.chart):
                    result = subprocess.run([HELM, 'template', 'phorvex', str(chart), '-n', 'phorvex-system', *invalid], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, chart.name)


REMOTE = ['--set', 'phorvex.services.brain.endpoint=phorvex-brain:9090', '--set', 'phorvex.services.sensor.endpoint=phorvex-sensor:9090',
          '--set', 'phorvex.services.actuator.endpoint=phorvex-actuator:9090']
# Code-exec admission admits only the manager's identity, so it needs the in-process actuator.
WITHOUT_CODE_EXEC = ['--set', 'phorvex.codeExecAdmission.enabled=false']
SPLIT_VALUE_SETS = {name: [*values, *WITHOUT_CODE_EXEC] for name, values in VALUE_SETS.items()}
SPLIT_FEATURES = [*SERVICE_FEATURES, *WITHOUT_CODE_EXEC]
ACTUATOR_VOLUMES = ActuatorChartTests.volumes
ACTUATOR_FILE_FLAGS = ('--lora-clean-sources-file=', '--mig-profiles-file=', '--serving-security-file=', '--mig-')


def manager_pod(docs):
    return next(d['spec']['template']['spec'] for d in docs
                if d['kind'] == 'Deployment' and 'manager' in [c['name'] for c in d['spec']['template']['spec']['containers']])


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ManagerRemoteModeTests(unittest.TestCase):
    def test_the_manager_acts_in_process_by_default(self):
        args = manager_pod(helm_template(MANAGER_CHART))['containers'][0]['args']
        self.assertEqual([a for a in args if a.split('=')[0] in ('--brain-endpoint', '--sensor-endpoint', '--actuator-endpoint')], [])

    def test_the_manager_reaches_each_remote_service(self):
        args = manager_pod(helm_template(MANAGER_CHART, *REMOTE))['containers'][0]['args']
        for flag in ('--brain-endpoint=phorvex-brain:9090', '--sensor-endpoint=phorvex-sensor:9090', '--actuator-endpoint=phorvex-actuator:9090'):
            self.assertIn(flag, args)

    def test_a_remote_actuator_leaves_the_manager_the_dispatchers_share(self):
        for name, values in SPLIT_VALUE_SETS.items():
            with self.subTest(values=name):
                remote = manager_rbac([*values, *REMOTE])
                share = library_rbac('dispatcher', values)
                self.assertEqual({rbac_key(d) for d in remote}, {rbac_key(d) for d in share})
                self.assertEqual(grants(remote), grants(share))
                self.assertEqual({g for g in grants(remote) if g[2] == 'secrets'}, set(), 'the dispatcher reads no Secret')

    def test_the_split_services_together_hold_exactly_the_in_process_access(self):
        for name, values in SPLIT_VALUE_SETS.items():
            with self.subTest(values=name):
                split = grants(manager_rbac([*values, *REMOTE]))
                for service in ('sensor', 'actuator'):
                    split |= grants(helm_template(CHARTS / ('phorvex-' + service), *values))
                self.assertEqual(split, grants(manager_rbac(values)))

    def test_a_remote_actuator_reads_its_own_files_and_credentials(self):
        docs = helm_template(MANAGER_CHART, *PODMONITOR, *SPLIT_FEATURES, *REMOTE)
        pod = manager_pod(docs)
        self.assertEqual({v['name'] for v in pod.get('volumes', [])} & ACTUATOR_VOLUMES, set())
        self.assertEqual([a for a in pod['containers'][0]['args'] if a.startswith(ACTUATOR_FILE_FLAGS)], [])
        self.assertEqual([d['metadata']['name'] for d in docs if d['kind'] == 'ConfigMap'
                          and d['metadata']['name'].endswith(('-lora-clean-sources', '-mig-profiles', '-serving-security'))], [])
        # In process the same values mount every one of them.
        in_process = manager_pod(helm_template(MANAGER_CHART, *PODMONITOR, *SPLIT_FEATURES))
        self.assertLessEqual(ACTUATOR_VOLUMES, {v['name'] for v in in_process['volumes']})

    def test_the_remote_manager_shares_the_services_handshake_configuration(self):
        handshake = {'trusted-detectors', 'trusted-loss-observers', 'trusted-current-inventory-observers', 'operator-namespace', 'policy-namespaces'}
        manager = reading(helm_template(MANAGER_CHART, *PODMONITOR, *SPLIT_FEATURES, *REMOTE), 'manager', handshake, TRUST_ENV | {'POD_NAMESPACE'}, set())
        self.assertEqual(len(manager['flags']), len(handshake))
        for service in ('sensor', 'actuator'):
            got = reading(helm_template(CHARTS / ('phorvex-' + service), *SPLIT_FEATURES), service, handshake, TRUST_ENV | {'POD_NAMESPACE'}, set())
            self.assertEqual({k: v for k, v in manager['flags'].items() if k in got['flags']}, got['flags'], service)
            self.assertEqual(manager['env'], got['env'], service)

    def test_a_remote_brain_records_the_math_lab(self):
        capture = ['--set', 'phorvex.audit.enabled=true', '--set', 'phorvex.mathLab.capturePolicies={vllm/vllm-defense}']
        in_process = manager_pod(helm_template(MANAGER_CHART, *capture))['containers'][0]['args']
        self.assertIn('--math-lab-capture-policies=vllm/vllm-defense', in_process)
        # The manager refuses capture flags with --brain-endpoint; the brain records instead.
        remote = manager_pod(helm_template(MANAGER_CHART, *capture, *REMOTE))['containers'][0]['args']
        self.assertEqual([a for a in remote if a.startswith('--math-lab')], [])
        brain = by_kind(helm_template(CHARTS / 'phorvex-brain', *capture))['Deployment'][0]['spec']['template']['spec']['containers'][0]['args']
        self.assertIn('--math-lab-capture-policies=vllm/vllm-defense', brain)

    def test_code_exec_admission_needs_the_in_process_actuator(self):
        result = subprocess.run([HELM, 'template', 'phorvex', str(MANAGER_CHART), '-n', 'phorvex-system',
                                 '--set', 'phorvex.codeExecAdmission.enabled=true', *REMOTE], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires the in-process actuator', result.stderr)

    def test_the_manager_outlasts_its_wait_for_the_services(self):
        # Startup waits for each remote service in turn before /healthz answers, and
        # liveness starts only once the startup probe passes.
        source = (ROOT / 'phorvex/cmd/main.go').read_text()
        waits = re.findall(r'"(?:brain|sensor|actuator)-connect-timeout", (\d+)\*time\.Minute', source)
        self.assertEqual(len(waits), 3)
        probe = manager_pod(helm_template(MANAGER_CHART, *REMOTE))['containers'][0]['startupProbe']
        self.assertGreater(probe['periodSeconds'] * probe['failureThreshold'], 60 * sum(map(int, waits)))


def containers(docs):
    for d in docs:
        spec = d.get('spec', {})
        spec = spec.get('jobTemplate', {}).get('spec', spec)
        yield from spec.get('template', {}).get('spec', {}).get('containers', [])


# The console renders only with its audit transport configured.
CONSOLE = ['--set', 'phorvex.console.enabled=true', '--set', 'phorvex.audit.enabled=true',
           '--set', 'phorvex.console.auditTransport.serverSecretName=audit-server',
           '--set', 'phorvex.console.auditTransport.clientSecretName=audit-client',
           '--set', 'phorvex.console.auditTransport.clientDNSName=console.example',
           '--set', 'phorvex.console.auditTransport.serverDNSName=phorvex-phorvex-audit-source.phorvex-system.svc']


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ImageDigestTests(unittest.TestCase):
    """The release pins each service image by the digest it pushed (docs/services/releasing.md)."""

    def test_a_service_runs_exactly_the_released_image(self):
        digest = 'sha256:' + 'a' * 64
        for service in ('brain', 'sensor', 'actuator'):
            with self.subTest(service=service):
                chart = CHARTS / ('phorvex-' + service)
                pod = by_kind(helm_template(chart, '--set', 'image.repository=registry.example/phorvex/' + service,
                                            '--set', 'image.tag=0.1.0', '--set', 'image.digest=' + digest))['Deployment'][0]
                image = pod['spec']['template']['spec']['containers'][0]['image']
                self.assertEqual(image, f'registry.example/phorvex/{service}:0.1.0@{digest}')
                result = subprocess.run([HELM, 'template', 'phorvex', str(chart), '-n', 'phorvex-system', '--set', 'image.digest=latest'],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('image.digest must be sha256', result.stderr)

    def test_every_manager_image_is_the_released_one(self):
        digest = 'sha256:' + 'a' * 64
        pinned = 'registry.example/phorvex/manager:0.6.0@' + digest
        docs = helm_template(MANAGER_CHART, '-f', str(ALL_FEATURES), '--set', 'phorvex.image.repository=registry.example/phorvex/manager',
                             '--set', 'phorvex.image.tag=0.6.0', '--set', 'phorvex.image.releaseDigest=' + digest)
        images = [c['image'] for c in containers(docs) if c['image'].startswith('registry.example/phorvex/manager')]
        self.assertGreater(len(images), 1)
        self.assertEqual(set(images), {pinned})
        env = {e['name']: e.get('value') for c in containers(docs) for e in c.get('env', [])}
        self.assertEqual(env['PHORVEX_BRAIN_IMAGE'], pinned)

    def test_the_console_runs_exactly_the_released_image(self):
        digest = 'sha256:' + 'b' * 64
        docs = helm_template(MANAGER_CHART, *CONSOLE, '--set', 'phorvex.console.image.repository=registry.example/phorvex/console',
                             '--set', 'phorvex.console.image.tag=0.6.0', '--set', 'phorvex.console.image.releaseDigest=' + digest)
        self.assertIn('registry.example/phorvex/console:0.6.0@' + digest, [c['image'] for c in containers(docs)])

    def test_a_release_digest_must_be_a_digest(self):
        for key in ('phorvex.image.releaseDigest', 'phorvex.console.image.releaseDigest'):
            with self.subTest(key=key):
                result = subprocess.run([HELM, 'template', 'phorvex', str(MANAGER_CHART), '-n', 'phorvex-system', *CONSOLE,
                                         '--set', key + '=latest'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key + ' must be sha256', result.stderr)


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class InjectorTests(unittest.TestCase):
    """The console creates the workload live arms' events as the identity the services admit."""

    def test_the_console_and_the_manager_name_one_injector(self):
        docs = helm_template(MANAGER_CHART, *CONSOLE, '--set', 'phorvex.injectorIdentity=fixture/injector')
        env = {c['name']: {e['name']: e.get('value') for e in c.get('env', [])} for c in containers(docs)}
        for container in ('manager', 'console'):
            self.assertEqual(env[container].get('PHORVEX_INJECTOR_IDENTITY'), 'fixture/injector', container)
        # The default sets nothing, so an image older than the setting runs unchanged.
        default = helm_template(MANAGER_CHART, *CONSOLE)
        self.assertEqual([e for c in containers(default) for e in c.get('env', []) if e['name'] == 'PHORVEX_INJECTOR_IDENTITY'], [])


def account_grants(docs, namespace, name):
    """(scope, apiGroup, resource, resourceName, verb) the ServiceAccount namespace/name holds."""
    roles = {(d['kind'], d['metadata'].get('namespace'), d['metadata']['name']): d for d in docs if d['kind'] in ('Role', 'ClusterRole')}
    out = set()
    for b in docs:
        if b['kind'] not in ('RoleBinding', 'ClusterRoleBinding') or not any(
                s.get('kind') == 'ServiceAccount' and s.get('name') == name and s.get('namespace') == namespace for s in b.get('subjects') or []):
            continue
        ref = b['roleRef']
        role = roles[(ref['kind'], b['metadata'].get('namespace') if ref['kind'] == 'Role' else None, ref['name'])]
        scope = b['metadata']['namespace'] if b['kind'] == 'RoleBinding' else '*cluster*'
        out |= {(scope,) + g[1:] for g in grants([role])}
    return out


ATTACKS_CHART = CHARTS / 'phorvex-attacks'
ATTACKS_REMOTE = ['--set', 'phorvex.services.attacks.endpoint=phorvex-attacks:8090']
STACK = [HELM, 'template', 'phorvex', str(ROOT / 'deploy/helm/phorvex-stack'), '-n', 'phorvex-system',
         '-f', str(ROOT / 'deploy/helm/phorvex-stack/values.yaml'), '-f', str(ROOT / 'deploy/helm/phorvex-stack/values-eks.yaml'), *PODMONITOR]
CONSOLE_SA, ATTACKS_SA = ('phorvex-system', 'phorvex-phorvex-console'), ('phorvex-system', 'phorvex-attacks')
# Live arms whose reviewed profiles pin the production console as their injector: the
# chart refuses them with the attacks service remote until they are reviewed for it.
CONSOLE_PINNED = ('endpointLease', 'voiceAgencyLive', 'voiceOutputLive', 'voiceMCPLive')
CONSOLE_PINNED_OFF = [a for arm in CONSOLE_PINNED for a in ('--set', f'phorvex.phorvex.console.{arm}.enabled=false')]


def stack(*args):
    """The production stack's render; with the attacks service remote, its account is
    trusted as the injector in place of the console's, as an environment would set it."""
    with tempfile.TemporaryDirectory() as tmp:
        extra = []
        if any('services.attacks.endpoint' in a for a in args):
            eks = yaml.safe_load((ROOT / 'deploy/helm/phorvex-stack/values-eks.yaml').read_text())
            console = 'system:serviceaccount:phorvex-system:phorvex-phorvex-console'
            detectors = [d for d in eks['phorvex']['phorvex']['trustedDetectors'] if d != console]
            trust = Path(tmp) / 'trust.yaml'
            trust.write_text(yaml.safe_dump({'phorvex': {'phorvex': {'trustedDetectors': detectors + ['system:serviceaccount:phorvex-system:phorvex-attacks']}}}))
            extra = ['-f', str(trust)]
        out = subprocess.run([*STACK, *extra, *args], check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def firing(granted):
    """The grants that fire attacks: exec into workloads, change them, and inject or reap events."""
    return {g for g in granted if g[2] == 'pods/exec' or (g[2] in ('pods', 'services') and g[4] in ('update', 'patch', 'delete'))
            or (g[2] == 'securityevents' and g[4] in ('create', 'update', 'patch', 'delete'))}


def container(docs, name):
    return next(c for c in containers(docs) if c['name'] == name)


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class AttacksServiceTests(unittest.TestCase):
    """The attacks service (docs/services/attacks.md) holds what the console fired with."""

    def test_the_attacks_service_holds_the_grants_the_console_fired_with(self):
        cases = {'console': lambda *a: helm_template(MANAGER_CHART, *CONSOLE, *a),
                 # The production stack enables the live arms, and their grants. The arms whose
                 # reviewed profiles pin the production console as their injector stay off.
                 'stack': lambda *a: stack(*CONSOLE_PINNED_OFF, *[x.replace('phorvex.services', 'phorvex.phorvex.services') for x in a])}
        for name, render in cases.items():
            with self.subTest(values=name):
                in_process = account_grants(render(), *CONSOLE_SA)
                remote = render(*ATTACKS_REMOTE)
                console, attacks = account_grants(remote, *CONSOLE_SA), account_grants(remote, *ATTACKS_SA)
                self.assertEqual(console | attacks, in_process)
                self.assertTrue(firing(in_process))
                self.assertEqual(firing(console), set(), 'the console fires nothing once the attacks service does')

    def test_the_attacks_service_mounts_the_grants_its_own_release_renders(self):
        # The pod reads its grants once, at startup. Mounting the manager release's copy let
        # an attacks pod that rolled before the manager synced start on the old grants.
        data = '{"version": 1, "subjects": [{"issuer": "https://issuer.example", "subject": "a"}]}\n'
        with tempfile.TemporaryDirectory() as tmp:
            values = Path(tmp) / 'grants.yaml'
            values.write_text(yaml.safe_dump({'phorvex': {'console': {'auth': {'grants': {'enabled': True, 'create': True, 'data': data}}}}}))
            manager = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE, '-f', str(values))
            attacks = helm_template(ATTACKS_CHART, *CONSOLE, '-f', str(values))
        def mounted(docs, name):
            pod = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == name)['spec']['template']['spec']
            return next(v['configMap']['name'] for v in pod['volumes'] if v['name'] == 'console-grants')
        maps = {d['metadata']['name']: d['data'] for d in manager + attacks if d['kind'] == 'ConfigMap' and 'grants' in d['metadata']['name']}
        self.assertEqual(mounted(manager, 'phorvex-phorvex-console'), 'phorvex-phorvex-console-grants')
        self.assertEqual(mounted(attacks, 'phorvex-attacks'), 'phorvex-attacks-grants')
        self.assertEqual(maps['phorvex-attacks-grants'], maps['phorvex-phorvex-console-grants'])
        self.assertEqual(maps['phorvex-attacks-grants'], {'grants.json': data})

    def test_attack_namespaces_confine_what_the_attacks_service_changes(self):
        docs = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE, '--set', 'phorvex.console.allowWorkloadMutations=true',
                             '--set', 'phorvex.console.attackNamespaces={team-a,team-b}')
        fire = firing(account_grants(docs, *ATTACKS_SA))
        self.assertEqual({g[0] for g in fire if g[2] != 'securityevents'}, {'team-a', 'team-b'})
        self.assertEqual({g for g in account_grants(docs, *ATTACKS_SA) if g[0] == '*cluster*' and g[2] in ('pods', 'pods/exec', 'services')}, set())

    def test_attack_namespaces_confine_policy_edits(self):
        docs = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE, '--set', 'phorvex.console.attackNamespaces={team-a,team-b}')
        for account in (CONSOLE_SA, ATTACKS_SA):
            with self.subTest(account=account[1]):
                edits = {g[0] for g in account_grants(docs, *account) if g[2] == 'phorvexpolicies' and g[4] == 'patch'}
                self.assertEqual(edits, {'team-a', 'team-b'})
        # Unconfined, both may edit any policy, as the console could.
        docs = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE)
        self.assertIn(('*cluster*', 'phorvex.ai', 'phorvexpolicies', '*', 'patch'), account_grants(docs, *CONSOLE_SA))

    def test_the_attacks_service_targets_only_its_namespaces(self):
        scope = ['--set', 'phorvex.console.attackNamespaces={team-a,team-b}']
        docs = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE, *scope)
        guard = [d for d in docs if d['kind'].startswith('ValidatingAdmissionPolicy') and d['metadata']['labels'].get('phorvex.ai/policy') == 'attacks-targets']
        policy = next(d for d in guard if d['kind'] == 'ValidatingAdmissionPolicy')
        binding = next(d for d in guard if d['kind'] == 'ValidatingAdmissionPolicyBinding')
        spec = policy['spec']
        self.assertEqual(spec['failurePolicy'], 'Fail')
        # Only the attacks service's own requests: every other requester, production's included, is untouched.
        self.assertEqual(spec['matchConditions'], [{'name': 'the-attacks-service',
                                                    'expression': 'request.userInfo.username == "system:serviceaccount:phorvex-system:phorvex-attacks"'}])
        self.assertEqual(spec['matchConstraints']['resourceRules'][0]['operations'], ['CREATE', 'UPDATE', 'DELETE'])
        self.assertIn('["team-a","team-b"].exists', spec['validations'][0]['expression'])
        self.assertEqual(binding['spec'], {'policyName': policy['metadata']['name'], 'validationActions': ['Deny']})
        self.assertTrue(policy['metadata']['name'].startswith('phorvex-attacks-targets-'))
        # The sweeper reaps only those namespaces' events, wherever it runs.
        for chart, docs, name in ((MANAGER_CHART, docs, 'console'), (ATTACKS_CHART, helm_template(ATTACKS_CHART, *CONSOLE, *scope), 'attacks')):
            self.assertIn({'name': 'PHORVEX_CONSOLE_SWEEP_NAMESPACES', 'value': 'team-a,team-b'}, container(docs, name)['env'], name)
        # Unconfined, there is neither.
        for values in ([], ATTACKS_REMOTE):
            docs = helm_template(MANAGER_CHART, *CONSOLE, *values)
            self.assertEqual([d for d in docs if d['kind'] == 'ValidatingAdmissionPolicy' and 'attacks-targets' in d['metadata']['name']], [])
            self.assertNotIn('PHORVEX_CONSOLE_SWEEP_NAMESPACES', [e['name'] for e in container(docs, 'console')['env']])

    def test_the_console_forwards_to_the_attacks_service_and_names_it_the_injector(self):
        docs = helm_template(MANAGER_CHART, *CONSOLE, *ATTACKS_REMOTE)
        env = {c['name']: {e['name']: e.get('value') for e in c.get('env', [])} for c in containers(docs)}
        self.assertEqual(env['console']['PHORVEX_CONSOLE_ATTACKS_URL'], 'http://phorvex-attacks:8090')
        for name in ('manager', 'console'):
            self.assertEqual(env[name].get('PHORVEX_INJECTOR_IDENTITY'), 'phorvex-system/phorvex-attacks', name)
        for service in ('sensor', 'actuator'):
            got = container(helm_template(CHARTS / ('phorvex-' + service), *ATTACKS_REMOTE), service)
            self.assertIn({'name': 'PHORVEX_INJECTOR_IDENTITY', 'value': 'phorvex-system/phorvex-attacks'}, got['env'], service)
        # In process, nothing names an injector or an attacks service.
        local = helm_template(MANAGER_CHART, *CONSOLE)
        self.assertEqual([e for c in containers(local) for e in c.get('env', []) if e['name'] in ('PHORVEX_INJECTOR_IDENTITY', 'PHORVEX_CONSOLE_ATTACKS_URL')], [])

    def test_the_attacks_service_runs_the_consoles_pod(self):
        digest = 'sha256:' + 'c' * 64
        attacks = helm_template(ATTACKS_CHART, *CONSOLE, '--set', 'image.repository=registry.example/phorvex/attacks',
                                '--set', 'image.tag=0.1.0', '--set', 'image.digest=' + digest)
        got, want = container(attacks, 'attacks'), container(helm_template(MANAGER_CHART, *CONSOLE), 'console')
        self.assertEqual(got['image'], 'registry.example/phorvex/attacks:0.1.0@' + digest)
        self.assertEqual(got['args'], [a for a in want['args'] if not a.startswith('-web=')])
        self.assertEqual([e for e in got['env'] if e['name'] != 'PHORVEX_INJECTOR_IDENTITY'], want['env'])
        self.assertIn({'name': 'PHORVEX_INJECTOR_IDENTITY', 'value': 'phorvex-system/phorvex-attacks'}, got['env'])
        self.assertEqual(got['volumeMounts'], want['volumeMounts'])
        self.assertEqual(got['readinessProbe']['httpGet']['path'], '/api/health')
        pod = next(d for d in attacks if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], 'phorvex-attacks')
        self.assertIn({'name': 'console-state', 'persistentVolumeClaim': {'claimName': 'phorvex-attacks-state'}}, pod['volumes'])
        kinds = {d['kind']: d['metadata']['name'] for d in attacks}
        self.assertEqual(kinds, {'Deployment': 'phorvex-attacks', 'Service': 'phorvex-attacks', 'ServiceAccount': 'phorvex-attacks',
                                 'NetworkPolicy': 'phorvex-attacks', 'PersistentVolumeClaim': 'phorvex-attacks-state'})
        policy = next(d for d in attacks if d['kind'] == 'NetworkPolicy')['spec']
        self.assertEqual(policy['ingress'], [{'from': [{'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'phorvex-console', 'app.kubernetes.io/instance': 'phorvex'}}}],
                                              'ports': [{'port': 'http'}]}])
        # Without the console nothing renders, and the release digest is a digest.
        self.assertEqual(helm_template(ATTACKS_CHART), [])
        result = subprocess.run([HELM, 'template', 'phorvex', str(ATTACKS_CHART), *CONSOLE, '--set', 'image.digest=latest'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('image.digest must be sha256', result.stderr)

    def test_its_defaults_are_the_managers(self):
        manager = yaml.safe_load(MANAGER_VALUES.read_text())['phorvex']
        attacks = yaml.safe_load((ATTACKS_CHART / 'values.yaml').read_text())['phorvex']
        for key, value in attacks.items():
            self.assertEqual(value, manager[key], key)
@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class NativeBackendTests(unittest.TestCase):
    def test_the_native_backend_writes_no_phoenix_objects(self):
        for name, values in {'in process': [], 'remote actuator': REMOTE}.items():
            with self.subTest(mode=name):
                docs = [*helm_template(MANAGER_CHART, '--set', 'phorvex.actuator=native', *WITHOUT_CODE_EXEC, *values),
                        *helm_template(CHARTS / 'phorvex-actuator', '--set', 'phorvex.actuator=native')]
                writes = {g for g in grants(docs) if g[1] == 'amtd.r6security.com' and g[4] not in ('get', 'list', 'watch')}
                self.assertEqual(writes, set())
        phoenix = helm_template(MANAGER_CHART)
        self.assertIn(('*cluster*', 'amtd.r6security.com', 'securityevents', '*', 'create'), grants(phoenix))


MONITORING = ['--set', 'phorvex.metrics.podMonitor.enabled=true', '--set', 'phorvex.metrics.podMonitor.environment=staging']


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class MonitoringTests(unittest.TestCase):
    """Each service is scraped, labelled with its environment (deploy/environments/README.md)."""
    charts = {'manager': MANAGER_CHART, 'brain': CHARTS / 'phorvex-brain', 'sensor': CHARTS / 'phorvex-sensor', 'actuator': CHARTS / 'phorvex-actuator'}

    def test_each_service_is_scraped_with_its_environment(self):
        for service, chart in self.charts.items():
            with self.subTest(service=service):
                docs = helm_template(chart, *PODMONITOR, *MONITORING)
                monitor = next(d for d in docs if d['kind'] == 'PodMonitor')['spec']
                pod = next(d for d in docs if d['kind'] == 'Deployment' and service in [c['name'] for c in d['spec']['template']['spec']['containers']])
                labels = pod['spec']['template']['metadata']['labels']
                self.assertLessEqual(monitor['selector']['matchLabels'].items(), labels.items())
                self.assertEqual(monitor['namespaceSelector'], {'matchNames': ['phorvex-system']})
                endpoint = monitor['podMetricsEndpoints'][0]
                self.assertIn('metrics', [p['name'] for c in pod['spec']['template']['spec']['containers'] for p in c.get('ports', [])])
                self.assertIn({'action': 'replace', 'targetLabel': 'environment', 'replacement': 'staging'}, endpoint['relabelings'])
                # Off by default, and refused where Prometheus cannot read it.
                self.assertEqual([d for d in helm_template(chart, *PODMONITOR) if d['kind'] == 'PodMonitor'], [])
                result = subprocess.run([HELM, 'template', 'phorvex', str(chart), *MONITORING], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requires the PodMonitor API', result.stderr)

    def test_the_dashboard_and_rules_read_only_their_environment(self):
        docs = helm_template(MANAGER_CHART, *PODMONITOR, *MONITORING, '--set', 'phorvex.metrics.dashboard.enabled=true', '--set', 'phorvex.metrics.rules.enabled=true')
        dashboard = next(d for d in docs if d['kind'] == 'ConfigMap' and d['metadata']['name'].endswith('-services-dashboard'))
        self.assertEqual(dashboard['metadata']['labels']['grafana_dashboard'], '1')
        board = json.loads(dashboard['data']['phorvex-services-staging.json'])
        self.assertEqual(board['uid'], 'phorvex-services-staging')
        exprs = [t['expr'] for panel in board['panels'] for t in panel.get('targets', [])]
        rules = next(d for d in docs if d['kind'] == 'PrometheusRule' and d['metadata']['name'].endswith('-services'))['spec']['groups'][0]['rules']
        exprs += [r['expr'] for r in rules]
        self.assertGreater(len(exprs), 15)
        for expr in exprs:
            self.assertNotIn('__', expr)
            self.assertTrue('environment="staging"' in expr or 'namespace="phorvex-system"' in expr, expr)
        self.assertEqual({r['labels']['severity'] for r in rules}, {'info'})
        for key in ('dashboard', 'rules'):
            result = subprocess.run([HELM, 'template', 'phorvex', str(MANAGER_CHART), *PODMONITOR, '--set', f'phorvex.metrics.{key}.enabled=true'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, key)
            self.assertIn('podMonitor.environment', result.stderr)
@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ExternalIdentityPolicyTests(unittest.TestCase):
    """Beside a release that installs the creator-identity guard, trust waits on it (M-94)."""
    OFF = ['--set', 'phorvex.eventIdentityPolicy.enabled=false', '--set', 'phorvex.trustedDetectors={staging/staging-attacks}']
    GUARD = ['--set', 'phorvex.eventIdentityPolicy.external=prod-se-creator']

    def test_trusted_detectors_need_a_guard(self):
        result = subprocess.run([HELM, 'template', 'phorvex', str(MANAGER_CHART), '-n', 'phorvex-system', *self.OFF], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('phorvex.eventIdentityPolicy.external', result.stderr)

    def test_the_manager_and_the_sensor_verify_the_named_guard(self):
        manager = helm_template(MANAGER_CHART, *self.OFF, *self.GUARD)
        self.assertEqual([d for d in manager if d['kind'] in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')], [])
        guard = {(n, 'admissionregistration.k8s.io', r, 'prod-se-creator', 'get')
                 for n in ('*cluster*',) for r in ('validatingadmissionpolicies', 'validatingadmissionpolicybindings')}
        for name, docs, service in (('manager', manager, 'manager'),
                                    ('sensor', helm_template(CHARTS / 'phorvex-sensor', *self.OFF, *self.GUARD), 'sensor')):
            with self.subTest(service=name):
                self.assertIn({'name': 'PHORVEX_EVENT_IDENTITY_POLICY', 'value': 'prod-se-creator'}, container(docs, service)['env'])
                self.assertLessEqual(guard, grants(docs))
        self.assertEqual({g for g in grants(helm_template(CHARTS / 'phorvex-actuator', *self.OFF, *self.GUARD)) if g[2].startswith('validatingadmission')}, set())


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ConsoleIngressTests(unittest.TestCase):
    def test_the_console_can_be_exposed_on_its_own(self):
        docs = helm_template(MANAGER_CHART, *CONSOLE, '--set', 'phorvex.console.ingress.enabled=true', '--set', 'phorvex.console.ingress.className=alb',
                             '--set', 'phorvex.console.ingress.host=staging-console.example', '--set', 'phorvex.console.ingress.annotations.a=b')
        service = next(d for d in docs if d['kind'] == 'Service' and d['metadata']['name'] == 'phorvex-phorvex-console')
        console = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == 'phorvex-phorvex-console')
        self.assertLessEqual(service['spec']['selector'].items(), console['spec']['template']['metadata']['labels'].items())
        self.assertEqual(service['spec']['ports'], [{'name': 'http', 'port': 80, 'targetPort': 'http'}])
        ingress = next(d for d in docs if d['kind'] == 'Ingress')
        self.assertEqual(ingress['spec']['ingressClassName'], 'alb')
        self.assertEqual(ingress['metadata']['annotations'], {'a': 'b'})
        rule = ingress['spec']['rules'][0]
        self.assertEqual(rule['host'], 'staging-console.example')
        self.assertEqual(rule['http']['paths'][0]['backend']['service'], {'name': 'phorvex-phorvex-console', 'port': {'name': 'http'}})
        # Off by default, and it needs a host.
        self.assertEqual([d for d in helm_template(MANAGER_CHART, *CONSOLE) if d['kind'] in ('Ingress', 'Service') and 'console' in d['metadata']['name']], [])
        result = subprocess.run([HELM, 'template', 'phorvex', str(MANAGER_CHART), *CONSOLE, '--set', 'phorvex.console.ingress.enabled=true'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ingress.host is required', result.stderr)



@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class ServiceTLSTests(unittest.TestCase):
    """Mutual TLS between the dispatcher and the services (docs/services/service-tls.md)."""
    ON = ['--set', 'phorvex.serviceTLS.enabled=true']
    FILES = ['--grpc-tls-cert=/etc/phorvex/grpc-tls/tls.crt', '--grpc-tls-key=/etc/phorvex/grpc-tls/tls.key',
             '--grpc-tls-ca=/etc/phorvex/grpc-tls/ca.crt']

    @staticmethod
    def pod(docs, container):
        return next(d['spec']['template']['spec'] for d in docs if d['kind'] == 'Deployment'
                    and d['spec']['template']['spec']['containers'][0]['name'] == container)

    @staticmethod
    def tls(pod):
        args = [a for a in pod['containers'][0].get('args', []) if a.startswith('--grpc-tls-')]
        secrets = [v['secret']['secretName'] for v in pod.get('volumes') or [] if v['name'] == 'grpc-tls']
        mounts = [m for m in pod['containers'][0].get('volumeMounts') or [] if m['name'] == 'grpc-tls']
        return args, secrets, mounts

    def test_it_is_off_by_default(self):
        renders = {service: self.pod(helm_template(CHARTS / ('phorvex-' + service)), service) for service in ('brain', 'sensor', 'actuator')}
        renders['manager'] = self.pod(helm_template(MANAGER_CHART, *REMOTE), 'manager')
        for end, pod in renders.items():
            self.assertEqual(self.tls(pod), ([], [], []), end)

    def test_each_service_mounts_its_secret_and_admits_only_the_dispatcher(self):
        for service in ('brain', 'sensor', 'actuator'):
            with self.subTest(service=service):
                args, secrets, mounts = self.tls(self.pod(helm_template(CHARTS / ('phorvex-' + service), *self.ON), service))
                self.assertEqual(args, self.FILES + ['--grpc-tls-peer=phorvex-dispatcher.phorvex-system.svc'])
                self.assertEqual(secrets, [f'phorvex-{service}-grpc-tls'])
                self.assertEqual([(m['mountPath'], m['readOnly']) for m in mounts], [('/etc/phorvex/grpc-tls', True)])

    def test_the_dispatcher_dials_with_its_own_secret(self):
        args, secrets, _ = self.tls(self.pod(helm_template(MANAGER_CHART, *REMOTE, *self.ON), 'manager'))
        self.assertEqual(args, self.FILES)
        self.assertEqual(secrets, ['phorvex-dispatcher-grpc-tls'])
        # In process it calls no service, and mounts nothing.
        self.assertEqual(self.tls(self.pod(helm_template(MANAGER_CHART, *self.ON), 'manager')), ([], [], []))

    def test_the_provisioning_script_issues_what_the_charts_mount(self):
        script = (ROOT / 'deploy/eks/provision-service-mtls.sh').read_text()
        self.assertIn('ends=(dispatcher brain sensor actuator)', script)
        self.assertIn("secret() { printf '%s-%s-grpc-tls' \"$RELEASE\" \"$1\"; }", script)
        self.assertIn("printf '%s-dispatcher.%s.svc' \"$RELEASE\" \"$NAMESPACE\"", script)
        self.assertTrue(os.access(ROOT / 'deploy/eks/provision-service-mtls.sh', os.X_OK))

class VendoredLibraryTests(unittest.TestCase):
    """Argo CD renders a chart's vendored charts/*.tgz, never deploy/charts/phorvex-common."""

    def test_every_chart_vendors_the_current_library(self):
        source = yaml.safe_load((LIBRARY / 'Chart.yaml').read_text())
        want = {f'phorvex-common/{p.relative_to(LIBRARY)}': p.read_bytes()
                for p in LIBRARY.rglob('*') if p.is_file() and p.name != 'Chart.yaml'}
        users = []
        for chart in sorted(p.parent for p in CHARTS.glob('*/Chart.yaml')) + [MANAGER_CHART]:
            deps = [d for d in yaml.safe_load((chart / 'Chart.yaml').read_text()).get('dependencies') or [] if d['name'] == 'phorvex-common']
            if not deps:
                continue
            users.append(chart.name)
            with self.subTest(chart=chart.name):
                self.assertEqual(deps, [{'name': 'phorvex-common', 'version': source['version'],
                                         'repository': 'file://' + os.path.relpath(LIBRARY, chart)}])
                package = chart / 'charts' / f"phorvex-common-{source['version']}.tgz"
                self.assertEqual(sorted(p.name for p in package.parent.iterdir()), [package.name])
                with tarfile.open(package) as archive:
                    got = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
                # helm package rewrites Chart.yaml, so it is compared as data.
                self.assertEqual(yaml.safe_load(got.pop('phorvex-common/Chart.yaml')), source)
                self.assertEqual(got, want, f'stale: run helm dependency update {chart.relative_to(ROOT)}')
                lock = yaml.safe_load((chart / 'Chart.lock').read_text())
                self.assertEqual(lock['dependencies'], deps)
        self.assertLessEqual({'phorvex-sensor', 'phorvex-actuator', 'phorvex'}, set(users))


if __name__ == '__main__':
    unittest.main()
