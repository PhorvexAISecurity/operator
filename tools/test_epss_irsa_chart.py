#!/usr/bin/env python3
"""Light Helm render controls for legacy Secret and opt-in web identity modes."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'phorvex/charts/phorvex'
PACKAGE = ROOT / 'deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz'
HOSTS = ['753556437180.dkr.ecr.us-east-2.amazonaws.com', '602401143452.dkr.ecr.us-east-2.amazonaws.com']
ROLE = 'arn:aws:iam::753556437180:role/phorvex-dev-epss-feed'
IMAGE = HOSTS[0] + '/phorvex@sha256:' + 'a' * 64  # synthetic render fixture only


def irsa_values():
    return {'phorvex': {'epss': {'enabled': True, 'feed': {
        'enabled': True,
        'registryAuth': {'enabled': True, 'mode': 'irsaInit', 'registries': HOSTS,
                         'irsaInit': {'enabled': True, 'image': IMAGE, 'roleARN': ROLE, 'region': 'us-east-2'}},
        'serviceAccount': {'annotations': {'eks.amazonaws.com/role-arn': ROLE}},
    }}}}


def render(values, chart=SOURCE, release="phorvex", namespace="phorvex-system"):
    helm = os.environ.get('HELM_BIN') or shutil.which('helm')
    if not helm:
        raise RuntimeError('Helm is required for this render contract')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml') as config:
        yaml.safe_dump(values, config)
        config.flush()
        return subprocess.run([helm, 'template', release, str(chart), '-n', namespace, '--api-versions', 'monitoring.coreos.com/v1/PodMonitor', '-f', config.name],
                              capture_output=True, text=True)


def objects(values, chart=SOURCE):
    result = render(values, chart)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [x for x in yaml.safe_load_all(result.stdout) if x]


def named(items, kind):
    return next(x for x in items if x['kind'] == kind and x['metadata']['name'].endswith('-epss-feed'))


class ChartTests(unittest.TestCase):
    def test_default_feed_has_no_auth(self):
        values = {'phorvex': {'epss': {'enabled': True, 'feed': {'enabled': True}}}}
        items = objects(values)
        pod = named(items, 'CronJob')['spec']['jobTemplate']['spec']['template']['spec']
        self.assertEqual([x['name'] for x in pod['initContainers']], ['trivy'])
        self.assertFalse(any(x['name'] == 'registry-auth' for x in pod['volumes']))
        self.assertNotIn('annotations', named(items, 'ServiceAccount')['metadata'])
        self.assertFalse(any('registry-auth' in x for x in pod['containers'][0]['args']))

    def test_legacy_secret_mode_keeps_projection(self):
        values = {'phorvex': {'epss': {'enabled': True, 'feed': {'enabled': True, 'registryAuth': {
            'enabled': True, 'secretName': 'fixture-auth', 'secretKey': 'docker-config.json', 'registries': HOSTS,
        }}}}}
        items = objects(values)
        pod = named(items, 'CronJob')['spec']['jobTemplate']['spec']['template']['spec']
        volume = next(x for x in pod['volumes'] if x['name'] == 'registry-auth')
        self.assertEqual(volume['secret'], {'secretName': 'fixture-auth', 'defaultMode': 0o440,
                                           'items': [{'key': 'docker-config.json', 'path': 'config.json'}]})
        self.assertEqual([x['name'] for x in pod['initContainers']], ['trivy'])
        baseline = objects({'phorvex': {'epss': {'enabled': True, 'feed': {'enabled': True}}}})
        secret_names = lambda rows: sorted(x['metadata']['name'] for x in rows if x['kind'] == 'Secret')
        self.assertEqual(secret_names(items), secret_names(baseline))

    def test_irsa_init_is_bounded_and_read_only_in_feed(self):
        items = objects(irsa_values())
        job = named(items, 'CronJob')['spec']['jobTemplate']['spec']
        pod = job['template']['spec']
        auth = next(x for x in pod['initContainers'] if x['name'] == 'ecr-auth')
        self.assertEqual(auth['image'], IMAGE)
        self.assertEqual(auth['securityContext']['capabilities']['drop'], ['ALL'])
        self.assertTrue(auth['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(auth['securityContext']['allowPrivilegeEscalation'])
        self.assertEqual(pod['securityContext']['runAsUser'], 65532)
        self.assertEqual(pod['securityContext']['runAsGroup'], 65532)
        self.assertEqual(pod['securityContext']['fsGroup'], 65532)
        volumes = {x['name']: x for x in pod['volumes']}
        self.assertEqual(volumes['registry-auth']['emptyDir'], {'medium': 'Memory', 'sizeLimit': '1Mi'})
        token = volumes['epss-web-identity']['projected']['sources'][0]['serviceAccountToken']
        self.assertEqual(token, {'audience': 'sts.amazonaws.com', 'expirationSeconds': 3600, 'path': 'token'})
        feed = pod['containers'][0]
        mount = next(x for x in feed['volumeMounts'] if x['name'] == 'registry-auth')
        self.assertTrue(mount['readOnly'])
        self.assertEqual(job['activeDeadlineSeconds'], 3600)
        self.assertIn('--epss-feed-apply=false', feed['args'])
        self.assertIn('--epss-feed-allow-partial=false', feed['args'])
        self.assertIn('--epss-feed-registry-auth-registries=' + ','.join(HOSTS), feed['args'])
        self.assertFalse(any('scope-digests' in x or 'scope-namespaces' in x for x in feed['args']))
        baseline = objects({'phorvex': {'epss': {'enabled': True, 'feed': {'enabled': True}}}})
        secret_names = lambda rows: sorted(x['metadata']['name'] for x in rows if x['kind'] == 'Secret')
        self.assertEqual(secret_names(items), secret_names(baseline))
        for item in items:
            for rule in item.get('rules', []):
                self.assertNotIn('secrets', rule.get('resources', []))
        self.assertEqual(named(items, 'ServiceAccount')['metadata']['annotations']['eks.amazonaws.com/role-arn'], ROLE)

    def test_invalid_modes_and_identity_fail_closed(self):
        cases = {
            'secret-conflict': ('registryAuth.secretName', 'fixture-auth'),
            'secret-key-conflict': ('registryAuth.secretKey', 'other.json'),
            'init-disabled': ('registryAuth.irsaInit.enabled', False),
            'auth-disabled': ('registryAuth.enabled', False),
            'mode': ('registryAuth.mode', 'unknown'),
            'secret-with-init': ('registryAuth.mode', 'secret'),
            'role': ('registryAuth.irsaInit.roleARN', 'arn:aws:iam::753556437180:role/other'),
            'annotation': ('serviceAccount.annotations', {}),
            'region': ('registryAuth.irsaInit.region', 'us-west-2'),
            'missing-image': ('registryAuth.irsaInit.image', ''),
            'tag-only': ('registryAuth.irsaInit.image', HOSTS[0] + '/phorvex:helper'),
            'foreign-image': ('registryAuth.irsaInit.image', HOSTS[1] + '/other@sha256:' + 'a' * 64),
            'one-host': ('registryAuth.registries', HOSTS[:1]),
            'duplicate-host': ('registryAuth.registries', [HOSTS[0], HOSTS[0]]),
            'foreign-host': ('registryAuth.registries', [HOSTS[0], '111111111111.dkr.ecr.us-east-2.amazonaws.com']),
            'deadline': ('activeDeadlineSeconds', 3601),
            'zero-deadline': ('activeDeadlineSeconds', 0),
            'timeout': ('scanTimeout', '11m'),
        }
        for name, (path, value) in cases.items():
            with self.subTest(name=name):
                values = copy.deepcopy(irsa_values())
                cursor = values['phorvex']['epss']['feed']
                keys = path.split('.')
                for key in keys[:-1]:
                    cursor = cursor[key]
                cursor[keys[-1]] = value
                result = render(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('EPSS registry authentication', result.stderr)

    def test_irsa_requires_trusted_service_account_subject(self):
        for release, namespace in [('other', 'phorvex-system'), ('phorvex', 'other')]:
            result = render(irsa_values(), release=release, namespace=namespace)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('exact trusted ServiceAccount subject', result.stderr)

    def test_vendored_source_matches_in_both_auth_modes(self):
        for values in (irsa_values(), {'phorvex': {'epss': {'enabled': True, 'feed': {'enabled': True}}}}):
            epss = lambda rows: [x for x in rows if x['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 'epss-feed']
            self.assertEqual(epss(objects(values)), epss(objects(values, PACKAGE)))
        with tarfile.open(PACKAGE) as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name != 'phorvex/Chart.yaml':
                    relative = Path(member.name).relative_to('phorvex')
                    # helm package rewrites Chart.lock and stores the chart's own vendored
                    # dependencies expanded; tools/check-vendored-chart.sh compares those.
                    if relative.parts[0] == 'charts' or relative == Path('Chart.lock'):
                        continue
                    self.assertEqual(archive.extractfile(member).read(), (SOURCE / relative).read_bytes())

    def test_active_stack_values_leave_auth_disabled(self):
        items = objects({}, ROOT / 'deploy/helm/phorvex-stack')
        # Defaults disable the feed entirely. The active EKS overlay is checked separately.
        self.assertFalse(any(x['kind'] == 'CronJob' and x['metadata']['name'].endswith('-epss-feed') for x in items))
        values = yaml.safe_load((ROOT / 'deploy/helm/phorvex-stack/values-eks.yaml').read_text())
        items = objects(values, ROOT / 'deploy/helm/phorvex-stack')
        pod = named(items, 'CronJob')['spec']['jobTemplate']['spec']['template']['spec']
        self.assertFalse(any(x['name'] == 'ecr-auth' for x in pod['initContainers']))
        self.assertNotIn('eks.amazonaws.com/role-arn', named(items, 'ServiceAccount')['metadata'].get('annotations', {}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
