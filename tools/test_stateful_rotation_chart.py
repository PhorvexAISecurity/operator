"""The stateful rotation family's RBAC: opt-in, exact, and split between sensor and actuator."""
import os
import subprocess
import unittest

from test_service_charts import HELM, MANAGER_CHART, grants, helm_template, library_rbac, manager_rbac

ENABLED = ['--set', 'phorvex.actuator=native', '--set', 'phorvex.statefulRotation.enabled=true',
           '--set', 'phorvex.actuatorNamespaces[0]=db']
CLAIMS = ('db', '', 'persistentvolumeclaims', '*')
SNAPSHOTS = ('db', 'snapshot.storage.k8s.io', 'volumesnapshots', '*')
CLASSES = ('*cluster*', 'snapshot.storage.k8s.io', 'volumesnapshotclasses', '*')


def stateful(access):
    return {g for g in access if g[2] in ('persistentvolumeclaims', 'volumesnapshots', 'volumesnapshotclasses')}


@unittest.skipUnless(HELM or os.environ.get('GITHUB_ACTIONS'), 'helm is not installed')
class StatefulRotationChartTests(unittest.TestCase):
    def test_disabled_by_default(self):
        access = grants(manager_rbac(['--set', 'phorvex.actuator=native', '--set', 'phorvex.actuatorNamespaces[0]=db']))
        self.assertEqual(stateful(access), set())

    def test_enabled_grants_exactly_the_family(self):
        access = grants(manager_rbac(ENABLED))
        self.assertEqual(stateful(access), {
            CLAIMS + ('get',), CLAIMS + ('delete',),
            SNAPSHOTS + ('get',), SNAPSHOTS + ('create',),
            CLASSES + ('get',),
        })

    def test_requires_a_native_route(self):
        args = [HELM, 'template', 'phorvex', str(MANAGER_CHART), '-n', 'phorvex-system',
                '--set', 'phorvex.actuator=phoenix', '--set', 'phorvex.statefulRotation.enabled=true']
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('statefulRotation requires native or hybrid actuator', result.stderr)

    def test_the_sensor_reads_and_the_actuator_writes(self):
        sensor = stateful(grants(library_rbac('sensor', ENABLED)))
        actuator = stateful(grants(library_rbac('actuator', ENABLED)))
        dispatcher = stateful(grants(library_rbac('dispatcher', ENABLED)))
        self.assertEqual(sensor, {CLAIMS + ('get',), CLASSES + ('get',)})
        self.assertEqual({g for g in actuator if g[4] not in ('get',)}, {CLAIMS + ('delete',), SNAPSHOTS + ('create',)})
        self.assertEqual(dispatcher, set())
        self.assertEqual(sensor | actuator, stateful(grants(manager_rbac(ENABLED))))


if __name__ == '__main__':
    unittest.main()
