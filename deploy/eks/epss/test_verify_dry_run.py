import copy
import unittest

from verify_dry_run import verify


def fixture():
    spec = {'template': {'metadata': {'labels': {'app': 'epss'}}, 'spec': {'containers': [{
        'name': 'feed', 'args': ['--epss-feed-apply=false', '--epss-feed-allow-partial=false', '--epss-metadata-key=epss-metadata.json']}]}}}
    cron = {'kind': 'CronJob', 'spec': {'jobTemplate': {'spec': spec}}}
    job = {'kind': 'Job', 'metadata': {'name': 'witness-unique', 'uid': 'witness-uid'}, 'spec': copy.deepcopy(spec)}
    cm = {'kind': 'ConfigMap', 'metadata': {'name': 'phorvex-epss', 'uid': 'cache-uid', 'resourceVersion': '42'}, 'data': {'epss-cache.json': '{}'}}
    result = {'mode': 'dry-run', 'uniqueImages': 46, 'scannedImages': 46, 'failedImages': 0}
    return cron, job, copy.deepcopy(cm), copy.deepcopy(cm), result


class EvidenceTests(unittest.TestCase):
    def test_full_template_and_unchanged_cache(self):
        evidence = fixture()
        self.assertEqual(verify(*evidence)['uniqueImages'], 46)
        evidence[1]['spec']['selector'] = {'matchLabels': {'controller-uid': 'synthetic'}}
        evidence[1]['spec']['template']['metadata']['labels']['batch.kubernetes.io/job-name'] = 'witness-unique'
        verify(*evidence)

    def test_reject_inventory_narrowing_and_non_auth_failure(self):
        for field, value in [('mode', 'rejected-partial'), ('failedImages', 1), ('scannedImages', 45), ('uniqueImages', 0), ('scopeSHA256', 'synthetic')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence = fixture(); evidence[4][field] = value; verify(*evidence)
        with self.assertRaises(ValueError):
            evidence = fixture(); evidence[1]['spec']['template']['spec']['containers'][0]['args'].append('--epss-feed-scope-namespaces=owned'); verify(*evidence)

    def test_reject_cache_changes(self):
        for mutate in (lambda x: x['metadata'].update(uid='new'), lambda x: x['metadata'].update(resourceVersion='43'),
                       lambda x: x['data'].update({'epss-cache.json': 'changed'}),
                       lambda x: x['data'].update({'epss-metadata.json': '{}'}),
                       lambda x: x['metadata'].update(annotations={'success': 'true'})):
            with self.assertRaises(ValueError):
                evidence = fixture(); mutate(evidence[3]); verify(*evidence)


if __name__ == '__main__':
    unittest.main()
