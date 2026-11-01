"""Stage identity boundaries use real local Git/files and explicit cluster doubles."""
import copy
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import service
import testkit
import file_requests
from stage_runtime import StageRuntime
from mathlab import stage_scope, experiment, snapshots
from mathlab.common import write_json, read_json
import stage_cli
import code_experiment
from runner import Console, TransportError


class StageScopeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='stage-scope-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'repo'
        self.source = testkit.make_repo(self.repo)
        self.data = self.tmp / 'data'
        testkit.make_corpus(self.data, self.source)
        self.pin = testkit.write_stage_pin(self.data, self.source)
        self.policy = stage_scope.DEFAULT_POLICY

    def entries(self):
        ns, name = self.policy.split('/')
        return experiment.select_cohort(self.data, {'namespace': ns, 'policy': name,
                    'cohort': {'git_sha': self.source, 'policy_uid': 'u'}})

    def test_exact_stage_pin_and_real_corpus_validate(self):
        pin, identity, provenance = stage_scope.validate_run(self.data, self.policy, self.entries(), self.repo)
        self.assertEqual(identity['git_sha'], self.source)
        self.assertEqual(provenance['policy_uid'], 'u')
        self.assertEqual(provenance['brain']['image_digest'], pin['brain']['image_digest'])

    def test_legacy_repository_and_non_stage_namespaces_are_rejected(self):
        testkit.git(self.repo, 'remote', 'set-url', 'origin', 'https://github.com/PhorvexSecurity/operator.git')
        with self.assertRaisesRegex(stage_scope.StageError, 'legacy operator'):
            stage_scope.load(self.data, self.policy, self.repo)
        for policy in ('vllm/vllm-defense', 'phorvex-system/test', 'notstaging/test', '../stage/test'):
            with self.subTest(policy=policy), self.assertRaises(stage_scope.StageError):
                stage_scope.policy(policy)
        with self.assertRaises(file_requests.RequestError):
            file_requests.parse('[bench]\npolicy: production/test\nchange: adjust the scoring threshold')
        with self.assertRaises(service.ConfigError):
            service.Config({'BOT_ALLOWED_USER_IDS': '1', 'BOT_STATE_DIR': str(self.tmp/'state'),
                            'BOT_DEFAULT_POLICY': 'vllm/vllm-defense'})

    def test_missing_pin_and_tampered_binary_stop_before_model_work(self):
        path = self.data / 'mathlab/stage.json'
        path.unlink()
        with self.assertRaisesRegex(stage_scope.StageError, 'stage is not pinned'):
            stage_scope.load(self.data, self.policy)
        testkit.write_stage_pin(self.data, self.source)
        Path(self.pin['replay']['path']).write_text('tampered')
        with self.assertRaisesRegex(stage_scope.StageError, 'hash changed'):
            stage_scope.identity(self.data)

    def test_pin_cannot_repurpose_a_legacy_production_data_root(self):
        (self.data/'mathlab/snapshots/vllm').mkdir()
        with mock.patch.object(stage_cli, 'kube', side_effect=AssertionError('no cluster read needed')):
            with self.assertRaisesRegex(stage_scope.StageError, 'separate stage data'):
                stage_cli.pin_stage(self.data, self.repo, 'ctx', 'phorvex-staging', self.policy)

    def test_recreated_policy_or_mixed_source_cannot_enter_cohort(self):
        entries = self.entries()
        for key, value in [('policyUID', 'new-uid'), ('namespace', 'production'), ('gitSHA', 'a'*40)]:
            bad = copy.deepcopy(entries); bad[0]['header'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(stage_scope.StageError, 'different namespace'):
                stage_scope.cohort(self.pin, self.policy, bad)
        pin = copy.deepcopy(self.pin); pin['policies'][self.policy]['uid'] = 'new-uid'
        write_json(self.data/'mathlab/stage.json', pin)
        ns, name = self.policy.split('/')
        self.assertEqual(experiment.select_cohort(self.data, {'namespace': ns, 'policy': name,
            'cohort': {'git_sha': self.source, 'policy_uid': 'new-uid'}}), [])

    def test_same_source_old_image_and_legacy_headers_never_inherit_current_pin(self):
        entries = self.entries()
        for change in ({'brainImage': self.pin['brain']['image'].replace('e'*64, 'f'*64)},
                       {'brainImage': self.pin['brain']['image'].replace('/brain:', '/manager:')},
                       {'captureIdentitySource': None}):
            old = copy.deepcopy(entries); old[0]['header'].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(stage_scope.StageError, 'remain historical'):
                stage_scope.cohort(self.pin, self.policy, old)
        folder = self.data/'mathlab/snapshots'/self.policy
        old_image = self.pin['brain']['image'].replace('e'*64, 'f'*64)
        old_digest = testkit.make_snapshot(folder, self.source, 9, True, '2026-10-29T00:00:00Z', brain_image=old_image)
        legacy_digest = testkit.make_snapshot(folder, self.source, 10, True, '2026-10-29T00:00:01Z', capture_identity_source=None)
        selected = experiment.select_cohort(self.data, {'namespace': self.policy.split('/')[0],
            'policy': self.policy.split('/')[1], 'cohort': {**stage_scope.cohort_filter(self.pin, self.policy),
                                                         'max_snapshots': 2, 'spacing': 'even'}})
        self.assertEqual([entry['digest'] for entry in selected], [entries[0]['digest'], entries[-1]['digest']])
        self.assertTrue((folder/(old_digest+'.pxms')).exists())
        self.assertTrue((folder/(legacy_digest+'.pxms')).exists())

    def test_stage_sync_filters_actual_headers_and_resumes_from_matching_image(self):
        folder = self.data/'mathlab/snapshots'/self.policy
        old_image = self.pin['brain']['image'].replace('e'*64, 'f'*64)
        old_digest = testkit.make_snapshot(folder, self.source, 8, True, '2026-10-29T00:00:00Z', brain_image=old_image)
        remote = self.tmp/'remote'
        good = testkit.make_snapshot(remote, self.source, 9, True, '2026-10-28T00:00:06Z')
        bad = testkit.make_snapshot(remote, self.source, 10, True, '2026-10-28T00:00:07Z', brain_image=old_image)
        console = mock.Mock()
        console.request.return_value = {'entries': [{'digest': good}, {'digest': bad}]}
        def opened(path, **kwargs):
            digest = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['digest'][0]
            return io.BytesIO((remote/(digest+'.pxms')).read_bytes())
        console.open.side_effect = opened
        record = snapshots.sync(self.data, *self.policy.split('/'), console,
                                expected_header=stage_scope.snapshot_header(self.pin, self.policy))
        self.assertIn('since=2026-10-28T00%3A00%3A05Z', console.request.call_args.args[0])
        self.assertEqual((record['downloaded'], record['corpus']['snapshots']), (1, 7))
        self.assertEqual(record['rejected'][0]['digest'], bad)
        self.assertFalse((folder/(bad+'.pxms')).exists())
        self.assertTrue((folder/(old_digest+'.pxms')).exists())

    def remote_console(self, folder, digests):
        entries = [{'digest': digest, 'header': snapshots.read_header(folder/(digest+'.pxms'))} for digest in digests]
        entries.sort(key=lambda entry: (snapshots._clock(entry['header']['capturedAt']), entry['digest']))
        console = mock.Mock()
        def listed(path):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            since = snapshots._clock(query.get('since', [None])[0])
            until = snapshots._clock(query.get('until', [None])[0])
            # Same oldest-first, inclusive-since and exclusive-until semantics
            # as mathlab.Store.List; no artificial server-side image filter.
            rows = [e for e in entries if (not since or snapshots._clock(e['header']['capturedAt']) >= since)
                    and (not until or snapshots._clock(e['header']['capturedAt']) < until)]
            return {'entries': rows[:int(query['limit'][0])]}
        def opened(path, **kwargs):
            digest = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['digest'][0]
            return io.BytesIO((folder/(digest+'.pxms')).read_bytes())
        console.request.side_effect, console.open.side_effect = listed, opened
        return console

    def test_stage_sync_paginates_old_image_pages_and_equal_time_boundaries(self):
        remote = self.tmp/'pages'
        old_image = self.pin['brain']['image'].replace('e'*64, 'f'*64)
        old = [testkit.make_snapshot(remote, self.source, i, True, '2026-10-28T00:00:0%dZ' % i,
                                    brain_image=old_image) for i in (1, 2)]
        good = testkit.make_snapshot(remote, self.source, 3, True, '2026-10-28T00:00:03Z')
        console = self.remote_console(remote, old+[good])
        data = self.tmp/'fresh-pages'
        record = snapshots.sync(data, *self.policy.split('/'), console, limit=2,
                                expected_header=stage_scope.snapshot_header(self.pin, self.policy))
        self.assertEqual((record['downloaded'], record['index_scanned'], record['index_pages']), (1, 3, 3))
        self.assertFalse(record['more_available'])
        self.assertEqual(len(record['rejected']), 2)
        self.assertEqual(console.open.call_count, 1)

        # Place a current-image tick behind two old-image ticks with exactly
        # the same timestamp/digest order. Growing the inclusive page exposes
        # the boundary group; advancing a timestamp epsilon would lose it.
        tied = self.tmp/'tied'
        good = testkit.make_snapshot(tied, self.source, 3, True, '2026-10-28T00:00:03Z')
        old = []
        for risk in range(100):
            digest = testkit.make_snapshot(tied, self.source, risk, True, '2026-10-28T00:00:03Z', brain_image=old_image)
            if digest < good: old.append(digest)
            if len(old) == 2: break
        self.assertEqual(len(old), 2)
        console = self.remote_console(tied, old+[good])
        record = snapshots.sync(self.tmp/'fresh-tied', *self.policy.split('/'), console, limit=2,
                                expected_header=stage_scope.snapshot_header(self.pin, self.policy))
        self.assertEqual(record['downloaded'], 1)
        self.assertFalse(record['more_available'])
        self.assertTrue(any('limit=4' in call.args[0] for call in console.request.call_args_list))

    def test_bounded_index_scan_resumes_remote_progress_and_never_skips_unreturned_ties(self):
        remote = self.tmp/'bounded-pages'
        old_image = self.pin['brain']['image'].replace('e'*64, 'f'*64)
        old = [testkit.make_snapshot(remote, self.source, i, True, '2026-10-28T00:00:0%dZ' % i,
                                    brain_image=old_image) for i in (1, 2)]
        good = testkit.make_snapshot(remote, self.source, 3, True, '2026-10-28T00:00:03Z')
        console = self.remote_console(remote, old+[good])
        data = self.tmp/'bounded-data'; expected = stage_scope.snapshot_header(self.pin, self.policy)
        with mock.patch.object(snapshots, 'MAX_INDEX_PAGES', 1):
            first = snapshots.sync(data, *self.policy.split('/'), console, limit=2, expected_header=expected)
            second = snapshots.sync(data, *self.policy.split('/'), console, limit=2, expected_header=expected)
        self.assertEqual(first['downloaded'], 0)
        self.assertEqual(first['next_since'], '2026-10-28T00:00:02Z')
        self.assertEqual(second['downloaded'], 1)
        self.assertEqual(second['since'], first['next_since'])

        page = [{'digest': '%064x' % i, 'header': {'capturedAt': '2026-10-28T00:00:00Z'}} for i in range(5000)]
        blocked_console = mock.Mock(); blocked_console.request.return_value = {'entries': page}
        _, scan = snapshots.stage_listing(blocked_console, {'namespace': self.policy.split('/')[0],
            'policy': self.policy.split('/')[1], 'limit': '5000'}, expected)
        self.assertIn('without a digest cursor', scan['pagination_blocked'])
        self.assertEqual(scan['next_since'], '2026-10-28T00:00:00Z')
        self.assertEqual(blocked_console.request.call_count, 2)

    def test_sync_enforces_cumulative_transfer_cap_and_tracks_only_verified_new_files(self):
        remote = self.tmp/'quota-remote'
        first = testkit.make_snapshot(remote, self.source, 1, True, '2026-10-28T00:00:01Z')
        last = testkit.make_snapshot(remote, self.source, 2, True, '2026-10-28T00:00:02Z')
        console = self.remote_console(remote, [first, last])
        expected = stage_scope.snapshot_header(self.pin, self.policy)
        budget = (remote/(last+'.pxms')).stat().st_size
        data = self.tmp/'quota-data'
        result = snapshots.sync(data, *self.policy.split('/'), console, expected_header=expected, max_bytes=budget)
        self.assertEqual(result['downloaded_digests'], [last])
        self.assertEqual((result['downloaded_bytes'], result['transferred_bytes']), (budget, budget))
        self.assertTrue(result['byte_limit_reached'])
        # The later downloaded tick cannot advance the resume cursor past the
        # earlier blob that was deferred by this transfer cap.
        retry = snapshots.sync(data, *self.policy.split('/'), console, expected_header=expected, max_bytes=budget)
        self.assertEqual(retry['downloaded_digests'], [first])
        self.assertEqual(retry['corpus']['snapshots'], 2)
        self.assertFalse(retry['byte_limit_reached'])
        partial = snapshots.sync(self.tmp/'partial-quota', *self.policy.split('/'), console,
                                 expected_header=expected, max_bytes=budget//2)
        self.assertEqual((partial['downloaded'], partial['downloaded_digests']), (0, []))
        self.assertEqual(partial['transferred_bytes'], budget//2)
        self.assertTrue(partial['byte_limit_reached'])
        self.assertFalse(list((self.tmp/'partial-quota/mathlab/snapshots'/self.policy).glob('*.pxms')))

    def test_parameter_freeze_holds_shared_lock_then_replay_survives_cache_prune(self):
        cfg = service.Config({'BOT_ALLOWED_USER_IDS': '1', 'BOT_STATE_DIR': str(self.tmp/'state'),
                              'BOT_REPO': str(self.repo), 'MATHLAB_DATA_DIR': str(self.data)})
        runtime = cfg.dashboard()
        request = {'mode': 'REPLAY', 'policy': self.policy, 'parameter_id': 'P-FEA-006',
                   'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                            {'arm_id': 'trial', 'value': 1.5}]}
        copying, attempted, pruned = threading.Event(), threading.Event(), threading.Event()
        errors = []
        def prune():
            try:
                if not copying.wait(3): raise AssertionError('freeze did not begin')
                attempted.set()
                with snapshots.cache_lock(self.data, *self.policy.split('/'), exclusive=True):
                    for path in (self.data/'mathlab/snapshots'/self.policy).glob('*.pxms'): path.unlink()
                    pruned.set()
            except BaseException as error:
                errors.append(error)
        original = snapshots.shutil.copy2
        def slow_copy(source, target):
            if not copying.is_set():
                copying.set()
                self.assertTrue(attempted.wait(3))
                self.assertFalse(pruned.wait(.05), 'exclusive prune entered before the cohort was frozen')
            return original(source, target)
        writer = threading.Thread(target=prune, daemon=True); writer.start()
        with mock.patch.object(snapshots.shutil, 'copy2', slow_copy):
            self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        writer.join(3)
        self.assertFalse(writer.is_alive()); self.assertFalse(errors); self.assertTrue(pruned.is_set())
        self.assertEqual(self.entries(), [])
        result = runtime.wait_experiment(runtime.create(request)['id'])
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(result['result']['population']['control_eligible'], 6)

    def test_stage_sync_registers_only_its_verified_new_files_after_shared_lock(self):
        from endpoint_refresh import cache_records
        remote = self.tmp/'registered-remote'
        value = testkit.make_snapshot(remote, self.source, 7, True, '2026-10-28T00:00:07Z')
        console = self.remote_console(remote, [value])
        pin = copy.deepcopy(self.pin)
        pin['brain'].update(deployment='staging-brain', deployment_uid='deployment', digest=pin['brain']['image_digest'])
        pin['console'] = {'service': 'staging-phorvex-console', 'service_account': 'staging-brain-benchmark',
                          'port': 80, 'audience': 'phorvex-staging-console'}
        write_json(self.data/'mathlab/stage.json', pin)
        with mock.patch.object(stage_cli, 'running_image', return_value=pin['brain']), \
             mock.patch.object(stage_cli, 'kube', return_value={'metadata': {'uid': 'u'}}), \
             mock.patch('runner.Console', return_value=console):
            result = stage_cli.sync_stage(self.data, self.repo, self.policy, sync_limit=2, max_sync_bytes=1<<20)
        self.assertEqual(result['downloaded_digests'], [value])
        self.assertEqual(set(cache_records(self.data, self.policy)['snapshots']), {value})
        self.assertEqual(len(self.entries()), 7, 'preexisting cache remains untouched and unclaimed')
        console.close.assert_called_once()

    def test_pending_parameter_copies_are_bounded_and_created_results_are_preserved(self):
        cfg = service.Config({'BOT_ALLOWED_USER_IDS': '1', 'BOT_STATE_DIR': str(self.tmp/'state'),
                              'BOT_REPO': str(self.repo), 'MATHLAB_DATA_DIR': str(self.data)})
        runtime = cfg.dashboard()
        request = {'mode': 'REPLAY', 'policy': self.policy, 'parameter_id': 'P-FEA-006',
                   'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                            {'arm_id': 'trial', 'value': 1.5}]}
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        old = runtime.root(next(iter(runtime.requests.values()))['experiment_id'])
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        self.assertFalse(old.exists())
        created = runtime.root(runtime.create(request)['id'])
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        pending = runtime.root(next(iter(runtime.requests.values()))['experiment_id'])
        (self.data/'mathlab/stage.json').unlink()
        with self.assertRaises(stage_scope.StageError): runtime.create(request)
        self.assertFalse(pending.exists())
        self.assertTrue((created/'request.json').exists())
        self.assertEqual(len(list((created/'cohort').glob('*.pxms'))), 6)

    def test_stage_sync_serializes_download_to_ownership_registration_gap(self):
        from endpoint_refresh import cache_records, prune_cache
        remote = self.tmp/'serialized-remote'
        value = testkit.make_snapshot(remote, self.source, 7, True, '2026-10-28T00:00:07Z')
        console = self.remote_console(remote, [value])
        pin = copy.deepcopy(self.pin)
        pin['brain'].update(deployment='staging-brain', deployment_uid='deployment', digest=pin['brain']['image_digest'])
        pin['console'] = {'service': 'staging-phorvex-console', 'service_account': 'staging-brain-benchmark',
                          'port': 80, 'audience': 'phorvex-staging-console'}
        write_json(self.data/'mathlab/stage.json', pin)
        gap, release, second_attempted, second_network = [threading.Event() for _ in range(4)]
        failures, results = [], []
        original = snapshots.sync
        def paused_sync(*args, **kwargs):
            result = original(*args, **kwargs)
            if threading.current_thread().name == 'stage-sync-a':
                gap.set()
                if not release.wait(3): raise AssertionError('registration gap was not released')
            return result
        def connect(**kwargs):
            if threading.current_thread().name == 'stage-sync-b': second_network.set()
            return console
        def run():
            try:
                if threading.current_thread().name == 'stage-sync-b': second_attempted.set()
                results.append(stage_cli.sync_stage(self.data, self.repo, self.policy, sync_limit=2, max_sync_bytes=1<<20))
            except BaseException as error:
                failures.append(error)
        with mock.patch.object(stage_cli, 'running_image', return_value=pin['brain']), \
             mock.patch.object(stage_cli, 'kube', return_value={'metadata': {'uid': 'u'}}), \
             mock.patch('runner.Console', side_effect=connect), mock.patch.object(snapshots, 'sync', paused_sync):
            first = threading.Thread(target=run, name='stage-sync-a', daemon=True)
            second = threading.Thread(target=run, name='stage-sync-b', daemon=True)
            first.start(); self.assertTrue(gap.wait(3)); second.start()
            try:
                self.assertTrue(second_attempted.wait(3))
                self.assertFalse(second_network.wait(.05), 'second stage writer entered before the first registered')
                # No cache lock is retained across the gap. A real exclusive
                # prune sees this new file as unowned and cannot delete it.
                with snapshots.cache_lock(self.data, *self.policy.split('/'), exclusive=True):
                    prune_cache(self.data, pin, self.policy, keep=1)
                self.assertTrue((self.data/'mathlab/snapshots'/self.policy/(value+'.pxms')).exists())
            finally:
                release.set(); first.join(3); second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertFalse(failures)
        self.assertEqual(sorted(result['downloaded'] for result in results), [0, 1])
        self.assertEqual(set(cache_records(self.data, self.policy)['snapshots']), {value})

    def test_readiness_requires_actual_exact_baseline_execution(self):
        available = stage_cli.readiness(self.data, self.repo, self.policy)
        self.assertEqual((available['status'], available['baseline_validation']), ('DATA_AVAILABLE', 'NOT_RUN'))
        exact = stage_cli.readiness(self.data, self.repo, self.policy, verify_replay=True)
        self.assertEqual((exact['status'], exact['baseline_validation'], exact['ticks']), ('READY', 'EXACT', 6))
        # A real mismatched recorded outcome must fail; changing a final status flag is not the test.
        folder = self.data/'mathlab/snapshots'/self.policy
        testkit.make_snapshot(folder, self.source, 9, False, '2026-10-28T00:01:00Z')
        failed = stage_cli.readiness(self.data, self.repo, self.policy, verify_replay=True)
        self.assertEqual((failed['status'], failed['baseline_validation']), ('BLOCKED', 'DIVERGED'))

    def test_parameter_adapter_executes_real_worker_and_retains_stage_provenance(self):
        cfg = service.Config({'BOT_ALLOWED_USER_IDS': '1', 'BOT_STATE_DIR': str(self.tmp/'state'),
                              'BOT_REPO': str(self.repo), 'MATHLAB_DATA_DIR': str(self.data)})
        runtime = cfg.dashboard()
        self.assertIsInstance(runtime, StageRuntime)
        request = {'mode': 'REPLAY', 'title': 'stage control', 'policy': self.policy,
                   'parameter_id': 'P-FEA-006', 'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                                                      {'arm_id': 'trial', 'value': 1.5}], 'cohort': {'max_snapshots': 6}}
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        job = runtime.create(request)
        done = runtime.wait_experiment(job['id'])
        self.assertEqual(done['status'], 'COMPLETE')
        self.assertEqual(done['manifest']['stage_provenance']['repository'], stage_scope.REPOSITORY)
        self.assertEqual(len(done['manifest']['cohort']['snapshot_digests']), 6)
        self.assertTrue(runtime.metrics(job['id']))
        self.assertTrue(runtime.artifact(job['id'], 'report.md'))

    def test_pin_change_after_parameter_preflight_is_rejected(self):
        cfg = service.Config({'BOT_ALLOWED_USER_IDS': '1', 'BOT_STATE_DIR': str(self.tmp/'state'),
                              'BOT_REPO': str(self.repo), 'MATHLAB_DATA_DIR': str(self.data)})
        runtime = cfg.dashboard()
        request = {'mode': 'REPLAY', 'policy': self.policy, 'parameter_id': 'P-FEA-006',
                   'arms': [{'arm_id':'control','value_source':'RECORDED_EFFECTIVE'}, {'arm_id':'trial','value':1.5}]}
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        pin = read_json(self.data/'mathlab/stage.json'); pin['brain']['git_sha'] = 'f'*40
        write_json(self.data/'mathlab/stage.json', pin)
        with self.assertRaises(stage_scope.StageError): runtime.create(request)

    def test_missing_pin_after_freeze_blocks_code_and_direct_worker_requests(self):
        entries = self.entries()
        _, control, provenance = stage_scope.validate_run(self.data, self.policy, entries, self.repo)
        request = {'schema_version': 'math-lab.experiment.v1', 'mode': 'REPLAY',
                   'namespace': self.policy.split('/')[0], 'policy': self.policy.split('/')[1],
                   'parameter_id': 'P-FEA-006', 'stage_provenance': provenance,
                   'cohort': {'digests': [entry['digest'] for entry in entries]},
                   'arms': [{'arm_id': 'control', 'value_source': 'RECORDED_EFFECTIVE'},
                            {'arm_id': 'trial', 'value': 1.5}],
                   'base_commit': self.source, 'candidate_commit': self.source}
        self.assertEqual(experiment.preflight(self.data, request, control)['status'], 'PASS')
        (self.data/'mathlab/stage.json').unlink()
        for frozen in (provenance, None, {}):
            request['stage_provenance'] = frozen
            with self.subTest(provenance=frozen):
                check = experiment.preflight(self.data, request, control)
                self.assertEqual(check['status'], 'FAIL')
                self.assertIn('STAGE_SCOPE', {error['error_code'] for error in check['errors']})
                with self.assertRaisesRegex(stage_scope.StageError, 'stage is not pinned'):
                    code_experiment.run(self.data, self.tmp/'missing-pin', request, control, control, control)
        self.assertFalse((self.tmp/'missing-pin/replay.jsonl').exists())

    def test_one_unreplayable_trial_tick_makes_parameter_result_partial(self):
        replay = Path(self.pin['replay']['path'])
        source = replay.read_text()
        # The replay transport fixture models an override asking an unrecorded
        # collaborator question on one captured state. Run the real worker,
        # analysis and export pipeline on those rows.
        source = source.replace("by_status[line['status']] = by_status.get(line['status'], 0) + 1",
            "if arm['arm_id'] == 'trial' and payload['risk'] == 1:\n"
            "            line = {**base, 'status': 'UNREPLAYABLE', 'reasons': ['capability query not recorded']}\n"
            "        by_status[line['status']] = by_status.get(line['status'], 0) + 1")
        replay.write_text(source)
        current = read_json(self.data/'mathlab/bin/current.json')
        current['binary_sha256'] = testkit.hashlib.sha256(replay.read_bytes()).hexdigest()
        write_json(self.data/'mathlab/bin/current.json', current)
        testkit.write_stage_pin(self.data, self.source)
        cfg = service.Config({'BOT_ALLOWED_USER_IDS':'1', 'BOT_STATE_DIR':str(self.tmp/'state'),
                              'BOT_REPO':str(self.repo), 'MATHLAB_DATA_DIR':str(self.data)})
        runtime = cfg.dashboard()
        request = {'mode':'REPLAY','policy':self.policy,'parameter_id':'P-FEA-006',
                   'arms':[{'arm_id':'control','value_source':'RECORDED_EFFECTIVE'},{'arm_id':'trial','value':1.5}]}
        self.assertEqual(runtime.preflight(request)['status'], 'PASS')
        done = runtime.wait_experiment(runtime.create(request)['id'])
        self.assertEqual(done['result']['population']['control_eligible'], 6)
        self.assertEqual(done['result']['population']['matched_by_arm']['trial'], 5)
        self.assertEqual((done['status'],done['result']['state']), ('PARTIAL','PARTIAL'))

    def test_experimental_engine_keeps_true_candidate_source_and_evidence(self):
        (self.repo/'reviewed-change.txt').write_text('experimental endpoint mode')
        testkit.git(self.repo, 'add', 'reviewed-change.txt')
        testkit.git(self.repo, 'commit', '-qm', 'experimental mode')
        candidate_sha = testkit.git(self.repo, 'rev-parse', 'HEAD')
        candidate = testkit.write_fake_replay(self.tmp/'candidate', candidate_sha, 3)
        review = self.tmp/'review.json'; review.write_text(json.dumps({'source':candidate_sha,'result':'PASS','fixture':True}))
        evidence = self.tmp/'tests.log'; evidence.write_text('explicit test-only evidence fixture')
        with self.assertRaisesRegex(stage_scope.StageError, 'structured'):
            stage_cli.install_study_engine(self.data, self.repo, candidate, candidate_sha,
                                            self.pin['replay']['path'], [review, evidence])
        receipt = {'schema':'phorvex-bench.study-engine-review.v1', 'source_revision':candidate_sha,
                   'base_source':self.source, 'result':'PASS', 'reviewer':'independent-test-fixture',
                   'candidate_binary_sha256':testkit.hashlib.sha256(candidate.read_bytes()).hexdigest(),
                   'base_binary_sha256':self.pin['replay']['binary_sha256'],
                   'evidence_sha256':[testkit.hashlib.sha256(evidence.read_bytes()).hexdigest()]}
        review.write_text(json.dumps({**receipt, 'candidate_binary_sha256':'f'*64}))
        with self.assertRaisesRegex(stage_scope.StageError, 'exact source revisions'):
            stage_cli.install_study_engine(self.data, self.repo, candidate, candidate_sha,
                                            self.pin['replay']['path'], [review, evidence])
        review.write_text(json.dumps(receipt))
        installed = stage_cli.install_study_engine(self.data, self.repo, candidate, candidate_sha,
                                                   self.pin['replay']['path'], [review,evidence])
        self.assertEqual(installed['base_source'], self.source)
        self.assertEqual(installed['candidate']['git_sha'], candidate_sha)
        self.assertNotEqual(installed['candidate']['git_sha'], self.source)
        self.assertEqual(stage_scope.study_engine(self.data)['source_revision'], candidate_sha)
        # Independently retained review bytes are immutable inputs to the pin.
        Path(installed['review_evidence'][0]['path']).write_text('changed')
        with self.assertRaisesRegex(stage_scope.StageError,'review evidence changed'):
            stage_scope.study_engine(self.data)

    def test_experimental_engine_rejects_spoofed_source_and_missing_review(self):
        candidate = testkit.write_fake_replay(self.tmp/'candidate', 'f'*40, 3)
        review = self.tmp/'review.json'; review.write_text('{}')
        with self.assertRaisesRegex(stage_scope.StageError,'actual declared source'):
            stage_cli.install_study_engine(self.data, self.repo, candidate, self.source, self.pin['replay']['path'], [review])
        with self.assertRaisesRegex(stage_scope.StageError,'review evidence are required'):
            stage_cli.install_study_engine(self.data, self.repo, candidate, self.source, self.pin['replay']['path'], [])


class RunningStageImageTest(unittest.TestCase):
    def fixtures(self):
        image = '000000000000.dkr.ecr.test.amazonaws.com/phorvex/staging/brain:staging-1-git-'+'a'*40+'@sha256:'+'e'*64
        dep = {'metadata': {'uid':'dep','generation':3,'annotations':{'deployment.kubernetes.io/revision':'3'}},
               'spec': {'replicas':1,'template': {'spec': {'containers':[{'name':'brain','image':image}]}}},
               'status': {'observedGeneration':3,'replicas':1,'updatedReplicas':1,'readyReplicas':1,'availableReplicas':1}}
        rs = {'items':[{'metadata':{'uid':'rs','annotations':{'deployment.kubernetes.io/revision':'3'},
                                   'ownerReferences':[{'uid':'dep','controller':True}]}}]}
        pods = {'items':[{'metadata':{'name':'pod','uid':'pod-uid','ownerReferences':[{'uid':'rs','controller':True}]},
                         'status': {'phase':'Running','containerStatuses':[{'name':'sidecar','ready':True,'imageID':'irrelevant'},
                                    {'name':'brain','ready':True,'imageID':image}]}}]}
        return dep, rs, pods

    def test_resolves_container_by_name_and_proves_embedded_source(self):
        dep, rs, pods = self.fixtures()
        with mock.patch.object(stage_cli, 'kube', side_effect=[dep,rs,pods,{'service':'brain','gitSHA':'a'*40}]) as kube:
            actual = stage_cli.running_image('explicit-context','phorvex-staging','staging-brain','brain')
        self.assertEqual(actual['git_sha'], 'a'*40)
        self.assertEqual(kube.call_args.args, ('explicit-context','phorvex-staging','exec','pod','-c','brain','--','/service','--version'))

    def test_partial_rollout_old_replicaset_and_false_source_are_rejected(self):
        dep, rs, pods = self.fixtures()
        bad = copy.deepcopy(dep); bad['spec']['replicas'] = 3
        with mock.patch.object(stage_cli, 'kube', return_value=bad), self.assertRaisesRegex(stage_scope.StageError,'rollout is incomplete'):
            stage_cli.running_image('ctx','phorvex-staging','staging-brain','brain')

        rs['items'][0]['metadata']['annotations']['deployment.kubernetes.io/revision']='2'
        with mock.patch.object(stage_cli, 'kube', side_effect=[dep,rs,pods]), self.assertRaises(stage_scope.StageError):
            stage_cli.running_image('ctx','phorvex-staging','staging-brain','brain')
        dep,rs,pods=self.fixtures()
        with mock.patch.object(stage_cli, 'kube', side_effect=[dep,rs,pods,{'service':'brain','gitSHA':'b'*40}]), self.assertRaisesRegex(stage_scope.StageError,'embedded source'):
            stage_cli.running_image('ctx','phorvex-staging','staging-brain','brain')

class StageConsoleScopeTest(unittest.TestCase):
    def test_explicit_stage_context_and_short_token_ignore_ambient_production_endpoint(self):
        minted = mock.Mock(returncode=0, stdout='private-fixture-token\n')
        def forward(console): console.url = 'http://127.0.0.1:8123'
        with mock.patch.dict('os.environ', {'CONSOLE_URL':'https://production.invalid', 'CONSOLE_TOKEN':'production-secret'}), \
             mock.patch('runner.subprocess.run', return_value=minted) as run, \
             mock.patch.object(Console, 'start_forward', forward):
            console = Console(kube_context='explicit-stage-context', namespace='phorvex-staging',
                              service='staging-phorvex-console', token_service_account='staging-brain-benchmark',
                              use_environment=False, token_audience='phorvex-staging-console', token_duration='10m')
        self.assertEqual(console.url, 'http://127.0.0.1:8123')
        self.assertEqual(console.token, 'private-fixture-token')
        self.assertEqual(run.call_args.args[0], ['kubectl','--context','explicit-stage-context','-n','phorvex-staging',
            'create','token','staging-brain-benchmark','--audience=phorvex-staging-console','--duration=10m'])
        console.close()

    def test_failed_forward_constructor_releases_owned_transport(self):
        with mock.patch('runner.subprocess.run', return_value=mock.Mock(returncode=0, stdout='token')), \
             mock.patch.object(Console,'start_forward',side_effect=TransportError('owned forward failed')), \
             mock.patch.object(Console,'close') as close, self.assertRaises(TransportError):
            Console(kube_context='stage', namespace='phorvex-staging', use_environment=False)
        close.assert_called_once()



if __name__ == '__main__': unittest.main()
