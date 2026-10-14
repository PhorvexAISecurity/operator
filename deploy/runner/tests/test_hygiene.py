#!/usr/bin/python3
"""Disposable exact-object engine and process fixtures; never connect to Docker/SSH."""
import contextlib
import fcntl
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

OWN = Path(__file__).resolve().parents[1]


def load(name, file):
    loader = importlib.machinery.SourceFileLoader(name, str(file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


h = load('hygiene', OWN / 'phvx-disk-hygiene')
hook = load('hook', OWN / 'phvx-runner-job-completed')
BOUND = {'repository': 'PhorvexSecurity/operator', 'run_id': 42, 'run_attempt': 1}
BUILDER = 'builder-01234567-89ab-cdef-0123-456789abcdef'
CID = '1' * 64
OTHER = '2' * 64


def api(bound=BOUND, status='completed', conclusion='success', runner=130):
    run = {'repository': {'full_name': bound['repository']}, 'id': bound['run_id'],
           'run_attempt': bound['run_attempt'], 'status': status, 'conclusion': conclusion,
           'url': 'https://api.github.com/repos/' + bound['repository'] + '/actions/runs/' + str(bound['run_id'])}
    jobs = {'total_count': 1, 'jobs': [{'id': 91, 'run_id': bound['run_id'],
        'run_attempt': bound['run_attempt'], 'runner_id': runner, 'status': status,
        'conclusion': conclusion, 'started_at': '2026-10-14T00:00:00Z',
        'completed_at': '2026-10-14T01:00:00Z' if status == 'completed' else None}]}
    return run, jobs


class FakeOps:
    def __init__(self, directory):
        self.directory = directory
        self.containers, self.volumes, self.extra = {}, {}, {}
        self.identity = {'id': 'rootful-test-daemon', 'root': '/var/lib/docker', 'socket_dev': 1, 'socket_ino': 2}
        self.calls = []
        self.sizes = {}
        self.fail = None
        self.api_records = {('PhorvexSecurity/operator', 42, 1): api()}
        self.on_snapshot = None
        self.expired = False

    def remaining(self):
        if self.expired:
            raise h.Refuse('deadline reached')
        return 50

    def daemon(self):
        self.calls.append(('daemon',))
        if self.on_snapshot:
            self.on_snapshot()
        return copy.deepcopy(self.identity)

    def container(self, name):
        self.calls.append(('container', name))
        return copy.deepcopy(self.containers.get(name))

    def volume(self, name):
        self.calls.append(('volume', name))
        return copy.deepcopy(self.volumes.get(name))

    def attachments(self, name):
        self.calls.append(('attachments', name))
        return sorted([c['id'] for c in self.containers.values() if any(m['Name'] == name for m in c['mounts'])] + self.extra.get(name, []))

    def size(self, name):
        return self.sizes.get(name, 9 * 1024**3)

    def api(self, repository, run_id, attempt, use_gh=False):
        self.calls.append(('api', repository, run_id, attempt, use_gh))
        value = self.api_records[(repository, run_id, attempt)]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def remove_builder(self, builder):
        self.calls.append(('remove_builder', builder))
        cname = 'buildx_buildkit_' + builder + '0'
        vname = cname + '_state'
        if self.fail == 'before':
            raise h.Refuse('injected command failure')
        had_container = self.containers.pop(cname, None) is not None
        if self.fail == 'container-only':
            raise h.Refuse('injected partial removal')
        (self.directory / builder).unlink(missing_ok=True)
        if had_container and self.fail not in {'volume-left', 'metadata-only'}:
            self.volumes.pop(vname, None)
        if self.fail == 'metadata-only':
            self.containers[cname] = self.original_container

    def stop_container(self, cid):
        self.calls.append(('stop_container', cid))
        for container in self.containers.values():
            if container['id'] == cid:
                container['running'] = False
                return
        raise h.Refuse('exact container absent')

    def remove_container(self, cid):
        self.calls.append(('remove_container', cid))
        for name, container in list(self.containers.items()):
            if container['id'] == cid and not container['running']:
                del self.containers[name]
                return
        raise h.Refuse('exact container running/absent')

    def remove_volume(self, name):
        self.calls.append(('remove_volume', name))
        if self.attachments(name):
            raise h.Refuse('volume in use')
        if self.fail == 'volume-rm':
            raise h.Refuse('volume rm failure')
        del self.volumes[name]


class Fixture(unittest.TestCase):
    def setUp(self):
        # Safe directory parents, unlike globally writable /tmp; fully removed in tearDown.
        self.tmp = tempfile.TemporaryDirectory(prefix='.fixture-', dir=OWN / 'tests')
        self.root = Path(self.tmp.name)
        self.instances, self.diag, self.state = [self.root / item for item in ('instances', 'diag', 'state')]
        for path in (self.instances, self.diag, self.state):
            path.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.cgroups = self.root / 'cgroups'
        for group in h.RUNNER_GROUPS:
            directory = self.cgroups / group.lstrip('/')
            directory.mkdir(parents=True)
            (directory / 'cgroup.procs').write_text('')
        original_safe_dir = h.safe_dir
        original_fstat = os.fstat
        # This workspace has two group-writable ancestors. Model secure production
        # ancestors only; every actual fixture component/file retains real permissions.
        workspace_ancestors = {((OWN.parents[4]).stat().st_dev, (OWN.parents[4]).stat().st_ino),
                               ((OWN.parents[5]).stat().st_dev, (OWN.parents[5]).stat().st_ino)}
        def fixture_fstat(fd):
            value = original_fstat(fd)
            if (value.st_dev, value.st_ino) in workspace_ancestors:
                return SimpleNamespace(st_uid=value.st_uid, st_gid=value.st_gid, st_mode=value.st_mode & ~0o022)
            return value
        def fixture_safe_dir(path, uid=None, metadata_only=False):
            with patch.object(h.os, 'fstat', side_effect=fixture_fstat):
                return original_safe_dir(path, uid, metadata_only)
        self.patches = [patch.object(h, 'profile_context', side_effect=lambda p: contextlib.nullcontext()),
                        patch.object(h.profiles_lib, 'worker_profile', return_value=h.profiles_lib.APPROVED[0]),
                        patch.object(h.profiles_lib, 'cleanup_lock', side_effect=lambda uid: contextlib.nullcontext()),
                        patch.object(h, 'process_table', return_value={}),
                        patch.object(h, 'HOME', str(self.root)), patch.object(h, 'INSTANCES', str(self.instances)), patch.object(h, 'DIAG', str(self.diag)),
                        patch.object(h, 'RUNNER_BIN', str(self.root) + '/actions-runner/bin/'),
                        patch.object(h, 'safe_dir', side_effect=fixture_safe_dir),
                        patch.object(h, 'CGROUP_ROOT', str(self.cgroups)),
                        patch.object(h, 'runner_service', return_value=(0, ''))]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])
        self.ops = FakeOps(self.instances)
        self.config = dict(h.DEFAULT_CONFIG, timer_orphan_live=True)
        self.store = h.Store(str(self.state), self.uid, 512).__enter__()
        self.engine = h.Hygiene(self.store, self.ops, self.uid, self.config, gate=self.gate)
        self.gate_calls = 0
        self.gate_failure = None
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.create_builder()
        (self.diag / 'Runner_20261014-000000-utc.log').write_text('Running job: build\nJob build completed with result: Succeeded\n')

    def tearDown(self):
        self.redirect.__exit__(None, None, None)
        self.store.__exit__(None, None, None)
        self.tmp.cleanup()

    def gate(self, uid, mode, current):
        self.gate_calls += 1
        if self.gate_failure:
            raise h.Refuse(self.gate_failure)
        return {'idle': True}

    def create_builder(self, builder=BUILDER, cid=CID, container=True):
        cname = 'buildx_buildkit_' + builder + '0'
        vname = cname + '_state'
        (self.instances / builder).write_text(json.dumps({'Name': builder, 'Driver': 'docker-container',
            'Nodes': [{'Name': builder + '0', 'Endpoint': h.ENDPOINT}], 'Dynamic': False}))
        volume = {'name': vname, 'created': '2026-10-14T00:01:00Z', 'driver': 'local', 'scope': 'local',
                  'options': None, 'labels': None, 'mountpoint': '/var/lib/docker/volumes/' + vname + '/_data'}
        if container:
            self.ops.containers[cname] = {'id': cid, 'name': cname, 'created': '2026-10-14T00:01:00Z',
                'image': 'sha256:' + 'a' * 64, 'mounts': [{'Name': vname, 'Type': 'volume',
                'Destination': '/var/lib/buildkit'}], 'running': True}
        self.ops.volumes[vname] = volume
        return cname, vname

    def register(self, builder=BUILDER, bound=BOUND):
        self.engine.register(bound, builder, bound)
        self.engine.refresh(bound['repository'])

    def record(self):
        return self.store.registry()['entries'][0]

    def edit_record(self, edit):
        registry = self.store.registry()
        edit(registry['entries'][0])
        self.store.write('registry.json', registry)

    def removals(self):
        return [call for call in self.ops.calls if call[0].startswith(('remove_', 'stop_'))]

    def assert_no_removal(self, current=None, dry_run=False):
        self.engine.sweep('timer', current, dry_run)
        self.assertEqual(self.removals(), [])
        self.assertTrue((self.instances / BUILDER).exists())
        self.assertIn('buildx_buildkit_' + BUILDER + '0_state', self.ops.volumes)

    def seed_manifest(self):
        expected = self.engine.snapshot(BUILDER)
        return {'schema': 1, 'entries': [{**BOUND, 'builder': BUILDER,
            'job_id': 91, 'runner_id': 130, 'expected': expected}]}

    def test_cancelled_completed_attempt_reclaimed_over_four_gib(self):
        self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = api(conclusion='cancelled')
        self.register()
        self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER)])
        self.assertTrue(self.record()['removed'])
        self.assertEqual(self.record()['reclaimed_upper_bound_bytes'], 9 * 1024**3)
        self.assertGreaterEqual(self.gate_calls, 6)
        self.assertFalse((self.instances / BUILDER).exists())
        self.assertEqual(self.ops.volumes, {})
        self.assertIn('"object": "volume"', self.output.getvalue())

    def test_multiple_completed_builders_no_one_builder_limit(self):
        second = 'builder-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.create_builder(second, OTHER)
        self.register()
        self.register(second)
        self.engine.sweep('timer', None, False)
        self.assertEqual(len(self.removals()), 2)
        self.assertTrue(all(e['removed'] for e in self.store.registry()['entries']))

    def test_stale_instance_without_container_exact_volume_recovery(self):
        self.ops.containers.clear()
        manifest = self.seed_manifest()
        self.engine.seed(manifest, {'schema': 1, 'records': [{'run': api()[0], 'jobs': api()[1]}]})
        self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER), ('remove_volume', 'buildx_buildkit_' + BUILDER + '0_state')])
        self.assertTrue(self.record()['removed'])

    def test_partial_container_removal_retry_keeps_exact_volume_identity(self):
        self.register()
        self.ops.fail = 'container-only'
        self.engine.sweep('timer', None, False)
        self.assertFalse(self.record()['removed'])
        self.assertTrue((self.instances / BUILDER).exists())
        self.ops.fail = None
        self.engine.sweep('timer', None, False)
        self.assertTrue(self.record()['removed'])
        self.assertIn(('remove_volume', 'buildx_buildkit_' + BUILDER + '0_state'), self.removals())

    def test_partial_metadata_only_recovers_exact_registered_container(self):
        self.register()
        self.ops.original_container = copy.deepcopy(next(iter(self.ops.containers.values())))
        self.ops.fail = 'metadata-only'
        self.engine.sweep('timer', None, False)
        self.assertTrue(self.record()['removed'])
        self.assertEqual(self.removals(), [('remove_builder', BUILDER), ('stop_container', CID),
            ('remove_container', CID), ('remove_volume', 'buildx_buildkit_' + BUILDER + '0_state')])

    def test_partial_metadata_then_container_replaced_never_stops_new_container(self):
        self.register()
        self.ops.original_container = copy.deepcopy(next(iter(self.ops.containers.values())))
        self.ops.original_container['id'] = OTHER
        self.ops.fail = 'metadata-only'
        self.engine.sweep('timer', None, False)
        self.assertFalse(self.record()['removed'])
        self.assertEqual(self.removals(), [('remove_builder', BUILDER)])
        self.assertEqual(next(iter(self.ops.containers.values()))['id'], OTHER)

    def test_failed_volume_removal_then_later_exact_recovery(self):
        self.ops.containers.clear()
        self.engine.seed(self.seed_manifest(), {'schema': 1, 'records': [{'run': api()[0], 'jobs': api()[1]}]})
        self.ops.fail = 'volume-rm'
        self.engine.sweep('timer', None, False)
        self.assertFalse(self.record()['removed'])
        self.ops.fail = None
        self.engine.sweep('timer', None, False)
        self.assertTrue(self.record()['removed'])

    def test_nonterminal_is_excluded(self):
        self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = api(status='in_progress', conclusion=None)
        self.register()
        self.assert_no_removal()

    def test_current_attempt_is_excluded_even_if_api_completed(self):
        self.register()
        self.assert_no_removal(current=BOUND)

    def test_missing_provenance_excluded(self):
        self.engine.register(BOUND, BUILDER, BOUND)
        self.assert_no_removal()

    def test_caller_completion_flag_is_not_evidence(self):
        self.engine.register(BOUND, BUILDER, BOUND)
        self.edit_record(lambda e: e.update(evidence={**BOUND, 'status': 'completed', 'terminal': True}))
        self.assert_no_removal()

    def test_verified_wrong_attempt_excluded(self):
        self.register()
        self.edit_record(lambda e: e['evidence'].update(run_attempt=2))
        self.assert_no_removal()

    def test_unknown_builder_and_ptest_volume_survive(self):
        unknown = 'builder-ffffffff-1111-2222-3333-444444444444'
        self.create_builder(unknown, OTHER)
        self.ops.volumes['ptest-keep_state'] = {'name': 'ptest-keep_state'}
        self.register()
        self.engine.sweep('timer', None, False)
        self.assertTrue((self.instances / unknown).exists())
        self.assertIn('ptest-keep_state', self.ops.volumes)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER)])

    def test_filesystem_sources_workspaces_logs_and_rootless_fixture_survive(self):
        protected = []
        for relative in ('home/mehrdad/data', 'home/github-runner/actions-runner/_work/operator/.git/HEAD',
                         'home/github-runner/actions-runner/_work/_temp/in-use', 'tmp/shared', 'dev/shm/shared',
                         'rootless/volumes/cache', 'runner/.credentials', 'diag/Worker_20261001.log'):
            file = self.root / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('protected\n')
            protected.append((file, file.read_bytes(), file.stat().st_ino))
        self.register()
        self.engine.sweep('timer', None, False)
        for file, data, inode in protected:
            self.assertEqual(file.read_bytes(), data)
            self.assertEqual(file.stat().st_ino, inode)

    def test_attachment_to_stopped_or_other_container_excluded(self):
        self.register()
        self.ops.extra['buildx_buildkit_' + BUILDER + '0_state'] = [OTHER]
        self.assert_no_removal()

    def test_attachment_races_first_destructive_call(self):
        self.register()
        original = self.ops.size
        def race(name):
            self.ops.extra[name] = [OTHER]
            return original(name)
        self.ops.size = race
        self.assert_no_removal()

    def test_worker_races_first_destructive_call(self):
        self.register()
        def race(name):
            self.gate_failure = 'Runner.Worker appeared'
            return 9 * 1024**3
        self.ops.size = race
        self.assert_no_removal()

    def test_worker_appears_during_identity_recheck(self):
        self.register()
        self.ops.on_snapshot = lambda: setattr(self, 'gate_failure', 'Worker appeared during inspection')
        self.assert_no_removal()

    def test_worker_between_buildx_removal_and_volume_rm(self):
        self.ops.containers.clear()
        self.engine.seed(self.seed_manifest(), {'schema': 1, 'records': [{'run': api()[0], 'jobs': api()[1]}]})
        original = self.ops.remove_builder
        def race(builder):
            original(builder)
            self.gate_failure = 'new Worker'
        self.ops.remove_builder = race
        self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER)])
        self.assertIn('buildx_buildkit_' + BUILDER + '0_state', self.ops.volumes)
        self.assertFalse(self.record()['removed'])

    def test_container_identity_drift_excluded(self):
        self.register()
        next(iter(self.ops.containers.values()))['id'] = OTHER
        self.assert_no_removal()

    def test_volume_creation_drift_excluded(self):
        self.register()
        next(iter(self.ops.volumes.values()))['created'] = '2026-10-14T02:00:00Z'
        self.assert_no_removal()

    def test_daemon_socket_identity_drift_excluded(self):
        self.register()
        self.ops.identity['socket_ino'] += 1
        self.assert_no_removal()

    def test_instance_inode_drift_excluded(self):
        self.register()
        path = self.instances / BUILDER
        data = path.read_bytes()
        replacement = self.instances / 'replacement'
        replacement.write_bytes(data)
        replacement.replace(path)
        self.assert_no_removal()

    def test_instance_symlink_does_not_follow_or_touch_target(self):
        self.register()
        path = self.instances / BUILDER
        path.unlink()
        target = self.root / 'protected'
        target.write_text('must survive')
        path.symlink_to(target)
        self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [])
        self.assertEqual(target.read_text(), 'must survive')

    def test_parent_symlink_excluded(self):
        self.register()
        self.instances.rename(self.root / 'other-instances')
        self.instances.symlink_to(self.root / 'other-instances', target_is_directory=True)
        self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [])

    def test_instance_endpoint_drift_excluded(self):
        self.register()
        path = self.instances / BUILDER
        value = json.loads(path.read_text())
        value['Nodes'][0]['Endpoint'] = 'unix:///run/user/1001/docker.sock'
        path.write_text(json.dumps(value))
        self.assert_no_removal()

    def test_dry_run_overrides_live_config_no_cache_or_registry_mutation(self):
        self.register()
        before = (self.state / 'registry.json').read_bytes()
        self.assert_no_removal(dry_run=True)
        self.assertEqual(before, (self.state / 'registry.json').read_bytes())
        self.assertFalse((self.state / 'pending.json').exists())

    def test_initial_config_is_report_only(self):
        self.register()
        self.config['timer_orphan_live'] = False
        self.assert_no_removal()

    def test_hook_remains_dry_until_ordering_proven(self):
        self.register()
        self.config['hook_orphan_live'] = True
        current = dict(BOUND, run_id=43)
        self.engine.sweep('hook', current, False)
        self.assertEqual(self.removals(), [])
        self.config['hook_ordering_verified'] = True
        self.engine.sweep('hook', current, False)
        self.assertTrue(self.record()['removed'])

    def test_registration_rebinding_rejected(self):
        self.register()
        new = dict(BOUND, run_id=43)
        with self.assertRaises(h.Refuse):
            self.engine.register(new, BUILDER, new)

    def test_registration_requires_current_identity_and_all_objects(self):
        with self.assertRaises(h.Refuse):
            self.engine.register(BOUND, BUILDER, None)
        self.ops.containers.clear()
        with self.assertRaises(h.Refuse):
            self.engine.register(BOUND, BUILDER, BOUND)

    def test_refresh_queries_exact_attempt_and_never_changes_identities(self):
        self.engine.register(BOUND, BUILDER, BOUND)
        identities = copy.deepcopy(self.record()['identities'])
        self.engine.refresh(BOUND['repository'])
        self.assertIn(('api', BOUND['repository'], 42, 1, False), self.ops.calls)
        self.assertEqual(self.record()['identities'], identities)

    def test_refresh_api_failure_revokes_evidence(self):
        # Nonterminal evidence must be revoked; terminal completion is monotonic.
        self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = api(status='in_progress', conclusion=None)
        self.register()
        self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = h.Refuse('API error')
        with self.assertRaises(h.Refuse):
            self.engine.refresh(BOUND['repository'])
        self.assertIsNone(self.record()['evidence'])
        self.assert_no_removal()

    def test_legacy_seed_requires_exact_attested_identity(self):
        manifest = self.seed_manifest()
        manifest['entries'][0]['expected']['volume']['created'] = 'wrong'
        with self.assertRaises(h.Refuse):
            self.engine.seed(manifest, {'schema': 1, 'records': [{'run': api()[0], 'jobs': api()[1]}]})
        self.assertEqual(self.store.registry()['entries'], [])

    def test_legacy_seed_queries_existing_gh_exact_attempt(self):
        self.engine.seed(self.seed_manifest(), use_gh=True)
        self.assertIn(('api', BOUND['repository'], 42, 1, True), self.ops.calls)
        self.assertEqual(self.record()['job_id'], 91)

    def test_lock_contention_is_nonblocking_and_no_mutation(self):
        started = time.monotonic()
        with self.assertRaises(h.Busy):
            with h.Store(str(self.state), self.uid, 512):
                self.fail('unexpected lock acquisition')
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(self.removals(), [])

    def test_lock_inode_replacement_before_mutation_refuses(self):
        self.register()
        (self.state / 'lock').unlink()
        (self.state / 'lock').touch(mode=0o600)
        self.engine.sweep('timer', None, True)
        self.assertEqual(self.removals(), [])

    def test_registry_symlink_rejected(self):
        target = self.root / 'protected'
        target.write_text('protected')
        (self.state / 'registry.json').symlink_to(target)
        with self.assertRaises(OSError):
            self.store.registry()
        self.assertEqual(target.read_text(), 'protected')

    def test_byte_accounting_error_does_not_create_a_size_gate(self):
        self.register()
        def unavailable(name):
            raise OSError('metadata timeout')
        self.ops.size = unavailable
        self.engine.sweep('timer', None, False)
        self.assertTrue(self.record()['removed'])
        self.assertIsNone(self.record()['reclaimed_upper_bound_bytes'])
        self.assertIn('byte-accounting-unavailable', self.output.getvalue())

    def test_instance_mount_boundary_rejected(self):
        original = h.mount_id
        def mounted(fd):
            value = original(fd)
            return value + 1 if os.readlink('/proc/self/fd/' + str(fd)) == str(self.instances) else value
        with patch.object(h, 'mount_id', side_effect=mounted), self.assertRaises(h.Refuse):
            self.engine.snapshot(BUILDER)

    def test_expired_deadline_defers_all_mutation(self):
        self.register()
        self.ops.expired = True
        self.assert_no_removal()

    def test_timer_uses_real_matching_local_logs_and_rejects_worker(self):
        self.engine.gate = h.local_gate
        with patch.object(h, 'process_table', return_value={}):
            self.assertEqual(h.local_gate(self.uid, 'timer', None)['latest_job'], 'build')
            self.register()
            worker = {'pid': 123, 'ppid': 1, 'exe': h.RUNNER_BIN + 'Runner.Worker', 'uid': self.uid}
            with patch.object(h, 'process_table', return_value={123: worker}):
                self.assert_no_removal()

    def test_unmatched_latest_log_excluded(self):
        self.register()
        self.engine.gate = h.local_gate
        (self.diag / 'Runner_20261014-000000-utc.log').write_text('Running job: build\nJob other completed with result: Succeeded\n')
        with patch.object(h, 'process_table', return_value={}):
            self.assert_no_removal()

    def test_latest_running_job_rejects_older_matching_completion(self):
        self.register()
        self.engine.gate = h.local_gate
        (self.diag / 'Runner_20261014-000000-utc.log').write_text('Running job: old\nJob old completed with result: Succeeded\nRunning job: new\n')
        with patch.object(h, 'process_table', return_value={}):
            self.assert_no_removal()

    def test_large_active_log_is_read_with_bounded_tail(self):
        file = self.diag / 'Runner_20261014-000000-utc.log'
        file.write_text('earlier diagnostic metadata\n' * 400000 + 'Running job: build\nJob build completed with result: Succeeded\n')
        self.assertGreater(file.stat().st_size, h.MAX_BYTES)
        self.assertEqual(h.latest_job_logs(self.uid)['completed'], 'build')

    def test_new_empty_probe_log_does_not_hide_latest_job_records(self):
        (self.diag / 'Runner_20261014-010000-utc.log').write_text('Listening for Jobs\n')
        self.assertEqual(h.latest_job_logs(self.uid)['latest_job'], 'build')

    def test_active_listener_log_without_jobs_cannot_reuse_prior_completion(self):
        file = self.diag / 'Runner_20261014-010000-utc.log'
        file.write_text('Listening for Jobs\n')
        opened = open(file)
        try:
            class Item:
                path = '/proc/self/fd/' + str(opened.fileno())
            original_scandir = h.os.scandir
            def scandir(path):
                return iter([Item()]) if path == '/proc/999999/fd' else original_scandir(path)
            with patch.object(h.os, 'scandir', side_effect=scandir), self.assertRaises(h.Refuse):
                h.latest_job_logs(self.uid, {'pid': 999999})
        finally:
            opened.close()

    def test_builder_creation_outside_exact_job_interval_excluded(self):
        self.register()
        self.edit_record(lambda e: e['evidence']['jobs'][0].update(started_at='2026-10-14T02:00:00Z'))
        self.assert_no_removal()

    def test_group_writable_diag_read_only_but_instance_group_write_rejected(self):
        self.diag.chmod(0o775)
        self.assertEqual(h.latest_job_logs(self.uid)['latest_job'], 'build')
        self.instances.chmod(0o775)
        with self.assertRaises(h.Refuse):
            self.engine.snapshot(BUILDER)

    def test_hook_validates_single_expected_worker_ancestry(self):
        listener = {'pid': 10, 'ppid': 1, 'exe': h.RUNNER_BIN + 'Runner.Listener', 'uid': self.uid, 'cgroup': 'ci'}
        worker = {'pid': 20, 'ppid': 10, 'exe': h.RUNNER_BIN + 'Runner.Worker', 'uid': self.uid, 'cgroup': 'ci', 'start': 123}
        helper = {'pid': os.getpid(), 'ppid': 20, 'exe': '/usr/bin/python3', 'uid': self.uid, 'cgroup': 'ci'}
        table = {10: listener, 20: worker, os.getpid(): helper}
        with patch.object(h, 'process_table', return_value=table):
            self.assertEqual(h.local_gate(self.uid, 'hook', BOUND)['worker_pid'], 20)
        table[30] = dict(worker, pid=30)
        with patch.object(h, 'process_table', return_value=table), self.assertRaises(h.Refuse):
            h.local_gate(self.uid, 'hook', BOUND)

    def test_manual_request_then_report_uses_cli_without_any_docker_mutation(self):
        state = self.root / 'cli-state'
        state.mkdir(mode=0o700)
        account = SimpleNamespace(pw_uid=self.uid, pw_gid=os.getgid())
        with patch.object(h, 'STATE', str(state)), patch.object(h.pwd, 'getpwnam', return_value=account), patch.object(h, 'trusted_json', return_value=self.config), patch.dict(os.environ, {}, clear=True):
            with patch.object(h.sys, 'argv', ['phvx-disk-hygiene', 'request']):
                self.assertEqual(h.main(), 0)
            self.assertTrue((state / 'pending.json').exists())
            before = (state / 'pending.json').read_bytes()
            with patch.object(h.sys, 'argv', ['phvx-disk-hygiene', 'report']):
                self.assertEqual(h.main(), 0)
            self.assertEqual((state / 'pending.json').read_bytes(), before)
        self.assertEqual(self.removals(), [])

    def test_timer_rejects_surviving_listener_job_descendants(self):
        table = {10: {'pid': 10, 'ppid': 1, 'exe': h.RUNNER_BIN + 'Runner.Listener', 'uid': self.uid},
                 20: {'pid': 20, 'ppid': 10, 'exe': '/usr/bin/buildctl', 'uid': self.uid}}
        with patch.object(h, 'process_table', return_value=table), self.assertRaises(h.Refuse):
            h.local_gate(self.uid, 'timer', None)

    def cgroup_write(self, group, pids, nested=''):
        directory = self.cgroups / group.lstrip('/')
        directory.mkdir(parents=True, exist_ok=True)
        if not (directory / 'cgroup.procs').exists():
            (directory / 'cgroup.procs').write_text('')
        for part in nested.split('/') if nested else []:
            directory /= part
            directory.mkdir(exist_ok=True)
            (directory / 'cgroup.procs').touch(exist_ok=True)
        (directory / 'cgroup.procs').write_text(''.join(str(pid) + '\n' for pid in pids))

    def clear_cgroup_pids(self):
        for file in self.cgroups.rglob('cgroup.procs'):
            file.write_text('')

    def service_tree(self, group, wrapper=True):
        self.clear_cgroup_pids()
        root = h.HOME + '/actions-runner'
        table = {
            10: {'pid': 10, 'ppid': 9, 'exe': h.RUNNER_BIN + 'Runner.Listener', 'uid': self.uid, 'cgroup': '0::' + group + '\n'},
            9: {'pid': 9, 'ppid': 8 if wrapper else 1, 'exe': root + '/externals/node20/bin/node',
                'uid': self.uid, 'cgroup': '0::' + group + '\n', 'argv': [b'./externals/node20/bin/node', b'./bin/RunnerService.js'], 'cwd': root}}
        if wrapper:
            table[8] = {'pid': 8, 'ppid': 1, 'exe': '/usr/bin/bash', 'uid': self.uid,
                'cgroup': '0::' + group + '\n', 'argv': [b'/bin/bash', (root + '/runsvc.sh').encode()], 'cwd': root}
        self.cgroup_write(group, table)
        return table

    def test_timer_accepts_only_verified_service_tree_both_topologies(self):
        for group in h.RUNNER_GROUPS:
            for wrapper in (True, False):
                with self.subTest(group=group, wrapper=wrapper):
                    for known in h.RUNNER_GROUPS:
                        self.cgroup_write(known, [])
                    table = self.service_tree(group, wrapper)
                    with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(8 if wrapper else 9, group)), patch.object(h, 'latest_job_logs', return_value={'completed': 'build'}):
                        self.assertEqual(h.local_gate(self.uid, 'timer', None)['completed'], 'build')

    def test_timer_rejects_adopted_docker_buildx_clients_in_root_and_nested_cgroups(self):
        group = h.RUNNER_GROUPS[1]
        for executable in ('/usr/bin/docker', '/usr/libexec/docker/cli-plugins/docker-buildx'):
            for nested in ('', 'job/export'):
                with self.subTest(executable=executable, nested=nested):
                    table = self.service_tree(group)
                    table[40] = {'pid': 40, 'ppid': 1, 'exe': executable, 'uid': self.uid,
                        'cgroup': '0::' + group + ('/' + nested if nested else '') + '\n'}
                    self.cgroup_write(group, table if not nested else [40], nested)
                    with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(8, group)), patch.object(h, 'latest_job_logs', return_value={'completed': 'build'}), self.assertRaisesRegex(h.Refuse, 'unclassified'):
                        h.local_gate(self.uid, 'timer', None)

    def test_stopped_listener_populated_old_new_or_nested_cgroup_defers(self):
        for group in h.RUNNER_GROUPS:
            for nested in ('', 'job'):
                with self.subTest(group=group, nested=nested):
                    self.clear_cgroup_pids()
                    self.cgroup_write(group, [40], nested)
                    # PID absent from /proc table must still defer, including permission/race cases.
                    with patch.object(h, 'process_table', return_value={}), self.assertRaisesRegex(h.Refuse, 'stopped listener.*populated'):
                        h.local_gate(self.uid, 'timer', None)

    def test_runner_cgroup_census_checks_actual_service_path_and_both_known_paths(self):
        actual = '/custom.slice/' + h.RUNNER_UNIT
        self.cgroup_write(actual, [40], 'nested')
        with patch.object(h, 'process_table', return_value={}), patch.object(h, 'runner_service', return_value=(0, actual)), self.assertRaises(h.Refuse):
            h.local_gate(self.uid, 'timer', None)
        table = self.service_tree(h.RUNNER_GROUPS[1])
        self.cgroup_write(h.RUNNER_GROUPS[0], [40])
        with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(8, h.RUNNER_GROUPS[1])), self.assertRaisesRegex(h.Refuse, 'unclassified'):
            h.local_gate(self.uid, 'timer', None)

    def test_timer_rejects_unverified_node_wrapper_mainpid_and_same_name_processes(self):
        group = h.RUNNER_GROUPS[0]
        for mutation in ('node-script', 'node-exe', 'node-uid', 'wrapper-script', 'wrapper-exe', 'wrapper-uid', 'mainpid'):
            with self.subTest(mutation=mutation):
                table = self.service_tree(group)
                main = 8
                if mutation == 'mainpid':
                    main = 99
                else:
                    target = table[9 if mutation.startswith('node') else 8]
                    if mutation.endswith('script'):
                        target['argv'][1] = b'/unrelated/RunnerService.js'
                    elif mutation.endswith('exe'):
                        target['exe'] = '/unrelated/' + Path(target['exe']).name
                    else:
                        target['uid'] += 1
                with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(main, group)), self.assertRaisesRegex(h.Refuse, 'unverified'):
                    h.local_gate(self.uid, 'timer', None)

    def test_unreadable_missing_or_symlinked_nested_cgroup_inventory_defers(self):
        group = h.RUNNER_GROUPS[0]
        self.cgroup_write(group, [], 'nested')
        file = self.cgroups / group.lstrip('/') / 'nested/cgroup.procs'
        file.unlink()
        with patch.object(h, 'process_table', return_value={}), self.assertRaises(OSError):
            h.local_gate(self.uid, 'timer', None)
        file.write_text('')
        (file.parent.parent / 'foreign').symlink_to(file.parent, target_is_directory=True)
        with patch.object(h, 'process_table', return_value={}), self.assertRaises(h.Refuse):
            h.local_gate(self.uid, 'timer', None)

    def test_expected_helper_only_context_allowed_no_other_python_exemption(self):
        group = h.RUNNER_GROUPS[0]
        helper = {'pid': os.getpid(), 'ppid': 1, 'exe': os.readlink('/proc/self/exe'),
            'uid': self.uid, 'cgroup': '0::' + group + '\n'}
        self.cgroup_write(group, [os.getpid()])
        with patch.object(h, 'process_table', return_value={os.getpid(): helper}):
            self.assertEqual(h.local_gate(self.uid, 'timer', None)['completed'], 'build')
        self.cgroup_write(group, [os.getpid(), 40])
        table = {os.getpid(): helper, 40: dict(helper, pid=40)}
        with patch.object(h, 'process_table', return_value=table), self.assertRaises(h.Refuse):
            h.local_gate(self.uid, 'timer', None)

    def test_adopted_client_appearing_during_inspection_blocks_first_deletion(self):
        self.register()
        self.engine.gate = h.local_gate
        self.ops.on_snapshot = lambda: self.cgroup_write(h.RUNNER_GROUPS[1], [40], 'job')
        with patch.object(h, 'process_table', return_value={}):
            self.assert_no_removal()
        self.assertIn('populated runner cgroup', self.output.getvalue())

    def test_adopted_client_after_buildx_blocks_residual_volume_deletion(self):
        self.ops.containers.clear()
        self.engine.seed(self.seed_manifest(), {'schema': 1, 'records': [{'run': api()[0], 'jobs': api()[1]}]})
        self.engine.gate = h.local_gate
        remove = self.ops.remove_builder
        def race(builder):
            remove(builder)
            self.cgroup_write(h.RUNNER_GROUPS[0], [40], 'export')
        self.ops.remove_builder = race
        with patch.object(h, 'process_table', return_value={}):
            self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER)])
        self.assertIn('buildx_buildkit_' + BUILDER + '0_state', self.ops.volumes)
        self.assertFalse(self.record()['removed'])

    def test_adopted_client_after_container_stop_blocks_container_removal(self):
        self.register()
        self.ops.original_container = copy.deepcopy(next(iter(self.ops.containers.values())))
        self.ops.fail = 'metadata-only'
        self.engine.gate = h.local_gate
        stop = self.ops.stop_container
        def race(cid):
            stop(cid)
            self.cgroup_write(h.RUNNER_GROUPS[1], [40], 'export')
        self.ops.stop_container = race
        with patch.object(h, 'process_table', return_value={}):
            self.engine.sweep('timer', None, False)
        self.assertEqual(self.removals(), [('remove_builder', BUILDER), ('stop_container', CID)])
        self.assertFalse(self.record()['removed'])
        self.assertIn('buildx_buildkit_' + BUILDER + '0', self.ops.containers)

    def test_listener_cgroup_pid_without_readable_proc_metadata_defers(self):
        for group in h.RUNNER_GROUPS:
            for nested in ('', 'job/export'):
                with self.subTest(group=group, nested=nested):
                    table = self.service_tree(group)
                    self.cgroup_write(group, [*table, 40] if not nested else [40], nested)
                    with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(8, group)), self.assertRaisesRegex(h.Refuse, 'unclassified'):
                        h.local_gate(self.uid, 'timer', None)

    def test_stopped_listener_with_verified_service_parents_still_defers(self):
        group = h.RUNNER_GROUPS[1]
        table = self.service_tree(group)
        del table[10]
        self.cgroup_write(group, table)
        with patch.object(h, 'process_table', return_value=table), patch.object(h, 'runner_service', return_value=(8, group)), self.assertRaisesRegex(h.Refuse, 'stopped listener.*populated'):
            h.local_gate(self.uid, 'timer', None)

    def test_hook_requires_actual_current_worker_ancestry_after_adoption(self):
        listener = {'pid': 10, 'ppid': 9, 'exe': h.RUNNER_BIN + 'Runner.Listener', 'uid': self.uid, 'cgroup': 'ci'}
        worker = {'pid': 20, 'ppid': 10, 'exe': h.RUNNER_BIN + 'Runner.Worker', 'uid': self.uid, 'cgroup': 'ci', 'start': 123}
        helper = {'pid': os.getpid(), 'ppid': 1, 'exe': '/usr/bin/python3', 'uid': self.uid, 'cgroup': 'ci'}
        with patch.object(h, 'process_table', return_value={10: listener, 20: worker, os.getpid(): helper}), self.assertRaisesRegex(h.Refuse, 'not descended'):
            h.local_gate(self.uid, 'hook', BOUND)

    def test_refresh_verified_terminal_is_monotonic_and_makes_zero_api_calls(self):
        self.register()
        before = (self.state / 'registry.json').read_bytes()
        self.ops.calls.clear()
        self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = h.Refuse('deleted/retained API')
        self.engine.refresh(BOUND['repository'])
        self.assertEqual([c for c in self.ops.calls if c[0] == 'api'], [])
        self.assertEqual(before, (self.state / 'registry.json').read_bytes())
        self.engine.sweep('timer', None, False)
        self.assertTrue(self.record()['removed'])

    def test_contradictory_or_malformed_terminal_evidence_is_cleared_on_failure(self):
        self.register()
        original = self.record()
        edits = [lambda e: e['evidence'].update(run_attempt=2),
                 lambda e: e['evidence'].update(source='caller'),
                 lambda e: e['evidence'].update(url='https://invalid'),
                 lambda e: e['evidence']['jobs'][0].update(runner_id=133),
                 lambda e: e['evidence']['jobs'][0].update(conclusion=None),
                 lambda e: e['evidence']['jobs'][0].update(started_at='invalid')]
        for edit in edits:
            with self.subTest(edit=edit):
                self.store.write('registry.json', {'schema': 1, 'entries': [copy.deepcopy(original)]})
                self.edit_record(edit)
                self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = h.Refuse('unavailable')
                with self.assertRaises(h.Refuse):
                    self.engine.refresh(BOUND['repository'])
                self.assertIsNone(self.record()['evidence'])
                self.assert_no_removal()

    def test_refresh_invalid_metadata_clears_proof_and_skips_deletion(self):
        for value in ((None, None), (api()[0], {'total_count': 1, 'jobs': [None]}),
                      OSError('unavailable'), subprocess.TimeoutExpired(['gh', 'api'], 20)):
            with self.subTest(value=value):
                self.engine.register(BOUND, BUILDER, BOUND)
                self.ops.api_records[('PhorvexSecurity/operator', 42, 1)] = value
                with self.assertRaises(h.Refuse):
                    self.engine.refresh(BOUND['repository'])
                self.assertIsNone(self.record()['evidence'])
                self.assert_no_removal()

    def test_refresh_terminal_api_contradictory_job_interval_clears_proof(self):
        run, jobs = api()
        jobs['jobs'][0]['started_at'] = '2026-10-14T02:00:00Z'
        self.engine.register(BOUND, BUILDER, BOUND)
        self.ops.api_records[(BOUND['repository'], 42, 1)] = (run, jobs)
        with self.assertRaises(h.Refuse):
            self.engine.refresh(BOUND['repository'])
        self.assertIsNone(self.record()['evidence'])
        self.assert_no_removal()

    def test_refresh_bounded_cursor_fairness_survives_failures_and_new_invocation(self):
        # Production 8-entry bound: 19 entries, including persistent early failures.
        entries = []
        for index in range(19):
            bound = dict(BOUND, run_id=100 + index)
            builder = 'builder-' + format(index, '08d')
            self.create_builder(builder, format(index + 3, '064x'))
            self.engine.register(bound, builder, bound)
            self.ops.api_records[(bound['repository'], bound['run_id'], 1)] = h.Refuse('persistent failure') if index < 8 else api(bound, status='in_progress', conclusion=None)
            entries.append(builder)
        with self.assertRaises(h.Refuse):
            self.engine.refresh(BOUND['repository'])
        self.assertEqual(len([c for c in self.ops.calls if c[0] == 'api']), 8)
        self.assertEqual(self.store.registry()['refresh_cursors'][BOUND['repository']], entries[7])
        self.ops.calls.clear()
        # New instance reads the persisted cursor rather than an in-memory offset.
        other = h.Hygiene(self.store, self.ops, self.uid, self.config, gate=self.gate)
        other.refresh(BOUND['repository'])
        calls = [c for c in self.ops.calls if c[0] == 'api']
        self.assertEqual([c[2] for c in calls], list(range(108, 116)))
        self.ops.calls.clear()
        with self.assertRaises(h.Refuse):
            other.refresh(BOUND['repository'])
        calls = [c for c in self.ops.calls if c[0] == 'api']
        self.assertEqual([c[2] for c in calls], [116, 117, 118, 100, 101, 102, 103, 104])
        self.assertEqual(self.removals(), [])

    def test_refresh_budget_stop_persists_cursor_and_continues_next_time(self):
        second = 'builder-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.create_builder(second, OTHER)
        self.engine.register(BOUND, BUILDER, BOUND)
        next_bound = dict(BOUND, run_id=43)
        self.engine.register(next_bound, second, next_bound)
        self.ops.api_records[(BOUND['repository'], 43, 1)] = api(next_bound)
        query = self.ops.api
        def exhausted(*args, **kwargs):
            result = query(*args, **kwargs)
            self.ops.expired = True
            return result
        self.ops.api = exhausted
        with self.assertRaises(h.Refuse):
            self.engine.refresh(BOUND['repository'])
        self.assertEqual(self.store.registry()['refresh_cursors'][BOUND['repository']], BUILDER)
        self.assertTrue(self.record()['evidence']['terminal'])
        self.ops.expired = False
        self.ops.api = query
        self.ops.calls.clear()
        self.engine.refresh(BOUND['repository'])
        self.assertEqual([c[2] for c in self.ops.calls if c[0] == 'api'], [43])

    def test_refresh_failed_shared_attempt_is_queried_only_once(self):
        second = 'builder-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.create_builder(second, OTHER)
        self.engine.register(BOUND, BUILDER, BOUND)
        self.engine.register(BOUND, second, BOUND)
        self.ops.api_records[(BOUND['repository'], 42, 1)] = h.Refuse('unavailable')
        with self.assertRaises(h.Refuse):
            self.engine.refresh(BOUND['repository'])
        self.assertEqual(len([c for c in self.ops.calls if c[0] == 'api']), 1)
        self.assertTrue(all(e['evidence'] is None for e in self.store.registry()['entries']))

    def test_bookkeeping_cli_waits_out_80s_timer_then_starts_full_operation_budget(self):
        for command in ('register', 'refresh'):
            with self.subTest(command=command):
                fcntl.flock(self.store.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                clock = [1000.0]
                sleeps = []
                def wait(seconds):
                    sleeps.append(seconds)
                    clock[0] += seconds
                    if clock[0] >= 1080:
                        fcntl.flock(self.store.lockfd, fcntl.LOCK_UN)
                def ops(uid, gid, deadline):
                    self.assertGreaterEqual(clock[0], 1080)
                    self.assertAlmostEqual(deadline - clock[0], 80)
                    return self.ops
                account = SimpleNamespace(pw_uid=self.uid, pw_gid=os.getgid())
                argv = ['phvx-disk-hygiene', command, '--repository', BOUND['repository']]
                if command == 'register':
                    argv += ['--run-id', '42', '--run-attempt', '1', '--builder', BUILDER]
                env = dict(GITHUB_REPOSITORY=BOUND['repository'], GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1')
                with patch.object(h, 'STATE', str(self.state)), patch.object(h.pwd, 'getpwnam', return_value=account), patch.object(h, 'trusted_json', return_value=self.config), patch.object(h, 'Ops', side_effect=ops), patch.object(h.sys, 'argv', argv), patch.dict(os.environ, env, clear=True), patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(h.time, 'sleep', side_effect=wait):
                    self.assertEqual(h.main(), 0)
                self.assertTrue(sleeps)
                self.assertLess(clock[0], 1100)

    def test_bookkeeping_cli_times_out_at_100s_without_mutation(self):
        clock = [1000.0]
        before = self.store.registry()
        def wait(seconds):
            clock[0] += seconds
        account = SimpleNamespace(pw_uid=self.uid, pw_gid=os.getgid())
        with patch.object(h, 'STATE', str(self.state)), patch.object(h.pwd, 'getpwnam', return_value=account), patch.object(h, 'trusted_json', return_value=self.config), patch.object(h.sys, 'argv', ['phvx-disk-hygiene', 'refresh', '--repository', BOUND['repository']]), patch.dict(os.environ, {}, clear=True), patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(h.time, 'sleep', side_effect=wait), patch.object(h, 'Ops') as ops, self.assertRaises(h.Busy):
            h.main()
        self.assertAlmostEqual(clock[0], 1100)
        ops.assert_not_called()
        self.assertEqual(self.store.registry(), before)

    def test_inventory_hook_timer_and_manual_commands_still_nonblocking(self):
        account = SimpleNamespace(pw_uid=self.uid, pw_gid=os.getgid())
        for args in (['--timer'], ['--job-boundary'], ['report'], ['request'], ['inspect', '--builder', BUILDER]):
            with self.subTest(args=args), patch.object(h, 'STATE', str(self.state)), patch.object(h.pwd, 'getpwnam', return_value=account), patch.object(h, 'trusted_json', return_value=self.config), patch.object(h.sys, 'argv', ['phvx-disk-hygiene', *args]), patch.dict(os.environ, {}, clear=True), patch.object(h.time, 'sleep') as sleep, patch.object(h, 'Ops') as ops, self.assertRaises(h.Busy):
                h.main()
            sleep.assert_not_called()
            ops.assert_not_called()

    def test_waiting_lock_inode_replacement_refuses_before_acquisition(self):
        def replaced(seconds):
            (self.state / 'lock').unlink()
            (self.state / 'lock').touch(mode=0o600)
        with patch.object(h.time, 'sleep', side_effect=replaced), self.assertRaisesRegex(h.Refuse, 'identity drift'):
            with h.Store(str(self.state), self.uid, 512, wait_seconds=100):
                self.fail('replaced lock acquired')



class MetadataTests(unittest.TestCase):
    def test_runner_service_reads_actual_controlgroup_mainpid_with_bounded_query(self):
        group = h.RUNNER_GROUPS[1]
        result = SimpleNamespace(returncode=0, stdout=('MainPID=123\nControlGroup=' + group + '\n').encode())
        with patch.object(h.subprocess, 'run', return_value=result) as run:
            self.assertEqual(h.runner_service(), (123, group))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/usr/bin/systemctl', 'show', h.RUNNER_UNIT, '--property=MainPID', '--property=ControlGroup'])
        self.assertEqual(kwargs['timeout'], 2)
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})

    def test_runner_service_rejects_unavailable_or_invalid_cgroup_metadata(self):
        for result in (SimpleNamespace(returncode=1, stdout=b''),
                       SimpleNamespace(returncode=0, stdout=b'ControlGroup=\n'),
                       SimpleNamespace(returncode=0, stdout=b'MainPID=1\nControlGroup=/../../unsafe\n'),
                       SimpleNamespace(returncode=0, stdout=b'MainPID=1\nControlGroup=/other.service\n')):
            with self.subTest(result=result), patch.object(h.subprocess, 'run', return_value=result), self.assertRaises(h.Refuse):
                h.runner_service()

    def test_running_container_top_includes_pid_and_rejects_build_processes(self):
        ops = h.Ops(os.getuid(), os.getgid(), time.monotonic() + 20)
        cname = 'buildx_buildkit_' + BUILDER + '0'
        payload = [CID, '/' + cname, '2026-10-14T00:01:00Z', 'sha256:' + 'a' * 64,
                   [{'Type': 'volume', 'Name': cname + '_state', 'Destination': '/var/lib/buildkit'}],
                   {'Running': True}, None, None]
        calls = []
        def docker(*args):
            calls.append(args)
            return 'PID COMMAND\n123 docker-init\n124 buildkitd\n' if args[1] == 'top' else json.dumps(payload)
        with patch.object(ops, 'exists', return_value=True), patch.object(ops, 'docker', side_effect=docker):
            self.assertEqual(ops.container(cname)['id'], CID)
        self.assertIn(('container', 'top', CID, '-eo', 'pid,comm'), calls)
        def busy(*args):
            return 'PID COMMAND\n123 docker-init\n124 buildkitd\n125 bash\n' if args[1] == 'top' else json.dumps(payload)
        with patch.object(ops, 'exists', return_value=True), patch.object(ops, 'docker', side_effect=busy), self.assertRaises(h.Refuse):
            ops.container(cname)

    def test_volume_only_byte_accounting_is_cached_per_pass(self):
        ops = h.Ops(os.getuid(), os.getgid(), time.monotonic() + 20)
        response = SimpleNamespace(status=200, read=lambda limit: json.dumps({'Volumes': [
            {'Name': 'exact_state', 'UsageData': {'Size': 9000000000}}]}).encode())
        with patch.object(h.http.client.HTTPConnection, 'request') as request, patch.object(h.http.client.HTTPConnection, 'getresponse', return_value=response):
            self.assertEqual(ops.size('exact_state'), 9000000000)
            self.assertEqual(ops.size('exact_state'), 9000000000)
        request.assert_called_once_with('GET', '/v1.47/system/df?type=volume')

    def test_byte_accounting_failure_is_not_retried_unboundedly(self):
        ops = h.Ops(os.getuid(), os.getgid(), time.monotonic() + 20)
        with patch.object(h.http.client.HTTPConnection, 'request') as request, patch.object(h.http.client.HTTPConnection, 'getresponse', side_effect=TimeoutError()):
            with self.assertRaises(h.Refuse):
                ops.size('exact_state')
            with self.assertRaises(h.Refuse):
                ops.size('exact_state')
        self.assertEqual(request.call_count, 1)

    def test_api_rejects_attempt_repository_runner_and_incomplete_job_metadata(self):
        for mutation in ('attempt', 'repository', 'runner', 'incomplete'):
            with self.subTest(mutation=mutation):
                run, jobs = api()
                if mutation == 'attempt':
                    run['run_attempt'] = 2
                elif mutation == 'repository':
                    run['repository']['full_name'] = 'other/repo'
                elif mutation == 'runner':
                    jobs['jobs'][0]['runner_id'] = 133
                else:
                    jobs['total_count'] = 2
                with self.assertRaises(h.Refuse):
                    h.verify_api(run, jobs, BOUND, 130)

    def test_token_only_used_for_fixed_exact_api_urls_never_in_result_or_logs(self):
        token = 'disposable-token-marker-never-persist'
        paths = []
        run, jobs = api()
        class Response:
            def __init__(self, data):
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return json.dumps(self.data).encode()
        class Opener:
            def open(self, req, timeout):
                paths.append(req.full_url)
                self_test.assertEqual(req.get_header('Authorization'), 'Bearer ' + token)
                return Response(jobs if '/jobs?' in req.full_url else run)
        self_test = self
        ops = h.Ops(os.getuid(), os.getgid(), time.monotonic() + 20)
        output = io.StringIO()
        with patch.dict(os.environ, {'GH_TOKEN': token}), patch.object(h.urllib.request, 'build_opener', return_value=Opener()), contextlib.redirect_stdout(output):
            result = ops.api(BOUND['repository'], 42, 1)
            evidence = h.verify_api(*result, BOUND, 130)
        self.assertEqual(paths, ['https://api.github.com/repos/PhorvexSecurity/operator/actions/runs/42/attempts/1',
            'https://api.github.com/repos/PhorvexSecurity/operator/actions/runs/42/attempts/1/jobs?per_page=100'])
        self.assertNotIn(token, json.dumps(evidence) + output.getvalue())

    def test_docker_invocation_fixed_endpoint_and_env_removes_tokens(self):
        captured = {}
        class Proc:
            returncode = 0
            def communicate(self, timeout):
                return b'[]', None
        def popen(argv, **kw):
            captured.update(argv=argv, **kw)
            return Proc()
        ops = h.Ops(os.getuid(), os.getgid(), time.monotonic() + 20)
        with patch.dict(os.environ, {'DOCKER_HOST': 'unix:///run/user/1001/docker.sock', 'GH_TOKEN': 'secret',
                                    'DOCKER_CONTEXT': 'rootless', 'BUILDX_CONFIG': '/home/mehrdad'}), patch.object(h.subprocess, 'Popen', side_effect=popen):
            ops.remove_builder(BUILDER)
        self.assertEqual(captured['argv'], ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'buildx', 'rm', BUILDER])
        self.assertEqual(captured['env']['BUILDX_CONFIG'], '/home/github-runner/.docker/buildx')
        self.assertNotIn('GH_TOKEN', captured['env'])
        self.assertNotIn('DOCKER_CONTEXT', captured['env'])

    def test_invalid_names_and_paths_rejected(self):
        for name in ('ptest-a', '../builder-12345678', 'builder-01234567;rm -rf /', '-flag'):
            self.assertIsNone(h.NAME.fullmatch(name))
        with self.assertRaises(h.Refuse):
            h.binding('bad/../../mehrdad', 1, 1)
        with self.assertRaises(h.Refuse):
            h.safe_dir('relative/path', os.getuid())

    def test_exact_df_denominator_uses_bavail_not_reserved_bfree(self):
        info = type('VFS', (), {'f_bavail': 20, 'f_bfree': 30, 'f_blocks': 100,
            'f_frsize': 4096, 'f_files': 1000, 'f_ffree': 500})()
        with patch.object(h.os, 'statvfs', return_value=info):
            pressure = h.disk_pressure()
        self.assertEqual(pressure['available_bytes'], 20 * 4096)
        self.assertEqual(pressure['used_fraction'], 70 / 90)
        self.assertEqual(pressure['inode_fraction'], .5)


class HookProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.hook-', dir=OWN / 'tests')
        self.root = Path(self.tmp.name)
        self.signals = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}

    def tearDown(self):
        for sig, handler in self.signals.items():
            signal.signal(sig, handler)
        self.tmp.cleanup()

    def test_missing_helper_always_succeeds(self):
        with patch.object(hook, 'HELPER', str(self.root / 'missing')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.main(), 0)

    def test_nonzero_helper_always_succeeds(self):
        file = self.root / 'helper'
        file.write_text('#!/usr/bin/python3\nraise SystemExit(7)\n')
        file.chmod(0o700)
        with patch.object(hook, 'HELPER', str(file)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.main(), 0)

    def test_timeout_kills_only_own_helper_group_and_no_child_survives(self):
        file = self.root / 'helper'
        marker = self.root / 'child-pid'
        file.write_text('#!/usr/bin/python3\nimport subprocess,sys,time,signal\n'
                        'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                        'p=subprocess.Popen([sys.executable,"-c","import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"])\n'
                        + 'open(' + repr(str(marker)) + ',"w").write(str(p.pid))\n'
                        'time.sleep(60)\n')
        file.chmod(0o700)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '10'], start_new_session=True)
        real_popen = subprocess.Popen
        def ready_helper(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            until = time.monotonic() + 5
            while time.monotonic() < until:
                if marker.exists() and marker.read_text().strip():
                    return proc
                time.sleep(.01)
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            self.fail('disposable helper did not initialize within five seconds')
        try:
            started = time.monotonic()
            with patch.object(hook.subprocess, 'Popen', side_effect=ready_helper), patch.object(hook, 'HELPER', str(file)), patch.object(hook, 'BUDGET', .25), patch.object(hook, 'GRACE', .2), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(hook.main(), 0)
            self.assertLess(time.monotonic() - started, 7)
            child = int(marker.read_text())
            time.sleep(.05)
            procstat = Path('/proc/' + str(child) + '/stat')
            self.assertTrue(not procstat.exists() or procstat.read_text().split(') ')[1].startswith('Z '))
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
