"""Shared-host capacity/admission safety tests; no real systemd/Docker/SSH calls."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch
import phvx_runner_profiles as p

OWN = Path(__file__).resolve().parents[1]
def load(name, file):
    loader = importlib.machinery.SourceFileLoader(name, str(OWN / file))
    spec = importlib.util.spec_from_loader(name, loader)
    result = importlib.util.module_from_spec(spec)
    loader.exec_module(result)
    return result

h = load('speed_hygiene', 'phvx-disk-hygiene')
g = load('speed_guard', 'phvx-runner-start-guard')
c = load('speed_capacity', 'phvx-runner-capacity')
m = load('speed_maintenance', 'phvx-runner-maintenance')

def listener(profile, pid):
    return {'pid': pid, 'ppid': pid + 10, 'start': 123, 'state': 'S', 'uid': 1000,
            'exe': profile['bin'] + 'Runner.Listener', 'comm': 'Runner.Listener',
            'cgroup': '0::/phvxci.slice/' + profile['unit']}
def worker(profile, pid, parent):
    return {**listener(profile, pid), 'ppid': parent, 'exe': profile['bin'] + 'Runner.Worker', 'comm': 'Runner.Worker'}

class Profiles(unittest.TestCase):
    def test_root_owned_allowlist_rejects_job_supplied_roots_and_third_profile(self):
        config = json.loads((OWN / 'phvx-runner-hygiene.json').read_text())
        self.assertEqual(p.profiles(config), p.APPROVED)
        for mutation in ('path', 'third'):
            bad = copy.deepcopy(config)
            if mutation == 'path': bad['profiles'][1]['docker_config'] = p.APPROVED[0]['docker_config'] + '/phorvex-1'
            else: bad['profiles'].append({**bad['profiles'][1], 'runner_id': 134})
            with self.assertRaises(RuntimeError): p.profiles(bad)
        self.assertEqual(p.profiles({'schema': 1, 'runner_id': 130}), p.APPROVED[:1])

    def test_docker_roots_and_state_paths_do_not_overlap(self):
        a, b = p.APPROVED
        for field in ('docker_config', 'state', 'work', 'instances'):
            self.assertNotIn(Path(a[field]), Path(b[field]).parents)
            self.assertNotIn(Path(b[field]), Path(a[field]).parents)
            self.assertNotEqual(a[field], b[field])

    def test_both_listeners_and_other_worker_allowed_for_start(self):
        a, b = p.APPROVED
        table = [listener(a, 10), worker(a, 20, 10)]
        with patch.object(g, 'profiles', return_value=p.APPROVED), patch.object(g, 'check_hold'), patch.object(g, 'listener_count', return_value=2), patch.object(g, 'FENCE') as fence:
            fence.exists.return_value = False
            g.check(133, table)
            with self.assertRaises(RuntimeError): g.check(130, table)
            with self.assertRaises(RuntimeError): g.check(133, table + [listener(b, 30)])

    def test_duplicate_unknown_and_action_runner_2_refused(self):
        a, b = p.APPROVED
        for table in ([listener(a, 1), listener(a, 2)],
                      [{**listener(b, 3), 'exe': '/home/github-runner/action-runner-2/bin/Runner.Listener'}],
                      [{**listener(b, 3), 'uid': 0}],
                      [{**listener(b, 3), 'cgroup': '0::/system.slice/' + b['unit']}],
                      [listener(b, 3), worker(b, 4, 2)]):
            with self.assertRaises(RuntimeError): p.census(table, p.APPROVED)
        with self.assertRaises(RuntimeError): p.select(134, p.APPROVED)

    def test_worker_ancestry_selects_only_correct_profile(self):
        a, b = p.APPROVED
        table = {x['pid']: x for x in (listener(a, 10), listener(b, 30), worker(a, 20, 10), worker(b, 40, 30))}
        table[50] = {'pid': 50, 'ppid': 40, 'comm': 'python3', 'exe': '/usr/bin/python3', 'uid': 1000, 'cgroup': table[40]['cgroup']}
        self.assertEqual(p.worker_profile(table, 50, p.APPROVED), b)
        with self.assertRaises(RuntimeError): p.worker_profile(table, 99, p.APPROVED)

    def test_either_worker_blocks_global_deletion_before_profile_checks(self):
        for selected in p.APPROVED:
            table = {x['pid']: x for x in [listener(selected, 10), worker(selected, 20, 10)]}
            with patch.object(h, 'PROFILES', p.APPROVED), patch.object(h, 'process_table', return_value=table), patch.object(h, 'local_gate') as gate:
                with self.assertRaises(h.Refuse): h.global_gate(1000, 'timer', None)
                gate.assert_not_called()

    def test_global_gate_checks_both_idle_profiles(self):
        table = {x['pid']: x for x in [listener(p.APPROVED[0], 10), listener(p.APPROVED[1], 30)]}
        with patch.object(h, 'PROFILES', p.APPROVED), patch.object(h, 'ACTIVE_PROFILES', p.APPROVED), patch.object(h, 'process_table', return_value=table), patch.object(h, 'local_gate', return_value={'idle': True}) as gate:
            self.assertEqual(len(h.global_gate(1000, 'timer', None)), 2)
            self.assertEqual(gate.call_count, 2)
        self.assertEqual(h.RUNNER_BIN, p.APPROVED[0]['bin'])

    def test_global_lock_contention_and_wrong_mode_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            with patch.object(p, 'LOCK', root / 'lock'):
                with p.cleanup_lock(os.getuid()):
                    with self.assertRaises(BlockingIOError):
                        with p.cleanup_lock(os.getuid()): pass
                root.chmod(0o777)
                with self.assertRaises(RuntimeError):
                    with p.cleanup_lock(os.getuid()): pass

    def test_schema1_lease_primary_only_and_wrong_profile_refused(self):
        entry = {'runner_id': 133, 'repository': 'PhorvexSecurity/operator', 'run_id': 42, 'run_attempt': 1}
        store = unittest.mock.Mock(spec=h.Store)
        ops = unittest.mock.Mock()
        obj = h.Hygiene(store, ops, 1000, {'runner_id': 130})
        with self.assertRaisesRegex(h.Refuse, 'wrong-profile'): obj.validated(entry, 'timer', None)
        # Schema-1 entries have no runner_id, so they retain ID130 ownership.
        obj = h.Hygiene(store, ops, 1000, {'runner_id': 133})
        entry.pop('runner_id')
        with self.assertRaisesRegex(h.Refuse, 'wrong-profile'): obj.validated(entry, 'timer', None)

class Capacity(unittest.TestCase):
    def test_policy_matches_both_topologies(self):
        self.assertEqual(c.policy(4, 1), (300, 100, 2))
        self.assertEqual(c.policy(16, 2), (1500, 700, 7))
        self.assertEqual(c.policy(1, 1), (100, 100, 1))
        self.assertEqual(c.policy(1000, 2)[1], 10000)

    def test_r2_gate_never_accepts_current_host_or_advertised_24gb(self):
        good = {'cores': 16, 'physical_bytes': 31 * 2**30, 'available_bytes': 15 * 2**30,
                'disk_available_bytes': 50 * 2**30, 'memory_full_avg10': 0}
        c.gate(good)
        for key, value in [('cores', 4), ('physical_bytes', int(22.7 * 2**30)), ('available_bytes', 11 * 2**30), ('disk_available_bytes', 39 * 2**30), ('memory_full_avg10', 1)]:
            with self.assertRaises(RuntimeError): c.gate({**good, key: value})

    def test_listener_requires_capacity_daemons_only_want_it(self):
        for filename in ('130.conf', '133.conf'):
            data = (OWN / filename).read_text()
            self.assertIn('Requires=phvx-runner-capacity.service', data)
            self.assertIn('After=phvx-runner-capacity.service', data)
            self.assertIn('EnvironmentFile=/run/phvx-runner-capacity.env', data)
        data = (OWN / 'daemon-capacity.conf').read_text()
        self.assertIn('Wants=phvx-runner-capacity.service', data)
        self.assertNotIn('Requires=', data)

class Hold(unittest.TestCase):
    def test_persistent_hold_survives_runtime_fence_loss_blocks_recovery_and_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            hold = Path(directory) / 'hold'
            state = {'owner': 'runner-speed-20261014', 'nonce': 'test', 'at': time.time()}
            hold.write_text(json.dumps(state))
            with patch.object(p, 'HOLD', hold), patch.object(p, 'trusted_json', return_value=state):
                self.assertTrue(p.admission_closed())
                with self.assertRaises(RuntimeError): p.check_hold()
                with patch.object(m, 'command') as command:
                    with self.assertRaises(RuntimeError): m.start_listeners()
                    command.assert_not_called()
                with patch.object(g, 'profiles', return_value=p.APPROVED):
                    with self.assertRaises(RuntimeError): g.check(130, [])
                with patch.object(m, 'log'):
                    with self.assertRaises(RuntimeError): m.hold('release', 'wrong')
                    self.assertTrue(hold.exists())
                    m.hold('release', 'test')
                    self.assertFalse(hold.exists())
                    p.check_hold()

class SourceContract(unittest.TestCase):
    def test_final_stages_byte_equal_and_no_forced_full_compilation(self):
        import subprocess
        root = OWN.parents[1]
        pin = '9fd64966de5b93162da59f1a21cedafd11ff9ce0'
        for filename in ('operator.Dockerfile', 'console.Dockerfile'):
            path = 'deploy/docker/' + filename
            old = subprocess.check_output(['git', 'show', pin + ':' + path], cwd=root, text=True)
            new = (root / path).read_text()
            self.assertEqual(old[old.rindex('FROM '):], new[new.rindex('FROM '):])
            self.assertNotRegex(new, r'go build[^\n]* -a\b')
            self.assertNotIn('max-parallelism', new)
            for line in new.splitlines():
                if line.startswith('RUN ') and ('go ' in line or 'CGO_ENABLED=' in line):
                    self.assertIn('target=/go/pkg/mod,sharing=locked', line)
                    self.assertIn('target=/root/.cache/go-build,sharing=locked', line)

if __name__ == '__main__': unittest.main(verbosity=2)

# Exercise a two-listener transaction using the audited fake pidfd/controller
# harness. All watchdogs arm before either listener freezes.
from test_admission import Drain as AuditedDrain
class DualDrain(unittest.TestCase):
    def setUp(self):
        AuditedDrain.setUp(self)
        self.second = {**self.listener, 'pid': 101, 'ppid': 201,
                       'exe': p.APPROVED[1]['bin'] + 'Runner.Listener'}
        self.states = {100: 'S', 101: 'S'}
        def process(pid):
            if pid in self.states:
                item = self.listener if pid == 100 else self.second
                return {**item, 'state': self.states[pid]}
            return {'pid': pid, 'uid': 0, 'start': 456 if pid in (300, 301) else 555}
        def command(args, timeout=8):
            if args[0] == 'systemd-run' and '--watchdog' in args:
                path = Path(args[args.index('--watchdog') + 1])
                state = json.loads(path.read_text())
                ident = 300 if state['listener']['pid'] == 100 else 301
                state.update(phase='armed', watchdog_pid=ident, watchdog_start=456)
                m.write_state(path, state)
            if args[0] == 'systemctl' and 'show' in args:
                return '301' if args[2].startswith('phvx-admission-resume-101-') else '300'
            return ''
        def send(fd, sig):
            self.signals.append((fd, sig))
            if sig == signal.SIGSTOP: self.states[fd] = 'T'
            if sig == signal.SIGCONT: self.states[fd] = 'S'
        # AuditedDrain patches its own module instance; install the same patches
        # on this module's independently loaded maintenance implementation.
        for mock in [patch.object(m, 'RUN', self.run), patch.object(m, 'proc', side_effect=process),
                     patch.object(m, 'local_idle', return_value=[self.listener, self.second]),
                     patch.object(m, 'command', side_effect=command),
                     patch.object(m.os, 'pidfd_open', side_effect=lambda pid: pid), patch.object(m.os, 'close'),
                     patch.object(m.signal, 'pidfd_send_signal', side_effect=send),
                     patch.object(m.select, 'select', return_value=([], [], [])),
                     patch.object(m.time, 'monotonic', side_effect=lambda: self.clock),
                     patch.object(m.time, 'sleep', side_effect=lambda n: setattr(self, 'clock', self.clock + n)),
                     patch.object(m, 'log')]:
            mock.start()
            self.addCleanup(mock.stop)

    def test_two_listener_busy_abort_resumes_both_without_int(self):
        with patch.object(m, 'proof', side_effect=RuntimeError('busy')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError): m.drain()
        self.assertEqual(self.signals, [(100, signal.SIGSTOP), (101, signal.SIGSTOP), (100, signal.SIGCONT), (101, signal.SIGCONT)])
        self.assertFalse((self.run / 'offline-fence').exists())

    def test_two_listener_expiry_never_shutdown_either(self):
        def expired(**kwargs):
            self.clock += 15
            return {'finished_at': time.time()}
        with patch.object(m, 'proof', side_effect=expired), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError): m.drain()
        self.assertFalse(any(sig == signal.SIGINT for _, sig in self.signals))
        self.assertEqual(self.states, {100: 'S', 101: 'S'})

    def test_two_listener_post_int_worker_race_retains_fence_without_kill(self):
        with patch.object(m, 'proof', return_value={'finished_at': time.time()}), patch.object(m, 'processes', return_value=[{'comm': 'Runner.Worker'}]), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError): m.drain()
        self.assertTrue((self.run / 'offline-fence').exists())
        self.assertFalse(any(sig == signal.SIGKILL for _, sig in self.signals))
        self.assertEqual(self.states, {100: 'S', 101: 'S'})
