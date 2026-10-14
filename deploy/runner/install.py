#!/usr/bin/python3
"""Install reviewed payloads on the drained, fixed host; never restart daemons."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import time

OWN = Path(__file__).resolve().parent
HOST = '7089cf7bcdeb41869b950cf23aefff81'
UNIT = 'actions.runner.PhorvexSecurity.phorvex.service'
TASK = 'runner-speed-20261014'
PAYLOADS = {
    **{name: '/usr/local/libexec/' + name for name in ('phvx_runner_profiles.py', 'phvx-runner-capacity',
        'phvx-runner-start-guard', 'phvx-runner-maintenance', 'phvx-disk-hygiene',
        'phvx-runner-job-completed', 'phvx-runner-job-completed.sh')},
    **{name: '/etc/systemd/system/' + name for name in ('phvx-runner-capacity.service', 'phvx-disk-hygiene.service', 'phvx-disk-hygiene.timer')},
    'phvx-runner-capacity.json': '/etc/phvx-runner-capacity.json',
    'phvx-runner-hygiene.json': '/etc/phvx-runner-hygiene.json',
    '130.conf': '/etc/systemd/system/' + UNIT + '.d/70-runner-speed.conf',
    '133.conf': '/etc/systemd/system/actions.runner.PhorvexSecurity.phorvex-1.service.d/50-phvx-hardening.conf',
}
DAEMONS = ['/etc/systemd/system/' + service + '.d/70-runner-speed.conf' for service in ('docker.service', 'containerd.service')]

def command(argv):
    return subprocess.check_output(argv, text=True, timeout=60)

def assert_host_idle():
    if os.geteuid() != 0 or Path('/etc/machine-id').read_text().strip() != HOST:
        raise RuntimeError('Root on fixed runner host required')
    fence = Path('/run/phvx-runner-maintenance/offline-fence')
    if not fence.is_file() or fence.is_symlink() or fence.stat().st_uid != 0:
        raise RuntimeError('Audited drained admission fence required')
    for directory in Path('/proc').iterdir():
        if directory.name.isdigit():
            try:
                if (directory / 'comm').read_text().strip() in ('Runner.Listener', 'Runner.Worker'):
                    raise RuntimeError('Runner process remains; install deferred')
            except FileNotFoundError:
                continue
    group = Path('/sys/fs/cgroup/phvxci.slice') / UNIT
    if group.exists() and any(file.read_text().strip() for file in group.rglob('cgroup.procs')):
        raise RuntimeError('Unknown runner descendants remain')
    if subprocess.run(['systemctl', 'is-enabled', 'actions.runner.PhorvexSecurity.phorvex-1.service'], text=True, capture_output=True).stdout.strip() != 'disabled':
        raise RuntimeError('R2 must remain disabled')

def capture(path, backup):
    path = Path(path)
    result = {'path': str(path), 'exists': path.exists()}
    if path.is_symlink():
        raise RuntimeError('Symlink destination refused')
    if path.exists():
        info = path.stat()
        result.update(uid=info.st_uid, gid=info.st_gid, mode=info.st_mode & 0o777,
                      sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        dest = backup / 'files' / str(path).lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', required=True)
    args = parser.parse_args()
    assert_host_idle()
    backup = Path(args.backup)
    if backup.parent != Path('/var/backups') or not backup.name.startswith('phvx-runner-speed-'):
        raise RuntimeError('Task-scoped backup path required')
    backup.mkdir(mode=0o700)
    paths = list(PAYLOADS.values()) + DAEMONS + ['/etc/systemd/system/phvxci.slice.d/70-runner-speed.conf', '/run/phvx-runner-capacity.env']
    paths += [str(file) for file in Path('/run/systemd/system.control/phvxci.slice.d').glob('*') if file.is_file()]
    records = [capture(path, backup) for path in paths]
    # Preserve leases in place, plus root-only evidence copies. No credential reads.
    for state in ('phvx-runner-hygiene', 'phvx-runner-hygiene-133'):
        directory = Path('/var/lib') / state
        if directory.exists():
            for name in ('registry.json', 'pending.json', 'last-report.json'):
                file = directory / name
                if file.exists(): capture(file, backup)
    manifest = {'task': TASK, 'at': time.time(), 'files': records,
                'properties': command(['systemctl', 'show', 'phvxci.slice', '-p', 'CPUQuotaPerSecUSec', '-p', 'CPUWeight']),
                'primary_enabled': command(['systemctl', 'is-enabled', UNIT]).strip()}
    (backup / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for source, target in PAYLOADS.items():
        assert_host_idle()
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replacement; chmod/chown the staged file before exposing it.
        temp = path.with_name(path.name + '.speed-install')
        shutil.copyfile(OWN / source, temp)
        temp.chmod(0o755 if target.startswith('/usr/local/libexec/') and not source.endswith('.py') else 0o644)
        os.chown(temp, 0, 0)
        os.replace(temp, path)
    for target in DAEMONS:
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(OWN / 'daemon-capacity.conf', path)
        path.chmod(0o644)
        os.chown(path, 0, 0)
    account = pwd.getpwnam('github-runner')
    for directory in ('/var/lib/phvx-runner-hygiene-133', '/var/lib/phvx-runner-cleanup',
                      '/home/github-runner/.docker-phorvex-1', '/home/github-runner/.docker-phorvex-1/buildx',
                      '/home/github-runner/.docker-phorvex-1/buildx/instances'):
        path = Path(directory)
        if path.is_symlink(): raise RuntimeError('Profile directory symlink refused')
        if not path.exists():
            path.mkdir(mode=0o750, parents=True)
            os.chown(path, account.pw_uid, account.pw_gid)
    path = Path('/var/lib/phvx-runner-maintenance')
    path.mkdir(mode=0o755, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise RuntimeError('Untrusted persistent maintenance directory')
    command(['systemctl', 'daemon-reload'])
    # New capacity unit is required by listeners. Existing rootful daemons continue.
    command(['systemctl', 'start', 'phvx-runner-capacity.service'])
    command(['systemd-analyze', 'verify', '/etc/systemd/system/phvx-runner-capacity.service',
             '/etc/systemd/system/phvx-disk-hygiene.service', '/etc/systemd/system/phvx-disk-hygiene.timer',
             '/etc/systemd/system/' + UNIT, '/etc/systemd/system/actions.runner.PhorvexSecurity.phorvex-1.service'])
    installed = {target: hashlib.sha256(Path(target).read_bytes()).hexdigest() for target in paths if Path(target).is_file()}
    (backup / 'installed-hashes.json').write_text(json.dumps(installed, indent=2) + '\n')
    print(json.dumps({'installed': True, 'backup': str(backup), 'hashes': installed, 'second_enabled': False}))

if __name__ == '__main__': main()
