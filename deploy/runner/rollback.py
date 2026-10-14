#!/usr/bin/python3
"""Restore only captured configuration on the drained host; preserve all leases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HOST = '7089cf7bcdeb41869b950cf23aefff81'

def restore(backup, force_cpu=False):
    if os.geteuid() != 0 or Path('/etc/machine-id').read_text().strip() != HOST:
        raise RuntimeError('Root on fixed host required')
    manifest = json.loads((backup / 'manifest.json').read_text())
    if not force_cpu:
        if not Path('/run/phvx-runner-maintenance/offline-fence').is_file():
            raise RuntimeError('Fresh audited drain required for helper restoration')
        for directory in Path('/proc').iterdir():
            if directory.name.isdigit():
                try:
                    if (directory / 'comm').read_text().strip() in ('Runner.Listener', 'Runner.Worker'):
                        raise RuntimeError('Runner processes remain; rollback deferred')
                except FileNotFoundError: continue
    # CPU emergency rollback is explicitly permitted during a job: no signals.
    if force_cpu and 'before_max' not in manifest:
        raise RuntimeError('CPU baseline manifest required')
    for record in manifest['files']:
        path = Path(record['path'])
        if path.is_symlink(): raise RuntimeError('Destination symlink refused')
        if record['exists']:
            source = backup / 'files' / str(path).lstrip('/')
            if hashlib.sha256(source.read_bytes()).hexdigest() != record['sha256']:
                raise RuntimeError('Backup hash mismatch')
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, path)
            path.chmod(record['mode'])
            os.chown(path, record['uid'], record['gid'])
        else: path.unlink(missing_ok=True)
    if force_cpu:
        maximum, period = manifest['before_max'].split()
        quota = int(maximum) * 100 / int(period)
        weight = manifest['before_weight'].strip()
    else:
        props = dict(line.split('=', 1) for line in manifest['properties'].splitlines())
        value = props['CPUQuotaPerSecUSec']
        if value.endswith('s'): quota = float(value[:-1]) * 100
        else: raise RuntimeError('Unsupported captured quota')
        weight = props['CPUWeight']
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'set-property', '--runtime', 'phvxci.slice', f'CPUQuota={quota}%', f'CPUWeight={weight}'], check=True)
    # set-property may materialize runtime files. Only undo task-created files
    # with known names; restore baseline ones byte-for-byte again.
    captured = {record['path'] for record in manifest['files']}
    for path in Path('/run/systemd/system.control/phvxci.slice.d').glob('*'):
        if str(path) not in captured and path.name in {'50-CPUQuota.conf', '50-CPUQuotaPerSecUSec.conf', '50-CPUWeight.conf'}:
            path.unlink()
    for record in manifest['files']:
        if record['exists'] and record['path'].startswith('/run/systemd/system.control/'):
            path = Path(record['path'])
            shutil.copy2(backup / 'files' / str(path).lstrip('/'), path)
            path.chmod(record['mode'])
            os.chown(path, record['uid'], record['gid'])
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    maximum, period = Path('/sys/fs/cgroup/phvxci.slice/cpu.max').read_text().split()
    if int(maximum) * 100 != quota * int(period) or Path('/sys/fs/cgroup/phvxci.slice/cpu.weight').read_text().strip() != weight:
        raise RuntimeError('Rollback effective CPU mismatch')
    print(json.dumps({'restored_configuration': str(backup), 'leases': 'retained in place', 'quota_percent': quota, 'weight': weight}))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--cpu-only', action='store_true')
    args = parser.parse_args()
    if args.backup.parent != Path('/var/backups') or not args.backup.name.startswith('phvx-runner-speed-'):
        raise RuntimeError('Task-scoped backup path required')
    restore(args.backup, args.cpu_only)

if __name__ == '__main__': main()
