"""Fixed host profiles; only root-attested configuration may select them."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import stat

CONFIG = Path('/etc/phvx-runner-hygiene.json')
FENCE = Path('/run/phvx-runner-maintenance/offline-fence')
HOLD = Path('/var/lib/phvx-runner-maintenance/rescale-hold')
CAPACITY = Path('/etc/phvx-runner-capacity.json')
LOCK = Path('/var/lib/phvx-runner-cleanup/lock')
UID = 1000

def profile(runner_id, name, installation, work, docker_config, state):
    root = '/home/github-runner/' + installation
    return {'runner_id': runner_id, 'unit': f'actions.runner.PhorvexSecurity.{name}.service',
            'root': root, 'bin': root + '/bin/', 'diag': root + '/_diag', 'work': root + '/' + work,
            'docker_config': '/home/github-runner/' + docker_config,
            'instances': '/home/github-runner/' + docker_config + '/buildx/instances', 'state': state}

APPROVED = [
    profile(130, 'phorvex', 'actions-runner', 'phorvex', '.docker', '/var/lib/phvx-runner-hygiene'),
    profile(21, 'phorvex-1', 'action-runner-1', 'phorvex_1_work', '.docker-phorvex-1', '/var/lib/phvx-runner-hygiene-133'),
]

def trusted_json(path):
    path = Path(path)
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Untrusted root-owned configuration path')
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Untrusted configuration file type')
    return json.loads(path.read_text())

def profiles(config=None):
    config = trusted_json(CONFIG) if config is None else config
    if config.get('schema') == 1 and config.get('runner_id') == 130 and 'profiles' not in config:
        return APPROVED[:1]
    if config.get('schema') != 2 or config.get('profiles') != APPROVED:
        raise RuntimeError('Profile allowlist/path drift')
    return config['profiles']

def select(value, allowed=None):
    allowed = profiles() if allowed is None else allowed
    matches = [p for p in allowed if str(value) in {str(p['runner_id']), p['unit']}]
    if len(matches) != 1:
        raise RuntimeError('Unknown runner profile')
    return matches[0]

def classify(process, allowed=None):
    allowed = profiles() if allowed is None else allowed
    matches = [p for p in allowed if process['uid'] == UID and
               process['exe'] == p['bin'] + process['comm'] and
               process['cgroup'].strip() == '0::/phvxci.slice/' + p['unit']]
    if process['comm'] not in {'Runner.Listener', 'Runner.Worker'} or len(matches) != 1:
        raise RuntimeError('Unclassified runner process')
    return matches[0]

def census(processes, allowed=None):
    allowed = profiles() if allowed is None else allowed
    listeners = {}
    workers = []
    for process in processes:
        if process['comm'] not in {'Runner.Listener', 'Runner.Worker'}:
            continue
        p = classify(process, allowed)
        if process['comm'] == 'Runner.Listener':
            if p['runner_id'] in listeners:
                raise RuntimeError('Duplicate listener in installation')
            listeners[p['runner_id']] = process
        else:
            workers.append((p, process))
    for p, worker in workers:
        listener = listeners.get(p['runner_id'])
        if not listener or worker['ppid'] != listener['pid'] or worker['cgroup'] != listener['cgroup']:
            raise RuntimeError('Worker ancestry/cgroup mismatch')
    return listeners, workers

def worker_profile(table, pid=None, allowed=None):
    listeners, workers = census(table.values(), allowed)
    pid = os.getpid() if pid is None else pid
    ancestors = set()
    while pid in table and pid not in ancestors:
        ancestors.add(pid)
        pid = table[pid]['ppid']
    matches = [p for p, worker in workers if worker['pid'] in ancestors]
    if len(matches) != 1:
        raise RuntimeError('Helper is not descended from exactly one verified Worker')
    return matches[0]

def admission_closed():
    return FENCE.exists() or HOLD.exists()

def check_hold():
    if HOLD.exists():
        trusted_json(HOLD)
        raise RuntimeError('Persistent rescale hold active; readiness/release required')

def listener_count():
    config = trusted_json(CAPACITY)
    if set(config) != {'listeners'} or type(config['listeners']) is not int or config['listeners'] not in (1, 2):
        raise RuntimeError('Invalid root-owned listener count')
    return config['listeners']

@contextlib.contextmanager
def cleanup_lock(uid=UID):
    # Directory is provisioned by root, writable only by github-runner; neither
    # profile can substitute another profile's lock path through job environment.
    directory = LOCK.parent
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise RuntimeError('Unsafe global cleanup lock directory')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RuntimeError('Unsafe global cleanup lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)
