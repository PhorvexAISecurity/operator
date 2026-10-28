"""Build brain-replay from one commit, as operator.Dockerfile's build set one does.

The source directory must already be checked out at the commit, with nothing
modified. The binary links that commit as its linkedGitSHA, and that SHA is
how brain-replay decides whether a snapshot was recorded by "its" revision. It
is built for the host, because it runs on the host. The flags match the
Dockerfile's: -trimpath, -s -w, CGO off, -mod=readonly. The bot reads the Go
release from the deployed binary's build metadata and uses it for tests and
both builds. VCS stamping is off, because the Docker build has no .git.
"""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

LDFLAG = 'github.com/phorvex/phorvex/internal/buildinfo.linkedGitSHA'
TOOLCHAIN = 'go1.26.1'
GIT_ENV = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_OPTIONAL_LOCKS': '0'}


class BuildError(Exception):
    pass


def _git(src, *args):
    result = subprocess.run(['git', '-C', str(src), *args], text=True, capture_output=True, env={**os.environ, **GIT_ENV})
    if result.returncode:
        raise BuildError('git %s failed: %s' % (' '.join(args), result.stderr.strip()))
    return result.stdout.strip()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def deployed_toolchain(binary, go='go'):
    """Read build metadata without executing the deployed binary."""
    env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
           'HOME': str(Path.home()), 'GOTOOLCHAIN': 'local', 'LANG': 'C.UTF-8'}
    try:
        result = subprocess.run([go, 'version', '-m', str(binary)], env=env,
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise BuildError('cannot read the deployed Go toolchain (%s)' % type(err).__name__)
    first = result.stdout.splitlines()[0] if result.stdout else ''
    match = re.search(r': (go\d+\.\d+\.\d+)\s*$', first)
    if result.returncode or not match:
        raise BuildError('the deployed binary has no supported Go release metadata')
    return match.group(1)


def go_environment(src, toolchain=TOOLCHAIN):
    """Use the host's Go caches, but give tested code no service/cloud credentials."""
    home = Path(src).parent / 'go-home'
    home.mkdir(exist_ok=True, mode=0o700)
    return {
        'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
        'HOME': str(home), 'LANG': 'C.UTF-8',
        'GOCACHE': os.environ.get('GOCACHE', str(Path.home() / '.cache/go-build')),
        'GOPATH': os.environ.get('GOPATH', str(Path.home() / 'go')),
        'GOMODCACHE': os.environ.get('GOMODCACHE', str(Path.home() / 'go/pkg/mod')),
        'GOTOOLCHAIN': toolchain, 'GOFLAGS': '-mod=readonly -buildvcs=false',
        'CGO_ENABLED': '0', 'GOMAXPROCS': '2', 'KUBECONFIG': os.devnull,
        'KUBEBUILDER_ASSETS': '', 'USE_EXISTING_CLUSTER': 'false',
        'AWS_EC2_METADATA_DISABLED': 'true',
    }


def test(src, commit, packages, go='go', timeout=1800, log=None, toolchain=TOOLCHAIN):
    """Run uncached unit tests; return counts and preserve the complete JSON log."""
    src = Path(src)
    if _git(src, 'rev-parse', 'HEAD') != commit or _git(src, 'status', '--porcelain'):
        raise BuildError('tests require a clean checkout of %s' % commit)
    packages = sorted(set(packages))
    # Each package can spawn CPU-bound deadline checks. Do not run two test
    # packages together on the small jump host; keep their original deadlines.
    cmd = [go, 'test', '-json', '-count=1', '-p=1', '-timeout=10m',
           '-ldflags=-X %s=%s' % (LDFLAG, commit), *packages]
    timed_out = False
    try:
        result = subprocess.run(cmd, cwd=str(src / 'phorvex'), env=go_environment(src, toolchain),
                                text=True, capture_output=True, timeout=timeout)
        output, returncode = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as err:
        timed_out = True
        def decoded(value):
            return value.decode('utf-8', 'replace') if isinstance(value, bytes) else (value or '')
        output, returncode = decoded(err.stdout) + decoded(err.stderr), None
    if log is not None:
        Path(log).write_text(output)
    counts = {'pass': 0, 'fail': 0, 'skip': 0}
    completed = set()
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        action = event.get('Action')
        if event.get('Test') and action in counts:
            counts[action] += 1
        elif not event.get('Test') and action == 'pass':
            completed.add(event.get('Package'))
    return {'commit': commit, 'toolchain': toolchain, 'packages': packages, 'counts': counts, 'returncode': returncode,
            'status': 'PASS' if returncode == 0 and completed else ('TIMEOUT' if timed_out else 'FAIL')}


def build(src, commit, out, go='go', toolchain=TOOLCHAIN, timeout=1800, log=None):
    """Compile <src>/phorvex/cmd/brain-replay at `commit` into `out`; return its sha256."""
    src, out = Path(src), Path(out)
    head = _git(src, 'rev-parse', 'HEAD')
    if head != commit:
        raise BuildError('%s is at %s, not %s' % (src, head, commit))
    dirty = _git(src, 'status', '--porcelain')
    if dirty:
        raise BuildError('%s has uncommitted changes; a build must be the commit alone' % src)
    out.parent.mkdir(parents=True, exist_ok=True)
    env = go_environment(src, toolchain)
    cmd = [go, 'build', '-p=2', '-trimpath', '-ldflags=-s -w -X %s=%s' % (LDFLAG, commit), '-o', str(out), './cmd/brain-replay']
    result = subprocess.run(cmd, cwd=str(src / 'phorvex'), env=env, text=True, capture_output=True, timeout=timeout)
    if log is not None:
        Path(log).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise BuildError('go build of brain-replay at %s failed: %s' % (commit[:12], result.stderr.strip()[-600:]))
    if commit.encode() not in out.read_bytes():
        raise BuildError('the built brain-replay does not carry linkedGitSHA %s' % commit)
    return sha256_file(out)


def tags_at(repo, commit):
    """Tags that point at `commit`, release (manager-v*) tags first."""
    tags = _git(repo, 'tag', '--points-at', commit).split()
    return sorted(tags, key=lambda t: (not t.startswith('manager-v'), t))


def checkout(repo, commit, dest):
    """A clean, detached clone of `repo` at `commit`. `repo` is only read: --shared
    borrows its objects rather than copying them, which matters on a full disk."""
    dest = Path(dest)
    if dest.exists():
        raise BuildError('%s already exists' % dest)
    result = subprocess.run(['git', 'clone', '--quiet', '--shared', '--', str(repo), str(dest)],
                            text=True, capture_output=True, env={**os.environ, **GIT_ENV})
    if result.returncode:
        raise BuildError('cannot clone %s: %s' % (repo, result.stderr.strip()))
    _git(dest, '-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', commit)
    return dest
