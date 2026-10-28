"""Build brain-replay from one commit, as operator.Dockerfile's build set one does.

The source directory must already be checked out at the commit, with nothing
modified. The binary links that commit as its linkedGitSHA, and that SHA is
how brain-replay decides whether a snapshot was recorded by "its" revision. It
is built for the host, because it runs on the host. The flags match the
Dockerfile's: go1.26.1, -trimpath, -s -w, CGO off, -mod=readonly. VCS stamping
is off, because the Docker build has no .git.
"""
import hashlib
import os
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
    env = {**os.environ, 'GOTOOLCHAIN': toolchain, 'GOFLAGS': '-mod=readonly -buildvcs=false', 'CGO_ENABLED': '0'}
    cmd = [go, 'build', '-trimpath', '-ldflags=-s -w -X %s=%s' % (LDFLAG, commit), '-o', str(out), './cmd/brain-replay']
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
