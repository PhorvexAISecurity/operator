"""Source and dataset boundaries for the stage benchmark bot.

The pin is installed by a read-only cluster discovery command, never by an
uploaded request. Historical corpora may coexist, but cannot enter a stage run.
"""
import re
import subprocess
from contextlib import contextmanager
import fcntl
import os
import threading
import time
from pathlib import Path

from .common import read_json, sha256_file, sha256_json

SCHEMA = 'phorvex-bench.stage-pin.v1'
REPOSITORY = 'https://github.com/PhorvexSecurity/operator-refactored.git'
DEFAULT_POLICY = 'phorvex-staging-demo/demo-api-defense'
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
NAME = re.compile(r'^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$')
STAGE_CONTEXT = 'arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
STAGE_NAMESPACE = 'phorvex-staging'
ALLOWED_POLICIES = ('phorvex-staging-demo/demo-api-defense', 'phorvex-staging-demo/stage-bench-defense')
POLICY_WORKLOADS = dict(zip(ALLOWED_POLICIES, ('demo-api', 'stage-bench-api')))
_pin_locks = threading.local()


class StageError(ValueError):
    pass


class StageLeaseBusy(StageError):
    """The bounded wait for an actual conflicting pin lease expired."""


def observation_git_env():
    # Older supported Git versions do not honor GIT_NO_LAZY_FETCH. Denying
    # every transport is the additional fail-closed boundary for promisor
    # objects; observation must never obtain objects implicitly.
    return {**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0',
            'GIT_ALLOW_PROTOCOL': ''}


@contextmanager
def pin_lock(data_dir, exclusive=False, timeout=20, readonly=False):
    """Global pin/job lease; acquire before any policy cache lock.

    Nested calls in one thread reuse the outer lease. A reader cannot upgrade
    itself. Validation never creates a directory/lock: an absent lease yields
    False, which the runtime probe reports as reconciliation required.
    """
    if not 0 <= timeout <= 1800:
        raise StageError('stage pin lock timeout must be 0..1800 seconds')
    path = Path(data_dir).resolve() / 'mathlab/stage.lock'
    held = getattr(_pin_locks, 'held', None)
    if held is None:
        held = _pin_locks.held = {}
    key = (os.getpid(), str(path))
    if key in held:
        if exclusive and not held[key][1]:
            raise StageError('stage pin read lease cannot be upgraded')
        yield True
        return
    if readonly and not path.exists():
        yield False
        return
    if readonly and exclusive:
        raise StageError('read-only stage pin lease cannot be exclusive')
    if not readonly:
        path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY if readonly else os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StageLeaseBusy('stage pin is busy with active jobs or reconciliation; retry after it completes')
                time.sleep(min(.05, max(0, deadline-time.monotonic())))
        held[key] = (fd, exclusive)
        try:
            yield True
        finally:
            del held[key]
    finally:
        os.close(fd)


def namespace(value):
    if not isinstance(value, str) or not NAME.fullmatch(value) or not re.search(r'(?:^|-)(?:stage|staging)(?:-|$)', value):
        raise StageError('benchmark namespace must contain a stage or staging segment')
    return value


def policy(value):
    parts = value.split('/') if isinstance(value, str) else []
    if len(parts) != 2 or not NAME.fullmatch(parts[1]):
        raise StageError('policy must be a stage namespace/name')
    namespace(parts[0])
    return parts


def repository(path, source=None, timeout=30, complete_tree=False):
    if not path:
        raise StageError('BOT_REPO must name an operator-refactored clone')
    deadline = time.monotonic()+timeout
    def git(*args):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise StageError('source repository observation deadline exceeded')
        result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True,
                                timeout=remaining, env=observation_git_env())
        if result.returncode:
            raise StageError('operator-refactored clone or pinned source is unavailable; fetch the exact stage source')
        return result.stdout.strip()
    url = git('remote', 'get-url', 'origin')
    accepted = {REPOSITORY, REPOSITORY[:-4], 'git@github.com:PhorvexSecurity/operator-refactored.git',
                'ssh://git@github.com/PhorvexSecurity/operator-refactored.git'}
    if url not in accepted:
        raise StageError('BOT_REPO origin must be PhorvexSecurity/operator-refactored; legacy operator is not a benchmark source')
    if source and (not SHA.fullmatch(source) or git('cat-file', '-t', source + '^{commit}') != 'commit'):
        raise StageError('the exact stage source commit is unavailable in BOT_REPO')
    if complete_tree:
        if not source:raise StageError('complete source-tree observation requires the exact deployed revision')
        objects=git('rev-list','--objects','--no-object-names','--no-walk=unsorted','--missing=print','HEAD',source).splitlines()
        if len(objects)>200000 or any(not SHA.fullmatch(item) for item in objects):
            raise StageError('exact deployed/HEAD source tree objects are unavailable offline; run bounded stage reconciliation')
    return REPOSITORY


def load(data_dir, requested_policy=None, repo=None):
    if not data_dir:
        raise StageError('MATHLAB_DATA_DIR must name the separate stage data directory')
    pin = read_json(Path(data_dir) / 'mathlab/stage.json')
    if not isinstance(pin, dict) or pin.get('schema') != SCHEMA or pin.get('repository') != REPOSITORY:
        raise StageError('stage is not pinned; run stage_cli.py pin against operator-refactored and the stage brain')
    namespace(pin.get('service_namespace'))
    if not isinstance(pin.get('kube_context'), str) or not pin['kube_context']:
        raise StageError('stage pin has no explicit Kubernetes context')
    brain = pin.get('brain') or {}
    if not SHA.fullmatch(str(brain.get('git_sha', ''))) or not DIGEST.fullmatch(str(brain.get('image_digest', ''))):
        raise StageError('stage pin needs an exact brain source and image digest')
    if '/phorvex/staging/brain' not in str(brain.get('repository', '')):
        raise StageError('stage brain must use the isolated staging image repository')
    image = brain.get('image')
    if (not isinstance(image, str) or not image.endswith('@' + brain['image_digest']) or
            image.split('@')[0].rsplit(':', 1)[0] != brain['repository']):
        raise StageError('stage pin must retain the exact immutable running brain image; pin the current stage deployment again')
    if requested_policy:
        policy(requested_policy)
        record = (pin.get('policies') or {}).get(requested_policy)
        if not isinstance(record, dict) or not record.get('uid'):
            raise StageError('policy is not in the installed stage capture pin; pin and sync it before running')
    if repo is not None:
        repository(repo, brain['git_sha'])
    return pin


def identity(data_dir, pin=None):
    pin = pin or load(data_dir)
    # New installs publish one atomic pin containing its immutable identity.
    # The old current.json remains untouched and readable for historical pins.
    ident = (pin.get('replay') if pin.get('identity_binding') == 'stage-pin.replay.v1'
             else read_json(Path(data_dir) / 'mathlab/bin/current.json'))
    if not isinstance(ident, dict) or ident.get('local'):
        raise StageError('no image-extracted stage replay binary; run stage_cli.py pin')
    expected = pin.get('replay') or {}
    for key in ('git_sha', 'binary_sha256', 'image_digest'):
        if not ident.get(key) or ident.get(key) != expected.get(key):
            raise StageError('stage replay identity differs from the installed pin; pin the current stage deployment again')
    if ident['git_sha'] != pin['brain']['git_sha']:
        raise StageError('replay source does not match the actual stage brain source')
    path = Path(ident.get('path', ''))
    if not path.is_file() or sha256_file(path) != ident['binary_sha256']:
        raise StageError('stage replay binary is missing or its hash changed; reinstall the verified image binary')
    return ident


def cohort(pin, requested_policy, entries):
    ns, name = policy(requested_policy)
    record = (pin.get('policies') or {}).get(requested_policy) or {}
    if not record.get('uid'):
        raise StageError('policy is not in the installed stage pin')
    if not entries:
        raise StageError('no fresh source-matched stage ticks; enable capture on the stage brain and run stage_cli.py sync')
    for entry in entries:
        h = entry['header']
        if h.get('finalized') is not True:
            raise StageError('stage snapshot is not finalized; wait for completed capture')
        if (h.get('namespace'), h.get('policyName'), h.get('policyUID'), h.get('gitSHA')) != (
                ns, name, record['uid'], pin['brain']['git_sha']):
            raise StageError('cohort includes a different namespace, policy UID or brain source; sync and select the pinned stage policy')
        if (not pin['brain'].get('image') or h.get('brainImage') != pin['brain']['image'] or
                h.get('captureIdentitySource') != 'recorder-process'):
            raise StageError('snapshot brain image differs from the installed stage brain; old manager-stamped or different-image records remain historical and cannot enter this benchmark')
        if not h.get('capturedAt'):
            raise StageError('stage snapshot has no capture timestamp')
        if pin.get('identity_binding') == 'stage-pin.replay.v1' and h.get('policyGeneration') != record.get('generation'):
            raise StageError('cohort includes a different policy generation; gather fresh matching snapshots')
    return {'repository': REPOSITORY, 'pin_sha256': sha256_json(pin), 'kube_context': pin['kube_context'],
            'service_namespace': pin['service_namespace'], 'brain': pin['brain'], 'policy': requested_policy,
            'policy_uid': record['uid'], 'replay': pin['replay'], 'measurement': 'recorded-stage-brain-offline-replay'}


def cohort_filter(pin, requested_policy):
    """Filter before sampling so historical same-source image cohorts stay out."""
    result = {'git_sha': pin['brain']['git_sha'], 'brain_image': pin['brain']['image'],
              'policy_uid': pin['policies'][requested_policy]['uid'], 'capture_identity_source': 'recorder-process',
              'require_finalized': True}
    if pin.get('identity_binding') == 'stage-pin.replay.v1':
        result['policy_generation'] = pin['policies'][requested_policy]['generation']
    return result


def snapshot_header(pin, requested_policy):
    filters = cohort_filter(pin, requested_policy)
    result = {'gitSHA': filters['git_sha'], 'brainImage': filters['brain_image'], 'policyUID': filters['policy_uid'],
              'captureIdentitySource': filters['capture_identity_source'], 'finalized': True}
    if 'policy_generation' in filters: result['policyGeneration'] = filters['policy_generation']
    return result


def validate_run(data_dir, requested_policy, entries, repo=None):
    pin = load(data_dir, requested_policy, repo)
    replay = identity(data_dir, pin)
    provenance = cohort(pin, requested_policy, entries)
    return pin, replay, provenance


def study_engine(data_dir, pin=None):
    """An operator-installed reviewed experimental brain, separate from capture."""
    from . import binary
    pin = pin or load(data_dir)
    if pin.get('study_engine_lane') == 'native-stage-image':
        return native_study_engine(data_dir, pin)
    reference = pin.get('study_engine_reference')
    if reference:
        path = Path(reference.get('path', ''))
        if not path.is_file() or sha256_file(path) != reference.get('sha256'):
            raise StageError('installed reviewed study engine reference changed')
        engine = read_json(path)
    else:
        engine = read_json(Path(data_dir) / 'mathlab/study-engine.json')
    if not isinstance(engine, dict) or engine.get('schema') != 'phorvex-bench.study-engine.v1':
        raise StageError('reviewed endpoint brain engine is not installed; install-study-engine after its source tests and independent review')
    if engine.get('base_source') != pin['brain']['git_sha']:
        raise StageError('experimental brain base differs from the captured stage source; rebuild and review it against this stage release')
    for name, expected_source in (('candidate', engine.get('source_revision')), ('base_local', engine['base_source'])):
        item = engine.get(name) or {}
        path = Path(item.get('path', ''))
        if not path.is_file() or sha256_file(path) != item.get('binary_sha256'):
            raise StageError('installed study %s binary is missing or changed' % name)
        actual = binary.local_identity(path, readonly=True)
        if actual.get('git_sha') != expected_source or item.get('git_sha') != expected_source:
            raise StageError('installed study %s embedded source differs from the reviewed pin' % name)
    if not engine.get('review_evidence'):
        raise StageError('experimental brain review evidence is missing')
    for item in engine['review_evidence']:
        if not Path(item['path']).is_file() or sha256_file(item['path']) != item['sha256']:
            raise StageError('experimental brain review evidence changed after installation')
    receipt = engine.get('review_receipt') or {}
    if (receipt.get('schema') != 'phorvex-bench.study-engine-review.v1' or receipt.get('result') != 'PASS' or
            not str(receipt.get('reviewer') or '').strip() or receipt.get('source_revision') != engine['source_revision'] or
            receipt.get('base_source') != engine['base_source'] or
            receipt.get('candidate_binary_sha256') != engine['candidate']['binary_sha256'] or
            receipt.get('base_binary_sha256') != engine['base_local']['binary_sha256']):
        raise StageError('experimental brain review receipt does not bind the installed sources and binaries')
    return engine


def native_study_engine(data_dir, pin, timeout=10):
    """Verified image-native lane, distinct from an independently reviewed fork.

    Its receipt is measured baseline equivalence, never a review PASS. Every
    endpoint run still reproduces its own exact frozen snapshot cohort.
    """
    from . import binary, snapshots
    deadline = time.monotonic()+timeout
    def remaining():
        value=deadline-time.monotonic()
        if value<=0: raise StageError('native stage evidence validation exceeded its bounded deadline')
        return value
    replay_path=Path((pin.get('replay') or {}).get('path',''))
    if not replay_path.is_file() or replay_path.stat().st_size > 128 << 20:
        raise StageError('native stage replay binary exceeds its bounded size')
    ident = identity(data_dir, pin)
    actual = binary.local_identity(ident['path'],timeout=remaining(),readonly=True)
    expected = pin.get('native_study') or {}
    if (expected.get('schema') != 'phorvex-bench.native-study.v1' or
            expected.get('source_revision') != pin['brain']['git_sha'] or
            expected.get('image_digest') != pin['brain']['image_digest'] or
            expected.get('binary_sha256') != ident['binary_sha256'] or
            actual.get('git_sha') != ident['git_sha'] or
            actual.get('endpoint_study_mode') != 'PAIRED_BRAIN_REPLAY' or
            actual.get('study_candidates_schema') != 'math-lab.study-candidates.v1'):
        raise StageError('native stage study identity/capabilities are unverified; run stage reconciliation')
    refs = expected.get('baseline_evidence')
    if not isinstance(refs, list) or not 1 <= len(refs) <= len(ALLOWED_POLICIES):
        raise StageError('native stage study requires measured source-matched baseline equivalence')
    covered = set(); total_bytes = 0
    for ref in refs:
        path = Path(ref.get('path', ''))
        if not path.is_file() or path.stat().st_size > 16 << 20 or sha256_file(path) != ref.get('sha256'):
            raise StageError('native stage baseline evidence is missing or changed')
        receipt = read_json(path, {})
        rows = receipt.get('rows') or []
        digests = receipt.get('snapshot_digests') or []
        pol = (pin.get('policies') or {}).get(receipt.get('policy')) or {}
        if (receipt.get('schema') != 'phorvex-bench.native-baseline.v1' or
                receipt.get('source_revision') != ident['git_sha'] or
                receipt.get('image_digest') != ident['image_digest'] or
                receipt.get('binary_sha256') != ident['binary_sha256'] or
                receipt.get('policy_uid') != pol.get('uid') or not pol.get('uid') or
                not 1 <= len(digests) <= 256 or len(set(digests)) != len(digests) or
                len(rows) != len(digests) or
                {r.get('snapshot', {}).get('snapshot_digest') for r in rows} != set(digests) or
                any(r.get('status') != 'OK' or (r.get('baseline_check') or {}).get('reproduced') is not True for r in rows)):
            raise StageError('native stage baseline evidence does not bind exact source/policy/cohort equivalence')
        if receipt['policy'] in covered:
            raise StageError('native stage baseline policy evidence is duplicated')
        covered.add(receipt['policy'])
        folder = Path(receipt.get('cohort_path', ''))
        for digest in digests:
            remaining()
            if not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise StageError('native stage baseline snapshot digest is invalid')
            snapshot = folder/(digest+'.pxms')
            if not snapshot.is_file() or snapshot.stat().st_size > snapshots.MAX_SNAPSHOT_BYTES:
                raise StageError('native stage baseline snapshot is missing or oversized')
            total_bytes += snapshot.stat().st_size
            if total_bytes > 256 << 20:
                raise StageError('native stage frozen baseline evidence exceeds its 256 MiB validation bound')
            if not snapshot.is_file() or sha256_file(snapshot) != digest:
                raise StageError('native stage baseline frozen snapshot is missing or changed')
            header = snapshots.read_header(snapshot)
            if any(header.get(k) != v for k,v in snapshot_header(pin, receipt['policy']).items()):
                raise StageError('native stage baseline frozen header differs from its producer/policy identity')
    if covered != set(pin['policies']):
        raise StageError('native baseline evidence does not cover all installed policies')
    remaining()
    return {'schema': 'phorvex-bench.study-engine.v1', 'lane': 'native-stage-image',
            'classification': 'same-source image-native offline study; no cross-source review claim',
            'source_revision': ident['git_sha'], 'base_source': ident['git_sha'],
            'candidate': ident, 'base_local': ident, 'baseline_evidence': refs}
