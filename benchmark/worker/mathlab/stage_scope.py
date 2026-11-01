"""Source and dataset boundaries for the stage benchmark bot.

The pin is installed by a read-only cluster discovery command, never by an
uploaded request. Historical corpora may coexist, but cannot enter a stage run.
"""
import re
import subprocess
from pathlib import Path

from .common import read_json, sha256_file, sha256_json

SCHEMA = 'phorvex-bench.stage-pin.v1'
REPOSITORY = 'https://github.com/PhorvexSecurity/operator-refactored.git'
DEFAULT_POLICY = 'phorvex-staging-demo/demo-api-defense'
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
NAME = re.compile(r'^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$')


class StageError(ValueError):
    pass


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


def repository(path, source=None):
    if not path:
        raise StageError('BOT_REPO must name an operator-refactored clone')
    def git(*args):
        result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, timeout=30)
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
    ident = read_json(Path(data_dir) / 'mathlab/bin/current.json')
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
        if (h.get('namespace'), h.get('policyName'), h.get('policyUID'), h.get('gitSHA')) != (
                ns, name, record['uid'], pin['brain']['git_sha']):
            raise StageError('cohort includes a different namespace, policy UID or brain source; sync and select the pinned stage policy')
        if (not pin['brain'].get('image') or h.get('brainImage') != pin['brain']['image'] or
                h.get('captureIdentitySource') != 'recorder-process'):
            raise StageError('snapshot brain image differs from the installed stage brain; old manager-stamped or different-image records remain historical and cannot enter this benchmark')
        if not h.get('capturedAt'):
            raise StageError('stage snapshot has no capture timestamp')
    return {'repository': REPOSITORY, 'pin_sha256': sha256_json(pin), 'kube_context': pin['kube_context'],
            'service_namespace': pin['service_namespace'], 'brain': pin['brain'], 'policy': requested_policy,
            'policy_uid': record['uid'], 'replay': pin['replay'], 'measurement': 'recorded-stage-brain-offline-replay'}


def cohort_filter(pin, requested_policy):
    """Filter before sampling so historical same-source image cohorts stay out."""
    return {'git_sha': pin['brain']['git_sha'], 'brain_image': pin['brain']['image'],
            'policy_uid': pin['policies'][requested_policy]['uid'], 'capture_identity_source': 'recorder-process'}


def snapshot_header(pin, requested_policy):
    filters = cohort_filter(pin, requested_policy)
    return {'gitSHA': filters['git_sha'], 'brainImage': filters['brain_image'], 'policyUID': filters['policy_uid'],
            'captureIdentitySource': filters['capture_identity_source']}


def validate_run(data_dir, requested_policy, entries, repo=None):
    pin = load(data_dir, requested_policy, repo)
    replay = identity(data_dir, pin)
    provenance = cohort(pin, requested_policy, entries)
    return pin, replay, provenance


def study_engine(data_dir, pin=None):
    """An operator-installed reviewed experimental brain, separate from capture."""
    from . import binary
    pin = pin or load(data_dir)
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
        actual = binary.local_identity(path)
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
