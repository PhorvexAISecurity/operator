"""Obtain `brain-replay` from the exact deployed operator image.

The binary is read out of the image layers in ECR by digest (no container runtime is
needed), every downloaded blob is checked against its content digest, and the extracted
binary's embedded source revision is recorded. The replay therefore runs the decision code
of the image that produced the snapshots, and a mismatch is detectable.
"""
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from .common import data_root, read_json, sha256_file, utc, write_json

ECR_IMAGE = re.compile(r'^(?P<registry>(?P<account>\d{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com)/(?P<repo>[a-z0-9._/-]+)$')
INDEX_TYPES = ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json')
MANIFEST_TYPES = ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
BINARY = 'brain-replay'
# A build whose -version predates overridableParameters supports exactly the first two knobs.
LEGACY_OVERRIDABLE = ('P-FEA-006', 'P-OBJ-003')
MAX_LAYER_BYTES = 512 << 20


class BinaryError(Exception):
    pass


def _run(args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise BinaryError(args[0] + ' ' + args[1] + ' failed')
    return result.stdout


def deployed_image(namespace='phorvex-system', selector='app.kubernetes.io/name=phorvex'):
    """The running manager image and its resolved digest (read-only kubectl)."""
    pods = json.loads(_run(['kubectl', '-n', namespace, 'get', 'pods', '-l', selector, '-o', 'json']))
    for pod in pods.get('items', []):
        if pod.get('status', {}).get('phase') != 'Running':
            continue
        for spec, status in zip(pod['spec']['containers'], pod['status'].get('containerStatuses', [])):
            image_id = status.get('imageID', '')
            if spec['name'] in ('manager', 'phorvex') or 'phorvex@sha256:' in image_id:
                if '@sha256:' in image_id:
                    repo = image_id.split('@')[0].replace('docker-pullable://', '')
                    return {'image': spec['image'], 'repository': repo, 'digest': image_id.split('@')[1], 'pod': pod['metadata']['name']}
    raise BinaryError('no running manager pod with a resolved image digest')


def _ecr(args, region):
    return json.loads(_run(['aws', 'ecr', *args, '--region', region, '--output', 'json'], timeout=90))


def _manifest(repo, digest):
    m = ECR_IMAGE.match(repo)
    if not m:
        raise BinaryError('image repository is not ECR')
    images = _ecr(['batch-get-image', '--registry-id', m['account'], '--repository-name', m['repo'],
                   '--image-ids', 'imageDigest=' + digest, '--accepted-media-types', *INDEX_TYPES, *MANIFEST_TYPES], m['region'])
    found = images.get('images') or []
    if not found:
        raise BinaryError('image digest not found in ECR (it may have expired)')
    raw = found[0]['imageManifest']
    if 'sha256:' + hashlib.sha256(raw.encode()).hexdigest() != digest:
        raise BinaryError('ECR manifest does not hash to the requested digest')
    return json.loads(raw), m


def _layer(m, digest, workdir):
    url = _ecr(['get-download-url-for-layer', '--registry-id', m['account'], '--repository-name', m['repo'], '--layer-digest', digest], m['region'])['downloadUrl']
    if not url.startswith('https://'):
        raise BinaryError('layer download URL is not HTTPS')
    path = Path(workdir) / digest.replace(':', '-')
    h = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(url, timeout=120) as response, open(path, 'wb') as out:
        for chunk in iter(lambda: response.read(1 << 20), b''):
            size += len(chunk)
            if size > MAX_LAYER_BYTES:
                raise BinaryError('layer exceeds the size bound')
            h.update(chunk)
            out.write(chunk)
    if 'sha256:' + h.hexdigest() != digest:
        raise BinaryError('layer blob failed its content-digest check')
    return path


def ensure_binary(data_dir, image=None, platform=('linux', 'amd64')):
    """Return the identity of a verified brain-replay for the deployed (or given) image."""
    image = image or deployed_image()
    target = data_root(data_dir) / 'bin' / image['digest'].replace(':', '-')
    identity_path = target / 'identity.json'
    cached = read_json(identity_path)
    if cached and Path(cached['path']).exists() and sha256_file(cached['path']) == cached['binary_sha256']:
        return cached
    manifest, m = _manifest(image['repository'], image['digest'])
    platform_digest = image['digest']
    if manifest.get('mediaType') in INDEX_TYPES or 'manifests' in manifest:
        chosen = [x for x in manifest.get('manifests', []) if (x.get('platform') or {}).get('os') == platform[0]
                  and (x.get('platform') or {}).get('architecture') == platform[1]]
        if not chosen:
            raise BinaryError('image index has no %s/%s manifest' % platform)
        platform_digest = chosen[0]['digest']
        manifest, m = _manifest(image['repository'], platform_digest)
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target) as work:
        for layer in reversed(manifest.get('layers', [])):
            if 'gzip' not in layer.get('mediaType', '') and not layer.get('mediaType', '').endswith('.tar'):
                continue
            blob = _layer(m, layer['digest'], work)
            with tarfile.open(blob, 'r:*') as tar:
                member = next((x for x in tar.getmembers() if x.name.lstrip('./') == BINARY and x.isfile()), None)
                if member is None:
                    continue
                if member.size > 256 << 20:
                    raise BinaryError('binary exceeds the size bound')
                data = tar.extractfile(member).read()
            path = target / BINARY
            tmp = target / (BINARY + '.tmp')
            tmp.write_bytes(data)
            os.chmod(tmp, 0o755)
            os.replace(tmp, path)
            version = json.loads(run_isolated([str(path), '-version'], timeout=30))
            identity = {'schema_version': 'math-lab.replay-binary.v1', 'path': str(path), 'image': image['image'],
                        'image_digest': image['digest'], 'platform_manifest_digest': platform_digest, 'layer_digest': layer['digest'],
                        'binary_sha256': sha256_file(path), 'git_sha': version.get('gitSHA'), 'brain_image': version.get('brainImage'),
                        'snapshot_schema': version.get('snapshotSchema'), 'replay_schema': version.get('replaySchema'),
                        'overridable_parameters': version.get('overridableParameters'), 'extracted_at': utc()}
            write_json(identity_path, identity)
            return identity
    raise BinaryError('brain-replay is not present in this image (the deployed release predates the Math Lab)')


def run_isolated(args, timeout=1800, cwd=None):
    """Run the replay binary with no inherited credentials (no kubeconfig, no cloud keys)."""
    with tempfile.TemporaryDirectory() as home:
        env = {'PATH': '/usr/bin:/bin', 'HOME': home, 'TMPDIR': home, 'LANG': 'C.UTF-8'}
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd or home)
    if result.returncode:
        raise BinaryError('brain-replay exited %d: %s' % (result.returncode, result.stderr.strip()[-400:]))
    return result.stdout


def local_identity(path):
    """Identity for a locally supplied binary (development/tests). Never used for a matched claim."""
    version = json.loads(run_isolated([str(path), '-version'], timeout=30))
    return {'schema_version': 'math-lab.replay-binary.v1', 'path': str(path), 'image': None, 'image_digest': None,
            'binary_sha256': sha256_file(path), 'git_sha': version.get('gitSHA'), 'brain_image': version.get('brainImage'),
            'snapshot_schema': version.get('snapshotSchema'), 'replay_schema': version.get('replaySchema'),
            'overridable_parameters': version.get('overridableParameters'), 'local': True}


def overridable(identity):
    """Parameters this replay build accepts as arm overrides."""
    listed = (identity or {}).get('overridable_parameters')
    return set(listed) if listed is not None else set(LEGACY_OVERRIDABLE)
