"""Shared paths, atomic file writes and hashing for the Math Lab worker."""
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BENCHMARK_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = BENCHMARK_ROOT / 'mathlab' / 'registry' / 'parameter_registry.json'
NAME = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
EXPERIMENT_ID = re.compile(r'^[0-9a-f-]{36}$')


def utc():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def data_root(data_dir):
    root = Path(data_dir).resolve() / 'mathlab'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def corpus_dir(data_dir, namespace, policy):
    if not NAME.match(namespace) or not NAME.match(policy.replace('.', '-')):
        raise ValueError('invalid namespace/policy')
    path = data_root(data_dir) / 'snapshots' / namespace / policy
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False, default=str)
            f.write('\n')
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False, default=str).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value and value not in (float('inf'), float('-inf'))
