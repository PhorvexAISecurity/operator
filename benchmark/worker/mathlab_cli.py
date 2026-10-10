#!/usr/bin/env python3
"""Math Lab worker entry point (spawned by the benchmark API; never by a browser).

Subcommands:
  binary    resolve the deployed operator image and extract a verified brain-replay
  sync      pull recorded decision snapshots for one policy through the Console relay,
            then inspect the newest one for configured/effective values
  preflight validate an experiment request (prints JSON)
  run       execute a queued REPLAY experiment
Nothing here writes to the cluster: kubectl is used only for reads and the existing
Console identity token; the replay binary runs without any credentials.
"""
import argparse
import json
import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mathlab import binary, experiment, registry, snapshots  # noqa: E402
from mathlab.common import data_root, read_json, utc, write_json  # noqa: E402


def current_binary(data_dir):
    local = os.environ.get('MATHLAB_LOCAL_BINARY')
    if local:
        return binary.local_identity(local)
    identity = read_json(data_root(data_dir) / 'bin' / 'current.json')
    if identity and Path(identity.get('path', '')).exists():
        return identity
    return None


def refresh_binary(data_dir):
    if os.environ.get('MATHLAB_LOCAL_BINARY'):
        return current_binary(data_dir)
    identity = binary.ensure_binary(data_dir)
    write_json(data_root(data_dir) / 'bin' / 'current.json', identity)
    return identity


def inspect_latest(data_dir, namespace, policy, identity):
    entries = snapshots.local_index(data_dir, namespace, policy)
    if not entries or not identity:
        return None
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        latest = entries[-1]
        src = data_root(data_dir) / 'snapshots' / namespace / policy / (latest['digest'] + '.pxms')
        os.symlink(src, Path(tmp) / src.name)
        out = Path(tmp) / 'inspect.jsonl'
        binary.run_isolated([identity['path'], '-inspect', '-snapshots', tmp, '-out', str(out)], timeout=120)
        lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    inspection = next((x for x in lines if 'effective' in x), None)
    if inspection:
        root = data_root(data_dir)
        write_json(root / 'inspections' / ('%s--%s.json' % (namespace, policy)), inspection)
        write_json(root / 'registry-effective' / ('%s--%s.json' % (namespace, policy)), registry.overlay(registry.load_registry(), inspection))
    return inspection


def job_status(data_dir, job_id, **fields):
    if not job_id:
        return
    path = data_root(data_dir) / 'jobs' / (job_id + '.json')
    status = read_json(path, {}) or {}
    status.update(fields, updated_at=utc())
    write_json(path, status)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=['binary', 'sync', 'preflight', 'run'])
    p.add_argument('--data', required=True)
    p.add_argument('--namespace')
    p.add_argument('--policy')
    p.add_argument('--since')
    p.add_argument('--request')
    p.add_argument('--experiment')
    p.add_argument('--job')
    a = p.parse_args(argv)
    try:
        if a.command == 'binary':
            identity = refresh_binary(a.data)
            print(json.dumps(identity))
        elif a.command == 'sync':
            from runner import Console
            job_status(a.data, a.job, state='RUNNING', stage='binary', message='resolving the deployed replay binary')
            identity_error = None
            try:
                identity = refresh_binary(a.data)
            except binary.BinaryError as error:
                identity, identity_error = None, str(error)
            job_status(a.data, a.job, stage='sync', message='downloading recorded snapshots')
            console = Console()
            try:
                record = snapshots.sync(a.data, a.namespace, a.policy, console, since=a.since,
                                        progress=lambda d, t: job_status(a.data, a.job, completed=d, total=t))
            finally:
                console.close()
            inspection = None
            if identity:
                job_status(a.data, a.job, stage='inspect', message='resolving effective values')
                inspection = inspect_latest(a.data, a.namespace, a.policy, identity)
            job_status(a.data, a.job, state='COMPLETE', stage='done', message='synced', result={
                'sync': record, 'binary': identity, 'binary_error': identity_error,
                'inspection_digest': (inspection or {}).get('snapshot_digest')})
        elif a.command == 'preflight':
            request = json.loads(Path(a.request).read_text())
            print(json.dumps(experiment.preflight(a.data, request, current_binary(a.data))))
        elif a.command == 'run':
            state = experiment.run(a.data, a.experiment, current_binary(a.data))
            print(json.dumps({'state': state}))
        return 0
    except Exception as error:  # the API records the failure; details stay in the job file
        job_status(a.data, a.job, state='FAILED', message=type(error).__name__ + ': ' + str(error)[:400])
        if a.command == 'run' and a.experiment:
            root = data_root(a.data) / 'experiments' / a.experiment
            if root.exists():
                write_json(root / 'status.json', {'state': 'FAILED', 'stage': 'error', 'message': type(error).__name__ + ': ' + str(error)[:400], 'updated_at': utc()})
        traceback.print_exc(limit=3)
        return 1


if __name__ == '__main__':
    sys.exit(main())
