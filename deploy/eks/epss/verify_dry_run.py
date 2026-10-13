#!/usr/bin/env python3
"""Bounded offline check of full-template witness/result/cache evidence. No API writes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

MAX_BYTES = 16 << 20
CONTROLLER_LABELS = {'controller-uid', 'job-name', 'batch.kubernetes.io/controller-uid', 'batch.kubernetes.io/job-name'}


def read_json(path):
    with Path(path).open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('evidence exceeds size bound')
    return json.loads(raw)


def normalized_job_spec(spec):
    spec = copy.deepcopy(spec)
    if spec.get('manualSelector'):
        raise ValueError('manual witness selector forbidden')
    spec.pop('selector', None)
    labels = spec.get('template', {}).get('metadata', {}).get('labels', {})
    for key in CONTROLLER_LABELS:
        labels.pop(key, None)
    return spec


def verify(cron, job, before, after, result):
    if cron.get('kind') != 'CronJob' or job.get('kind') != 'Job':
        raise ValueError('wrong evidence object kinds')
    if normalized_job_spec(cron['spec']['jobTemplate']['spec']) != normalized_job_spec(job['spec']):
        raise ValueError('witness does not preserve the full CronJob template')
    pod = job['spec']['template']['spec']
    feed = next(x for x in pod['containers'] if x['name'] == 'feed')
    args = feed['args']
    for flag in ('--epss-feed-apply=false', '--epss-feed-allow-partial=false'):
        if args.count(flag) != 1:
            raise ValueError('witness must retain strict dry-run flags')
    if any(x.startswith(('--epss-feed-scope-namespaces', '--epss-feed-scope-digests')) for x in args):
        raise ValueError('inventory narrowing forbidden')
    count = result.get('uniqueImages')
    if (result.get('mode') != 'dry-run' or type(count) is not int or count <= 0
            or result.get('failedImages') != 0 or result.get('scannedImages') != count
            or result.get('scanFailures') or result.get('scopeSHA256')):
        raise ValueError('full-inventory strict dry-run has not passed')
    for obj in (before, after):
        if obj.get('kind') != 'ConfigMap' or obj['metadata'].get('name') != 'phorvex-epss':
            raise ValueError('wrong cache evidence object')
    for key in ('uid', 'resourceVersion'):
        if not before['metadata'].get(key) or before['metadata'][key] != after['metadata'].get(key):
            raise ValueError('cache identity/version changed')
    for key in ('data', 'binaryData'):
        if before.get(key, {}) != after.get(key, {}):
            raise ValueError('cache contents changed')
    if before['metadata'].get('annotations', {}) != after['metadata'].get('annotations', {}):
        raise ValueError('cache annotations changed')
    metadata_keys = [x.split('=', 1)[1] for x in args if x.startswith('--epss-metadata-key=')]
    if len(metadata_keys) != 1 or metadata_keys[0] in after.get('data', {}):
        raise ValueError('dry-run cache must have no generated metadata key')
    if not job['metadata'].get('uid') or not job['metadata'].get('name'):
        raise ValueError('witness identity missing')
    return {'mode': result['mode'], 'uniqueImages': count, 'failedImages': 0,
            'jobName': job['metadata']['name'], 'jobUID': job['metadata']['uid'],
            'cacheUID': after['metadata']['uid'], 'cacheResourceVersion': after['metadata']['resourceVersion'],
            'cacheSHA256': hashlib.sha256(json.dumps(after.get('data', {}), sort_keys=True).encode()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cronjob', 'job', 'before', 'after', 'result'):
        parser.add_argument('--' + name, required=True)
    options = parser.parse_args()
    try:
        summary = verify(*(read_json(getattr(options, name)) for name in ('cronjob', 'job', 'before', 'after', 'result')))
    except (ValueError, KeyError, TypeError, OSError, StopIteration):
        raise SystemExit('EPSS dry-run evidence verification failed')
    print(json.dumps(summary, sort_keys=True))
