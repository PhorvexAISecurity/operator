#!/usr/bin/env python3
"""Static recipe and existing ECR lifecycle gates; no AWS calls or mutations."""
import fnmatch
import json
from pathlib import Path
import re
import sys

RECIPE = Path(__file__).resolve().parent


def verify_recipe():
    contract = json.loads((RECIPE / 'image-contract.json').read_text())
    dockerfile = (RECIPE / 'Dockerfile').read_text()
    for key in ('builderImage', 'runtimeImage'):
        pin = contract[key]
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', pin) or pin not in dockerfile:
            raise ValueError('base image pin does not match Dockerfile')
    if contract['publishedImageDigest'] is not None:
        raise ValueError('publication must not activate a deployment pin')
    if 'USER 65532:65532' not in dockerfile or 'GOTOOLCHAIN=local' not in dockerfile:
        raise ValueError('runtime identity or toolchain is unpinned')
    required = {'github.com/aws/aws-sdk-go-v2': 'v1.47.3',
                'github.com/aws/aws-sdk-go-v2/credentials': 'v1.20.9',
                'github.com/aws/aws-sdk-go-v2/service/ecr': 'v1.66.4',
                'github.com/aws/aws-sdk-go-v2/service/sts': 'v1.51.4'}
    module = (RECIPE / 'go.mod').read_text()
    sums = (RECIPE / 'go.sum').read_text()
    for name, version in required.items():
        if not re.search(r'^\s*' + re.escape(name + ' ' + version) + r'\s*$', module, re.M):
            raise ValueError('SDK module is not pinned')
        for suffix in ('', '/go.mod'):
            if not re.search(r'^' + re.escape(name + ' ' + version + suffix) + r' h1:', sums, re.M):
                raise ValueError('SDK checksum is missing')
    return contract


def verify_lifecycle(policy, tag):
    if not re.fullmatch(r'epss-ecr-auth-[0-9a-f]{40}', tag):
        raise ValueError('unexpected durable runtime tag')
    rules = policy.get('rules')
    if not isinstance(rules, list) or not rules:
        raise ValueError('existing lifecycle policy must be readable')
    for rule in rules:
        selection = rule.get('selection', {})
        status = selection.get('tagStatus')
        if status == 'untagged':
            continue
        if status != 'tagged':
            raise ValueError('lifecycle can expire tagged runtime images')
        prefixes = selection.get('tagPrefixList', [])
        patterns = selection.get('tagPatternList', [])
        if not prefixes and not patterns:
            raise ValueError('unbounded tagged lifecycle rule')
        if any(tag.startswith(prefix) for prefix in prefixes) or any(fnmatch.fnmatchcase(tag, pattern) for pattern in patterns):
            raise ValueError('lifecycle can expire the helper runtime tag')
    return True


def verify_tag_absent(result, tag):
    if not re.fullmatch(r'epss-ecr-auth-[0-9a-f]{40}', tag):
        raise ValueError('unexpected source tag')
    failures = result.get('failures', [])
    if result.get('images') or len(failures) != 1:
        raise ValueError('source tag absence is unproven')
    failure = failures[0]
    if failure.get('failureCode') != 'ImageNotFound' or failure.get('imageId', {}).get('imageTag') != tag:
        raise ValueError('source tag absence is unproven')


if __name__ == '__main__':
    try:
        verify_recipe()
        if len(sys.argv) == 4 and sys.argv[1] == 'lifecycle':
            response = json.loads(Path(sys.argv[2]).read_text())
            verify_lifecycle(json.loads(response['lifecyclePolicyText']), sys.argv[3])
        elif len(sys.argv) == 4 and sys.argv[1] == 'tag-absent':
            verify_tag_absent(json.loads(Path(sys.argv[2]).read_text()), sys.argv[3])
        elif len(sys.argv) != 1:
            raise ValueError('invalid verification arguments')
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit('EPSS runtime recipe/publication preflight failed')
    print('EPSS runtime recipe/publication preflight passed')
