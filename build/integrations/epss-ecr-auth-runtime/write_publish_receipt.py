#!/usr/bin/env python3
"""Record nonsecret source/recipe/digest evidence only after remote verification."""
import hashlib
import json
import os
from pathlib import Path
import re

from verify_recipe import RECIPE, verify_recipe

contract = verify_recipe()
source = os.environ['SOURCE_SHA']
digest = os.environ['DIGEST']
image = os.environ['IMAGE']
assert re.fullmatch(r'[0-9a-f]{40}', source)
assert re.fullmatch(r'sha256:[0-9a-f]{64}', digest)
assert image == contract['repository'] + ':' + contract['tagPrefix'] + source
files = ['go.mod', 'go.sum', 'main.go', 'auth.go', 'Dockerfile', 'image-contract.json', 'verify_recipe.py']
receipt = {'schema': 'phorvex.epss-ecr-auth-publication.v1', 'sourceCommit': source,
           'imageTag': image, 'imageByDigest': contract['repository'] + '@' + digest,
           'runID': os.environ['RUN_ID'], 'runAttempt': os.environ['RUN_ATTEMPT'],
           'recipeSHA256': {name: hashlib.sha256((RECIPE / name).read_bytes()).hexdigest() for name in files}}
Path('epss-ecr-auth-publish-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
