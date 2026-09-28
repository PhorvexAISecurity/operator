"""Record source/base/wheel pins after workflow independently verifies ECR."""
import hashlib
import json
import os
from pathlib import Path
import re

from prepare_wheelhouse import BASE, EXPECTED, FILENAME, verify

recipe = Path(__file__).parent
verify(recipe / "wheelhouse")
source, image, sha = os.environ["SOURCE_SHA"], os.environ["IMAGE"], os.environ["DIGEST"]
if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"sha256:[0-9a-f]{64}", sha) or \
        image != "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:voice-admission-" + source:
    raise SystemExit("publication identity differs")
value = {"version": 1, "sourceCommit": source, "image": image, "digest": sha, "baseImage": BASE,
         "runID": os.environ["RUN_ID"], "runAttempt": os.environ["RUN_ATTEMPT"],
         "wheels": {FILENAME: EXPECTED}, "recipeSHA256": {name: hashlib.sha256((recipe / name).read_bytes()).hexdigest()
             for name in ("Dockerfile", "requirements.lock", "overlay_install.py", "prepare_wheelhouse.py")}}
Path("voice-admission-publish-receipt.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
