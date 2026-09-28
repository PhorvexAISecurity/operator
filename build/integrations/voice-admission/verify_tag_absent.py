"""Only ECR's structured ImageNotFound result proves the source tag absent."""
import json
from pathlib import Path
import sys


def verify(value, tag):
    if not isinstance(value, dict) or value.get("images") != [] or not isinstance(value.get("failures"), list) or len(value["failures"]) != 1:
        raise ValueError("ECR did not prove source tag absent")
    failure = value["failures"][0]
    if failure.get("failureCode") != "ImageNotFound" or failure.get("imageId") != {"imageTag": tag}:
        raise ValueError("ECR did not prove source tag absent")


if __name__ == "__main__":
    verify(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2])
