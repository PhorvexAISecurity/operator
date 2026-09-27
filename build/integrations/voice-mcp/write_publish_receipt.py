"""Write a checked, credential-free GitHub publication receipt."""

import json
import os
from pathlib import Path
import re

from verify_recipe import verify


IMAGE = re.compile(r"[0-9]+\.dkr\.ecr\.us-east-2\.amazonaws\.com/phorvex:voice-mcp-[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")


def receipt(source_sha: str, image: str, digest: str, run_id: str,
            run_attempt: str) -> dict:
    if not HEAD.fullmatch(source_sha) or not IMAGE.fullmatch(image) or \
            image.rsplit(":voice-mcp-", 1)[1] != source_sha or \
            not DIGEST.fullmatch(digest) or \
            not re.fullmatch(r"[1-9][0-9]*", run_id) or \
            not re.fullmatch(r"[1-9][0-9]*", run_attempt):
        raise ValueError("published MCP image identity is invalid")
    recipe = verify()
    return {"schemaVersion": 1, "sourceSHA": source_sha,
            "mcpSourceSHA256": recipe["sourceSHA256"],
            "image": image, "digest": digest,
            "imageByDigest": image.rsplit(":voice-mcp-", 1)[0] + "@" + digest,
            "platform": "linux/amd64", "baseImage": recipe["baseImage"],
            "wheelCount": recipe["wheelCount"],
            "recipeSHA256": recipe["recipeSHA256"],
            "githubRunID": run_id, "githubRunAttempt": run_attempt}


def main() -> None:
    result = receipt(os.environ["SOURCE_SHA"], os.environ["IMAGE"],
                     os.environ["DIGEST"], os.environ["RUN_ID"],
                     os.environ["RUN_ATTEMPT"])
    output = Path("voice-mcp-publish-receipt.json")
    if output.exists():
        raise SystemExit("publication receipt already exists")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"Published `{result['imageByDigest']}` from `{result['sourceSHA']}`.\n")


if __name__ == "__main__":
    main()
